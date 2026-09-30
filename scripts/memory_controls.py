"""Durable structural-memory controls. RAW capture never consults this module.

The global switch and each exact role must permit processing. HTTP transports
reserve one budget slot immediately before each actual attempt, including SDK
retries. A reservation is conservative: a crash before send does not refund it.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import uuid

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / 'tools/memory-adapter'))
from javis_memory_adapter.review_policy import ReviewBlocked, digest, guarded_path, safe_id
from role_registry import ROLE_IDS, ROLE_REGISTRY
from runtime_io import atomic_json, lock

SCHEMA = 'javis.memory-controls.v1'
PATH = 'state/memory-controls/control.json'
DEFAULT_DAILY_CALL_LIMIT = 200
LOCAL_STAGES = frozenset({'local_accept', 'local_replay', 'activation'})


class MemoryProcessingHeld(ReviewBlocked):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _now():
    return datetime.now(timezone.utc)


def _path(root, relative):
    return guarded_path(root, root / relative)


def _read(root, relative):
    path = _path(root, relative)
    if not path.exists():
        return None
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ReviewBlocked('memory_controls_file_too_large')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ReviewBlocked('memory_controls_invalid') from None
    if not isinstance(value, dict):
        raise ReviewBlocked('memory_controls_invalid')
    return value


def _write(root, relative, value):
    path = _path(root, relative)
    atomic_json(path, value)
    # atomic_json fsyncs the file; persist the rename and new parent chain too.
    parent = path.parent
    while True:
        fd = os.open(parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        if parent == root:
            break
        parent = parent.parent


def _state(root):
    value = _read(root, PATH)
    if value is None:
        legacy = _read(root, 'memory/ai-review/control.json')
        enabled = legacy.get('enabled', False) if legacy else False
        revision = legacy.get('revision', 0) if legacy else 0
        if type(enabled) is not bool or type(revision) is not int or revision < 0:
            raise ReviewBlocked('memory_controls_invalid')
        return {'schema': SCHEMA, 'revision': revision, 'global_enabled': enabled,
                'roles': {role: True for role in sorted(ROLE_IDS)},
                'daily_call_limit': DEFAULT_DAILY_CALL_LIMIT, 'commands': {},
                'updated_at': legacy.get('updated_at') if legacy else None,
                'origin': 'legacy_autoreview' if legacy else 'safe_default_paused'}
    if (value.get('schema') != SCHEMA or type(value.get('revision')) is not int
            or value['revision'] < 0 or type(value.get('global_enabled')) is not bool
            or not isinstance(value.get('roles'), dict) or set(value['roles']) != set(ROLE_IDS)
            or any(type(v) is not bool for v in value['roles'].values())
            or type(value.get('daily_call_limit')) is not int
            or not 0 <= value['daily_call_limit'] <= 100000
            or not isinstance(value.get('commands'), dict)
            or value.get('digest') != digest({k: v for k, v in value.items() if k != 'digest'})):
        raise ReviewBlocked('memory_controls_invalid')
    return value


def _budget(root, day):
    relative = 'state/memory-controls/budget/' + day + '.json'
    value = _read(root, relative)
    if value is None:
        return {'schema': SCHEMA, 'day': day, 'reservations': {}}
    if (value.get('schema') != SCHEMA or value.get('day') != day
            or not isinstance(value.get('reservations'), dict)
            or value.get('digest') != digest({k: v for k, v in value.items() if k != 'digest'})):
        raise ReviewBlocked('memory_budget_invalid')
    for key, row in value['reservations'].items():
        safe_id(key)
        if (not isinstance(row, dict) or row.get('scope') not in ROLE_IDS
                or not isinstance(row.get('stage'), str) or not row.get('reserved_at')):
            raise ReviewBlocked('memory_budget_invalid')
    return value


def status(root):
    """Safe read-only projection. Missing configuration never creates files."""
    root = Path(root).resolve()
    state = _state(root)
    day = _now().date().isoformat()
    used = len(_budget(root, day)['reservations'])
    return {'schema': SCHEMA, 'revision': state['revision'],
            'global_enabled': state['global_enabled'], 'roles': dict(state['roles']),
            'role_labels': {role: ROLE_REGISTRY[role]['label'] for role in sorted(ROLE_IDS)},
            'daily_call_limit': state['daily_call_limit'], 'raw_capture_enabled': True,
            'updated_at': state.get('updated_at'), 'origin': state.get('origin', 'memory_controls'),
            'budget': {'day': day, 'timezone': 'UTC', 'reserved_calls': used,
                       'remaining_calls': max(0, state['daily_call_limit'] - used),
                       'unit': 'actual_http_attempt', 'refund_on_unknown_outcome': False}}


@contextmanager
def _locked(root):
    with lock(_path(root, 'state/maintenance.lock'), shared=True):
        from task_service import ensure_not_held
        ensure_not_held(root)
        with lock(_path(root, 'state/locks/memory-controls.lock')):
            yield


def update(root, expected_revision, *, global_enabled=None, roles=None,
           daily_call_limit=None, command_id=None):
    """CAS update; callers must authenticate their own local memory session."""
    root = Path(root).resolve()
    if type(expected_revision) is not int or expected_revision < 0:
        raise ReviewBlocked('invalid_controls_revision')
    if global_enabled is not None and type(global_enabled) is not bool:
        raise ReviewBlocked('invalid_global_enabled')
    if roles is not None and (not isinstance(roles, dict) or not roles
            or any(role not in ROLE_IDS or type(value) is not bool for role, value in roles.items())):
        raise ReviewBlocked('invalid_role_controls')
    if daily_call_limit is not None and (type(daily_call_limit) is not int or not 0 <= daily_call_limit <= 100000):
        raise ReviewBlocked('invalid_daily_call_limit')
    if global_enabled is None and roles is None and daily_call_limit is None:
        raise ReviewBlocked('empty_controls_update')
    command_id = command_id or ('controls_' + uuid.uuid4().hex)
    safe_id(command_id)
    binding = {'expected_revision': expected_revision, 'global_enabled': global_enabled,
               'roles': roles, 'daily_call_limit': daily_call_limit}
    with _locked(root):
        state = _state(root)
        previous = state['commands'].get(command_id)
        if previous is not None:
            if previous['binding'] != binding:
                raise ReviewBlocked('command_id_conflict')
            return previous['result']
        if state['revision'] != expected_revision:
            raise ReviewBlocked('stale_controls_revision')
        state.pop('digest', None)
        state['revision'] += 1
        state['origin'] = 'memory_controls'
        state['updated_at'] = _now().isoformat()
        if global_enabled is not None:
            state['global_enabled'] = global_enabled
        if roles is not None:
            state['roles'].update(roles)
        if daily_call_limit is not None:
            state['daily_call_limit'] = daily_call_limit
        result = {k: state[k] for k in ('revision', 'global_enabled', 'daily_call_limit', 'updated_at')}
        result['roles'] = dict(state['roles'])
        result['raw_capture_enabled'] = True
        state['commands'][command_id] = {'binding': binding, 'result': result}
        state['digest'] = digest(state)
        _write(root, PATH, state)
        return result


def _check(state, scope, stage):
    if scope not in ROLE_IDS:
        raise ReviewBlocked('unknown_memory_scope')
    if not isinstance(stage, str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,80}', stage):
        raise ReviewBlocked('invalid_memory_stage')
    if not state['global_enabled']:
        raise MemoryProcessingHeld('global_paused')
    if not state['roles'][scope]:
        raise MemoryProcessingHeld('role_paused')


def require_processing(root, scope, stage):
    root = Path(root).resolve()
    state = _state(root)
    _check(state, scope, stage)
    if stage not in LOCAL_STAGES:
        day = _now().date().isoformat()
        if len(_budget(root, day)['reservations']) >= state['daily_call_limit']:
            raise MemoryProcessingHeld('daily_budget_exhausted')
    return {'revision': state['revision'], 'scope': scope, 'stage': stage}


def reserve_call(root, scope, stage, attempt_id):
    """Durably reserve once per actual network attempt, never per logical call.

    This does not authorize replaying the same HTTP request twice. Transports
    generate a new ID for every send/retry and keep this ID only for write retry.
    """
    root = Path(root).resolve()
    safe_id(attempt_id)
    with _locked(root):
        state = _state(root)
        _check(state, scope, stage)
        day = _now().date().isoformat()
        value = _budget(root, day)
        previous = value['reservations'].get(attempt_id)
        if previous is not None:
            if previous['scope'] != scope or previous['stage'] != stage:
                raise ReviewBlocked('budget_attempt_binding_conflict')
            return {'attempt_id': attempt_id, 'day': day, 'replayed': True}
        if len(value['reservations']) >= state['daily_call_limit']:
            raise MemoryProcessingHeld('daily_budget_exhausted')
        value.pop('digest', None)
        value['reservations'][attempt_id] = {'scope': scope, 'stage': stage,
            'reserved_at': _now().isoformat(), 'controls_revision': state['revision']}
        value['digest'] = digest(value)
        _write(root, 'state/memory-controls/budget/' + day + '.json', value)
        return {'attempt_id': attempt_id, 'day': day, 'replayed': False}
