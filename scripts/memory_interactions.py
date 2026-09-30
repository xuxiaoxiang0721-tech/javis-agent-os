"""Append-only user supplements, bound to an immutable memory question.

A reply creates its own RAW source. Accepted facts from that reply do not prove
that it answers the original question, which remains open without a separate
answer-validation receipt bound to the question and its exact target version.
"""
from pathlib import Path
import sys

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / 'tools/memory-adapter'))
from javis_memory_adapter.review_policy import digest, guarded_path, safe_id, read_rows
from raw_storage import append_event, now_iso
from runtime_io import atomic_json, lock
from role_registry import ROLE_IDS


def _target(root, target_id, scope):
    safe_id(target_id)
    if scope not in ROLE_IDS: raise ValueError('unknown_memory_scope')
    if target_id.startswith('triage_'):
        from memory_triage import _read
        row = _read(root, guarded_path(root, root / 'memory/triage/items' / (target_id + '.json')))
        binding = row['binding']
        if binding['scope'] != scope: raise ValueError('source_scope_mismatch')
        return row['record_digest'], binding['event_id'], binding['source_digest']
    from memory_review import MemoryReview
    row = MemoryReview(root)._current(scope, target_id)
    event_id = row['payload']['effects'][-1]['source_event_id']
    return row['version_digest'], event_id, row['payload']['source_digests'][event_id]


def supplement(root, request):
    root = Path(root).resolve()
    fields = {'target_id', 'scope', 'expected_version', 'text', 'command_id'}
    if not isinstance(request, dict) or set(request) != fields: raise ValueError('invalid_supplement_request')
    safe_id(request['command_id'])
    text = request['text']
    if not isinstance(text, str) or not text.strip() or len(text.encode('utf-8')) > 12000:
        raise ValueError('supplement_requires_complete_text_under_12000_bytes')
    command_digest = digest(request)
    operation_id = 'supplement_' + digest(request['command_id'])
    path = guarded_path(root, root / 'memory/supplements/items' / (operation_id + '.json'))
    from task_service import ensure_not_held
    from memory_screen import load_source
    import json
    with lock(guarded_path(root, root / 'state/maintenance.lock'), shared=True), \
         lock(guarded_path(root, root / 'state/locks/memory-supplements.lock')):
        ensure_not_held(root)
        version, parent, source_digest = _target(root, request['target_id'], request['scope'])
        if version != request['expected_version']: raise ValueError('supplement_target_changed')
        if digest(load_source(root, parent)) != source_digest: raise ValueError('supplement_source_changed')
        if path.exists():
            row = json.loads(path.read_text())
            if row.get('command_digest') != command_digest: raise ValueError('supplement_command_conflict')
            if row.get('record_digest') != digest({k: v for k, v in row.items() if k != 'record_digest'}):
                raise ValueError('supplement_record_corrupt')
        else:
            row = {'operation_id': operation_id, 'command_digest': command_digest,
                'target_id': request['target_id'], 'target_version': version, 'scope': request['scope'],
                'parent_event_id': parent, 'parent_digest': source_digest,
                'event_id': 'memory-' + operation_id, 'created_at': now_iso(),
                'text_digest': digest(text), 'state': 'prepared', 'authority': 'local_user_supplement'}
            row['record_digest'] = digest(row)
            atomic_json(path, row)
        if row['state'] == 'queued': return {**_public(row), 'replayed': True}
        append_event(root, {'event_id': row['event_id'], 'event_type': 'user_input', 'agent': row['scope'],
            'entry': 'local_memory_supplement', 'parent_event_id': parent,
            'occurred_at': row['created_at'], 'captured_at': row['created_at'], 'received_at': row['created_at'],
            'completeness': 'complete', 'payload': {'text': text, 'is_original_user_input': True,
                'supplement_for': request['target_id'], 'source_version': version,
                'attribution': 'local_user_supplement', 'confirmation_authority': False}})
        from memory_pipeline import enqueue
        queue = enqueue(root, event_id=row['event_id'], scope=row['scope'])
        row.pop('record_digest', None)
        row.update(state='queued', queue_id=queue.get('queue_id'), queue_status=queue.get('status'))
        row['record_digest'] = digest(row)
        atomic_json(path, row)
        return {**_public(row), 'replayed': False}


def _public(row):
    return {k: row.get(k) for k in ('operation_id', 'target_id', 'scope', 'parent_event_id',
        'event_id', 'created_at', 'state', 'queue_id', 'queue_status', 'authority')}


def status(root):
    from javis_memory_adapter.review_policy import batch_source_snapshot
    root = Path(root).resolve()
    # Empty installations need no RAW scan; a populated view uses one coherent
    # local snapshot, revalidated on exit and never cached across requests.
    if not any(guarded_path(root, root / 'memory/supplements/items').glob('*.json')):
        return {'items': [], 'invalid_records': 0, 'closed_targets': {}}
    with batch_source_snapshot(root):
        return _status(root)


def _status(root):
    root = Path(root).resolve()
    import json
    rows, invalid = [], 0
    for path in sorted(guarded_path(root, root / 'memory/supplements/items').glob('*.json')):
        try:
            row = json.loads(guarded_path(root, path).read_text())
            if row['record_digest'] != digest({k: v for k, v in row.items() if k != 'record_digest'}):
                raise ValueError('supplement_record_corrupt')
            if path.name != row['operation_id'] + '.json' or row['scope'] not in ROLE_IDS: raise ValueError()
            rows.append(row)
        except (OSError, ValueError, TypeError, KeyError): invalid += 1
    if not rows: return {'items': [], 'invalid_records': invalid, 'closed_targets': {}}
    from memory_screen import load_source
    from memory_autoreview import MemoryAutoreview
    from javis_memory_adapter.review_policy import usable_facts
    review = MemoryAutoreview(root)
    facts = {}
    for scope in {r['scope'] for r in rows}:
        try: facts[scope] = usable_facts(review.review._store(scope))
        except (OSError, ValueError, KeyError): facts[scope] = []
    output, closed = [], {}
    for row in rows:
        result = _public(row)
        try:
            version, parent, source_digest = _target(root, row['target_id'], row['scope'])
            source = load_source(root, row['event_id'])
            if (version != row['target_version'] or parent != row['parent_event_id']
                    or source_digest != row['parent_digest'] or digest(load_source(root, parent)) != source_digest
                    or digest(source.get('payload', {}).get('text')) != row['text_digest']): raise ValueError()
            accepted = [f.fact_id for f in facts[row['scope']] if f.source_event_id == row['event_id']]
            result['state'] = 'accepted_pending_resolution' if accepted else 'awaiting_processing'
            result['accepted_fact_ids'] = accepted
            if accepted:
                result['message_zh'] = '补充已形成记忆，原问题仍待核验'
            # No answer-to-question validator exists yet. A valid memory from
            # this RAW may be unrelated to the target's missing evidence.
            # Keep its fact links visible but do not hide the original task.
        except (OSError, ValueError, KeyError, TypeError): result['state'] = 'source_changed_or_unavailable'
        output.append(result)
    return {'items': output, 'invalid_records': invalid, 'closed_targets': closed}
