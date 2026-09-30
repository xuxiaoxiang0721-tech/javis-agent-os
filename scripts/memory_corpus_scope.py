"""Read-only import identity bindings; never authorship or approval evidence."""
from __future__ import annotations
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/memory-adapter'))
from javis_memory_adapter.review_policy import guarded_path, digest
from raw_policy import redact, is_vault_path, is_vault_bytes
from role_registry import ROLE_REGISTRY, ROLE_IDS
from task_memory import _explicit_l4

SCHEMA = 'javis.corpus-scope.v1'
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
MAX_META_BYTES = 256 * 1024


def _path(root, value):
    path = Path(value)
    if '..' in path.parts:
        raise ValueError('scope_path_invalid')
    path = path if path.is_absolute() else root / path
    guarded_path(root, path)
    if not path.resolve().is_relative_to(root):
        raise ValueError('scope_path_outside_root')
    return path


def _cloud_false(value):
    if isinstance(value, dict):
        return value.get('cloud_eligible') is False or any(_cloud_false(v) for v in value.values())
    return isinstance(value, list) and any(_cloud_false(v) for v in value)


def _read(root, path):
    path = _path(root, path)
    if is_vault_path(path):
        raise ValueError('scope_metadata_excluded')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_META_BYTES:
            raise ValueError('scope_metadata_invalid')
        body = stream.read(MAX_META_BYTES + 1)
    if len(body) > MAX_META_BYTES or is_vault_bytes(body):
        raise ValueError('scope_metadata_excluded')
    row = json.loads(body)
    if not isinstance(row, dict):
        raise ValueError('scope_metadata_invalid')
    _, changes = redact(row)
    if changes or _cloud_false(row) or _explicit_l4(row) or '[REDACTED:' in json.dumps(row):
        raise ValueError('scope_metadata_excluded')
    return row, hashlib.sha256(body).hexdigest()


def _evidence(root, path, sha, selector, value):
    return dict(path=str(path.relative_to(root)).replace('\\', '/'), file_sha256=sha,
                selector=[selector], value=value)


def _registry(scope):
    row = ROLE_REGISTRY[scope]
    return {k: row[k] for k in ('role_id', 'bot_id', 'exported_agent_id')}


def _binding(root, group, uid, scope, evidence):
    value = dict(schema=SCHEMA, group_prefix=str(group.relative_to(root)).replace('\\', '/'),
                 scope=scope, agent_id=uid, evidence=evidence, registry=_registry(scope))
    value['binding_digest'] = digest(value)
    return value


@dataclass
class _Index:
    root: Path
    groups: dict


def scope_index(root):
    """One in-memory index per inventory call. No cache or write is persisted."""
    root = Path(root).resolve()
    base = _path(root, root / 'memory/imports')
    direct = {v['exported_agent_id']: k for k, v in ROLE_REGISTRY.items() if v['exported_agent_id']}
    numeric = {v['bot_id']: k for k, v in ROLE_REGISTRY.items() if v['bot_id']}
    identities, profiles, groups = {}, [], {}
    for uid, role in direct.items():
        identities[uid] = [(role, [])]
    if not base.exists():
        return _Index(root, groups)
    # File selectors, not directory aliases, establish upstream identity.
    for namepath in sorted(base.glob('*/grokbot-agents/*/agent-name.json')):
        try:
            name, nh = _read(root, namepath)
            uid = name.get('uuid')
            if not isinstance(uid, str) or not UUID.fullmatch(uid):
                continue
            evidence = [_evidence(root, namepath, nh, 'uuid', uid)]
            profilepath = namepath.parent / 'profile.json'
            numeric_role = None
            if profilepath.exists():
                profile, ph = _read(root, profilepath)
                server = profile.get('serverId')
                numeric_role = numeric.get(str(server)) if type(server) in (str, int) else None
                if numeric_role:
                    bridge = evidence + [_evidence(root, profilepath, ph, 'serverId', server)]
                    identities.setdefault(uid, []).append((numeric_role, bridge))
            profiles.append((namepath.parent, uid, evidence))
        except (OSError, ValueError, TypeError):
            continue
    def identity(uid):
        options = identities.get(uid, [])
        if len({scope for scope, _ in options}) != 1:
            return None
        # Keep every bridge, including duplicate identities: changes to any
        # corroborating evidence must be visible during load-time revalidation.
        return options[0][0], [e for _, evidence in options for e in evidence]
    for group, uid, evidence in profiles:
        selected = identity(uid)
        if selected:
            scope, bridge = selected
            rows = {digest(e): e for e in evidence + bridge}
            groups[str(group.relative_to(root)).replace('\\', '/')] = _binding(root, group, uid, scope, list(rows.values()))
    for path in sorted(base.glob('*/bots/*/BOT-META.json')):
        try:
            row, sha = _read(root, path)
            uid = row.get('agent_id')
            if not isinstance(uid, str) or not UUID.fullmatch(uid):
                continue
            selected = identity(uid)
            if not selected:
                continue
            scope, bridge = selected
            # An explicit competing authorized scope is a conflict, never a hint.
            if any(row.get(k) in ROLE_IDS and row[k] != scope for k in ('scope', 'role_id', 'javis_role')):
                continue
            if any(numeric.get(str(row.get(k))) not in {None, scope} for k in ('bot_id', 'serverId')):
                continue
            evidence = [_evidence(root, path, sha, 'agent_id', uid)] + bridge
            groups[str(path.parent.relative_to(root)).replace('\\', '/')] = _binding(root, path.parent, uid, scope, evidence)
        except (OSError, ValueError, TypeError):
            continue
    return _Index(root, groups)


def resolve_scope_binding(root, path, *, index=None):
    """Return evidence for exactly one recognized import group, or None."""
    root = Path(root).resolve()
    path = _path(root, path)
    rel = path.relative_to(root).parts
    if len(rel) < 6 or rel[:2] != ('memory', 'imports') or rel[3] not in {'bots', 'grokbot-agents'}:
        return None
    if index is None:
        index = scope_index(root)
    if not isinstance(index, _Index) or index.root != root:
        raise ValueError('scope_index_root_mismatch')
    prefix = '/'.join(rel[:5])
    return copy.deepcopy(index.groups.get(prefix))


def verify_scope_binding(root, binding):
    """Rebuild identity evidence and return scope, or fail closed on any drift.

    The caller must separately bind its source path below group_prefix and
    revalidate source bytes/privacy. This evidence conveys no author identity.
    """
    if not isinstance(binding, dict) or binding.get('schema') != SCHEMA:
        raise ValueError('scope_binding_invalid')
    root = Path(root).resolve()
    prefix = binding.get('group_prefix')
    if not isinstance(prefix, str):
        raise ValueError('scope_binding_invalid')
    group = _path(root, prefix)
    rel = group.relative_to(root).parts
    if len(rel) != 5 or rel[:2] != ('memory', 'imports') or rel[3] not in {'bots', 'grokbot-agents'}:
        raise ValueError('scope_binding_invalid')
    current = scope_index(root).groups.get('/'.join(rel))
    if current is None or current != binding:
        raise ValueError('scope_binding_changed_or_excluded')
    return current['scope']
