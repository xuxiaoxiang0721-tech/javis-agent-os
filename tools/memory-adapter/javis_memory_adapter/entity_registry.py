"""Evidence-bound canonical entities. No fuzzy or same-name identity merging.

PSA certificate numbers are identifiers, not proof of ownership/authenticity.
Project aliases require an explicit alias sentence in an immutable RAW source.
Registry events are append-only and every lookup revalidates their RAW digest.
"""
import json
from pathlib import Path
import re
from .review_policy import guarded_path, source_rows, digest, read_rows, ReviewBlocked
from .runtime import runtime_module
from .normalization import label_key

SCHEMA = 'javis.entity-alias.v1'
PSA = re.compile(r'\bPSA\s*(?:(?:cert(?:ificate)?|证号|证书编号)\s*)?[:#：-]?\s*(\d{7,10})(?!\d)', re.I)


def _path(root, scope):
    if scope not in runtime_module('role_registry').ROLE_IDS:
        raise ReviewBlocked('entity_scope_invalid')
    return guarded_path(root, Path(root) / 'memory/entities' / scope / 'aliases.jsonl')


def _source(root, scope, event_id, text, evidence):
    raw = source_rows(root, [event_id])[event_id]
    if raw.get('agent') != scope:
        raise ReviewBlocked('entity_alias_source_scope_mismatch')
    payload = raw.get('payload') or {}
    texts = [payload.get('text')] + [m.get('text') for m in payload.get('messages', []) if isinstance(m, dict)]
    if text not in texts or not evidence or evidence not in text:
        raise ReviewBlocked('entity_alias_evidence_mismatch')
    return raw


def register_alias(root, scope, *, canonical_name, alias, source_event_id, text, evidence,
                   identifier=None):
    root = Path(root).resolve(); path = _path(root, scope)
    raw = _source(root, scope, source_event_id, text, evidence)
    if not all(isinstance(x, str) and 1 <= len(x) <= 200 for x in (canonical_name, alias)):
        raise ReviewBlocked('entity_alias_label_invalid')
    if identifier:
        matches = {match.group(1) for match in PSA.finditer(evidence)}
        label_ids = {match.group(1) for match in PSA.finditer(alias)}
        if identifier not in matches or label_ids != {identifier}:
            raise ReviewBlocked('entity_identifier_not_supported')
        canonical = 'entity:psa:' + identifier
        basis = 'explicit_psa_certificate_identifier'
    else:
        # Only explicit project naming, not a general identity assertion about
        # people, accounts or physical objects. No pronoun/fuzzy resolution.
        pattern = (r'(?:项目|project)\s*' + re.escape(canonical_name) + r'\s*(?:也叫|又称|别名为|also known as)\s*'
                   + re.escape(alias) + r'(?=$|[。.!！；;，,\s])')
        if not re.search(pattern, evidence, re.I):
            raise ReviewBlocked('entity_alias_explicit_statement_required')
        canonical = 'entity:project:' + digest({'scope': scope, 'name': label_key(canonical_name)})[:32]
        basis = 'explicit_project_alias_statement'
    start = text.find(evidence)
    row = {'schema': SCHEMA, 'scope': scope, 'canonical_id': canonical,
        'canonical_label': canonical_name, 'alias_key': label_key(alias), 'basis': basis,
        'source_event_id': source_event_id, 'source_digest': digest(raw),
        'evidence_span': [start, start+len(evidence)], 'evidence_sha256': digest(evidence),
        'human_confirmed': False}
    row['event_id'] = 'alias_' + digest(row)[:32]
    with runtime_module('runtime_io').lock(guarded_path(root, path.parent / '.registry.lock')):
        existing = read_rows(root, path)
        if not any(item.get('event_id') == row['event_id'] for item in existing):
            path.parent.mkdir(parents=True, exist_ok=True)
            import os
            fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'a', encoding='utf-8') as stream:
                if os.fstat(stream.fileno()).st_nlink != 1:
                    raise ReviewBlocked('entity_registry_hardlink')
                stream.write(json.dumps(row, ensure_ascii=False) + '\n'); stream.flush(); os.fsync(stream.fileno())
    return _resolution(row)


def _resolution(row):
    return {'canonical_id': row['canonical_id'], 'registry_event_id': row['event_id'], 'basis': row['basis'],
        'dependency': {'source_event_id': row['source_event_id'], 'source_digest': row['source_digest'],
            'registry_event_id': row['event_id'], 'canonical_id': row['canonical_id']}}


def resolve_entity(root, scope, *, label, source_event_id, text, evidence):
    ids = {match.group(1) for match in PSA.finditer(label)}
    if len(ids) == 1 and ids <= {match.group(1) for match in PSA.finditer(evidence)}:
        identifier = next(iter(ids))
        return register_alias(root, scope, canonical_name='PSA ' + identifier, alias=label,
            identifier=identifier, source_event_id=source_event_id, text=text, evidence=evidence)
    candidates = []
    for row in read_rows(root, _path(root, scope)):
        if row.get('schema') != SCHEMA or (row.get('alias_key') != label_key(label)
                and label_key(row.get('canonical_label', '')) != label_key(label)):
            continue
        if row.get('event_id') != 'alias_' + digest({k:v for k,v in row.items() if k != 'event_id'})[:32]:
            raise ReviewBlocked('entity_registry_integrity_failed')
        try:
            raw = source_rows(root, [row['source_event_id']])[row['source_event_id']]
            if raw.get('agent') != scope or row.get('scope') != scope or digest(raw) != row['source_digest']:
                continue
        except (ValueError, KeyError):
            continue
        candidates.append(row)
    if len({row['canonical_id'] for row in candidates}) == 1:
        _source(root, scope, source_event_id, text, evidence)
        if label_key(label) not in label_key(evidence):
            return None
        return _resolution(candidates[0])
    return None


def validate_entity_dependencies(root, scope, fact):
    """Validate pinned alias evidence on proposals, writes, recall and rebuild.

The digest in the normalized notes must match both the current RAW and registry
event. Merely adding a fresh RAW pin during a later proposal cannot bless an
identity that was resolved from older evidence (the normalize/propose race).
"""
    from .normalization import metadata
    row = fact if isinstance(fact, dict) else fact.to_dict()
    meta = metadata(row)
    if not meta:
        return True
    dependencies = meta.get('entity_dependencies', [])
    if not isinstance(dependencies, list):
        raise ReviewBlocked('entity_dependencies_invalid')
    expected = {rid: cid for rid, cid in [
        (meta.get('registry_event_id'), meta.get('canonical_id')),
        (meta.get('target_registry_event_id'), meta.get('target_id'))] if rid}
    if not expected and not dependencies:
        return True
    if len(dependencies) != len(expected):
        raise ReviewBlocked('entity_dependencies_missing')
    registry = {item.get('event_id'): item for item in read_rows(root, _path(root, scope))}
    seen = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ReviewBlocked('entity_dependencies_invalid')
        event_id, pin, rid = dependency.get('source_event_id'), dependency.get('source_digest'), dependency.get('registry_event_id')
        item = registry.get(rid)
        if (rid in seen or expected.get(rid) != dependency.get('canonical_id') or item is None
                or item.get('scope') != scope or item.get('canonical_id') != dependency.get('canonical_id')
                or item.get('source_event_id') != event_id or item.get('source_digest') != pin
                or item.get('event_id') != 'alias_' + digest({k:v for k,v in item.items() if k != 'event_id'})[:32]
                or event_id not in (row.get('raw_refs') or [])):
            raise ReviewBlocked('entity_dependencies_mismatch')
        raw = source_rows(root, [event_id])[event_id]
        if raw.get('agent') != scope or digest(raw) != pin:
            raise ReviewBlocked('entity_dependency_source_changed')
        seen.add(rid)
    if seen != set(expected):
        raise ReviewBlocked('entity_dependencies_missing')
    return True
