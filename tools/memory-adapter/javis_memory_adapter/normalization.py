"""Conservative, versioned identities and source spans for NEW verified facts.

Existing ledger rows are never rewritten. Normalized labels are comparison
keys, not a claim that two named people or physical objects are identical.
"""
import hashlib
import json
import re
import unicodedata

VERSION = 'javis-normalization-1'
NOTE_PREFIX = 'memory_structure_v1:'
PREDICATES = {
    'prefers': 'prefers', 'preference': 'prefers', 'has_preference': 'prefers',
    '偏好': 'prefers', 'likes': 'likes', '喜欢': 'likes',
    'owns': 'owns', '拥有': 'owns', 'purchased': 'purchased', '购买': 'purchased',
    'plans': 'plans', '计划': 'plans', 'requires': 'requires', '要求': 'requires',
    'works_for': 'works_for', 'located_in': 'located_in', '位于': 'located_in',
    'has_grade': 'grade', 'grade': 'grade', '评级': 'grade', 'status': 'status',
}


def label_key(value):
    return re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', str(value))).strip().casefold()


def _hash(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:32]


def metadata(row):
    parts = {}
    for note in row.get('notes') or []:
        if isinstance(note, str) and note.startswith(NOTE_PREFIX):
            try:
                checksum, index, count, payload = note[len(NOTE_PREFIX):].split(':', 3)
                parts.setdefault((checksum, int(count)), {})[int(index)] = payload
            except (ValueError, TypeError):
                pass
    for (checksum, count), chunks in parts.items():
        if count < 1 or count > 128 or set(chunks) != set(range(count)):
            continue
        raw = ''.join(chunks[i] for i in range(count))
        if hashlib.sha256(raw.encode()).hexdigest() != checksum:
            continue
        try:
            value = json.loads(raw)
            if isinstance(value, dict) and value.get('version') == VERSION:
                return value
        except ValueError:
            pass
    return {}


def _notes(meta):
    raw = json.dumps(meta, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    chunks = [raw[i:i+100] for i in range(0, len(raw), 100)]
    if len(chunks) > 128:
        raise ValueError('normalization_metadata_too_large')
    checksum = hashlib.sha256(raw.encode()).hexdigest()
    return [NOTE_PREFIX + f'{checksum}:{i}:{len(chunks)}:' + chunk for i, chunk in enumerate(chunks)]


def normalize_verified_fact(edge, *, text, evidence, scope, source_event_id,
                            model=None, statement_kind=None, root=None):
    if not isinstance(evidence, str) or not evidence or evidence not in text:
        raise ValueError('normalization_evidence_not_exact')
    subject, raw_predicate = edge['subject_label'], edge['predicate']
    key = label_key(raw_predicate).replace(' ', '_').replace('-', '_')
    predicate = PREDICATES.get(key) or 'relation_' + _hash(key)[:24]
    target = edge.get('object_label') or edge.get('target_label')
    # Generic or same-named endpoints are not automatically resolved across
    # episodes. Source-scoped IDs preserve distinct objects/people; label keys
    # can retrieve related evidence without pretending to verify identity.
    identity = {'scope': scope, 'source': source_event_id, 'label': label_key(subject)}
    resolution = None
    target_id, target_resolution = None, None
    if root is not None:
        from .entity_registry import resolve_entity
        resolution = resolve_entity(root, scope, label=subject, source_event_id=source_event_id,
            text=text, evidence=evidence)
    if target and label_key(target) in label_key(evidence):
        target_id = 'entity:' + _hash({'scope': scope, 'source': source_event_id, 'label': label_key(target)})
        if root is not None:
            target_resolution = resolve_entity(root, scope, label=target, source_event_id=source_event_id,
                text=text, evidence=evidence)
            if target_resolution:
                target_id = target_resolution['canonical_id']
    start = text.find(evidence)
    meta = {'version': VERSION, 'subject_label_key': label_key(subject),
        'predicate_key': predicate, 'raw_subject_id': edge.get('subject_id'),
        'raw_predicate': raw_predicate, 'target_label': target,
        'target_id': target_id,
        'target_identity_resolution': target_resolution['basis'] if target_resolution else
            'source_scoped_evidence_label' if target_id else 'target_not_in_evidence',
        'target_label_key': label_key(target) if target else None,
        'identity_resolution': 'source_scoped_unresolved',
        'cardinality': 'single' if predicate in {'grade', 'status', 'located_in'} else 'many',
        'evidence': {'source_event_id': source_event_id, 'start': start, 'end': start + len(evidence),
                     'source_text_sha256': hashlib.sha256(text.encode()).hexdigest(),
                     'quote_sha256': hashlib.sha256(evidence.encode()).hexdigest(), 'offset_unit': 'unicode_codepoints'},
        'extraction_model': model, 'statement_kind': statement_kind}
    if resolution:
        meta.update(identity_resolution=resolution['basis'], canonical_id=resolution['canonical_id'],
                    registry_event_id=resolution['registry_event_id'])
    if target_resolution:
        meta['target_registry_event_id'] = target_resolution['registry_event_id']
    dependencies = {r['registry_event_id']: r['dependency'] for r in (resolution, target_resolution) if r}
    meta['entity_dependencies'] = [dependencies[rid] for rid in sorted(dependencies)]
    refs = sorted({source_event_id, *(dependency['source_event_id'] for dependency in dependencies.values())})
    return {'subject_id': resolution['canonical_id'] if resolution else 'entity:' + _hash(identity), 'subject_label': subject[:100],
            'predicate': predicate, 'raw_refs': refs,
            'notes': _notes(meta) + ['identity_resolution:' + meta['identity_resolution']]}
