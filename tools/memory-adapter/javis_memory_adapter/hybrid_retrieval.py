"""Reviewed-ledger retrieval: provider vectors + lexical rank + one-hop relations.

The cache is disposable, model-isolated and bound to each exact fact version.
No vector match establishes authority: every request revalidates the ledger and
RAW bindings first. Missing keys, paused processing and provider errors leave
local keyword/relation recall available with an explicit degradation receipt.
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import math
from pathlib import Path
import re

from .ledger_query import query_semantic_memory
from .normalization import label_key, metadata
from .review_policy import guarded_path, digest, batch_source_snapshot
from .structured_store import StructuredStore
from .runtime import runtime_module, held_error


def lexical_score(text, query):
    text, query = label_key(text), label_key(query)
    words = set(re.findall(r'[a-z0-9_-]{2,}', query))
    for segment in re.findall(r'[\u4e00-\u9fff]+', query):
        words.update(segment[i:i+2] for i in range(max(1, len(segment)-1)))
    return sum(1 for word in words if word and word in text)


def _text(row):
    meta = metadata(row)
    return ' '.join(str(x) for x in [row.get('subject_label'), row.get('predicate'),
        meta.get('raw_predicate'), row.get('value'), row.get('unit'), meta.get('target_label')] if x is not None)


def _nodes(row):
    meta = metadata(row)
    generic = {'原文记录', '来源记录', '用户', 'user', 'source', 'source record', 'record', 'task', 'memory'}
    if row.get('predicate') in {'source_attributed_memory', 'episodic_ref'}:
        return set()
    subject = meta.get('canonical_id') or label_key(row.get('subject_label') or '')
    nodes = {subject} if subject and subject not in generic else set()
    if meta.get('target_id'):
        nodes.add(meta['target_id'])
        if meta.get('target_label_key') not in generic:
            nodes.add(meta['target_label_key'])
    return {x for x in nodes if x}


def _valid_vector(vector, dimensions):
    return (isinstance(vector, list) and len(vector) == dimensions
        and all(type(x) in (int, float) and math.isfinite(x) for x in vector)
        and sum(x*x for x in vector) > 0)


def _cosine(a, b):
    return sum(x*y for x, y in zip(a, b)) / (math.sqrt(sum(x*x for x in a))*math.sqrt(sum(y*y for y in b)))


async def _provider_vectors(root, role, texts, cfg, run_id):
    from openai import AsyncOpenAI
    from .metered_client import MeteredAsyncHttpClient
    from .usage_meter import UsageMeter
    def validate_request(request):
        configuration = runtime_module('memory_model_config')
        fresh = configuration.runtime_embedding_config(root)
        if any(fresh[field] != cfg[field] for field in ('provider', 'revision', 'embedding_model', 'embedding_dimensions')):
            raise configuration.MemoryModelUnavailable('waiting_for_configuration')
        if json.loads(request.content).get('model') != cfg['embedding_model']:
            raise configuration.MemoryModelUnavailable('waiting_for_configuration')
        if str(request.url) != fresh['base_url'] + '/embeddings':
            raise ValueError('memory_embedding_endpoint_changed')
        request.headers['Authorization'] = 'Bearer ' + fresh['api_key']
    http = MeteredAsyncHttpClient(meter=UsageMeter(root), stage='retrieval_embedding',
        model=cfg['embedding_model'], run_id=run_id, scope=role, request_validator=validate_request)
    async with AsyncOpenAI(api_key=cfg['api_key'], base_url=cfg['base_url'], http_client=http) as client:
        value = await client.embeddings.create(model=cfg['embedding_model'],
            input=texts, dimensions=cfg['embedding_dimensions'], encoding_format='float')
        if value.model != cfg['embedding_model']:
            raise ValueError('embedding_model_mismatch')
        ordered = sorted(value.data, key=lambda item: item.index)
        if [item.index for item in ordered] != list(range(len(texts))):
            raise ValueError('embedding_indices_invalid')
        return [item.embedding for item in ordered]


def retrieve(root, role, query, *, limit=10, scopes=None, safe_filter=None,
             vectorizer=None, run_id=None, allow_provider=True):
    """vectorizer is an explicit offline-test seam; production uses metered SDK."""
    root = Path(root).resolve()
    roles = runtime_module('role_registry').ROLE_IDS
    if role not in roles:
        raise ValueError('retrieval_role_required')
    allowed = [role] if role in {'idea-lab', 'friday'} else [role, 'shared']
    scopes = allowed if scopes is None else list(scopes)
    if not set(scopes).issubset(allowed):
        raise ValueError('retrieval_scope_not_authorized')
    if safe_filter is None:
        privacy = runtime_module('task_memory')
        events = privacy._raw_index(root)
        safe_filter = lambda row: privacy._cloud_recall_safe(row, events)
    rows, conflicts = [], []
    # Parse RAW once for this bounded local pass. Context exit rechecks every
    # source file hash before any provider call; no snapshot survives retrieval.
    with batch_source_snapshot(root):
        for scope in scopes:
            base = guarded_path(root, root / 'memory/structured' / scope)
            if not base.exists():
                continue
            store = StructuredStore(base)
            with store.transaction():
                result = query_semantic_memory(store)
                originals = {r['fact_id']: r for r in store._read_jsonl(store.facts_path)}
            conflicted = {fid for c in result['conflicts'] for fid in c.get('fact_ids', [])}
            for c in result['conflicts']:
                ids = c.get('fact_ids') or []
                if ids and all(fid in originals and safe_filter(originals[fid]) for fid in ids):
                    if any(lexical_score(_text(originals[fid]), query) for fid in ids):
                        conflicts.append({**c, 'scope': scope})
            for row in result['facts']:
                original = originals.get(row['fact_id'], row)
                if row['fact_id'] not in conflicted and safe_filter(original):
                    rows.append({**original, 'review_origin': row['review_origin'],
                        'validity_state': row['validity_state'], 'scope': scope})
    normalized = {}
    for row in rows:
        meta = metadata(row)
        if meta and meta.get('cardinality') == 'single':
            normalized.setdefault((row['scope'], meta['subject_label_key'], meta['predicate_key']), []).append(row)
    for (scope, subject, predicate), versions in normalized.items():
        if (len({str(row['value']) for row in versions}) > 1
                and any(lexical_score(_text(row), query) for row in versions)):
            conflicts.append({'scope': scope, 'status': 'possible_conflict',
                'reason': 'source_scoped_identity_unresolved', 'slot': subject + ':' + predicate,
                'fact_ids': [row['fact_id'] for row in versions]})
    lexical = {r['fact_id']: lexical_score(_text(r), query) if query else 1 for r in rows}
    by_id = {r['fact_id']: r for r in rows}
    vector_scores, cached = {}, 0
    status = {'mode': 'keyword_relation', 'degraded': True, 'reason': 'provider_disabled',
              'vector_model': None, 'cached_fact_vectors': 0, 'searched_fact_count': len(rows)}
    if allow_provider and rows and query:
        try:
            privacy = runtime_module('task_memory')
            if not privacy._safe(query) or privacy._explicit_l4(query):
                raise ValueError('retrieval_query_privacy_blocked')
            controls = runtime_module('memory_controls')
            controls.require_processing(root, role, 'retrieval_embedding')
            cfg = runtime_module('memory_model_config').runtime_embedding_config(root)
            model = cfg['embedding_model']; dimensions = cfg['embedding_dimensions']
            status['vector_model'] = model
            provider = cfg['provider']
            status['vector_provider'] = provider
            namespace = hashlib.sha256((provider + '|' + model + '|' + str(dimensions)).encode()).hexdigest()[:24]
            vectors, missing = {}, []
            def cache_path(row):
                version = digest({'scope': row['scope'], 'fact': row})
                return guarded_path(root, root / 'memory/retrieval' / provider / namespace / (version + '.json'))
            for row in rows:
                path = cache_path(row)
                try:
                    value = json.loads(path.read_text(encoding='utf-8')) if path.exists() and path.stat().st_size < 1024*1024 else {}
                except (ValueError, OSError):
                    value = {}
                if (value.get('provider') == provider and value.get('model') == model and value.get('dimensions') == dimensions
                        and _valid_vector(value.get('vector'), dimensions)):
                    vectors[row['fact_id']] = value['vector']; cached += 1
                else:
                    missing.append(row)
            def embed(texts):
                controls.require_processing(root, role, 'retrieval_embedding')
                result = vectorizer(texts) if vectorizer else asyncio.run(_provider_vectors(root, role, texts, cfg, run_id))
                if (not isinstance(result, list) or len(result) != len(texts)
                        or not all(_valid_vector(v, dimensions) for v in result)):
                    raise ValueError('embedding_shape_invalid')
                return result
            # Query first: no corpus indexing expense for an invalid request.
            query_vector = embed([query[:3500]])[0]
            batch_size = 10 if provider == 'dashscope' else 16
            for start in range(0, len(missing), batch_size):
                batch = missing[start:start+batch_size]
                result = embed([_text(row)[:3500] for row in batch])
                for row, vector in zip(batch, result):
                    vectors[row['fact_id']] = vector
                    runtime_module('runtime_io').atomic_json(cache_path(row),
                        {'provider': provider, 'model': model, 'dimensions': dimensions, 'vector': vector})
            vector_scores = {fid: _cosine(vector, query_vector) for fid, vector in vectors.items()}
            status.update(mode='hybrid', degraded=False, reason=None, cached_fact_vectors=cached)
        except Exception as exc:
            held = held_error(exc)
            reason = held.code if held is not None else 'provider_unavailable'
            if str(exc) == 'retrieval_query_privacy_blocked':
                reason = 'query_privacy_blocked'
            status.update(reason=reason, cached_fact_vectors=cached)
    lexical_order = sorted((fid for fid, score in lexical.items() if score), key=lambda fid: (-lexical[fid], fid))
    vector_order = sorted((fid for fid, score in vector_scores.items() if score >= .35), key=lambda fid: (-vector_scores[fid], fid))
    seeds = set(lexical_order[:10] + vector_order[:5])
    seed_nodes = set().union(*(_nodes(by_id[fid]) for fid in seeds)) if seeds else set()
    related = sorted((fid for fid, row in by_id.items() if fid not in seeds and _nodes(row) & seed_nodes))
    scores, channels = {}, {}
    for channel, ordered in [('keyword', lexical_order), ('vector', vector_order), ('relationship', related)]:
        for rank, fid in enumerate(ordered, 1):
            scores[fid] = scores.get(fid, 0) + 1/(60+rank)
            channels.setdefault(fid, []).append(channel)
    selected = sorted(scores, key=lambda fid: (-scores[fid], fid))[:max(0, limit)]
    return {'facts': [{**by_id[fid], 'retrieval_score': scores[fid], 'retrieval_channels': channels[fid]}
                      for fid in selected], 'conflicts': conflicts, 'retrieval': status}
