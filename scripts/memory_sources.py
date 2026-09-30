"""Local, append-only source coverage and legacy provenance; never confirms facts.

This module does not call a model or network. Source maps contain hashes/locations,
not private fact bodies. A matching derived import remains derived evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import mimetypes
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/memory-adapter'))
from javis_memory_adapter.review_policy import guarded_path, safe_id

from raw_policy import CredentialFileBlocked, is_vault_path, sanitize
from raw_storage import _append_line, _read_rows, append_event, now_iso, snapshot_file, stable_id
from runtime_io import lock


def _context_row(root, event_id, scope):
    from javis_memory_adapter.review_policy import source_rows
    from role_registry import ROLE_IDS
    root = Path(root).resolve(); safe_id(event_id); safe_id(scope)
    if scope not in ROLE_IDS and scope != 'shared': raise ValueError('unknown_source_scope')
    row = source_rows(root, [event_id])[event_id]
    declared = {row[k] for k in ('agent','scope','role_id') if isinstance(row.get(k),str) and row[k]}
    if not declared and isinstance(row.get('task_id'),str):
        safe_id(row['task_id'])
        path = guarded_path(root, root/'state/tasks'/(row['task_id']+'.json'))
        if path.exists():
            task = json.loads(path.read_bytes())
            if task.get('task_id') != row['task_id']: raise ValueError('source_task_identity_mismatch')
            declared = {task[k] for k in ('role_id','role','agent') if isinstance(task.get(k),str) and task[k]}
    if declared != {scope}: raise ValueError('source_scope_mismatch_or_unknown')
    return root, row


def _snapshot_refs(root, row):
    """Only direct immutable references or same-task input files, never a global lookup grant."""
    payload = row.get('payload') if isinstance(row.get('payload'),dict) else {}
    explicit = set()
    def refs(value):
        if isinstance(value,dict):
            sid = value.get('snapshot_id')
            if isinstance(sid,str):explicit.add(sid)
            for k in ('attachments','input_refs','evidence_refs'):
                if k in value:refs(value[k])
        elif isinstance(value,list):
            for x in value:refs(x)
    refs(row.get('evidence_refs',[]));refs(payload)
    result = {}; task = row.get('task_id')
    for path in sorted(guarded_path(root,root/'raw/manifests').glob('objects-*.jsonl')):
        for snap in _rows(guarded_path(root,path)):
            own_task = isinstance(task,str) and task and snap.get('task_id') == task
            direct_event = isinstance(snap.get('source_locator'),dict) and snap['source_locator'].get('event_id') == row['event_id']
            selected = snap.get('snapshot_id') in explicit
            if not (direct_event or own_task and (selected or snap.get('relation')=='input')):continue
            if selected and task and not own_task: raise ValueError('snapshot_source_mismatch')
            sid=snap.get('snapshot_id');safe_id(sid)
            if sid in result and _digest(result[sid])!=_digest(snap):raise ValueError('ambiguous_snapshot')
            result[sid]=snap
    if explicit-set(result):raise ValueError('source_snapshot_missing_or_unbound')
    modern=[snap for snap in result.values() if snap.get('preservation_scope')=='new_capture_only_no_historical_reconstruction']
    if modern:
        from javis_memory_adapter.review_policy import source_rows
        receipts=source_rows(root,[stable_id(snap['snapshot_id']) for snap in modern])
        for snap in modern:
            receipt=receipts[stable_id(snap['snapshot_id'])]
            if receipt.get('event_type')!='file_snapshot' or _digest(receipt.get('payload'))!=_digest(snap):
                raise ValueError('snapshot_manifest_receipt_mismatch')
    return list(result.values())


def source_context(root, event_id, scope):
    """Read-only owner/local UI view. Never promotes authorship or returns private originals.

    The caller authenticates access. This function independently binds the exact
    source scope, revalidates corpus origins and returns only safe text/receipts.
    """
    from raw_storage import _local_sensitive, _read_regular
    from raw_policy import redact
    from raw_time import semantic_source_time
    from memory_corpus import text_fields, selected_provenance, selected_time
    root,row=_context_row(root,event_id,scope)
    sensitive=_local_sensitive(row)
    safe,context_redactions=redact(row);payload=safe.get('payload') if isinstance(safe.get('payload'),dict) else {}
    texts=[];gaps=[]
    if sensitive:gaps.append('source_local_only_use_controlled_original_access')
    else:
        fields=text_fields(safe)
        if safe.get('event_type')=='corpus_text' and isinstance(payload.get('text'),str):
            fields=[(['payload','text'],payload['text'],payload.get('source_kind','source_bound_adaptation'))]
        elif safe.get('event_type')=='grok_direct_capture':
            fields=[(['payload','messages',i,'text'],m['text'],'unverified_message') for i,m in enumerate(payload.get('messages',[])) if isinstance(m,dict) and isinstance(m.get('text'),str)]
        for selector,text,nature in fields:
            provenance=selected_provenance(safe,selector)
            fidelity='credential_redacted_copy' if row.get('redactions') or context_redactions or row.get('raw_preservation',{}).get('content_form')=='credential_redacted_copy' else 'derived' if nature in {'derived_memory','model_output','model_derived','derived_summary','derived_log_fragment','structured_tool_observation'} else 'source_bound_adaptation' if safe.get('event_type')=='corpus_text' else 'recorded_text'
            texts.append({'text':text,'selector':selector,'sha256':hashlib.sha256(text.encode()).hexdigest(),
                'utf8_bytes':len(text.encode()),'fidelity':fidelity,'source_nature':nature,
                'location':{'selector':selector,'char_start':0,'char_end':len(text),'byte_start':0,'byte_end':len(text.encode())},
                'source_time':selected_time(safe,selector),'provenance':provenance,
                'authorship_verified':row.get('event_type')=='user_input' and selector==['payload','text'] and payload.get('is_original_user_input') is True})
    attachments=[]
    for snap in _snapshot_refs(root,row):
        digest=snap.get('sha256')
        if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('invalid_snapshot_hash')
        path=guarded_path(root,root/'raw/objects'/digest)
        data=_read_regular(path)
        if hashlib.sha256(data).hexdigest()!=digest or len(data)!=snap.get('size'):raise ValueError('snapshot_object_changed')
        original=snap.get('original')
        if not isinstance(original,dict):
            original={'sha256':digest,'size':len(data),'storage':'raw_object' if snap.get('content_form')=='source_bytes' else 'unavailable',
                'available':snap.get('content_form')=='source_bytes','fidelity':'legacy_capture_unverified_original'}
        public_original={k:original.get(k) for k in ('sha256','size','storage','available','fidelity','restore_dependency') if k in original}
        public_original['cloud_eligible']=False  # view permission is never cloud permission
        attachments.append({k:snap.get(k) for k in ('snapshot_id','artifact_id','sha256','size','original_name','relation','content_form','source_locator','derived_from','version','captured_at')} | {'original':public_original})
        if Path(str(snap.get('original_name',''))).suffix.lower() in {'.pdf','.png','.jpg','.jpeg','.tif','.tiff','.webp'} and not snap.get('derived_from'):
            gaps.append('ocr_or_document_text_derivative_not_recorded')
    if not texts and not sensitive:gaps.append('text_body_not_available_in_supported_source_fields')
    if 'attachments' not in payload and not attachments:gaps.append('attachment_inventory_unknown')
    missing=safe.get('missing_reason')
    if isinstance(missing,str):gaps.extend(x for x in missing.split(';') if re.fullmatch(r'[A-Za-z0-9_:-]{1,120}',x))
    event_original=row.get('raw_preservation',{}).get('original') if isinstance(row.get('raw_preservation'),dict) else None
    locator_keys={'path','source_path','file_sha256','record_sha256','line','line_number','byte_start','byte_end','page',
                  'selector','kind','source_digest','content_sha256','original_event_id','adapter_item_id'}
    reference=payload.get('source_reference')
    source_locator={k:v for k,v in reference.items() if k in locator_keys} if isinstance(reference,dict) else None
    evidence_locations=[{k:v for k,v in item.items() if k in locator_keys} for item in safe.get('evidence_refs',[]) if isinstance(item,dict)]
    return {'schema':'javis.source-context.v1','event_id':event_id,'scope':scope,'source_digest':_digest(row),
        'event_type':safe.get('event_type'),'texts':texts,'attachments':attachments,'source_locator':source_locator,'evidence_locations':evidence_locations,
        'times':{'occurred_at':semantic_source_time(row),'captured_at':safe.get('captured_at'),'time_basis':safe.get('time_basis')},
        'event_original':{k:event_original.get(k) for k in ('sha256','size','storage','available','fidelity','restore_dependency')} if isinstance(event_original,dict) else None,
        'gaps':sorted(set(gaps)),'confirmation_authority':False,'model_processed_by_this_call':False}


def resolve_original(root, event_id, scope, snapshot_id=None, *, allow_sensitive=False):
    """Return locally bound bytes. No generic path/URL arguments are accepted.

    With snapshot_id=None only a sealed original event can be resolved, and it
    requires the explicit local sensitive capability. Never expose that flag in
    an ordinary web request; the server's download route must retain False.
    """
    from raw_storage import read_preserved_original, _local_sensitive
    root,row=_context_row(root,event_id,scope)
    if _local_sensitive(row) and not allow_sensitive:raise ValueError('sensitive_original_local_access_required')
    if snapshot_id is None:
        reference=row.get('raw_preservation',{}).get('original') if isinstance(row.get('raw_preservation'),dict) else None
        if not isinstance(reference,dict):raise ValueError('event_original_not_preserved_before_v3')
        name='source-event.json';mime='application/json';fidelity='exact_submitted_event_json_not_transport_bytes'
    else:
        safe_id(snapshot_id)
        match=[x for x in _snapshot_refs(root,row) if x.get('snapshot_id')==snapshot_id]
        if len(match)!=1:raise ValueError('snapshot_not_bound_to_source')
        snap=match[0];reference=snap.get('original')
        if not isinstance(reference,dict):
            if snap.get('content_form')!='source_bytes':raise ValueError('legacy_original_unproven')
            reference={'storage':'raw_object','sha256':snap['sha256'],'size':snap['size']}
        name=Path(str(snap.get('original_name') or 'original.bin')).name
        mime=mimetypes.guess_type(name)[0] or 'application/octet-stream'
        fidelity='exact_captured_derived_bytes_not_source_document' if snap.get('derived_from') else 'exact_original_bytes'
    data=read_preserved_original(root,reference,allow_sensitive=allow_sensitive)
    return {'bytes':data,'filename':name,'mime_type':mime,'sha256':hashlib.sha256(data).hexdigest(),
        'fidelity':fidelity,'local_only':True}


def segment_text(text, max_chars=12000, overlap=400):
    """Exact bounded slices; offsets bind to whole text, never invented pages/times."""
    if not isinstance(text,str) or isinstance(max_chars,bool) or not isinstance(max_chars,int) or max_chars<1 or max_chars>200000:
        raise ValueError('invalid_segment_size')
    if isinstance(overlap,bool) or not isinstance(overlap,int) or overlap<0 or overlap>=max_chars:raise ValueError('invalid_overlap')
    bodyhash=hashlib.sha256(text.encode()).hexdigest();result=[];start=0;byte_start=0
    while start<len(text):
        end=min(len(text),start+max_chars);part=text[start:end]
        result.append({'index':len(result),'text':part,'source_sha256':bodyhash,'sha256':hashlib.sha256(part.encode()).hexdigest(),
            'char_start':start,'char_end':end,'byte_start':byte_start,'byte_end':byte_start+len(part.encode()),'context_overlap_chars':0 if start==0 else overlap})
        if end==len(text):break
        advance=end-overlap-start;byte_start+=len(text[start:start+advance].encode());start+=advance
    return result


def coverage_reconcile(root, previous_inventory=None):
    """Read-only counts and dated-inventory delta. Does not enqueue or run a model."""
    from raw_storage import _read_regular
    from role_registry import ROLE_IDS
    root=Path(root).resolve();by_role=Counter();by_type=Counter();ids={};missing=0;invalid=0;rawbytes=0
    rawbase=guarded_path(root,root/'raw/events')
    rawfiles=sorted(rawbase.rglob('*.jsonl')) if rawbase.exists() else []
    for path in rawfiles:
        data=_read_regular(guarded_path(root,path));rawbytes+=len(data)
        for line in data.split(b'\n'):
            if not line.strip():continue
            try:row=json.loads(line)
            except (ValueError,UnicodeError):invalid+=1;continue
            if not isinstance(row,dict):invalid+=1;continue
            by_role[row.get('agent') if row.get('agent') in ROLE_IDS else 'unresolved']+=1
            typ=row.get('event_type');by_type[typ if isinstance(typ,str) and re.fullmatch(r'[A-Za-z0-9_:-]{1,100}',typ) else 'untyped_legacy']+=1
            eid=row.get('event_id')
            if not isinstance(eid,str) or not eid:missing+=1
            else:ids.setdefault(eid,[]).append(_digest(row))
    if previous_inventory is not None and not isinstance(previous_inventory,dict):raise ValueError('previous_inventory_must_be_metadata_mapping')
    known={r['path']:r.get('sha256') for r in (previous_inventory or {}).get('files',[]) if isinstance(r,dict) and isinstance(r.get('path'),str)}
    imports=[];excluded=Counter()
    base=guarded_path(root,root/'memory/imports')
    if base.exists():
        for folder,dirs,names in os.walk(base,followlinks=False):
            kept=[]
            for d in dirs:
                p=Path(folder)/d
                if p.is_symlink() or d.lower() in SKIP_DIRS or d.startswith('.'):excluded['excluded_directory_or_link']+=1
                else:kept.append(d)
            dirs[:]=kept
            for name in names:
                p=Path(folder)/name
                if p.is_symlink() or is_vault_path(p) or name.lower() in CREDENTIAL_NAMES or name.lower().startswith('.env.') or p.suffix.lower() in {'.key','.p12','.pfx','.pem'}:
                    excluded['credential_or_link']+=1;continue
                if not p.is_file():continue
                if p.stat().st_nlink!=1:excluded['hardlink']+=1;continue
                data=_read_regular(guarded_path(root,p))
                from raw_policy import is_vault_bytes
                if is_vault_bytes(data):excluded['vault_signature_not_part_of_memory_corpus']+=1;continue
                path=p.relative_to(root).as_posix();digest=hashlib.sha256(data).hexdigest()
                imports.append({'path':path,'sha256':digest,'bytes':len(data),'group':p.relative_to(base).parts[0],
                    'inventory_state':'not_previously_inventoried' if path not in known else 'unchanged' if known[path]==digest else 'changed_or_previous_hash_unavailable'})
    runs={};runpath=guarded_path(root,root/'memory/screen/runs.jsonl')
    for r in _rows(runpath):
        if isinstance(r.get('run_id'),str):runs[r['run_id']]=r
    screened={r.get('event_id') for r in runs.values()}-{None}
    queue=Counter()
    for p in guarded_path(root,root/'state/memory-pipeline/queue').glob('*.json'):
        try:r=json.loads(_read_regular(guarded_path(root,p)));s=r.get('status');queue[s if s in {'queued','running','retry','completed','blocked','needs_review','waiting_for_key','waiting_for_configuration','held','credentials_rejected'} else 'invalid']+=1
        except (ValueError,TypeError):queue['invalid']+=1
    return {'schema':'javis.source-coverage.v3','generated_at':now_iso(),'read_only':True,'model_calls':0,'enqueued':0,
        'raw':{'files':len(rawfiles),'bytes':rawbytes,'rows':sum(by_type.values()),'unique_event_ids':len(ids),'missing_event_id':missing,
            'duplicate_nonempty_event_ids':sum(len(v)-1 for v in ids.values()),'conflicting_event_ids':sum(len(set(v))>1 for v in ids.values()),
            'invalid_json_records':invalid,'by_role':dict(by_role),'by_event_type':dict(by_type)},
        'imports':{'files':len(imports),'bytes':sum(x['bytes'] for x in imports),'by_inventory_state':dict(Counter(x['inventory_state'] for x in imports)),
            'by_group':dict(Counter(x['group'] for x in imports)),'excluded':dict(excluded),'files_metadata':imports},
        'processing':{'unique_screen_runs':len(runs),'unique_screened_sources':len(screened),'queue':dict(queue)},
        'boundary':'Preservation inventory is not model processing coverage; native import records require a new local corpus inventory before a whole-history processing claim.'}

SCHEMA = 'javis-memory-source-1'
KINDS = {'original_message', 'tool_result', 'artifact', 'legacy_memory',
         'derived_memory', 'import_metadata', 'unknown'}
SKIP_DIRS = {'backups', 'backup', '.git', '.codex', 'secrets', 'credentials',
             'javis-vault', 'node_modules', '__pycache__'}
TEXT_EXT = {'.json', '.jsonl', '.md', '.txt'}
MAX_IMPORT_BYTES = 64 * 1024 * 1024
CREDENTIAL_NAMES = {'auth.json', 'credentials.json', 'id_rsa', 'id_ed25519', '.env'}


def _digest(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return hashlib.sha256(value).hexdigest()


def _snapshot_source(root, path, data, artifact_id, relation):
    """Same current bytes replay; A -> B -> A is a third observed version."""
    previous = None
    manifests = [guarded_path(root, p) for p in sorted(guarded_path(root, root / 'raw/manifests').glob('objects-*.jsonl'))]
    for row in _read_rows(manifests):
        if row.get('artifact_id') == artifact_id:
            previous = row
    prefix = 'content:' + _digest(data) + ':'
    capture_key = previous.get('capture_key', '') if previous else ''
    if not capture_key.startswith(prefix):
        capture_key = prefix + (previous['snapshot_id'] if previous else 'initial')
    return snapshot_file(root, path, 'memory-source-audit', source_path=path.relative_to(root).as_posix(),
        artifact_id=artifact_id, capture_key=capture_key, relation=relation, captured_bytes=data)


def _rows(path):
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding='utf-8').split('\n'):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            # A damaged ledger must not silently erase previous gap history.
            raise ValueError('source_audit_ledger_corrupt:' + path.name) from exc
        if not isinstance(row, dict):
            raise ValueError('source_audit_ledger_non_object:' + path.name)
        out.append(row)
    return out


def _state(root):
    maps = _rows(guarded_path(root, root / 'memory/provenance/sources.jsonl'))
    gaps = _rows(guarded_path(root, root / 'memory/provenance/gaps.jsonl'))
    return ({r['source_key']: r for r in maps}, {r['gap_id']: r for r in gaps})


def _safe_local(root, path):
    path = Path(path)
    if not path.is_absolute():
        path = root / path
    resolved = path.resolve()
    if not resolved.is_relative_to(root.resolve()) or is_vault_path(path) or path.name.casefold() in CREDENTIAL_NAMES:
        raise ValueError('source_path_outside_allowed_root')
    if any(p.casefold() in SKIP_DIRS for p in path.relative_to(root).parts):
        raise ValueError('source_path_excluded')
    # Never follow a link to a secret or an unselected data tree.
    if any(p.is_symlink() for p in (path, *path.parents) if p != root.parent):
        raise ValueError('source_symlink_excluded')
    return guarded_path(root, path)


def _guard_outputs(root):
    for rel in ('memory/provenance/sources.jsonl', 'memory/provenance/gaps.jsonl',
                'state/locks/memory-sources.lock', 'state/locks/raw-append.lock',
                'state/locks/raw-object.lock', 'raw/events', 'raw/manifests', 'raw/objects'):
        guarded_path(root, root / rel)
    # RAW helpers also read existing manifests/events. Refuse links before reuse.
    for rel in ('raw/events', 'raw/manifests', 'raw/objects'):
        for path in (root / rel).glob('*'):
            guarded_path(root, path)


def _ensure_not_held(root):
    # Call only while the caller holds the shared maintenance lock.
    from task_service import ensure_not_held
    guarded_path(root, root / 'state/recovery-hold.json')
    ensure_not_held(root)


def _source_time(record):
    value = record.get('occurred_at') or record.get('source_time') or record.get('timestamp')
    if value:
        try:
            parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
            if parsed.tzinfo is not None:
                return parsed.isoformat().replace('+00:00', 'Z')
        except (ValueError, TypeError):
            pass
    ms = record.get('timestampMs')
    if isinstance(ms, (int, float)) and not isinstance(ms, bool):
        try:
            return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat().replace('+00:00', 'Z')
        except (ValueError, OverflowError, OSError):
            pass
    return None


def _body(record):
    for key in ('body', 'content', 'text', 'fact'):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, list):
            parts = [p.get('text', '') for p in value if isinstance(p, dict) and p.get('type') in ('text', 'input_text', 'output_text')]
            if any(parts):
                return '\n'.join(parts)
    message = record.get('message')
    return _body(message) if isinstance(message, dict) else (message if isinstance(message, str) else None)


def _attachment_gaps(root, record):
    gaps, refs = set(), []
    attachments = record.get('attachments')
    if attachments is None or not isinstance(attachments, list):
        return {'attachment_inventory_unknown'}, []
    expected = record.get('attachment_count')
    if isinstance(expected, int) and expected > len(attachments):
        gaps.add('missing_attachment')
    for attachment in attachments:
        if not isinstance(attachment, dict):
            gaps.add('missing_attachment')
            continue
        sha = attachment.get('sha256') or attachment.get('object_sha256')
        ref = {'attachment_id': attachment.get('id'), 'expected_sha256': sha}
        path = attachment.get('path') or attachment.get('local_path')
        try:
            target = _safe_local(root, path) if path else None
        except ValueError:
            target = None
            gaps.add('attachment_path_unavailable')
        if target and target.is_file():
            actual = _digest(target.read_bytes())
            ref.update(path=str(target.relative_to(root)), original_sha256=actual)
            if sha and actual != sha:
                gaps.add('attachment_hash_mismatch')
        elif isinstance(sha, str) and len(sha) == 64 and all(c in '0123456789abcdef' for c in sha):
            obj = root / 'raw/objects' / sha
            if not obj.is_file() or _digest(obj.read_bytes()) != sha:
                gaps.add('missing_attachment')
            else:
                ref['object_sha256'] = sha
        else:
            gaps.add('missing_attachment')
        refs.append(ref)
    return gaps, refs


def _observation(root, source_key, record, source_kind, source_ref, extra_gaps):
    if source_kind not in KINDS:
        raise ValueError('unknown_source_kind')
    if not source_key or not isinstance(record, dict):
        raise ValueError('source_key_and_record_required')
    source_time = _source_time(record)
    native_id = record.get('source_event_id') or record.get('message_id') or record.get('id')
    gaps = set(extra_gaps)
    if not _body(record):
        gaps.add('missing_body')
    if not source_time:
        gaps.add('missing_source_time')
    if not native_id:
        gaps.add('missing_source_id')
    attachment_gaps, attachment_refs = _attachment_gaps(root, record)
    gaps.update(attachment_gaps)
    if source_kind in {'legacy_memory', 'derived_memory', 'unknown'}:
        gaps.add('original_conversation_unproven')
    return sanitize({'schema_version': SCHEMA, 'source_key': source_key,
        'source_kind': source_kind, 'original_conversation': source_kind == 'original_message',
        'record_sha256': _digest(record), 'native_source_id': native_id,
        'source_time': source_time, 'source_ref': source_ref or {},
        'attachment_refs': attachment_refs, 'missing': sorted(gaps),
        'memory_status': 'provenance_only', 'cloud_eligible': False})


def _commit(root, observation, states):
    maps, gaps = states
    source_key = observation['source_key']
    previous = maps.get(source_key)
    signature = _digest(observation)
    changed = not previous or previous.get('observation_sha256') != signature
    if changed:
        row = {**observation, 'observation_sha256': signature, 'observed_at': now_iso(),
               'version': (previous['version'] + 1) if previous else 1,
               'previous_observation_sha256': previous.get('observation_sha256') if previous else None}
        _append_line(guarded_path(root, root / 'memory/provenance/sources.jsonl'), row)
        maps[source_key] = row
    else:
        row = previous
    # Replay repairs a crash between committing the source map and its gap audit.
    old_missing = {g['reason'] for g in gaps.values() if g['source_key'] == source_key and g['status'] == 'open'}
    current_missing = set(observation['missing'])
    for reason in sorted(old_missing | current_missing):
        gap_id = 'gap-' + _digest([source_key, reason])[:24]
        status = 'open' if reason in current_missing else 'resolved'
        prior = gaps.get(gap_id)
        if prior and prior['status'] == status:
            continue
        gap = {'schema_version': SCHEMA, 'gap_id': gap_id, 'source_key': source_key,
               'reason': reason, 'status': status, 'observed_at': now_iso(),
               'source_version': row['version'], 'transition': prior.get('transition', 0) + 1 if prior else 1,
               'resolution_basis': None if status == 'open' else row['observation_sha256']}
        _append_line(guarded_path(root, root / 'memory/provenance/gaps.jsonl'), gap)
        gaps[gap_id] = gap
    append_event(root, {'event_id': stable_id('memory-source-observation', source_key, row['version'], signature),
        'event_type': 'source_coverage', 'entry': 'memory_sources', 'occurred_at': row['observed_at'],
        'completeness': 'partial' if observation['missing'] else 'complete',
        'missing_reason': ';'.join(observation['missing']) or None, 'payload': row})
    return {**row, 'changed': changed}


def reconcile_source(root, source_key, record, source_kind='unknown', *, apply=False,
                     source_ref=None, extra_gaps=()):
    """Observe a source; repeated identical observations do not add rows.

    The caller chooses a stable, connector-scoped source_key. The native ID and
    source timestamp must come from the source, never a capture clock. On apply,
    a redacted RAW record plus source/gap history are written. No facts are saved.
    """
    root = Path(root).resolve()
    observation = _observation(root, source_key, record, source_kind, source_ref, extra_gaps)
    if not apply:
        return observation
    with lock(guarded_path(root, root / 'state/maintenance.lock'), shared=True), \
         lock(guarded_path(root, root / 'state/locks/memory-sources.lock')):
        _ensure_not_held(root)
        _guard_outputs(root)
        for ref in observation['attachment_refs']:
            if not ref.get('path'):
                continue
            try:
                target = _safe_local(root, ref['path'])
                data = target.read_bytes()
                if _digest(data) != ref['original_sha256']:
                    observation['missing'] = sorted(set(observation['missing']) | {'attachment_changed_during_capture'})
                    continue
                snap = _snapshot_source(root, target, data,
                    'source-attachment-' + _digest([source_key, ref['path']])[:24], 'source_attachment')
                ref.update(snapshot_id=snap['snapshot_id'], object_sha256=snap['sha256'], content_form=snap['content_form'])
            except CredentialFileBlocked:
                observation['missing'] = sorted(set(observation['missing']) | {'credential_file_capture_blocked'})
        append_event(root, {'event_id': stable_id('source-record', source_key, observation['record_sha256']),
            'event_type': 'source_record', 'entry': 'memory_sources', 'occurred_at': observation['source_time'],
            'source_event_id': observation['native_source_id'], 'completeness': 'partial' if observation['missing'] else 'complete',
            'missing_reason': ';'.join(observation['missing']) or None,
            'payload': {'source_kind': source_kind, 'source_key': source_key, 'record': record,
                        'source_ref': source_ref or {}, 'cloud_eligible': False}})
        return _commit(root, observation, _state(root))


def legacy_gate_enabled(root):
    """Missing config preserves old installations; malformed config fails closed."""
    root = Path(root).resolve()
    path = guarded_path(root, root / 'config/memory-pipeline.json')
    if not path.exists():
        return False
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict) or type(value.get('enabled', False)) is not bool:
        raise ValueError('invalid_memory_pipeline_gate_config')
    return value.get('enabled', False)


def stage_legacy_candidate(root, record, *, source_key=None, source_ref=None):
    """Retain an old write request as a replayable, unconfirmed local candidate.

    Caller actor/tier/RAW references are historical claims, not owner authority.
    The source event proves only what the old importer submitted to this function.
    """
    root = Path(root).resolve()
    role = record.get('role_id') or record.get('role') or 'shared'
    role = 'idea-lab' if role == 'ide-lab' else role
    safe_id(role)
    if not isinstance(record.get('fact'), str) or not record['fact'].strip():
        raise ValueError('legacy_candidate_fact_required')
    # Capture-time defaults and generated legacy IDs must not defeat replay.
    claim = {k: v for k, v in record.items() if k not in {'created_at', 'memory_id', 'confirmed_at', 'confirmed_by'}}
    source_key = source_key or 'legacy-cli:' + _digest(claim)
    candidate_id = 'm-pending-' + _digest([source_key, claim])[:24]
    path = guarded_path(root, root / 'memory/candidates/by-role' / role / 'facts.jsonl')
    with lock(guarded_path(root, root / 'state/maintenance.lock'), shared=True), \
         lock(guarded_path(root, root / 'state/locks/legacy-memory-candidates.lock')):
        _ensure_not_held(root)
        observation = reconcile_source(root, source_key, claim, 'derived_memory',
            apply=True, source_ref=source_ref, extra_gaps=('owner_review_required',))
        raw_id = stable_id('source-record', source_key, observation['record_sha256'])
        previous = next((r for r in _rows(guarded_path(root, path)) if r.get('memory_id') == candidate_id), None)
        if previous is None:
            claimed_source = record.get('source') or {}
            temporal = record.get('temporal') or {
                'as_of': record.get('as_of'), 'learned_at': record.get('learned_at'),
                'valid_from': None, 'valid_to': None, 'kind': 'open_ended'}
            candidate = sanitize({'schema_version': 'javis-memory-2', 'memory_id': candidate_id,
                'tier': 'candidate', 'role_id': role, 'fact': record['fact'],
                'kind': record.get('kind', 'fact'), 'memory_class': record.get('memory_class', 'semantic'),
                'confidence': 'low' if record.get('confidence') == 'low' else 'medium',
                'sensitivity': record.get('sensitivity', 'normal'), 'temporal': temporal,
                'source': {'raw_event_ids': [raw_id], 'source_key': source_key,
                           'claimed_legacy_source': claimed_source, 'source_kind': 'derived_memory',
                           'original_evidence_verified': False},
                'created_at': now_iso(), 'confirmed_at': None, 'confirmed_by': None,
                'tags': record.get('tags', []), 'supersedes': None,
                'requested_supersedes': record.get('supersedes'),
                'memory_status': 'pending_evidence_and_owner_review',
                'cloud_eligible': False, 'missing': observation['missing']})
            _append_line(guarded_path(root, path), candidate)
        return {'ok': True, 'status': 'pending_evidence_and_owner_review',
            'requested_tier': record.get('tier', 'confirmed'), 'effective_tier': 'candidate',
            'confirmed_written': 0, 'candidate_written': int(previous is None),
            'replayed': previous is not None, 'path': str(path), 'memory_id': candidate_id,
            'source_event_id': raw_id, 'cloud_eligible': False}


def _files(base):
    """Only explicit import/confirmed roots; no links, backups or hidden trees."""
    if not base.is_dir() or base.is_symlink():
        return
    for current, dirs, files in os.walk(base, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d.casefold() not in SKIP_DIRS and not d.startswith('.') and not (Path(current) / d).is_symlink())
        for name in sorted(files):
            path = Path(current) / name
            if not name.startswith('.') and name.casefold() not in CREDENTIAL_NAMES and not path.is_symlink() and not is_vault_path(path) and path.stat().st_nlink == 1:
                yield path


def _kind(path):
    parts = {s.casefold() for s in path.parts}
    if path.name.lower().startswith(('manifest', 'summary', 'apply-confirmed-result')):
        return 'import_metadata'
    if ('transcripts' in parts or 'sessions' in parts) and path.suffix == '.jsonl':
        return 'original_message'  # Individual records still need message role/body.
    return 'derived_memory'


def _records(data, suffix):
    """Yield parsed records with original byte offsets; invalid records stay visible."""
    if suffix == '.jsonl':
        offset = 0
        for number, raw in enumerate(data.splitlines(keepends=True), 1):
            location = {'line': number, 'byte_start': offset, 'byte_end': offset + len(raw), 'record_bytes_sha256': _digest(raw)}
            offset += len(raw)
            if not raw.strip():
                continue
            try:
                item = json.loads(raw)
                yield (item if isinstance(item, dict) else None), location
            except (ValueError, UnicodeError):
                yield None, location
    elif suffix == '.json':
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError):
            yield None, {'byte_start': 0, 'byte_end': len(data)}
            return
        rows = value if isinstance(value, list) else [value]
        for n, row in enumerate(rows):
            if isinstance(row, dict):
                yield row, {'json_pointer': '/' + str(n) if isinstance(value, list) else ''}


def audit_legacy(root, apply=False):
    """Inventory import originals and map old facts to exact local matches.

    A byte/content match proves only that the bytes occur in that source. It does
    not prove truth, ownership, consent, or a confirmed memory. Dry-run writes
    nothing. Output never includes fact or message bodies. Apply snapshots legacy
    files and matching evidence files, keeping original and stored hashes apart.
    """
    root = Path(root).resolve()
    imports = guarded_path(root, root / 'memory/imports')
    index = defaultdict(list)
    inventory, issues, source_data = [], [], {}
    stats = Counter()
    for path in _files(imports):
        rel = path.relative_to(root).as_posix()
        stats['import_files_seen'] += 1
        if path.suffix.lower() not in TEXT_EXT or path.stat().st_size > MAX_IMPORT_BYTES:
            stats['import_files_excluded_format_or_size'] += 1
            continue
        data = path.read_bytes()
        info = {'path': rel, 'original_sha256': _digest(data), 'size': len(data), 'source_kind': _kind(path)}
        inventory.append(info)
        source_data[rel] = data
        for record, location in _records(data, path.suffix):
            if record is None:
                issues.append({'path': rel, **location, 'reason': 'invalid_import_record'})
                continue
            body = _body(record)
            kind = info['source_kind']
            message = record.get('message')
            role = record.get('role') or (message.get('role') if isinstance(message, dict) else None)
            if kind == 'original_message' and role not in {'user', 'assistant', 'system', 'tool'}:
                kind = 'unknown'
            if body:
                index[_digest(body)].append({**info, **location, 'source_kind': kind,
                    'match_basis': 'exact_field_content', 'native_source_id': record.get('id') or record.get('message_id'),
                    'source_time': _source_time(record), 'speaker_role': role})
        if path.suffix.lower() in {'.md', '.txt'} and info['source_kind'] != 'import_metadata':
            offset = 0
            for number, raw in enumerate(data.splitlines(keepends=True), 1):
                # No substring/fuzzy match: a claim cannot be "matched" inside a negation.
                try:
                    text = raw.decode('utf-8').strip()
                except UnicodeError:
                    offset += len(raw)
                    continue
                if text:
                    index[_digest(text)].append({**info, 'line': number, 'byte_start': offset,
                        'byte_end': offset + len(raw), 'match_basis': 'exact_line_content'})
                offset += len(raw)
    stats['import_files_indexed'] = len(inventory)
    stats['import_invalid_records'] = len(issues)
    stats['import_manifest_files'] = sum(i['source_kind'] == 'import_metadata' for i in inventory)
    legacy_files = list(_files(guarded_path(root, root / 'memory/confirmed')))
    idea = guarded_path(root, root / 'memory/ide-lab/facts.jsonl')
    if idea.is_file() and not idea.is_symlink() and idea.stat().st_nlink == 1:
        legacy_files.append(idea)
    mappings, snapshots, states = [], {}, None

    def capture(rel):
        if rel in snapshots:
            return snapshots[rel]
        data = source_data[rel]
        row = _snapshot_source(root, root / rel, data,
            'source-file-' + _digest(rel)[:24], 'local_source_evidence')
        snapshots[rel] = {'snapshot_id': row['snapshot_id'], 'object_sha256': row['sha256'],
                          'original_sha256': _digest(data), 'content_form': row['content_form']}
        return snapshots[rel]

    def run():
        nonlocal states
        states = _state(root) if apply else None
        for path in legacy_files:
            if path.name != 'facts.jsonl':
                continue
            rel = path.relative_to(root).as_posix()
            data = path.read_bytes()
            source_data[rel] = data
            stats['legacy_files'] += 1
            for record, location in _records(data, '.jsonl'):
                if record is None:
                    issues.append({'path': rel, **location, 'reason': 'invalid_legacy_record'})
                    stats['legacy_invalid_records'] += 1
                    continue
                if record.get('tier') != 'confirmed':
                    continue
                stats['legacy_records'] += 1
                body = _body(record)
                matches = index.get(_digest(body), []) if body else []
                stats['legacy_with_exact_import_match'] += bool(matches)
                key = 'legacy:' + rel + ':' + str(record.get('memory_id') or ('line-' + str(location['line'])))
                source_ref = {'path': rel, 'original_file_sha256': _digest(data), **location,
                              'matching_imports': matches, 'legacy_memory_id': record.get('memory_id'),
                              'legacy_claimed_tier': record.get('tier'), 'original_evidence_verified': False}
                missing = {'original_conversation_unproven'}
                if not matches:
                    missing.add('import_source_not_matched')
                if apply:
                    try:
                        source_ref['snapshot'] = capture(rel)
                        for match in matches:
                            match['snapshot'] = capture(match['path'])
                    except CredentialFileBlocked:
                        missing.add('credential_file_capture_blocked')
                observation = _observation(root, key, record, 'legacy_memory', source_ref, missing)
                if apply:
                    observation = _commit(root, observation, states)
                    stats['source_maps_added'] += observation['changed']
                mappings.append(observation)
        if apply:
            # Inventory itself is an audit artifact, never interpreted as a conversation.
            payload = {'schema_version': SCHEMA, 'files': inventory, 'parse_issues': issues,
                       'cloud_eligible': False, 'scope': 'explicit_memory_imports_only'}
            append_event(root, {'event_id': stable_id('memory-source-inventory', _digest(payload)),
                'event_type': 'source_inventory', 'entry': 'memory_sources', 'occurred_at': now_iso(),
                'completeness': 'partial' if issues else 'complete', 'payload': payload})
    if apply:
        with lock(guarded_path(root, root / 'state/maintenance.lock'), shared=True), \
             lock(guarded_path(root, root / 'state/locks/memory-sources.lock')):
            _ensure_not_held(root)
            _guard_outputs(root)
            run()
    else:
        run()
    stats['snapshots_captured_or_reused'] = len(snapshots)
    stats['confirmed_written'] = 0
    return {'schema_version': SCHEMA, 'apply': apply, 'stats': dict(stats),
            'mappings': mappings, 'inventory': inventory, 'issues': issues,
            'scope': 'local_only_no_model_calls', 'confirmation_policy': 'provenance_only'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--include-mappings', action='store_true')
    args = parser.parse_args()
    result = audit_legacy(args.root, apply=args.apply)
    if not args.include_mappings:
        result = {k: v for k, v in result.items() if k not in {'mappings', 'inventory', 'issues'}}
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
