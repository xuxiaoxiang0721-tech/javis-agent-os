"""Read-only, source-bound corpus routing. No network, confirmation, or RAW writes.

Inventory is metadata only. A candidate route means locally adaptable text, NOT
model processing or approval for external transmission. Every loader rechecks
the original bytes and policy, including explicit cloud exclusions.
"""
from __future__ import annotations
import hashlib
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from contextvars import ContextVar
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/memory-adapter'))
from javis_memory_adapter.review_policy import guarded_path as _guarded_path, digest
from raw_policy import redact, is_vault_path, is_vault_bytes
from role_registry import ROLE_IDS
from task_memory import _explicit_l4
from raw_time import native_time, source_timestamp, semantic_source_time

SCHEMA = 'javis.memory-corpus.v1'
BOUND_OBJECT_TIME_POLICY = 'bound-object-time-v2'
LEGACY_SOURCE_TIME_POLICY = 'legacy-source-time-v2'
_ACTIVE_READER=ContextVar('javis_corpus_reader',default=None)
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024
SKIP = {'backups', 'backup', '.git', '.codex', 'secrets', 'credentials',
        'javis-vault', 'node_modules', '__pycache__'}
CREDENTIAL_NAMES = {'auth.json', 'credentials.json', 'id_rsa', 'id_ed25519', '.env'}
TEXT_EXT = {'.txt', '.md', '.json', '.jsonl'}
CONTENT_EVENTS = {'user_input', 'model_output', 'native_final_output',
                  'conversation_turn', 'chat_message', 'dialogue'}
OPERATIONAL_LAYERS = {'provenance', 'triage', 'usage', 'screen', 'sync'}
PRESERVED_MEMORY_LAYERS = {'memory/structured', 'memory/candidates', 'memory/quarantine'}
STRUCTURAL_TYPES = {'session','session.started','session.ended','thread.started','turn.started','turn.completed',
    'model_change','thinking_level_change','custom','trace.metadata','trace.artifacts', 'tool.call',
    'turn.client_closed','turn.completion_idle_timeout','turn.dynamic_tool_terminal_release','model.fallback_step'}
RAW_RECEIPTS={'tool_call','task_lifecycle','status','error','artifact_delivery','memory_read','worker_execution',
    'memory_result','memory_write','input_transport','runtime_prompt','native_permissions','task_control',
    'source_coverage','source_inventory','grok_context_import','task_result','other','codex_stream_event'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def guarded_path(root, path):
    root,path=Path(root).resolve(),Path(path)
    if not path.is_absolute() or '..' in path.parts or not path.resolve().is_relative_to(root):
        raise ValueError('corpus_source_path_outside_root')
    return _guarded_path(root,path)


def _label(value):
    if value is None: return None
    if isinstance(value, str) and re.fullmatch(r'[a-zA-Z0-9_.:-]{1,160}', value): return value
    return 'unrecognized_' + digest(value)[:12]


def _cloud_false(value):
    if isinstance(value, dict):
        return value.get('cloud_eligible') is False or any(_cloud_false(x) for x in value.values())
    return isinstance(value, list) and any(_cloud_false(x) for x in value)


def policy_flags(value):
    """Distinct reasons, never equate an audit cloud=false with a credential."""
    _, changes = redact(value)
    flags = []
    if _cloud_false(value): flags.append('explicit_cloud_false')
    if _explicit_l4(value): flags.append('explicit_L4')
    if changes: flags.append('credential_patterns')
    if '[REDACTED:' in json.dumps(value, ensure_ascii=False): flags.append('redacted_marker')
    return flags


def _value(row, selector):
    value = row
    for part in selector:
        if isinstance(part, int) and isinstance(value, list): value = value[part]
        elif isinstance(part, str) and isinstance(value, dict): value = value[part]
        else: raise ValueError('invalid_corpus_selector')
    return value


def text_fields(row):
    """Yield exact fields only. Never stringify objects or concatenate excerpts."""
    found = []
    def add(path, nature):
        try: value = _value(row, path)
        except (KeyError, IndexError, TypeError): return
        if isinstance(value, str) and value.strip(): found.append((path, value, nature))
    def structured(path):
        try:value=_value(row,path)
        except (KeyError,IndexError,TypeError):return
        if isinstance(value,(dict,list)) and value:
            found.append((path,json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False),'structured_tool_observation'))
    def content(path, nature):
        try: value = _value(row, path)
        except (KeyError, IndexError, TypeError): return
        if isinstance(value, str): add(path, nature)
        elif isinstance(value, list):
            for i, block in enumerate(value):
                if isinstance(block, dict) and block.get('type') in {'text', 'input_text', 'output_text', 'inputText', 'outputText'}:
                    add(path + [i, 'text'], nature)
                elif isinstance(block,dict) and block.get('type')=='toolResult':
                    add(path+[i,'content'],'tool_observation')
                    if not isinstance(block.get('content'),str):add(path+[i,'text'],'tool_observation')
                elif isinstance(block,dict) and block.get('type')=='tool_result':
                    add(path+[i,'content'],'tool_observation')
                    add(path+[i,'result'],'tool_observation')
                    structured(path+[i,'result'])
    if not isinstance(row, dict): return found
    kind = row.get('event_type')
    p = row.get('payload') if isinstance(row.get('payload'), dict) else {}
    if kind in CONTENT_EVENTS:
        nature = 'recorded_user_input' if kind == 'user_input' else 'model_derived'
        add(['payload', 'text'], nature)
        for i, msg in enumerate(p.get('messages', []) if isinstance(p.get('messages'), list) else []):
            if isinstance(msg, dict): add(['payload', 'messages', i, 'text'], 'unverified_message')
        # log_tail is an explicitly incomplete derived fragment, not a final reply.
        add(['payload', 'log_tail'], 'derived_log_fragment')
    elif kind == 'tool_result': add(['payload', 'result'], 'tool_observation')
    elif kind == 'codex_stream_event':
        e = p.get('event') if isinstance(p.get('event'), dict) else {}
        item = e.get('item') if isinstance(e.get('item'), dict) else {}
        if e.get('type') == 'item.completed':
            if item.get('type') == 'agent_message': add(['payload', 'event', 'item', 'text'], 'model_derived')
            elif item.get('type') == 'command_execution': add(['payload', 'event', 'item', 'aggregated_output'], 'tool_observation')
            elif item.get('type') == 'mcp_tool_call': content(['payload', 'event', 'item', 'result', 'content'], 'tool_observation')
    elif kind is None:
        # Historical mail exports preserve body/preview/summary as different kinds.
        for key, nature in [('body_full', 'mail_body'), ('body_preview', 'mail_excerpt'),
                            ('snippet', 'mail_excerpt'), ('summary', 'derived_summary')]:
            add([key], nature)
        add(['fact'], 'legacy_claim')
        if row.get('type') in {'reasoning', 'thinking'}: return []
        message = row.get('message')
        if isinstance(message, dict):
            role = message.get('role') or row.get('role')
            if role in {'user', 'assistant', 'tool', 'toolResult'}:
                content(['message', 'content'], 'unverified_message' if role == 'user' else 'model_derived' if role == 'assistant' else 'tool_observation')
                add(['message', 'text'], 'unverified_message')
            elif message.get('type')=='text':
                add(['message','content'],'unverified_message')
        elif isinstance(message, str): add(['message'], 'unverified_message')
        if row.get('role') in {'user', 'assistant', 'tool', 'toolResult'}:
            content(['content'], 'unverified_message' if row['role'] == 'user' else 'model_derived' if row['role'] == 'assistant' else 'tool_observation')
            add(['text'], 'unverified_message' if row['role']=='user' else 'model_derived' if row['role']=='assistant' else 'tool_observation')
        if row.get('type') == 'response_item' and isinstance(row.get('payload'), dict):
            if p.get('type') == 'message' and p.get('role') in {'user', 'assistant', 'tool'}:
                content(['payload', 'content'], 'unverified_message' if p['role'] == 'user' else 'model_derived')
        if row.get('type') == 'event_msg' and p.get('type') in {'user_message','agent_message'}:
            add(['payload','message'], 'unverified_message' if p['type']=='user_message' else 'model_derived')
        mapping = row.get('mapping')
        if isinstance(mapping,dict):
            for node_id,node in mapping.items():
                msg=node.get('message') if isinstance(node,dict) else None
                if not isinstance(msg,dict): continue
                author=msg.get('author') or {}
                role=author.get('role') if isinstance(author,dict) else None
                if role not in {'user','assistant','tool'}:continue
                parts=(msg.get('content') or {}).get('parts') if isinstance(msg.get('content'),dict) else None
                if isinstance(parts,list):
                    for i in range(len(parts)):
                        add(['mapping',node_id,'message','content','parts',i], 'unverified_message' if role=='user' else 'model_derived' if role=='assistant' else 'tool_observation')
        if row.get('type') == 'tool.result':
            add(['data','output'], 'tool_observation')
            content(['data','result','content'], 'tool_observation')
            content(['data','contentItems'], 'tool_observation')
            if not isinstance((row.get('data') or {}).get('output'),str):structured(['data','result'])
        if row.get('type') == 'model.completed' and isinstance(row.get('data'),dict):
            for i in range(len(row['data'].get('assistantTexts',[])) if isinstance(row['data'].get('assistantTexts'),list) else 0):
                add(['data','assistantTexts',i], 'model_derived')
    unique = {}
    for path, text, nature in found: unique[tuple(path)] = (path, text, nature)
    return list(unique.values())


def record_scope(row):
    """Only exact declared role identifiers. No alias, path, or text inference."""
    values = {row[k] for k in ('agent', 'scope', 'role_id', 'role') if isinstance(row.get(k), str) and row[k] in ROLE_IDS}
    return next(iter(values)) if len(values) == 1 else None


def _epoch(value, divisor=1):
    if type(value) not in (int,float):return None
    try:
        number=Decimal(str(value))/divisor
        if not number.is_finite() or number<0 or number>4102444800:return None
        seconds=int(number);fraction=number-seconds
        digits=format(fraction,'f').split('.')[1].rstrip('0') if fraction else ''
        if len(digits)>9:return None
        base=datetime.fromtimestamp(seconds,timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
        return base+('.'+digits if digits else '')+'Z'
    except (InvalidOperation,ValueError,OverflowError,OSError):return None


def _selected_time_v1(row, selector):
    """Typed message time, never container/capture fallback for a nested message."""
    target=row;prefix=[]
    if len(selector)>=4 and selector[:2]==['payload','messages'] and isinstance(selector[2],int):
        prefix=selector[:3];target=_value(row,prefix)
    elif len(selector)>=3 and selector[0]=='mapping' and selector[2]=='message':
        prefix=selector[:3];target=_value(row,prefix)
        value=target.get('create_time')
        stamp=_epoch(value)
        return {'occurred_at':stamp,'time_basis':'source_timestamp' if stamp else 'source_time_invalid' if value is not None else 'capture_only',
                'source_time_field':prefix+['create_time'] if value is not None else None}
    elif selector[:3]==['payload','event','item']:
        prefix=['payload','event'];target=_value(row,prefix)
    elif selector[:1]==['message'] and isinstance(row.get('message'),dict) and any(row['message'].get(k) is not None for k in ('timestamp','occurred_at')):
        prefix=['message'];target=row['message']
    stamp,basis,field=native_time(target)
    if field is not None:return {'occurred_at':stamp,'time_basis':basis,'source_time_field':prefix+[field]}
    if not prefix and isinstance(row.get('message'),dict) and row['message'].get('type')=='text' and 'timestampMs' in row:
        stamp=_epoch(row['timestampMs'],1000)
        return {'occurred_at':stamp,'time_basis':'source_timestamp' if stamp else 'source_time_invalid','source_time_field':['timestampMs']}
    if not prefix and 'body_full' in row and row.get('receivedDateTime') is not None:
        stamp=source_timestamp(row['receivedDateTime'])
        return {'occurred_at':stamp,'time_basis':'source_timestamp' if stamp else 'source_time_invalid','source_time_field':['receivedDateTime']}
    return {'occurred_at':None,'time_basis':'capture_only','source_time_field':None}


def _rejected_legacy_time(row, selector):
    """Return exact legacy evidence only when the selected occurrence is unsafe.

    Native ``timestamp`` fields keep their own typed source semantics. Only a
    valid ``occurred_at`` that semantic_source_time explicitly disallows changes.
    """
    timing=_selected_time_v1(row,selector)
    field=timing['source_time_field']
    if timing['occurred_at'] is not None and field and field[-1]=='occurred_at':
        target=_value(row,field[:-1])
        if semantic_source_time(target) is None:return target,timing
    return None


def selected_time(row, selector):
    timing=_selected_time_v1(row,selector)
    if _rejected_legacy_time(row,selector) is not None:
        return {'occurred_at':None,'time_basis':'capture_only','source_time_field':None}
    return timing


def selected_provenance(row,selector):
    target=row
    if selector[:2]==['payload','messages']:target=_value(row,selector[:3])
    elif selector[:1]==['message'] and isinstance(row.get('message'),dict):target=row['message']
    elif selector[:1]==['mapping']:target=_value(row,selector[:3])
    p=row.get('payload') if isinstance(row.get('payload'),dict) else {}
    author=target.get('author') if isinstance(target.get('author'),dict) else {}
    role=target.get('speaker') or target.get('role') or author.get('role') or row.get('role') or p.get('speaker')
    provenance={'speaker':role if role in {'user','assistant','tool','toolResult','system','developer'} else 'unknown',
        'fidelity':_label(target.get('fidelity') or p.get('fidelity')),
        'record_source':_label(p.get('record_source')),
        'legacy_context_digest':digest({k:row.get(k) for k in ('source','temporal','as_of','learned_at','tier') if k in row})}
    return provenance


def adapt_record(row, location, *, layer='raw_events', scope_binding=None):
    """Metadata-only descriptors; location must identify immutable source bytes."""
    flags = policy_flags(row)
    scope = record_scope(row)
    declared={row[k] for k in ('agent','scope','role_id','role') if isinstance(row.get(k),str) and row[k] in ROLE_IDS}
    conflict=len(declared)>1 or bool(scope_binding and scope and scope!=scope_binding['scope'])
    if scope_binding and not conflict: scope=scope or scope_binding['scope']
    if conflict:scope=None
    kind = _label(row.get('event_type') or row.get('type'))
    base = {'source':dict(location), 'source_digest':digest(row), 'layer':layer,
            'event_id':_label(row.get('event_id')), 'event_type':kind,
            'scope':scope, 'declared_agent':_label(row.get('agent')),
            'policy_flags':flags, 'confirmation_authority':False,
            'model_processed':False, 'external_send_authorized':False}
    if scope_binding:base['scope_binding']=scope_binding
    fields = text_fields(row)
    def block_group(selector):
        if len(selector)>1 and selector[-1]=='text' and isinstance(selector[-2],int):return tuple(selector[:-2])
        if selector and isinstance(selector[-1],int) and 'parts' in selector:return tuple(selector[:-1])
        return None
    parts=Counter(block_group(selector) for selector,_,_ in fields if block_group(selector) is not None)
    if not fields:
        reason = 'structure_or_receipt_only'
        route = 'noncontent'
        if kind not in STRUCTURAL_TYPES and not (layer=='raw_events' and kind in RAW_RECEIPTS):
            route, reason = 'recoverable', 'unadapted_import_schema_requires_review' if layer=='memory/imports' else 'unadapted_source_schema_requires_review'
        if set(row)=={'kind','note','pos'}:
            route,reason='recoverable','exported_content_omitted'
        if kind=='model.completed' and isinstance(row.get('data'),dict) and 'truncated' in row['data']:
            route,reason='recoverable','original_content_truncated_in_export' if row['data']['truncated'] is True else 'export_truncation_metadata_requires_original'
        if set(row)=={'runtimeFile','schemaVersion','sessionId','traceSchema'}:
            route,reason='recoverable','index_only_requires_original_runtime_file'
        if kind in {'context.compiled','prompt.submitted'}:
            route,reason='local_only','derived_prompt_context'
        if isinstance(row.get('message'),dict):
            content = (row.get('message') or {}).get('content') if isinstance(row.get('message'),dict) else None
            if isinstance(content,list) and all(isinstance(x,dict) and x.get('type') in {'thinking','reasoning','toolCall','tool_use'} for x in content):
                route,reason='noncontent','reasoning_or_tool_call_blocks_not_memory_source'
        if kind == 'native_final_output': reason = 'body_in_referenced_artifact'
        elif kind == 'file_snapshot': reason = 'body_in_content_addressed_object'
        return [{**base, 'item_id':'corpus_'+digest([location, None])[:32],
                 'route':'local_only' if flags else 'recoverable' if kind in {'native_final_output','file_snapshot'} else route,
                 'reason':flags[0] if flags else reason, 'text_selector':None}]
    result = []
    for selector, text, nature in fields:
        size = len(text.encode('utf-8'))
        route, reason = 'candidate', 'source_bound_text_requires_authorized_processing'
        if flags: route, reason = 'local_only', flags[0]
        elif scope is None: route, reason = 'recoverable', 'scope_binding_conflict' if conflict else 'scope_unresolved'
        elif parts[block_group(selector)]>1:route,reason='recoverable','multipart_message_requires_whole_context_adapter'
        elif size > MAX_TEXT_BYTES: route, reason = 'recoverable', 'oversize_requires_context_preserving_adapter'
        elif nature in {'mail_excerpt','derived_log_fragment'}: route, reason = 'recoverable', 'incomplete_source_fragment'
        result.append({**base, 'item_id':'corpus_'+digest([location,selector])[:32],
            'route':route, 'reason':reason, 'text_selector':selector, 'source_nature':nature,
            'content_sha256':sha(text.encode('utf-8')), 'utf8_bytes':size,
            'text_encoding':'canonical_json_value' if nature=='structured_tool_observation' else 'verbatim_field',
            'authorship_verified':bool(layer == 'raw_events' and row.get('event_type') == 'user_input' and selector == ['payload','text']
                 and isinstance(row.get('payload'),dict) and row['payload'].get('is_original_user_input') is True),
            'has_original_time':selected_time(row,selector)['occurred_at'] is not None,
            'source_time':selected_time(row,selector)})
        result[-1]['provenance']=selected_provenance(row,selector)
    return result


def _files(root, base, excluded=None):
    base = guarded_path(root, base)
    if not base.exists(): return
    for folder, dirs, names in os.walk(base, followlinks=False):
        removed = [d for d in dirs if d.casefold() in SKIP or d.startswith('.') or (Path(folder)/d).is_symlink()]
        if excluded is not None:
            excluded.extend({'path':(Path(folder)/d).relative_to(root).as_posix(), 'reason':'excluded_directory_or_link'} for d in removed)
        dirs[:] = sorted(d for d in dirs if d not in removed)
        for name in sorted(names):
            path = Path(folder)/name
            if path.is_symlink() or name.casefold() in CREDENTIAL_NAMES or is_vault_path(path):
                if excluded is not None: excluded.append({'path':path.relative_to(root).as_posix(), 'reason':'credential_filename_or_link_not_opened'})
                continue
            yield guarded_path(root, path)


def _hash_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024), b''): h.update(block)
    return h.hexdigest()


def _records(path):
    """Stream JSONL without hiding invalid/large records; no shell/database reads."""
    if path.suffix.lower() == '.jsonl':
        with path.open('rb') as stream:
            n, offset = 0, 0
            while True:
                line=stream.readline(MAX_RECORD_BYTES+1)
                if not line:break
                n += 1; start = offset; offset += len(line)
                if len(line)>MAX_RECORD_BYTES:
                    h=hashlib.sha256(line)
                    while line and not line.endswith(b'\n'):
                        line=stream.readline(MAX_RECORD_BYTES+1);offset+=len(line);h.update(line)
                    yield None,{'line':n,'byte_start':start,'byte_end':offset,'record_bytes_sha256':h.hexdigest()},'oversize_record'
                    continue
                if not line.strip(): continue
                loc = {'line':n, 'byte_start':start, 'byte_end':offset, 'record_bytes_sha256':sha(line)}
                if len(line)>MAX_RECORD_BYTES: yield None, loc, 'oversize_record'; continue
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict): raise ValueError()
                    yield row, loc, None
                except (ValueError, UnicodeError): yield None, loc, 'invalid_record'
    elif path.suffix.lower() == '.json' and path.stat().st_size <= MAX_RECORD_BYTES:
        data = path.read_bytes()
        try: value = json.loads(data)
        except (ValueError, UnicodeError): yield None, {}, 'invalid_json'; return
        rows = value if isinstance(value,list) else [value]
        for n, row in enumerate(rows):
            yield (row if isinstance(row,dict) else None), {'json_index':n if isinstance(value,list) else None}, None if isinstance(row,dict) else 'non_object_json'


def _file_item(info, route, reason):
    return {'item_id':'corpus_'+digest(info)[:32], 'source':info, 'layer':info['layer'],
            'route':route, 'reason':reason, 'scope':None, 'model_processed':False,
            'external_send_authorized':False, 'confirmation_authority':False, 'text_selector':None}


def _record_at(root, source, reader=None):
    if reader is not None:return reader._record(source)
    path=guarded_path(root,root/source['path'])
    if _hash_file(path)!=source['file_sha256']: raise ValueError('corpus_source_file_changed')
    for row,loc,error in _records(path):
        match=(source.get('line') is not None and loc.get('line')==source['line']) or ('json_index' in source and loc.get('json_index')==source['json_index'])
        if match:
            if error or (source.get('record_bytes_sha256') and loc.get('record_bytes_sha256')!=source['record_bytes_sha256']):
                raise ValueError('corpus_source_record_changed')
            return row
    raise ValueError('corpus_source_record_missing')


def _object_bindings(root, files, raw_records, manifest_records):
    """Bind whole UTF-8 object bodies to explicit RAW scope and manifest hashes."""
    objects={f['file_sha256']:f for f in files if f['layer']=='raw_objects'}
    manifests=defaultdict(list)
    for row,loc in manifest_records:
        if isinstance(row.get('sha256'),str):manifests[row['sha256']].append((row,loc))
    result=[]
    for row,loc in raw_records:
        payload=row.get('payload') if isinstance(row.get('payload'),dict) else {}
        h=payload.get('native_final_output_sha256') if row.get('event_type')=='native_final_output' else payload.get('sha256') if row.get('event_type')=='file_snapshot' else None
        if h not in objects or h not in manifests:continue
        info=objects[h];parent_flags=policy_flags(row)
        bindings=[]
        for m,mref in manifests[h]:
            parent_flags.extend(policy_flags(m));bindings.append({'source':mref,'source_digest':digest(m)})
        source={**info,'kind':'bound_object','parent':{'source':loc,'source_digest':digest(row)},'manifests':bindings}
        item=_file_item(source,'recoverable','object_scope_unresolved')
        item.update(item_id='corpus_'+digest(source)[:32],scope=record_scope(row),source_digest=digest(row),
            event_id=_label(row.get('event_id')),event_type='bound_object',source_nature='model_derived' if row.get('event_type')=='native_final_output' else 'unverified_artifact',
            authorship_verified=False,policy_flags=sorted(set(parent_flags)),text_selector=[])
        if info['bytes']>MAX_RECORD_BYTES:
            item['reason']='oversize_object_requires_adapter';result.append(item);continue
        data=guarded_path(root,root/info['path']).read_bytes()
        try:
            text=data.decode('utf-8')
            if '\x00' in text:raise UnicodeError()
        except UnicodeError:
            item['reason']='opaque_object_requires_dedicated_adapter';result.append(item);continue
        item.update(content_sha256=sha(data),utf8_bytes=len(data),policy_flags=sorted(set(parent_flags+policy_flags({'text':text}))))
        if item['policy_flags']:item.update(route='local_only',reason=item['policy_flags'][0])
        elif not text.strip():item.update(route='noncontent',reason='empty_object')
        elif len(data)>MAX_TEXT_BYTES:item['reason']='oversize_requires_context_preserving_adapter'
        elif item['scope'] is not None:item.update(route='candidate',reason='source_bound_object_requires_authorized_processing')
        result.append(item)
    return result


def inventory(root):
    """Scan selected data roots only; never backups, credentials, or production writes."""
    root = Path(root).resolve()
    files, items, seen, excluded = [], [], set(), []
    raw_records, manifest_records = [], []
    try:
        from memory_corpus_scope import scope_index, resolve_scope_binding
    except ImportError:
        scope_index=resolve_scope_binding=None
    scopes=scope_index(root) if scope_index else None
    trees = [('raw/events','raw_events'), ('raw/objects','raw_objects'),
             ('raw/manifests','raw_manifests'), ('memory','memory'),
             ('life-notebook','life_notebook'), ('lab/memory-adapter','lab_projection')]
    for rel, family in trees:
        for path in _files(root, root/rel, excluded):
            relpath = path.relative_to(root).as_posix()
            if relpath in seen: continue
            seen.add(relpath)
            layer = family
            if family == 'memory':
                parts = path.relative_to(root/'memory').parts
                layer = 'memory/'+parts[0] if len(parts)>1 else 'memory/root'
            info = {'path':relpath, 'file_sha256':_hash_file(path), 'bytes':path.stat().st_size, 'layer':layer}
            files.append(info)
            binding=resolve_scope_binding(root,path,index=scopes) if resolve_scope_binding else None
            if path.name.startswith('.') or path.suffix.lower() in {'.lock','.pid','.journal-mode'}:
                items.append(_file_item(info,'noncontent','local_lock_or_hidden_bookkeeping_file')); continue
            if family == 'memory' and layer.split('/')[-1] in OPERATIONAL_LAYERS:
                items.append(_file_item(info,'noncontent','derived_operational_ledger')); continue
            if layer in PRESERVED_MEMORY_LAYERS:
                items.append(_file_item(info,'local_only','existing_memory_ledger_preserved_no_automatic_reprocessing')); continue
            if family == 'lab_projection':
                items.append(_file_item(info,'noncontent','derived_graph_projection_or_test_artifact')); continue
            if family == 'raw_objects':
                with path.open('rb') as stream: header = stream.read(8)
                if is_vault_bytes(header): route,reason='local_only','credential_container'
                else: route,reason='recoverable','content_addressed_object_requires_manifest_binding'
                items.append(_file_item(info,route,reason)); continue
            if path.suffix.lower() not in TEXT_EXT:
                items.append(_file_item(info,'recoverable','binary_or_unknown_format_requires_dedicated_adapter')); continue
            if path.suffix.lower() in {'.txt','.md'}:
                if info['bytes'] > MAX_RECORD_BYTES:
                    items.append(_file_item(info,'recoverable','oversize_text_file')); continue
                data = path.read_bytes()
                try: text = data.decode('utf-8')
                except UnicodeError:
                    items.append(_file_item(info,'recoverable','text_encoding_requires_adapter')); continue
                flags = policy_flags({'text':text})
                item = _file_item(info,'local_only' if flags else 'recoverable',flags[0] if flags else 'text_file_scope_and_provenance_unresolved')
                item.update(content_sha256=sha(data), utf8_bytes=len(data), policy_flags=flags, source_nature='unverified_document')
                if binding:
                    source={**info,'kind':'whole_text'}
                    item.update(source=source,scope_binding=binding,scope=binding['scope'],
                        source_digest=digest({'file_sha256':info['file_sha256']}),text_selector=[],authorship_verified=False)
                    item['item_id']='corpus_'+digest([source,binding])[:32]
                    if not flags and text.strip() and len(data)<=MAX_TEXT_BYTES:item.update(route='candidate',reason='source_bound_document_requires_authorized_processing')
                    elif not flags and len(data)>MAX_TEXT_BYTES:item['reason']='oversize_requires_context_preserving_adapter'
                items.append(item); continue
            if path.suffix.lower() == '.json' and info['bytes'] > MAX_RECORD_BYTES:
                items.append(_file_item(info,'recoverable','oversize_json_file')); continue
            count=0
            for row, location, error in _records(path):
                count+=1; source={**info,**location}
                if error: items.append(_file_item(source,'recoverable',error))
                else:
                    if family=='raw_events':raw_records.append((row,source))
                    if family=='raw_manifests':manifest_records.append((row,source))
                    items.extend(adapt_record(row,source,layer=layer,scope_binding=binding))
            if not count: items.append(_file_item(info,'noncontent','empty_file'))
    items.extend(_object_bindings(root,files,raw_records,manifest_records))
    # Keep all bindings. Only exact text with the same scope and source nature
    # shares a proposed processing representative; never merge source authority.
    representatives = {}
    for item in items:
        if item['route'] != 'candidate': continue
        key=(item['scope'],item['source_nature'],item['content_sha256'],item.get('authorship_verified',False),
             digest(item.get('source_time')),digest(item.get('provenance')))
        if key in representatives:
            item.update(route='duplicate', reason='exact_same_scope_and_provenance_text', duplicate_of=representatives[key])
        else: representatives[key]=item['item_id']
    summary={'files':len(files),'bytes':sum(f['bytes'] for f in files),'items':len(items),
        'routes':dict(Counter(x['route'] for x in items)),
        'reasons':dict(Counter(x['reason'] for x in items)),
        'by_layer':{layer:dict(Counter(x['route'] for x in items if x['layer']==layer)) for layer in sorted({x['layer'] for x in items})},
        'candidate_utf8_bytes':sum(x.get('utf8_bytes',0) for x in items if x['route']=='candidate'),
        'recoverable_text_utf8_bytes':sum(x.get('utf8_bytes',0) for x in items if x['route']=='recoverable'),
        'scope_unresolved_groups':dict(Counter('/'.join(x['source']['path'].split('/')[:4]) for x in items if x['reason'] in {'scope_unresolved','object_scope_unresolved','text_file_scope_and_provenance_unresolved'})),
        'excluded_file_or_directory_entries':len(excluded),
        'model_calls':0,'production_writes':0,'new_external_authorization_required':True}
    result={'schema':SCHEMA,'summary':summary,'files':files,'items':items,'excluded_entries':excluded,
        'boundary':'Local routing is not model processing, fact validation, owner approval, or authorization to send additional content.',
        'excluded_roots':['backups','state/owner-auth','config credentials','tools runtimes','unselected workspace artifacts']}
    result['manifest_digest']=digest(result)
    return result


def load_text(root, item, *, _reader=None):
    """Return only a revalidated, complete candidate field; caller owns API consent."""
    if item.get('route') not in {'candidate','duplicate'}: raise ValueError('corpus_item_not_candidate')
    source=item['source'];root=Path(root).resolve()
    if _reader is not None:_reader._accept(root,item)
    path=guarded_path(root,root/source['path'])
    if (_reader._hash(path) if _reader else _hash_file(path))!=source['file_sha256']: raise ValueError('corpus_source_file_changed')
    binding=item.get('scope_binding')
    if binding:
        from memory_corpus_scope import verify_scope_binding
        bound_scope=_reader._binding(binding) if _reader else verify_scope_binding(root,binding)
        group=guarded_path(root,root/binding['group_prefix'])
        if not path.is_relative_to(group) or bound_scope!=item.get('scope'):raise ValueError('corpus_scope_binding_changed')
    if source.get('kind')=='whole_text':
        if not binding or item['item_id']!='corpus_'+digest([source,binding])[:32] or item.get('source_nature')!='unverified_document' or item.get('authorship_verified') is not False:
            raise ValueError('corpus_document_binding_changed')
        data=_reader._bytes(path) if _reader else path.read_bytes();text=data.decode('utf-8')
        if policy_flags({'text':text}) or len(data)>MAX_TEXT_BYTES or sha(data)!=item.get('content_sha256') or not text.strip():raise ValueError('corpus_document_changed_or_excluded')
        return text
    if source.get('kind')=='bound_object':
        if item.get('item_id')!='corpus_'+digest(source)[:32] or item.get('scope') not in ROLE_IDS:
            raise ValueError('corpus_object_binding_changed')
        parent=_record_at(root,source['parent']['source'],_reader)
        if digest(parent)!=source['parent']['source_digest'] or policy_flags(parent):raise ValueError('corpus_parent_changed_or_excluded')
        h=source['file_sha256'];payload=parent.get('payload') or {}
        expected=payload.get('native_final_output_sha256') if parent.get('event_type')=='native_final_output' else payload.get('sha256') if parent.get('event_type')=='file_snapshot' else None
        if expected!=h or record_scope(parent)!=item.get('scope'):raise ValueError('corpus_object_scope_or_hash_changed')
        nature='model_derived' if parent.get('event_type')=='native_final_output' else 'unverified_artifact'
        if item.get('source_nature')!=nature or item.get('authorship_verified') is not False or item.get('source_digest')!=digest(parent):
            raise ValueError('corpus_object_provenance_changed')
        if not source.get('manifests'):raise ValueError('corpus_object_manifest_required')
        for ref in source['manifests']:
            m=_record_at(root,ref['source'],_reader)
            if digest(m)!=ref['source_digest'] or m.get('sha256')!=h or policy_flags(m):raise ValueError('corpus_manifest_changed_or_excluded')
        text=(_reader._bytes(path).decode('utf-8') if _reader else path.read_bytes().decode('utf-8'))
        if policy_flags({'text':text}) or '\x00' in text or len(text.encode())>MAX_TEXT_BYTES or sha(text.encode())!=item.get('content_sha256'):
            raise ValueError('corpus_object_content_changed_or_excluded')
        return text
    row=_record_at(root,source,_reader)
    if row is None or digest(row)!=item['source_digest']: raise ValueError('corpus_source_record_changed')
    if policy_flags(row): raise ValueError('corpus_source_policy_excluded')
    adapted=adapt_record(row,source,layer=item['layer'],scope_binding=binding)
    matching=[x for x in adapted if x['item_id']==item['item_id'] and x['route']=='candidate']
    if len(matching)!=1: raise ValueError('corpus_selector_or_scope_changed')
    current=matching[0]
    for key in ('scope','source_nature','authorship_verified','text_selector','content_sha256','text_encoding','source_time','provenance'):
        if current.get(key)!=item.get(key):
            # Existing descriptors retain the original declared clock as
            # evidence. Accept exactly that old interpretation only after the
            # source bytes/provenance and the new semantic rejection are proven.
            if key=='source_time' and _rejected_legacy_time(row,item['text_selector']) is not None and item.get(key)==_selected_time_v1(row,item['text_selector']):
                continue
            raise ValueError('corpus_binding_changed')
    value=_value(row,item['text_selector'])
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False) if item.get('text_encoding')=='canonical_json_value' else value


def build_event(root, item, *, _reader=None):
    """Construct (do not persist) an evidence-bound canonical adaptation.

    Only an explicitly authorized caller may append or send this returned text.
    The stable ID identifies this adaptation, never a fabricated upstream ID.
    Unknown source time remains unknown; recorded time is not fact validity.
    """
    text = load_text(root, item,_reader=_reader)
    source = item['source']
    path = guarded_path(Path(root).resolve(), Path(root).resolve()/source['path'])
    row = {} if source.get('kind')=='whole_text' else _record_at(Path(root).resolve(),source['parent']['source'],_reader) if source.get('kind')=='bound_object' else _record_at(Path(root).resolve(),source,_reader)
    if source.get('kind')!='whole_text' and (row is None or digest(row)!=item['source_digest']): raise ValueError('corpus_source_record_changed')
    # Do not use ts/created_at: legacy exports often mean export or observation
    # time. Additional typed time adapters must identify their exact basis.
    bound_object=source.get('kind')=='bound_object'
    rejected_time=None if bound_object or source.get('kind')=='whole_text' else _rejected_legacy_time(row,item['text_selector'])
    timing=({'occurred_at':None,'time_basis':'capture_only','source_time_field':None} if bound_object else
            selected_time(row,item['text_selector']) if source.get('kind')!='whole_text' else selected_time(row,[]))
    identity=[item['item_id'],item['source_digest'],item['content_sha256']]
    if bound_object:identity.append(BOUND_OBJECT_TIME_POLICY)
    elif rejected_time is not None:identity.extend([LEGACY_SOURCE_TIME_POLICY,digest(item)])
    event={'schema_version':'javis-raw-event-1',
        'event_id':'ev-corpus-'+digest(identity)[:32],
        'event_type':'corpus_text', 'agent':item['scope'], **timing,
        'completeness':'partial', 'missing_reason':'adapted_source_requires_owner_review',
        'payload':{'text':text, 'record_source':'source_bound_corpus_adapter',
            'source_kind':item['source_nature'], 'is_original_user_input':False,
            'speaker':item.get('provenance',{}).get('speaker','unknown'),
            'fidelity':'source_bound_adaptation',
            'text_encoding':item.get('text_encoding','verbatim_utf8_object' if source.get('kind')=='bound_object' else 'verbatim_utf8_file'),
            'corpus_item':item,
            'authorship_verified':False, 'confirmation_authority':False,
            'source_reference':{**source,'selector':item['text_selector'],
                'source_digest':item['source_digest'],'content_sha256':item['content_sha256'],
                'original_event_id':item.get('event_id'), 'adapter_item_id':item['item_id'],
                'scope_binding':item.get('scope_binding')}}}
    if bound_object:
        # A snapshot/native-final-output event dates local recording of a file.
        # It does not establish when any sentence in that file was uttered.
        event['payload']['artifact_receipt']={
            'time_policy':BOUND_OBJECT_TIME_POLICY, 'semantic_anchor':False,
            'parent_event_id':item.get('event_id'),
            'parent_event_occurred_at':source_timestamp(row.get('occurred_at')),
            'parent_captured_at':source_timestamp(row.get('captured_at')),
            'parent_received_at':source_timestamp(row.get('received_at')),
            'parent_time_basis':row.get('time_basis') if row.get('time_basis') in
                {'source_timestamp','local_received','capture_only','source_time_invalid'} else None}
    elif rejected_time is not None:
        target,original_time=rejected_time
        event['payload']['legacy_time_receipt']={
            'time_policy':LEGACY_SOURCE_TIME_POLICY, 'semantic_anchor':False,
            'original_event_id':item.get('event_id'),
            'source_time_field':original_time['source_time_field'],
            'declared_occurred_at':original_time['occurred_at'],
            'captured_at':source_timestamp(target.get('captured_at')),
            'received_at':source_timestamp(target.get('received_at')),
            'declared_time_basis':target.get('time_basis') if target.get('time_basis') in
                {'source_timestamp','local_received','capture_only','source_time_invalid'} else None}
    return event


def verify_canonical(root, row, text=None, *, _reader=None):
    """Revalidate an already materialized corpus RAW immediately before use."""
    if not isinstance(row,dict) or row.get('event_type')!='corpus_text':raise ValueError('not_corpus_canonical')
    payload=row.get('payload')
    if not isinstance(payload,dict) or not isinstance(payload.get('corpus_item'),dict):raise ValueError('corpus_canonical_binding_missing')
    if _reader is None:
        active=_ACTIVE_READER.get()
        # Other dependencies (for example a learning profile's historical
        # feedback sources) are not necessarily part of this execution batch.
        # They get a complete independent verification, never a pin bypass.
        if active is not None and active.root==Path(root).resolve() and digest(payload['corpus_item']) in active.pins:
            _reader=active
    expected=build_event(root,payload['corpus_item'],_reader=_reader)
    for key in ('event_id','event_type','agent','occurred_at','time_basis','source_time_field','payload'):
        if row.get(key)!=expected.get(key):raise ValueError('corpus_canonical_changed')
    if text is not None and text!=expected['payload']['text']:raise ValueError('corpus_canonical_text_changed')
    if policy_flags(row):raise ValueError('corpus_canonical_policy_excluded')
    return {'item_id':payload['corpus_item']['item_id'],'event_id':row['event_id'],
            'scope':row['agent'],'content_sha256':sha(expected['payload']['text'].encode()),'verified':True}


class CorpusReader:
    """Bounded batch snapshot; buffer outputs until successful context exit.

    Full file hashes are checked at opening and closing. Stat checks during the
    batch are additional checks, never a replacement for the closing hash.
    Only the pinned descriptors supplied to this reader can be loaded.
    """
    def __init__(self,root,items):
        self.root=Path(root).resolve()
        if not isinstance(items,list) or len(items)>1000:raise ValueError('corpus_batch_at_most_1000_items')
        self.items=json.loads(json.dumps(items,ensure_ascii=False,allow_nan=False))
        self.pins={digest(x) for x in self.items};self.files={};self.records={};self.bodies={};self.bindings={};self.opened=False
    def __enter__(self):
        requested=defaultdict(list);body_paths=set()
        def add(source):
            path=guarded_path(self.root,self.root/source['path'])
            old=self.files.get(str(path))
            if old and old['sha']!=source['file_sha256']:raise ValueError('corpus_batch_conflicting_file_versions')
            self.files[str(path)]={'sha':source['file_sha256']}
            requested[str(path)].append(source)
            if source.get('kind') in {'bound_object','whole_text'}:body_paths.add(str(path))
            if source.get('parent'):add(source['parent']['source'])
            for ref in source.get('manifests',[]):add(ref['source'])
        for item in self.items:
            add(item['source'])
            binding=item.get('scope_binding')
            if binding:
                from memory_corpus_scope import verify_scope_binding
                key=digest(binding)
                if key not in self.bindings:self.bindings[key]=(binding,verify_scope_binding(self.root,binding))
                for evidence in binding['evidence']:
                    path=guarded_path(self.root,self.root/evidence['path'])
                    self.files.setdefault(str(path),{'sha':evidence['file_sha256']})
        cached=0
        for name,info in self.files.items():
            path=Path(name)
            if _hash_file(path)!=info['sha']:raise ValueError('corpus_source_file_changed')
            info['stat']=self._stat(path)
            if name in body_paths:
                body=path.read_bytes()
                if len(body)>MAX_TEXT_BYTES or sha(body)!=info['sha']:raise ValueError('corpus_batch_body_invalid')
                self.bodies[name]=body;cached+=len(body)
            positions={(x.get('line'),x.get('json_index')) for x in requested[name] if 'line' in x or 'json_index' in x}
            if positions:
                for row,loc,error in _records(path):
                    key=(loc.get('line'),loc.get('json_index'))
                    if key not in positions:continue
                    if error:raise ValueError('corpus_batch_record_invalid')
                    self.records[(name,*key)]=(row,loc);cached+=len(json.dumps(row,ensure_ascii=False).encode())
                    if cached>128*1024*1024:raise ValueError('corpus_batch_snapshot_too_large')
            if self._stat(path)!=info['stat'] or _hash_file(path)!=info['sha']:raise ValueError('corpus_source_changed_during_snapshot')
        self.opened=True;self._token=_ACTIVE_READER.set(self);return self
    @staticmethod
    def _stat(path):
        s=path.stat();return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)
    def _check(self,path):
        if not self.opened:raise ValueError('corpus_reader_not_open')
        path=guarded_path(self.root,path);name=str(path)
        if name not in self.files or self._stat(path)!=self.files[name]['stat']:raise ValueError('corpus_batch_source_changed')
        return name
    def _accept(self,root,item):
        if Path(root).resolve()!=self.root or digest(item) not in self.pins:raise ValueError('corpus_reader_item_not_pinned')
        self._check(self.root/item['source']['path'])
    def _hash(self,path):return self.files[self._check(path)]['sha']
    def _bytes(self,path):return self.bodies[self._check(path)]
    def _record(self,source):
        name=self._check(self.root/source['path'])
        if self.files[name]['sha']!=source['file_sha256']:raise ValueError('corpus_batch_source_changed')
        value=self.records.get((name,source.get('line'),source.get('json_index')))
        if value is None:raise ValueError('corpus_batch_record_not_pinned')
        row,loc=value
        if source.get('record_bytes_sha256') and source['record_bytes_sha256']!=loc.get('record_bytes_sha256'):raise ValueError('corpus_batch_record_changed')
        return row
    def _binding(self,binding):
        key=digest(binding)
        if key not in self.bindings:raise ValueError('corpus_binding_not_pinned')
        for e in binding['evidence']:self._check(self.root/e['path'])
        return self.bindings[key][1]
    def load_text(self,item):return load_text(self.root,item,_reader=self)
    def build_event(self,item):return build_event(self.root,item,_reader=self)
    def verify_canonical(self,row,text=None):return verify_canonical(self.root,row,text,_reader=self)
    def __exit__(self,kind,value,tb):
        try:
            for name,info in self.files.items():
                path=guarded_path(self.root,Path(name))
                if _hash_file(path)!=info['sha']:raise ValueError('corpus_source_changed_before_commit')
            if self.bindings:
                from memory_corpus_scope import verify_scope_binding
                for binding,scope in self.bindings.values():
                    if verify_scope_binding(self.root,binding)!=scope:raise ValueError('corpus_scope_changed_before_commit')
        finally:
            self.opened=False
            _ACTIVE_READER.reset(self._token)
        return False
