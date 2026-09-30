#!/usr/bin/env python3
"""Archive only content actually provided by the Grok-side adapter. No model call.

Local OS account access is the transport trust boundary, not proof of authorship.
Unknown/unavailable bubbles are gaps. A URL is not a saved web page.
"""
import argparse
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from raw_policy import redact, safe_file_bytes, CredentialFileBlocked
from raw_storage import append_event, snapshot_file, stable_id, _local_sensitive
from runtime_io import lock
from role_registry import ROLE_IDS
from raw_time import source_timestamp, received_fields, utc_now

FIDELITY = {'forwarded_original_unverified', 'relay', 'summary'}

def _screen_captured(root, event_id, role, messages):
    try:
        return _enqueue_captured(root,event_id,role,messages)
    except (OSError,ValueError,KeyError) as exc:
        # The immutable capture is already committed. Replaying capture_id
        # retries only queue insertion, without repeating any business action.
        return {'status':'retry','error_type':type(exc).__name__,
                'recovery':'replay_same_capture_id','items':[]}

def _enqueue_captured(root, event_id, role, messages):
    from memory_pipeline import enqueue
    queued=[]
    for index,message in enumerate(messages):
        # A relay/summary remains archived; do not present it as direct evidence
        # in the automatic user-memory path. It can be reviewed separately.
        if message.get('fidelity')=='forwarded_original_unverified' and message.get('speaker')=='user':
            queued.append(enqueue(root,event_id=event_id,scope=role,
                                  text_path=['payload','messages',index,'text']))
    return {'status':'queued' if queued else 'archive_only','items':queued}

def ingest(root, request):
    root = Path(root).resolve()
    if not isinstance(request, dict) or set(request) - {'capture_id','role_id','source_event_id','messages','attachments','gaps'}:
        raise ValueError('Unknown capture fields')
    cid = request.get('capture_id'); role = request.get('role_id')
    import re
    if not isinstance(cid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', cid):
        raise ValueError('capture_id must be a stable local capture identifier')
    if role not in ROLE_IDS: raise ValueError('Role is not enabled for the local Grok bridge')
    messages = request.get('messages')
    if not isinstance(messages, list) or not 1 <= len(messages) <= 100: raise ValueError('1..100 actual messages required')
    for message in messages:
        if not isinstance(message,dict) or not isinstance(message.get('text'),str) or len(message['text'].encode())>262144:
            raise ValueError('Invalid original message text')
    filtered, changes = redact(request)
    local_only_capture = _local_sensitive(request)
    for message in filtered['messages']:
        if not isinstance(message, dict) or set(message) - {'speaker','text','fidelity','source_event_id','occurred_at','urls'}:
            raise ValueError('Unknown message fields')
        if message.get('speaker') not in {'user','grok'} or message.get('fidelity') not in FIDELITY:
            raise ValueError('Explicit speaker and fidelity are required')
        text = message.get('text')
        if not isinstance(text, str) or not text.strip() or len(text.encode()) > 262144:
            raise ValueError('Invalid message text')
        if message.get('occurred_at') is not None and source_timestamp(message['occurred_at']) is None:
            raise ValueError('Source timestamp must be a complete valid timestamp with timezone')
        urls = message.get('urls', [])
        if not isinstance(urls, list) or any(not isinstance(url,str) or not url.startswith(('http://','https://')) for url in urls):
            raise ValueError('URL references must be HTTP(S) strings')
    gaps = filtered.get('gaps', [])
    if not isinstance(gaps, list) or any(not isinstance(g,str) for g in gaps): raise ValueError('gaps must be strings')
    attachment_requests = filtered.get('attachments', [])
    if not isinstance(attachment_requests,list) or len(attachment_requests)>20: raise ValueError('Invalid attachment list')
    attachments=[]; attachment_hashes=[]; original_attachment_hashes=[]
    allowed = root/'workspace/inbox/grok-sync/attachments'
    for item in attachment_requests:
        if not isinstance(item,dict) or set(item)-{'path','label'}:raise ValueError('Invalid attachment fields')
        source=Path(item['path'])
        if not source.is_absolute():source=allowed/source
        if source.is_symlink() or not source.resolve().is_relative_to(allowed.resolve()) or not source.is_file():
            raise ValueError('Attachment must be an ordinary file in the dedicated intake directory')
        if source.stat().st_size>16*1024*1024:raise ValueError('Attachment exceeds intake limit')
        if source.stat().st_nlink != 1:raise ValueError('Hardlinked attachment is not allowed')
        from raw_storage import _read_regular
        original_bytes=_read_regular(source)
        try:safe_bytes, _, _ = safe_file_bytes(source,captured_bytes=original_bytes)
        except CredentialFileBlocked as exc:
            if str(exc)!='explicit_credential_in_binary_file':raise
            safe_bytes=b'[LOCAL_ONLY_BINARY_ORIGINAL]\n'
        attachment_hashes.append(hashlib.sha256(safe_bytes).hexdigest())
        original_attachment_hashes.append(hashlib.sha256(original_bytes).hexdigest())
        attachments.append((source,item.get('label',source.name)))
    encoded=json.dumps({'request':filtered,'attachment_hashes':attachment_hashes},sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
    fingerprint=hashlib.sha256(encoded).hexdigest();eid=stable_id('grok-line1',role,cid)
    original_fingerprint=hashlib.sha256(json.dumps({'request':request,'attachment_hashes':original_attachment_hashes},sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    with lock(root/'state/maintenance.lock',shared=True),lock(root/'state/locks/grok-sync.lock'):
        from task_service import ensure_not_held
        ensure_not_held(root)
        old=None
        for p in (root/'raw/events/grok-sync').glob('*.jsonl'):
            for line in p.read_text().split('\n'):
                if not line.strip():continue
                row=json.loads(line)
                if row.get('event_id')==eid:old=row
        if old:
            old_payload=old.get('payload') or {}
            if old_payload.get('capture_fingerprint',old.get('capture_fingerprint'))!=fingerprint:raise ValueError('capture_id reused with changed content; append a new capture')
            if old_payload.get('original_capture_fingerprint',old.get('capture_original_fingerprint',original_fingerprint))!=original_fingerprint:raise ValueError('capture_id reused with changed original content; append a new capture')
            return {'ok':True,'archived':True,'event_id':eid,'capture_id':cid,'replayed':True,'memory_confirmed':False,
                    'screening':{'status':'local_only','items':[]} if local_only_capture or old.get('cloud_eligible') is False else _screen_captured(root,eid,role,filtered['messages'])}
        refs=[]
        for index,(source,label) in enumerate(attachments):
            snap=snapshot_file(root,source,'capture-'+role+'-'+cid,label,capture_key=eid,relation='grok_provided_attachment',source_locator={'event_id':eid},sensitivity='L4' if local_only_capture else None)
            if not local_only_capture and snap['sha256'] != attachment_hashes[index]:raise ValueError('Attachment changed during capture; no complete capture receipt issued')
            if snap['original']['sha256']!=original_attachment_hashes[index]:raise ValueError('Original attachment changed during capture')
            refs.append({k:snap[k] for k in ('snapshot_id','artifact_id','sha256','object_path')})
        now=utc_now()
        # The fingerprint above binds the original supplied envelope. Local
        # observation fields are added only on the first immutable capture.
        for message in filtered['messages']:
            message.update(received_fields(occurred_at=message.get('occurred_at'), received_at=now))
        missing=['platform_complete_event_feed_not_available','upstream_authorship_not_independently_verified',
                 'hidden_reasoning_not_available','URL_references_are_not_saved_page_content']+gaps
        if any(not m.get('occurred_at') for m in filtered['messages']):missing.append('one_or_more_source_timestamps_unavailable')
        if changes:missing.append('explicit_credentials_filtered_before_RAW')
        if local_only_capture:missing.append('local_only_original_preserved_no_structured_processing')
        append_event(root,{'event_id':eid,'source_event_id':filtered.get('source_event_id'),'event_type':'grok_direct_capture',
            'agent':role,'entry':'grok_sync_file','execution_path':'direct_grok; no_codex_execution',
            'capture_fingerprint':fingerprint,'capture_original_fingerprint':original_fingerprint,
            **received_fields(received_at=now), 'completeness':'partial','missing_reason':';'.join(missing),
            'payload':{'source_line':1,'capture_id':cid,'capture_fingerprint':fingerprint,
                'messages':filtered['messages'],'attachments':refs,'gaps':missing,'original_capture_fingerprint':original_fingerprint,'redaction_boundary':'explicit credential patterns; not semantic privacy classification',
                'memory_status':'not_confirmed','business_execution':'grok_reported; not_verified_by_node0'}},
            relative_path='events/grok-sync/'+datetime.now(timezone.utc).strftime('%Y%m%d')+'.jsonl',original_event=request)
        return {'ok':True,'archived':True,'event_id':eid,'capture_id':cid,'replayed':False,
                'memory_confirmed':False,'gaps':missing,'attachments':refs,
                'screening':{'status':'local_only','items':[]} if local_only_capture else _screen_captured(root,eid,role,filtered['messages'])}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',default=str(Path.home()/'javis'))
    p.add_argument('--message-file',required=True,help='UTF-8 JSON envelope; exact message text is carried inside')
    a=p.parse_args();source=Path(a.message_file)
    if source.stat().st_size>1048576:raise ValueError('Capture file too large')
    print(json.dumps(ingest(a.root,json.loads(source.read_text(encoding='utf-8-sig'))),ensure_ascii=False,indent=2))

if __name__=='__main__':main()
