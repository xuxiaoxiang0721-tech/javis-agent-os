"""Durable RAW-referenced screening queue. No task execution or owner approval."""
from __future__ import annotations
import argparse
import asyncio
import collections
import json
import math
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / 'tools/memory-adapter'))
from javis_memory_adapter.review_policy import digest, guarded_path, read_rows, safe_id
from raw_storage import append_event, stable_id, now_iso
from runtime_io import atomic_json, lock
from role_registry import ROLE_IDS
from memory_controls import status as controls_status, require_processing, MemoryProcessingHeld

def _model_waiting(value):
    return isinstance(value, str) and (value in {
        'waiting_for_key', 'waiting_for_configuration',
        'waiting_for_embedding_key', 'waiting_for_embedding_configuration'}
        or re.fullmatch(r'chatgpt_subscription_[a-z_]{1,70}', value) is not None)

def settings(root):
    root = Path(root).resolve()
    p = guarded_path(root, root / 'config/memory-pipeline.json')
    value = json.loads(p.read_text()) if p.exists() else {}
    if not isinstance(value,dict):raise ValueError('invalid_pipeline_config')
    enabled = value.get('enabled', False)
    if type(enabled) is not bool: raise ValueError('invalid_pipeline_enabled')
    model = value.get('model') or 'jev-1.13.0'
    provider = value.get('provider', 'typesafe')
    if provider != 'typesafe': raise ValueError('unsupported_screen_provider')
    if enabled and (not isinstance(model, str) or not re.fullmatch(r'jev-\d+\.\d+\.\d+',model)):
        raise ValueError('pinned_typesafe_model_required')
    return {'enabled': enabled, 'model': model, 'provider': provider,
            'prompt_version': value.get('prompt_version', 'jev-typesafe-v4-temporal')}

def load_event(root, event_id):
    from task_memory import _raw_index
    event = _raw_index(root).get(event_id)
    if not event: raise ValueError('raw_event_not_found')
    return event

def select_text(event, path):
    if path != ['payload', 'text'] and not (
        len(path) == 4 and path[:2] == ['payload','messages']
        and type(path[2]) is int and 0 <= path[2] < 100 and path[3] == 'text'):
        raise ValueError('unsupported_text_selector')
    value = event
    for key in path: value = value[key]
    if not isinstance(value, str) or not value.strip(): raise ValueError('missing_source_text')
    return value

def enqueue(root, *, event_id, scope, text_path=None):
    root = Path(root).resolve(); safe_id(event_id)
    if scope not in ROLE_IDS: raise ValueError('pipeline_scope_not_enabled')
    cfg = settings(root)
    event = load_event(root, event_id)
    if event.get('agent') != scope: raise ValueError('source_scope_mismatch')
    path = text_path or ['payload','text']; text = select_text(event, path)
    binding = {'event_id':event_id, 'scope':scope, 'text_path':path,
               'source_digest':digest(event), 'text_digest':digest(text),
               'model':cfg['model'], 'prompt_version':cfg['prompt_version']}
    binding['provider'] = cfg['provider']
    from jev_policy import POLICY_DIGEST
    from memory_learning import runtime_profile
    profile = runtime_profile(root, scope, cfg['model'], POLICY_DIGEST)
    binding.update(policy_digest=POLICY_DIGEST,
                   learning_version=profile['version_id'] if profile else 'baseline',
                   learning_profile_digest=profile['digest'] if profile else None)
    qid = 'screen_' + digest(binding)[:32]
    target = guarded_path(root, root / 'state/memory-pipeline/queue' / (qid+'.json'))
    with lock(guarded_path(root,root/'state/maintenance.lock'),shared=True), \
         lock(guarded_path(root,root/'state/locks/memory-pipeline-queue.lock')):
        from task_service import ensure_not_held
        ensure_not_held(root)
        if target.exists(): return {'queue_id':qid,'status':json.loads(target.read_text())['status'],'replayed':True}
        atomic_json(target, {**binding,'queue_id':qid,'status':'queued','attempts':0,
                             'created_at':now_iso(),'next_attempt_at':0})
    return {'queue_id':qid,'status':'queued','replayed':False}

def _queue_rows(root):
    rows=[];corrupt=0
    base=guarded_path(root,root/'state/memory-pipeline/queue')
    for p in sorted(base.glob('*.json')):
        try:
            row=json.loads(guarded_path(root,p).read_text())
            if not isinstance(row,dict) or any(k not in row for k in ('queue_id','event_id','scope','status','attempts')):
                raise ValueError('malformed_queue_item')
            if type(row['attempts']) is not int or row['attempts']<0:raise ValueError('invalid_attempts')
            if type(row.get('provider_attempts',0)) is not int or row.get('provider_attempts',0)<0:
                raise ValueError('invalid_provider_attempts')
            if type(row.get('receipt_sequence',0)) is not int or row.get('receipt_sequence',0)<0:
                raise ValueError('invalid_receipt_sequence')
            if not isinstance(row.get('configuration_history',[]),list):raise ValueError('invalid_configuration_history')
            if row['scope'] not in ROLE_IDS:raise ValueError('invalid_scope')
            if 'policy_digest' in row and (not isinstance(row['policy_digest'],str)
                    or not re.fullmatch(r'[a-f0-9]{64}',row['policy_digest'])):
                raise ValueError('invalid_queue_policy_digest')
            if 'learning_version' in row:
                version=row['learning_version'];profile_digest=row.get('learning_profile_digest')
                if version=='baseline':
                    if profile_digest is not None:raise ValueError('invalid_queue_learning_binding')
                elif (not isinstance(version,str) or not re.fullmatch(r'learn_[a-f0-9]{32}',version)
                      or not isinstance(profile_digest,str) or not re.fullmatch(r'[a-f0-9]{64}',profile_digest)):
                    raise ValueError('invalid_queue_learning_binding')
            safe_id(row['queue_id']);safe_id(row['event_id'])
            if p.name!=row['queue_id']+'.json':raise ValueError('queue_identity_mismatch')
            due=row.get('next_attempt_at',0)
            if type(due) not in (int,float) or not math.isfinite(due) or due<0:raise ValueError('invalid_next_attempt')
            if row['status'] not in {'queued','running','retry','completed','blocked','needs_review','credentials_rejected','held'} and not _model_waiting(row['status']):
                raise ValueError('invalid_queue_state')
            if row.get('receipt_recorded') is False and not isinstance(row.get('updated_at'),str):
                raise ValueError('invalid_receipt_timestamp')
            if 'result' in row:
                _review_refs(row['result'])
            rows.append((p,row))
        except (OSError,ValueError,KeyError,TypeError):corrupt+=1
    return rows,corrupt


def _review_refs(result):
    if not isinstance(result,dict):raise ValueError('invalid_queue_result')
    refs=result.get('review_refs',[])
    if (not isinstance(refs,list) or len(refs)>201 or len(set(ref for ref in refs if isinstance(ref,str)))!=len(refs)
            or any(not isinstance(ref,str) or not re.fullmatch(r'triage_[a-f0-9]{64}',ref) for ref in refs)
            or type(result.get('review_count',len(refs))) is not int
            or result.get('review_count',len(refs))!=len(refs)):
        raise ValueError('invalid_queue_review_refs')
    return refs


def _record_result(root,path,row):
    refs=_review_refs(row.get('result',{}))
    payload={'queue_id':row['queue_id'],'status':row['status'],'attempt':row['attempts']}
    if refs:payload.update(review_refs=refs,review_count=len(refs))
    sequence=row.get('receipt_sequence',row['attempts'])
    append_event(root,{'event_id':stable_id(row['queue_id'],sequence,row['status']),
        'event_type':'memory_pipeline_result','agent':row['scope'],'entry':'memory_pipeline',
        'parent_event_id':row['event_id'],'occurred_at':row['updated_at'],'completeness':'complete',
        'payload':payload})
    row['receipt_recorded']=True;atomic_json(path,row)


def status(root):
    root=Path(root).resolve();rows,corrupt=_queue_rows(root)
    counts=collections.Counter(row['status'] for _,row in rows)
    cfg=settings(root)
    controls=controls_status(root)
    held=sum(1 for _,row in rows if (row['status'] in {'queued','running','retry','held'} or _model_waiting(row['status']))
             and (not controls['global_enabled'] or not controls['roles'][row['scope']]))
    from jev_client import credentials_status
    from memory_screen import PIPELINE_VERSION
    from jev_policy import POLICY_VERSION, POLICY_DIGEST
    readiness = credentials_status(root)
    from memory_model_config import status as extraction_status
    extraction = extraction_status(root)
    return {'enabled':cfg['enabled'],'model':cfg['model'],'provider':cfg['provider'],
            'prompt_version':cfg['prompt_version'],'pipeline_version':PIPELINE_VERSION,
            'policy_version':POLICY_VERSION,'policy_digest':POLICY_DIGEST,
            'readiness':readiness,'extraction':extraction,'controls':controls,'held_queue_count':held,
             'execution_state':('paused' if not controls['global_enabled'] else 'disabled' if not cfg['enabled'] else
                'credentials_rejected' if counts.get('credentials_rejected') else
                'waiting_for_key' if not readiness['configured'] else
                extraction['status'] if extraction['status'] != 'ready' else 'ready'), 'queue_counts':dict(counts),
            'corrupt_queue_files':corrupt,'confirmation':'ai_reviewed_distinct_from_owner_confirmed'}

def _local_resume_runs(root):
    # One run index per worker tick; do not rescan per candidate or queue row.
    latest = {}
    for row in read_rows(root, Path(root) / 'memory/screen/runs.jsonl'):
        if isinstance(row.get('run_id'), str):
            latest[row['run_id']] = row
    return {run_id for run_id, row in latest.items()
            if row.get('candidates') and 'verified' in row
            and row.get('autoreview', {}).get('status') in {'paused','retry'}
            and row.get('checkpoint_digest') == digest({k:v for k,v in row.items() if k != 'checkpoint_digest'})}


async def process_once(root, *, limit=2, screen_fn=None):
    root=Path(root).resolve()
    from task_service import ensure_not_held
    ensure_not_held(root)
    cfg=settings(root)
    if not cfg['enabled']:return {'status':'disabled','processed':0}
    controls=controls_status(root)
    if not controls['global_enabled']:return {'status':'held','hold_reason':'global_paused','processed':0}
    dependency_state = None
    if screen_fn is None:
        from jev_client import credentials_status
        from memory_model_config import status as extraction_status
        readiness = credentials_status(root)
        extraction = extraction_status(root)
        dependency_state = ('waiting_for_key' if not readiness['configured'] else
                            extraction['status'] if extraction['status'] != 'ready' else None)
        from memory_screen import screen
        screen_fn=screen
    processed=[]; corrupt=0; receipts_recovered=0
    with lock(guarded_path(root,root/'state/maintenance.lock'),shared=True), \
         lock(guarded_path(root,root/'state/locks/memory-pipeline-worker.lock'),blocking=False):
        ensure_not_held(root)
        rows,corrupt=_queue_rows(root)
        resume_runs = _local_resume_runs(root)
        if dependency_state and not any((row.get('result') or {}).get('run_id') in resume_runs for _,row in rows):
            return {'status':dependency_state,'processed':0,'provider':cfg['provider'],
                    'model':cfg['model'],'readiness':readiness,'extraction':extraction,
                    'corrupt_queue_files':corrupt,'receipts_recovered':0}
        for p,row in rows:
            if row.get('receipt_recorded') is False and (row['status'] in {'completed','blocked','retry','needs_review','credentials_rejected','held'} or _model_waiting(row['status'])):
                _record_result(root,p,row);receipts_recovered+=1
        if any(row['status']=='credentials_rejected' for _,row in rows):
            return {'status':'credentials_rejected','processed':0,'provider':cfg['provider'],
                    'model':cfg['model'],'action':'replace_key_with_configure_jev',
                    'corrupt_queue_files':corrupt,'receipts_recovered':receipts_recovered}
        for p,row in rows:
            if len(processed)>=limit:break
            local_resume = ((row.get('result') or {}).get('run_id') in resume_runs
                            and (row['status'] in {'completed','needs_review','held','retry'} or _model_waiting(row['status'])))
            if dependency_state and not local_resume:continue
            if not local_resume and ((row['status'] not in {'queued','retry','running','held'} and not _model_waiting(row['status'])) or row.get('next_attempt_at',0)>time.time()):continue
            try:
                require_processing(root,row['scope'],'local_replay')
            except MemoryProcessingHeld:
                continue
            ensure_not_held(root)
            desired = {k:cfg[k] for k in ('provider','model','prompt_version')}
            from jev_policy import POLICY_DIGEST
            mismatch = ('queued_policy_unpinned' if 'policy_digest' not in row else
                        'queued_policy_changed' if row['policy_digest'] != POLICY_DIGEST else
                        'queued_configuration_changed' if any(row.get(k)!=v for k,v in desired.items()) else None)
            if mismatch:
                # An operator may explicitly enqueue under the new identity.
                # Never silently move paid partial work onto a different policy.
                row.update(status='blocked',error_code=mismatch,updated_at=now_iso(),receipt_recorded=False)
                atomic_json(p,row);_record_result(root,p,row)
                processed.append({'queue_id':row['queue_id'],'status':'blocked','reason':mismatch})
                continue
            row['provider_attempts']=row.get('provider_attempts',0)+1
            # Waiting does not exhaust processing attempts, but each emitted
            # result receipt still needs a unique, crash-replayable identity.
            row['receipt_sequence']=row.get('receipt_sequence',row['attempts'])+1
            row.update(status='running',attempts=row['attempts']+1,updated_at=now_iso());atomic_json(p,row)
            try:
                event=load_event(root,row['event_id']);text=select_text(event,row['text_path'])
                if digest(event)!=row['source_digest'] or digest(text)!=row['text_digest']:
                    raise ValueError('queued_source_changed')
                result=await asyncio.wait_for(screen_fn(root,event_id=row['event_id'],scope=row['scope'],
                    text=text,source_digest=row['source_digest'],model=row['model'],
                    prompt_version=row['prompt_version'],learning_version=row.get('learning_version','baseline'),
                    learning_profile_digest=row.get('learning_profile_digest'),
                    resume_run_id=(row.get('result') or {}).get('run_id')),timeout=300)
                state=result.get('status')
                _review_refs(result)
                row['result']={k:result[k] for k in ('run_id','status','outcome','candidates','review_refs','review_count','autoreview','hold_reason') if k in result}
                row['result']['decision']=(result.get('screening') or {}).get('decision')
                row['status']=('completed' if state in {'complete','completed'} else
                               state if state in {'blocked','credentials_rejected','needs_review','held'} or _model_waiting(state) else 'retry')
                if state in {'complete','completed','needs_review'} and _review_refs(row['result']):
                    row['status']='needs_review'
                if row['status']=='held' or _model_waiting(row['status']):
                    row['attempts']=max(0,row['attempts']-1)
                    row['provider_attempts']=max(0,row['provider_attempts']-1)
                    row['next_attempt_at']=time.time()+60 if _model_waiting(row['status']) else 0
            except MemoryProcessingHeld as exc:
                row.update(status='held',hold_reason=exc.code,next_attempt_at=0)
                row['provider_attempts']=max(0,row['provider_attempts']-1)
            except Exception as exc:
                row['status']='blocked' if isinstance(exc,(ValueError,KeyError)) else 'retry'
                row['error_type']=type(exc).__name__
            if row['status']=='retry':
                row['next_attempt_at']=time.time()+min(3600,60*2**min(row['provider_attempts'],6))
                if row['provider_attempts']>=5:row['status']='needs_review'
            row.update(updated_at=now_iso(),receipt_recorded=False);atomic_json(p,row)
            _record_result(root,p,row)
            processed.append({'queue_id':row['queue_id'],'status':row['status']})
            if row['status']=='credentials_rejected' or _model_waiting(row['status']):break
    return {'status':'attention_required' if corrupt else dependency_state if dependency_state and not processed else 'ok','processed':len(processed),
            'corrupt_queue_files':corrupt,'receipts_recovered':receipts_recovered,'items':processed}

def retry_pending(root, triage_id, expected_digest, command_id):
    """Resume an actually failed stage; never silently rerun a terminal model result.

    A completed empty extraction or invalid typed response needs new evidence.
    Callers authenticate the local memory session; no owner confirmation occurs.
    """
    root=Path(root).resolve();safe_id(triage_id);safe_id(command_id)
    from memory_triage import _read, get_pending
    from memory_controls import _write
    receipt_rel='state/memory-pipeline/retries/'+command_id+'.json'
    binding={'triage_id':triage_id,'expected_digest':expected_digest,'command_id':command_id}
    with lock(guarded_path(root,root/'state/maintenance.lock'),shared=True), \
         lock(guarded_path(root,root/'state/locks/memory-pipeline-worker.lock'),blocking=False):
        from task_service import ensure_not_held
        ensure_not_held(root)
        receipt=guarded_path(root,root/receipt_rel)
        if receipt.exists():
            old=json.loads(receipt.read_text())
            if old.get('binding') != binding:raise ValueError('command_id_conflict')
            return old['result']
        item=_read(root,guarded_path(root,root/'memory/triage/items'/(triage_id+'.json')))
        if item['record_digest'] != expected_digest:raise ValueError('stale_triage_version')
        public=get_pending(root,triage_id)
        if public['source_integrity'] != 'verified' or public['status'] != 'needs_review':
            raise ValueError('triage_not_pending_or_source_changed')
        from memory_autoreview import MemoryAutoreview
        if triage_id in MemoryAutoreview(root).resolved():raise ValueError('triage_already_reviewed')
        bound=item['binding']
        runs=[r for r in read_rows(root,root/'memory/screen/runs.jsonl') if r.get('run_id')==bound['run_id']]
        run=runs[-1] if runs else None
        result={'status':'not_retryable','reason':'new_source_required','can_supplement':True,
                'triage_id':triage_id,'model_called':False}
        if run and run.get('status')=='retry' and 'policy_validation_failure' not in run:
            if run.get('checkpoint_digest') != digest({k:v for k,v in run.items() if k!='checkpoint_digest'}):
                raise ValueError('screen_checkpoint_integrity_failed')
            if any(run.get(k)!=bound.get(k) for k in ('event_id','scope','source_digest','content_digest','policy_digest')):
                raise ValueError('triage_run_binding_mismatch')
            rows,corrupt=_queue_rows(root)
            matching=[(p,row) for p,row in rows if (row.get('result') or {}).get('run_id')==bound['run_id']
                      and row['event_id']==bound['event_id'] and row['scope']==bound['scope']
                      and row['source_digest']==bound['source_digest']]
            if len(matching)==1:
                path,row=matching[0]
                # The source and exact selected text are checked again on processing.
                row.update(status='retry',provider_attempts=0,next_attempt_at=0,updated_at=now_iso())
                if command_id not in row.setdefault('manual_retry_commands',[]):
                    row['manual_retry_commands'].append(command_id)
                _write(root,str(path.relative_to(root)),row)
                result={'status':'queued','queue_id':row['queue_id'],'triage_id':triage_id,
                        'preserved_checkpoints':True,'model_called':False}
        _write(root,receipt_rel,{'binding':binding,'result':result})
        return result


def resume_credentials(root):
    """After an explicit key replacement, unblock only authentication failures."""
    root=Path(root).resolve(); resumed=0
    with lock(guarded_path(root,root/'state/maintenance.lock'),shared=True), \
         lock(guarded_path(root,root/'state/locks/memory-pipeline-worker.lock')):
        from task_service import ensure_not_held
        ensure_not_held(root)
        rows,_=_queue_rows(root)
        for path,row in rows:
            if row['status']!='credentials_rejected':continue
            if row.get('receipt_recorded') is False:_record_result(root,path,row)
            row.update(status='queued',provider_attempts=0,next_attempt_at=0,
                       credentials_reset_at=now_iso(),updated_at=now_iso())
            atomic_json(path,row);resumed+=1
    return resumed


async def advance_learning_when_idle(root, *, advance_fn=None):
    """Use the existing worker for bounded feedback evaluation after RAW work."""
    root = Path(root).resolve()
    from task_service import ensure_not_held
    ensure_not_held(root)
    current = status(root)
    pending = {'queued', 'running', 'retry', 'held', 'waiting_for_key', 'waiting_for_configuration', 'credentials_rejected'}
    if (not current['enabled'] or current['execution_state'] != 'ready'
            or current['corrupt_queue_files'] or any(v for k,v in current['queue_counts'].items()
                                                    if k in pending or _model_waiting(k))):
        return {'status': 'deferred', 'reason': 'raw_pipeline_not_idle_and_ready'}
    if advance_fn is None:
        from memory_learning import MemoryLearning
        advance_fn = MemoryLearning(root).advance
    # One profile, at most four requests per tick. The learner owns its durable
    # per-case checkpoints, so a later tick resumes only unstarted work.
    return await advance_fn(limit=1, max_calls=4)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['status','enqueue','run'])
    p.add_argument('--root',default=str(Path.home()/'javis'));p.add_argument('--event-id');p.add_argument('--scope')
    p.add_argument('--limit',type=int,default=2);a=p.parse_args()
    try:
        if a.command=='status':out=status(a.root)
        elif a.command=='enqueue':out=enqueue(a.root,event_id=a.event_id,scope=a.scope)
        else:
            from memory_sync import run
            # The scheduled worker owns this side independently from Grok.
            # run() uses content-addressed snapshots, making repeated visits safe.
            try:sync_result=run(a.root)
            except Exception as exc:
                sync_result={'state':'failed','error_type':type(exc).__name__}
            out=asyncio.run(process_once(a.root,limit=max(1,min(a.limit,10))))
            out['sync_status']=sync_result['state']
            if sync_result.get('error_type'):out['sync_error_type']=sync_result['error_type']
            if out.get('status') == 'ok' and out.get('processed') == 0:
                try:
                    out['learning'] = asyncio.run(advance_learning_when_idle(a.root))
                except BlockingIOError:
                    out['learning'] = {'status': 'already_running'}
                except Exception as exc:
                    out['learning'] = {'status': 'error', 'error_type': type(exc).__name__}
        print(json.dumps(out,ensure_ascii=False));return 0
    except BlockingIOError:
        print(json.dumps({'status':'already_running'}));return 0
    except Exception as exc:
        print(json.dumps({'status':'error','error_type':type(exc).__name__}));return 1

if __name__=='__main__':raise SystemExit(main())
