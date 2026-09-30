"""Durable local task consumer. Only explicit persisted dispatches can launch workers."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from runtime_io import atomic_json, lock
from task_control import process_identity, safe_id
from task_service import ROLES, load_control, save_control, digest, control_ids, ControlService, ControlError, ensure_not_held, memory_repair_guard, seal_memory_repair_locked
from task_control import now, state_event
from role_registry import role_workspace

def prepare_packet(root, c, state):
    """Bound stdin context; exact originals remain separate immutable RAW references."""
    role_workspace(root,c['role_id'])
    dispatch=c['dispatch'];revision=dispatch['goal_revision']
    if dispatch.get('mode')=='reconcile_memory':
        memory_repair_guard(root,c,state)
        path=root/'workspace/tasks'/c['task_id']/'packet.json'
        original=json.loads(path.read_text())
        if digest(original)!=dispatch['original_packet_sha256']:raise ControlError('packet_identity_changed','Original executed packet changed; no memory repair started')
        return {**original,'mode':'reconcile_memory','control_dispatch_id':dispatch['command_id'],
            'memory_repair_source_sha256':dispatch['source_receipt_sha256']}
    goals=[g for g in c['goals'] if g['revision']<=revision]
    effective='\n\n'.join(('Original request' if g['revision']==1 else f"Append revision {g['revision']}")+':\n'+g['text'] for g in goals)
    task=root/'workspace/tasks'/c['task_id'];task.mkdir(parents=True,exist_ok=True)
    references=[{'revision':g['revision'],'event_id':g['event_id'],'input_sha256':g['input_sha256']} for g in goals]
    prior={'attempt':state.get('attempt',0),'session_id':state.get('session_id'),'state':state.get('state'),
        'artifact_refs':state.get('artifact_refs',[]),'failure_reason':state.get('failure_reason')}
    handoff={'task_id':c['task_id'],'goal_revision':revision,'original_inputs':goals,
        'effective_goal':effective,'prior_checkpoint':prior,'instructions':'Read all requested constraints before tools. Verify existing artifacts; never replay uncertain external actions.'}
    budget=c['context_budget_bytes'];oversize=len(effective.encode())+len(goals[0]['text'].encode())+6144>budget
    prior_tokens=(state.get('native_usage') or {}).get('input_tokens',0)
    observed_budget=type(prior_tokens) is int and prior_tokens>=c.get('native_context_budget_tokens',16000)
    # Explicit new session when the bounded input would overflow, or when retrying.
    fresh=oversize or observed_budget or dispatch['mode']=='retry' or (dispatch['mode'] in {'resume','continue'} and not state.get('session_id'))
    path=task/'attempts'/str(dispatch['expected_attempt']+1)/'continuation.json'
    atomic_json(path,handoff)
    if oversize:
        goal=f"Continue task {c['task_id']} at goal revision {revision}. Read the complete original request and every append from {path} before acting. Preserve all constraints; inspect prior artifacts and do not replay uncertain actions."
    else: goal=effective
    packet={'task_id':c['task_id'],'role_id':c['role_id'],'from_agent_id':ROLES[c['role_id']],
        'goal':goal,'original_user_input':goals[0]['text'],'source_event_id':goals[0].get('source_event_id'),
        'current_user_input':goals[-1]['text'],'current_input_ref':{k:goals[-1][k] for k in ('event_id','input_sha256','revision','source_event_id')},
        'permission':c['permission'],'entry':c['entry'],'mode':dispatch['mode'],
        'control_dispatch_id':dispatch['command_id'],'goal_revision':revision,'original_input_refs':references,
        'context':{'budget_bytes':budget,'inline_effective_goal_bytes':len(goal.encode()),'handoff_ref':str(path),
            'native_context_budget_tokens':c.get('native_context_budget_tokens',16000),'prior_observed_input_tokens':prior_tokens,
            'new_native_session':fresh,'reason':'input_budget_handoff' if oversize else ('explicit_retry' if dispatch['mode']=='retry' else ('new_session_without_native_checkpoint' if fresh else 'native_continuation')),
            'original_in_prompt':not oversize,'bounded_input_only':True}}
    if observed_budget and not oversize:packet['context']['reason']='observed_native_usage_budget'
    return packet

def consume(root, tid):
    root=Path(root).resolve();tid=safe_id(tid)
    # Separate launch ownership from runtime task lock; a stale claimed dispatch is never blindly relaunched.
    with lock(root/'state/maintenance.lock',shared=True),lock(root/'state/locks'/f'{tid}.dispatch.lock',blocking=False):
        ensure_not_held(root)
        with lock(root/'state/locks'/f'{tid}.control.lock'):
            c=load_control(root,tid);d=c.get('dispatch') or {}
            if c.get('schema')!='javis-control-1':return {'task_id':tid,'status':'unmanaged','launched':False}
            if d.get('status')!='queued': return {'task_id':tid,'status':d.get('status'),'launched':False}
            ControlService(root)._ensure_queued(c)
            statepath=root/'state/tasks'/f'{tid}.json';state=json.loads(statepath.read_text())
            if state.get('attempt',0)!=d['expected_attempt'] or state.get('state') in {'created','running'}:
                d.update(status='needs_review',reason='State changed before dispatch; no worker launched')
                save_control(root,c,'dispatch_rejected',d['command_id']);return {'task_id':tid,'status':'needs_review','launched':False}
            for label in ('runner','worker'):
                identity=process_identity(state.get(label+'_pid'))
                if identity and identity==state.get(label+'_identity'):
                    if label=='runner' and state.get('process_cleanup',{}).get('ok') is True and str(state.get('attempt')) in c.get('attempt_receipts',{}):
                        return {'task_id':tid,'status':'queued','launched':False,'reason':'Finalized runner is still exiting; wait for its execution lock'}
                    d.update(status='needs_review',reason='Previous process identity is still alive')
                    save_control(root,c,'dispatch_rejected',d['command_id']);return {'task_id':tid,'status':'needs_review','launched':False}
            try:packet=prepare_packet(root,c,state)
            except (ControlError,OSError,ValueError) as exc:
                d.update(status='needs_review',reason='Pre-dispatch validation failed: '+(exc.code if isinstance(exc,ControlError) else type(exc).__name__))
                c['commands'][d['command_id']].update(status='needs_review',reason=d['reason'])
                save_control(root,c,'dispatch_rejected',d['command_id'])
                return {'task_id':tid,'status':'needs_review','launched':False}
            path=root/'workspace/tasks'/tid/'dispatch'/f"{d['command_id']}.json"
            atomic_json(path,packet)
            d.update(status='claimed',dispatcher_pid=os.getpid(),dispatcher_identity=process_identity(os.getpid()),packet_sha256=digest(packet),packet_ref=str(path))
            save_control(root,c,'dispatch_claimed',d['command_id'])
        env={**os.environ,'JAVIS_ROOT':str(root)}
        p=subprocess.run([sys.executable,str(Path(__file__).with_name('task-runner.py')),str(path)],env=env,capture_output=True,text=True)
        with lock(root/'state/locks'/f'{tid}.control.lock'):
            c=load_control(root,tid);d=c['dispatch']
            if d['status'] in {'claimed','started'}:
                d.update(status='needs_review',reason='Executor returned without a finalized control acknowledgement',exit_code=p.returncode)
                save_control(root,c,'dispatch_unacknowledged',d['command_id'])
        return {'task_id':tid,'status':d['status'],'exit_code':p.returncode,'launched':True}

def reconcile(root,tid):
    """Dead consumer does not authorize reexecution. Runtime receipt can prove completion."""
    with lock(root/'state/maintenance.lock',shared=True),lock(root/'state/locks'/f'{tid}.control.lock'):
        c=load_control(root,tid);d=c.get('dispatch') or {}
        if c.get('schema')!='javis-control-1':return
        if d.get('status') not in {'claimed','started'}: return
        identity=process_identity(d.get('dispatcher_pid'))
        if identity and identity==d.get('dispatcher_identity'): return
        statepath=root/'state/tasks'/f'{tid}.json';state=json.loads(statepath.read_text()) if statepath.exists() else {}
        identity=process_identity(state.get('runner_pid'))
        if identity and identity==state.get('runner_identity'): return
        # The launch gap can leave queued/created state even though dispatch is claimed.
        # Expose an explicit reviewed recovery path after checking the execution lock.
        try:
            with lock(root/'state/locks'/f'{tid}.lock',blocking=False):
                state=json.loads(statepath.read_text()) if statepath.exists() else {}
                if d.get('mode')=='reconcile_memory':
                    try:
                        seal_memory_repair_locked(root,c,state)
                        return
                    except ControlError:
                        # No command-bound receipt proves completion. Never re-run the repair implicitly.
                        pass
                if state and state.get('state') in {'queued','created','running'}:
                    worker=process_identity(state.get('worker_pid'))
                    state.update(state='waiting_user',updated_at=now(),recovery_required=True,
                        orphan_worker_may_be_running=bool(worker and worker==state.get('worker_identity')),
                        failure_reason='dispatcher_interrupted; inspect last action before explicit reviewed retry')
                    atomic_json(statepath,state);state_event(root,state,'dispatch_recovery_required')
        except BlockingIOError:return
        d.update(status='needs_review',reason='Dispatcher/runner disappeared; inspect attempt receipt and process tree. No automatic reexecution.')
        save_control(root,c,'dispatch_interrupted',d['command_id'])

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',default=os.environ.get('JAVIS_ROOT',str(Path.home()/'javis')))
    p.add_argument('--task-id');p.add_argument('--once',action='store_true');p.add_argument('--max-workers',type=int,default=2)
    args=p.parse_args();root=Path(args.root).resolve()
    if args.task_id:
        try: print(json.dumps(consume(root,args.task_id),ensure_ascii=False))
        except BlockingIOError: return 75
        except ControlError as exc:print(json.dumps({'ok':False,'error':exc.code,'message':str(exc)}));return 77
        return 0
    children={}
    with lock(root/'state/locks/task-dispatch-coordinator.lock',blocking=False):
        while True:
            try:ensure_not_held(root)
            except ControlError:
                if args.once:return 77
                time.sleep(.25);continue
            children={tid:child for tid,child in children.items() if child.poll() is None}
            for tid in control_ids(root):
                if tid in children: continue
                reconcile(root,tid)
                c=load_control(root,tid)
                if c.get('schema')!='javis-control-1':continue
                if (c.get('dispatch') or {}).get('status')=='queued' and len(children)<max(1,args.max_workers):
                    children[tid]=subprocess.Popen([sys.executable,__file__,'--root',str(root),'--task-id',tid],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
            if args.once:
                for child in children.values(): child.wait()
                return 0
            time.sleep(.25)

if __name__=='__main__': raise SystemExit(main())
