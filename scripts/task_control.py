"""Task state and cooperative control; recovery never automatically replays tools."""
import argparse, json, os, re, sys, uuid
from datetime import datetime, timezone
from pathlib import Path
from runtime_io import atomic_json, lock
from raw_policy import sanitize
from raw_storage import append_event, stable_id
from task_service import Principal, ControlService, ControlError

def now(): return datetime.now(timezone.utc).isoformat()

def safe_id(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}',value):
        raise ValueError('invalid task_id or role_id')
    return value

def process_identity(pid):
    try:
        stat=(Path('/proc')/str(int(pid))/'stat').read_text()
        # comm can contain spaces; starttime is field 22.
        start=stat[stat.rfind(')')+2:].split()[19]
        return (Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+str(pid)+':'+start)
    except (OSError,ValueError,TypeError,IndexError): return None

def state_event(root,state,phase,*,details=None):
    stamp=now()
    return append_event(root,{'event_id':stable_id(state['task_id'],state.get('attempt',0),phase,uuid.uuid4().hex),
        'task_id':state['task_id'],'session_id':state.get('session_id'),'turn_id':state.get('turn_id'),
        'entry':state.get('entry'),'agent':state.get('role_id'),'model':state.get('model'),
        'execution_path':state.get('execution_path'),'risk':state.get('risk'),
        'event_type':'task_lifecycle','occurred_at':stamp,'captured_at':stamp,'timezone':'Asia/Shanghai',
        'completeness':'complete','payload':{'phase':phase,'state_snapshot':sanitize(state),'details':details or {}}})

def request_control(root,tid,action):
    tid=safe_id(tid); path=root/'state/tasks'/f'{tid}.json'
    state=json.loads(path.read_text())
    if state.get('control_managed'):
        from task_service import local_principal
        service=ControlService(root);principal=local_principal();status=service.status(principal,tid)
        return service.command(principal,tid,{'command_id':'local-'+uuid.uuid4().hex,'action':action,
            'expected_goal_revision':status['goal_revision'],'expected_attempt':status['attempt']})
    with lock(root/'state/maintenance.lock',shared=True),lock(root/'state/locks'/f'{tid}.control.lock'):
        state=json.loads(path.read_text())
        if state.get('state')!='running': raise ValueError('task is not running')
        if process_identity(state.get('runner_pid'))!=state.get('runner_identity'):
            raise ValueError('runner is unavailable; run recover first')
        req={'request_id':uuid.uuid4().hex,'task_id':tid,'attempt':state['attempt'],
             'action':action,'requested_at':now(),'status':'requested'}
        atomic_json(root/'state/control'/f'{tid}.json',req)
        state_event(root,state,'control_requested',details=req)
        return {'ok':True,**req,'note':'Requested only; wait for paused/cancelled state before assuming execution stopped.'}

def recover(root):
    recovered=[]; active=[]
    with lock(root/'state/maintenance.lock',shared=True):
        for path in sorted((root/'state/tasks').glob('*.json')):
            state=json.loads(path.read_text())
            if state.get('state')!='running': continue
            tid=safe_id(state['task_id'])
            try:
                with lock(root/'state/locks'/f'{tid}.lock',blocking=False):
                    state=json.loads(path.read_text())
                    identity=process_identity(state.get('runner_pid'))
                    if identity and identity==state.get('runner_identity'):
                        active.append(tid); continue
                    # An orphan worker may still be alive. Record uncertainty;
                    # do not kill unrelated/reused PIDs or launch another worker.
                    worker_identity=process_identity(state.get('worker_pid'))
                    worker_active=bool(worker_identity and worker_identity==state.get('worker_identity'))
                    state.update(state='waiting_user',updated_at=now(),recovery_required=True,
                        failure_reason='runner_interrupted; verify last successful action before resuming',
                        orphan_worker_may_be_running=worker_active,
                        available_recovery='native_session' if state.get('session_id') else 'file_checkpoint_only')
                    atomic_json(path,state); state_event(root,state,'recovery_required')
                    recovered.append(tid)
            except BlockingIOError: active.append(tid)
    return {'ok':True,'recovered_to_waiting_user':recovered,'active':active,'automatically_replayed':[]}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    s=p.add_subparsers(dest='cmd',required=True)
    for name in ['pause','cancel','status']:
        q=s.add_parser(name); q.add_argument('task_id')
    s.add_parser('recover')
    args=p.parse_args(); root=Path(os.environ.get('JAVIS_ROOT',Path.home()/'javis')).resolve()
    if args.cmd=='recover': result=recover(root)
    elif args.cmd=='status':
        result=json.loads((root/'state/tasks'/f'{safe_id(args.task_id)}.json').read_text())
        if result.get('control_managed'):
            from task_service import local_principal
            result=ControlService(root).status(local_principal(),args.task_id)
    else: result=request_control(root,args.task_id,args.cmd)
    print(json.dumps(sanitize(result),ensure_ascii=False,indent=2))

if __name__=='__main__':
    try: main()
    except (OSError,ValueError,KeyError) as e:
        print(str(sanitize(str(e))),file=sys.stderr); raise SystemExit(2)
