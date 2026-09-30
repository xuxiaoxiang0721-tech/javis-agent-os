#!/usr/bin/env python3
"""Execute one fixed workflow through actual Flowise and the trusted local UDS API."""
import argparse,hashlib,json,os,pathlib,re,stat,time
from fixed_work import FixedWorkManager,read,now,JOB_ID
from flowise_session import FlowiseSession
from flowise_flow import build_flow,SOCKET

def run(root,run_id,timeout=900):
    if not re.fullmatch(r'fw-[a-f0-9]{24}',run_id):raise ValueError('Invalid run_id')
    manager=FixedWorkManager(root)
    record=read(manager.runs/(run_id+'.json'))
    if record['job_id']!=JOB_ID or record['state'] not in {'queued','starting'}:raise ValueError('Run has already started; no automatic continuation')
    manager.update_run(run_id,state='starting',actual_at=now())
    try:
        sock=pathlib.Path(SOCKET)
        info=sock.stat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.getuid():raise ValueError('Trusted workflow socket unavailable')
        flow=build_flow();definition=json.dumps(flow,ensure_ascii=False)
        execution_ids=[]
        with FlowiseSession() as session:
            _,created=session.request('POST','/api/v1/chatflows',{'name':'Javis '+JOB_ID,'flowData':definition,'type':'AGENTFLOW','isPublic':False,'deployed':True})
            flow_id=created['id']
            _,saved=session.request('GET','/api/v1/chatflows/'+flow_id)
            if json.loads(saved['flowData'])!=flow:raise ValueError('Flow definition read-back mismatch')
            manager.update_run(run_id,state='running',flowise_version='3.1.4',flow_id=flow_id,flow_definition_sha256=hashlib.sha256(definition.encode()).hexdigest(),editor_persistent=False)
            deadline=time.monotonic()+timeout
            while True:
                _,response=session.request('POST','/api/v1/prediction/'+flow_id,{'question':json.dumps({'command_id':record['command_id']}),'streaming':False},timeout=60)
                result=json.loads(response['text'])
                execution_ids.append(response.get('executionId'))
                manager.update_run(run_id,task_id=result.get('task_id'),attempt=result.get('attempt'),task_state=result.get('state'),flow_execution_ids=execution_ids)
                if not result.get('pending'):
                    complete=result.get('current_goal_completed') is True
                    state='completed' if complete else 'needs_review'
                    manager.update_run(run_id,state=state,current_goal_completed=complete,result_ref=result.get('result_ref'),result_sha256=result.get('result_sha256'),finished_at=now(),flow_result=result)
                    break
                if time.monotonic()>=deadline:
                    manager.update_run(run_id,state='needs_review',reason='task_wait_timeout_no_resubmit',finished_at=now())
                    break
                time.sleep(3)
        manager.update_run(run_id,ephemeral_runtime_removed=not session.run_dir.exists(),plaintext_secret_files=session.secret_leak_files)
    except Exception as error:
        manager.update_run(run_id,state='needs_review',error_type=type(error).__name__,reason=str(error)[:400],finished_at=now())
    final=read(manager.runs/(run_id+'.json'))
    print(json.dumps({k:final.get(k) for k in ('run_id','state','task_id','attempt','current_goal_completed','result_ref','result_sha256','reason')},ensure_ascii=False))
    return 0 if final['state']=='completed' else 1

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=pathlib.Path,required=True);p.add_argument('--run-id',required=True);args=p.parse_args();raise SystemExit(run(args.root,args.run_id))
