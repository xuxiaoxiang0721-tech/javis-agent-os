"""Common control integration with a synthetic native worker. No real inference."""
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
import test_v02_runtime as base_runtime
CODE=base_runtime.CODE
sys.path.insert(0,str(CODE/'scripts'))
from task_control import Principal, ControlService, ControlError
from task_service import load_control

FAKE=r'''#!/usr/bin/env python3
import json,os,sys,time,uuid
from pathlib import Path
args=sys.argv[1:];prompt=sys.stdin.read()
calls=Path(os.environ['FAKE_CALLS'])
with calls.open('a') as f:f.write(json.dumps({'args':args,'prompt':prompt})+'\n')
sid=args[args.index('resume')+1] if 'resume' in args else 'synthetic-'+uuid.uuid4().hex
def emit(x):print(json.dumps(x),flush=True)
emit({'type':'thread.started','thread_id':sid})
emit({'type':'item.completed','item':{'id':'tool1','type':'command_execution','command':'synthetic','exit_code':0,'aggregated_output':'started'}})
if 'SLOW_P1' in prompt and 'resume' not in args:time.sleep(20)
if 'FAIL_P1' in prompt and len(calls.read_text().splitlines())==1:sys.exit(9)
out=Path(prompt.split('Write deliverables under: ',1)[1].split('\n')[0]);out.mkdir(parents=True,exist_ok=True)
(out/'answer.txt').write_text('synthetic completed')
emit({'type':'item.completed','item':{'id':'reply','type':'agent_message','text':'SUMMARY: synthetic completed'}})
emit({'type':'turn.completed','usage':{'input_tokens':20000 if 'USAGE_P1' in prompt else 10,'output_tokens':10}})
'''

class ControlP1(unittest.TestCase):
    def setUp(self):
        base_runtime.RuntimeV02.setUp(self)
        for role in ('cards-master','invest'):(self.r/'workspace/roles'/role).mkdir(parents=True)
        self.fake.write_text(base_runtime.bind_fake_calls(FAKE,self.calls))
        self.env['JAVIS_MEMORY_GRAPH_DISABLED']='1'
        self.svc=ControlService(self.r)
        self.owner=Principal('synthetic-owner','owner',frozenset({'cards-master','invest'}),frozenset({'task:create','task:read','task:control'}),'proof-test')
    tearDown=base_runtime.RuntimeV02.tearDown
    def create(self,text='synthetic task',**kw):
        return self.svc.submit(self.owner,{'command_id':'create-1','role_id':'cards-master','original_text':text,**kw})
    def cmd(self,tid,action,cid,**kw):
        st=self.svc.status(self.owner,tid)
        return self.svc.command(self.owner,tid,{'command_id':cid,'action':action,'expected_goal_revision':st['goal_revision'],'expected_attempt':st['attempt'],**kw})
    def launch(self,tid,wait=True):
        args=[sys.executable,str(self.r/'scripts/task_dispatch.py'),'--task-id',tid]
        if wait:return subprocess.run(args,env=self.env,capture_output=True,text=True,timeout=40)
        p=subprocess.Popen(args,env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(lambda:p.poll() is None and p.kill());return p
    def wait_running(self,tid):
        for _ in range(250):
            st=self.svc.status(self.owner,tid)
            if st.get('session_id'):return st
            time.sleep(.02)
        self.fail('synthetic worker not running')
    def count(self):return len(self.calls.read_text().splitlines()) if self.calls.exists() else 0
    def test_acceptance_is_durable_and_deduped_without_worker(self):
        a=self.create();b=self.create();self.assertEqual(a['task_id'],b['task_id']);self.assertTrue(b['replayed'])
        self.assertEqual(self.svc.status(self.owner,a['task_id'])['state'],'queued');self.assertEqual(self.count(),0)
        with self.assertRaises(ControlError):self.create('changed')
    def test_body_cannot_set_actor_and_roles_are_scoped(self):
        with self.assertRaises(ControlError):self.create(actor_id='other')
        limited=Principal('flowise','service',frozenset({'invest'}),frozenset({'task:create'}))
        with self.assertRaises(ControlError):self.svc.submit(limited,{'command_id':'x','role_id':'cards-master','original_text':'x'})
        tid=self.create()['task_id']
        with self.assertRaises(ControlError):self.svc.status(Principal('other','owner',self.owner.role_ids,self.owner.capabilities),tid)
    def test_raw_projection_repairs_acceptance_without_new_task(self):
        tid=self.create()['task_id'];(self.r/'state/control'/f'{tid}.json').unlink();(self.r/'state/tasks'/f'{tid}.json').unlink()
        again=self.create();self.assertEqual(again['task_id'],tid);self.assertTrue(again['replayed'])
        self.assertEqual(self.svc.status(self.owner,tid)['state'],'queued')
    def test_submit_launch_once_and_receipt(self):
        tid=self.create()['task_id'];p=self.launch(tid);self.assertEqual(p.returncode,0,p.stderr+p.stdout)
        st=self.svc.status(self.owner,tid);self.assertEqual(st['state'],'completed',st);self.assertTrue(st['current_goal_completed'])
        self.assertEqual(st['commands'][0]['status'],'applied');self.assertEqual(st['attempt'],1)
        self.assertEqual(self.svc.result(self.owner,tid)['result']['exit_code'],0)
        self.launch(tid);self.assertEqual(self.count(),1)
    def test_append_cas_and_stale_result_not_current(self):
        tid=self.create()['task_id'];self.launch(tid)
        a=self.cmd(tid,'append','append-1',original_text='add exact new constraint')
        self.assertEqual(a['status'],'received');self.assertFalse(self.svc.status(self.owner,tid)['current_goal_completed'])
        with self.assertRaises(ControlError):self.svc.command(self.owner,tid,{'command_id':'stale','action':'append','expected_goal_revision':1,'expected_attempt':1,'original_text':'stale'})
        self.cmd(tid,'continue','continue-1');self.launch(tid)
        st=self.svc.status(self.owner,tid);self.assertTrue(st['current_goal_completed'],st);self.assertEqual(st['attempt'],2)
        self.assertEqual(st['applied_goal_revision'],2);self.assertEqual(self.svc.result(self.owner,tid,1)['result']['goal_revision'],1)
        calls=[json.loads(x) for x in self.calls.read_text().splitlines()]
        self.assertIn('add exact new constraint',calls[1]['prompt']);self.assertIn('resume',calls[1]['args'])
    def test_running_append_pause_ack_and_resume_same_task(self):
        tid=self.create('SLOW_P1 original constraint')['task_id'];p=self.launch(tid,False);self.wait_running(tid)
        a=self.cmd(tid,'append','a1',original_text='AFTER_APPEND constraint');self.assertEqual(a['status'],'received')
        pause=self.cmd(tid,'pause','p1');self.assertEqual(pause['status'],'received')
        p.communicate(timeout=15)
        st=self.svc.status(self.owner,tid);self.assertEqual(st['state'],'paused',st)
        stopped=[x for x in st['commands'] if x['command_id']=='p1'][0];self.assertEqual(stopped['status'],'applied')
        self.assertEqual(st['applied_goal_revision'],1)
        self.cmd(tid,'resume','r1');self.launch(tid);st=self.svc.status(self.owner,tid)
        self.assertEqual(st['attempt'],2);self.assertEqual(st['state'],'completed',st);self.assertEqual(st['applied_goal_revision'],2)
        self.assertEqual(self.count(),2)
    def test_failed_task_requires_explicit_reviewed_retry(self):
        tid=self.create('FAIL_P1')['task_id'];self.launch(tid);self.assertEqual(self.svc.status(self.owner,tid)['state'],'failed')
        self.create('FAIL_P1');self.launch(tid);self.assertEqual(self.count(),1)
        with self.assertRaises(ControlError):self.cmd(tid,'retry','retry-1')
        self.cmd(tid,'retry','retry-1',review_confirmed=True);self.launch(tid)
        st=self.svc.status(self.owner,tid);self.assertEqual(st['state'],'completed',st);self.assertEqual(st['attempt'],2)
        self.assertNotIn('resume',json.loads(self.calls.read_text().splitlines()[1])['args'])
    def test_queued_cancel_does_not_launch(self):
        tid=self.create()['task_id'];self.assertEqual(self.cmd(tid,'cancel','c1')['status'],'applied')
        self.launch(tid);self.assertEqual(self.count(),0)
    def test_oversize_context_handoff_uses_new_native_session(self):
        tid=self.create()['task_id'];self.launch(tid)
        self.cmd(tid,'append','a1',original_text='bounded constraint '*1400)
        self.cmd(tid,'continue','c1');self.launch(tid)
        st=self.svc.status(self.owner,tid);self.assertEqual(st['state'],'completed',st)
        calls=[json.loads(x) for x in self.calls.read_text().splitlines()];self.assertNotIn('resume',calls[1]['args'])
        self.assertLess(len(calls[1]['prompt'].encode()),16384)
        receipt=self.svc.result(self.owner,tid)['result'];self.assertEqual(receipt['context']['reason'],'input_budget_handoff')
        handoff=json.loads(Path(receipt['context']['handoff_ref']).read_text());self.assertEqual(len(handoff['original_inputs']),2)
    def test_l4_and_external_risk_rejected_before_plaintext_storage(self):
        for kwargs in ({'text':'L4: sensitive synthetic'},{'text':'external action','permission':'R2'}):
            with self.assertRaises(ControlError):self.create(**kwargs)
        self.assertEqual(self.count(),0);self.assertFalse((self.r/'state/control').exists())
    def test_managed_task_cannot_bypass_dispatch_with_role_runner(self):
        tid=self.create()['task_id'];packet=Path(self.tmp.name)/'bypass.json'
        packet.write_text(json.dumps({'task_id':tid,'role_id':'cards-master','from_agent_id':'100003','goal':'bypass'}))
        p=subprocess.run([sys.executable,str(self.r/'scripts/task-runner.py'),str(packet)],env=self.env,capture_output=True,text=True)
        self.assertEqual(p.returncode,2,p.stderr);self.assertEqual(self.count(),0)

    def test_lookup_repairs_missing_projection_and_is_owner_scoped(self):
        tid=self.create()['task_id'];(self.r/'state/control'/f'{tid}.json').unlink()
        self.assertEqual(self.svc.lookup_command(self.owner,'create-1')['task_id'],tid)
        stranger=Principal('other','owner',self.owner.role_ids,self.owner.capabilities)
        with self.assertRaises(ControlError):self.svc.lookup_command(stranger,'create-1')
    def test_legacy_cli_stop_preserves_managed_projection(self):
        tid=self.create('SLOW_P1')['task_id'];p=self.launch(tid,False);self.wait_running(tid)
        stopped=subprocess.run([sys.executable,str(self.r/'scripts/task-control.py'),'pause',tid],env=self.env,capture_output=True,text=True)
        self.assertEqual(stopped.returncode,0,stopped.stderr);p.communicate(timeout=15)
        c=load_control(self.r,tid);self.assertEqual(c['schema'],'javis-control-1');self.assertEqual(c['goal_revision'],1)
        rejected=subprocess.run([sys.executable,str(self.r/'scripts/task-cli.py'),'update',tid,'--attempt','99'],env=self.env,capture_output=True,text=True)
        self.assertEqual(rejected.returncode,2);self.assertEqual(self.svc.status(self.owner,tid)['attempt'],1)
    def test_receipt_tampering_detected(self):
        tid=self.create()['task_id'];self.launch(tid);receipt=self.svc.result(self.owner,tid)
        p=Path(receipt['result_ref']);p.write_text(p.read_text()+' ')
        with self.assertRaises(ControlError):self.svc.result(self.owner,tid)
    def test_concurrent_duplicate_launch_only_one_worker(self):
        tid=self.create()['task_id'];a=self.launch(tid,False);b=self.launch(tid,False)
        a.communicate(timeout=20);b.communicate(timeout=20)
        self.assertEqual(self.count(),1);self.assertEqual(self.svc.status(self.owner,tid)['attempt'],1)
    def test_dead_claim_does_not_launch_and_requires_review(self):
        from task_service import save_control
        from task_dispatch import reconcile
        tid=self.create()['task_id'];c=load_control(self.r,tid)
        c['dispatch'].update(status='claimed',dispatcher_pid=99999999,dispatcher_identity='not-live')
        save_control(self.r,c,'synthetic_claim_crash');reconcile(self.r,tid);self.launch(tid)
        self.assertEqual(self.count(),0);self.assertEqual(load_control(self.r,tid)['dispatch']['status'],'needs_review')
        self.assertEqual(self.svc.status(self.owner,tid)['state'],'waiting_user')
        with self.assertRaises(ControlError):self.cmd(tid,'retry','reviewed-retry')
        self.cmd(tid,'retry','reviewed-retry',review_confirmed=True);self.launch(tid)
        self.assertEqual(self.count(),1);self.assertEqual(self.svc.status(self.owner,tid)['attempt'],1)
    def test_cas_parallel_append_only_one_accepted(self):
        import concurrent.futures
        tid=self.create()['task_id']
        def append(cid):
            try:return self.svc.command(self.owner,tid,{'command_id':cid,'action':'append','expected_goal_revision':1,'expected_attempt':0,'original_text':cid})
            except ControlError as exc:return exc.code
        with concurrent.futures.ThreadPoolExecutor() as pool:results=list(pool.map(append,['a1','a2']))
        self.assertEqual(sum(isinstance(v,dict) for v in results),1);self.assertIn('version_conflict',results)
        self.assertEqual(self.svc.status(self.owner,tid)['goal_revision'],2)
    def test_observed_context_budget_starts_new_session_next_attempt(self):
        tid=self.create('USAGE_P1')['task_id'];self.launch(tid);self.cmd(tid,'continue','c1');self.launch(tid)
        receipt=self.svc.result(self.owner,tid)['result'];self.assertEqual(receipt['context']['reason'],'observed_native_usage_budget')
        self.assertNotIn('resume',json.loads(self.calls.read_text().splitlines()[1])['args']);self.assertEqual(receipt['attempt'],2)
    def test_recovery_hold_blocks_mutations_and_direct_dispatch_but_allows_reads(self):
        tid=self.create()['task_id'];hold=self.r/'state/recovery-hold.json';hold.write_text('{"hold":true}')
        with self.assertRaises(ControlError) as caught:self.create()
        self.assertEqual(caught.exception.code,'recovery_hold')
        with self.assertRaises(ControlError):self.cmd(tid,'append','a1',original_text='blocked')
        self.assertEqual(self.svc.status(self.owner,tid)['state'],'queued')
        self.assertEqual(self.launch(tid).returncode,77);self.assertEqual(self.count(),0)
        hold.write_text('invalid-json');self.assertEqual(self.launch(tid).returncode,77);self.assertEqual(self.count(),0)
    def test_memory_failure_cannot_queue_a_model_retry(self):
        tid=self.create()['task_id'];self.launch(tid);path=self.r/'state/tasks'/f'{tid}.json'
        state=json.loads(path.read_text());state['memory_retry_required']=True;path.write_text(json.dumps(state))
        with self.assertRaises(ControlError) as caught:self.cmd(tid,'continue','new-attempt')
        self.assertEqual(caught.exception.code,'memory_repair_required');self.assertEqual(self.count(),1)
        self.assertTrue(self.svc.status(self.owner,tid)['memory_repair_required'])

if __name__=='__main__':unittest.main()
