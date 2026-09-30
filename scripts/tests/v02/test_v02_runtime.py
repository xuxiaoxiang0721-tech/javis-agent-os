"""Synthetic integration tests for the V0.2 runner. No external inference."""
import hashlib, json, os, shutil, subprocess, sys, tempfile, time, unittest
from pathlib import Path
STAGE=Path(__file__).parent
CODE=Path(os.environ.get('JAVIS_TEST_CODE_ROOT',STAGE))
sys.dont_write_bytecode=True
FAKE=r'''#!/usr/bin/env python3
import json,os,sys,time
from pathlib import Path
args=sys.argv[1:]; prompt=sys.stdin.read()
with Path(os.environ['FAKE_CALLS']).open('a') as f: f.write(json.dumps(args)+'\n')
goal=prompt.split('Goal:\n',1)[1].split('\nWhen done',1)[0]
sid=args[args.index('resume')+1] if 'resume' in args else 'synthetic-session-1'
def emit(x): print(json.dumps(x),flush=True)
emit({'type':'thread.started','thread_id':sid})
emit({'type':'item.completed','item':{'id':'tool-1','type':'command_execution','command':'python synthetic.py','aggregated_output':'synthetic ok','exit_code':0}})
if goal=='slow': time.sleep(15)
summary='SUMMARY: '+goal
if goal=='write output':
    out=Path(prompt.split('Write deliverables under: ',1)[1].split('\n',1)[0]);out.mkdir(parents=True,exist_ok=True)
    (out/'交付 文件.json').write_text('{"total_usd":1600}')
if goal=='emit synthetic secrets':
    summary='SUMMARY: password=fake-password-Q7x!'
    sys.stderr.write('-----BEGIN PRIVATE KEY-----\nfake-private-material\n');sys.stderr.flush();time.sleep(.02)
    sys.stderr.write('-----END PRIVATE KEY-----\n');sys.stderr.flush()
    emit({'type':'item.completed','item':{'id':'tool-secret','type':'command_execution','command':'synthetic','aggregated_output':'api_key=sk-test-SecretAlpha1234567890','exit_code':0}})
emit({'type':'item.completed','item':{'id':'reply','type':'agent_message','text':summary}})
emit({'type':'turn.completed','usage':{'input_tokens':10,'output_tokens':10}})
'''

def bind_fake_calls(source, calls):
    first, rest = source.split('\n', 1)
    return first+'\nimport os\nos.environ["FAKE_CALLS"]='+repr(str(calls))+'\n'+rest

class RuntimeV02(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='javis-v02-runtime-'); self.r=Path(self.tmp.name)/'javis'
        shutil.copytree(CODE/'scripts',self.r/'scripts')
        # Source-only fixtures: never copy runtime databases or virtualenvs.
        for name in ['raw-index','memory-adapter']:
            source=CODE/'tools'/name
            if source.exists():
                for p in source.rglob('*.py'):
                    if any(x in {'.venv','venv','__pycache__'} for x in p.relative_to(source).parts): continue
                    target=self.r/'tools'/name/p.relative_to(source)
                    target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target)
        (self.r/'workspace/roles/gpt-star').mkdir(parents=True)
        self.calls=Path(self.tmp.name)/'calls.jsonl'
        self.fake=Path(self.tmp.name)/'fake-codex';self.fake.write_text(bind_fake_calls(FAKE,self.calls));self.fake.chmod(0o755)
        self.env={**os.environ,'JAVIS_ROOT':str(self.r),'JAVIS_CODEX_BIN':str(self.fake),
            'FAKE_CALLS':str(self.calls),'PYTHONDONTWRITEBYTECODE':'1','JAVIS_TASK_TIMEOUT':'30'}
    def tearDown(self): self.tmp.cleanup()
    def packet(self,tid='test',goal='first',**kw):
        p=Path(self.tmp.name)/(tid+'-input.json')
        p.write_text(json.dumps(dict(task_id=tid,role_id='gpt-star',goal=goal,from_agent_id='synthetic',**kw)))
        return p
    def invoke(self,**kw):
        p=self.packet(**kw)
        return subprocess.run(['bash',str(self.r/'scripts/gpt-star-run.sh'),'--packet',str(p)],env=self.env,capture_output=True,text=True,timeout=40)
    def state(self,tid='test'): return json.loads((self.r/'state/tasks'/f'{tid}.json').read_text())
    def control(self,action,tid='test'):
        return subprocess.run([sys.executable,str(self.r/'scripts/task-control.py'),action,tid],env=self.env,capture_output=True,text=True)
    def events(self):
        return [json.loads(l) for p in (self.r/'raw/events').glob('*.jsonl') for l in p.read_text().splitlines() if l.strip()]
    def start_slow(self):
        p=self.packet(goal='slow')
        process=subprocess.Popen(['bash',str(self.r/'scripts/gpt-star-run.sh'),'--packet',str(p)],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        for _ in range(200):
            path=self.r/'state/tasks/test.json'
            if path.exists() and json.loads(path.read_text()).get('session_id'): return process
            time.sleep(.02)
        self.fail('runner did not become ready')
    def test_l4_never_starts_external_worker(self):
        p=self.invoke(goal='private synthetic content',privacy_level='L4')
        self.assertEqual(p.returncode,77,p.stderr);self.assertFalse(self.calls.exists())
        self.assertEqual(self.state()['state'],'waiting_user')
        for f in self.r.rglob('*'):
            if f.is_file() and f.suffix in {'.json','.jsonl'}: self.assertNotIn('private synthetic content',f.read_text())
    def test_nested_l4_metadata_is_blocked(self):
        p=self.invoke(inputs={'data_classification':'L4'})
        self.assertEqual(p.returncode,77);self.assertFalse(self.calls.exists())
    def test_r2_r3_are_not_fake_approvals(self):
        for permission in ['R2','R3']:
            p=self.invoke(tid=permission,permission=permission,approval_refs=['synthetic-approval'])
            self.assertEqual(p.returncode,77,p.stderr)
        self.assertFalse(self.calls.exists())
    def test_completed_retry_is_deduped(self):
        self.assertEqual(self.invoke().returncode,0)
        self.assertEqual(self.invoke().returncode,0)
        self.assertEqual(len(self.calls.read_text().splitlines()),1)
        self.assertEqual(self.state()['attempt'],1)
    def test_changed_completed_task_requires_continue(self):
        self.invoke();p=self.invoke(goal='second')
        self.assertEqual(p.returncode,2,p.stderr);self.assertEqual(len(self.calls.read_text().splitlines()),1)
    def test_native_continue_uses_exact_original_session(self):
        self.invoke();sid=self.state()['session_id'];p=self.invoke(goal='second',mode='continue')
        self.assertEqual(p.returncode,0,p.stderr)
        args=json.loads(self.calls.read_text().splitlines()[-1])
        self.assertEqual(args[args.index('resume')+1],sid)
        self.assertEqual(self.state()['session_id'],sid);self.assertEqual(self.state()['attempt'],2)
        self.assertTrue((self.r/'workspace/tasks/test/attempts/1/result.json').exists())
    def test_pause_then_resume(self):
        process=self.start_slow();sid=self.state()['session_id'];p=self.control('pause')
        self.assertEqual(p.returncode,0,p.stderr);process.communicate(timeout=10)
        self.assertEqual(self.state()['state'],'paused')
        p=self.invoke(goal='continue after pause',mode='resume')
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(self.state()['session_id'],sid)
    def test_cancel_stops_runner(self):
        process=self.start_slow();p=self.control('cancel')
        self.assertEqual(p.returncode,0,p.stderr);process.communicate(timeout=10)
        self.assertEqual(self.state()['state'],'cancelled')
    def test_active_task_cannot_be_changed_by_metadata_cli(self):
        process=self.start_slow()
        p=subprocess.run([sys.executable,str(self.r/'scripts/task-cli.py'),'update','test','--state','failed'],env=self.env,capture_output=True,text=True)
        self.assertEqual(p.returncode,75,p.stderr)
        self.control('cancel');process.communicate(timeout=10)
    def test_crash_recovery_waits_without_replaying(self):
        self.invoke();state=self.state();state.update(state='running',runner_pid=99999999,runner_identity='old-boot')
        (self.r/'state/tasks/test.json').write_text(json.dumps(state))
        p=subprocess.run([sys.executable,str(self.r/'scripts/task-control.py'),'recover'],env=self.env,capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(self.state()['state'],'waiting_user')
        self.assertEqual(len(self.calls.read_text().splitlines()),1)
    def test_explicit_credentials_not_in_generated_records(self):
        p=self.invoke(goal='emit synthetic secrets')
        self.assertEqual(p.returncode,0,p.stderr)
        markers=['fake-password-Q7x!','fake-private-material','sk-test-SecretAlpha1234567890']
        for f in self.r.rglob('*'):
            if f.is_file() and 'scripts' not in f.parts and f.suffix not in {'.sqlite','.lock'}:
                data=f.read_bytes()
                for marker in markers: self.assertNotIn(marker.encode(),data,str(f))
    def test_input_transfer_and_versions_preserve_hash(self):
        source=self.r/'workspace/inbox/ordinary-approved/中文 空格.txt'
        source.parent.mkdir(parents=True);source.write_text('A=100\n',encoding='utf-8')
        p=self.invoke(inputs={'files':[str(source)]});self.assertEqual(p.returncode,0,p.stderr)
        first=self.state()['input_refs'][0]
        self.assertEqual(Path(first['linux_path']).read_bytes(),source.read_bytes())
        self.assertEqual(first['sha256'],hashlib.sha256(source.read_bytes()).hexdigest())
        source.write_text('A=120\n',encoding='utf-8')
        p=self.invoke(goal='second',mode='continue',inputs={'files':[str(source)]});self.assertEqual(p.returncode,0,p.stderr)
        second=self.state()['input_refs'][0]
        self.assertEqual(second['previous_sha256'],first['sha256'])
        self.assertEqual((self.r/'raw/objects'/first['sha256']).read_text(),'A=100\n')
    def test_unknown_model_is_not_invented(self):
        self.invoke();self.assertIsNone(self.state()['model'])
        self.assertTrue(self.state()['model_missing_reason'])
        event=next(e for e in self.events() if e['event_type']=='codex_stream_event')
        self.assertIsNone(event['occurred_at']);self.assertTrue(event['captured_at'])
    def test_original_input_is_separate_from_goal(self):
        p=self.invoke(goal='normalized task',original_user_input='original exact synthetic request')
        self.assertEqual(p.returncode,0,p.stderr)
        rows=[e for e in self.events() if e['event_type']=='user_input' and e['payload'].get('is_original_user_input')]
        self.assertTrue(rows);self.assertEqual(rows[0]['payload']['text'],'original exact synthetic request')
    def test_r0_preserves_read_only_sandbox(self):
        p=self.invoke(permission='R0');self.assertEqual(p.returncode,0,p.stderr)
        args=json.loads(self.calls.read_text().splitlines()[0]);self.assertNotIn('-s',args)
        filesystem=next(value for value in args if value.startswith('permissions.javis_private_worker.filesystem='))
        self.assertIn(json.dumps(str(self.r/'workspace/roles/gpt-star'))+' = "read"',filesystem)
        self.assertIn(json.dumps(str(self.r/'workspace/tasks/test'))+' = "read"',filesystem)
        self.assertNotIn('--dangerously-bypass-approvals-and-sandbox',args)
    def test_output_exchange_has_matching_hash_and_artifact_id(self):
        exchange=Path(self.tmp.name)/'exchange';self.env['JAVIS_EXCHANGE_ROOT']=str(exchange)
        p=self.invoke(goal='write output');self.assertEqual(p.returncode,0,p.stderr)
        artifact=self.state()['artifact_refs'][0]
        self.assertEqual(artifact['delivery_status'],'verified')
        dst=Path(artifact['exchange_path']);self.assertTrue(dst.is_relative_to(exchange))
        self.assertEqual(hashlib.sha256(dst.read_bytes()).hexdigest(),artifact['sha256'])
        delivered=next(e for e in self.events() if e['event_type']=='artifact_delivery')
        self.assertEqual(delivered['payload']['artifact_id'],artifact['artifact_id'])
    def test_completed_attempt_results_remain_bound(self):
        first=self.invoke(goal='first');self.assertEqual(first.returncode,0,first.stderr)
        receipt=json.loads(first.stdout.splitlines()[0]);path=Path(receipt['result'])
        before=path.read_bytes()
        self.assertEqual(self.invoke(goal='second',mode='continue').returncode,0)
        self.assertEqual(path.read_bytes(),before)
        self.assertIn('first',json.loads(path.read_text())['user_reply_zh'])
        self.assertIn('second',json.loads((self.r/'workspace/tasks/test/result.json').read_text())['user_reply_zh'])

if __name__=='__main__': unittest.main(verbosity=2)
