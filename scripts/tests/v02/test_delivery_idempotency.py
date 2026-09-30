"""P0 delivery regressions: synthetic workers only, no external inference."""
import json
import contextlib
import io
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import test_v02_runtime as support

FAKE = r'''#!/usr/bin/env python3
import json,os,sys,time
from pathlib import Path
args=sys.argv[1:]; prompt=sys.stdin.read()
with Path(os.environ['FAKE_CALLS']).open('a') as f: f.write(json.dumps(args)+'\n')
goal=prompt.split('Goal:\n',1)[1].split('\nWhen done',1)[0]
sid=args[args.index('resume')+1] if 'resume' in args else 'synthetic-delivery-session'
def emit(x): print(json.dumps(x),flush=True)
emit({'type':'thread.started','thread_id':sid})
emit({'type':'turn.started'})
if goal=='worker-failed':
    emit({'type':'turn.failed','error':{'message':'synthetic worker execution failure'}})
    sys.exit(9)
if goal=='slow': time.sleep(15)
summary='plain completed reply' if goal=='protocol-missing' else 'SUMMARY: '+goal
emit({'type':'item.completed','item':{'type':'agent_message','text':summary}})
if goal!='no-turn-completion': emit({'type':'turn.completed'})
'''

class DeliveryIdempotency(unittest.TestCase):
    packet=support.RuntimeV02.packet
    invoke=support.RuntimeV02.invoke
    state=support.RuntimeV02.state
    events=support.RuntimeV02.events
    control=support.RuntimeV02.control
    start_slow=support.RuntimeV02.start_slow

    def setUp(self):
        support.RuntimeV02.setUp(self)
        self.fake.write_text(FAKE)
        self.env['JAVIS_MEMORY_GRAPH_DISABLED']='1'

    def tearDown(self): support.RuntimeV02.tearDown(self)

    def calls_count(self):
        return len(self.calls.read_text().splitlines()) if self.calls.exists() else 0

    def test_completed_native_turn_missing_summary_is_protocol_failure_and_cached(self):
        first=self.invoke(goal='protocol-missing',source_event_id='real-platform-id-fixture')
        self.assertEqual(first.returncode,1,first.stderr)
        receipt=json.loads(first.stdout.splitlines()[0]); path=Path(receipt['result'])
        result=json.loads(path.read_text())
        self.assertEqual(result['failure_category'],'completion_protocol_error')
        self.assertTrue(result['native_turn_completed'])
        self.assertEqual(result['worker_exit_code'],0)
        self.assertEqual(self.state()['state'],'failed')
        before=(path.read_bytes(),(self.r/'state/tasks/test.json').read_bytes(),len(self.events()))
        repeat=self.invoke(goal='protocol-missing',source_event_id='real-platform-id-fixture')
        self.assertEqual(repeat.returncode,1,repeat.stderr)
        repeated=json.loads(repeat.stdout.splitlines()[0])
        self.assertTrue(repeated['deduped']); self.assertEqual(repeated['result'],str(path))
        self.assertEqual(self.calls_count(),1)
        self.assertEqual(before,(path.read_bytes(),(self.r/'state/tasks/test.json').read_bytes(),len(self.events())))

    def test_actual_worker_failure_is_cached_and_never_automatically_continued(self):
        first=self.invoke(goal='worker-failed')
        self.assertEqual(first.returncode,9,first.stderr)
        repeat=self.invoke(goal='worker-failed')
        self.assertEqual(repeat.returncode,9,repeat.stderr)
        self.assertTrue(json.loads(repeat.stdout.splitlines()[0])['deduped'])
        self.assertEqual(self.calls_count(),1); self.assertEqual(self.state()['attempt'],1)

    def test_changed_failed_delivery_original_or_source_is_rejected_without_mutation(self):
        request=dict(goal='worker-failed',original_user_input='exact original',source_event_id='source-1')
        self.invoke(**request)
        state_path=self.r/'state/tasks/test.json'; before=state_path.read_bytes()
        for field,value in [('original_user_input','changed original'),('source_event_id','source-2')]:
            changed={**request,field:value}
            response=self.invoke(**changed)
            self.assertEqual(response.returncode,2,response.stderr)
            self.assertIn('identity changed',response.stderr)
            self.assertEqual(state_path.read_bytes(),before)
        self.assertEqual(self.calls_count(),1)

    def test_live_worker_duplicate_returns_busy_and_never_starts_second_worker(self):
        process=self.start_slow()
        repeat=self.invoke(goal='slow')
        self.assertEqual(repeat.returncode,75,repeat.stderr)
        self.assertEqual(self.calls_count(),1)
        self.control('cancel'); process.communicate(timeout=10)

    def test_stale_running_state_never_restarts_and_conflict_preserves_state(self):
        self.invoke()
        path=self.r/'state/tasks/test.json'; state=self.state(); state['state']='running'
        path.write_text(json.dumps(state)); before=path.read_bytes()
        repeat=self.invoke()
        self.assertEqual(repeat.returncode,75,repeat.stderr)
        self.assertEqual(json.loads(repeat.stdout.splitlines()[0])['status'],'busy')
        changed=self.invoke(goal='different')
        self.assertEqual(changed.returncode,2,changed.stderr)
        self.assertEqual(path.read_bytes(),before); self.assertEqual(self.calls_count(),1)

    def test_missing_result_after_failed_execution_requires_review_without_replay(self):
        self.invoke(goal='worker-failed')
        task=self.r/'workspace/tasks/test'
        (task/'attempts/1/result.json').unlink(); (task/'result.json').unlink()
        repeat=self.invoke(goal='worker-failed')
        self.assertEqual(repeat.returncode,75,repeat.stderr)
        self.assertEqual(json.loads(repeat.stdout.splitlines()[0])['status'],'needs_review')
        self.assertEqual(self.calls_count(),1)

    def test_corrupt_result_is_not_rewritten_or_reexecuted(self):
        self.invoke(goal='worker-failed')
        result=self.r/'workspace/tasks/test/attempts/1/result.json'
        result.write_text('{broken')
        before=(self.r/'state/tasks/test.json').read_bytes()
        repeat=self.invoke(goal='worker-failed')
        self.assertEqual(repeat.returncode,2,repeat.stderr)
        self.assertEqual(result.read_text(),'{broken')
        self.assertEqual((self.r/'state/tasks/test.json').read_bytes(),before)
        self.assertEqual(self.calls_count(),1)

    def test_input_exists_without_state_requires_review_without_replay(self):
        self.invoke()
        state=self.r/'state/tasks/test.json'; state.unlink()
        repeat=self.invoke()
        self.assertEqual(repeat.returncode,75,repeat.stderr)
        self.assertFalse(state.exists()); self.assertEqual(self.calls_count(),1)

    def test_failed_task_can_only_resume_by_explicit_continue(self):
        first=self.invoke(goal='worker-failed'); self.assertEqual(first.returncode,9)
        task=self.r/'workspace/tasks/test'; receipt=task/'attempts/1/result.json'
        prior=receipt.read_bytes(); sid=self.state()['session_id']
        next_turn=self.invoke(goal='reviewed continuation',mode='continue')
        self.assertEqual(next_turn.returncode,0,next_turn.stderr)
        args=json.loads(self.calls.read_text().splitlines()[-1])
        self.assertEqual(args[args.index('resume')+1],sid)
        self.assertEqual(self.state()['attempt'],2); self.assertEqual(self.calls_count(),2)
        self.assertEqual(receipt.read_bytes(),prior)

    def test_missing_native_completion_remains_failure(self):
        response=self.invoke(goal='no-turn-completion')
        self.assertEqual(response.returncode,1,response.stderr)
        result=json.loads((self.r/'workspace/tasks/test/result.json').read_text())
        self.assertEqual(result['failure_category'],'incomplete_response')
        self.assertFalse(result['native_turn_completed'])
        self.assertEqual(self.invoke(goal='no-turn-completion').returncode,1)
        self.assertEqual(self.calls_count(),1)

    def test_preworker_policy_failure_is_not_implicitly_retried(self):
        first=self.invoke(permission='R3')
        repeat=self.invoke(permission='R3')
        self.assertEqual(first.returncode,77); self.assertEqual(repeat.returncode,77)
        self.assertTrue(json.loads(repeat.stdout.splitlines()[0])['deduped'])
        self.assertEqual(self.calls_count(),0); self.assertEqual(self.state()['attempt'],1)

    def test_explicit_memory_only_repair_remains_compatible_without_worker_replay(self):
        import sys
        sys.path.insert(0,str(support.CODE/'scripts'))
        import task_runtime
        self.invoke()
        task=self.r/'workspace/tasks/test'; path=self.r/'state/tasks/test.json'
        state=self.state(); state.update(worker_execution_completed=True,memory_retry_required=True,memory_status='error')
        path.write_text(json.dumps(state))
        immutable=task/'attempts/1/result.json'; old_receipt=immutable.read_bytes()
        with patch.dict(os.environ,self.env), patch('task_memory.finalize',return_value={
                'status':'ok','write_refs':[],'candidate_refs':[],'read_refs':[],
                'graph_status':'disabled','issues':[]}), contextlib.redirect_stdout(io.StringIO()) as out:
            code=task_runtime.run([str(self.packet())])
        self.assertEqual(code,0)
        self.assertTrue(json.loads(out.getvalue().splitlines()[-1])['memory_only_retry'])
        self.assertEqual(self.calls_count(),1); self.assertEqual(self.state()['attempt'],1)
        self.assertFalse(self.state()['memory_retry_required'])
        self.assertEqual(immutable.read_bytes(),old_receipt)
        repeat=self.invoke(); self.assertEqual(repeat.returncode,0,repeat.stderr)
        self.assertEqual(self.calls_count(),1)

if __name__=='__main__': unittest.main(verbosity=2)
