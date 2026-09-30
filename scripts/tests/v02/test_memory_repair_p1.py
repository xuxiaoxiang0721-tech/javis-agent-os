"""Explicit common memory reconciliation never launches a second native worker."""
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import test_control_p1 as support
from task_control import Principal, ControlError, process_identity
from task_service import load_control, save_control

MEMORY='''from pathlib import Path
def prepare(root,task,packet,attempt,input_event_id):
    return {'status':'ok','prompt':'Synthetic memory fixture only','read_refs':[],'graph_status':'disabled'}
def finalize(root,task,packet,attempt,input_event_id):
    count=Path(task)/'memory-call-count.txt'
    count.write_text(str(int(count.read_text())+1 if count.exists() else 1))
    if not (Path(task)/'allow-memory-repair').exists():raise RuntimeError('synthetic local memory outage')
    return {'status':'ok','memory_status':'pending_review','write_refs':[],'candidate_refs':['synthetic-candidate'],
        'read_refs':[],'graph_status':'disabled','issues':[]}
'''

class MemoryRepair(unittest.TestCase):
    def setUp(self):
        support.ControlP1.setUp(self);(self.r/'scripts/task_memory.py').write_text(MEMORY)
    tearDown=support.ControlP1.tearDown
    create=support.ControlP1.create
    cmd=support.ControlP1.cmd
    launch=support.ControlP1.launch
    count=support.ControlP1.count
    def failure(self):
        tid=self.create()['task_id'];self.launch(tid)
        status=self.svc.status(self.owner,tid);self.assertTrue(status['memory_repair_required']);self.assertEqual(self.count(),1)
        return tid,self.r/'workspace/tasks'/tid
    def test_explicit_repair_keeps_attempt_and_old_receipt_and_caches_command(self):
        tid,task=self.failure();old=(task/'attempts/1/result.json').read_bytes();packet=(task/'packet.json').read_bytes()
        (task/'allow-memory-repair').touch();req=self.cmd(tid,'reconcile_memory','repair-1');self.assertEqual(req['status'],'received')
        self.launch(tid);status=self.svc.status(self.owner,tid)
        self.assertFalse(status['memory_repair_required']);self.assertEqual(status['attempt'],1);self.assertEqual(status['memory_status'],'pending_review')
        current=self.svc.result(self.owner,tid);original=self.svc.result(self.owner,tid,1)
        self.assertEqual(current['result']['exit_code'],0);self.assertIn('/memory-retries/',current['result_ref']);self.assertEqual(original['result']['exit_code'],78)
        self.assertEqual((task/'attempts/1/result.json').read_bytes(),old);self.assertEqual((task/'packet.json').read_bytes(),packet)
        self.assertFalse((task/'attempts/2').exists());self.assertEqual(self.count(),1)
        repeat=self.cmd(tid,'reconcile_memory','repair-1');self.assertTrue(repeat['replayed']);self.assertEqual(repeat['status'],'applied')
        self.launch(tid);self.assertEqual((task/'memory-call-count.txt').read_text(),'2');self.assertEqual(self.count(),1)
    def test_memory_failure_can_be_explicitly_repaired_again_without_model(self):
        tid,task=self.failure();self.cmd(tid,'reconcile_memory','repair-failed');self.launch(tid)
        failed=self.svc.result(self.owner,tid);self.assertEqual(failed['result']['exit_code'],78)
        (task/'allow-memory-repair').touch();self.cmd(tid,'reconcile_memory','repair-after-fix');self.launch(tid)
        self.assertEqual(self.svc.result(self.owner,tid)['result']['exit_code'],0);self.assertEqual(self.count(),1)
        self.assertEqual(len(self.svc.status(self.owner,tid)['memory_repairs']),2)
        self.assertTrue(Path(failed['result_ref']).exists())
    def test_service_cannot_reconcile_even_with_spoofed_owner_name(self):
        tid,task=self.failure();service=Principal(self.owner.actor_id,'service',self.owner.role_ids,self.owner.capabilities)
        req={'command_id':'service-repair','action':'reconcile_memory','expected_goal_revision':1,'expected_attempt':1}
        with self.assertRaises(ControlError) as caught:self.svc.command(service,tid,req)
        self.assertEqual(caught.exception.code,'human_review_required');self.assertEqual(self.count(),1)
    def test_running_old_process_blocks_repair(self):
        tid,task=self.failure();path=self.r/'state/tasks'/f'{tid}.json';state=json.loads(path.read_text())
        state.update(runner_pid=os.getpid(),runner_identity=process_identity(os.getpid()));path.write_text(json.dumps(state))
        with self.assertRaises(ControlError) as caught:self.cmd(tid,'reconcile_memory','busy-repair')
        self.assertEqual(caught.exception.code,'busy');self.assertEqual(self.count(),1)
    def test_tampered_base_receipt_blocks_repair(self):
        tid,task=self.failure();p=task/'attempts/1/result.json';p.write_text(p.read_text()+' ')
        with self.assertRaises(ControlError) as caught:self.cmd(tid,'reconcile_memory','tampered-repair')
        self.assertEqual(caught.exception.code,'receipt_invalid');self.assertEqual(self.count(),1)
    def test_crash_after_repair_receipt_is_reconciled_without_executing_again(self):
        from task_dispatch import reconcile
        tid,task=self.failure();(task/'allow-memory-repair').touch();self.cmd(tid,'reconcile_memory','repair-crash');self.launch(tid)
        control=load_control(self.r,tid);control['dispatch'].update(status='started',dispatcher_pid=99999999,dispatcher_identity='synthetic-dead')
        control['commands']['repair-crash']['status']='received';control.pop('latest_memory_receipt');control['memory_repairs']={}
        save_control(self.r,control,'synthetic_post_repair_crash');reconcile(self.r,tid)
        self.assertEqual(self.svc.result(self.owner,tid)['result']['exit_code'],0);self.assertEqual((task/'memory-call-count.txt').read_text(),'2')
        self.assertEqual(self.count(),1);self.assertEqual(load_control(self.r,tid)['commands']['repair-crash']['status'],'applied')
    def test_repair_rejects_stale_cas_and_requires_actual_memory_failure(self):
        tid,task=self.failure()
        with self.assertRaises(ControlError) as caught:self.svc.command(self.owner,tid,{'command_id':'stale','action':'reconcile_memory','expected_goal_revision':1,'expected_attempt':0})
        self.assertEqual(caught.exception.code,'version_conflict')
        (task/'allow-memory-repair').touch();self.cmd(tid,'reconcile_memory','good');self.launch(tid)
        with self.assertRaises(ControlError) as caught:self.cmd(tid,'reconcile_memory','unneeded')
        self.assertEqual(caught.exception.code,'memory_repair_not_required');self.assertEqual(self.count(),1)
    def test_packet_changed_after_queued_repair_stops_before_memory_write(self):
        tid,task=self.failure();self.cmd(tid,'reconcile_memory','packet-repair')
        p=task/'packet.json';packet=json.loads(p.read_text());packet['original_user_input']='tampered';p.write_text(json.dumps(packet))
        self.launch(tid);self.assertEqual((task/'memory-call-count.txt').read_text(),'1');self.assertEqual(self.count(),1)
        self.assertEqual(load_control(self.r,tid)['dispatch']['status'],'needs_review')
    def test_repaired_receipt_tampering_is_not_trusted(self):
        tid,task=self.failure();(task/'allow-memory-repair').touch();self.cmd(tid,'reconcile_memory','repair');self.launch(tid)
        result=self.svc.result(self.owner,tid);p=Path(result['result_ref']);p.write_text(p.read_text()+' ')
        with self.assertRaises(ControlError) as caught:self.svc.result(self.owner,tid)
        self.assertEqual(caught.exception.code,'receipt_invalid');self.assertEqual(self.count(),1)
    def test_line_one_is_archive_only_default_codex_line_is_two(self):
        with self.assertRaises(ControlError) as caught:self.create(source_line=1)
        self.assertEqual(caught.exception.code,'invalid_source_line');self.assertEqual(caught.exception.status_code,400)
        self.assertEqual(self.count(),0);self.assertFalse((self.r/'state/tasks').exists())
        tid=self.create()['task_id'];self.assertEqual(self.svc.status(self.owner,tid)['source_line'],2)
    def test_original_filtering_is_explicit_without_persisting_fixture_credential(self):
        marker='sk-test-RepairFixtureSecret1234567890'
        tid=self.create('Remember only this synthetic note\r\napi_key='+marker)['task_id'];self.launch(tid)
        c=load_control(self.r,tid)
        rows=[json.loads(line) for p in (self.r/'raw/events').glob('*.jsonl') for line in p.read_text().splitlines()]
        original=next(row for row in rows if row['event_id']==c['goals'][0]['event_id'])
        self.assertTrue(original['payload']['original_was_filtered'])
        self.assertEqual(original['payload']['redaction_boundary'],'explicit_credentials_removed_before_control_storage')
        self.assertIn('original_text_filtered_before_control_storage',original['missing_reason'])
        self.assertNotIn(marker,self.calls.read_text())
        for folder in ('raw','state','workspace'):
            for path in (self.r/folder).rglob('*'):
                if path.is_file() and path.suffix not in {'.sqlite','.lock'}:self.assertNotIn(marker.encode(),path.read_bytes(),str(path))

if __name__=='__main__':unittest.main()
