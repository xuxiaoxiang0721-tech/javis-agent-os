import importlib.util
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

STAGE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(STAGE/'scripts'))
from task_service import ControlService,Principal,ControlError
import task_runtime
from raw_storage import read_preserved_original,_read_rows
spec=importlib.util.spec_from_file_location('grok_original_v3',STAGE/'scripts/grok-sync.py');grok=importlib.util.module_from_spec(spec);spec.loader.exec_module(grok)


class RawIntakeOriginalV3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        p=self.root/'config/memory-pipeline.json';p.parent.mkdir();p.write_text('{"enabled":false}')
    def tearDown(self):self.tmp.cleanup()
    def rows(self):return list(_read_rows(sorted((self.root/'raw/events').rglob('*.jsonl'))))
    def original(self,event):return json.loads(read_preserved_original(self.root,event['raw_preservation']['original'],allow_sensitive=True))
    def test_task_service_submission_and_append_roundtrip_before_redaction(self):
        principal=Principal('synthetic-owner','owner',frozenset({'invest'}),frozenset({'task:create','task:control','task:read'}),'synthetic-proof')
        service=ControlService(self.root);text='完整\r\npassword=synthetic-first-value\n尾'
        result=service.submit(principal,{'command_id':'create1','role_id':'invest','original_text':text})
        service.command(principal,result['task_id'],{'command_id':'append1','action':'append','expected_goal_revision':1,'expected_attempt':0,'original_text':'password=synthetic-next-value'})
        rows=[x for x in self.rows() if x['event_type']=='user_input']
        self.assertEqual(len(rows),2);self.assertEqual(self.original(rows[0])['payload']['text'],text)
        self.assertEqual(self.original(rows[1])['payload']['text'],'password=synthetic-next-value')
        self.assertNotIn('synthetic-first-value',json.dumps(self.rows()));self.assertNotIn('synthetic-next-value',json.dumps(self.rows()))
        for p in (self.root/'state/control').rglob('*.json'):
            self.assertNotIn('synthetic-first-value',p.read_text())
    def test_grok_exact_unfiltered_envelope_and_secret_change_id_conflict(self):
        request={'capture_id':'capture1','role_id':'invest','messages':[{'speaker':'user','fidelity':'forwarded_original_unverified','text':'password=synthetic-first-value\n中文'}]}
        first=grok.ingest(self.root,request);again=grok.ingest(self.root,request)
        row=next(x for x in self.rows() if x['event_id']==first['event_id'])
        self.assertEqual(self.original(row),request);self.assertTrue(again['replayed']);self.assertNotIn('synthetic-first-value',json.dumps(row))
        changed=json.loads(json.dumps(request));changed['messages'][0]['text']='password=synthetic-second-value\n中文'
        with self.assertRaisesRegex(ValueError,'changed original'):grok.ingest(self.root,changed)
    def test_grok_sensitive_binary_original_and_binding(self):
        p=self.root/'workspace/inbox/grok-sync/attachments/test.bin';p.parent.mkdir(parents=True);data=b'\x00\xffpassword=synthetic-binary-value\n';p.write_bytes(data)
        request={'capture_id':'capture1','role_id':'invest','messages':[{'speaker':'user','fidelity':'forwarded_original_unverified','text':'See attachment'}],'attachments':[{'path':'test.bin'}]}
        result=grok.ingest(self.root,request)
        from memory_sources import source_context,resolve_original
        view=source_context(self.root,result['event_id'],'invest');self.assertEqual(len(view['attachments']),1)
        sid=view['attachments'][0]['snapshot_id']
        with self.assertRaises(ValueError):resolve_original(self.root,result['event_id'],'invest',sid)
        self.assertEqual(resolve_original(self.root,result['event_id'],'invest',sid,allow_sensitive=True)['bytes'],data)
    def test_runtime_native_json_capture_roundtrip_and_safe_execution_copy(self):
        original={'type':'item.completed','item':{'type':'agent_message','id':'reply1','text':'完整\r\napi_key=sk-synthetic-native-123456789\n尾'}}
        safe,changes,allowed=task_runtime.native_capture_record(original)
        self.assertTrue(changes);self.assertNotIn('sk-synthetic-native',json.dumps(safe))
        event={'event_id':'native1','event_type':'codex_stream_event','agent':'cards-master','payload':{'record_source':'codex_json_stream','event':safe,'redactions':changes}}
        task_runtime.append_native_capture(self.root,event,allowed);row=self.rows()[0]
        self.assertEqual(self.original(row)['payload']['event'],original);self.assertNotIn('sk-synthetic-native',json.dumps(row))
    def test_reasoning_capture_preserves_only_existing_visible_summary_policy(self):
        native={'type':'item.completed','item':{'type':'reasoning','id':'r1','text':'visible password=synthetic-summary','hidden_chain':'unallowed-hidden-data'}}
        safe,changes,allowed=task_runtime.native_capture_record(native)
        self.assertNotIn('hidden_chain',allowed['item'])
        event={'event_id':'native1','event_type':'codex_stream_event','agent':'invest','payload':{'record_source':'codex_json_stream','event':safe}}
        task_runtime.append_native_capture(self.root,event,allowed)
        self.assertNotIn('unallowed-hidden-data',json.dumps(self.original(self.rows()[0])))
    def test_paused_structured_pipeline_does_not_block_three_intakes(self):
        principal=Principal('synthetic-owner','owner',frozenset({'cards-master'}),frozenset({'task:create'}),'proof')
        ControlService(self.root).submit(principal,{'command_id':'create1','role_id':'cards-master','original_text':'Routine source'})
        grok.ingest(self.root,{'capture_id':'capture1','role_id':'idea-lab','messages':[{'speaker':'user','fidelity':'forwarded_original_unverified','text':'Routine source'}]})
        safe,changes,original=task_runtime.native_capture_record({'type':'item.completed','item':{'type':'agent_message','text':'Routine reply'}})
        task_runtime.append_native_capture(self.root,{'event_id':'native1','event_type':'codex_stream_event','agent':'invest','payload':{'record_source':'codex_json_stream','event':safe}},original)
        self.assertTrue({'cards-master','idea-lab','invest'}<={r.get('agent') for r in self.rows()})
        self.assertFalse((self.root/'memory/screen/runs.jsonl').exists())
        self.assertEqual(len(list((self.root/'state/memory-pipeline/queue').glob('*.json'))),1)
    def test_existing_L4_and_task_permission_gates_unchanged(self):
        principal=Principal('synthetic-owner','owner',frozenset({'invest'}),frozenset({'task:create'}),'proof')
        with self.assertRaises(ControlError):ControlService(self.root).submit(principal,{'command_id':'c','role_id':'invest','original_text':'L4: do not externally process'})
        self.assertIn('L4',task_runtime.policy_block({'goal':'L4: local only','permission':'R1'}))
        self.assertIn('R2_R3',task_runtime.policy_block({'goal':'synthetic','permission':'R2'}))
    def test_direct_runtime_packet_filtered_before_execution_is_preserved_locally(self):
        original={'task_id':'task1','role_id':'invest','goal':'password=synthetic-packet-secret','permission':'R1'}
        safe=task_runtime.checked_packet(original)
        task_runtime.preserve_packet_intake(self.root,safe,original)
        row=self.rows()[0];self.assertEqual(self.original(row),original);self.assertNotIn('synthetic-packet-secret',json.dumps(row))
        self.assertFalse((self.root/'state/tasks').exists())
    def test_direct_runtime_L4_remains_blocked_with_local_encrypted_receipt(self):
        original={'task_id':'task1','role_id':'invest','goal':'L4: synthetic private material','permission':'R1'}
        safe=task_runtime.checked_packet(original);self.assertTrue(task_runtime.policy_block(safe))
        task_runtime.preserve_packet_intake(self.root,safe,original)
        self.assertEqual(self.original(self.rows()[0]),original)
        self.assertNotIn('synthetic private material',json.dumps(self.rows()))
    def test_grok_L4_raw_only_encrypted_replay_and_no_enqueue_even_when_enabled(self):
        (self.root/'config/memory-pipeline.json').write_text('{"enabled":true,"provider":"typesafe","model":"jev-1.13.0"}')
        request={'capture_id':'local1','role_id':'invest','messages':[{'speaker':'user','fidelity':'forwarded_original_unverified','text':'L4: synthetic confidential original'}]}
        with patch.object(grok,'_screen_captured',side_effect=AssertionError('must not enqueue local-only source')):
            first=grok.ingest(self.root,request);replay=grok.ingest(self.root,request)
        row=next(r for r in self.rows() if r['event_id']==first['event_id'])
        self.assertEqual(self.original(row),request);self.assertEqual(first['screening']['status'],'local_only');self.assertTrue(replay['replayed'])
        self.assertFalse(row['cloud_eligible']);self.assertNotIn('confidential original',json.dumps(row))
        self.assertFalse((self.root/'state/memory-pipeline/queue').exists())


if __name__=='__main__':unittest.main()
