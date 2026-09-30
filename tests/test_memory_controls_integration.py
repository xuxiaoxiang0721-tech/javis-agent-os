"""Offline pause/resume, transport budget and independent feedback boundaries."""
import asyncio
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE/'scripts'), str(CODE/'tests'), str(CODE/'tools/memory-adapter')]
import memory_controls as controls
import memory_pipeline as pipeline
import memory_screen as screen
from raw_storage import append_event
from javis_memory_adapter.review_policy import digest, read_rows


class PipelineControlTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'config').mkdir()
        (self.root/'config/memory-pipeline.json').write_text(json.dumps({'enabled':True,'model':'jev-1.13.0'}))
        self.text = 'Alice prefers short weekly reports for Project Cedar.'
        for role in ('invest', 'cards-master'):
            append_event(self.root, {'event_id':'source-'+role,'event_type':'model_output','agent':role,
                'payload':{'text':self.text,'speaker':'assistant'}})

    def queue(self, role='invest'):
        return pipeline.enqueue(self.root,event_id='source-'+role,scope=role)

    def read_queue(self, qid):
        return json.loads((self.root/'state/memory-pipeline/queue'/f'{qid}.json').read_text())

    async def test_global_pause_durably_queues_and_resume_preserves_identity(self):
        first = self.queue()
        self.assertEqual(first['status'],'queued')
        calls=[]
        async def fake(*a,**kw): calls.append(kw);return {'status':'completed'}
        result=await pipeline.process_once(self.root,screen_fn=fake)
        self.assertEqual(result['status'],'held')
        self.assertEqual(self.read_queue(first['queue_id'])['attempts'],0)
        self.assertEqual(calls,[])
        self.assertEqual(pipeline.status(self.root)['held_queue_count'],1)
        controls.update(self.root,0,global_enabled=True)
        self.assertEqual(self.queue()['queue_id'],first['queue_id'])
        self.assertEqual((await pipeline.process_once(self.root,screen_fn=fake))['processed'],1)
        self.assertEqual(len(calls),1)

    async def test_one_role_pause_never_stops_or_leaks_to_another_role(self):
        controls.update(self.root,0,global_enabled=True,roles={'invest':False})
        invest=self.queue();self.queue('cards-master');calls=[]
        async def fake(*a,**kw):calls.append(kw['scope']);return {'status':'completed'}
        await pipeline.process_once(self.root,limit=10,screen_fn=fake)
        self.assertEqual(calls,['cards-master'])
        self.assertEqual(self.read_queue(invest['queue_id'])['attempts'],0)
        controls.update(self.root,1,roles={'invest':True})
        await pipeline.process_once(self.root,screen_fn=fake)
        self.assertEqual(calls,['cards-master','invest'])

    async def test_legacy_disabled_pipeline_still_accepts_raw_queue(self):
        (self.root/'config/memory-pipeline.json').write_text('{"enabled":false}')
        self.assertEqual(self.queue()['status'],'queued')
        self.assertEqual((await pipeline.process_once(self.root))['processed'],0)

    async def test_paid_terminal_candidates_resume_locally_at_zero_budget(self):
        from test_jev_policy import FakeClient
        from test_memory_screen_autoreview import Graph
        from memory_autoreview import MemoryAutoreview
        controls.update(self.root,0,global_enabled=True)
        q=self.queue();client=FakeClient();graph=Graph()
        evaluate=client.evaluate
        async def pause_after_paid(*a,**kw):
            result=await evaluate(*a,**kw)
            if kw['stage']=='verification':controls.update(self.root,1,global_enabled=False)
            return result
        async def call(root,**kw):
            return await screen.screen(root,**kw,model_client=client,graph_client=graph,env_path=self.root/'no-env')
        with patch.object(client,'evaluate',side_effect=pause_after_paid):
            result=await pipeline.process_once(self.root,screen_fn=call)
        self.assertEqual(result['items'][0]['status'],'held')
        first=self.read_queue(q['queue_id'])
        self.assertEqual(len(client.calls),2)
        self.assertEqual(len(graph.calls),1)
        # Older workers persisted a terminal queue row without autoreview details.
        path=self.root/'state/memory-pipeline/queue'/f"{q['queue_id']}.json"
        first['status']='completed';first['result'].pop('autoreview',None)
        path.write_text(json.dumps(first))
        controls.update(self.root,2,global_enabled=True,daily_call_limit=0)
        result=await pipeline.process_once(self.root,screen_fn=call)
        self.assertEqual(result['processed'],1)
        self.assertEqual(len(client.calls),2)
        self.assertEqual(len(graph.calls),1)
        self.assertEqual(MemoryAutoreview(self.root).status()['counts']['accepted'],1)
        self.assertEqual(controls.status(self.root)['budget']['reserved_calls'],0)

    async def test_missing_extractor_configuration_does_not_spend_screening(self):
        from test_jev_policy import FakeClient
        controls.update(self.root,0,global_enabled=True)
        client=FakeClient();raw=screen.load_source(self.root,'source-invest')
        with patch('memory_model_config.status',return_value={'status':'waiting_for_configuration'}):
            result=await screen.screen(self.root,event_id='source-invest',scope='invest',text=self.text,
                source_digest=digest(raw),model_client=client,env_path=self.root/'no-env')
        self.assertEqual(result['status'],'waiting_for_configuration')
        self.assertEqual(client.calls,[])
        self.assertFalse((self.root/'memory/usage/requests.jsonl').exists())

    async def test_missing_dependencies_leave_queue_and_raw_unchanged(self):
        controls.update(self.root,0,global_enabled=True)
        self.queue()
        def snapshot():
            return {str(p.relative_to(self.root)):p.read_bytes()
                    for base in ('raw','state/memory-pipeline/queue')
                    for p in (self.root/base).rglob('*') if p.is_file()}
        before=snapshot()
        for key, config, expected in ((False,'ready','waiting_for_key'),
                                      (True,'waiting_for_configuration','waiting_for_configuration')):
            with patch('jev_client.credentials_status',return_value={'configured':key}), \
                 patch('memory_model_config.status',return_value={'status':config}):
                for _ in range(3):
                    result=await pipeline.process_once(self.root)
                    self.assertEqual(result['status'],expected)
                    self.assertEqual(result['processed'],0)
                self.assertEqual(pipeline.status(self.root)['execution_state'],expected)
            self.assertEqual(snapshot(),before)

    async def test_partial_paid_run_does_not_repeat_after_extraction_config_changes(self):
        from test_jev_policy import FakeClient
        controls.update(self.root,0,global_enabled=True)
        client=FakeClient();raw=screen.load_source(self.root,'source-invest')
        class FailingGraph:
            async def extract(self, **kw):raise OSError('synthetic graph failure')
        args=dict(event_id='source-invest',scope='invest',text=self.text,
                  source_digest=digest(raw),model_client=client,env_path=self.root/'no-env')
        first=await screen.screen(self.root,**args,graph_client=FailingGraph())
        self.assertEqual(first['status'],'retry')
        self.assertEqual(len(client.calls),1)
        before=(self.root/'memory/screen/runs.jsonl').read_bytes()
        with patch('memory_model_config.status',return_value={'status':'waiting_for_configuration'}):
            waiting=await screen.screen(self.root,**args,resume_run_id=first['run_id'])
        self.assertEqual(waiting['run_id'],first['run_id'])
        config={'status':'ready','provider':'openai','model':'synthetic-new-extractor',
                'embedding_model':'synthetic-embedding','revision':2}
        with patch('memory_model_config.status',return_value=config):
            result=await screen.screen(self.root,**args,resume_run_id=first['run_id'])
        self.assertEqual(result['status'],'blocked')
        self.assertEqual(result['outcome'],'screen_resume_configuration_changed')
        self.assertEqual(len(client.calls),1)
        self.assertEqual((self.root/'memory/screen/runs.jsonl').read_bytes(),before)

    async def test_retry_only_restores_retry_checkpoint_and_terminal_needs_new_evidence(self):
        import hashlib
        from memory_triage import record_pending
        from jev_policy import POLICY_DIGEST, POLICY_VERSION
        controls.update(self.root,0,global_enabled=True)
        queued=self.queue();raw=screen.load_source(self.root,'source-invest')
        content=hashlib.sha256(self.text.encode()).hexdigest()
        run_id='screen_synthetic_retry'
        triage=record_pending(self.root,event_id='source-invest',scope='invest',source_digest=digest(raw),
            run_id=run_id,policy_version=POLICY_VERSION,policy_digest=POLICY_DIGEST,
            stage='graphiti',reason_code='graph_no_facts',content_digest=content)
        item=json.loads((self.root/'memory/triage/items'/f"{triage['triage_id']}.json").read_text())
        state={'run_id':run_id,'event_id':'source-invest','scope':'invest','source_digest':digest(raw),
            'content_digest':content,'policy_digest':POLICY_DIGEST,'status':'retry',
            'screening':{'decision':'keep'},'paid_checkpoint':'synthetic-preserve'}
        screen._append(self.root,state)
        path=self.root/'state/memory-pipeline/queue'/f"{queued['queue_id']}.json"
        row=json.loads(path.read_text());row.update(status='needs_review',attempts=5,provider_attempts=5,
            result={'run_id':run_id,'review_refs':[triage['triage_id']]})
        path.write_text(json.dumps(row))
        before=(self.root/'memory/screen/runs.jsonl').read_bytes()
        result=pipeline.retry_pending(self.root,triage['triage_id'],item['record_digest'],'retry-one')
        self.assertEqual(result['status'],'queued')
        updated=json.loads(path.read_text())
        self.assertEqual(updated['attempts'],5)
        self.assertEqual(updated['provider_attempts'],0)
        self.assertEqual((self.root/'memory/screen/runs.jsonl').read_bytes(),before)
        self.assertEqual(pipeline.retry_pending(self.root,triage['triage_id'],item['record_digest'],'retry-one'),result)
        state['status']='needs_review';screen._append(self.root,state)
        result=pipeline.retry_pending(self.root,triage['triage_id'],item['record_digest'],'retry-two')
        self.assertEqual(result['status'],'not_retryable')
        self.assertTrue(result['can_supplement'])


class TransportControlTests(unittest.TestCase):
    def test_real_jev_transport_guard_prevents_second_request_and_usage_record(self):
        from jev_client import JevClient
        from test_jev_client import FakeResponse, RESULT, KEY, MODEL, QUESTIONS
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);controls.update(root,0,global_enabled=True,daily_call_limit=1)
            opener=Mock();opener.open.side_effect=lambda *a,**k:FakeResponse(RESULT)
            client=JevClient(root,scope='invest')
            with patch.dict(os.environ,{'TYPESAFE_API_KEY':KEY}),patch('jev_client.build_opener',return_value=opener):
                asyncio.run(client.evaluate({},QUESTIONS,model=MODEL,stage='screening'))
                with self.assertRaisesRegex(controls.MemoryProcessingHeld,'daily_budget_exhausted'):
                    asyncio.run(client.evaluate({},QUESTIONS,model=MODEL,stage='screening'))
            self.assertEqual(opener.open.call_count,1)
            self.assertEqual(len(read_rows(root,root/'memory/usage/requests.jsonl')),2)


class FeedbackMergeTests(unittest.TestCase):
    def test_owner_local_conflicting_labels_are_excluded_and_same_label_is_one_group(self):
        from memory_learning import MemoryLearning
        from test_memory_learning import row
        from memory_feedback import MemoryFeedback, LocalMemoryFeedback
        owner=row(1);local=copy.deepcopy(owner);local['feedback_id']='feedback_local'
        local['label']='archive';local['group_keys'].append('task:extra')
        with tempfile.TemporaryDirectory() as temp:
            service=MemoryLearning(temp)
            with patch.object(MemoryFeedback,'training_rows',return_value=[owner]),patch.object(LocalMemoryFeedback,'training_rows',return_value=[local]):
                self.assertEqual(service._rows(),[])
                self.assertEqual(service.feedback_conflict_rows,2)
            local['label']='keep'
            with patch.object(MemoryFeedback,'training_rows',return_value=[owner]),patch.object(LocalMemoryFeedback,'training_rows',return_value=[local]):
                rows=service._rows()
            self.assertEqual(len(rows),1)
            self.assertIn('task:extra',rows[0]['group_keys'])
            self.assertFalse(rows[0]['source_context']['authorship_verified'])


if __name__=='__main__':unittest.main()
