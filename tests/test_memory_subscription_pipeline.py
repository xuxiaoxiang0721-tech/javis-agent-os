"""Offline subscription identity and resumable waiting; no provider or graph I/O."""
import copy
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE/'scripts'), str(CODE/'tests'), str(CODE/'tools/memory-adapter')]
import memory_pipeline as pipeline
import memory_screen as screen
from memory_controls import update
from memory_model_config import MemoryModelUnavailable
from raw_storage import append_event
from javis_memory_adapter.review_policy import digest
from test_jev_policy import FakeClient
from test_memory_screen_autoreview import Graph, TEXT


class SubscriptionPipelineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root/'config').mkdir()
        (self.root/'config/memory-pipeline.json').write_text(json.dumps({'enabled':True,'model':'jev-1.13.0'}))
        update(self.root, 0, global_enabled=True)
        append_event(self.root, {'event_id':'subscription-source','event_type':'model_output','agent':'invest',
            'payload':{'text':TEXT,'speaker':'assistant'}})
        self.source = screen.load_source(self.root, 'subscription-source')
        self.client = FakeClient(); self.graph = Graph()
        self.config = {'provider':'openai','model':'gpt-test-snapshot','revision':3,'status':'ready',
            'auth_mode':'chatgpt_subscription','account_id':'synthetic-account-a',
            'embedding_provider':'openai','embedding_model':'text-embedding-3-small','embedding_dimensions':1536}

    async def call(self, config=None, **extra):
        args = dict(event_id='subscription-source',scope='invest',text=TEXT,
            source_digest=digest(self.source), model_client=self.client, env_path=self.root/'no-env')
        args.update(extra)
        with patch('memory_model_config.status',return_value=config or self.config), \
             patch('memory_screen.GraphitiCandidateClient',return_value=self.graph):
            return await screen.screen(self.root, **args)

    async def test_refresh_metadata_does_not_change_identity_or_replay_paid_steps(self):
        first = await self.call({**self.config,'token_revision':1,'refreshed_at':'first',
                                'access_token':'SYNTHETIC-DO-NOT-PERSIST'})
        self.assertEqual(first['status'],'complete',first)
        self.assertEqual(first['graph_auth_mode'],'chatgpt_subscription')
        self.assertEqual(first['graph_account_id'],'synthetic-account-a')
        self.assertEqual(first['embedding_provider'],'openai')
        self.assertEqual(first['embedding_dimensions'],1536)
        journal=self.root/'memory/screen/runs.jsonl'; before=journal.read_bytes()
        again=await self.call({**self.config,'token_revision':2,'refreshed_at':'second',
                               'access_token':'SYNTHETIC-OTHER-DO-NOT-PERSIST'})
        self.assertEqual(again['run_id'],first['run_id'])
        self.assertEqual(journal.read_bytes(),before)
        self.assertNotIn(b'DO-NOT-PERSIST',before)
        self.assertEqual(len(self.client.calls),2); self.assertEqual(len(self.graph.calls),1)

    async def test_partial_paid_run_never_crosses_account_auth_model_or_embedding_identity(self):
        with patch.object(self.graph,'extract',side_effect=OSError('synthetic failure')):
            first=await self.call()
        self.assertEqual(first['status'],'retry')
        before=(self.root/'memory/screen/runs.jsonl').read_bytes()
        for key,value in [('account_id','synthetic-account-b'),('auth_mode','api_key'),
                          ('model','gpt-other-snapshot'),('embedding_provider','dashscope'),
                          ('embedding_model','text-embedding-3-large'),('embedding_dimensions',3072)]:
            with self.subTest(key=key):
                result=await self.call({**self.config,key:value},resume_run_id=first['run_id'])
                self.assertEqual(result['status'],'blocked')
                self.assertEqual(result['outcome'],'screen_resume_configuration_changed')
        self.assertEqual(len(self.client.calls),1)
        self.assertEqual((self.root/'memory/screen/runs.jsonl').read_bytes(),before)

    async def test_completed_paid_candidate_can_finish_locally_with_its_original_account_receipt(self):
        evaluate=self.client.evaluate
        async def pause_after_verification(*args,**kwargs):
            result=await evaluate(*args,**kwargs)
            if kwargs['stage']=='verification':update(self.root,1,global_enabled=False)
            return result
        with patch.object(self.client,'evaluate',side_effect=pause_after_verification):
            first=await self.call()
        self.assertEqual(first['status'],'held')
        update(self.root,2,global_enabled=True,daily_call_limit=0)
        result=await self.call({**self.config,'status':'chatgpt_subscription_login_required',
                               'account_id':'synthetic-account-b'},resume_run_id=first['run_id'])
        self.assertEqual(result['status'],'complete')
        self.assertEqual(result['graph_account_id'],'synthetic-account-a')
        self.assertEqual(result['run_id'],first['run_id'])
        self.assertEqual(len(self.client.calls),2);self.assertEqual(len(self.graph.calls),1)

    async def test_subscription_or_embedding_unready_ticks_preserve_raw_and_queue_bytes(self):
        pipeline.enqueue(self.root,event_id='subscription-source',scope='invest')
        def snapshot():
            return {str(p.relative_to(self.root)):p.read_bytes()
                for base in ('raw','state/memory-pipeline/queue')
                for p in (self.root/base).rglob('*') if p.is_file()}
        before=snapshot()
        codes=['chatgpt_subscription_login_required','chatgpt_subscription_access_denied',
               'chatgpt_subscription_usage_limit_exceeded','chatgpt_subscription_usage_unavailable',
               'chatgpt_subscription_account_changed','waiting_for_embedding_key',
               'waiting_for_embedding_configuration']
        for code in codes:
            with self.subTest(code=code), patch('jev_client.credentials_status',return_value={'configured':True}), \
                 patch('memory_model_config.status',return_value={**self.config,'status':code}):
                for _ in range(3):
                    result=await pipeline.process_once(self.root)
                    self.assertEqual((result['status'],result['processed']),(code,0))
                self.assertEqual(pipeline.status(self.root)['execution_state'],code)
                self.assertEqual(snapshot(),before)

    async def test_provider_wait_keeps_paid_prefix_and_stops_tick_then_resumes_same_run(self):
        queued=pipeline.enqueue(self.root,event_id='subscription-source',scope='invest')
        append_event(self.root,{'event_id':'second-source','event_type':'model_output','agent':'invest',
            'payload':{'text':TEXT,'speaker':'assistant'}})
        pipeline.enqueue(self.root,event_id='second-source',scope='invest')
        # Direct the first queue item to the primary source, regardless of digest order.
        rows=pipeline._queue_rows(self.root)[0]
        for path,row in rows:
            if row['event_id']=='second-source':
                row['next_attempt_at']=time.time()+3600;path.write_text(json.dumps(row))
        async def call(root,**kwargs):
            return await screen.screen(root,**kwargs,model_client=self.client,env_path=self.root/'no-env')
        original=self.graph.extract
        with patch('memory_model_config.status',return_value=self.config), \
             patch('memory_screen.GraphitiCandidateClient',return_value=self.graph), \
             patch.object(self.graph,'extract',side_effect=MemoryModelUnavailable('chatgpt_subscription_usage_limit_exceeded')):
            first=await pipeline.process_once(self.root,screen_fn=call,limit=10)
        self.assertEqual(first['processed'],1)
        path=self.root/'state/memory-pipeline/queue'/f"{queued['queue_id']}.json"
        row=json.loads(path.read_text());run_id=row['result']['run_id']
        self.assertEqual(row['status'],'chatgpt_subscription_usage_limit_exceeded')
        self.assertEqual((row['attempts'],row['provider_attempts']),(0,0))
        self.assertEqual(len(self.client.calls),1)
        with patch('memory_model_config.status',return_value=self.config), \
             patch('memory_screen.GraphitiCandidateClient',return_value=self.graph), \
             patch('memory_pipeline.time.time',return_value=time.time()+120):
            resumed=await pipeline.process_once(self.root,screen_fn=call)
        final=json.loads(path.read_text())
        self.assertEqual(final['result']['run_id'],run_id)
        self.assertEqual(final['status'],'completed',final)
        self.assertEqual(final['receipt_sequence'],2)
        self.assertEqual(len(self.client.calls),2)

    async def test_repeated_provider_wait_receipts_do_not_collide_after_attempt_rollback(self):
        queued=pipeline.enqueue(self.root,event_id='subscription-source',scope='invest')
        async def wait(*args,**kwargs):return {'status':'chatgpt_subscription_login_required'}
        with patch('memory_pipeline.time.time',return_value=1000):
            first=await pipeline.process_once(self.root,screen_fn=wait)
        with patch('memory_pipeline.time.time',return_value=2000):
            second=await pipeline.process_once(self.root,screen_fn=wait)
        self.assertEqual((first['processed'],second['processed']),(1,1))
        row=json.loads((self.root/'state/memory-pipeline/queue'/f"{queued['queue_id']}.json").read_text())
        self.assertTrue(row['receipt_recorded']);self.assertEqual(row['attempts'],0)
        self.assertEqual(row['receipt_sequence'],2)


if __name__=='__main__':unittest.main()
