"""Runtime integration: pinned versions, scope, replay and evidence separation."""
import asyncio
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

CODE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(CODE/'scripts'),str(CODE/'tests')]
import memory_pipeline as pipeline
import test_jev_integration as integration
from test_memory_screen import TEXT
from javis_memory_adapter.review_policy import ReviewBlocked


class LearningRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        integration.JevPipelineIntegrationTests.setUp(self)
        from memory_controls import status, update
        state=status(self.root)
        if not state['global_enabled']:
            update(self.root,state['revision'],global_enabled=True,command_id='learning-runtime-enable')
    tearDown=integration.JevPipelineIntegrationTests.tearDown
    screen=integration.JevPipelineIntegrationTests.screen

    def profile(self, version='learning-one'):
        return {'version_id':'learn_'+('a' if version=='learning-one' else 'b')*32,
                'digest':('a' if version=='learning-one' else 'b')*64}

    async def test_guidance_only_reaches_screening_and_replay_is_free(self):
        profile=self.profile(); wire=[]
        from test_jev_integration import reply
        def capture(request,**kwargs): wire.append(json.loads(request.data));return reply(request,**kwargs)
        self.opener.open.side_effect=capture
        with patch('memory_learning.runtime_profile',return_value=profile), \
             patch('memory_learning.validate_profile',side_effect=lambda p,*args:copy.deepcopy(p)), \
             patch('memory_learning.screening_context',return_value={'examples':['UNRELATED_PRIOR_SOURCE']}), \
             patch('jev_client.build_opener',return_value=self.opener):
            result=await self.screen();again=await self.screen()
        self.assertEqual(result,again)
        self.assertEqual(result['learning_version'],'learn_'+'a'*32)
        self.assertEqual(self.opener.open.call_count,2)
        self.assertIn('UNRELATED_PRIOR_SOURCE',json.dumps(wire[0]['state']['routing']))
        self.assertEqual(wire[0]['state']['source']['original_source'],TEXT)
        self.assertNotIn('UNRELATED_PRIOR_SOURCE',json.dumps(wire[1]))
        self.assertEqual(result['autoreview']['accepted_count'],1)
        from memory_autoreview import MemoryAutoreview
        fact=MemoryAutoreview(self.root).review._store('invest').get_fact(result['autoreview']['accepted'][0]['fact_id'])
        self.assertEqual(fact.status,'ai_reviewed')
        self.assertIsNone(fact.confirmation_event_id)

    async def test_explicit_snapshot_does_not_select_new_active_profile(self):
        with patch('memory_learning.runtime_profile',side_effect=AssertionError('must use queued snapshot')), \
             patch('memory_learning.profile_by_version',return_value=None) as load, \
             patch('jev_client.build_opener',return_value=self.opener):
            result=await self.screen(learning_version='baseline')
        self.assertEqual(result['learning_version'],'baseline')
        self.assertEqual(load.call_args.args[1],'baseline')

    async def test_changed_snapshot_blocks_before_http(self):
        with patch('memory_learning.profile_by_version',return_value=self.profile()), \
             patch('jev_client.build_opener',return_value=self.opener):
            with self.assertRaises(ReviewBlocked):
                await self.screen(learning_version='learning-one',learning_profile_digest='b'*64)
        self.opener.open.assert_not_called()

    async def test_queue_retains_version_across_activation_change(self):
        with patch('memory_learning.runtime_profile',return_value=self.profile()):
            first=pipeline.enqueue(self.root,event_id='synthetic-event',scope='invest')
        calls=[]
        async def fake(root,**kwargs):calls.append(kwargs);return {'status':'complete','run_id':'synthetic-run'}
        with patch('memory_learning.runtime_profile',side_effect=AssertionError('must not replace queued profile')):
            result=await pipeline.process_once(self.root,screen_fn=fake)
        self.assertEqual(result['processed'],1)
        self.assertEqual(calls[0]['learning_version'],'learn_'+'a'*32)
        self.assertEqual(calls[0]['learning_profile_digest'],'a'*64)
        self.assertEqual((await pipeline.process_once(self.root,screen_fn=fake))['processed'],0)

    async def test_new_version_creates_new_queue_identity_without_overwriting_old(self):
        with patch('memory_learning.runtime_profile',return_value=self.profile()):
            first=pipeline.enqueue(self.root,event_id='synthetic-event',scope='invest')
        with patch('memory_learning.runtime_profile',return_value=self.profile('learning-two')):
            second=pipeline.enqueue(self.root,event_id='synthetic-event',scope='invest')
        self.assertNotEqual(first['queue_id'],second['queue_id'])
        self.assertEqual(len(list((self.root/'state/memory-pipeline/queue').glob('*.json'))),2)


if __name__=='__main__':unittest.main()
