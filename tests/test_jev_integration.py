"""Offline production-path integration: real Jev adapter/policy, mocked HTTP only."""
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE/'scripts'), str(CODE/'tests')]
import memory_pipeline as pipeline
from memory_screen import screen, load_source, source_digest, ReviewBlocked
from raw_storage import append_event
from javis_memory_adapter.usage_meter import summary, recent
from test_memory_screen import Graph, TEXT, DATE

PIN = 'jev-1.13.0'


class Reply(io.BytesIO):
    status = 200
    headers = {'x-typesafe-request-id': 'synthetic-only-request'}


def reply(request, **kwargs):
    body = json.loads(request.data)
    answers = {}
    for key, question in body['questions'].items():
        name = key.split('_', 1)[1] if key.startswith('f0') else key
        if question['type'] == 'noul':
            answers[key] = {'type':'noul','noul':.01 if name in {'injection','ambiguity','missing_referent'} else .99}
        else:
            chosen = {'decision':'keep','category':'rule','statement_kind':'user_explicit','verdict':'supports'}[name]
            answers[key] = {'type':'choice','choice':chosen,'confidence':.99,
                'probabilities':{k:1.0 if k==chosen else 0.0 for k in question['criteria']}}
    return Reply(json.dumps({'model':PIN,'answers':answers,
                            'usage':{'input_tokens':100,'output_tokens':0}}).encode())


class JevPipelineIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='javis-jev-integration-')
        self.root = Path(self.tmp.name)
        from memory_controls import update
        update(self.root, 0, global_enabled=True)
        (self.root/'config').mkdir()
        shutil.copyfile(CODE/'config/memory-pricing.json',self.root/'config/memory-pricing.json')
        shutil.copyfile(CODE/'config/memory-pipeline.json',self.root/'config/memory-pipeline.json')
        from memory_model_config import configure
        configure(self.root, expected_revision=0, model='gpt-test-2026-09-30', api_key='synthetic-only-openai-memory-key')
        self.env = patch.dict(os.environ, {'TYPESAFE_API_KEY':'synthetic-only-key'}, clear=False)
        self.env.start()
        append_event(self.root, {'event_id':'synthetic-event','event_type':'user_input','agent':'invest',
            'occurred_at':DATE,'completeness':'complete','payload':{'text':TEXT,'is_original_user_input':True}})
        self.digest = source_digest(load_source(self.root,'synthetic-event'))
        self.graph = Graph()
        self.opener = Mock()
        self.opener.open.side_effect = reply

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    async def screen(self, **extra):
        args = dict(event_id='synthetic-event', scope='invest', text=TEXT,
            source_digest=self.digest, model=PIN, graph_client=self.graph,
            env_path=self.root/'no-graph-env')
        args.update(extra)
        return await screen(self.root, **args)

    def enqueue(self):
        pipeline.enqueue(self.root,event_id='synthetic-event',scope='invest')
        return next((self.root/'state/memory-pipeline/queue').glob('*.json'))

    async def test_actual_adapter_to_policy_to_candidate_and_replay_metered_once(self):
        with patch('jev_client.build_opener',return_value=self.opener):
            result = await self.screen()
            again = await self.screen()
        self.assertEqual(result['status'],'complete',result)
        self.assertEqual(result['outcome'],'pending_review',result)
        self.assertEqual(result,again)
        self.assertEqual(self.opener.open.call_count,2)
        self.assertEqual(len(self.graph.calls),1)
        self.assertEqual(result['provider'],'typesafe')
        self.assertEqual(result['actual_model'],PIN)
        self.assertEqual(result['verification_model'],PIN)
        self.assertTrue(result['verification_checkpoint'])
        self.assertEqual(result['candidates'][0]['status'],'pending_review')
        from memory_autoreview import MemoryAutoreview
        from javis_memory_adapter.review_policy import usable_facts
        facts=usable_facts(MemoryAutoreview(self.root).review._store('invest'))
        self.assertEqual(len(facts),1)
        self.assertEqual(facts[0].status,'ai_reviewed')
        self.assertIsNone(facts[0].confirmation_event_id)
        self.assertFalse((self.root/'memory/review/decisions.jsonl').exists())
        rows = recent(self.root)
        self.assertEqual({r['stage'] for r in rows},{'screening','verification'})
        self.assertEqual({r['provider_host'] for r in rows},{'api.typesafe.ai'})
        self.assertEqual(summary(self.root)['all']['estimated_cost_by_currency']['USD']['amount'],'0.0000084')
        ledger = (self.root/'memory/usage/requests.jsonl').read_text()
        self.assertNotIn('synthetic-only-key',ledger)
        self.assertNotIn(TEXT,ledger)

    async def test_no_key_keeps_raw_and_queue_byte_identical_across_ticks(self):
        os.environ['TYPESAFE_API_KEY']=''
        path=self.enqueue(); before=path.read_bytes()
        with patch('jev_client.build_opener') as network:
            direct=await self.screen()
            for _ in range(7):
                out=await pipeline.process_once(self.root)
                self.assertEqual(out['status'],'waiting_for_key')
                self.assertEqual(out['processed'],0)
        network.assert_not_called()
        self.assertEqual(direct['status'],'waiting_for_key')
        self.assertEqual(path.read_bytes(),before)
        self.assertEqual(load_source(self.root,'synthetic-event')['payload']['text'],TEXT)
        self.assertFalse((self.root/'memory/usage/requests.jsonl').exists())
        self.assertEqual(pipeline.status(self.root)['execution_state'],'waiting_for_key')

    async def test_queued_old_provider_is_not_silently_repaid_under_new_config(self):
        path=self.enqueue(); row=json.loads(path.read_text())
        row.update(model='qwen-turbo',prompt_version='jev-screen-v1',attempts=3)
        row.pop('provider');path.write_text(json.dumps(row))
        with patch('jev_client.build_opener',return_value=self.opener), \
             patch('memory_screen.GraphitiCandidateClient',return_value=self.graph):
            result=await pipeline.process_once(self.root)
        row=json.loads(path.read_text())
        self.assertEqual(result['processed'],1)
        self.assertEqual(row['status'],'blocked',row)
        self.assertEqual(row['error_code'],'queued_configuration_changed')
        self.assertEqual(row['model'],'qwen-turbo')
        self.assertEqual(row['attempts'],3)
        self.opener.open.assert_not_called()

    async def test_graph_failure_resumes_without_repaying_jev_screen(self):
        self.graph.fail=True
        with patch('jev_client.build_opener',return_value=self.opener):
            first=await self.screen()
            self.graph.fail=False
            second=await self.screen()
        self.assertEqual(first['status'],'retry')
        self.assertEqual(second['outcome'],'pending_review')
        self.assertEqual(self.opener.open.call_count,2)

    async def test_qwen_or_unpinned_models_are_rejected(self):
        with patch('jev_client.build_opener') as network:
            for model in ('qwen-turbo','jev-latest','jev-1.13'):
                with self.subTest(model=model),self.assertRaises(ReviewBlocked):
                    await self.screen(model=model)
        network.assert_not_called()

    async def test_rejected_key_pauses_all_work_and_replacement_resumes(self):
        path=self.enqueue()
        self.opener.open.side_effect=HTTPError('https://api.typesafe.ai/v1/systemone',401,
            'sensitive-do-not-log',{},io.BytesIO(b'private response'))
        with patch('jev_client.build_opener',return_value=self.opener), \
             patch('memory_screen.GraphitiCandidateClient',return_value=self.graph):
            first=await pipeline.process_once(self.root)
            self.assertEqual(first['items'][0]['status'],'credentials_rejected')
            for _ in range(7):
                out=await pipeline.process_once(self.root)
                self.assertEqual(out['status'],'credentials_rejected')
                self.assertEqual(out['processed'],0)
            self.assertEqual(self.opener.open.call_count,1)
            row=json.loads(path.read_text())
            self.assertEqual(row['attempts'],1)
            self.assertEqual(row['provider_attempts'],1)
            self.assertEqual(pipeline.status(self.root)['execution_state'],'credentials_rejected')
            self.assertEqual(pipeline.resume_credentials(self.root),1)
            self.opener.open.side_effect=reply
            await pipeline.process_once(self.root)
        self.assertEqual(json.loads(path.read_text())['status'],'completed')
        self.assertEqual(self.opener.open.call_count,3)

    async def test_corrupt_rejection_marker_cannot_starve_valid_queue(self):
        path=self.enqueue()
        (path.parent/'broken.json').write_text('{"status":"credentials_rejected"}')
        with patch('jev_client.build_opener',return_value=self.opener), \
             patch('memory_screen.GraphitiCandidateClient',return_value=self.graph):
            result=await pipeline.process_once(self.root)
        self.assertEqual(result['processed'],1)
        self.assertEqual(result['corrupt_queue_files'],1)
        self.assertEqual(json.loads(path.read_text())['status'],'completed')

    async def test_authentication_receipt_crash_recovers_before_pause_or_reset(self):
        path=self.enqueue()
        self.opener.open.side_effect=HTTPError('https://api.typesafe.ai/v1/systemone',401,
            'private',{},io.BytesIO(b'private'))
        with patch('jev_client.build_opener',return_value=self.opener):
            with patch.object(pipeline,'append_event',side_effect=OSError('synthetic receipt disk failure')):
                with self.assertRaises(OSError):await pipeline.process_once(self.root)
            self.assertFalse(json.loads(path.read_text())['receipt_recorded'])
            result=await pipeline.process_once(self.root)
            self.assertEqual(result['status'],'credentials_rejected')
            self.assertEqual(result['receipts_recovered'],1)
            self.assertTrue(json.loads(path.read_text())['receipt_recorded'])
            self.assertEqual(self.opener.open.call_count,1)
            # Exercise key replacement directly after a crash as well. Receipt
            # append is idempotent, and its old attempt/status remain recorded.
            row=json.loads(path.read_text());row['receipt_recorded']=False
            path.write_text(json.dumps(row))
            self.assertEqual(pipeline.resume_credentials(self.root),1)
            self.assertTrue(json.loads(path.read_text())['receipt_recorded'])
        events=[json.loads(line) for p in (self.root/'raw/events').rglob('*.jsonl')
                for line in p.read_text().splitlines()]
        receipts=[e for e in events if e['event_type']=='memory_pipeline_result']
        self.assertEqual(len(receipts),1)
        self.assertEqual(receipts[0]['payload']['status'],'credentials_rejected')
        self.assertEqual(receipts[0]['payload']['attempt'],1)

    async def test_oversized_source_is_preserved_and_never_sent(self):
        text='合成原始资料。'*3000
        append_event(self.root,{'event_id':'synthetic-large','event_type':'user_input','agent':'invest',
            'occurred_at':DATE,'payload':{'text':text,'is_original_user_input':True}})
        with patch('jev_client.build_opener') as network:
            result=await self.screen(event_id='synthetic-large',text=text,
                source_digest=source_digest(load_source(self.root,'synthetic-large')))
        network.assert_not_called()
        self.assertEqual(result['outcome'],'needs_evidence')
        self.assertIsNone(result['actual_model'])
        self.assertEqual(result['screen_decisions']['local_reason'],'source_too_large')
        self.assertEqual(load_source(self.root,'synthetic-large')['payload']['text'],text)
        self.assertEqual(self.graph.calls,[])
        self.assertEqual(result['status'],'needs_review')
        self.assertEqual(result['review_count'],1)
        from memory_triage import get_pending
        self.assertEqual(get_pending(self.root,result['review_refs'][0])['reason_code'],'source_too_large')

    async def test_real_adapter_uncertainty_is_durable_without_formal_write_or_repay(self):
        def uncertain(request, **kwargs):
            value=json.loads(reply(request, **kwargs).read())
            for key, answer in value['answers'].items():
                if key.endswith('_verdict'):
                    answer.update(confidence=.6,probabilities={'supports':.8,'contradicts':0,'insufficient':.2})
            return Reply(json.dumps(value).encode())
        self.opener.open.side_effect=uncertain
        with patch('jev_client.build_opener',return_value=self.opener):
            result=await self.screen()
            again=await self.screen()
        self.assertEqual(result,again)
        self.assertEqual(result['status'],'needs_review')
        self.assertEqual(result['review_count'],1)
        self.assertEqual(result['candidates'],[])
        self.assertEqual(self.opener.open.call_count,2)
        self.assertEqual(len(self.graph.calls),1)
        from memory_triage import get_pending
        item=get_pending(self.root,result['review_refs'][0])
        self.assertEqual(item['source_integrity'],'verified')
        self.assertEqual(item['reason_code'],'verification_uncertain')
        self.assertFalse((self.root/'memory/structured').exists())
        requests=[json.loads(call.args[0].data) for call in self.opener.open.call_args_list]
        verification=requests[-1]
        self.assertNotIn('edge-one',json.dumps(verification['state']))
        self.assertNotIn('node-one',json.dumps(verification['state']))
        self.assertFalse(any(key.endswith('_numbers') for key in verification['questions']))

    async def test_invalid_authoritative_probability_is_visible_review_not_repaid_retry(self):
        for stage in ('screening','verification'):
            with self.subTest(stage=stage):
                eid='invalid-protocol-'+stage
                append_event(self.root,{'event_id':eid,'event_type':'user_input','agent':'invest',
                    'occurred_at':DATE,'payload':{'text':TEXT,'is_original_user_input':True}})
                def malformed(request,**kwargs):
                    value=json.loads(reply(request,**kwargs).read())
                    key='statement_kind' if stage=='screening' else 'f0000_statement_kind'
                    if key in value['answers']:
                        value['answers'][key]['probabilities']['user_explicit']=.99
                    return Reply(json.dumps(value).encode())
                self.opener.open.side_effect=malformed
                previous=self.opener.open.call_count
                with patch('jev_client.build_opener',return_value=self.opener):
                    result=await self.screen(event_id=eid,source_digest=source_digest(load_source(self.root,eid)))
                    replay=await self.screen(event_id=eid,source_digest=source_digest(load_source(self.root,eid)))
                self.assertEqual(result,replay)
                self.assertEqual(result['status'],'needs_review',result)
                self.assertEqual(result['review_count'],1)
                self.assertEqual(result['error_code'],'jev_invalid_probability_sum')
                self.assertEqual(self.opener.open.call_count-previous,1 if stage=='screening' else 2)
                self.assertFalse(result.get('candidates'))
                from memory_triage import get_pending
                item=get_pending(self.root,result['review_refs'][0])
                self.assertEqual(item['reason_code'],'model_response_invalid')
                self.assertEqual(item['stage'],stage)
                self.assertFalse((self.root/'memory/structured').exists())


if __name__=='__main__': unittest.main(verbosity=2)
