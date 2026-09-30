import asyncio,importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
CODE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(CODE/'scripts'))
import memory_pipeline as pipeline
import task_memory
from raw_storage import append_event
from javis_memory_adapter.review_policy import source_digests, digest

class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);(self.root/'config').mkdir()
        (self.root/'config/memory-pipeline.json').write_text(json.dumps({'enabled':True,'model':'jev-1.13.0'}))
        from memory_controls import update
        update(self.root, 0, global_enabled=True, command_id='synthetic-enable')
        append_event(self.root,{'event_id':'source-one','event_type':'user_input','agent':'invest',
            'task_id':'task-one','occurred_at':'2026-09-24T01:00:00Z',
            'payload':{'text':'Synthetic weekly report is Monday','is_original_user_input':True}},
            relative_path='events/nested/source.jsonl')

    def enqueue(self):return pipeline.enqueue(self.root,event_id='source-one',scope='invest')

    def test_status_reads_active_config_and_runtime_policy_without_writes(self):
        config=self.root/'config/memory-pipeline.json'
        config.write_text(json.dumps({'enabled':True,'model':'jev-1.13.0',
                                      'prompt_version':'synthetic-configured-prompt'}))
        before={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        result=pipeline.status(self.root)
        self.assertEqual(result['prompt_version'],'synthetic-configured-prompt')
        from memory_screen import PIPELINE_VERSION
        self.assertEqual(result['pipeline_version'], PIPELINE_VERSION)
        self.assertEqual(result['policy_version'],'jev-typed-v4-temporal')
        from jev_policy import POLICY_DIGEST
        self.assertEqual(result['policy_digest'],POLICY_DIGEST)
        self.assertRegex(result['policy_digest'],r'^[a-f0-9]{64}$')
        self.assertEqual({str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()},before)
        self.assertFalse((self.root/'memory').exists())

    def test_nested_raw_is_visible_to_approval_and_task(self):
        event=task_memory._raw_index(self.root)['source-one']
        self.assertEqual(source_digests(self.root,{'source-one'}),{'source-one':digest(event)})

    def test_duplicate_event_with_changed_payload_rejected(self):
        row=task_memory._raw_index(self.root)['source-one'];row['payload']['text']='changed'
        (self.root/'raw/events/duplicate.jsonl').write_text(json.dumps(row)+'\n')
        with self.assertRaises(ValueError):self.enqueue()
        with self.assertRaises(ValueError):source_digests(self.root,{'source-one'})

    def test_durable_enqueue_replay_and_no_body_copy(self):
        first=self.enqueue();again=self.enqueue();self.assertEqual(first['queue_id'],again['queue_id'])
        self.assertTrue(again['replayed'])
        row=json.loads(next((self.root/'state/memory-pipeline/queue').glob('*.json')).read_text())
        self.assertNotIn('Synthetic',json.dumps(row))

    def test_scope_forgery_rejected(self):
        with self.assertRaises(ValueError):pipeline.enqueue(self.root,event_id='source-one',scope='cards-master')

    def test_learning_waits_for_queue_and_credentials_then_is_bounded(self):
        from unittest.mock import AsyncMock
        advance=AsyncMock(return_value={'status':'waiting_for_feedback'})
        with patch('jev_client.credentials_status',return_value={'configured':False}):
            self.assertEqual(asyncio.run(pipeline.advance_learning_when_idle(self.root,advance_fn=advance))['status'],'deferred')
        advance.assert_not_called()
        with patch('jev_client.credentials_status',return_value={'configured':True}), \
             patch('memory_model_config.status',return_value={'status':'ready'}):
            result=asyncio.run(pipeline.advance_learning_when_idle(self.root,advance_fn=advance))
        self.assertEqual(result['status'],'waiting_for_feedback')
        advance.assert_awaited_once_with(limit=1,max_calls=4)
        self.enqueue();advance.reset_mock()
        with patch('jev_client.credentials_status',return_value={'configured':True}), \
             patch('memory_model_config.status',return_value={'status':'ready'}):
            self.assertEqual(asyncio.run(pipeline.advance_learning_when_idle(self.root,advance_fn=advance))['status'],'deferred')
        advance.assert_not_called()

    def test_worker_replay_skips_completed(self):
        self.enqueue();calls=[]
        async def fake(*a,**k):calls.append(k);return {'status':'completed','run_id':'test-only'}
        self.assertEqual(asyncio.run(pipeline.process_once(self.root,screen_fn=fake))['processed'],1)
        self.assertEqual(asyncio.run(pipeline.process_once(self.root,screen_fn=fake))['processed'],0)
        self.assertEqual(len(calls),1)
        self.assertFalse((self.root/'memory/structured').exists())

    def test_manual_review_is_terminal_and_preserves_refs_in_receipt(self):
        self.enqueue();calls=[];refs=['triage_'+'a'*64]
        async def fake(*a,**k):
            calls.append(1)
            return {'status':'needs_review','run_id':'synthetic_run','outcome':'needs_evidence',
                    'review_refs':refs,'review_count':1,'candidates':[]}
        out=asyncio.run(pipeline.process_once(self.root,screen_fn=fake))
        self.assertEqual(out['items'][0]['status'],'needs_review')
        self.assertEqual(asyncio.run(pipeline.process_once(self.root,screen_fn=fake))['processed'],0)
        self.assertEqual(calls,[1])
        row=json.loads(next((self.root/'state/memory-pipeline/queue').glob('*.json')).read_text())
        self.assertEqual(row['result']['review_refs'],refs)
        events=task_memory._raw_index(self.root)
        receipts=[item for item in events.values() if item.get('event_type')=='memory_pipeline_result']
        self.assertEqual(receipts[0]['payload']['review_refs'],refs)
        self.assertEqual(receipts[0]['payload']['review_count'],1)

    def test_manual_receipt_crash_recovered_without_rescreen(self):
        self.enqueue();calls=[]
        async def fake(*a,**k):
            calls.append(1)
            return {'status':'needs_review','review_refs':['triage_'+'b'*64],'review_count':1}
        with patch.object(pipeline,'append_event',side_effect=OSError('synthetic crash')):
            with self.assertRaises(OSError):asyncio.run(pipeline.process_once(self.root,screen_fn=fake))
        out=asyncio.run(pipeline.process_once(self.root,screen_fn=fake))
        self.assertEqual(out['receipts_recovered'],1)
        self.assertEqual(out['processed'],0)
        self.assertEqual(calls,[1])

    def test_partial_triage_does_not_make_failed_proposal_terminal(self):
        self.enqueue();calls=[];refs=['triage_'+'c'*64]
        async def fake(*a,**k):
            calls.append(1)
            return {'status':'retry' if len(calls)==1 else 'needs_review','review_refs':refs,'review_count':1}
        first=asyncio.run(pipeline.process_once(self.root,screen_fn=fake))
        self.assertEqual(first['items'][0]['status'],'retry')
        path=next((self.root/'state/memory-pipeline/queue').glob('*.json'))
        row=json.loads(path.read_text());row['next_attempt_at']=0;path.write_text(json.dumps(row))
        second=asyncio.run(pipeline.process_once(self.root,screen_fn=fake))
        self.assertEqual(second['items'][0]['status'],'needs_review')
        self.assertEqual(calls,[1,1])

    def test_old_completed_item_does_not_rerun_after_policy_config_change(self):
        self.enqueue();calls=[]
        async def fake(*a,**k):calls.append(1);return {'status':'complete'}
        asyncio.run(pipeline.process_once(self.root,screen_fn=fake))
        config=self.root/'config/memory-pipeline.json'
        config.write_text(json.dumps({'enabled':True,'model':'jev-1.13.0','prompt_version':'jev-typesafe-v99'}))
        self.assertEqual(asyncio.run(pipeline.process_once(self.root,screen_fn=fake))['processed'],0)
        self.assertEqual(calls,[1])

    def test_unpinned_or_changed_policy_is_blocked_before_model(self):
        from unittest.mock import AsyncMock
        for value in (None,'0'*64):
            with self.subTest(policy=value):
                self.enqueue();path=next((self.root/'state/memory-pipeline/queue').glob('*.json'))
                row=json.loads(path.read_text());row['status']='retry';row['next_attempt_at']=0
                if value is None:row.pop('policy_digest',None)
                else:row['policy_digest']=value
                path.write_text(json.dumps(row))
                screen=AsyncMock()
                out=asyncio.run(pipeline.process_once(self.root,screen_fn=screen))
                self.assertEqual(out['items'][0]['status'],'blocked');screen.assert_not_called()

    def test_dynamic_or_unbound_profile_is_corrupt_queue(self):
        self.enqueue();path=next((self.root/'state/memory-pipeline/queue').glob('*.json'))
        row=json.loads(path.read_text());row['learning_version']='active';path.write_text(json.dumps(row))
        rows,corrupt=pipeline._queue_rows(self.root)
        self.assertEqual(rows,[]);self.assertEqual(corrupt,1)

    def test_failure_is_retry_not_archive_only(self):
        self.enqueue()
        async def fake(*a,**k):raise TimeoutError('synthetic')
        out=asyncio.run(pipeline.process_once(self.root,screen_fn=fake));self.assertEqual(out['items'][0]['status'],'retry')

    def test_source_changes_block_before_model(self):
        self.enqueue();p=self.root/'raw/events/nested/source.jsonl'
        event=json.loads(p.read_text());event['payload']['text']='changed';p.write_text(json.dumps(event)+'\n')
        async def fake(*a,**k):self.fail('Model must not run')
        out=asyncio.run(pipeline.process_once(self.root,screen_fn=fake));self.assertEqual(out['items'][0]['status'],'blocked')

    def test_hold_prevents_worker(self):
        self.enqueue();(self.root/'state/recovery-hold.json').write_text('{"hold":true}')
        with self.assertRaises(Exception):asyncio.run(pipeline.process_once(self.root))

    def test_runtime_enqueues_without_formal_write(self):
        task=self.root/'workspace/tasks/task-one'
        packet={'task_id':'task-one','role_id':'invest','original_user_input':'Synthetic weekly report is Monday'}
        result=task_memory.finalize(self.root,task,packet,1,'source-one')
        self.assertEqual(result['memory_status'],'screening_queued');self.assertEqual(result['write_refs'],[])
        self.assertFalse((self.root/'memory/structured').exists())

    def test_corrupt_queue_does_not_starve_valid_work(self):
        self.enqueue();(self.root/'state/memory-pipeline/queue/000bad.json').write_text('{')
        async def fake(*a,**k):return {'status':'complete'}
        out=asyncio.run(pipeline.process_once(self.root,screen_fn=fake))
        self.assertEqual(out['processed'],1);self.assertEqual(out['corrupt_queue_files'],1)

    def test_receipt_crash_recovered_without_model_rerun(self):
        self.enqueue();calls=[]
        async def fake(*a,**k):calls.append(1);return {'status':'complete'}
        with patch.object(pipeline,'append_event',side_effect=OSError('synthetic crash')):
            with self.assertRaises(OSError):asyncio.run(pipeline.process_once(self.root,screen_fn=fake))
        out=asyncio.run(pipeline.process_once(self.root,screen_fn=fake))
        self.assertEqual(out['receipts_recovered'],1);self.assertEqual(calls,[1])

    def test_unknown_screen_status_is_not_success(self):
        self.enqueue()
        async def fake(*a,**k):return {'status':'unexpected'}
        out=asyncio.run(pipeline.process_once(self.root,screen_fn=fake))
        self.assertEqual(out['items'][0]['status'],'retry')

    def test_hold_blocks_enqueue_and_grok_and_owner_review(self):
        (self.root/'state').mkdir(exist_ok=True)
        (self.root/'state/recovery-hold.json').write_text('{"hold":true}')
        with self.assertRaises(Exception):self.enqueue()
        self.assertFalse((self.root/'state/memory-pipeline/queue').exists())
        def module(name,file):
            spec=importlib.util.spec_from_file_location(name,CODE/'scripts'/file)
            value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
        grok=module('pipeline_grok_test','grok-sync.py')
        request={'capture_id':'held-test','role_id':'invest','messages':[
            {'speaker':'user','text':'Synthetic report','fidelity':'forwarded_original_unverified'}]}
        with self.assertRaises(Exception):grok.ingest(self.root,request)
        self.assertFalse((self.root/'raw/events/grok-sync').exists())
        panel=module('pipeline_panel_test','control-panel.py');app=panel.App(self.root)
        with patch('memory_review.MemoryReview.review') as review:
            with self.assertRaises(Exception):app.review_memory(None,{},None)
            review.assert_not_called()

    def test_typed_queue_corruption_does_not_starve_valid_work(self):
        self.enqueue();folder=self.root/'state/memory-pipeline/queue'
        row=json.loads(next(folder.glob('*.json')).read_text())
        row.update(queue_id='000corrupt',next_attempt_at='invalid')
        (folder/'000corrupt.json').write_text(json.dumps(row))
        row.update(queue_id='001corrupt',next_attempt_at=0,status=['queued'])
        (folder/'001corrupt.json').write_text(json.dumps(row))
        async def fake(*a,**k):return {'status':'complete'}
        out=asyncio.run(pipeline.process_once(self.root,screen_fn=fake))
        self.assertEqual(out['processed'],1);self.assertEqual(out['corrupt_queue_files'],2)

    def test_sync_failure_does_not_prevent_queue_processing(self):
        async def fake(*a,**k):return {'status':'ok','processed':1}
        import memory_sync,io
        from contextlib import redirect_stdout
        with patch.object(sys,'argv',['memory_pipeline.py','run','--root',str(self.root)]), \
             patch.object(memory_sync,'run',side_effect=OSError('synthetic')), \
             patch.object(pipeline,'process_once',side_effect=fake) as worker:
            with redirect_stdout(io.StringIO()) as capture:self.assertEqual(pipeline.main(),0)
        worker.assert_called_once()
        self.assertEqual(json.loads(capture.getvalue())['sync_status'],'failed')

    def test_grok_archive_survives_enqueue_failure_and_replay_recovers(self):
        spec=importlib.util.spec_from_file_location('pipeline_grok_retry',CODE/'scripts/grok-sync.py')
        grok=importlib.util.module_from_spec(spec);spec.loader.exec_module(grok)
        request={'capture_id':'retry-test','role_id':'invest','messages':[
            {'speaker':'user','text':'Synthetic report','fidelity':'forwarded_original_unverified'}]}
        with patch.object(pipeline,'enqueue',side_effect=OSError('synthetic disk failure')):
            first=grok.ingest(self.root,request)
        self.assertTrue(first['archived']);self.assertEqual(first['screening']['status'],'retry')
        replay=grok.ingest(self.root,request)
        self.assertTrue(replay['replayed']);self.assertEqual(replay['screening']['status'],'queued')
        self.assertEqual(len(list((self.root/'state/memory-pipeline/queue').glob('*.json'))),1)

if __name__=='__main__':unittest.main(verbosity=2)
