#!/usr/bin/env python3
"""Synthetic V0.2 RAW acceptance checks. Never touches live user evidence."""
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
HERE = Path(os.environ.get('JAVIS_TEST_CODE_ROOT',Path(__file__).resolve().parent.parent))/'scripts'
sys.path.insert(0,str(HERE))
from raw_policy import redact, sanitize, StreamRedactor, safe_file_bytes, CredentialFileBlocked, MASK
from raw_storage import append_event, snapshot_file, normalize_event
from raw_cursor import ingest_jsonl

spec = importlib.util.spec_from_file_location('rebuilder', HERE / 'rebuild-task-view.py')
rebuilder = importlib.util.module_from_spec(spec); spec.loader.exec_module(rebuilder)


class RawAcceptance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='javis-v02-raw-')
        self.base = Path(self.temp.name); self.root = self.base / 'isolated-javis'
        self.source = self.base / '用户 输入.txt'

    def tearDown(self): self.temp.cleanup()

    def events(self):
        rows = []
        for path in (self.root / 'raw/events').glob('*.jsonl'):
            rows.extend(json.loads(line) for line in path.read_text().splitlines())
        return rows

    def assert_not_persisted(self, *secrets):
        for path in self.root.rglob('*'):
            if path.is_file():
                data = path.read_bytes()
                for secret in secrets: self.assertNotIn(secret.encode(), data, str(path))

    def test_credential_labels_and_values_filtered(self):
        samples = {'password': 'FakePassOne!', 'api_key': 'fake_api_xyz', 'notes': '密码是 虚构密码甲 token=fake_token_xyz; Bearer fakeBearer123',
                   'model': 'gpt-example', 'source_event_id': 'source-real-id', 'total_tokens': 18}
        safe, changes = redact(samples)
        self.assertTrue(changes)
        self.assertEqual(safe['source_event_id'], 'source-real-id')
        self.assertEqual(safe['total_tokens'], 18)
        self.assertEqual(safe, sanitize(safe))
        append_event(self.root, {'event_id': 'safe-1', 'event_type': 'user_input', 'payload': samples})
        self.assert_not_persisted('FakePassOne!', 'fake_api_xyz', '虚构密码甲', 'fake_token_xyz', 'fakeBearer123')
        self.assertTrue(self.events()[0]['redactions'])

    def test_stream_filters_chunk_boundaries_and_pem(self):
        stream = StreamRedactor(); out = ''
        for chunk in ['hello\napi_', 'key=fakeSplitKey\n-----BEGIN PRI', 'VATE KEY-----\nprivatePart1\n', 'privatePart2\n-----END PRIVATE KEY-----\nlast']:
            out += stream.feed(chunk)
        out += stream.finish()
        self.assertEqual(out, 'hello\napi_key=' + MASK + '\n' + MASK + '\nlast')
        self.assertTrue(stream.redactions)

    def test_stream_credentials_with_value_on_next_line(self):
        stream=StreamRedactor()
        out=stream.feed('API Key:\n')+stream.feed('fakeNextLineKey\nnormal\n')+stream.finish()
        self.assertNotIn('fakeNextLineKey',out)
        self.assertIn('normal',out)

    def test_unknown_occurrence_is_null_with_unified_fields(self):
        event = normalize_event({'event_type': 'user_input', 'payload': {'text': '产品A100'}})
        self.assertIsNone(event['occurred_at'])
        for field in ('turn_id','source_event_id','parent_event_id','entry','model','execution_path','evidence_refs','risk','approval_ref','supersedes','contradicts'):
            self.assertIn(field, event)
        self.assertIn('timestamp_unavailable', event['missing_reason'])

    def test_multi_process_append_deduplicates(self):
        cmd = [sys.executable, str(HERE / 'raw-append-event.py'), '--root', str(self.root), json.dumps({'event_id': 'same', 'event_type': 'status'})]
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: subprocess.run(cmd, capture_output=True, text=True), range(12)))
        self.assertTrue(all(r.returncode == 0 for r in results))
        self.assertEqual(len(self.events()), 1)

    def test_writer_rejects_path_escape(self):
        with self.assertRaises(ValueError): append_event(self.root, {'event_type': 'status'}, relative_path='../../outside.jsonl')
        self.assertFalse((self.base / 'outside.jsonl').exists())

    def test_snapshot_versions_keep_both_values_and_sources(self):
        self.source.write_text('产品A数量100，单价12美元；产品B数量50，单价8美元；合计1600美元', encoding='utf-8')
        one = snapshot_file(self.root, self.source, 'task-a', capture_key='turn-1', windows_path='C:/用户 输入.txt', linux_path='/tmp/task/in/file.txt')
        self.source.write_text('产品A数量120，单价12美元；产品B数量50，单价8美元；合计1840美元', encoding='utf-8')
        two = snapshot_file(self.root, self.source, 'task-a', capture_key='turn-2')
        self.assertEqual(two['artifact_id'], one['artifact_id'])
        self.assertEqual(two['previous_snapshot_id'], one['snapshot_id'])
        self.assertEqual(two['previous_sha256'], one['sha256'])
        self.assertEqual(two['version'], 2)
        self.assertEqual(one['original_name'], '用户 输入.txt')
        self.assertEqual(one['linux_path'], '/tmp/task/in/file.txt')
        for row in (one,two):
            data = (self.root / 'raw/objects' / row['sha256']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(),row['sha256'])
        self.assertIn('1600', (self.root / 'raw/objects' / one['sha256']).read_text())
        self.assertIn('1840', (self.root / 'raw/objects' / two['sha256']).read_text())

    def test_same_object_keeps_distinct_file_references(self):
        self.source.write_text('same contents')
        other = self.base / 'other.txt'; other.write_text('same contents')
        a = snapshot_file(self.root,self.source,'t',capture_key='one')
        b = snapshot_file(self.root,other,'t',capture_key='one')
        self.assertEqual(a['sha256'],b['sha256'])
        self.assertNotEqual(a['artifact_id'],b['artifact_id'])
        self.assertEqual(len(self.events()),2)

    def test_snapshot_replay_recovers_after_manifest_commit(self):
        self.source.write_text('no secret')
        with patch('raw_storage.append_event',side_effect=OSError('synthetic append failure')):
            with self.assertRaises(OSError): snapshot_file(self.root,self.source,'t',capture_key='one')
        row = snapshot_file(self.root,self.source,'t',capture_key='one')
        replay = snapshot_file(self.root,self.source,'t',capture_key='one')
        self.assertEqual(row,replay)
        self.assertEqual(len(self.events()),1)
        manifests = list((self.root / 'raw/manifests').glob('*.jsonl'))
        self.assertEqual(len(manifests[0].read_text().splitlines()),1)

    def test_text_snapshot_excludes_original_credential_bytes(self):
        self.source.write_text('name=fixture\npassword="fake secret with spaces"\n',encoding='utf-8')
        row = snapshot_file(self.root,self.source,'t')
        self.assertEqual(row['content_form'],'credential_redacted_copy')
        self.assertTrue(row['redactions'])
        self.assert_not_persisted('fake secret with spaces')

    def test_utf16_snapshot_filters_credentials(self):
        self.source.write_text('密码: 假密码ABCD',encoding='utf-16')
        row = snapshot_file(self.root,self.source,'t')
        data = (self.root/'raw/objects'/row['sha256']).read_bytes().decode('utf-16')
        self.assertNotIn('假密码ABCD',data)

    def test_known_credential_file_blocked(self):
        source = self.base/'auth.json'; source.write_text('{"token":"fakeAuthXYZ"}')
        with self.assertRaises(CredentialFileBlocked): snapshot_file(self.root,source,'t')
        self.assertFalse((self.root/'raw/objects').exists())

    def test_binary_allowed_or_sensitive_original_kept_only_encrypted(self):
        self.source.write_bytes(b'\x00\xff\x05ordinary binary\x10')
        row = snapshot_file(self.root,self.source,'t')
        self.assertEqual(row['credential_check_scope'],'opaque_bytes_explicit_patterns_only')
        self.source.write_bytes(b'\x00\xffpassword=fakeBinaryPass\n')
        row = snapshot_file(self.root,self.source,'t')
        self.assertEqual(row['content_form'], 'local_only_safe_placeholder')
        self.assertEqual(row['original']['storage'], 'local_encrypted')
        self.assert_not_persisted('fakeBinaryPass')

    def test_cursor_resume_partial_record_and_replay(self):
        source = self.base/'stream.jsonl'
        first = json.dumps({'type':'thread.started','thread_id':'thread-one'})+'\n'
        final = json.dumps({'type':'item.completed','item':{'id':'item-one','type':'agent_message','text':'合计1600美元'}})+'\n'
        source.write_text(first+final[:20])
        one=ingest_jsonl(self.root,source,task_id='t',final=False)
        self.assertGreater(one['pending_bytes'],0)
        self.assertEqual(one['byte_offset'],len(first.encode()))
        source.write_text(first+final)
        two=ingest_jsonl(self.root,source,task_id='t')
        three=ingest_jsonl(self.root,source,task_id='t')
        self.assertEqual(len(two['written_event_ids']),1)
        self.assertEqual(three['written_event_ids'],[])
        native=[e for e in self.events() if (e.get('payload') or {}).get('record_source')=='codex_native_jsonl']
        self.assertEqual(len(native),2)
        self.assertEqual(native[-1]['payload']['stream_mode'],'final')
        self.assertEqual(native[-1]['session_id'],'thread-one')

    def test_cursor_failure_after_append_replays_without_duplicates(self):
        source=self.base/'stream.jsonl'; source.write_text('{"type":"thread.started","thread_id":"one"}\n')
        import raw_cursor
        real_atomic = raw_cursor.atomic_json
        def fail_checkpoint(path,value):
            if value.get('status') != 'failed': raise OSError('synthetic checkpoint failure')
            return real_atomic(path,value)
        with patch('raw_cursor.atomic_json',side_effect=fail_checkpoint):
            with self.assertRaises(OSError): ingest_jsonl(self.root,source,task_id='t')
        ingest_jsonl(self.root,source,task_id='t')
        self.assertEqual(len(self.events()),1)

    def test_cursor_rotation_and_malformed_records_make_gaps(self):
        source=self.base/'stream.jsonl'; source.write_text('{"type":"thread.started","thread_id":"long-one"}\n')
        ingest_jsonl(self.root,source,task_id='t')
        source.write_text('{"type":"turn.started"}\n{broken\n')
        result=ingest_jsonl(self.root,source,task_id='t')
        self.assertTrue(any('replaced_or_truncated' in gap for gap in result['gaps']))
        self.assertIn('invalid_or_incomplete_JSON_record',result['gaps'])

    def test_rebuild_uses_raw_snapshot_when_cache_is_deleted_or_wrong(self):
        append_event(self.root,{'event_id':'i','event_type':'user_input','task_id':'task-a','payload':{'text':'产品A100'}})
        append_event(self.root,{'event_id':'s','event_type':'task_lifecycle','task_id':'task-a','payload':{'state_snapshot':{'task_id':'task-a','status':'completed','goal':'产品A120','session_id':'session-one','attempt':2}}})
        cache=self.root/'state/tasks/task-a.json';cache.parent.mkdir(parents=True);cache.write_text('{"status":"failed","goal":"wrong-cache"}')
        one=rebuilder.rebuild(self.root,'task-a');cache.unlink();two=rebuilder.rebuild(self.root,'task-a')
        self.assertEqual(one['state'],two['state'])
        self.assertEqual(two['state']['goal'],'产品A120')
        self.assertEqual(two['state']['status'],'completed')
        self.assertEqual(two['rebuilt_from'],'raw_events+raw_manifests')

    def test_rebuild_runtime_state_has_no_contradictory_status(self):
        append_event(self.root,{'event_id':'state','event_type':'task_lifecycle','task_id':'t',
                              'payload':{'state_snapshot':{'task_id':'t','state':'completed'}}})
        state=rebuilder.rebuild(self.root,'t')['state']
        self.assertEqual(state['state'],'completed')
        self.assertEqual(state['status'],'completed')

    def test_native_deltas_are_not_duplicated_in_model_text_view(self):
        source=self.base/'stream.jsonl'
        events=[{'type':'item.delta','item':{'id':'one','text':'1600'}},{'type':'item.completed','item':{'id':'one','type':'agent_message','text':'1600'}}]
        source.write_text(''.join(json.dumps(e)+'\n' for e in events))
        ingest_jsonl(self.root,source,task_id='t')
        append_event(self.root,{'event_id':'final','task_id':'t','event_type':'model_output','payload':{'text':'1600'}})
        view=rebuilder.rebuild(self.root,'t')
        self.assertEqual(len(view['model_outputs']),1)
        self.assertEqual(len([e for e in view['events'] if e['event_type']=='other']),2)

    def test_live_stream_and_finalize_deduplicate_identical_native_lines(self):
        native={'type':'item.completed','item':{'id':'message-a','type':'agent_message','text':'1600'}}
        source=self.base/'stream.jsonl';source.write_text(json.dumps(native)+'\n')
        append_event(self.root,{'event_id':'live-line-0','task_id':'t','event_type':'codex_stream_event',
                              'payload':{'record_source':'codex_json_stream','attempt':1,'native_sequence':0,'event':native}})
        result=ingest_jsonl(self.root,source,task_id='t')
        self.assertEqual(result['written_event_ids'],[])
        self.assertEqual(len(self.events()),1)
        self.assertEqual(self.events()[0]['payload']['stream_mode'],'final')

    def test_different_live_line_is_not_silently_discarded(self):
        source=self.base/'stream.jsonl';source.write_text('{"type":"turn.completed"}\n')
        append_event(self.root,{'event_id':'live-line-0','task_id':'t','event_type':'codex_stream_event',
                              'payload':{'record_source':'codex_json_stream','attempt':1,'native_sequence':0,'event':{'type':'turn.failed'}}})
        result=ingest_jsonl(self.root,source,task_id='t')
        self.assertEqual(len(result['written_event_ids']),1)
        self.assertIn('live_and_replayed_native_event_differ',result['gaps'])

    def test_collector_cross_process_replay_safe_and_final_text_single(self):
        task=self.root/'workspace/tasks/t';(task/'out').mkdir(parents=True)
        (task/'packet.json').write_text(json.dumps({'task_id':'t','role_id':'test','goal':'产品A100产品B50'}))
        (task/'result.json').write_text(json.dumps({'task_id':'t','status':'ok','summary_zh':'合计1600美元','exit_code':0}))
        (task/'codex.log').write_text(json.dumps({'type':'thread.started','thread_id':'thread-test'})+'\n'+json.dumps({'type':'item.completed','item':{'id':'one','type':'agent_message','text':'SUMMARY: 合计1600美元'}})+'\n')
        (task/'out/数量.txt').write_text('A=100 B=50')
        command=[sys.executable,str(HERE/'codex-log-to-raw.py'),'--root',str(self.root),'--task-dir',str(task)]
        first=subprocess.run(command,capture_output=True,text=True)
        self.assertEqual(first.returncode,0,first.stderr)
        count=len(self.events())
        second=subprocess.run(command,capture_output=True,text=True)
        self.assertEqual(second.returncode,0,second.stderr)
        self.assertEqual(count,len(self.events()))
        self.assertEqual(json.loads(second.stdout)['written_event_ids'],[])
        view=rebuilder.rebuild(self.root,'t')
        self.assertEqual(len(view['model_outputs']),1)
        replayed=[e for e in self.events() if e['event_type'] in ('user_input','model_output','task_lifecycle')]
        self.assertTrue(all(e['occurred_at'] is None for e in replayed))


if __name__=='__main__': unittest.main(verbosity=2)
