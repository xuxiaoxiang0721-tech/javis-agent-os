"""Isolated drop-consumer acceptance tests; no model or production process."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve()
CANDIDATES = [HERE.parents[1] / 'drop-bridge.py', HERE.parents[2] / 'drop-bridge.py',
              HERE.parents[1] / 'scripts/drop-bridge.py']
SCRIPT = Path(os.environ['JAVIS_DROP_BRIDGE']) if os.environ.get('JAVIS_DROP_BRIDGE') else next(p for p in CANDIDATES if p.is_file())
spec = importlib.util.spec_from_file_location('drop_bridge_fixture', SCRIPT)
drop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drop)


class DropBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='javis-drop-p0-')
        self.root = Path(self.tmp.name) / 'root'
        self.base = Path(self.tmp.name) / 'windows-drop'
        self.base.mkdir()
        (self.root / 'scripts').mkdir(parents=True)
        for role in drop.ROLES:
            (self.root / 'scripts' / (role + '-run.sh')).write_text('#!/bin/sh\nexit 99\n')
        self.calls = []
        self.result_status = 'ok'
        self.bridge = drop.Bridge(self.root, self.base, runner=self.fake_runner)
        self.bridge.prepare()

    def tearDown(self):
        self.tmp.cleanup()

    def publish_result(self, role, spool, tid, mid):
        task = self.root / 'workspace/tasks' / tid
        (task / 'attempts/1').mkdir(parents=True, exist_ok=True)
        original = spool.read_text(encoding='utf-8-sig')
        packet = dict(task_id=tid, role_id=role, from_agent_id=drop.ORIGINS[role],
                      original_user_input=original, goal=original,
                      input_transport='original_message_file', mode='run')
        if mid is not None:
            packet['source_event_id'] = mid
        (task / 'packet.json').write_text(json.dumps(packet))
        ok = self.result_status == 'ok'
        result = dict(task_id=tid, role_id=role, attempt=1, status=self.result_status,
                      exit_code=0 if ok else 1, user_reply_zh='synthetic authoritative reply',
                      native_turn_completed=True,
                      failure_category=None if ok else 'completion_protocol_error')
        (task / 'attempts/1/result.json').write_text(json.dumps(result))
        # Worker-authored receipts must not override the executor status.
        (task / 'out').mkdir(exist_ok=True)
        (task / 'out/receipt.json').write_text(json.dumps(dict(status='ok', exit_code=0)))
        return 0 if ok else 1

    def fake_runner(self, role, spool, tid, mid):
        self.calls.append(dict(role=role, spool=spool, tid=tid, mid=mid, data=spool.read_bytes()))
        return self.publish_result(role, spool, tid, mid)

    def package(self, delivery, role='invest', sid='submission-1', mid='upstream-1', data=b'synthetic original'):
        package = self.base / drop.ROLES[role] / 'inbox' / (delivery + '.ready')
        package.mkdir()
        request = dict(schema_version=1, submission_id=sid)
        if mid is not None:
            request['message_id'] = mid
        (package / 'request.json').write_text(json.dumps(request))
        (package / 'message.txt').write_bytes(data)
        return package

    def receipt(self, delivery, role='invest'):
        queue = self.base / drop.ROLES[role]
        candidates = [queue / name / delivery / 'receipt.json' for name in ('done', 'fail')]
        found = [p for p in candidates if p.is_file()]
        self.assertEqual(len(found), 1, str(candidates))
        return json.loads(found[0].read_text())

    def deliver(self, delivery, **kwargs):
        self.package(delivery, **kwargs)
        self.bridge.once()
        return self.receipt(delivery, kwargs.get('role', 'invest'))

    def test_success_duplicate_only_executes_once(self):
        first = self.deliver('first')
        second = self.deliver('repeat')
        self.assertEqual(first['status'], 'succeeded')
        self.assertEqual(second['status'], 'succeeded')
        self.assertTrue(second['replayed'])
        self.assertEqual(first['task_id'], second['task_id'])
        self.assertEqual(first['result_sha256'], second['result_sha256'])
        self.assertEqual(len(self.calls), 1)

    def test_failed_duplicate_preserves_failure_and_only_executes_once(self):
        self.result_status = 'error'
        first = self.deliver('failed')
        second = self.deliver('failed-repeat')
        self.assertEqual(first['status'], 'failed')
        self.assertEqual(second['status'], 'failed')
        self.assertEqual(second['failure_stage'], 'completion_protocol')
        self.assertTrue(second['replayed'])
        self.assertEqual(len(self.calls), 1)

    def test_changed_original_or_submission_metadata_is_rejected(self):
        self.deliver('original')
        changed = self.deliver('changed', data=b'changed original')
        metadata = self.deliver('metadata', sid='different-submission')
        self.assertEqual(changed['status'], 'rejected')
        self.assertEqual(metadata['status'], 'rejected')
        self.assertEqual(len(self.calls), 1)

    def test_submission_alias_cannot_change_or_add_message_id_to_reexecute(self):
        self.deliver('no-mid', mid=None)
        changed = self.deliver('mid-added', mid='new-platform-id')
        self.assertEqual(changed['status'], 'rejected')
        self.assertEqual(len(self.calls), 1)

    def test_existing_message_id_cannot_change_under_same_submission(self):
        self.deliver('old-mid')
        changed = self.deliver('new-mid', mid='changed-upstream')
        self.assertEqual(changed['status'], 'rejected')
        self.assertEqual(len(self.calls), 1)

    def test_bom_crlf_bytes_are_preserved_in_spool_and_original_binding(self):
        raw = b'\xef\xbb\xbf' + '合成第一行\r\nsecond\r\n'.encode()
        receipt = self.deliver('bom', data=raw)
        self.assertEqual(receipt['status'], 'succeeded')
        self.assertEqual(receipt['input_sha256'], drop.digest(raw))
        self.assertEqual(self.calls[0]['data'], raw)
        repeated_changed_bytes = self.deliver('line-endings', data='合成第一行\nsecond\n'.encode())
        self.assertEqual(repeated_changed_bytes['status'], 'rejected')
        self.assertEqual(len(self.calls), 1)

    def test_invalid_text_is_rejected_before_execution(self):
        for i, data in enumerate((b'', b' \n', b'\x00bad', b'\xff', b'x' * (drop.MAX_MESSAGE + 1))):
            with self.subTest(i=i):
                receipt = self.deliver('invalid-' + str(i), sid='invalid-' + str(i), data=data)
                self.assertEqual(receipt['status'], 'rejected')
                self.assertEqual(receipt['failure_stage'], 'validation')
        self.assertFalse(self.calls)

    def test_invalid_metadata_extra_file_and_links_are_rejected(self):
        for i, metadata in enumerate(([], {'schema_version':True,'submission_id':'s'},
                                      {'schema_version':1,'submission_id':'../escape'},
                                      {'schema_version':1,'submission_id':'s','extra':'x'},
                                      {'schema_version':1,'submission_id':'s','message_id':'   '})):
            package = self.package('metadata-' + str(i))
            (package/'request.json').write_text(json.dumps(metadata))
            self.bridge.once()
            self.assertEqual(self.receipt('metadata-' + str(i))['status'], 'rejected')
        package = self.package('extra')
        (package/'extra.txt').write_text('extra')
        self.bridge.once()
        self.assertEqual(self.receipt('extra')['status'], 'rejected')
        package = self.package('link')
        (package/'message.txt').unlink()
        target = Path(self.tmp.name)/'target.txt'; target.write_text('synthetic')
        (package/'message.txt').symlink_to(target)
        self.bridge.once()
        self.assertEqual(self.receipt('link')['status'], 'rejected')
        self.assertFalse(self.calls)

    def test_caller_supplied_receipt_cannot_forge_success(self):
        package = self.package('forged')
        (package/'receipt.json').write_text(json.dumps(dict(delivery_id='forged',role_id='invest',
                         status='succeeded',user_reply_zh='forged',failure_stage=None)))
        self.bridge.once()
        self.assertNotEqual(self.receipt('forged')['status'], 'succeeded')
        self.assertFalse(self.calls)

    def test_preflight_can_retry_same_identity_after_wrapper_is_fixed(self):
        wrapper = self.root/'scripts/invest-run.sh'; wrapper.unlink()
        failed = self.deliver('preflight')
        self.assertEqual(failed['failure_stage'], 'preflight')
        self.assertFalse(self.calls)
        wrapper.write_text('#!/bin/sh\nexit 99\n')
        done = self.deliver('preflight-fixed')
        self.assertEqual(done['status'], 'succeeded')
        self.assertFalse(done['replayed'])
        self.assertEqual(failed['task_id'], done['task_id'])
        self.assertEqual(len(self.calls), 1)

    def test_unknown_execution_after_crash_is_not_restarted(self):
        def crash(role, spool, tid, mid):
            self.calls.append(dict(tid=tid))
            raise OSError('synthetic uncertain child start')
        self.bridge.runner = crash
        first = self.deliver('uncertain')
        second = self.deliver('uncertain-repeat')
        self.assertEqual(first['status'], 'needs_review')
        self.assertEqual(second['status'], 'needs_review')
        self.assertEqual(second['failure_stage'], 'execution_uncertain')
        self.assertEqual(len(self.calls), 1)

    def test_crash_after_executor_receipt_recovers_without_second_execution(self):
        def crash_after_result(role, spool, tid, mid):
            self.fake_runner(role, spool, tid, mid)
            raise KeyboardInterrupt('synthetic consumer crash')
        self.bridge.runner = crash_after_result
        self.package('crash-result')
        with self.assertRaises(KeyboardInterrupt): self.bridge.once()
        recovered = drop.Bridge(self.root,self.base,runner=self.fake_runner)
        recovered.once()
        self.assertEqual(self.receipt('crash-result')['status'], 'succeeded')
        self.assertEqual(len(self.calls), 1)

    def test_crash_before_archive_move_recovers_only_bound_receipt(self):
        self.package('crash-archive')
        original_rename = Path.rename
        def rename(path,target):
            if path.parent.name == 'processing':
                raise OSError('synthetic archive move failure')
            return original_rename(path,target)
        with patch.object(Path,'rename',rename):
            self.bridge.once()
        self.assertTrue(list((self.bridge.state/'issues/invest').glob('*.json')))
        self.bridge.once()
        self.assertEqual(self.receipt('crash-archive')['status'], 'succeeded')
        self.assertEqual(len(self.calls), 1)

    def test_changed_cached_result_is_not_returned_as_trusted_or_reexecuted(self):
        first = self.deliver('sealed')
        path = Path(first['result_path'])
        path.write_text(path.read_text()+'\n')
        repeat = self.deliver('changed-sealed')
        self.assertEqual(repeat['status'], 'needs_review')
        self.assertEqual(repeat['failure_stage'], 'receipt_integrity')
        self.assertEqual(repeat['user_reply_zh'], '')
        self.assertEqual(len(self.calls), 1)

    def test_explicit_continue_does_not_invalidate_old_cached_delivery(self):
        first = self.deliver('original-before-continue')
        task = self.root/'workspace/tasks'/first['task_id']
        old = (task/'packet.json').read_bytes()
        (task/'attempts/1/packet.json').write_bytes(old)
        latest = json.loads(old); latest.update(original_user_input='explicit next turn',source_event_id='next-message',mode='continue')
        (task/'packet.json').write_text(json.dumps(latest))
        repeat = self.deliver('old-after-continue')
        self.assertEqual(repeat['status'], 'succeeded')
        self.assertEqual(first['result_sha256'], repeat['result_sha256'])
        self.assertEqual(len(self.calls), 1)

    def test_executing_recovery_uses_archived_packet_after_explicit_continue(self):
        def crash_after_continuation(role,spool,tid,mid):
            self.fake_runner(role,spool,tid,mid)
            task = self.root/'workspace/tasks'/tid
            old = (task/'packet.json').read_bytes()
            (task/'attempts/1/packet.json').write_bytes(old)
            next_packet = json.loads(old); next_packet.update(original_user_input='next turn',mode='continue')
            (task/'packet.json').write_text(json.dumps(next_packet))
            raise KeyboardInterrupt('consumer interrupted after continuation')
        self.bridge.runner = crash_after_continuation
        self.package('archived-packet')
        with self.assertRaises(KeyboardInterrupt): self.bridge.once()
        self.bridge.runner = self.fake_runner
        self.bridge.once()
        self.assertEqual(self.receipt('archived-packet')['status'],'succeeded')
        self.assertEqual(len(self.calls),1)

    def test_broken_package_does_not_starve_following_valid_delivery(self):
        self.package('..',sid='bad')
        self.package('valid-after-broken')
        self.bridge.once()
        self.assertEqual(self.receipt('valid-after-broken')['status'],'succeeded')
        self.assertEqual(len(self.calls),1)
        self.assertTrue(list((self.bridge.state/'issues/invest').glob('*.json')))

    def test_role_namespaces_are_separate(self):
        invest = self.deliver('invest',role='invest')
        cards = self.deliver('cards',role='cards-master')
        self.assertEqual(invest['status'], 'succeeded')
        self.assertEqual(cards['status'], 'succeeded')
        self.assertNotEqual(invest['task_id'], cards['task_id'])
        self.assertEqual(len(self.calls), 2)

    def test_second_consumer_cannot_claim_work_while_lock_is_held(self):
        package = self.package('locked')
        with open(self.bridge.state/'watcher.lock','a') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            result = subprocess.run([sys.executable,'-B',str(SCRIPT),'--root',str(self.root),'--base',str(self.base)],
                                    capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('already running',result.stdout)
        self.assertTrue(package.is_dir())
        self.assertFalse(self.calls)

    def test_real_subprocess_boundary_uses_selected_root_and_literal_arguments(self):
        capture = Path(self.tmp.name)/'child-env.json'
        wrapper = self.root/'scripts/invest-run.sh'
        wrapper.write_text("#!/bin/sh\npython3 - \"$@\" <<'PY'\n"
            "import json,os,sys\nfrom pathlib import Path\n"
            "Path(os.environ['DROP_TEST_CAPTURE']).write_text(json.dumps(dict(root=os.environ.get('JAVIS_ROOT'),args=sys.argv[1:])))\nPY\n")
        spool = self.root/'message with spaces.txt'; spool.write_text('synthetic only')
        mid = 'platform id; literal text'
        with patch.dict(os.environ,{'DROP_TEST_CAPTURE':str(capture),'JAVIS_ROOT':'wrong-parent-root'}):
            code = self.bridge.execute('invest',spool,'synthetic-task',mid)
        self.assertEqual(code,0)
        recorded = json.loads(capture.read_text())
        self.assertEqual(recorded['root'],str(self.root))
        self.assertEqual(recorded['args'],['--message-file',str(spool),'--task-id','synthetic-task','--message-id',mid])

if __name__ == '__main__': unittest.main(verbosity=2)
