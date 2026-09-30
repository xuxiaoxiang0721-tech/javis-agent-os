#!/usr/bin/env python3
"""Offline producer tests: private Linux temporary queues, no consumer/model execution."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
TEST_FILE = Path(__file__).resolve()
PRODUCER_FILE = TEST_FILE.with_name('submit-drop.py')
if not PRODUCER_FILE.is_file():
    PRODUCER_FILE = TEST_FILE.parents[2] / 'submit-drop.py'
spec = importlib.util.spec_from_file_location('submit_drop_tested', PRODUCER_FILE)
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.area = tempfile.TemporaryDirectory(prefix='javis-drop-producer-')
        self.root = Path(self.area.name)
        self.queue = self.root / 'isolated queue'
        self.source = self.root / 'source with spaces.txt'
        self.source.write_bytes(b'\xef\xbb\xbffirst\r\n' + '\u539f\u6587\nlast\r\n'.encode())

    def tearDown(self):
        self.assertEqual(self.root.parent, Path(tempfile.gettempdir()))
        self.area.cleanup()

    def submit(self, **changes):
        args = dict(role='invest', message_file=str(self.source), submission_id='stable-1', base=str(self.queue))
        args.update(changes)
        return producer.submit(**args)

    def reject(self, **changes):
        with self.assertRaises((producer.contract.Reject, OSError, UnicodeError)):
            self.submit(**changes)
        self.assertEqual(list(self.queue.rglob('*.ready')) if self.queue.exists() else [], [])

    def test_bytes_and_real_unicode_message_id(self):
        mid = 'grok:\u6d4b\u8bd5/opaque-123'
        result = self.submit(message_id=mid)
        ready = Path(result['ready_path'])
        self.assertEqual((ready / 'message.txt').read_bytes(), self.source.read_bytes())
        self.assertEqual(json.loads((ready / 'request.json').read_bytes()),
                         dict(schema_version=1, submission_id='stable-1', message_id=mid))
        self.assertEqual(result['input_sha256'], producer.contract.digest(self.source.read_bytes()))
        self.assertTrue(result['receipt_locations']['done'].endswith('/done/' + result['delivery_id'] + '/receipt.json'))

    def test_two_roles_and_missing_upstream_identity(self):
        result = self.submit(role='cards-master')
        self.assertIn('/cards-drop/inbox/', result['ready_path'])
        self.assertNotIn('message_id', json.loads((Path(result['ready_path']) / 'request.json').read_bytes()))
        self.assertIsNone(result['message_id'])

    def test_repeat_has_new_delivery_stable_submission(self):
        first, second = self.submit(), self.submit()
        self.assertNotEqual(first['delivery_id'], second['delivery_id'])
        self.assertEqual(first['submission_id'], second['submission_id'])
        self.assertTrue(Path(first['ready_path']).is_dir())

    def test_publish_only_after_complete_valid_package(self):
        real_rename = os.rename
        observed = []
        def inspect(source, target):
            self.assertTrue(str(source).endswith('.tmp'))
            self.assertEqual(source.parent, target.parent)
            self.assertEqual({p.name for p in source.iterdir()}, {'message.txt', 'request.json'})
            producer.contract.validate(source)
            observed.append(True)
            real_rename(source, target)
        with patch.object(producer.os, 'rename', side_effect=inspect):
            self.submit()
        self.assertEqual(observed, [True])
        self.assertEqual(list(self.queue.rglob('*.tmp')), [])

    def test_input_byte_limit(self):
        self.source.write_bytes(b'x' * (1024 * 1024 + 1))
        self.reject()
        self.source.write_bytes(b'x' * (1024 * 1024))
        self.assertEqual(self.submit()['submission_status'], 'queued')

    def test_invalid_text_never_published(self):
        for data in (b'', b'\xef\xbb\xbf \r\n', b'\xff\xfe', b'hello\x00world'):
            with self.subTest(data=data):
                self.source.write_bytes(data)
                self.reject()

    def test_invalid_submission_ids(self):
        for sid in ('', '../bad', 'a' * 81, 'has space', 'x\n'):
            with self.subTest(sid=sid):
                self.reject(submission_id=sid)

    def test_real_message_id_limits_and_printability(self):
        for mid in ('', ' ', 'bad\nID', 'bad\u200bID', 'a' * 161, '\ue000'):
            with self.subTest(mid=mid):
                self.reject(message_id=mid)
        result = self.submit(message_id='\U0001f600' * 160)
        self.assertEqual(result['message_id'], '\U0001f600' * 160)

    def test_linked_files_and_ancestors_rejected(self):
        link = self.root / 'linked.txt'
        link.symlink_to(self.source)
        self.reject(message_file=str(link))
        hardlink = self.root / 'hardlinked.txt'
        os.link(self.source, hardlink)
        self.reject(message_file=str(hardlink))
        linked_dir = self.root / 'linked-dir'
        linked_dir.symlink_to(self.root, target_is_directory=True)
        self.reject(message_file=str(linked_dir / self.source.name))

    def test_non_file_and_linked_queue_rejected(self):
        self.reject(message_file=str(self.root))
        target = self.root / 'actual queue'
        target.mkdir()
        self.queue.symlink_to(target, target_is_directory=True)
        self.reject()

    def test_local_path_conversion_without_unc(self):
        self.assertEqual(producer.local_path('C:\\Users\\user\\message.txt'), Path('/mnt/c/Users/user/message.txt'))
        self.assertEqual(producer.local_path(str(self.source)), self.source)
        for value in ('\\\\server\\share\\file', '//server/share/file', 'C:relative', 'relative.txt', 'C:\\a\\..\\b'):
            with self.subTest(value=value), self.assertRaises(producer.contract.Reject):
                producer.local_path(value)

    def test_cli_reports_queued_without_running_consumer(self):
        args = [sys.executable, '-B', str(PRODUCER_FILE),
                '--role', 'invest', '--message-file', str(self.source), '--submission-id', 'cli-test', '--base', str(self.queue)]
        result = subprocess.run(args, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['submission_status'], 'queued')
        self.assertFalse((self.queue / 'state').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
