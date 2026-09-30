"""Local correction evidence must remain independent from owner authority."""
import json
import tempfile
import time
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from memory_feedback import LocalMemoryFeedback, MemoryFeedback, ReviewBlocked
from raw_storage import append_event


class LocalFeedbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.session = {'kind': 'local_memory', 'expires': time.time() + 600}
        self.local = LocalMemoryFeedback(self.root)
        append_event(self.root, {'event_id': 'local-source', 'agent': 'invest', 'event_type': 'user_input',
            'occurred_at': None, 'payload': {'text': '请在每周报告中注明数据来源。', 'is_original_user_input': True}})

    def test_local_feedback_is_usable_without_owner_impersonation_or_confirmation(self):
        context = self.local.context(self.session, 'local-source', 'invest')
        request = {**context['bindings'], 'label': 'keep', 'command_id': 'local-correct-1'}
        result = self.local.record(self.session, request)
        self.assertEqual(result['authority'], 'local_user_feedback')
        self.assertFalse(result['confirmation_authority'])
        self.assertEqual(self.local.record(self.session, request)['feedback_id'], result['feedback_id'])
        rows = list((self.root / 'memory/local-feedback/items').glob('*.json'))
        self.assertEqual(len(rows), 1)
        saved = json.loads(rows[0].read_text())
        self.assertEqual(saved['actor_id'], 'local-user')
        self.assertEqual(self.local.training_status()['eligible'], 1)
        self.assertEqual(MemoryFeedback(self.root).training_rows(), [])
        for folder in ('memory/review', 'memory/structured', 'state/owner-auth/decisions', 'memory/feedback'):
            self.assertFalse((self.root / folder).exists(), folder)

    def test_owner_endpoint_does_not_accept_local_capability(self):
        with self.assertRaises(ReviewBlocked):
            MemoryFeedback(self.root).context(self.session, 'local-source', 'invest')

    def test_expired_local_session_or_cross_scope_is_denied(self):
        for session in (None, {'kind': 'owner', 'expires': time.time()+600}, {'kind': 'local_memory', 'expires': 0}):
            with self.assertRaises(ReviewBlocked): self.local.context(session, 'local-source', 'invest')
        with self.assertRaises(ReviewBlocked): self.local.context(self.session, 'local-source', 'cards-master')

    def test_revision_invalidates_old_label_and_keeps_unknown_time(self):
        first = self.local.context(self.session, 'local-source', 'invest')
        self.local.record(self.session, {**first['bindings'], 'label':'keep', 'command_id':'one'})
        second = self.local.context(self.session, 'local-source', 'invest')
        self.local.record(self.session, {**second['bindings'], 'label':'archive', 'command_id':'two'})
        rows = self.local.training_rows()
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0]['label'], 'archive')
        self.assertIsNone(rows[0]['source_time'])


if __name__ == '__main__': unittest.main()
