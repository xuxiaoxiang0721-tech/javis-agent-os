import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE / 'scripts'), str(CODE / 'tools/memory-adapter')]
from memory_autoreview import MemoryAutoreview, ReviewBlocked
from memory_review import MemoryReview
from raw_storage import append_event
from javis_memory_adapter.review_policy import ai_reviewed, owner_confirmed, digest

class AutoReviewTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='memory-ai-test-')
        self.root = Path(self.tmp.name)
        self.auto = MemoryAutoreview(self.root)
        self.review = MemoryReview(self.root)
        append_event(self.root, {'event_id': 'source-one', 'task_id': 'task-one', 'event_type': 'user_input',
            'agent': 'cards-master', 'payload': {'text': '我喜欢蓝色', 'is_original_user_input': True}})
        self.fact = dict(fact_id='fact_one', subject_id='user', subject_label='用户', predicate='color', value='蓝色',
                         unit=None, valid_from=None, valid_to=None, recorded_at='2026-09-30T00:00:00+00:00',
                         source_event_id='source-one', raw_refs=['source-one'], notes=[])
        self.candidate = self.review.propose('cards-master', self.fact)
        self.raw_before = {str(p): p.read_bytes() for p in (self.root/'raw').rglob('*.jsonl')}

    def tearDown(self):
        self.tmp.cleanup()

    def enable(self):
        return self.auto.control('resume', 0, 'enable-test')

    def accept(self, **kwargs):
        return self.auto.review_candidate('cards-master', self.candidate['candidate_id'],
            self.candidate['version_digest'], '原文明确偏好', kwargs.get('excerpt', '我喜欢蓝色'))

    def test_disabled_then_accept_is_not_owner_and_replay_is_idempotent(self):
        with self.assertRaisesRegex(ReviewBlocked, 'paused'):
            self.accept()
        self.enable()
        decision = self.accept()
        ledger_path = self.root/'memory/structured/cards-master/facts.jsonl'
        ledger_before = ledger_path.read_bytes()
        self.assertEqual(self.accept(), decision)
        self.assertEqual(ledger_path.read_bytes(), ledger_before)
        store = self.review._store('cards-master')
        fact = store.get_fact(decision['effect']['fact_id'])
        self.assertTrue(ai_reviewed(store, fact))
        self.assertFalse(owner_confirmed(store, fact))
        self.assertIsNone(fact.confirmation_event_id)
        self.assertIsNone(fact.valid_from)
        self.assertEqual(len(self.auto._rows()), 1)
        self.assertEqual(self.raw_before, {str(p): p.read_bytes() for p in (self.root/'raw').rglob('*.jsonl')})
        self.assertFalse((self.root/'memory/feedback').exists())

    def test_pause_does_not_remove_memory_withdraw_does_and_cannot_resurrect(self):
        self.enable(); decision = self.accept()
        store = self.review._store('cards-master'); fact = store.get_fact(decision['effect']['fact_id'])
        self.auto.control('pause', 1, 'pause-test')
        self.assertTrue(ai_reviewed(store, fact))
        self.auto.withdraw(decision['review_event_id'], digest(decision), 'withdraw-test')
        self.assertFalse(ai_reviewed(store, fact))
        self.assertEqual(self.auto.resolved(), {})
        self.auto.control('resume', 2, 'resume-test')
        self.assertTrue(self.accept()['withdrawn'])
        self.assertFalse(ai_reviewed(store, fact))

    def test_wrong_excerpt_stale_version_and_cross_scope_fail(self):
        self.enable()
        with self.assertRaisesRegex(ReviewBlocked, 'excerpt'):
            self.accept(excerpt='我喜欢红色')
        with self.assertRaises(ReviewBlocked):
            self.auto.review_candidate('cards-master', self.candidate['candidate_id'], '0'*64, 'reason', '我喜欢蓝色')
        wrong = self.review.propose('invest', self.fact)
        with self.assertRaisesRegex(ReviewBlocked, 'scope'):
            self.auto.review_candidate('invest', wrong['candidate_id'], wrong['version_digest'], 'reason', '我喜欢蓝色')
        self.assertEqual(self.auto._rows(), [])

    def test_changed_source_invalidates_recall_and_replay(self):
        self.enable(); decision = self.accept()
        store = self.review._store('cards-master'); fact = store.get_fact(decision['effect']['fact_id'])
        for p in (self.root/'raw').rglob('*.jsonl'):
            p.write_text(p.read_text().replace('蓝色', '红色'))
        self.assertFalse(ai_reviewed(store, fact))
        with self.assertRaisesRegex(ReviewBlocked, 'source_changed'):
            self.accept()
        self.assertEqual(self.auto.resolved(), {})

    def test_control_stale_and_command_reuse(self):
        first = self.enable()
        self.assertEqual(self.enable(), first)
        with self.assertRaises(ReviewBlocked):
            self.auto.control('pause', 0, 'pause-stale')
        with self.assertRaises(ReviewBlocked):
            self.auto.control('pause', 1, 'enable-test')

if __name__ == '__main__': unittest.main()
