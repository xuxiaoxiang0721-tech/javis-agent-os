"""Regression proofs for independently reproduced autoreview write boundaries."""
import sys
import tempfile
import unittest
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE / "scripts"), str(CODE / "tools/memory-adapter")]
from memory_autoreview import MemoryAutoreview
from memory_review import MemoryReview
from raw_storage import append_event
from javis_memory_adapter.review_policy import ReviewBlocked
from task_service import ControlError


class MemoryAutoreviewGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="javis-autoreview-guard-")
        self.root = Path(self.tmp.name)
        self.review = MemoryReview(self.root)
        self.auto = MemoryAutoreview(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def prepare(self, **source_fields):
        append_event(self.root, {"event_id": "source-one", "event_type": "user_input", "agent": "invest",
            "payload": {"text": "Alice prefers blue."}, **source_fields})
        candidate = self.review.propose("invest", {"fact_id": "synthetic-fact", "subject_id": "alice",
            "subject_label": "Alice", "predicate": "prefers", "value": "Alice prefers blue.",
            "unit": None, "valid_from": None, "valid_to": None, "recorded_at": "2026-09-30T00:00:00Z",
            "source_event_id": "source-one", "raw_refs": ["source-one"], "notes": []})
        self.auto.control("resume", 0, "synthetic-enable")
        return candidate

    def accept(self, candidate):
        return self.auto.review_candidate("invest", candidate["candidate_id"], candidate["version_digest"],
            "Synthetic explicit source evidence", "Alice prefers blue.")

    def assert_no_acceptance(self):
        self.assertEqual(self.auto._rows(), [])
        self.assertFalse((self.root / "memory/structured").exists())
        self.assertFalse((self.root / "memory/feedback").exists())

    def test_restore_hold_blocks_auto_acceptance_after_policy_is_enabled(self):
        candidate = self.prepare()
        hold = self.root / "state/recovery-hold.json"
        hold.parent.mkdir(exist_ok=True)
        hold.write_text('{"hold":true}')
        with self.assertRaises(ControlError) as raised:
            self.accept(candidate)
        self.assertEqual(raised.exception.code, "recovery_hold")
        self.assert_no_acceptance()
        # Read-only inspection remains available during a restore hold.
        self.assertTrue(self.auto.status()["enabled"])
        hold.write_text('{"hold":false}')
        self.assertEqual(self.accept(candidate)["effect"]["status"], "ai_reviewed")

    def test_parent_cloud_false_is_checked_before_benign_excerpt(self):
        candidate = self.prepare(cloud_eligible=False)
        with self.assertRaisesRegex(ReviewBlocked, "source_privacy_excluded"):
            self.accept(candidate)
        self.assert_no_acceptance()

    def test_parent_l4_is_checked_before_benign_excerpt(self):
        candidate = self.prepare(privacy_level="L4")
        with self.assertRaisesRegex(ReviewBlocked, "source_privacy_excluded"):
            self.accept(candidate)
        self.assert_no_acceptance()

    def test_same_scope_other_source_cannot_archive_a_candidate(self):
        candidate = self.prepare()
        append_event(self.root, {"event_id": "source-two", "event_type": "user_input", "agent": "invest",
            "payload": {"text": "Bob prefers green."}})
        with self.assertRaisesRegex(ReviewBlocked, "candidate_source_mismatch"):
            self.auto.review_item(kind="candidate", item_id=candidate["candidate_id"], scope="invest",
                version_digest=candidate["version_digest"], event_id="source-two", action="archive",
                reason="Synthetic unrelated evidence", source_excerpt="Bob prefers green.")
        self.assert_no_acceptance()
        self.assertEqual(self.review._current("invest", candidate["candidate_id"])["status"], "pending_review")


if __name__ == "__main__":
    unittest.main()
