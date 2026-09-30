"""Enabled screening retains exact owner-reviewed revisions; no real owner or graph."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / "scripts"))
import task_memory
from raw_storage import append_event
import test_owner_memory_review as owner_support


class RevisionPipelineTests(unittest.TestCase):
    def setUp(self):
        # Reuse the isolated content-bound owner fixture, never production auth.
        self.owner = owner_support.OwnerMemoryTest(methodName="test_candidate_is_isolated_and_idempotent")
        self.owner.setUp()
        self.addCleanup(self.owner.tearDown)
        self.owner.confirm()
        self.root = self.owner.root
        config = self.root / "config/memory-pipeline.json"
        config.parent.mkdir()
        config.write_text(json.dumps({"enabled": True, "model": "jev-1.13.0"}))
        self.task = self.root / "workspace/tasks/revision-task"
        self.formal = self.snapshot()

    def snapshot(self):
        base = self.owner.root / "memory/structured"
        return {str(p.relative_to(base)): p.read_bytes() for p in base.rglob("*.jsonl")}

    def request(self, *, operation="state_change", original=None, proposals=None):
        when = "2026-02-01" if operation == "state_change" else "2026-01-01"
        original = original or f"On {when}, my color {'changes to' if operation == 'state_change' else 'was actually'} red."
        self.packet = {"task_id": "revision-task", "role_id": "cards-master",
            "original_user_input": original, "goal": original}
        append_event(self.root, {"event_id": "revision-input", "event_type": "user_input",
            "task_id": "revision-task", "agent": "cards-master", "occurred_at": "2026-02-01T00:00:00+00:00",
            "payload": {"text": original, "is_original_user_input": True}})
        proposal = {"operation": operation, "target_fact_id": "fact_one", "subject_id": "user",
            "subject_label": "user", "predicate": "color", "value": "red", "scope": "role",
            "quote": original, "valid_from": when + "T00:00:00+00:00", "valid_to": None}
        path = self.task / "attempts/1/memory-proposals.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(proposals if proposals is not None else [proposal]))
        return proposal, path

    def finalize(self):
        with patch.object(task_memory, "_graph", side_effect=AssertionError("No graph projection before owner review")):
            return task_memory.finalize(self.root, self.task, self.packet, 1, "revision-input")

    def pending(self):
        return self.owner.review.list_pending(self.owner.principal)

    def test_state_change_is_exact_pending_revision_without_formal_mutation(self):
        self.request()
        result = self.finalize()
        self.assertEqual(result["memory_status"], "screening_queued")
        self.assertEqual(result["screening"]["status"], "queued")
        self.assertEqual(result["write_refs"], [])
        self.assertEqual(result["revision_proposals_received"], 1)
        self.assertEqual(len(result["candidate_refs"]), 1)
        candidate = self.pending()[0]
        self.assertEqual(candidate["status"], "pending_review")
        payload = candidate["payload"]
        self.assertEqual(payload["operation"], "state_change")
        self.assertEqual(payload["target_versions"][0]["fact_id"], "fact_one")
        self.assertEqual(payload["effects"][0]["valid_to"], "2026-02-01T00:00:00+00:00")
        self.assertEqual(payload["effects"][-1]["supersedes"], "fact_one")
        self.assertEqual(set(payload["source_digests"]), {"input-one", "revision-input"})
        self.assertEqual(self.snapshot(), self.formal)
        self.assertEqual(self.owner.store().get_fact("fact_one").value, "blue")

    def test_historical_correction_retains_original_interval_pending_owner(self):
        self.request(operation="historical_correction")
        result = self.finalize()
        self.assertEqual(len(result["candidate_refs"]), 1)
        payload = self.pending()[0]["payload"]
        self.assertEqual(payload["operation"], "historical_correction")
        self.assertEqual(payload["effects"][-1]["revision_of"], "fact_one")
        self.assertEqual(payload["effects"][-1]["valid_from"], "2026-01-01T00:00:00+00:00")
        self.assertIsNone(payload["effects"][-1]["valid_to"])
        self.assertEqual(self.snapshot(), self.formal)

    def test_ordinary_append_and_confirm_cannot_bypass_screening(self):
        proposal, path = self.request()
        items = [{**proposal, "operation": "append"}, {**proposal, "operation": "confirm"}]
        path.write_text(json.dumps(items))
        result = self.finalize()
        self.assertEqual(result["proposals_received"], 2)
        self.assertEqual(result["proposals_deferred_to_screening"], 1)
        self.assertEqual(result["revision_proposals_received"], 0)
        self.assertEqual(result["confirmation_proposals_rejected"], 1)
        self.assertIn('proposal_1_owner_review_required', result['issues'])
        self.assertEqual(result["candidate_refs"], [])
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.snapshot(), self.formal)
        self.assertEqual(len(list((self.root / "state/memory-pipeline/queue").glob("*.json"))), 1)
        queue = json.loads(next((self.root / 'state/memory-pipeline/queue').glob('*.json')).read_text())
        self.assertEqual(queue['event_id'], 'revision-input')

    def test_replay_does_not_duplicate_revision_or_episodic_candidates(self):
        self.request()
        first = self.finalize()
        candidate_path = self.root / "memory/quarantine/cards-master/candidates.jsonl"
        before = candidate_path.read_bytes()
        second = self.finalize()
        self.assertEqual(first["candidate_refs"], second["candidate_refs"])
        self.assertTrue(second["screening"]["replayed"])
        self.assertEqual(candidate_path.read_bytes(), before)
        self.assertEqual(len(self.pending()), 1)
        self.assertFalse(any(e["predicate"] == "episodic_ref" for c in self.pending() for e in c["payload"]["effects"]))

    def test_missing_unknown_or_mismatched_targets_are_not_guessed(self):
        proposal, path = self.request()
        for change in ({"target_fact_id": None}, {"target_fact_id": "missing-fact"}, {"predicate": "different"},
                       {"subject_id": "other"}, {"scope": "invest"}):
            with self.subTest(change=change):
                path.write_text(json.dumps([{**proposal, **change}]))
                result = self.finalize()
                self.assertEqual(result["candidate_refs"], [])
                self.assertEqual(result['revision_proposals_received'], 1)
                self.assertEqual(result['confirmation_proposals_rejected'], 0)
                self.assertTrue(result["issues"])
                self.assertEqual(self.snapshot(), self.formal)
        self.assertEqual(self.pending(), [])

    def test_unconfirmed_target_is_rejected(self):
        unconfirmed = self.owner.fact(fact_id="pending-fact", value="yellow")
        self.owner.review.propose("cards-master", unconfirmed)
        proposal, path = self.request()
        path.write_text(json.dumps([{**proposal, "target_fact_id": "pending-fact"}]))
        result = self.finalize()
        self.assertEqual(result["candidate_refs"], [])
        self.assertTrue(result["issues"])
        self.assertEqual(self.snapshot(), self.formal)

    def test_quote_value_and_date_must_be_supported_by_full_raw(self):
        proposal, path = self.request()
        for change in ({"quote": "A fabricated source says red."}, {"value": "invented"},
                       {"valid_from": "2027-03-09T00:00:00+00:00"}):
            with self.subTest(change=change):
                path.write_text(json.dumps([{**proposal, **change}]))
                result = self.finalize()
                self.assertEqual(result["candidate_refs"], [])
                self.assertTrue(result["issues"])
                self.assertEqual(self.snapshot(), self.formal)

    def test_enqueue_failure_propagates_for_existing_memory_only_repair(self):
        self.request()
        with patch("memory_pipeline.enqueue", side_effect=OSError("synthetic queue failure")):
            with self.assertRaises(OSError):
                self.finalize()
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.snapshot(), self.formal)


if __name__ == "__main__":
    unittest.main(verbosity=2)
