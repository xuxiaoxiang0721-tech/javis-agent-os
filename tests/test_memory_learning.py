"""Synthetic, offline tests of owner-feedback learning lifecycle and limits."""
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from memory_learning import (MemoryLearning, LearningBlocked, LABELS, GUIDANCE,
    validate_profile, screening_context, runtime_profile, profile_by_version)
from javis_memory_adapter.review_policy import digest
from jev_policy import POLICY_DIGEST

MODEL = "jev-1.13.0"


def row(number, label="keep", scope="invest", text=None):
    text = text or f"Synthetic source {number}, owner routing label {label}."
    content = hashlib.sha256(text.encode()).hexdigest()
    source = digest({"event": number, "scope": scope, "text": text})
    return {"feedback_id": f"feedback_{scope}_{number}", "source_event_id": f"event_{scope}_{number}",
        "scope": scope, "source_digest": source, "content_digest": content, "source_text": text,
        "text_path": ["payload", "text"], "label": label, "policy_digest": POLICY_DIGEST,
        "run_id": None, "source_context": {"authorship_verified": False, "fidelity": "unverified_forward",
            "speaker": "third_party", "occurred_at": None, "confirmation_authority": False},
        "source_time": None, "source_event_type": "user_input", "source_completeness": "complete",
        "group_keys": ["source:" + source, "text:" + content, "task:" + digest(number)]}


class Store:
    def __init__(self, rows):
        self.rows = rows
    def training_rows(self):
        return copy.deepcopy(self.rows)


class MemoryLearningTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        from memory_controls import update
        update(self.root, 0, global_enabled=True, command_id='synthetic-enable')
        (self.root / "config").mkdir()
        (self.root / "config/memory-pipeline.json").write_text(json.dumps({"enabled": True, "model": MODEL}))
        self.store = Store([row(label_index * 100 + i, label) for label_index, label in enumerate(LABELS) for i in range(6)])
        self.learning = MemoryLearning(self.root, self.store)
        self.calls = []

    def prepare(self):
        result = self.learning.prepare("invest", MODEL)
        self.assertEqual(result["status"], "prepared")
        return result["version_id"]

    async def fake_screen(self, client, request, *, model):
        self.calls.append(copy.deepcopy(request))
        label = next(r["label"] for r in self.store.rows if r["source_text"] == request["text"])
        decision = "needs_evidence" if label == "keep" and request["learning_profile"] is None else label
        return {"model": model, "provider_called": True, "content": {"decision": "archive_only" if decision == "archive" else decision}, "decisions": {"test": True}}

    async def qualify(self, version):
        with patch("jev_policy.screen_decision", self.fake_screen):
            result = await self.learning.evaluate(version)
        self.assertTrue(result["metrics"]["qualified"])
        return result

    async def test_empty_feedback_is_blocked_and_advance_has_zero_calls(self):
        self.store.rows = []
        self.assertEqual(self.learning.prepare("invest", MODEL)["reason"], "insufficient_independent_feedback")
        with patch("jev_policy.screen_decision", side_effect=AssertionError("must not call")):
            self.assertEqual((await self.learning.advance())["calls_this_tick"], 0)
        self.assertIsNone(runtime_profile(self.root, "invest", MODEL, POLICY_DIGEST))
        self.assertEqual(self.learning.status()["feedback_count"], 0)
        self.assertEqual(self.learning._state()["versions"], [])

    def test_prepare_balanced_groups_bounded_examples_and_idempotence(self):
        version = self.prepare()
        manifest = self.learning._version(version)
        self.assertEqual(len(manifest["train"]), 9)
        self.assertEqual(len(manifest["holdout"]), 9)
        self.assertEqual(len(manifest["profile"]["examples"]), 6)
        self.assertEqual({r["group_id"] for r in manifest["train"]} & {r["group_id"] for r in manifest["holdout"]}, set())
        self.assertEqual(self.learning.prepare("invest", MODEL)["version_id"], version)
        self.assertEqual(len(self.learning._state()["assignments"]), 18)
        self.assertNotIn("Synthetic source", json.dumps(self.learning.status()))

    def test_task_linked_feedback_does_not_count_as_independent(self):
        shared = "thread:" + digest("one shared conversation")
        for item in self.store.rows:
            item["group_keys"].append(shared)
        self.assertEqual(self.learning.prepare("invest", MODEL)["status"], "blocked")

    def test_same_text_across_roles_is_grouped_without_cross_role_examples(self):
        extra = row(999, "keep", "operations", self.store.rows[0]["source_text"])
        self.store.rows.append(extra)
        manifest = self.learning._version(self.prepare())
        allowed = {item["source_text"] for item in self.store.rows if item["scope"] == "invest"}
        self.assertTrue(all(e["text"] in allowed for e in manifest["profile"]["examples"]))
        self.assertTrue(any(len(g["rows"]) == 2 for g in self.learning._groups(self.store.rows)))

    def test_prior_holdout_never_becomes_training_or_reused_evaluation(self):
        original = self.learning._version(self.prepare())
        self.store.rows.extend(row(1000 + i + j * 100, label) for j, label in enumerate(LABELS) for i in range(3))
        later = self.learning._version(self.prepare())
        old_test = {ref["feedback_id"] for ref in original["holdout"]}
        new_ids = {ref["feedback_id"] for ref in later["train"] + later["holdout"]}
        self.assertFalse(old_test & new_ids)
        self.assertFalse({ref["feedback_id"] for ref in original["train"]} & {ref["feedback_id"] for ref in later["holdout"]})

    def test_long_examples_are_not_truncated_or_fabricated(self):
        self.store.rows = [row(i + j * 100, label, text=f"{i}-{label}" + "中" * 500) for j, label in enumerate(LABELS) for i in range(6)]
        self.assertEqual(self.learning.prepare("invest", MODEL)["status"], "blocked")

    def test_profile_has_only_original_provenance_and_no_authority(self):
        profile = self.learning._version(self.prepare())["profile"]
        context = screening_context(profile)
        self.assertEqual(context["instruction"], GUIDANCE)
        self.assertTrue(all(e["source_context"]["authorship_verified"] is False for e in context["examples"]))
        self.assertTrue(all(e["source_context"]["confirmation_authority"] is False for e in context["examples"]))
        self.assertIsNone(screening_context(None))
        with self.assertRaises(LearningBlocked):
            validate_profile(profile, "content", MODEL, POLICY_DIGEST)
        tampered = copy.deepcopy(profile)
        tampered["examples"][0]["text"] = "changed"
        with self.assertRaises(LearningBlocked):
            validate_profile(tampered, "invest", MODEL, POLICY_DIGEST)

    async def test_comparison_qualifies_but_does_not_activate_until_called(self):
        version = self.prepare()
        result = await self.qualify(version)
        self.assertEqual(result["calls_this_tick"], 18)
        self.assertFalse(self.learning._state()["active"])
        self.learning.activate(version)
        self.assertEqual(self.learning._profile_by_version(version, "invest", MODEL, POLICY_DIGEST)["version_id"], version)
        self.assertEqual(self.learning.status()["versions"][0]["status"], "active")
        self.assertTrue(all(r["source_context"]["authorship_verified"] is False for r in self.calls))
        self.assertTrue(all(r["source_time"] is None and r["event_type"] == "user_input" for r in self.calls))

    async def test_explicit_fake_client_evaluation_cannot_be_activated(self):
        version = self.prepare()
        with patch("jev_policy.screen_decision", self.fake_screen):
            result = await self.learning.evaluate(version, model_client=object())
        self.assertTrue(result["metrics"]["qualified"])
        with self.assertRaisesRegex(LearningBlocked, "learning_version_not_qualified"):
            self.learning.activate(version)

    async def test_quality_gates_reject_no_improvement_and_false_accept(self):
        version = self.prepare()
        async def unsafe(client, request, *, model):
            return {"model": model, "provider_called": True, "content": {"decision": "keep"}, "decisions": {}}
        with patch("jev_policy.screen_decision", unsafe):
            result = await self.learning.evaluate(version)
        self.assertFalse(result["metrics"]["qualified"])
        self.assertGreater(result["metrics"]["profile"]["false_accepts"], 0)
        with self.assertRaises(LearningBlocked):
            self.learning.activate(version)

    async def test_evaluation_checkpoint_resumes_only_unstarted_calls(self):
        version = self.prepare()
        with patch("jev_policy.screen_decision", self.fake_screen):
            first = await self.learning.evaluate(version, max_calls=4)
            self.assertEqual(first["status"], "evaluating")
            self.assertEqual(first["calls_this_tick"], 4)
            second = await self.learning.evaluate(version)
            replay = await self.learning.evaluate(version)
        self.assertEqual(second["calls_this_tick"], 14)
        self.assertEqual(replay["calls_this_tick"], 0)
        self.assertEqual(len(self.calls), 18)

    async def test_failed_attempt_not_retried_automatically_and_explicit_retry_bounded(self):
        version = self.prepare()
        async def failing(*args, **kwargs):
            raise ValueError("secret must not be stored")
        with patch("jev_policy.screen_decision", failing):
            await self.learning.evaluate(version, max_calls=1)
        with patch("jev_policy.screen_decision", self.fake_screen):
            result = await self.learning.evaluate(version)
            self.assertEqual(result["calls_this_tick"], 17)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual((await self.learning.evaluate(version))["calls_this_tick"], 0)
            self.assertEqual((await self.learning.evaluate(version, retry_failed=True))["calls_this_tick"], 1)
        ledger = (self.learning.base / "evaluations" / (version + ".json")).read_text()
        self.assertNotIn("secret must", ledger)

    async def test_advance_four_call_ticks_activate_once_and_then_zero_cost(self):
        with patch("jev_policy.screen_decision", self.fake_screen):
            results = [await self.learning.advance() for _ in range(5)]
            extra = await self.learning.advance()
        self.assertEqual([r["calls_this_tick"] for r in results], [4, 4, 4, 4, 2])
        self.assertEqual(results[-1]["status"], "active")
        self.assertEqual(extra["calls_this_tick"], 0)
        self.assertEqual(len(self.calls), 18)

    async def test_advance_failed_version_does_not_retest_holdout(self):
        async def no_improvement(client, request, *, model):
            return {"model": model, "provider_called": True, "content": {"decision": "needs_evidence"}, "decisions": {}}
        with patch("jev_policy.screen_decision", no_improvement):
            for _ in range(5):
                await self.learning.advance()
            self.assertEqual((await self.learning.advance())["calls_this_tick"], 0)
        self.assertFalse(self.learning._state()["active"])

    async def test_owner_label_correction_invalidates_active_profile(self):
        version = self.prepare()
        await self.qualify(version)
        self.learning.activate(version)
        feedback = self.learning._version(version)["train"][0]["feedback_id"]
        next(r for r in self.store.rows if r["feedback_id"] == feedback)["label"] = "archive"
        with self.assertRaisesRegex(LearningBlocked, "learning_feedback_or_source_changed"):
            self.learning._profile_by_version(version, "invest", MODEL, POLICY_DIGEST)

    async def test_invalid_active_is_explicitly_revoked_by_advance_without_http(self):
        version = self.prepare()
        await self.qualify(version)
        self.learning.activate(version)
        feedback = self.learning._version(version)["train"][0]["feedback_id"]
        self.store.rows = [r for r in self.store.rows if r["feedback_id"] != feedback]
        self.assertEqual(self.learning.status()["status"], "invalid_active")
        with patch("jev_policy.screen_decision", side_effect=AssertionError("no API")):
            result = await self.learning.advance()
        self.assertEqual(result["status"], "reverted")
        self.assertEqual(result["calls_this_tick"], 0)
        self.assertFalse(self.learning._state()["active"])
        self.assertEqual(self.learning._state()["history"][-1]["action"], "deactivate")
        self.assertTrue((self.learning.base / "versions" / (version + ".json")).exists())

    async def test_baseline_only_feedback_withdrawal_stops_next_paid_call(self):
        first = self.prepare()
        await self.qualify(first)
        self.learning.activate(first)
        self.store.rows.extend(row(1000 + i + j * 100, label) for j, label in enumerate(LABELS) for i in range(3))
        second = self.prepare()
        base = self.learning._version(first)
        candidate = self.learning._version(second)
        target = next(ref["feedback_id"] for ref in base["holdout"] if ref["feedback_id"] not in {r["feedback_id"] for r in candidate["train"] + candidate["holdout"]})
        calls = []
        async def retract(client, request, *, model):
            calls.append(request)
            self.store.rows = [r for r in self.store.rows if r["feedback_id"] != target]
            return {"model": model, "provider_called": True, "content": {"decision": "needs_evidence"}, "decisions": {}}
        with patch("jev_policy.screen_decision", retract):
            with self.assertRaisesRegex(LearningBlocked, "learning_feedback_or_source_changed"):
                await self.learning.evaluate(second)
        self.assertEqual(len(calls), 1)

    def test_write_syncs_directory_chain_after_atomic_file_write(self):
        import stat
        import os
        synced = []
        real = os.fsync
        def sync(fd):
            synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
            real(fd)
        with patch("memory_learning.os.fsync", sync):
            self.prepare()
        self.assertIn(True, synced)
        self.assertIn(False, synced)

    def test_new_group_bridge_invalidates_original_split(self):
        version = self.learning._version(self.prepare())
        bridge = row(9999, "keep")
        bridge["group_keys"].extend([version["train"][0]["group_keys"][0], version["holdout"][0]["group_keys"][0]])
        self.store.rows.append(bridge)
        with self.assertRaisesRegex(LearningBlocked, "learning_group_leakage_detected"):
            self.learning._fresh_rows(version)

    async def test_active_baseline_is_pinned_and_activation_compares_and_swaps(self):
        first = self.prepare()
        await self.qualify(first)
        self.learning.activate(first)
        self.store.rows.extend(row(1000 + i + j * 100, label) for j, label in enumerate(LABELS) for i in range(3))
        second = self.prepare()
        manifest = self.learning._version(second)
        self.assertEqual(manifest["baseline_version"], first)
        async def better(client, request, *, model):
            label = next(r["label"] for r in self.store.rows if r["source_text"] == request["text"])
            is_base = request["learning_profile"]["version_id"] == first
            decision = "needs_evidence" if is_base and label == "keep" else label
            return {"model": model, "provider_called": True, "content": {"decision": "archive_only" if decision == "archive" else decision}, "decisions": {}}
        with patch("jev_policy.screen_decision", better):
            self.assertTrue((await self.learning.evaluate(second))["metrics"]["qualified"])
        self.learning.rollback("invest", "baseline")
        with self.assertRaisesRegex(LearningBlocked, "learning_baseline_changed"):
            self.learning.activate(second)

    async def test_rollback_keeps_old_pinned_profile_and_baseline_none(self):
        version = self.prepare()
        await self.qualify(version)
        self.learning.activate(version)
        self.learning.rollback("invest", "baseline")
        self.assertEqual(self.learning._profile_by_version(version, "invest", MODEL, POLICY_DIGEST)["version_id"], version)
        self.assertIsNone(profile_by_version(self.root, None, "invest", MODEL, POLICY_DIGEST))
        self.assertIsNone(profile_by_version(self.root, "baseline", "invest", MODEL, POLICY_DIGEST))
        self.assertEqual(self.learning.rollback("invest", version)["version_id"], version)

    async def test_hold_blocks_prepare_evaluate_activate_and_advance(self):
        version = self.prepare()
        (self.root / "state/recovery-hold.json").write_text('{"hold":true}')
        with self.assertRaises(Exception):
            self.learning.prepare("invest", MODEL)
        with patch("jev_policy.screen_decision", side_effect=AssertionError("must not call")):
            with self.assertRaises(Exception):
                await self.learning.evaluate(version)
            with self.assertRaises(Exception):
                await self.learning.advance()
        with self.assertRaises(Exception):
            self.learning.activate(version)

    def test_unregistered_or_tampered_manifest_is_rejected(self):
        version = self.prepare()
        path = self.learning.base / "versions" / (version + ".json")
        content = json.loads(path.read_text())
        content["model"] = "jev-0.0.0"
        path.write_text(json.dumps(content))
        with self.assertRaisesRegex(LearningBlocked, "learning_record_integrity_failed"):
            self.learning._version(version)
        with self.assertRaisesRegex(LearningBlocked, "learning_unregistered_version"):
            self.learning._version("never_registered")


if __name__ == "__main__":
    unittest.main()
