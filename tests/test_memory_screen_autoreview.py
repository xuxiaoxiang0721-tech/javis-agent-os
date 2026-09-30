"""Offline typed-policy -> source-bound AI decision integration, no provider I/O."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE / "scripts"), str(CODE / "tests")]
import memory_screen as ms
from memory_autoreview import MemoryAutoreview, LOG
from memory_review import MemoryReview
from raw_storage import append_event
from javis_memory_adapter.review_policy import digest, read_rows, ReviewBlocked
from test_jev_policy import FakeClient, choice

TEXT = "Alice prefers short weekly reports for Project Cedar."


class Graph:
    def __init__(self, count=1):
        self.calls = []
        self.count = count

    async def extract(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        return {"episode_uuid": "synthetic-episode", "model": "synthetic-graph",
                "facts": [{"graph_edge_id": "edge-%d" % i, "subject_id": "alice",
                    "subject_label": "Alice", "predicate": "PREFERS", "value": TEXT,
                    "object_label": "short weekly reports", "valid_from": None, "valid_to": None}
                    for i in range(self.count)]}


class ScreenAutoreviewTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="javis-ai-screen-test-")
        self.root = Path(self.tmp.name)
        self.client = FakeClient()
        self.graph = Graph()
        append_event(self.root, {"event_id": "synthetic-source", "event_type": "model_output",
            "agent": "invest", "completeness": "complete", "occurred_at": None,
            "payload": {"text": TEXT, "speaker": "assistant"}})
        self.source_digest = ms.source_digest(ms.load_source(self.root, "synthetic-source"))
        self.service = MemoryAutoreview(self.root)
        self.service.control("resume", 0, "synthetic-enable")

    def tearDown(self):
        self.tmp.cleanup()

    async def run_screen(self, **extra):
        args = {"event_id": "synthetic-source", "scope": "invest", "text": TEXT,
                "source_digest": self.source_digest, "model": "jev-1.13.0",
                "model_client": self.client, "graph_client": self.graph,
                "env_path": self.root / "no-env"}
        args.update(extra)
        return await ms.screen(self.root, **args)

    def decisions(self):
        return read_rows(self.root, self.root / LOG)

    def current_run(self):
        return read_rows(self.root, self.root / "memory/screen/runs.jsonl")[-1]

    def formal(self, result):
        return self.service.review._store("invest").get_fact(result["autoreview"]["accepted"][0]["fact_id"])

    def alias_source(self):
        from javis_memory_adapter.entity_registry import register_alias
        text = 'Project Cedar also known as Alice.'
        append_event(self.root, {'event_id':'alias-source','event_type':'model_output','agent':'invest',
            'payload':{'text':text,'speaker':'assistant'}}, relative_path='events/alias.jsonl')
        register_alias(self.root, 'invest', canonical_name='Cedar', alias='Alice',
            source_event_id='alias-source', text=text, evidence=text)

    def change_alias(self):
        path = self.root/'raw/events/alias.jsonl'
        row = json.loads(path.read_text()); row['payload']['text'] = 'Cedar and Alice are unrelated.'
        path.write_text(json.dumps(row)+'\n')

    async def test_alias_dependency_is_pinned_in_candidate_receipt_and_recalled_fact(self):
        from javis_memory_adapter.ledger_query import query_semantic_memory
        self.alias_source()
        first = await self.run_screen()
        self.assertEqual(first['status'], 'complete', first)
        refs = ['alias-source', 'synthetic-source']
        self.assertEqual(first['candidates'][0]['raw_refs'], refs)
        self.assertEqual(self.formal(first).raw_refs, refs)
        self.assertEqual(set(self.decisions()[0]['source_digests']), set(refs))
        self.change_alias()
        self.assertEqual(query_semantic_memory(self.service.review._store('invest'))['facts'], [])
        again = await self.run_screen()
        self.assertEqual(again['status'], 'retry')
        self.assertEqual(again['error_code'], 'entity_dependency_source_changed')
        self.assertEqual(len(self.client.calls), 2)
        self.assertEqual(len(self.graph.calls), 1)

    async def test_alias_change_after_normalization_cannot_create_new_candidate(self):
        import javis_memory_adapter.normalization as normalization
        self.alias_source(); original = normalization.normalize_verified_fact
        def mutate_after(*args, **kwargs):
            result = original(*args, **kwargs)
            self.change_alias()
            return result
        with patch.object(normalization, 'normalize_verified_fact', side_effect=mutate_after):
            result = await self.run_screen()
        self.assertEqual(result['status'], 'retry', result)
        self.assertEqual(result['error_code'], 'entity_dependency_source_changed')
        self.assertEqual(self.decisions(), [])
        self.assertFalse((self.root/'memory/quarantine/invest/candidates.jsonl').exists())

    async def test_supported_typed_fact_is_ai_reviewed_with_exact_evidence_and_idempotent_replay(self):
        raw = next((self.root / "raw/events").glob("*.jsonl"))
        before_raw = raw.read_bytes()
        first = await self.run_screen()
        self.assertEqual(first["status"], "complete", first)
        self.assertEqual(first["autoreview"]["accepted_count"], 1, first)
        decision = self.decisions()[0]
        self.assertEqual(decision["run_id"], first["run_id"])
        self.assertEqual(decision["source_excerpt"], TEXT)
        self.assertEqual(decision["content_digest"], first["content_digest"])
        self.assertEqual(decision["reviewer_type"], "ai")
        self.assertFalse(decision["human_confirmed"])
        self.assertEqual(self.formal(first).status, "ai_reviewed")
        self.assertIsNone(self.formal(first).confirmation_event_id)
        self.assertEqual(self.formal(first).ai_review_event_id, decision["review_event_id"])
        before_runs = (self.root / "memory/screen/runs.jsonl").read_bytes()
        again = await self.run_screen()
        self.assertEqual(first, again)
        self.assertEqual(before_runs, (self.root / "memory/screen/runs.jsonl").read_bytes())
        self.assertEqual(len(self.client.calls), 2)
        self.assertEqual(len(self.graph.calls), 1)
        self.assertEqual(len(self.decisions()), 1)
        self.assertEqual(before_raw, raw.read_bytes())
        self.assertFalse((self.root / "state/owner").exists())

    async def test_unknown_time_and_unverified_attribution_are_not_promoted(self):
        result = await self.run_screen()
        fact = self.formal(result)
        self.assertIsNone(fact.valid_from)
        self.assertIsNone(fact.valid_to)
        self.assertIn("validity_unknown_not_current", fact.notes)
        self.assertIn("authorship:unverified", fact.notes)
        self.assertIn("statement_kind:third_party", fact.notes)
        self.assertNotIn("statement_kind:user_explicit", fact.notes)
        self.assertIsNone(result["source_context"]["occurred_at"])

    async def test_post_verification_review_is_not_auto_accepted(self):
        def mutate(response, questions):
            for key in response["answers"]:
                if key.endswith("verdict"):
                    response["answers"][key] = choice(questions[key], "supports", confidence=.70)
        self.client.mutate = mutate
        result = await self.run_screen()
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["candidates"], [])
        self.assertTrue(result["review_refs"])
        self.assertEqual(self.decisions(), [])

    async def test_post_verification_rejection_is_not_auto_accepted(self):
        def mutate(response, questions):
            for key in response["answers"]:
                if key.endswith("verdict"):
                    response["answers"][key] = choice(questions[key], "contradicts")
        self.client.mutate = mutate
        result = await self.run_screen()
        self.assertEqual(result["candidates"], [])
        self.assertEqual(self.decisions(), [])
        self.assertFalse((self.root / "memory/structured").exists())

    async def test_invalid_paid_post_response_never_auto_accepts_or_repeats_provider(self):
        def mutate(response, questions):
            for key, answer in response["answers"].items():
                if key.startswith("f") and key.endswith("statement_kind"):
                    answer["probabilities"][answer["choice"]] -= .01
        self.client.mutate = mutate
        first = await self.run_screen()
        self.assertEqual(first["status"], "needs_review", first)
        self.assertIn("policy_validation_failure", first)
        self.assertEqual(await self.run_screen(), first)
        self.assertEqual(len(self.client.calls), 2)
        self.assertEqual(self.decisions(), [])

    async def test_keep_and_verified_list_without_accepted_disposition_is_insufficient(self):
        original = ms.verify_facts
        async def missing_decision(*args, **kwargs):
            result = await original(*args, **kwargs)
            result["decisions"]["facts"] = []
            return result
        with patch("memory_screen.verify_facts", side_effect=missing_decision):
            result = await self.run_screen()
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["autoreview"]["accepted_count"], 0)
        self.assertEqual(self.decisions(), [])

    async def test_local_projection_failure_recovers_without_any_new_paid_stage(self):
        original = MemoryAutoreview._materialize
        failures = []
        def fail_once(instance, row):
            if not failures:
                failures.append(True)
                raise OSError("synthetic-private-error-do-not-log")
            return original(instance, row)
        with patch.object(MemoryAutoreview, "_materialize", fail_once):
            first = await self.run_screen()
            self.assertEqual(first["status"], "retry", first)
            self.assertEqual(first["stage"], "autoreview")
            self.assertEqual(len(self.decisions()), 1)
            second = await self.run_screen()
        self.assertEqual(second["status"], "complete", second)
        self.assertEqual(second["autoreview"]["accepted_count"], 1)
        self.assertEqual(len(self.client.calls), 2)
        self.assertEqual(len(self.graph.calls), 1)
        self.assertEqual(len(self.decisions()), 1)
        self.assertNotIn("synthetic-private-error", (self.root / "memory/screen/runs.jsonl").read_text())

    async def test_pause_keeps_proposal_and_later_resume_reuses_same_provider_run(self):
        evaluate = self.client.evaluate
        async def pause_after_paid_verification(*args, **kwargs):
            result = await evaluate(*args, **kwargs)
            if kwargs.get('stage') == 'verification':
                self.service.control('pause', 1, 'synthetic-pause')
            return result
        with patch.object(self.client, 'evaluate', side_effect=pause_after_paid_verification):
            first = await self.run_screen()
        self.assertEqual(first["status"], "held")
        self.assertEqual(first["autoreview"]["status"], "paused")
        self.assertEqual(first["autoreview"]["accepted_count"], 0)
        self.assertEqual(len(first["candidates"]), 1)
        self.assertEqual(self.decisions(), [])
        self.service.control("resume", 2, "synthetic-resume")
        second = await self.run_screen()
        self.assertEqual(second["run_id"], first["run_id"])
        self.assertEqual(second["autoreview"]["accepted_count"], 1)
        self.assertEqual(len(self.client.calls), 2)
        self.assertEqual(len(self.graph.calls), 1)

    async def test_no_controls_configuration_stops_processing_without_losing_raw(self):
        (self.root / "state/memory-controls/control.json").unlink()
        before = {str(p):p.read_bytes() for p in (self.root/'raw').rglob('*.jsonl')}
        result = await self.run_screen()
        self.assertEqual(result['status'], 'held')
        self.assertEqual(result['hold_reason'], 'global_paused')
        self.assertEqual(self.client.calls, [])
        self.assertEqual(self.graph.calls, [])
        self.assertEqual(before, {str(p):p.read_bytes() for p in (self.root/'raw').rglob('*.jsonl')})

    async def test_pause_does_not_make_an_existing_acceptance_disappear(self):
        first = await self.run_screen()
        self.service.control("pause", 1, "synthetic-later-pause")
        with patch.object(MemoryAutoreview, "review_candidate", side_effect=AssertionError("paused")):
            second = await self.run_screen()
        self.assertEqual(second['status'], 'held', second)
        self.assertEqual(len(self.service.active()), 1)
        from javis_memory_adapter.ledger_query import query_semantic_memory
        recalled = query_semantic_memory(self.service.review._store('invest'))
        self.assertEqual([row['fact_id'] for row in recalled['facts']], [self.formal(first).fact_id])
        self.assertEqual(len(self.client.calls), 2)

    async def test_withdrawal_is_not_reaccepted_by_cached_screen_replay(self):
        first = await self.run_screen()
        row = self.decisions()[0]
        self.service.withdraw(row["review_event_id"], digest(row), "synthetic-withdraw")
        second = await self.run_screen()
        self.assertEqual(second["status"], "complete", second)
        self.assertEqual(second["autoreview"]["accepted_count"], 0)
        self.assertEqual(second["autoreview"]["withdrawn_count"], 1)
        self.assertEqual(len(self.decisions()), 2)
        self.assertEqual(len(self.client.calls), 2)
        self.assertEqual(len(self.graph.calls), 1)

    async def test_changed_raw_blocks_cached_automatic_review(self):
        await self.run_screen()
        before = (self.root / LOG).read_bytes()
        path = next((self.root / "raw/events").glob("*.jsonl"))
        source = ms.load_source(self.root, "synthetic-source")
        source["payload"]["text"] = "Alice does not prefer short reports."
        path.write_text(json.dumps(source)+"\n")
        with self.assertRaisesRegex(ReviewBlocked, "source_digest_mismatch"):
            await self.run_screen()
        self.assertEqual(before, (self.root / LOG).read_bytes())
        self.assertEqual(len(self.client.calls), 2)

    async def test_cross_scope_cannot_reuse_a_source_for_auto_acceptance(self):
        with self.assertRaisesRegex(ReviewBlocked, "source_scope_mismatch"):
            await self.run_screen(scope="cards-master")
        self.assertEqual(self.client.calls, [])
        self.assertEqual(self.decisions(), [])

    async def test_mixed_supported_and_uncertain_edges_only_accepts_supported_one(self):
        self.graph.count = 2
        def mutate(response, questions):
            for key in response["answers"]:
                if key == "f0001_verdict":
                    response["answers"][key] = choice(questions[key], "supports", confidence=.60)
        self.client.mutate = mutate
        result = await self.run_screen()
        self.assertEqual(result["status"], "needs_review", result)
        self.assertEqual(result["autoreview"]["accepted_count"], 1)
        self.assertEqual(len(result["review_refs"]), 1)
        self.assertEqual(len(self.decisions()), 1)
        self.assertIn("graph_edge:edge-0", self.decisions()[0]["effect"]["notes"])
        self.assertNotIn("graph_edge:edge-1", self.decisions()[0]["effect"]["notes"])


if __name__ == "__main__":
    unittest.main()
