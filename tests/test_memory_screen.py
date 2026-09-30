"""Synthetic protocol tests: no real user input, cloud requests or graph writes."""
import asyncio
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from memory_screen import screen, load_source, source_digest, ReviewBlocked, GraphitiCandidateClient, _temporal_context
from raw_storage import append_event
from memory_triage import list_pending, get_pending
from jev_client import JevClient
from javis_memory_adapter.usage_meter import recent as usage_recent

TEXT = "From 2026-01-01, the synthetic Invest weekly report is due on Friday."
DATE = "2026-01-01T00:00:00+00:00"


class Model:
    def __init__(self, decision="keep"):
        self.calls = []
        self.decision = decision
        self.fail = False
        self.bad_evidence = False
        self.empty_verification = False

    async def complete(self, messages, *, model):
        self.calls.append(copy.deepcopy(messages))
        if self.fail:
            raise RuntimeError("synthetic password=DO_NOT_LOG_THIS")
        if "screen durable" in messages[0]["content"]:
            content = {"decision": self.decision, "category": "rule", "statement_kind": "user_explicit",
                "reason": "Synthetic explicit report schedule", "evidence": [TEXT]}
        else:
            content = {"facts": [] if self.empty_verification else [{"graph_edge_id": "edge-one",
                "evidence": "not present in RAW" if self.bad_evidence else TEXT,
                "category": "rule", "statement_kind": "user_explicit", "supported": True}]}
        return {"model": "synthetic-model-20260101", "content": content}


class Graph:
    def __init__(self):
        self.calls = []
        self.fail = False
        self.unknown_time = False

    async def extract(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("synthetic secret=DO_NOT_LOG_THIS")
        return {"episode_uuid": "episode-one", "model": "synthetic-graph-model",
            "facts": [{"graph_edge_id": "edge-one", "subject_id": "node-one", "subject_label": "Invest report",
                "predicate": "DUE_ON", "value": TEXT, "valid_from": None if self.unknown_time else DATE,
            "valid_to": None, "object_label": "Friday"}]}


class TypedHTTP:
    """Exercise the real HTTP client with complete synthetic typed responses."""
    def __init__(self, invalid_call):
        self.invalid_call = invalid_call
        self.calls = []

    def open(self, request, *, timeout):
        from test_jev_policy import good_response
        wire = json.loads(request.data)
        self.calls.append(wire)
        response = good_response(wire["questions"], wire["model"])
        if len(self.calls) == self.invalid_call:
            name = next(name for name in response["answers"] if name.endswith("statement_kind"))
            answer = response["answers"][name]
            answer["probabilities"][answer["choice"]] -= 0.01
            response["private_debug"] = "DO_NOT_LOG_PROVIDER_BODY"
        stream = io.BytesIO(json.dumps(response).encode())
        stream.status = 200
        stream.headers = {"x-typesafe-request-id": "synthetic-paid-request-%d" % len(self.calls)}
        return stream


class ScreenTests(unittest.IsolatedAsyncioTestCase):
    def test_nested_message_does_not_inherit_container_occurrence_time(self):
        result = _temporal_context({'occurred_at': DATE, 'captured_at': '2026-09-25T12:00:00Z'},
            {'occurred_at': None}, '2026-09-26T00:00:00Z')
        self.assertEqual(result['reference_basis'], 'captured_at')
        self.assertIsNone(result['source_time'])

    def test_no_source_or_capture_clock_uses_frozen_run_reference_only(self):
        result = _temporal_context({}, {'occurred_at': None}, '2026-09-26T00:00:00Z')
        self.assertEqual(result, {'source_time': None, 'reference_time': '2026-09-26T00:00:00Z', 'reference_basis': 'run_created_at'})

    def test_source_time_contract_preserves_nanoseconds_and_rejects_naive_source(self):
        stamp = '2026-09-24T09:00:00.123456789Z'
        self.assertEqual(_temporal_context({}, {'occurred_at': stamp}, DATE)['source_time'], stamp)
        for invalid in ('2026-09-24T09:00:00', '2026-09-24T09:00:00-00:00'):
            result = _temporal_context({'captured_at': DATE}, {'occurred_at': invalid}, DATE)
            self.assertIsNone(result['source_time'])
            self.assertEqual(result['reference_basis'], 'captured_at')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="javis-screen-test-")
        self.root = Path(self.tmp.name)
        from memory_controls import update
        update(self.root, 0, global_enabled=True, command_id='synthetic-enable')
        self.model = Model()
        self.graph = Graph()
        self.event = {"event_id": "synthetic-event", "event_type": "user_input", "agent": "invest",
            "occurred_at": DATE, "completeness": "complete", "payload": {"text": TEXT, "is_original_user_input": True}}
        self.source()

    def tearDown(self):
        self.tmp.cleanup()

    def source(self):
        append_event(self.root, self.event)
        self.digest = source_digest(load_source(self.root, self.event["event_id"]))

    async def run_screen(self, **kwargs):
        request = {"event_id": "synthetic-event", "scope": "invest", "text": TEXT,
            "source_digest": self.digest, "model_client": self.model, "graph_client": self.graph,
            "model": "synthetic-model-20260101"}
        request.update(kwargs)
        return await screen(self.root, **request)

    def runs(self):
        path = self.root / "memory/screen/runs.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    async def test_real_raw_required_and_whole_text_bound(self):
        for change in ({"event_id": "missing"}, {"source_digest": "0" * 64}, {"text": "Friday"}):
            with self.subTest(change=change), self.assertRaises(ReviewBlocked):
                await self.run_screen(**change)
        self.assertEqual(self.model.calls, [])
        self.assertEqual(self.graph.calls, [])

    async def test_keep_quarantines_and_replay_is_idempotent(self):
        first = await self.run_screen()
        second = await self.run_screen()
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "complete")
        self.assertEqual(first["actual_model"], "synthetic-model-20260101")
        self.assertEqual(first["outcome"], "pending_review")
        self.assertEqual(first["candidates"][0]["status"], "pending_review")
        self.assertEqual(len(self.model.calls), 2)
        self.assertEqual(len(self.graph.calls), 1)
        self.assertTrue(self.graph.calls[0]["group_id"].startswith("javis-screen-"))
        self.assertFalse((self.root / "memory/structured").exists())
        self.assertEqual(len((self.root / "memory/quarantine/invest/candidates.jsonl").read_text().splitlines()), 1)
        self.assertEqual(load_source(self.root, "synthetic-event")["payload"]["text"], TEXT)

    async def test_completed_review_replay_checks_integrity_without_rebuilding_supersession_index(self):
        self.model.decision = "needs_evidence"
        first = await self.run_screen()
        calls = len(self.model.calls)
        with patch("memory_triage._supersessions", side_effect=AssertionError("No repeated run index")), \
                patch("memory_screen.get_pending", wraps=get_pending) as get:
            self.assertEqual(await self.run_screen(), first)
        self.assertEqual(len(self.model.calls), calls)
        self.assertTrue(all(call.kwargs == {"check_supersession": False} for call in get.call_args_list))
        self.assertEqual(get.call_count, len(first["review_refs"]))
        path = self.root / "memory/triage/items" / (first["review_refs"][0] + ".json")
        path.write_text("{")
        with self.assertRaises(ValueError):await self.run_screen()
        self.assertEqual(len(self.model.calls), calls)

    async def test_new_prompt_or_model_creates_distinct_replayable_run(self):
        first = await self.run_screen()
        other_prompt = await self.run_screen(prompt_version="jev-screen-v2")
        other_model = await self.run_screen(model="synthetic-model-20260202")
        self.assertEqual(len({r["run_id"] for r in (first, other_prompt, other_model)}), 3)
        self.assertEqual(len({r["group_id"] for r in (first, other_prompt, other_model)}), 3)

    async def test_non_keep_never_calls_graph_or_erases_raw(self):
        for decision in ("archive_only", "needs_evidence", "conflict"):
            self.model.decision = decision
            result = await self.run_screen(prompt_version="test-" + decision)
            self.assertEqual(result["screening"]["decision"], decision)
            self.assertEqual(result["status"], "complete" if decision == "archive_only" else "needs_review")
            self.assertEqual(result["candidates"], [])
            self.assertEqual(result.get("review_count", 0), 0 if decision == "archive_only" else 1)
        self.assertEqual(self.graph.calls, [])
        self.assertEqual(load_source(self.root, "synthetic-event")["payload"]["text"], TEXT)

    async def test_graph_failure_retries_from_persisted_screening(self):
        self.graph.fail = True
        first = await self.run_screen()
        self.assertEqual(first["status"], "retry")
        self.assertEqual(first["stage"], "graphiti")
        self.assertNotIn("DO_NOT_LOG_THIS", (self.root / "memory/screen/runs.jsonl").read_text())
        self.graph.fail = False
        result = await self.run_screen()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(len(self.model.calls), 2)
        self.assertEqual(self.graph.calls[0]["group_id"], self.graph.calls[1]["group_id"])

    async def test_model_failure_is_retry_and_does_not_log_exception_text(self):
        self.model.fail = True
        result = await self.run_screen()
        self.assertEqual(result["status"], "retry")
        self.assertNotIn("screening", result)
        self.assertEqual(self.graph.calls, [])
        self.assertNotIn("DO_NOT_LOG_THIS", (self.root / "memory/screen/runs.jsonl").read_text())

    async def test_invalid_verification_cannot_propose(self):
        self.model.bad_evidence = True
        result = await self.run_screen()
        self.assertEqual(result["status"], "retry")
        self.assertFalse((self.root / "memory/quarantine").exists())
        self.model.bad_evidence = False
        result = await self.run_screen()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(self.graph.calls), 1)

    async def test_unknown_time_does_not_invent_current_fact(self):
        self.graph.unknown_time = True
        result = await self.run_screen()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["outcome"], "pending_review")
        self.assertEqual(len(result["candidates"]), 1)
        self.assertIsNone(result['verified'][0]['edge']['valid_from'])
        self.assertFalse((self.root / 'memory/structured').exists())

    async def test_unsupported_graph_facts_remain_quarantined(self):
        self.model.empty_verification = True
        result = await self.run_screen()
        self.assertEqual(result["outcome"], "needs_evidence")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["review_count"], 1)
        self.assertFalse((self.root / "memory/structured").exists())

    async def test_private_or_redacted_events_never_leave_local_storage(self):
        path = next((self.root / "raw/events").glob("*.jsonl"))
        original = load_source(self.root, "synthetic-event")
        for privacy in ({"privacy_level": "L4"}, {"classification": "strict L4"}, {"token": "test-secret"},
                        {"note": "[REDACTED:CREDENTIAL]"}):
            row = copy.deepcopy(original)
            row.update(privacy)
            path.write_text(json.dumps(row) + "\n")
            with self.subTest(privacy=list(privacy)), self.assertRaises(ReviewBlocked):
                await self.run_screen(source_digest=source_digest(row))
        self.assertEqual(self.model.calls, [])
        self.assertEqual(self.graph.calls, [])

    async def test_forbidden_shared_unknown_or_other_role(self):
        for scope in ("shared", "unknown", "../invest", "cards-master"):
            with self.subTest(scope=scope), self.assertRaises(ReviewBlocked):
                await self.run_screen(scope=scope)
        self.assertEqual(self.model.calls, [])

    async def test_changed_raw_invalidates_cached_result(self):
        await self.run_screen()
        path = next((self.root / "raw/events").glob("*.jsonl"))
        row = load_source(self.root, "synthetic-event")
        row["payload"]["text"] = "Changed source"
        path.write_text(json.dumps(row) + "\n")
        with self.assertRaises(ReviewBlocked):
            await self.run_screen()

    async def test_corrupt_checkpoint_is_not_replayed(self):
        await self.run_screen()
        path = self.root / "memory/screen/runs.jsonl"
        rows = self.runs()
        rows[-1]["candidates"] = []
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        with self.assertRaises(ReviewBlocked):
            await self.run_screen()

    async def test_timeout_leaves_retry(self):
        class Slow:
            async def complete(self, *args, **kwargs):
                await asyncio.sleep(1)
        result = await self.run_screen(model_client=Slow(), timeout=0.001)
        self.assertEqual(result["status"], "retry")
        self.assertEqual(result["error"], "TimeoutError")

    async def test_cancel_leaves_retry_and_propagates(self):
        class Cancelled:
            async def complete(self, *args, **kwargs):
                raise asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            await self.run_screen(model_client=Cancelled())
        self.assertEqual(self.runs()[-1]["status"], "retry")

    async def test_symlinked_source_is_rejected(self):
        path = next((self.root / "raw/events").glob("*.jsonl"))
        outside = self.root / "outside.jsonl"
        path.rename(outside)
        path.symlink_to(outside)
        with self.assertRaises(ReviewBlocked):
            await self.run_screen()

    async def test_nested_raw_source_is_supported(self):
        path = next((self.root / "raw/events").glob("*.jsonl"))
        nested = path.parent / "grok-sync" / path.name
        nested.parent.mkdir()
        path.rename(nested)
        # Full proposal support also requires review_policy's recursive source lookup.
        self.model.decision = "archive_only"
        result = await self.run_screen()
        self.assertEqual(result["status"], "complete")

    async def test_missing_agent_and_cloud_exclusion_are_blocked(self):
        path = next((self.root / "raw/events").glob("*.jsonl"))
        original = load_source(self.root, "synthetic-event")
        for change in ({"agent": None}, {"payload": {"text": TEXT, "cloud_eligible": False}}):
            row = copy.deepcopy(original)
            row.update(change)
            path.write_text(json.dumps(row) + "\n")
            with self.assertRaises(ReviewBlocked):
                await self.run_screen(source_digest=source_digest(row))
        self.assertEqual(self.model.calls, [])

    async def test_forwarded_original_cannot_upgrade_authorship(self):
        path = next((self.root / "raw/events").glob("*.jsonl"))
        row = load_source(self.root, "synthetic-event")
        row.update(event_type="grok_direct_capture", payload={"messages": [{"text": TEXT,
            "speaker": "user", "fidelity": "forwarded_original_unverified", "occurred_at": DATE}]})
        path.write_text(json.dumps(row) + "\n")
        result = await self.run_screen(source_digest=source_digest(row))
        self.assertEqual(result["status"], "retry")
        self.assertEqual(self.graph.calls, [])
        sent = json.loads(self.model.calls[0][1]["content"])
        self.assertFalse(sent["source_context"]["authorship_verified"])
        self.assertEqual(sent["source_context"]["fidelity"], "forwarded_original_unverified")

    async def test_missing_source_time_allows_extraction_without_promoting_capture_to_validity(self):
        path = next((self.root / "raw/events").glob("*.jsonl"))
        row = load_source(self.root, "synthetic-event")
        row["occurred_at"] = None
        self.assertTrue(row["captured_at"])
        self.assertIn("2026-01-01", row["payload"]["text"])
        path.write_text(json.dumps(row) + "\n")
        result = await self.run_screen(source_digest=source_digest(row))
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["outcome"], "pending_review")
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(len(self.graph.calls), 1)
        self.assertEqual(result['temporal_context']['reference_basis'], 'received_at' if row.get('received_at') else 'captured_at')
        self.assertIsNone(result['temporal_context']['source_time'])
        self.assertEqual(result['verified'][0]['edge']['valid_from'], DATE)
        self.assertIsNone(json.loads(self.model.calls[0][1]['content'])['source_time'])
        again = await self.run_screen(source_digest=source_digest(row))
        self.assertEqual(result, again)
        self.assertEqual(len(self.model.calls), 2)
        self.assertFalse((self.root / "memory/structured").exists())

    async def test_undated_preference_full_pipeline_proposes_unknown_start_and_preserves_graph_audit(self):
        from test_jev_policy import FakeClient
        text = 'Alice prefers the Orion report as a PDF attachment.'
        path = next((self.root / 'raw/events').glob('*.jsonl'))
        row = load_source(self.root, 'synthetic-event')
        row['occurred_at'] = None
        row['payload']['text'] = text
        path.write_text(json.dumps(row) + '\n')
        class UndatedGraph(Graph):
            async def extract(inner, **kwargs):
                inner.calls.append(kwargs)
                return {'episode_uuid': 'episode-one', 'model': 'synthetic', 'facts': [{
                    'graph_edge_id': 'edge-one', 'subject_id': 'alice', 'subject_label': 'Alice',
                    'object_label': 'Orion report', 'predicate': 'PREFERS_FORMAT', 'value': text,
                    'valid_from': kwargs['event_time'].isoformat(), 'valid_to': None}]}
        graph, client = UndatedGraph(), FakeClient()
        result = await self.run_screen(text=text, source_digest=source_digest(row), model='jev-1.13.0',
            model_client=client, graph_client=graph)
        self.assertEqual(result['outcome'], 'pending_review', result)
        self.assertEqual(len(result['candidates']), 1)
        self.assertIsNone(result['verified'][0]['edge']['valid_from'])
        self.assertIsNotNone(result['graph']['facts'][0]['valid_from'])
        self.assertEqual(result['verified'][0]['edge']['temporal_provenance']['normalization'], 'reference_default_to_unknown')
        sent = client.calls[1]['state']
        self.assertIsNone(sent['source']['reference_time'])
        self.assertEqual(sent['candidates']['f0000']['asserted_validity'], {})
        self.assertEqual(result['autoreview']['accepted_count'], 1)
        from memory_autoreview import MemoryAutoreview
        fact = MemoryAutoreview(self.root).review._store('invest').get_fact(result['autoreview']['accepted'][0]['fact_id'])
        self.assertEqual(fact.status, 'ai_reviewed')
        self.assertIsNone(fact.valid_from)
        self.assertIsNone(fact.confirmation_event_id)

    async def test_unknown_source_relative_time_reaches_graph_but_is_manual_evidence_task(self):
        from test_jev_policy import FakeClient
        text = 'Alice joins Orion tomorrow.'
        path = next((self.root / 'raw/events').glob('*.jsonl'))
        row = load_source(self.root, 'synthetic-event')
        row['occurred_at'] = None
        row['payload']['text'] = text
        path.write_text(json.dumps(row) + '\n')
        class RelativeGraph(Graph):
            async def extract(inner, **kwargs):
                result = await super().extract(**kwargs)
                result['facts'][0].update(value=text, valid_from=None)
                return result
        graph, client = RelativeGraph(), FakeClient()
        result = await self.run_screen(text=text, source_digest=source_digest(row), model='jev-1.13.0',
            model_client=client, graph_client=graph)
        self.assertEqual(len(graph.calls), 1)
        self.assertEqual(result['outcome'], 'needs_evidence', result)
        self.assertEqual(result['candidates'], [])
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(get_pending(self.root, result['review_refs'][0])['policy_reason'], 'relative_time_unanchored')

    async def test_remote_episode_without_success_receipt_is_not_complete(self):
        instances = []
        class ExistingAdapter:
            def __init__(self, group_id, *, env_path, meta_dir, usage_root=None, usage_run_id=None, usage_scope=None):
                self.group_id = group_id
                self.meta_dir = meta_dir
                self.meta_dir.mkdir(parents=True, exist_ok=True)
                self._driver = self
                self.queries = []
                self.closed = False
                instances.append(self)

            async def _ensure_read(self):
                pass

            async def execute_query(self, query, **kwargs):
                self.queries.append(query)
                if "Episodic" in query:
                    return ([{"uuid": "episode-one", "source": "javis:jev_candidate:synthetic-event"}], None, None)
                return ([], None, None)

            async def write_event(self, **kwargs):
                raise AssertionError("Partial existing graph must never be overwritten or ingested again")

            async def close(self):
                self.closed = True

        with patch("memory_screen.MemoryAdapter", ExistingAdapter):
            result = await self.run_screen(graph_client=GraphitiCandidateClient())
            self.assertEqual(result["status"], "retry")
            self.assertEqual(result["error_code"], "candidate_graph_completion_unproven")
            self.assertEqual(len(instances[0].queries), 1)
            self.assertTrue(instances[0].closed)
            self.assertFalse((self.root / "memory/quarantine").exists())
            receipt = {"source_event_id": "synthetic-event", "episode_uuid": "episode-one",
                "group_id": result["group_id"], "event_kind": "jev_candidate", 'temporal_context': result['temporal_context']}
            journal = self.root / "memory/screen/graph" / result["run_id"] / "source_events.jsonl"
            journal.write_text(json.dumps(receipt) + "\n")
            complete = await self.run_screen(graph_client=GraphitiCandidateClient())
            self.assertEqual(complete["status"], "needs_review")
            self.assertEqual(complete["outcome"], "needs_evidence")
            self.assertNotIn("error_code", complete)
            self.assertEqual(len(instances[1].queries), 2)
            self.assertTrue(instances[1].closed)
        self.assertEqual(len(self.model.calls), 1)

    async def test_oversized_whole_source_creates_reference_only_task_without_model(self):
        text = "Synthetic source sentence. " * 5000
        path = next((self.root / "raw/events").glob("*.jsonl"))
        event = load_source(self.root, "synthetic-event")
        event["payload"]["text"] = text
        path.write_text(json.dumps(event) + "\n")
        first = await self.run_screen(text=text, source_digest=source_digest(event))
        again = await self.run_screen(text=text, source_digest=source_digest(event))
        self.assertEqual(first, again)
        self.assertEqual(first["status"], "needs_review")
        self.assertEqual(first["review_count"], 1)
        item = get_pending(self.root, first["review_refs"][0])
        self.assertEqual(item["reason_code"], "source_too_large")
        self.assertEqual(self.model.calls, [])
        self.assertEqual(self.graph.calls, [])
        self.assertNotIn(text[:100], json.dumps(item))
        self.assertEqual(load_source(self.root, "synthetic-event")["payload"]["text"], text)

    async def test_supported_and_uncertain_edges_keep_separate_pending_paths(self):
        class MixedModel(Model):
            async def complete(inner, messages, *, model):
                result = await super().complete(messages, model=model)
                if "facts" in result["content"]:
                    result["content"]["review_facts"] = [{"graph_edge_id": "edge-two", "reason": "typed_low_confidence"}]
                return result

        class MixedGraph(Graph):
            async def extract(inner, **kwargs):
                result = await super().extract(**kwargs)
                result["facts"].append({**result["facts"][0], "graph_edge_id": "edge-two"})
                return result

        model, graph = MixedModel(), MixedGraph()
        with patch("memory_screen.MemoryReview.propose", side_effect=OSError("synthetic one-time proposal failure")):
            failed = await self.run_screen(model_client=model, graph_client=graph)
        self.assertEqual(failed["status"], "retry")
        self.assertEqual(failed["review_count"], 1)
        result = await self.run_screen(model_client=model, graph_client=graph)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["outcome"], "pending_review_and_evidence")
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["status"], "pending_review")
        self.assertEqual(result["review_count"], 1)
        self.assertEqual(list_pending(self.root)["total"], 1)
        self.assertEqual(len(model.calls), 2)
        self.assertEqual(len(graph.calls), 1)
        self.assertEqual(get_pending(self.root, result["review_refs"][0])["graph_edge_id"], "edge-two")
        self.assertFalse((self.root / "memory/structured").exists())

    async def test_explicit_typed_contradiction_is_rejected_without_human_backlog(self):
        class TypedClient:
            async def evaluate(inner, *args, **kwargs):
                raise AssertionError("No actual model call")

        async def fake_screen(*args, **kwargs):
            return {"model": "jev-1.13.0", "content": {"decision": "keep", "category": "rule",
                "statement_kind": "user_explicit", "reason": "typed_keep", "evidence": [TEXT]}}

        async def fake_verify(*args, **kwargs):
            return {"model": "jev-1.13.0", "content": {"facts": [], "review_facts": []},
                    "decisions": {"facts": [{"graph_edge_id": "edge-one", "disposition": "rejected"}]}}

        with patch("memory_screen.screen_decision", side_effect=fake_screen), patch("memory_screen.verify_facts", side_effect=fake_verify):
            result = await self.run_screen(model="jev-1.13.0", model_client=TypedClient())
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["outcome"], "no_supported_facts")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(list_pending(self.root)["total"], 0)

    async def test_triage_failure_retries_without_silently_finishing_or_rescreening(self):
        self.model.decision = "needs_evidence"
        with patch("memory_screen.record_pending", side_effect=OSError("synthetic disk failure")):
            failed = await self.run_screen()
        self.assertEqual(failed["status"], "retry")
        successful = await self.run_screen()
        self.assertEqual(successful["status"], "needs_review")
        self.assertEqual(successful["review_count"], 1)
        self.assertEqual(len(self.model.calls), 1)


    async def test_strict_screen_response_invalid_is_durable_review_without_paid_retry(self):
        http = TypedHTTP(invalid_call=1)
        client = JevClient(self.root, run_id="synthetic_invalid_screen", scope="invest")
        with patch.dict(os.environ, {"TYPESAFE_API_KEY": "synthetic-test-key"}), \
                patch("jev_client.build_opener", return_value=http), patch("memory_screen._load_dotenv"):
            result = await self.run_screen(model="jev-1.13.0", model_client=client)
            replay = await self.run_screen(model="jev-1.13.0", model_client=client)
        self.assertEqual(result, replay)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["error_code"], "jev_invalid_probability_sum")
        self.assertNotIn("screening", result)
        self.assertEqual(result["candidates"], [])
        self.assertEqual(self.graph.calls, [])
        self.assertEqual(len(http.calls), 1)
        self.assertEqual(len(usage_recent(self.root)), 1)
        self.assertEqual(usage_recent(self.root)[0]["tokens"]["input"], 77)
        item = get_pending(self.root, result["review_refs"][0])
        self.assertEqual((item["reason_code"], item["stage"]), ("model_response_invalid", "screening"))
        self.assertEqual((item["source_event_id"], item["run_id"]), ("synthetic-event", result["run_id"]))
        self.assertEqual(item["policy_version"], result["policy_version"])
        self.assertEqual(item["source_integrity"], "verified")
        audit = (self.root / "memory/screen/runs.jsonl").read_text()
        self.assertNotIn("DO_NOT_LOG_PROVIDER_BODY", audit)
        self.assertNotIn("synthetic-test-key", audit)
        self.assertFalse((self.root / "memory/quarantine").exists())

    async def test_invalid_later_verification_batch_keeps_paid_checkpoint_and_no_candidates(self):
        class NineEdges(Graph):
            async def extract(inner, **kwargs):
                result = await super().extract(**kwargs)
                edge = result["facts"][0]
                result["facts"] = [{**edge, "graph_edge_id": "edge-%d" % i} for i in range(9)]
                return result

        http, graph = TypedHTTP(invalid_call=3), NineEdges()
        client = JevClient(self.root, run_id="synthetic_invalid_verification", scope="invest")
        with patch.dict(os.environ, {"TYPESAFE_API_KEY": "synthetic-test-key"}), \
                patch("jev_client.build_opener", return_value=http), patch("memory_screen._load_dotenv"):
            result = await self.run_screen(model="jev-1.13.0", model_client=client, graph_client=graph)
            replay = await self.run_screen(model="jev-1.13.0", model_client=client, graph_client=graph)
        self.assertEqual(result, replay)
        self.assertEqual((result["status"], result["stage"]), ("needs_review", "verification"))
        self.assertEqual(result["error_code"], "jev_invalid_probability_sum")
        self.assertEqual(len(result["verification_checkpoint"]), 1)
        self.assertNotIn("verified", result)
        self.assertEqual(result["candidates"], [])
        self.assertEqual(len(http.calls), 3)
        self.assertEqual(len(graph.calls), 1)
        self.assertEqual(len(usage_recent(self.root)), 3)
        self.assertEqual(sum(row["tokens"]["input"] for row in usage_recent(self.root)), 231)
        item = get_pending(self.root, result["review_refs"][0])
        self.assertEqual((item["reason_code"], item["stage"]), ("model_response_invalid", "verification"))
        self.assertEqual(list_pending(self.root)["total"], 1)
        self.assertFalse((self.root / "memory/quarantine").exists())
        self.assertFalse((self.root / "memory/structured").exists())

    async def test_invalid_response_triage_write_failure_retries_only_local_persistence(self):
        http = TypedHTTP(invalid_call=1)
        client = JevClient(self.root, run_id="synthetic_invalid_disk_failure", scope="invest")
        with patch.dict(os.environ, {"TYPESAFE_API_KEY": "synthetic-test-key"}), \
                patch("jev_client.build_opener", return_value=http), patch("memory_screen._load_dotenv"):
            with patch("memory_screen.record_pending", side_effect=OSError("DO_NOT_LOG_THIS")):
                failed = await self.run_screen(model="jev-1.13.0", model_client=client)
            self.assertEqual(failed["status"], "retry")
            self.assertIn("policy_validation_failure", failed)
            self.assertEqual(list_pending(self.root)["total"], 0)
            result = await self.run_screen(model="jev-1.13.0", model_client=client)
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(len(http.calls), 1)
        self.assertEqual(len(usage_recent(self.root)), 1)
        self.assertEqual(list_pending(self.root)["total"], 1)
        self.assertNotIn("DO_NOT_LOG_THIS", (self.root / "memory/screen/runs.jsonl").read_text())

    async def test_invalid_policy_response_queue_is_terminal_before_retry_limit(self):
        import memory_pipeline
        (self.root / "config").mkdir()
        (self.root / "config/memory-pipeline.json").write_text(json.dumps({"enabled": True, "model": "jev-1.13.0"}))
        memory_pipeline.enqueue(self.root, event_id="synthetic-event", scope="invest")
        http = TypedHTTP(invalid_call=1)
        client = JevClient(self.root, run_id="synthetic_invalid_pipeline", scope="invest")

        async def screen_fn(root, **kwargs):
            return await screen(root, model_client=client, graph_client=self.graph, **kwargs)

        with patch.dict(os.environ, {"TYPESAFE_API_KEY": "synthetic-test-key"}), \
                patch("jev_client.build_opener", return_value=http), patch("memory_screen._load_dotenv"):
            first = await memory_pipeline.process_once(self.root, screen_fn=screen_fn)
            subsequent = [await memory_pipeline.process_once(self.root, screen_fn=screen_fn) for _ in range(8)]
        self.assertEqual(first["items"][0]["status"], "needs_review")
        self.assertTrue(all(run["processed"] == 0 for run in subsequent))
        queue = json.loads(next((self.root / "state/memory-pipeline/queue").glob("*.json")).read_text())
        self.assertEqual(queue["provider_attempts"], 1)
        self.assertEqual(self.runs()[-1]["error_code"], "jev_invalid_probability_sum")
        self.assertEqual(queue["result"]["review_count"], 1)
        self.assertEqual(len(http.calls), 1)
        self.assertEqual(len(usage_recent(self.root)), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
