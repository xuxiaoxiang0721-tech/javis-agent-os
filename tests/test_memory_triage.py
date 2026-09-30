"""Synthetic durable backlog tests; no provider/graph requests or production IO."""
from concurrent.futures import ThreadPoolExecutor
import json
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / "scripts"))
import memory_triage as triage
from raw_storage import append_event
from javis_memory_adapter.review_policy import digest, source_digests, ReviewBlocked

TEXT = "A synthetic individual prefers the synthetic green report."


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        append_event(self.root, {"event_id": "synthetic_source", "event_type": "user_input", "agent": "invest",
            "occurred_at": "2026-09-24T01:00:00Z", "payload": {"text": TEXT, "is_original_user_input": True}},
            relative_path="events/source.jsonl")
        self.binding = dict(event_id="synthetic_source", scope="invest",
            source_digest=source_digests(self.root, {"synthetic_source"})["synthetic_source"],
            run_id="synthetic_run", policy_version="jev-typed-v2", policy_digest=digest("synthetic-policy-v2"),
            stage="screening", reason_code="screen_needs_evidence", content_digest=digest(TEXT))

    def record(self, **changes):
        return triage.record_pending(self.root, **{**self.binding, **changes})

    def file(self, item):
        return self.root / "memory/triage/items" / (item["triage_id"] + ".json")

    def test_idempotent_immutable_reference_only_record(self):
        first = self.record()
        original = self.file(first).read_bytes()
        self.assertEqual(first, self.record())
        self.assertEqual(self.file(first).read_bytes(), original)
        self.assertEqual(first["source_integrity"], "verified")
        self.assertNotIn(TEXT, original.decode())
        self.assertNotIn("subject", original.decode())
        self.assertNotIn("source_digest", json.dumps(first))
        self.assertEqual(triage.get_pending(self.root, first["triage_id"]), first)
        self.assertEqual(triage.list_pending(self.root), {"items": [first], "total": 1, "invalid_records": 0,
            "superseded_count": 0, "invalid_run_records": 0})
        self.assertFalse((self.root / "memory/structured").exists())
        self.assertFalse((self.root / "memory/quarantine").exists())

    def test_concurrent_replay_creates_one_task(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.record(), range(8)))
        self.assertTrue(all(item == results[0] for item in results))
        self.assertEqual(triage.list_pending(self.root)["total"], 1)

    def test_policy_run_edge_bindings_have_distinct_identity(self):
        records = [self.record(), self.record(run_id="new_run"), self.record(policy_digest=digest("new-policy")),
            self.record(stage="verification", reason_code="verification_uncertain", graph_edge_id="edge_one",
                        edge_digest=digest("edge-one"), policy_reason="typed_low_confidence"),
            self.record(stage="verification", reason_code="verification_uncertain", graph_edge_id="edge_two",
                        edge_digest=digest("edge-two"), policy_reason="typed_insufficient")]
        self.assertEqual(len({row["triage_id"] for row in records}), 5)
        self.assertEqual(triage.list_pending(self.root, limit=2)["total"], 5)
        self.assertEqual(len(triage.list_pending(self.root, limit=2)["items"]), 2)

    def test_invalid_model_response_is_fixed_reason_with_separate_stage_bindings(self):
        screen = self.record(reason_code="model_response_invalid")
        verify = self.record(reason_code="model_response_invalid", stage="verification")
        self.assertNotEqual(screen["triage_id"], verify["triage_id"])
        self.assertEqual(screen, self.record(reason_code="model_response_invalid"))
        self.assertEqual(triage.list_pending(self.root)["total"], 2)
        self.assertIsNone(screen["policy_reason"])
        self.assertNotIn(TEXT, self.file(screen).read_text())

    def test_source_change_is_visible_and_cannot_generate_or_replay_stale_task(self):
        item = self.record()
        path = self.root / "raw/events/source.jsonl"
        row = json.loads(path.read_text())
        row["payload"]["text"] = "Corrected synthetic source."
        path.write_text(json.dumps(row) + "\n")
        self.assertEqual(triage.get_pending(self.root, item["triage_id"])["source_integrity"], "changed_or_unavailable")
        self.assertEqual(triage.list_pending(self.root)["items"][0]["source_integrity"], "changed_or_unavailable")
        with self.assertRaisesRegex(ReviewBlocked, "triage_source_changed_or_missing"):
            self.record()

    def test_missing_or_wrong_scope_source_fails_closed(self):
        for changes in ({"event_id": "missing_source"}, {"source_digest": "0" * 64}, {"scope": "cards-master"}):
            with self.assertRaises(ReviewBlocked):
                self.record(**changes)
        self.assertFalse((self.root / "memory/triage/items").exists())

    def test_corrupt_record_never_reaches_safe_projection_or_get(self):
        item = self.record()
        path = self.file(item)
        row = json.loads(path.read_text())
        row["binding"]["reason_code"] = "arbitrary private model text"
        path.write_text(json.dumps(row))
        with self.assertRaises(ReviewBlocked):
            triage.get_pending(self.root, item["triage_id"])
        self.assertEqual(triage.list_pending(self.root), {"items": [], "total": 0, "invalid_records": 1,
            "superseded_count": 0, "invalid_run_records": 0})
        with self.assertRaises(ReviewBlocked):
            self.record()

    def test_record_digest_tamper_and_hash_filename_mismatch_rejected(self):
        item = self.record()
        path = self.file(item)
        row = json.loads(path.read_text())
        row["created_at"] = "2026-09-25T00:00:00+00:00"
        path.write_text(json.dumps(row))
        with self.assertRaises(ReviewBlocked):
            triage.get_pending(self.root, item["triage_id"])

    def test_symlink_hardlink_and_raw_link_are_rejected(self):
        item = self.record()
        path = self.file(item)
        other = self.root / "linked.json"
        os.link(path, other)
        with self.assertRaises(ReviewBlocked):
            triage.get_pending(self.root, item["triage_id"])
        self.assertEqual(triage.list_pending(self.root)["invalid_records"], 1)
        other.unlink()
        path.rename(other)
        path.symlink_to(other)
        with self.assertRaises(ReviewBlocked):
            self.record()

    def test_arbitrary_reasons_and_path_traversal_cannot_be_stored(self):
        for changes in ({"reason_code": TEXT}, {"policy_reason": TEXT}, {"event_id": "../source"},
                        {"graph_edge_id": "../edge", "edge_digest": digest("edge")},
                        {"graph_edge_id": "edge_without_digest"}):
            with self.assertRaises(ReviewBlocked):
                self.record(**changes)

    def test_read_only_empty_root_and_query_limits(self):
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(triage.list_pending(empty), {"items": [], "total": 0, "invalid_records": 0,
                "superseded_count": 0, "invalid_run_records": 0})
            self.assertEqual(list(Path(empty).iterdir()), [])
        for limit in (-1, 501, True):
            with self.assertRaises(ReviewBlocked):
                triage.list_pending(self.root, limit=limit)

    def test_fsync_and_replace_failure_never_claims_pending_success(self):
        with patch.object(triage.os, "replace", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(OSError):
                self.record()
        self.assertEqual(triage.list_pending(self.root)["total"], 0)
        with patch.object(triage.os, "fsync", wraps=os.fsync) as fsync:
            self.record()
        self.assertGreaterEqual(fsync.call_count, 2)
        self.assertFalse(any(path.name.startswith(".triage-") for path in (self.root / "memory/triage/items").iterdir()))

    def test_recovery_hold_blocks_write_but_not_read_only_backlog(self):
        item = self.record()
        hold = self.root / "state/recovery-hold.json"
        hold.write_text('{"hold":true}')
        with self.assertRaises(Exception):
            self.record(run_id="new_run_under_hold")
        self.assertEqual(triage.get_pending(self.root, item["triage_id"]), item)
        self.assertEqual(triage.list_pending(self.root)["total"], 1)
        hold.write_text('{"hold":false}')
        self.record(run_id="new_run_after_hold")
        self.assertEqual(triage.list_pending(self.root)["total"], 2)

    def current_run(self, **changes):
        from datetime import datetime, timezone
        import memory_screen as screen
        import jev_policy as policy
        b = self.binding
        row = {"schema": screen.SCHEMA, "pipeline_version": screen.PIPELINE_VERSION, "provider": "typesafe",
            "policy_version": policy.POLICY_VERSION, "policy_digest": policy.POLICY_DIGEST,
            "event_id": b["event_id"], "scope": b["scope"], "source_digest": b["source_digest"],
            "content_digest": b["content_digest"], "model": "jev-1.13.0", "graph_model": "qwen-turbo",
            "embedding_model": "text-embedding-v3", "extraction_prompt_version": screen.PERSONAL_MEMORY_EXTRACTION_VERSION,
            "extraction_prompt_digest": digest(screen.PERSONAL_MEMORY_EXTRACTION_INSTRUCTIONS),
            "prompt_version": screen.PROMPT_VERSION, "prompt_digest": digest([screen.SCREEN_PROMPT, screen.VERIFY_PROMPT]),
            "learning_version": "baseline", "learning_profile_digest": None, **changes}
        identity = {key: row[key] for key in triage._RUN_BINDING_FIELDS}
        identity.update({key: row[key] for key in triage._RUN_OPTIONAL_BINDING_FIELDS if key in row})
        row["run_id"] = "screen_" + digest(identity)[:32]
        stamp = datetime.now(timezone.utc).isoformat()
        row.update(group_id="javis-screen-" + digest({"root": str(self.root), "run": row["run_id"]})[:40],
            status="complete", outcome="archive_only", candidates=[], review_refs=[], review_count=0,
            created_at=stamp, updated_at=stamp)
        return row

    def save_run(self, row, *, seal=True):
        row = copy.deepcopy(row)
        if seal:
            row["checkpoint_digest"] = digest({k: v for k, v in row.items() if k != "checkpoint_digest"})
        path = self.root / "memory/screen/runs.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        return row

    def new_review(self, run, number=0, **changes):
        return self.record(run_id=run["run_id"], policy_version=run["policy_version"], policy_digest=run["policy_digest"],
            stage="verification", reason_code="verification_uncertain", graph_edge_id="new_edge_" + str(number),
            edge_digest=digest(["new", number]), **changes)

    def test_completed_current_run_supersedes_same_source_old_task_without_writes_or_owner_decision(self):
        old = self.record(stage="source_time", reason_code="source_time_missing")
        before = self.file(old).read_bytes()
        run = self.current_run();self.save_run(run)
        view = triage.list_pending(self.root)
        self.assertEqual((view["total"], view["superseded_count"]), (0, 1))
        audit = triage.get_pending(self.root, old["triage_id"])
        self.assertEqual(audit["status"], "superseded")
        self.assertEqual(audit["superseded_by_run_id"], run["run_id"])
        self.assertEqual(triage.list_pending(self.root, include_superseded=True)["items"], [audit])
        self.assertEqual(self.file(old).read_bytes(), before)
        self.assertFalse((self.root / "memory/structured").exists())
        self.assertFalse((self.root / "state/owner-auth").exists())

    def test_source_scope_event_hash_or_content_mismatch_never_replaces(self):
        old = self.record()
        for fields in ({"scope": "cards-master"}, {"event_id": "other_event"},
                {"source_digest": "a" * 64}, {"content_digest": "b" * 64}):
            with self.subTest(fields=fields):
                self.save_run(self.current_run(**fields))
                self.assertEqual(triage.list_pending(self.root)["items"][0]["triage_id"], old["triage_id"])

    def test_subscription_identity_fields_are_pinned_when_present_and_legacy_remains_valid(self):
        old = self.record()
        run = self.current_run(graph_provider='openai', graph_config_revision=2,
            graph_auth_mode='chatgpt_subscription', graph_account_id='synthetic-account-a',
            embedding_provider='openai', embedding_dimensions=1536)
        self.save_run(run)
        self.assertEqual(triage.list_pending(self.root)['superseded_count'], 1)
        for key, value in [('graph_auth_mode','api_key'), ('graph_account_id','synthetic-account-b'),
                           ('embedding_provider','dashscope'), ('embedding_dimensions',3072)]:
            with self.subTest(key=key):
                changed = copy.deepcopy(run); changed[key] = value
                self.save_run(changed)
                view = triage.list_pending(self.root)
                self.assertEqual(view['items'][0]['triage_id'], old['triage_id'])
                self.assertEqual(view['superseded_count'], 0)
        legacy = self.current_run()
        self.save_run(legacy)
        self.assertEqual(triage.list_pending(self.root)['superseded_count'], 1)

    def test_nonterminal_old_version_older_time_or_broken_latest_checkpoint_cannot_hide(self):
        old = self.record()
        variants = [{"status": "running"}, {"status": "retry"}, {"status": "blocked"},
            {"status": "waiting_for_key"}, {"status": "credentials_rejected"},
            {"pipeline_version": "old"}, {"policy_digest": "b" * 64}, {"prompt_digest": "c" * 64},
            {"updated_at": "2000-01-01T00:00:00+00:00"}, {"outcome": "configuration_required"}]
        for fields in variants:
            with self.subTest(fields=fields):
                run = self.current_run();run.update(fields);self.save_run(run)
                self.assertEqual(triage.list_pending(self.root)["total"], 1)
        good = self.save_run(self.current_run())
        bad = {**good, "updated_at": "2099-01-03T00:00:00+00:00"}
        self.save_run(bad, seal=False)
        view = triage.list_pending(self.root)
        self.assertEqual(view["total"], 1)
        self.assertGreater(view["invalid_run_records"], 0)
        self.assertEqual(triage.get_pending(self.root, old["triage_id"])["status"], "needs_review")

    def test_new_review_refs_must_exist_match_and_be_intact_before_old_is_hidden(self):
        old = self.record()
        run = self.current_run()
        new = self.new_review(run)
        run.update(status="needs_review", outcome="needs_evidence", review_refs=[new["triage_id"]], review_count=1)
        self.save_run(run)
        self.assertEqual(triage.list_pending(self.root)["items"], [new])
        raw = self.file(new).read_bytes()
        for mode in ("missing", "corrupt", "other_content"):
            with self.subTest(mode=mode):
                if mode == "missing":self.file(new).unlink()
                elif mode == "corrupt":self.file(new).write_bytes(raw.replace(b'needs_review', b'tampered_row'))
                else:
                    other = self.new_review(run, 1, content_digest="f" * 64)
                    run.update(review_refs=[other["triage_id"]]);self.save_run(run)
                self.assertIn(old["triage_id"], {x["triage_id"] for x in triage.list_pending(self.root)["items"]})
                self.file(new).write_bytes(raw)

    def test_screening_terminal_can_retain_attempt_timestamp_before_its_new_review_record(self):
        from datetime import datetime, timezone
        old = self.record()
        run = self.current_run()
        stamp = datetime.now(timezone.utc).isoformat()
        run.update(created_at=stamp, updated_at=stamp)
        new = self.new_review(run)
        self.assertGreater(json.loads(self.file(new).read_text())["created_at"], stamp)
        run.update(status="needs_review", outcome="needs_evidence", review_refs=[new["triage_id"]], review_count=1)
        self.save_run(run)
        self.assertEqual(triage.list_pending(self.root)["items"], [new])
        self.assertEqual(triage.get_pending(self.root, old["triage_id"])["status"], "superseded")

    def test_missing_candidate_receipt_does_not_hide_old_review(self):
        old = self.record();run = self.current_run()
        run.update(outcome="pending_review", candidates=[{"candidate_id": "candidate_" + "a" * 32}])
        self.save_run(run)
        self.assertEqual(triage.list_pending(self.root)["items"], [old])

    def test_valid_owner_terminal_candidate_keeps_old_task_superseded_but_bad_status_or_missing_proof_does_not(self):
        from test_owner_memory_review import OwnerMemoryTest
        from memory_attention import snapshot
        for action in ("confirm", "reject"):
            with self.subTest(action=action):
                owner = OwnerMemoryTest();owner.setUp()
                try:
                    source_hash = source_digests(owner.root, {"input-one"})["input-one"]
                    binding = {**self.binding, "event_id": "input-one", "scope": "cards-master", "source_digest": source_hash}
                    old = triage.record_pending(owner.root, **binding)
                    with patch.object(self, "root", owner.root), patch.object(self, "binding", binding):
                        run = self.current_run();run.update(outcome="pending_review", candidates=[owner.candidate]);self.save_run(run)
                    self.assertEqual(triage.list_pending(owner.root)["superseded_count"], 1)
                    candidate_path = owner.root / "memory/quarantine/cards-master/candidates.jsonl"
                    original = candidate_path.read_bytes()
                    pending = json.loads(original)
                    for status in ("corrupted_status", None, "confirmed", "rejected"):
                        candidate_path.write_text(json.dumps({**pending, "status": status}) + "\n")
                        self.assertEqual(triage.list_pending(owner.root)["total"], 1)
                        self.assertGreater(snapshot(owner.root)["invalid_records"], 0)
                    candidate_path.write_bytes(original)
                    owner.review.review(owner.principal, owner.request(action), owner.assertion)
                    before = {str(p): p.read_bytes() for p in owner.root.rglob("*") if p.is_file()}
                    self.assertEqual(triage.get_pending(owner.root, old["triage_id"])["status"], "superseded")
                    self.assertEqual(snapshot(owner.root)["triage_items"], 0)
                    self.assertEqual(before, {str(p): p.read_bytes() for p in owner.root.rglob("*") if p.is_file()})
                    owner.proofs.clear()
                    self.assertEqual(triage.list_pending(owner.root)["total"], 1)
                    self.assertGreater(triage.list_pending(owner.root)["invalid_run_records"], 0)
                finally:
                    owner.tearDown()

    def test_cached_integrity_check_skips_supersession_index_but_still_checks_raw_and_record(self):
        old = self.record()
        with patch.object(triage, "_supersessions", side_effect=AssertionError("No repeated run scan")):
            self.assertEqual(triage.get_pending(self.root, old["triage_id"], check_supersession=False), old)
            path = self.root / "raw/events/source.jsonl"
            raw = json.loads(path.read_text());raw["payload"]["text"] = "Synthetic changed source"
            path.write_text(json.dumps(raw) + "\n")
            self.assertEqual(triage.get_pending(self.root, old["triage_id"], check_supersession=False)["source_integrity"], "changed_or_unavailable")
            self.file(old).write_text("{")
            with self.assertRaises(ValueError):triage.get_pending(self.root, old["triage_id"], check_supersession=False)

    def test_list_builds_one_run_index_for_all_records(self):
        for i in range(8):self.record(run_id="old_run_" + str(i))
        self.save_run(self.current_run())
        with patch.object(triage, "_supersessions", wraps=triage._supersessions) as index, \
                patch.object(triage, "read_rows", wraps=triage.read_rows) as reads:
            self.assertEqual(triage.list_pending(self.root)["superseded_count"], 8)
        self.assertEqual(index.call_count, 1)
        self.assertEqual(sum(str(call.args[1]).endswith("memory/screen/runs.jsonl") for call in reads.call_args_list), 1)

    def test_73_old_time_tasks_superseded_406_current_reviews_retained_and_uncovered_history_visible(self):
        for i in range(73):self.record(run_id="old_time_run_" + str(i), stage="source_time", reason_code="source_time_missing")
        uncovered = self.record(run_id="history_other_text", content_digest="f" * 64)
        run = self.current_run()
        new = [self.new_review(run, i) for i in range(406)]
        run.update(status="needs_review", outcome="needs_evidence", review_refs=[x["triage_id"] for x in new], review_count=406)
        self.save_run(run)
        from memory_attention import snapshot
        view = triage.list_pending(self.root, limit=500)
        self.assertEqual((view["total"], view["superseded_count"]), (407, 73))
        self.assertEqual({x["triage_id"] for x in view["items"]}, {x["triage_id"] for x in new} | {uncovered["triage_id"]})
        self.assertNotIn("source_time_missing", snapshot(self.root)["reason_counts"])
        self.assertEqual(snapshot(self.root)["triage_items"], 407)
        self.assertEqual(len(list((self.root / "memory/triage/items").glob("*.json"))), 480)

    def test_attention_removal_does_not_notify_and_historical_candidate_remains(self):
        from memory_attention import snapshot, changes
        self.record(stage="source_time", reason_code="source_time_missing")
        payload = {"scope": "invest", "synthetic": "Existing historical candidate"}
        path = self.root / "memory/quarantine/invest/candidates.jsonl"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"candidate_id": "candidate_" + "a" * 32, "payload": payload,
            "version_digest": digest(payload), "status": "pending_review"}) + "\n")
        before = snapshot(self.root)
        self.save_run(self.current_run())
        files = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        after = snapshot(self.root)
        self.assertEqual((after["triage_items"], after["superseded_triage_items"], after["candidates"]), (0, 1, 1))
        self.assertFalse(changes(after, before)["notify"])
        self.assertEqual(files, {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()})


if __name__ == "__main__":
    unittest.main()
