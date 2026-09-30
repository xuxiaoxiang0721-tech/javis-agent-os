"""Synthetic owner sessions and disposable RAW only; no model or production IO."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / "scripts"))
from memory_feedback import MemoryFeedback, ReviewBlocked, POLICY_DIGEST, _content
from javis_memory_adapter.review_policy import digest
import owner_auth
from raw_storage import append_event
from memory_screen import load_source
from memory_triage import record_pending

TEXT = "The synthetic report should include weekly totals."
DATE = "2026-09-24T09:00:00+00:00"


class MemoryFeedbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="javis-feedback-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.feedback = MemoryFeedback(self.root)
        # Same real principal verifier as production, with a test-only logged-in
        # session in this disposable root. No authenticators or real keys exist.
        self.auth = owner_auth.OwnerAuth(self.root)
        self.auth.sessions["synthetic-session-token"] = {"actor_id": owner_auth.ACTOR,
            "auth_ref": "synthetic-owner-session", "expires": time.time() + 900}
        self.principal = SimpleNamespace(actor_id=owner_auth.ACTOR, kind="owner",
                                         authentication_ref="synthetic-owner-session")
        self.addCleanup(owner_auth._active.pop, str(self.root), None)
        self.source = {"event_id": "source-one", "agent": "invest", "event_type": "user_input",
            "occurred_at": DATE, "task_id": "synthetic-task", "thread_id": "synthetic-thread",
            "payload": {"text": TEXT, "is_original_user_input": True}}
        append_event(self.root, self.source)

    def context(self, **kwargs):
        return self.feedback.context(self.principal, "source-one", "invest", **kwargs)

    def request(self, label="keep", command="command-one", **context):
        return {**self.context(**context)["bindings"], "command_id": command, "label": label}

    def record(self, **kwargs):
        return self.feedback.record(self.principal, self.request(**kwargs))

    def rewrite_source(self, row):
        paths = list((self.root / "raw/events").rglob("*.jsonl"))
        self.assertEqual(len(paths), 1)
        paths[0].write_text(json.dumps(row) + "\n")

    def record_path(self, item):
        return self.root / "memory/feedback/items" / (item["feedback_id"] + ".json")

    def add_run(self, run_id="synthetic-run", text=TEXT, source=None, decision="keep", **changes):
        source = source or load_source(self.root, "source-one")
        row = {"run_id": run_id, "event_id": source["event_id"], "scope": source["agent"],
               "source_digest": digest(source), "content_digest": _content(text), "policy_digest": POLICY_DIGEST,
               "status": "complete", "outcome": "pending_review", "screening": {"decision": decision,
               "reason": "DO_NOT_COPY_PRIVATE_MACHINE_BODY"}, **changes}
        row["checkpoint_digest"] = digest(row)
        path = self.root / "memory/screen/runs.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        return row

    def test_owner_session_required_for_every_interactive_method(self):
        for principal in (None, True, {"actor_id": owner_auth.ACTOR, "verified": True},
                          SimpleNamespace(actor_id=owner_auth.ACTOR, kind="service", authentication_ref="synthetic-owner-session"),
                          SimpleNamespace(actor_id=owner_auth.ACTOR, kind="owner", authentication_ref="fabricated")):
            for call in (lambda: self.feedback.context(principal, "source-one", "invest"),
                         lambda: self.feedback.record(principal, {}),
                         lambda: self.feedback.list_feedback(principal), lambda: self.feedback.sources(principal)):
                with self.subTest(principal=principal), self.assertRaises(ReviewBlocked):
                    call()
        self.assertFalse((self.root / "memory/feedback").exists())

    def test_active_session_no_second_assertion_and_no_memory_confirmation(self):
        with patch.object(owner_auth, "verify_decision", side_effect=AssertionError("No second owner assertion")):
            result = self.record()
        self.assertEqual(result["label"], "keep")
        self.assertEqual(result["status"], "active")
        self.assertFalse(result["confirmation_authority"])
        self.assertFalse((self.root / "memory/structured").exists())
        self.assertFalse((self.root / "memory/quarantine").exists())
        self.assertFalse((self.root / "state/owner-auth/decisions").exists())

    def test_expired_session_rejects_feedback(self):
        request = self.request()
        self.auth.sessions["synthetic-session-token"]["expires"] = 0
        with self.assertRaises(ReviewBlocked):
            self.feedback.record(self.principal, request)
        with self.assertRaises(ReviewBlocked):
            self.context()

    def test_context_preserves_full_text_hash_and_only_safe_machine_projection(self):
        run = self.add_run()
        context = self.context()
        self.assertEqual(context["source_text"], TEXT)
        self.assertEqual(context["bindings"]["source_digest"], run["source_digest"])
        self.assertEqual(context["bindings"]["content_digest"], _content(TEXT))
        self.assertEqual(context["bindings"]["run_id"], run["run_id"])
        self.assertTrue(context["source_context"]["authorship_verified"])
        self.assertNotIn("DO_NOT_COPY_PRIVATE_MACHINE_BODY", json.dumps(context))
        self.assertEqual(context["machine_decisions"][0]["decision"], "keep")

    def test_review_shows_source_received_and_saved_times_without_inventing_source_date(self):
        source=load_source(self.root,"source-one")
        source.update(occurred_at=None,received_at="2026-09-24T10:00:00Z",captured_at="2026-09-24T10:00:01Z")
        self.rewrite_source(source)
        times=self.context()["source_times"]
        self.assertIsNone(times["occurred_at"])
        self.assertEqual(times["received_at"],source["received_at"])
        self.assertEqual(times["captured_at"],source["captured_at"])

    def test_record_is_immutable_idempotent_and_does_not_copy_body_or_session(self):
        request = self.request()
        result = self.feedback.record(self.principal, request)
        before = self.record_path(result).read_bytes()
        self.assertEqual(result, self.feedback.record(self.principal, request))
        self.assertEqual(before, self.record_path(result).read_bytes())
        self.assertEqual(len(list((self.root / "memory/feedback/items").glob("*.json"))), 1)
        for private in (TEXT, "synthetic-session-token", "synthetic-owner-session"):
            self.assertNotIn(private, before.decode())
        self.assertEqual(self.record_path(result).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.record_path(result).parent.stat().st_mode & 0o777, 0o700)

    def test_command_id_reuse_with_different_content_is_rejected(self):
        request = self.request()
        self.feedback.record(self.principal, request)
        for changes in ({"label": "archive"}, {"policy_digest": "0" * 64}, {"scope": "cards-master"}):
            with self.assertRaises(ReviewBlocked):
                self.feedback.record(self.principal, {**request, **changes})
        self.assertEqual(self.feedback.list_feedback(self.principal)["total"], 1)

    def test_identical_command_replay_survives_policy_change_without_accepting_stale_new_label(self):
        request = self.request()
        first = self.feedback.record(self.principal, request)
        with patch("memory_feedback.POLICY_DIGEST", "a" * 64):
            self.assertEqual(first, self.feedback.record(self.principal, request))
            with self.assertRaisesRegex(ReviewBlocked, "feedback_policy_changed"):
                self.feedback.record(self.principal, {**request, "command_id": "new-command",
                    "supersedes_feedback_id": first["feedback_id"]})

    def test_revision_is_append_only_latest_owner_label_and_stale_form_cannot_win(self):
        stale = self.request(label="needs_evidence", command="stale")
        first = self.record()
        original = self.record_path(first).read_bytes()
        second = self.record(label="archive", command="correction")
        self.assertEqual(second["supersedes_feedback_id"], first["feedback_id"])
        self.assertEqual(self.record_path(first).read_bytes(), original)
        with self.assertRaisesRegex(ReviewBlocked, "feedback_version_changed"):
            self.feedback.record(self.principal, stale)
        items = self.feedback.list_feedback(self.principal)["items"]
        self.assertEqual({item["status"] for item in items}, {"active", "superseded"})
        training = self.feedback.training_rows()
        self.assertEqual(len(training), 1)
        self.assertEqual((training[0]["label"], training[0]["feedback_id"]), ("archive", second["feedback_id"]))

    def test_source_change_invalidates_feedback_and_old_commands_and_can_be_relabelled(self):
        request = self.request()
        first = self.feedback.record(self.principal, request)
        source = load_source(self.root, "source-one")
        source["payload"]["text"] = TEXT + " Corrected."
        self.rewrite_source(source)
        self.assertEqual(self.feedback.training_rows(), [])
        self.assertEqual(self.feedback.training_status()["invalidated_sources"], 1)
        self.assertEqual(self.feedback.list_feedback(self.principal)["items"][0]["status"], "invalidated")
        with self.assertRaisesRegex(ReviewBlocked, "feedback_source_changed"):
            self.feedback.record(self.principal, request)
        second = self.record(label="needs_evidence", command="updated-source")
        self.assertEqual(second["supersedes_feedback_id"], first["feedback_id"])
        self.assertEqual(self.feedback.training_rows()[0]["source_text"], source["payload"]["text"])

    def test_whole_raw_digest_and_scope_are_required_not_only_text_hash(self):
        request = self.request()
        source = load_source(self.root, "source-one")
        source["task_id"] = "other-task"
        self.rewrite_source(source)
        with self.assertRaisesRegex(ReviewBlocked, "feedback_source_changed"):
            self.feedback.record(self.principal, request)
        with self.assertRaisesRegex(ReviewBlocked, "source_scope_mismatch"):
            self.feedback.context(self.principal, "source-one", "cards-master")

    def test_selected_message_never_inherits_same_text_direct_user_authority(self):
        source = load_source(self.root, "source-one")
        source["payload"]["messages"] = [{"text": TEXT, "speaker": "assistant", "fidelity": "forwarded",
                                           "occurred_at": DATE}]
        self.rewrite_source(source)
        path = ["payload", "messages", 0, "text"]
        context = self.context(text_path=path)
        self.assertFalse(context["source_context"]["authorship_verified"])
        self.assertEqual(context["source_context"]["speaker"], "assistant")
        self.record(text_path=path)
        self.assertFalse(self.feedback.training_rows()[0]["source_context"]["authorship_verified"])
        self.assertFalse(self.feedback.training_rows()[0]["source_context"]["confirmation_authority"])

    def test_multiple_message_selectors_are_required_and_independent(self):
        source = load_source(self.root, "source-one")
        source["payload"] = {"messages": [{"text": "Synthetic first message", "occurred_at": DATE},
                                           {"text": "Synthetic second message", "occurred_at": DATE}]}
        self.rewrite_source(source)
        with self.assertRaisesRegex(ReviewBlocked, "feedback_source_text_ambiguous"):
            self.context()
        self.record(text_path=["payload", "messages", 0, "text"])
        self.record(label="archive", command="other-message", text_path=["payload", "messages", 1, "text"])
        self.assertEqual(len(self.feedback.training_rows()), 2)
        for path in (["payload", "messages", True, "text"], ["payload", "messages", 100, "text"], ["payload", "arbitrary"]):
            with self.assertRaises(ReviewBlocked):
                self.context(text_path=path)

    def test_run_policy_and_triage_bindings_cannot_be_forged(self):
        run = self.add_run()
        triage = record_pending(self.root, event_id="source-one", scope="invest", source_digest=run["source_digest"],
            content_digest=run["content_digest"], run_id=run["run_id"], policy_version="jev-typed-v2",
            policy_digest=POLICY_DIGEST, stage="screening", reason_code="screen_needs_evidence")
        request = self.request(triage_id=triage["triage_id"])
        for change in ({"run_id": "fake-run"}, {"policy_digest": "0" * 64}, {"content_digest": "0" * 64}):
            with self.assertRaises(ReviewBlocked):
                self.feedback.record(self.principal, {**request, **change})
        result = self.feedback.record(self.principal, request)
        self.assertEqual(result["triage_id"], triage["triage_id"])

    def test_no_run_feedback_binds_current_policy_and_is_not_inferred_from_candidates(self):
        context = self.context()
        self.assertIsNone(context["bindings"]["run_id"])
        self.assertEqual(context["bindings"]["policy_digest"], POLICY_DIGEST)
        folder = self.root / "memory/quarantine/invest"
        folder.mkdir(parents=True)
        (folder / "commands.jsonl").write_text(json.dumps({"action": "reject", "status": "rejected"}) + "\n")
        self.assertEqual(self.feedback.training_rows(), [])
        self.record(label="keep")
        self.assertEqual(self.feedback.training_rows()[0]["label"], "keep")

    def test_private_redacted_l4_and_cloud_excluded_sources_cannot_be_labelled_or_exported(self):
        original = load_source(self.root, "source-one")
        for changes in ({"privacy_level": "L4"}, {"cloud_eligible": False}, {"token": "synthetic_secret"},
                        {"note": "[REDACTED:CREDENTIAL]"}):
            self.rewrite_source({**original, **changes})
            with self.assertRaisesRegex(ReviewBlocked, "private_source_excluded"):
                self.context()
        self.rewrite_source(original)
        self.record()
        self.rewrite_source({**original, "cloud_eligible": False})
        self.assertEqual(self.feedback.training_rows(), [])

    def test_only_fixed_labels_and_exact_request_fields_are_accepted(self):
        request = self.request()
        for change in ({"label": "confirmed"}, {"label": "reject"}, {"label": "archive_only"},
                       {"label": True}, {"actor_id": owner_auth.ACTOR}, {"notes": "private body"},
                       {"command_id": "../outside"}):
            with self.assertRaises(ReviewBlocked):
                self.feedback.record(self.principal, {**request, **change})
        self.assertFalse((self.root / "memory/feedback").exists())

    def test_missing_time_is_preserved_for_screening_but_invalid_time_and_missing_text_excluded(self):
        original = load_source(self.root, "source-one")
        for index, timestamp in enumerate((None, "2026-09-24", "not-a-date")):
            source = {**original, "event_id": "missing-time-%d" % index, "occurred_at": timestamp}
            append_event(self.root, source)
            context = self.feedback.context(self.principal, source["event_id"], "invest")
            self.feedback.record(self.principal, {**context["bindings"], "label": "keep", "command_id": "missing-time-%d" % index})
        source = {**original, "event_id": "missing-text", "payload": {}}
        append_event(self.root, source)
        context = self.feedback.context(self.principal, "missing-text", "invest")
        self.assertIsNone(context["source_text"])
        self.feedback.record(self.principal, {**context["bindings"], "label": "archive", "command_id": "missing-text"})
        training = self.feedback.training_rows()
        self.assertEqual(len(training), 1)
        self.assertIsNone(training[0]["source_time"])
        self.assertIsNone(training[0]["source_context"]["occurred_at"])
        counts = self.feedback.training_status()
        self.assertEqual((counts["missing_time"], counts["invalid_time"], counts["missing_text"], counts["eligible"]), (1, 2, 1, 1))

    def test_group_keys_link_identical_text_task_and_thread_without_authority_upgrade(self):
        self.record()
        training = self.feedback.training_rows()[0]
        self.assertEqual(training["source_digest"], digest(load_source(self.root, "source-one")))
        self.assertIn("text:" + _content(TEXT), training["group_keys"])
        self.assertIn("task:" + digest("synthetic-task"), training["group_keys"])
        self.assertIn("thread:" + digest("synthetic-thread"), training["group_keys"])
        self.assertIn("raw_event:" + digest("source-one"), training["group_keys"])
        self.assertEqual(training["source_event_type"], "user_input")
        self.assertEqual(training["source_completeness"], load_source(self.root, "source-one").get("completeness"))

    def test_raw_event_group_survives_corrected_text_without_task_or_thread(self):
        source = load_source(self.root, "source-one")
        source.pop("task_id", None)
        source.pop("thread_id", None)
        self.rewrite_source(source)
        self.record()
        before = self.feedback.training_rows()[0]
        source["payload"]["text"] = "A corrected synthetic report should include daily totals."
        self.rewrite_source(source)
        self.assertEqual(self.feedback.training_rows(), [])
        self.record(label="archive", command="corrected-without-thread")
        after = self.feedback.training_rows()[0]
        self.assertNotEqual(before["source_digest"], after["source_digest"])
        self.assertNotEqual(before["content_digest"], after["content_digest"])
        self.assertEqual(set(before["group_keys"]) & set(after["group_keys"]),
                         {"raw_event:" + digest("source-one")})

    def test_corruption_of_latest_record_never_revives_an_old_training_label(self):
        self.record()
        second = self.record(label="archive", command="correction")
        row = json.loads(self.record_path(second).read_text())
        row["label"] = "keep"
        self.record_path(second).write_text(json.dumps(row))
        self.assertEqual(self.feedback.training_rows(), [])
        self.assertEqual(self.feedback.training_status()["invalid_records"], 1)
        self.assertEqual(self.feedback.list_feedback(self.principal)["items"], [])
        with self.assertRaisesRegex(ReviewBlocked, "feedback_integrity_failed"):
            self.context()

    def test_recovery_hold_true_and_malformed_block_writes_readers_remain_read_only(self):
        request = self.request()
        path = self.root / "state/recovery-hold.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        for content in (json.dumps({"hold": True}), "{"):
            path.write_text(content)
            with self.assertRaises(Exception):
                self.feedback.record(self.principal, request)
            self.assertEqual(self.feedback.training_rows(), [])
            self.assertEqual(self.feedback.list_feedback(self.principal)["total"], 0)
            self.assertFalse((self.root / "memory/feedback/items").exists())
        path.write_text(json.dumps({"hold": False}))
        self.assertEqual(self.feedback.record(self.principal, request)["status"], "active")

    def test_source_and_feedback_hardlinks_and_symlinks_fail_closed(self):
        raw = next((self.root / "raw/events").rglob("*.jsonl"))
        linked = self.root / "linked"
        os.link(raw, linked)
        with self.assertRaises(ReviewBlocked):
            self.context()
        linked.unlink()
        item = self.record()
        path = self.record_path(item)
        os.link(path, linked)
        self.assertEqual(self.feedback.training_rows(), [])
        self.assertEqual(self.feedback.list_feedback(self.principal)["invalid_records"], 1)
        linked.unlink()
        path.rename(linked)
        path.symlink_to(linked)
        self.assertEqual(self.feedback.training_rows(), [])
        with self.assertRaises(ReviewBlocked):
            self.context()

    def test_hardlinked_maintenance_lock_is_not_written(self):
        request = self.request()
        path = self.root / "state/maintenance.lock"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("unchanged")
        os.link(path, self.root / "linked")
        with self.assertRaises(ReviewBlocked):
            self.feedback.record(self.principal, request)
        self.assertEqual(path.read_text(), "unchanged")
        self.assertFalse((self.root / "memory/feedback/items").exists())

    def test_concurrent_same_command_produces_one_immutable_record(self):
        request = self.request()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.feedback.record(self.principal, request), range(8)))
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(self.feedback.list_feedback(self.principal)["total"], 1)

    def test_sources_include_archived_machine_outputs_without_source_body_and_paginate(self):
        self.add_run(decision="archive_only", outcome="archive_only")
        other = {**load_source(self.root, "source-one"), "event_id": "source-two"}
        append_event(self.root, other)
        self.add_run(run_id="second-run", source=other)
        first = self.feedback.sources(self.principal, limit=1)
        second = self.feedback.sources(self.principal, limit=1, cursor=first["next_cursor"])
        self.assertEqual(first["total"], 2)
        self.assertIsNone(second["next_cursor"])
        archived = second["items"][0]
        self.assertEqual(archived["decision"], "archive_only")
        self.assertEqual(archived["text_path"], ["payload", "text"])
        self.assertNotIn(TEXT, json.dumps(first) + json.dumps(second))
        self.assertNotIn("DO_NOT_COPY_PRIVATE_MACHINE_BODY", json.dumps(first) + json.dumps(second))

    def test_source_catalog_builds_raw_index_once_instead_of_scanning_per_item(self):
        for i in range(12):
            source = {**load_source(self.root, "source-one"), "event_id": "catalog-%d" % i}
            append_event(self.root, source)
            self.add_run(run_id="run-%d" % i, source=source)
        with patch.object(self.feedback, "_source_index", wraps=self.feedback._source_index) as index, \
                patch("memory_feedback.load_source", side_effect=AssertionError("Per-item RAW rescan")):
            result = self.feedback.sources(self.principal)
        self.assertEqual(result["total"], 12)
        self.assertEqual(index.call_count, 1)

    def test_read_only_import_context_and_training_do_not_create_files(self):
        before = {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        self.context()
        self.feedback.list_feedback(self.principal)
        self.feedback.sources(self.principal)
        self.feedback.training_rows()
        self.feedback.training_status()
        after = {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)

    def corpus_fixture(self, kind="bound"):
        from memory_corpus import inventory, build_event, sha, _selected_time_v1
        parent = {"event_id": "synthetic-parent-" + kind, "agent": "invest", "occurred_at": DATE,
                  "captured_at": DATE}
        if kind == "bound":
            body = b"Synthetic artifact: Alice joins Orion tomorrow."
            content_hash = sha(body)
            obj = self.root / "raw/objects" / content_hash
            obj.parent.mkdir(parents=True, exist_ok=True)
            obj.write_bytes(body)
            manifest = self.root / "raw/manifests/synthetic.jsonl"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(json.dumps({"sha256": content_hash,
                "object_path": str(obj.relative_to(self.root))}) + "\n")
            parent.update(event_type="native_final_output", payload={"native_final_output_sha256": content_hash})
        else:
            parent.update(event_type="tool_result", payload={"result": "Synthetic legacy: Alice joins Orion tomorrow.",
                "record_source": "codex_log_parse"})
        parent_path = self.root / ("raw/events/parent-" + kind + ".jsonl")
        parent_path.write_text(json.dumps(parent) + "\n")
        item = next(x for x in inventory(self.root)["items"] if x["route"] == "candidate"
                    and x.get("event_id") == parent["event_id"]
                    and (kind != "bound" or x.get("event_type") == "bound_object"))
        if kind == "legacy":
            item["source_time"] = _selected_time_v1(parent, item["text_selector"])
            item["has_original_time"] = True
        event = build_event(self.root, item)
        append_event(self.root, event, relative_path="events/canonical-" + kind + ".jsonl")
        return parent_path, parent, load_source(self.root, event["event_id"])

    def old_corpus_version(self, event, kind):
        item = event["payload"]["corpus_item"]
        old = copy.deepcopy(event)
        old["event_id"] = "ev-corpus-" + digest([item["item_id"], item["source_digest"], item["content_sha256"]])[:32]
        old.update(occurred_at=DATE, time_basis="source_timestamp", source_time_field=["occurred_at"])
        old["payload"].pop("artifact_receipt" if kind == "bound" else "legacy_time_receipt")
        append_event(self.root, old, relative_path="events/old-" + kind + ".jsonl")
        return load_source(self.root, old["event_id"])

    def test_current_corpus_context_label_and_training_preserve_unknown_time(self):
        for kind in ("bound", "legacy"):
            with self.subTest(kind=kind):
                _, _, event = self.corpus_fixture(kind)
                context = self.feedback.context(self.principal, event["event_id"], "invest")
                self.assertIsNone(context["source_times"]["occurred_at"])
                self.assertFalse(context["source_context"]["authorship_verified"])
                result = self.feedback.record(self.principal, {**context["bindings"], "label": "keep",
                    "command_id": "current-corpus-" + kind})
                self.assertEqual(result["status"], "active")
                self.assertTrue(any(x["feedback_id"] == result["feedback_id"] for x in self.feedback.training_rows()))

    def test_old_corpus_time_versions_cannot_be_displayed_or_labelled(self):
        for kind in ("bound", "legacy"):
            with self.subTest(kind=kind):
                _, _, event = self.corpus_fixture(kind)
                current = self.feedback.context(self.principal, event["event_id"], "invest")
                old = self.old_corpus_version(event, kind)
                with self.assertRaisesRegex(ReviewBlocked, "^corpus_original_source_changed_or_unavailable$"):
                    self.feedback.context(self.principal, old["event_id"], "invest")
                request = {**current["bindings"], "source_event_id": old["event_id"],
                    "source_digest": digest(old), "label": "keep", "command_id": "old-corpus-" + kind}
                with self.assertRaisesRegex(ReviewBlocked, "^corpus_original_source_changed_or_unavailable$"):
                    self.feedback.record(self.principal, request)
        self.assertEqual(self.feedback.training_rows(), [])

    def test_prior_feedback_on_old_corpus_is_invalidated_and_removed_from_training(self):
        _, _, event = self.corpus_fixture()
        old = self.old_corpus_version(event, "bound")
        # Model only the old local verifier gap while producing an authentic
        # synthetic-owner record. Production credentials/records are untouched.
        with patch("memory_corpus.verify_canonical", return_value={"verified": True}):
            context = self.feedback.context(self.principal, old["event_id"], "invest")
            result = self.feedback.record(self.principal, {**context["bindings"], "label": "keep",
                "command_id": "historical-gap-feedback"})
        before = self.record_path(result).read_bytes()
        self.assertEqual(self.feedback.training_rows(), [])
        self.assertEqual(self.feedback.training_status()["invalidated_sources"], 1)
        self.assertEqual(self.feedback.list_feedback(self.principal)["items"][0]["status"], "invalidated")
        self.assertEqual(self.record_path(result).read_bytes(), before)

    def test_corpus_parent_change_or_cloud_false_invalidates_context_training_and_catalog_only_that_item(self):
        path, parent, event = self.corpus_fixture()
        context = self.feedback.context(self.principal, event["event_id"], "invest")
        request = {**context["bindings"], "label": "keep", "command_id": "corpus-parent-label"}
        self.feedback.record(self.principal, request)
        self.add_run(run_id="corpus-run", source=event, text=event["payload"]["text"])
        self.add_run(run_id="ordinary-run")
        canonical_digest = digest(load_source(self.root, event["event_id"]))
        for changes in ({"task_id": "changed-parent-provenance"}, {"cloud_eligible": False}):
            with self.subTest(changes=changes):
                path.write_text(json.dumps({**parent, **changes}) + "\n")
                with self.assertRaisesRegex(ReviewBlocked, "^corpus_original_source_changed_or_unavailable$"):
                    self.feedback.context(self.principal, event["event_id"], "invest")
                with self.assertRaisesRegex(ReviewBlocked, "^corpus_original_source_changed_or_unavailable$"):
                    self.feedback.record(self.principal, request)
                self.assertEqual(self.feedback.training_rows(), [])
                self.assertEqual(self.feedback.training_status()["invalidated_sources"], 1)
                catalog = self.feedback.sources(self.principal)
                self.assertEqual([x["source_event_id"] for x in catalog["items"]], ["source-one"])
                self.assertEqual(catalog["invalid_records"], 1)
                self.assertEqual(digest(load_source(self.root, event["event_id"])), canonical_digest)

    def test_corpus_original_body_change_blocks_even_when_materialized_raw_is_unchanged(self):
        _, _, event = self.corpus_fixture()
        obj = self.root / event["payload"]["corpus_item"]["source"]["path"]
        obj.write_bytes(b"Synthetic altered body")
        with self.assertRaisesRegex(ReviewBlocked, "^corpus_original_source_changed_or_unavailable$"):
            self.feedback.context(self.principal, event["event_id"], "invest")

    def test_corpus_verification_failures_are_sanitized_and_original_sources_still_work(self):
        _, _, event = self.corpus_fixture()
        for error in (ValueError("private body sentinel"), OSError("private path sentinel")):
            with patch("memory_corpus.verify_canonical", side_effect=error):
                with self.assertRaisesRegex(ReviewBlocked, "^corpus_original_source_changed_or_unavailable$"):
                    self.feedback.context(self.principal, event["event_id"], "invest")
        with patch("memory_corpus.verify_canonical", side_effect=AssertionError("Not a corpus source")):
            self.assertEqual(self.context()["source_text"], TEXT)
            self.record()
            self.assertEqual(self.feedback.training_rows()[0]["source_text"], TEXT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
