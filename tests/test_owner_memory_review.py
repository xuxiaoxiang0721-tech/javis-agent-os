"""P2 owner-bound memory tests; fake owner credentials exist only in TemporaryDirectory."""
import asyncio
import copy
import hashlib
import importlib
import json
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tools/memory-adapter"))
from memory_review import MemoryReview, ReviewBlocked
from javis_memory_adapter.review_policy import digest, official_group, owner_confirmed, semantic
from javis_memory_adapter.structured_store import StructuredFact, StructuredStore
from javis_memory_adapter.ledger_query import query_effective, query_known, apply_state_change
from javis_memory_adapter.type_b import rebuild_group_from_store
from javis_memory_adapter.adapter import MemoryAdapter
from javis_memory_adapter.models import QueryResult, FactRecord, ConflictStatus
import task_memory
from raw_storage import append_event

class OwnerMemoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="javis-owner-review-test-")
        self.root = Path(self.tmp.name)
        self.review = MemoryReview(self.root)
        self.principal = object()
        self.assertion = "TEST-ONLY-PRIVATE-ASSERTION"
        self.proofs = {}
        self.counter = 0
        self.fake = types.ModuleType("owner_auth")
        def principal(root, value):
            self.assertEqual(root, self.root)  # Never authorize a real root.
            if value is not self.principal:
                raise ValueError("not authenticated")
            return {"actor_id": "test-owner"}
        def decision(root, assertion, binding):
            self.assertEqual(root, self.root)
            if assertion != self.assertion:
                raise ValueError("bad assertion")
            self.counter += 1
            proof = {"actor_id": "test-owner", "proof_id": "test-proof-" + str(self.counter),
                     "binding_hash": digest(binding)}
            self.proofs[proof["proof_id"]] = (copy.deepcopy(binding), proof)
            return proof
        def recorded(root, proof_id, binding):
            self.assertEqual(root, self.root)
            old, proof = self.proofs[proof_id]
            if old != binding:
                raise ValueError("binding changed")
            return copy.deepcopy(proof)
        self.fake.verify_principal = principal
        self.fake.verify_decision = decision
        self.fake.verify_recorded_decision = recorded
        self.module_patch = patch.dict(sys.modules, {"owner_auth": self.fake})
        self.module_patch.start()
        self.source("input-one", "remember blue")
        self.candidate = self.review.propose("cards-master", self.fact())

    def tearDown(self):
        self.module_patch.stop()
        self.tmp.cleanup()

    def source(self, eid, text):
        append_event(self.root, {"event_id": eid, "task_id": "task-one", "event_type": "user_input",
            "agent": "cards-master", "payload": {"text": text, "is_original_user_input": True}})

    def fact(self, **kwargs):
        row = dict(fact_id="fact_one", subject_id="user", subject_label="user", predicate="color",
                   value="blue", unit=None, valid_from="2026-01-01T00:00:00+00:00",
                   valid_to=None, recorded_at="2026-01-01T00:00:00+00:00",
                   source_event_id="input-one", raw_refs=["input-one"], status="extracted", notes=[])
        row.update(kwargs)
        return StructuredFact(**row)

    def request(self, action="confirm", candidate=None, command="command-one", **extra):
        row = candidate or self.candidate
        return dict(action=action, candidate_id=row["candidate_id"], version_digest=row["version_digest"],
                    scope=row["scope"], command_id=command, **extra)

    def confirm(self, candidate=None, command="command-one"):
        return self.review.review(self.principal, self.request(candidate=candidate, command=command), self.assertion)

    def store(self):
        return StructuredStore(self.root / "memory/structured/cards-master")

    def test_candidate_is_isolated_and_idempotent(self):
        self.assertFalse((self.root / "memory/structured").exists())
        self.assertEqual(self.review.propose("cards-master", self.fact()), self.candidate)
        self.assertEqual(len(self.review.list_pending(self.principal)), 1)
        self.assertEqual(self.candidate["status"], "pending_review")

    def test_missing_auth_module_fails_closed(self):
        with patch.dict(sys.modules, {"owner_auth": None}):
            with self.assertRaises(ReviewBlocked):
                self.confirm()
        self.assertFalse((self.root / "memory/structured").exists())

    def test_body_identity_boolean_and_bad_proof_rejected(self):
        for principal in ({"actor_id": "user", "verified": True}, True, "user"):
            with self.assertRaises(ReviewBlocked):
                self.review.review(principal, self.request(), self.assertion)
        for result in (True, {"actor_id": "user", "proof_id": "fake", "binding_hash": digest(self.request())}):
            with patch.object(self.fake, "verify_decision", return_value=result):
                with self.assertRaises(ReviewBlocked):
                    self.confirm()

    def test_wrong_assertion_and_stale_version_rejected(self):
        with self.assertRaises(ReviewBlocked):
            self.review.review(self.principal, self.request(), {"verified": True})
        req = self.request(); req["version_digest"] = "a" * 64
        with self.assertRaises(ReviewBlocked):
            self.review.review(self.principal, req, self.assertion)
        self.assertEqual(self.counter, 0)

    def test_confirm_requires_recorded_proof_and_omits_assertion(self):
        result = self.confirm()
        fact = self.store().get_fact("fact_one")
        self.assertTrue(owner_confirmed(self.store(), fact))
        self.assertEqual(result["status"], "confirmed")
        for p in self.root.rglob("*.jsonl"):
            self.assertNotIn(self.assertion, p.read_text())
        self.proofs.clear()
        self.assertFalse(owner_confirmed(self.store(), fact))
        self.assertEqual(query_effective(self.store(), datetime.now(timezone.utc))["facts"], [])

    def test_full_version_digest_covers_review_fields(self):
        original = self.review.list_pending(self.principal)[0]
        payload = original["payload"]
        for key, value in (("subject_id", "other"), ("subject_label", "Other"), ("predicate", "other"),
                           ("value", "red"), ("unit", "kg"), ("valid_from", "2025-01-01T00:00:00Z"),
                           ("valid_to", "2027-01-01T00:00:00Z"), ("source_event_id", "other"),
                           ("raw_refs", ["other"]), ("recorded_at", "2026-02-01T00:00:00Z")):
            changed = copy.deepcopy(payload); changed["effects"][-1][key] = value
            self.assertNotEqual(digest(changed), original["version_digest"], key)
        changed = copy.deepcopy(payload); changed["scope"] = "shared"
        self.assertNotEqual(digest(changed), original["version_digest"])

    def test_modify_is_new_pending_version_and_old_approval_rejected(self):
        req = self.request("modify", replacement={"value": "red"})
        binding = self.review.binding_for(self.principal, req)
        self.assertIn("replacement_digest", binding)
        result = self.review.review(self.principal, req, self.assertion)
        self.assertEqual(result["status"], "pending_review")
        self.assertFalse((self.root / "memory/structured").exists())
        with self.assertRaises(ReviewBlocked):
            self.confirm(command="stale-command")
        new = self.review.list_pending(self.principal)[0]
        self.assertEqual(new["payload"]["effects"][-1]["value"], "red")
        self.confirm(new, "confirm-new")
        self.assertEqual(len(self.store().load_facts()), 1)

    def test_reject_cannot_be_confirmed(self):
        self.review.review(self.principal, self.request("reject"), self.assertion)
        with self.assertRaises(ReviewBlocked):
            self.confirm(command="late-confirm")
        self.assertEqual(self.review.list_pending(self.principal), [])

    def test_command_replay_idempotent_and_collision_rejected(self):
        first = self.confirm()
        paths = {p: p.read_bytes() for p in self.root.rglob("*.jsonl")}
        self.assertEqual(self.confirm(), first)
        self.assertEqual({p: p.read_bytes() for p in paths}, paths)
        with self.assertRaises(ReviewBlocked):
            self.review.review(self.principal, self.request("reject"), self.assertion)
        self.assertEqual(self.counter, 1)

    def test_interrupted_commit_replay_finishes_without_new_assertion(self):
        with patch.object(StructuredStore, "upsert_fact", side_effect=OSError("synthetic interruption")):
            with self.assertRaises(OSError):
                self.confirm()
        result = self.review.review(self.principal, self.request(), None)
        self.assertEqual(result["status"], "confirmed")
        self.assertTrue(owner_confirmed(self.store(), self.store().get_fact("fact_one")))
        self.assertEqual(self.counter, 1)

    def test_source_mutation_blocks_confirmation_and_recall(self):
        self.confirm()
        path = next((self.root / "raw/events").glob("*.jsonl"))
        rows = [json.loads(x) for x in path.read_text().splitlines()]
        rows[0]["payload"]["text"] = "changed after review"
        path.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
        self.assertFalse(owner_confirmed(self.store(), self.store().get_fact("fact_one")))

    def test_duplicate_raw_id_is_ambiguous(self):
        path = next((self.root / "raw/events").glob("*.jsonl"))
        row = json.loads(path.read_text().splitlines()[0]); row["payload"]["text"] = "different"
        with path.open("a") as out: out.write(json.dumps(row) + "\n")
        with self.assertRaises(ReviewBlocked):
            self.confirm()

    def test_legacy_and_direct_confirm_bypasses_closed(self):
        store = self.store()
        with self.assertRaises(ReviewBlocked):
            store.upsert_fact(self.fact(status="confirmed", confirmation_event_id="fake"))
        with self.assertRaises(ReviewBlocked):
            store.write_confirmation(confirmation_event_id="fake", fact_id="fact_one",
                                     confirmed_at=datetime.now(timezone.utc), actor="user")
        with self.assertRaises(ReviewBlocked):
            apply_state_change(store, subject_id="user", subject_label="user", predicate="color",
                old_value="blue", new_value="red", unit=None, change_at=datetime.now(timezone.utc),
                source_event_id="input-one", raw_refs=["input-one"], confirmation_event_id="fake")
        # Existing legacy content is retained on disk and excluded without mutation.
        legacy = self.fact(status="confirmed", confirmation_event_id="legacy").to_dict()
        store.facts_path.write_text(json.dumps(legacy) + "\n")
        before = store.facts_path.read_bytes()
        self.assertEqual(query_effective(store, datetime.now(timezone.utc))["facts"], [])
        self.assertEqual(store.facts_path.read_bytes(), before)
        self.assertEqual(task_memory._bridge_legacy(self.root, "cards-master", {}), ([], 0))

    def test_correction_closes_old_version_with_owner_proof(self):
        self.confirm()
        self.source("input-two", "update red")
        fact = self.fact(fact_id="fact_two", value="red", source_event_id="input-two",
                         raw_refs=["input-two"], valid_from="2026-02-01T00:00:00+00:00")
        candidate = self.review.propose("cards-master", fact, operation="state_change", target_fact_id="fact_one")
        self.assertEqual(self.store().get_fact("fact_one").value, "blue")
        self.confirm(candidate, "correct-one")
        old, new = self.store().get_fact("fact_one"), self.store().get_fact("fact_two")
        self.assertEqual(old.status, "superseded")
        self.assertTrue(owner_confirmed(self.store(), old))
        self.assertTrue(owner_confirmed(self.store(), new))
        self.assertEqual(len(query_known(self.store(), datetime.now(timezone.utc))["corrections_known"]), 1)
        self.assertEqual(query_effective(self.store(), datetime(2026, 1, 10, tzinfo=timezone.utc))["facts"][0]["value"], "blue")
        self.assertEqual(query_effective(self.store(), datetime.now(timezone.utc))["facts"][0]["value"], "red")
        self.confirm()  # Older command must not resurrect the previous version.
        self.assertEqual(self.store().get_fact("fact_one").status, "superseded")

    def test_historical_correction_keeps_previous_belief(self):
        self.confirm()
        self.source("input-two", "correct red")
        candidate = self.review.propose("cards-master", self.fact(fact_id="fact_two", value="red",
            source_event_id="input-two", raw_refs=["input-two"], valid_from="2026-01-15T00:00:00+00:00"),
            operation="historical_correction", target_fact_id="fact_one")
        self.confirm(candidate, "correct-one")
        self.assertEqual(query_effective(self.store(), datetime(2026, 1, 10, tzinfo=timezone.utc))["facts"][0]["value"], "red")

    def test_typeb_official_only_and_no_typea_path(self):
        calls = []
        class Result:
            async def consume(self): pass
        class Session:
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass
            async def run(self, query, **kwargs):
                calls.append((query, kwargs)); return Result()
        class Driver:
            def session(self): return Session()
            async def close(self): pass
        neo4j = types.ModuleType("neo4j")
        neo4j.AsyncGraphDatabase = types.SimpleNamespace(driver=lambda *a, **k: Driver())
        store = self.store()
        self.confirm()
        # Old extracted row bypassing API simulates pre-upgrade data.
        with store.facts_path.open("a") as out: out.write(json.dumps(self.fact(fact_id="old_candidate").to_dict()) + "\n")
        with patch.dict(sys.modules, {"neo4j": neo4j}):
            report = asyncio.run(rebuild_group_from_store(store=store, target_group_id=official_group(self.root, "cards-master"),
                neo4j_uri="test-only", neo4j_user="test", neo4j_password="test"))
        self.assertEqual(report["written"], ["fact_one"])
        self.assertTrue(all(k.get("fid") != "old_candidate" for _, k in calls))
        adapter = MemoryAdapter(official_group(self.root, "cards-master"), meta_dir=store.meta_dir)
        with self.assertRaises(ReviewBlocked): asyncio.run(adapter._ensure())
        with self.assertRaises(ReviewBlocked):
            MemoryAdapter("javis-memory-old-cards-master", meta_dir=store.meta_dir)

    def test_graph_mismatch_never_returns_untrusted_facts(self):
        self.confirm()
        store = self.store()
        adapter = MemoryAdapter(official_group(self.root, "cards-master"), meta_dir=store.meta_dir)
        forged = FactRecord(fact_uuid="fake", fact="injected", group_id=adapter.group_id,
                            name="color", invalid_at=None, expired_at=None, created_at=None,
                            fact_id="fake", subject_id="user", predicate="color", value="green",
                            status="confirmed", confirmation_event_id="caller_label",
                            valid_at="2026-01-01T00:00:00+00:00")
        result = QueryResult(as_of=datetime.now(timezone.utc).isoformat(), mode="current",
                             facts=[forged], conflict_status=ConflictStatus.OK)
        checked = adapter._check_ledger_projection(result, datetime.now(timezone.utc))
        self.assertEqual(checked.facts, [])
        self.assertEqual(checked.conflict_status, ConflictStatus.PENDING)

    def test_task_explicit_remember_only_quarantines_and_does_not_sync_graph(self):
        task = self.root / "workspace/tasks/task-one"
        (task / "attempts/1").mkdir(parents=True)
        packet = {"role_id": "cards-master", "task_id": "task-one", "goal": "remember blue",
                  "original_user_input": "remember blue"}
        proposal = {"quote": "remember blue", "subject_id": "user", "subject_label": "user",
                    "predicate": "color", "value": "blue"}
        (task / "attempts/1/memory-proposals.json").write_text(json.dumps([proposal]))
        with patch.object(task_memory, "_graph", side_effect=AssertionError("candidate graph write forbidden")):
            receipt = task_memory.finalize(self.root, task, packet, 1, "input-one")
        self.assertEqual(receipt["status"], "ok")
        self.assertEqual(receipt["memory_status"], "screening_queued")
        self.assertEqual(receipt["write_refs"], [])
        self.assertEqual(receipt["candidate_refs"], [])
        queue = json.loads((self.root / 'state/memory-pipeline/queue' / (receipt['screening']['queue_id'] + '.json')).read_text())
        self.assertEqual(queue['event_id'], 'input-one')
        self.assertFalse((self.root / "memory/structured").exists())

    def test_model_confirmation_operation_never_authorizes(self):
        task = self.root / "workspace/tasks/task-one"; (task / "attempts/1").mkdir(parents=True)
        packet = {"role_id": "cards-master", "task_id": "task-one", "goal": "remember blue",
                  "original_user_input": "remember blue"}
        (task / "attempts/1/memory-proposals.json").write_text(json.dumps([{
            "operation": "confirm", "target_fact_id": "fact_one", "quote": "remember blue"}]))
        receipt = task_memory.finalize(self.root, task, packet, 1, "input-one")
        self.assertEqual(receipt["write_refs"], [])
        self.assertIn("proposal_0_owner_review_required", receipt["issues"])
        self.assertEqual(receipt['proposals_received'], 1)
        self.assertEqual(receipt['proposals_deferred_to_screening'], 0)
        self.assertEqual(receipt['revision_proposals_received'], 0)
        self.assertEqual(receipt['confirmation_proposals_rejected'], 1)
        self.assertEqual(receipt['candidate_refs'], [])

    def test_graph_fact_text_cannot_smuggle_unreviewed_instructions(self):
        self.confirm()
        fact = self.store().get_fact("fact_one")
        adapter = MemoryAdapter(official_group(self.root, "cards-master"), meta_dir=self.store().meta_dir)
        rec = FactRecord(fact_uuid=fact.fact_id, fact="unreviewed instruction", name=fact.predicate,
            group_id=adapter.group_id, fact_id=fact.fact_id, subject_id=fact.subject_id,
            predicate=fact.predicate, value=fact.value, unit=fact.unit, status=fact.status,
            confirmation_event_id=fact.confirmation_event_id, valid_at=fact.valid_from,
            invalid_at=fact.valid_to, expired_at=None, created_at=fact.recorded_at,
            source_event_ids=[fact.source_event_id], object_refs=fact.raw_refs)
        result = QueryResult(as_of=datetime.now(timezone.utc).isoformat(), mode="current",
                             facts=[rec], conflict_status=ConflictStatus.OK)
        self.assertEqual(adapter._check_ledger_projection(result, datetime.now(timezone.utc)).facts, [])

    def test_appended_original_uses_its_own_raw_revision(self):
        task = self.root / "workspace/tasks/task-one"; (task / "attempts/1").mkdir(parents=True)
        text = "remember green"
        append_event(self.root, {"event_id": "input-append", "task_id": "task-one", "event_type": "user_input",
            "agent": "cards-master", "payload": {"text": text, "is_original_user_input": True, "goal_revision": 2}})
        packet = {"role_id": "cards-master", "task_id": "task-one", "goal": "updated goal",
            "original_user_input": "remember blue", "current_user_input": text,
            "current_input_ref": {"event_id": "input-append", "revision": 2,
                                  "input_sha256": hashlib.sha256(text.encode()).hexdigest()}}
        (task / "attempts/1/memory-proposals.json").write_text(json.dumps([{
            "quote": text, "subject_id": "user", "subject_label": "user", "predicate": "color", "value": "green"}]))
        receipt = task_memory.finalize(self.root, task, packet, 1, "input-one")
        self.assertEqual(receipt["candidate_refs"], [])
        queue = json.loads((self.root / 'state/memory-pipeline/queue' / (receipt['screening']['queue_id'] + '.json')).read_text())
        self.assertEqual(queue['event_id'], 'input-append')
        packet["current_user_input"] = "remember forged"
        with self.assertRaises(ValueError): task_memory.finalize(self.root, task, packet, 1, "input-one")

    def test_current_input_without_source_binding_is_not_trusted(self):
        task = self.root / "workspace/tasks/task-one"
        packet = {"role_id": "cards-master", "task_id": "task-one", "goal": "blue",
            "original_user_input": "remember blue", "current_user_input": "remember forged"}
        with self.assertRaises(ValueError): task_memory._input(self.root, task, packet, 1, "input-one")

    def test_trace_and_entities_reverify_owner_proof(self):
        self.confirm()
        adapter = MemoryAdapter(official_group(self.root, "cards-master"), meta_dir=self.store().meta_dir)
        self.assertTrue(asyncio.run(adapter.trace_sources("fact_one"))["ok"])
        self.assertEqual(len(asyncio.run(adapter.list_entities())), 1)
        self.proofs.clear()
        self.assertFalse(asyncio.run(adapter.trace_sources("fact_one"))["ok"])
        self.assertEqual(asyncio.run(adapter.list_entities()), [])

    def test_all_raw_refs_must_resolve_and_owner_binding_cannot_be_reused(self):
        with self.assertRaises(ReviewBlocked):
            self.review.propose("cards-master", self.fact(raw_refs=["missing-source"]))
        with patch.object(self.fake, "verify_decision", return_value={
                "actor_id": "test-owner", "proof_id": "wrong", "binding_hash": "0" * 64}):
            with self.assertRaises(ReviewBlocked): self.confirm()

    def test_two_pending_corrections_cannot_apply_to_stale_target(self):
        self.confirm()
        self.source("input-two", "red or green")
        one = self.review.propose("cards-master", self.fact(fact_id="fact_two", value="red",
            source_event_id="input-two", raw_refs=["input-two"], valid_from="2026-02-01T00:00:00+00:00"),
            operation="state_change", target_fact_id="fact_one")
        two = self.review.propose("cards-master", self.fact(fact_id="fact_three", value="green",
            source_event_id="input-two", raw_refs=["input-two"], valid_from="2026-02-01T00:00:00+00:00"),
            operation="state_change", target_fact_id="fact_one")
        self.confirm(one, "correct-one")
        with self.assertRaises(ReviewBlocked): self.confirm(two, "correct-two")
        self.assertIsNone(self.store().get_fact("fact_three"))

    def test_symlink_and_hardlink_candidate_paths_rejected(self):
        path = self.root / "memory/quarantine/cards-master/candidates.jsonl"
        content = path.read_bytes(); path.unlink()
        target = self.root / "outside.jsonl"; target.write_bytes(content)
        path.symlink_to(target)
        with self.assertRaises(ReviewBlocked): self.review.list_pending(self.principal)
        path.unlink(); path.hardlink_to(target)
        with self.assertRaises(ReviewBlocked): self.review.list_pending(self.principal)

    def test_unknown_validity_is_reviewable_without_becoming_current(self):
        candidate = self.review.propose("cards-master", self.fact(fact_id="fact_unknown", valid_from=None))
        self.assertEqual(candidate["status"], "pending_review")
        self.assertEqual(self.store().load_facts(), [])
        self.confirm(candidate, "confirm-unknown")
        saved = self.store().get_fact("fact_unknown")
        self.assertIsNone(saved.valid_from)
        self.assertIn("validity_unknown_not_current", saved.notes)
        self.assertTrue(owner_confirmed(self.store(), saved))
        now = datetime.now(timezone.utc)
        self.assertEqual(query_effective(self.store(), now)["facts"], [])
        self.assertEqual([f["fact_id"] for f in query_known(self.store(), now)["facts"]], ["fact_unknown"])

    def test_unknown_validity_does_not_allow_malformed_dates(self):
        for field in ("valid_from", "valid_to"):
            for value in ("", "not-a-date", "null"):
                with self.subTest(field=field, value=value), self.assertRaisesRegex(ReviewBlocked, "invalid_fact_interval"):
                    self.review.propose("cards-master", self.fact(**{field: value}))

    def test_temporal_correction_requires_known_boundaries(self):
        candidate = self.review.propose("cards-master", self.fact(fact_id="fact_unknown", valid_from=None))
        self.confirm(candidate, "confirm-unknown")
        for operation in ("state_change", "historical_correction"):
            with self.subTest(operation=operation), self.assertRaisesRegex(ReviewBlocked, "correction_requires_known_validity"):
                self.review.propose("cards-master", self.fact(fact_id="fact_replacement"),
                    operation=operation, target_fact_id="fact_unknown")
        self.confirm(self.candidate, "confirm-known")
        with self.assertRaisesRegex(ReviewBlocked, "correction_requires_known_validity"):
            self.review.propose("cards-master", self.fact(fact_id="fact_no_boundary", valid_from=None),
                operation="state_change", target_fact_id="fact_one")

if __name__ == "__main__":
    unittest.main(verbosity=2)
