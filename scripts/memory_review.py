"""Quarantined proposals and content-bound owner review.

Only owner_auth can authorize a decision. Ordinary tasks call propose(), which
never writes the formal ledger or graph. No authentication assertion is stored.
"""
from __future__ import annotations
import copy
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_ROOT / "tools/memory-adapter"))
from javis_memory_adapter.structured_store import StructuredFact, StructuredStore
from javis_memory_adapter.review_policy import (
    SCHEMA, ReviewBlocked, digest, guarded_path, read_rows, safe_id, semantic,
    source_digests, validate_payload_sources, verify_principal, verified_proof, owner_confirmed,
)
from javis_memory_adapter.validity import parse_ts
from raw_policy import redact
from runtime_io import lock

def _now():
    return datetime.now(timezone.utc).isoformat()

class MemoryReview:
    def __init__(self, root):
        self.root = Path(root).resolve()

    def _path(self, rel):
        return guarded_path(self.root, self.root / rel)

    def _rows(self, rel):
        return read_rows(self.root, self._path(rel))

    def _append(self, rel, row):
        path = self._path(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        guarded_path(self.root, path)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            if os.fstat(stream.fileno()).st_nlink != 1:
                raise ReviewBlocked("hardlinked_memory_file")
            stream.write(json.dumps(row, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")
            stream.flush(); os.fsync(stream.fileno())

    def _lock(self):
        return lock(self._path("state/locks/memory-review.lock"))

    def _store(self, scope):
        return StructuredStore(self._path("memory/structured/" + safe_id(scope)))

    def _candidate_rel(self, scope):
        return "memory/quarantine/" + safe_id(scope) + "/candidates.jsonl"

    def _current(self, scope, candidate_id):
        safe_id(candidate_id)
        rows = [r for r in self._rows(self._candidate_rel(scope)) if r.get("candidate_id") == candidate_id]
        if not rows:
            raise ReviewBlocked("candidate_not_found")
        row = rows[-1]
        if digest(row["payload"]) != row["version_digest"] or row["payload"]["scope"] != scope:
            raise ReviewBlocked("candidate_integrity_failed")
        return row

    def _build_payload(self, scope, fact, operation="append", target_fact_id=None):
        safe_id(scope)
        row = semantic(fact)
        # Callers cannot submit approval or graph-sync metadata.
        if not isinstance(row["value"], (str, int, float, bool)) or len(str(row["value"])) > 1600:
            raise ReviewBlocked("invalid_fact_value")
        for name in ("fact_id", "predicate", "source_event_id"):
            safe_id(row[name])
        if not isinstance(row["subject_id"], str) or not re.fullmatch(r"[A-Za-z0-9_:-]{1,160}", row["subject_id"]):
            raise ReviewBlocked("invalid_subject_id")
        if (not isinstance(row["subject_label"], str) or not row["subject_label"]
                or len(row["subject_label"]) > 100):
            raise ReviewBlocked("invalid_subject_label")
        if row["unit"] is not None and (not isinstance(row["unit"], str) or len(row["unit"]) > 40):
            raise ReviewBlocked("invalid_unit")
        if not isinstance(row["raw_refs"], list) or any(not isinstance(x, str) for x in row["raw_refs"]):
            raise ReviewBlocked("invalid_source_refs")
        start, end = parse_ts(row["valid_from"]), parse_ts(row["valid_to"])
        if ((row["valid_from"] is not None and start is None)
                or (row["valid_to"] is not None and end is None)
                or (start is not None and end is not None and end <= start)
                or parse_ts(row["recorded_at"]) is None):
            raise ReviewBlocked("invalid_fact_interval")
        if operation not in ("append", "state_change", "historical_correction"):
            raise ReviewBlocked("invalid_memory_operation")
        row.update(status="confirmed", superseded_by=None, supersedes=None, revision_of=None)
        row["notes"] = sorted(set(row.get("notes") or []))
        if not all(isinstance(n, str) and len(n) <= 200 for n in row["notes"]):
            raise ReviewBlocked("invalid_fact_notes")
        # Unknown validity can be reviewed and remembered without inventing a
        # start date. Event-time retrieval still excludes it as unknown.
        if start is None:
            row["notes"] = sorted(set(row["notes"]) | {"validity_unknown_not_current"})
        sources = {row["source_event_id"], *row["raw_refs"]}
        effects = [row]
        targets = []
        if operation != "append":
            if not target_fact_id:
                raise ReviewBlocked("correction_target_required")
            target = self._store(scope).get_fact(safe_id(target_fact_id))
            if target is None or not owner_confirmed(self._store(scope), target):
                raise ReviewBlocked("correction_target_not_owner_confirmed")
            old = semantic(target)
            if (target.status != "confirmed" or target.subject_id != row["subject_id"]
                    or target.predicate != row["predicate"] or target.unit != row["unit"]):
                raise ReviewBlocked("correction_target_mismatch")
            if start is None or parse_ts(target.valid_from) is None:
                raise ReviewBlocked("correction_requires_known_validity")
            targets.append({"fact_id": target.fact_id, "semantic_digest": digest(old)})
            sources.update([target.source_event_id, *(target.raw_refs or [])])
            prior = copy.deepcopy(old)
            prior.update(status="superseded", superseded_by=row["fact_id"])
            row["supersedes"] = target.fact_id
            if operation == "state_change":
                if start <= parse_ts(target.valid_from) or (target.valid_to and start >= parse_ts(target.valid_to)):
                    raise ReviewBlocked("state_change_outside_current_interval")
                prior["valid_to"] = row["valid_from"]
            else:
                if not (parse_ts(target.valid_from) <= start and (not target.valid_to or start < parse_ts(target.valid_to))):
                    raise ReviewBlocked("correction_outside_target_interval")
                row["valid_from"], row["valid_to"] = target.valid_from, target.valid_to
                row["revision_of"] = target.fact_id
                prior["notes"] = list(prior["notes"] or []) + ["historically_corrected"]
            effects = [prior, row]
        payload = {"schema": SCHEMA, "scope": scope, "operation": operation,
                   "target_versions": targets, "effects": effects,
                   "source_digests": source_digests(self.root, sources)}
        _, changes = redact(payload)
        if changes or "[REDACTED:" in json.dumps(payload):
            raise ReviewBlocked("sensitive_memory_excluded")
        digest(payload)  # Also rejects NaN/Infinity and unsupported objects.
        return payload

    def propose(self, scope, fact, *, operation="append", target_fact_id=None):
        """Quarantine a proposal. This API never accepts an authentication flag."""
        with self._lock():
            payload = self._build_payload(scope, fact, operation, target_fact_id)
            version = digest(payload)
            cid = "candidate_" + version[:32]
            rel = self._candidate_rel(scope)
            old = [r for r in self._rows(rel) if r.get("candidate_id") == cid]
            if old:
                return self._reference(old[-1])
            row = {"candidate_id": cid, "scope": scope, "version_digest": version, "payload": payload,
                   "status": "pending_review", "created_at": _now()}
            self._append(rel, row)
            return self._reference(row)

    def _reference(self, row):
        effect = row["payload"]["effects"][-1]
        return {"candidate_id": row["candidate_id"], "version_digest": row["version_digest"],
                "scope": row["payload"]["scope"], "fact_id": effect["fact_id"],
                "source_event_id": effect["source_event_id"], "raw_refs": effect["raw_refs"],
                "status": row["status"], "confirmation_event_id": None,
                "graph_sync_status": "quarantined",
                "path": str(self._path(self._candidate_rel(row["payload"]["scope"])))}

    def list_pending(self, principal):
        verify_principal(self.root, principal)
        from memory_autoreview import MemoryAutoreview
        resolved = MemoryAutoreview(self.root).resolved()
        with self._lock():
            output = []
            base = self._path("memory/quarantine")
            for p in sorted(base.glob("*/candidates.jsonl")):
                rows = self._rows(str(p.relative_to(self.root)))
                latest = {r["candidate_id"]: r for r in rows}
                for row in latest.values():
                    if row["status"] == "pending_review" and row['candidate_id'] not in resolved:
                        if digest(row["payload"]) != row["version_digest"]:
                            raise ReviewBlocked("candidate_integrity_failed")
                        output.append(copy.deepcopy(row))
            return output

    def _request(self, request):
        if not isinstance(request, dict) or set(request) - {
                "action", "candidate_id", "version_digest", "scope", "command_id", "replacement"}:
            raise ReviewBlocked("invalid_review_request")
        if request.get("action") not in ("confirm", "modify", "reject"):
            raise ReviewBlocked("invalid_review_action")
        for k in ("candidate_id", "scope", "command_id"):
            safe_id(request.get(k))
        if not isinstance(request.get("version_digest"), str) or len(request["version_digest"]) != 64:
            raise ReviewBlocked("invalid_version_digest")

    def _binding(self, request, row):
        self._request(request)
        if row["version_digest"] != request["version_digest"]:
            raise ReviewBlocked("stale_candidate_version")
        binding = {k: request[k] for k in ("action", "candidate_id", "version_digest", "scope", "command_id")}
        replacement = None
        if request["action"] == "modify":
            # Owner edits a new candidate version; this action never confirms it.
            supplied = request.get("replacement")
            if not isinstance(supplied, dict) or set(supplied) - {
                    "subject_id", "subject_label", "predicate", "value", "unit", "valid_from", "valid_to"}:
                raise ReviewBlocked("invalid_replacement")
            base = copy.deepcopy(row["payload"]["effects"][-1])
            base.update(supplied)
            # Stable new ID binds the modified meaning; no overwrite of approved facts.
            base["fact_id"] = "fact_review_" + digest(base)[:24]
            payload = row["payload"]
            targets = payload.get("target_versions") or []
            replacement = self._build_payload(request["scope"], base, payload["operation"],
                                               targets[0]["fact_id"] if targets else None)
            binding["replacement_digest"] = digest(replacement)
        elif "replacement" in request:
            raise ReviewBlocked("replacement_requires_modify")
        return binding, replacement

    def binding_for(self, principal, request):
        """Return the exact challenge binding before owner_auth creates its challenge."""
        verify_principal(self.root, principal)
        self._request(request)
        with self._lock():
            row = self._current(request["scope"], request["candidate_id"])
            if row["status"] != "pending_review":
                raise ReviewBlocked("candidate_not_pending")
            return self._binding(request, row)[0]

    def _check_targets(self, payload):
        store = self._store(payload["scope"])
        for target in payload.get("target_versions", []):
            current = store.get_fact(target["fact_id"])
            if current is None or digest(semantic(current)) != target["semantic_digest"] or not owner_confirmed(store, current):
                raise ReviewBlocked("stale_correction_target")

    def _materialize(self, decision):
        binding, payload = decision["binding"], decision["review_payload"]
        scope = binding["scope"]
        row = self._current(scope, binding["candidate_id"])
        if binding["action"] == "confirm":
            store = self._store(scope)
            eid = "owner-confirm-" + digest(binding)[:32]
            confirmation = {"schema": SCHEMA, "confirmation_event_id": eid,
                "fact_id": payload["effects"][-1]["fact_id"], "confirmed_at": decision["decided_at"],
                "persisted_at": decision["decided_at"], "actor": decision["owner_proof"]["actor_id"],
                "binding": binding, "review_payload": payload, "owner_proof": decision["owner_proof"]}
            with store.transaction():
                existing = [r for r in store.load_confirmations() if r.get("confirmation_event_id") == eid]
                if existing and existing != [confirmation]:
                    raise ReviewBlocked("confirmation_event_conflict")
                if not existing:
                    self._append("memory/structured/" + scope + "/confirmations.jsonl", confirmation)
                for effect in payload["effects"]:
                    fact = StructuredFact(**effect, confirmation_event_id=eid, graph_sync_status="pending_sync")
                    history = store._read_jsonl(store.facts_path)
                    if any(h.get("confirmation_event_id") == eid and semantic(h) == effect for h in history):
                        continue
                    current = store.get_fact(fact.fact_id)
                    if current and current.confirmation_event_id == eid and semantic(current) == effect:
                        continue
                    # A replay after a newer approved edit must not roll it back.
                    if current and current.confirmation_event_id != eid:
                        target_ids = {t["fact_id"] for t in payload.get("target_versions", [])}
                        if fact.fact_id not in target_ids:
                            raise ReviewBlocked("formal_fact_id_conflict")
                        target = next(t for t in payload["target_versions"] if t["fact_id"] == fact.fact_id)
                        if digest(semantic(current)) != target["semantic_digest"]:
                            raise ReviewBlocked("newer_fact_version_prevents_replay")
                    store.upsert_fact(fact)
                if payload["operation"] != "append":
                    correction = {"schema": SCHEMA, "correction_event_id": eid,
                        "owner_confirmation_event_id": eid, "kind": payload["operation"],
                        "source_event_id": payload["effects"][-1]["source_event_id"],
                        "target_versions": payload["target_versions"],
                        "new_fact_id": payload["effects"][-1]["fact_id"],
                        "persisted_at": decision["decided_at"]}
                    old = [r for r in store.load_corrections() if r.get("correction_event_id") == eid]
                    if old and old != [correction]:
                        raise ReviewBlocked("correction_event_conflict")
                    if not old:
                        self._append("memory/structured/" + scope + "/corrections.jsonl", correction)
            status = "confirmed"
        elif binding["action"] == "reject":
            status = "rejected"
        else:
            status = "pending_review"
        # Do not overwrite a newer candidate version when replaying an old command.
        if row["version_digest"] == binding["version_digest"] and row["status"] == "pending_review":
            changed = copy.deepcopy(row)
            if binding["action"] == "modify":
                changed["payload"] = decision["replacement"]
                changed["version_digest"] = binding["replacement_digest"]
            changed.update(status=status, last_command_id=binding["command_id"], reviewed_at=decision["decided_at"])
            self._append(self._candidate_rel(scope), changed)
        return {"command_id": binding["command_id"], "candidate_id": binding["candidate_id"],
                "version_digest": binding.get("replacement_digest", binding["version_digest"]),
                "scope": scope, "status": status, "memory_status": status,
                "owner_proof": decision["owner_proof"],
                "fact_ids": [e["fact_id"] for e in payload["effects"]] if status == "confirmed" else []}

    def review(self, principal, request, assertion):
        actor = verify_principal(self.root, principal)
        self._request(request)
        with self._lock():
            prior = [r for r in self._rows("memory/review/decisions.jsonl")
                     if r.get("binding", {}).get("command_id") == request["command_id"]]
            if prior:
                if len(prior) != 1 or prior[0].get("request_digest") != digest(request):
                    raise ReviewBlocked("command_id_conflict")
                decision = prior[0]
                verified_proof(self.root, decision["binding"], proof_id=decision["owner_proof"]["proof_id"], expected_actor=actor)
                # Complete an interrupted committed decision without accepting a new assertion.
                return self._materialize(decision)
            row = self._current(request["scope"], request["candidate_id"])
            if row["status"] != "pending_review":
                raise ReviewBlocked("candidate_not_pending")
            binding, replacement = self._binding(request, row)
            validate_payload_sources(self.root, row["payload"])
            if request["action"] == "confirm":
                self._check_targets(row["payload"])
            proof = verified_proof(self.root, binding, assertion=assertion, expected_actor=actor)
            # Metadata only: never persist assertion, session or principal credentials.
            decision = {"schema": SCHEMA, "binding": binding, "owner_proof": proof,
                        "review_payload": row["payload"], "request_digest": digest(request),
                        "decided_at": _now()}
            if replacement is not None:
                decision["replacement"] = replacement
            self._append("memory/review/decisions.jsonl", decision)
            return self._materialize(decision)

    def trace(self, principal, candidate_id, scope):
        verify_principal(self.root, principal)
        safe_id(candidate_id); safe_id(scope)
        with self._lock():
            versions = [r for r in self._rows(self._candidate_rel(scope)) if r.get("candidate_id") == candidate_id]
            decisions = [r for r in self._rows("memory/review/decisions.jsonl")
                         if r.get("binding", {}).get("candidate_id") == candidate_id
                         and r["binding"].get("scope") == scope]
            return {"candidate_id": candidate_id, "scope": scope, "versions": versions, "decisions": decisions}
