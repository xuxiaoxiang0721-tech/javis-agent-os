"""Immutable, source-bound manual evidence backlog. No confirmation authority.

Only references, hashes and fixed reason codes are stored. Resolving a gap means
adding/correcting source evidence and processing that source separately; this
module deliberately has no confirm/promote/resolve endpoint.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import tempfile

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / "tools/memory-adapter"))
from javis_memory_adapter.review_policy import ReviewBlocked, digest, guarded_path, read_rows, safe_id, verified_proof
from role_registry import ROLE_IDS
from runtime_io import lock

SCHEMA = "javis.memory-triage.v1"
REASONS = frozenset({"screen_needs_evidence", "screen_conflict", "source_too_large",
    "verification_uncertain", "validity_missing", "validity_invalid", "source_time_missing", "graph_no_facts",
    "model_response_invalid"})
POLICY_REASONS = frozenset({"source_too_large", "candidate_too_large", "typed_low_confidence",
    "typed_insufficient", "typed_subject_unproven", "typed_modality_unproven", "typed_attribution_unproven",
    "typed_numbers_unproven", "typed_dates_unproven", "quantity_not_in_source", "validity_not_in_source",
    "validity_precision_unproven", "relative_time_unanchored"})
STAGES = frozenset({"screening", "verification", "source_time", "proposal", "graphiti"})
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"triage_[a-f0-9]{64}\Z")
_FIELDS = {"schema", "event_id", "scope", "source_digest", "run_id", "policy_version", "policy_digest",
           "stage", "reason_code", "policy_reason", "graph_edge_id", "edge_digest", "content_digest"}


def _hash(value, optional=False):
    if optional and value is None:
        return
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ReviewBlocked("invalid_triage_digest")


def _binding(value):
    if not isinstance(value, dict) or set(value) != _FIELDS or value.get("schema") != SCHEMA:
        raise ReviewBlocked("invalid_triage_binding")
    for key in ("event_id", "run_id", "policy_version"):
        safe_id(value[key])
    if value["scope"] not in ROLE_IDS or value["stage"] not in STAGES or value["reason_code"] not in REASONS:
        raise ReviewBlocked("invalid_triage_binding")
    if value["policy_reason"] is not None and value["policy_reason"] not in POLICY_REASONS:
        raise ReviewBlocked("invalid_triage_reason")
    for key in ("source_digest", "policy_digest"):
        _hash(value[key])
    _hash(value["content_digest"], optional=True)
    if value["graph_edge_id"] is not None:
        safe_id(value["graph_edge_id"])
        _hash(value["edge_digest"])
    elif value["edge_digest"] is not None:
        raise ReviewBlocked("triage_edge_binding_missing")
    return value


def _sources(root, *, rows=None):
    found = {}
    for path in sorted(guarded_path(root, root / "raw/events").rglob("*.jsonl")):
        for row in read_rows(root, path):
            eid = row.get("event_id")
            if not isinstance(eid, str):
                continue
            current = (digest(row), row.get("agent"))
            if eid in found and found[eid] != current:
                raise ReviewBlocked("ambiguous_raw_event")
            found[eid] = current
            if rows is not None:
                rows[eid] = row
    return found


def _source_valid(binding, sources):
    return sources.get(binding["event_id"]) == (binding["source_digest"], binding["scope"])


def _fsync_dir(root, path):
    fd = os.open(guarded_path(root, path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _mkdir(root, path):
    path = guarded_path(root, path)
    if path.exists():
        if not path.is_dir():
            raise ReviewBlocked("triage_path_not_directory")
        return
    _mkdir(root, path.parent)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        guarded_path(root, path)
    _fsync_dir(root, path.parent)


@contextmanager
def _lock(root):
    # The maintenance lock protects this direct writer as well as worker calls.
    # Recovery hold is checked after acquiring it, before any triage write.
    with lock(guarded_path(root, root / "state/maintenance.lock"), shared=True):
        from task_service import ensure_not_held
        ensure_not_held(root)
        path = guarded_path(root, root / "state/locks/memory-triage.lock")
        _mkdir(root, path.parent)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_nlink != 1:
                raise ReviewBlocked("hardlinked_memory_file")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)


def _read(root, path):
    path = guarded_path(root, path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        if os.fstat(handle.fileno()).st_nlink != 1:
            raise ReviewBlocked("hardlinked_memory_file")
        text = handle.read(65537)
    if len(text) > 65536:
        raise ReviewBlocked("invalid_triage_record")
    row = json.loads(text)
    if not isinstance(row, dict) or set(row) != {"triage_id", "binding", "status", "created_at", "record_digest"}:
        raise ReviewBlocked("invalid_triage_record")
    binding = _binding(row["binding"])
    expected = "triage_" + digest(binding)
    if (row["triage_id"] != expected or path.name != expected + ".json" or row["status"] != "needs_review"
            or not isinstance(row["created_at"], str)
            or row["record_digest"] != digest({k: v for k, v in row.items() if k != "record_digest"})):
        raise ReviewBlocked("triage_record_integrity_failed")
    try:
        date = datetime.fromisoformat(row["created_at"])
        if date.tzinfo is None:
            raise ValueError()
    except ValueError:
        raise ReviewBlocked("invalid_triage_timestamp") from None
    return row


def _project(row, sources, replacement=None, archived_by=None):
    b = row["binding"]
    result = {"triage_id": row["triage_id"], "status": "needs_review", "reason_code": b["reason_code"],
            "version_digest": row["record_digest"],
            "policy_reason": b["policy_reason"], "stage": b["stage"], "source_event_id": b["event_id"],
            "raw_refs": [b["event_id"]], "scope": b["scope"], "run_id": b["run_id"],
            "graph_edge_id": b["graph_edge_id"], "policy_version": b["policy_version"],
            "created_at": row["created_at"], "source_integrity": "verified" if _source_valid(b, sources)
            else "changed_or_unavailable"}
    if replacement is not None:
        result.update(status="superseded", superseded_by_run_id=replacement)
    elif archived_by is not None:
        # Record stays immutable; the owner-signed cleanup batch is only projected.
        result.update(status="archived", archived_by_batch_id=archived_by)
    return result


def _cleanup_index(root):
    """Owner-signed cleanup batches (offline re-verified). Fail closed to 'nothing archived'."""
    try:
        from memory_cleanup_batch import archived
        return archived(root)
    except Exception:
        return {"quarantine": {}, "triage": {}, "legacy": {}}


_RUN_BINDING_FIELDS = ("schema", "pipeline_version", "provider", "policy_version", "policy_digest",
    "event_id", "scope", "source_digest", "content_digest", "model", "graph_model", "embedding_model",
    "extraction_prompt_version", "extraction_prompt_digest", "prompt_version", "prompt_digest",
    "learning_version", "learning_profile_digest")
_RUN_OPTIONAL_BINDING_FIELDS = ('graph_provider', 'graph_config_revision', 'graph_auth_mode',
    'graph_account_id', 'embedding_provider', 'embedding_dimensions')


def _source_key(value):
    # A full RAW can contain several messages. Never replace across text hashes.
    return tuple(value.get(key) for key in ("scope", "event_id", "source_digest", "content_digest"))


def _date(value):
    value = datetime.fromisoformat(value)
    if value.tzinfo is None:
        raise ValueError("unqualified_run_time")
    return value


def _supersessions(root, rows, sources, source_rows, cleanup=None):
    """Derive replacement references once; immutable backlog files are untouched."""
    from memory_screen import (PIPELINE_VERSION, PROMPT_VERSION, SCHEMA as RUN_SCHEMA, SCREEN_PROMPT, VERIFY_PROMPT,
        PERSONAL_MEMORY_EXTRACTION_VERSION, PERSONAL_MEMORY_EXTRACTION_INSTRUCTIONS)
    from jev_policy import POLICY_VERSION, POLICY_DIGEST
    latest, invalid = {}, 0
    try:
        for row in read_rows(root, root / "memory/screen/runs.jsonl"):
            run_id = row.get("run_id")
            try:
                safe_id(run_id)
                if row.get("checkpoint_digest") != digest({k: v for k, v in row.items() if k != "checkpoint_digest"}):
                    raise ValueError("invalid_run_checkpoint")
                latest[run_id] = row
            except (ValueError, TypeError):
                invalid += 1
                # A corrupt final checkpoint must not revive its earlier result.
                if isinstance(run_id, str):
                    latest[run_id] = None
    except (ValueError, OSError, KeyError, TypeError):
        return {}, invalid + 1
    by_id = {row["triage_id"]: row for row in rows}
    candidates_by_scope, current, decisions = {}, {}, None
    for run_id, run in latest.items():
        if not run or (run.get("schema"), run.get("pipeline_version"), run.get("prompt_version"),
                run.get("policy_version"), run.get("policy_digest"), run.get("provider")) != (
                RUN_SCHEMA, PIPELINE_VERSION, PROMPT_VERSION, POLICY_VERSION, POLICY_DIGEST, "typesafe"):
            continue
        if run.get("status") not in {"complete", "needs_review"}:
            continue
        try:
            binding = {key: run[key] for key in _RUN_BINDING_FIELDS}
            binding.update({key: run[key] for key in _RUN_OPTIONAL_BINDING_FIELDS if key in run})
            if (run.get("prompt_digest") != digest([SCREEN_PROMPT, VERIFY_PROMPT])
                    or run.get("extraction_prompt_version") != PERSONAL_MEMORY_EXTRACTION_VERSION
                    or run.get("extraction_prompt_digest") != digest(PERSONAL_MEMORY_EXTRACTION_INSTRUCTIONS)):
                raise ValueError("run_prompt_mismatch")
            if run_id != "screen_" + digest(binding)[:32]:
                raise ValueError("run_identity_mismatch")
            if run.get("group_id") != "javis-screen-" + digest({"root": str(root), "run": run_id})[:40]:
                raise ValueError("run_group_mismatch")
            key = _source_key(run)
            for field in ("source_digest", "content_digest"):
                _hash(run[field])
            if not _source_valid(run, sources):
                continue
            finished = _date(run["updated_at"])
            created = _date(run["created_at"])
            if finished < created:
                raise ValueError("invalid_run_time_order")
            refs = run.get("review_refs", [])
            if (not isinstance(refs, list) or any(not isinstance(ref, str) or not _ID.fullmatch(ref) for ref in refs)
                    or len(set(refs)) != len(refs) or run.get("review_count", len(refs)) != len(refs)
                    or (run["status"] == "needs_review") != bool(refs)):
                raise ValueError("incomplete_run_reviews")
            for ref in refs:
                item = by_id[ref]
                b = item["binding"]
                # Early screening terminals retain the attempt's updated_at;
                # their immutable review records can legitimately be newer.
                # The terminal checkpoint and exact ref binding prove coverage.
                if (_source_key(b) != key or b["run_id"] != run_id or b["policy_version"] != POLICY_VERSION
                        or b["policy_digest"] != POLICY_DIGEST or _date(item["created_at"]) < created):
                    raise ValueError("run_review_binding_mismatch")
            proposals = run["candidates"]
            if not isinstance(proposals, list):
                raise ValueError("invalid_run_proposals")
            expected_outcomes = ({"pending_review_and_evidence"} if proposals else {"needs_evidence"}) if refs else (
                {"pending_review"} if proposals else {"archive_only", "no_supported_facts"})
            if run.get("outcome") not in expected_outcomes:
                raise ValueError("incomplete_run_outcome")
            if proposals and run["scope"] not in candidates_by_scope:
                ledger = {}
                for candidate in read_rows(root, root / "memory/quarantine" / safe_id(run["scope"]) / "candidates.jsonl"):
                    cid = candidate.get("candidate_id")
                    if isinstance(cid, str):
                        ledger[cid] = candidate
                candidates_by_scope[run["scope"]] = ledger
            for proposal in proposals:
                candidate = candidates_by_scope[run["scope"]][proposal["candidate_id"]]
                payload = candidate["payload"]
                if (digest(payload) != candidate["version_digest"] or proposal["version_digest"] != candidate["version_digest"]
                        or candidate["candidate_id"] != "candidate_" + candidate["version_digest"][:32]
                        or candidate.get("scope") != run["scope"] or payload.get("scope") != run["scope"]
                        or proposal.get("scope") != run["scope"] or proposal.get("source_event_id") != run["event_id"]
                        or payload.get("source_digests", {}).get(run["event_id"]) != run["source_digest"]):
                    raise ValueError("run_candidate_binding_mismatch")
                if candidate.get("status") not in {"pending_review", "confirmed", "rejected"}:
                    raise ValueError("invalid_candidate_status")
                if candidate["status"] == "rejected" and candidate.get("owner_batch_id"):
                    # Javis260928 追加三: a one-signature owner cleanup batch; its
                    # decision is re-verified offline by memory_cleanup_batch.archived().
                    ref = (cleanup or {}).get("quarantine", {}).get(
                        (run["scope"], candidate["candidate_id"], candidate["version_digest"]))
                    if (not ref or candidate.get("last_command_id") != ref["command_id"]
                            or candidate.get("reviewed_at") != ref["decided_at"]
                            or candidate.get("owner_batch_id") != ref["cleanup_batch_id"]):
                        raise ValueError("candidate_owner_decision_invalid")
                    continue
                if candidate["status"] != "pending_review":
                    if decisions is None:
                        decisions = read_rows(root, root / "memory/review/decisions.jsonl")
                    matches = [d for d in decisions if d.get("binding", {}).get("command_id") == candidate.get("last_command_id")]
                    if len(matches) != 1:
                        raise ValueError("candidate_owner_decision_missing")
                    decision = matches[0]
                    authorized, proof = decision["binding"], decision["owner_proof"]
                    if (authorized.get("action") != {"confirmed": "confirm", "rejected": "reject"}[candidate["status"]]
                            or authorized.get("candidate_id") != candidate["candidate_id"]
                            or authorized.get("version_digest") != candidate["version_digest"]
                            or authorized.get("scope") != run["scope"] or decision.get("review_payload") != payload
                            or candidate.get("reviewed_at") != decision.get("decided_at")
                            or verified_proof(root, authorized, proof_id=proof["proof_id"], expected_actor=proof["actor_id"]) != proof):
                        raise ValueError("candidate_owner_decision_invalid")
            source = source_rows[run["event_id"]]
            if source.get("event_type") == "corpus_text":
                from memory_corpus import verify_canonical
                verify_canonical(root, source)
            # Require the replacing run itself to start after the old task.
            # A later ref/update cannot make an earlier run appear newer.
            current.setdefault(key, []).append((created, run_id))
        except (ValueError, OSError, KeyError, TypeError, IndexError):
            invalid += 1
    replacements = {}
    for row in rows:
        b = row["binding"]
        old = latest.get(b["run_id"])
        different_version = (b["policy_version"], b["policy_digest"]) != (POLICY_VERSION, POLICY_DIGEST)
        if not different_version and old:
            different_version = (old.get("pipeline_version"), old.get("prompt_version")) != (PIPELINE_VERSION, PROMPT_VERSION)
        if not different_version:
            continue
        possible = [(date, rid) for date, rid in current.get(_source_key(b), [])
                    if rid != b["run_id"] and date > _date(row["created_at"])]
        if possible:
            replacements[row["triage_id"]] = max(possible)[1]
    return replacements, invalid


def pending_view(root):
    """Read-only full backlog projection, shared by list and notification counts."""
    root = Path(root).resolve()
    rows, invalid = [], 0
    for path in sorted(guarded_path(root, root / "memory/triage/items").glob("*.json")):
        try:
            rows.append(_read(root, path))
        except (ValueError, OSError, KeyError, TypeError):
            invalid += 1
    source_rows = {}
    try:
        sources = _sources(root, rows=source_rows) if rows else {}
    except (ValueError, OSError):
        sources, source_rows = {}, {}
    cleanup = _cleanup_index(root) if rows else {"quarantine": {}, "triage": {}, "legacy": {}}
    replacements, invalid_runs = _supersessions(root, rows, sources, source_rows, cleanup) if rows else ({}, 0)
    rows.sort(key=lambda row: (row["created_at"], row["triage_id"]), reverse=True)
    archived = {row["triage_id"]: cleanup["triage"][row["triage_id"]]["cleanup_batch_id"] for row in rows
                if row["triage_id"] in cleanup["triage"] and row["triage_id"] not in replacements}
    from memory_autoreview import MemoryAutoreview
    ai_resolved = MemoryAutoreview(root).resolved()
    from memory_interactions import status as supplement_status
    supplements = supplement_status(root)['closed_targets']
    projected = []
    for row in rows:
        item = _project(row, sources, replacements.get(row['triage_id']), archived.get(row['triage_id']))
        decision = ai_resolved.get(row['triage_id'])
        if item['status'] == 'needs_review' and decision:
            item.update(status='ai_reviewed' if decision['action'] == 'accept' else 'archived',
                        ai_review_event_id=decision['review_event_id'], review_origin='ai')
        if item['status'] == 'needs_review' and row['triage_id'] in supplements:
            item.update(status='supplement_accepted', supplement=supplements[row['triage_id']])
        projected.append(item)
    return {"items": projected,
            "invalid_records": invalid, "invalid_run_records": invalid_runs,
            "superseded_count": len(replacements), "archived_count": sum(i['status'] == 'archived' for i in projected),
            'ai_reviewed_count': sum(i['status'] == 'ai_reviewed' for i in projected)}


def record_pending(root, *, event_id, scope, source_digest, run_id, policy_version, policy_digest,
                   stage, reason_code, graph_edge_id=None, edge_digest=None, content_digest=None, policy_reason=None):
    root = Path(root).resolve()
    binding = _binding({"schema": SCHEMA, "event_id": event_id, "scope": scope, "source_digest": source_digest,
        "run_id": run_id, "policy_version": policy_version, "policy_digest": policy_digest,
        "stage": stage, "reason_code": reason_code, "graph_edge_id": graph_edge_id,
        "edge_digest": edge_digest, "content_digest": content_digest, "policy_reason": policy_reason})
    triage_id = "triage_" + digest(binding)
    path = guarded_path(root, root / "memory/triage/items" / (triage_id + ".json"))
    with _lock(root):
        sources = _sources(root)
        if not _source_valid(binding, sources):
            raise ReviewBlocked("triage_source_changed_or_missing")
        if path.exists():
            row = _read(root, path)
            if row["binding"] != binding:
                raise ReviewBlocked("triage_record_integrity_failed")
            return _project(row, sources)
        row = {"triage_id": triage_id, "binding": binding, "status": "needs_review",
               "created_at": datetime.now(timezone.utc).isoformat()}
        row["record_digest"] = digest(row)
        _mkdir(root, path.parent)
        fd, temporary = tempfile.mkstemp(prefix=".triage-", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                if os.fstat(handle.fileno()).st_nlink != 1:
                    raise ReviewBlocked("hardlinked_memory_file")
                json.dump(row, handle, ensure_ascii=False, sort_keys=True, allow_nan=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            guarded_path(root, path)
            os.replace(temporary, path)
            _fsync_dir(root, path.parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(guarded_path(root, Path(temporary)))
        return _project(row, sources)


def get_pending(root, triage_id, *, check_supersession=True):
    root = Path(root).resolve()
    if not isinstance(triage_id, str) or not _ID.fullmatch(triage_id):
        raise ReviewBlocked("invalid_triage_id")
    # Validate the requested record explicitly; an invalid row is not 'missing'.
    try:
        row = _read(root, root / "memory/triage/items" / (triage_id + ".json"))
    except FileNotFoundError:
        raise ReviewBlocked("triage_item_missing") from None
    if not check_supersession:
        try:
            sources = _sources(root)
        except (ValueError, OSError):
            sources = {}
        return _project(row, sources)
    for row in pending_view(root)["items"]:
        if row["triage_id"] == triage_id:
            return row
    raise ReviewBlocked("triage_item_missing")


def list_pending(root, limit=100, scope=None, *, include_superseded=False):
    root = Path(root).resolve()
    if (type(limit) is not int or not 0 <= limit <= 500 or (scope is not None and scope not in ROLE_IDS)
            or type(include_superseded) is not bool):
        raise ReviewBlocked("invalid_triage_query")
    view = pending_view(root)
    rows = [row for row in view["items"] if (scope is None or row["scope"] == scope)
            and (include_superseded or row["status"] == "needs_review")]
    return {"items": rows[:limit], "total": len(rows), "invalid_records": view["invalid_records"],
            "superseded_count": view["superseded_count"], "invalid_run_records": view["invalid_run_records"]}
