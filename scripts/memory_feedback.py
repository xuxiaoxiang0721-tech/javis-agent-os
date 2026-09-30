"""Owner-session labels for offline evaluation, never memory confirmation.

Records contain immutable references and labels, not copied RAW text or session
tokens. Local account administrators remain within the existing trust boundary.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / "tools/memory-adapter"))
from javis_memory_adapter.review_policy import ReviewBlocked, digest, guarded_path, read_rows, safe_id, verify_principal
from jev_policy import POLICY_DIGEST
from memory_screen import load_source, _source_context, _cloud_excluded
from memory_triage import _read as _read_triage
from raw_policy import redact
from raw_time import semantic_source_time
from role_registry import ROLE_IDS
from task_memory import _explicit_l4

SCHEMA = "javis.memory-feedback.v1"
LABELS = frozenset({"keep", "archive", "needs_evidence"})
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"feedback_[a-f0-9]{64}\Z")
_BINDING = {"source_event_id", "scope", "source_digest", "content_digest", "text_path",
            "policy_digest", "run_id", "triage_id", "supersedes_feedback_id"}
_STATES = {"running", "retry", "complete", "completed", "needs_review", "blocked",
           "credentials_rejected", "waiting_for_key"}
_OUTCOMES = {"keep", "archive_only", "needs_evidence", "conflict", "pending_review",
             "pending_review_and_evidence", "no_supported_facts", "configuration_required"}


def _hash(value, optional=False):
    if optional and value is None:
        return
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ReviewBlocked("invalid_feedback_digest")


def _text_path(value):
    if value != ["payload", "text"] and not (isinstance(value, list) and len(value) == 4
            and value[:2] == ["payload", "messages"] and type(value[2]) is int
            and 0 <= value[2] < 100 and value[3] == "text"):
        raise ReviewBlocked("invalid_feedback_text_path")
    return list(value)


def _scope(scope):
    if not isinstance(scope, str) or scope not in ROLE_IDS or scope == "shared":
        raise ReviewBlocked("invalid_feedback_scope")


def _privacy(row):
    _, changes = redact(row)
    if changes or _explicit_l4(row) or _cloud_excluded(row) or "[REDACTED:" in json.dumps(row):
        raise ReviewBlocked("private_source_excluded")


def _content(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if isinstance(text, str) else None


def _target(binding):
    return digest({key: binding[key] for key in ("source_event_id", "scope", "text_path")})


def _binding(value):
    if not isinstance(value, dict) or set(value) != _BINDING:
        raise ReviewBlocked("invalid_feedback_binding")
    safe_id(value["source_event_id"])
    _scope(value["scope"])
    _text_path(value["text_path"])
    for key in ("source_digest", "policy_digest"):
        _hash(value[key])
    _hash(value["content_digest"], optional=True)
    if value["run_id"] is not None:
        safe_id(value["run_id"])
    if value["triage_id"] is not None and (not isinstance(value["triage_id"], str)
            or not re.fullmatch(r"triage_[a-f0-9]{64}", value["triage_id"])):
        raise ReviewBlocked("invalid_feedback_triage_id")
    if value["supersedes_feedback_id"] is not None and (not isinstance(value["supersedes_feedback_id"], str)
            or not _ID.fullmatch(value["supersedes_feedback_id"])):
        raise ReviewBlocked("invalid_feedback_revision")
    return value


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
            raise ReviewBlocked("feedback_path_not_directory")
        return
    _mkdir(root, path.parent)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        if not guarded_path(root, path).is_dir():
            raise ReviewBlocked("feedback_path_not_directory") from None
    _fsync_dir(root, path.parent)


@contextmanager
def _file_lock(root, path, shared=False):
    path = guarded_path(root, path)
    _mkdir(root, path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_nlink != 1:
            raise ReviewBlocked("hardlinked_memory_file")
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


class MemoryFeedback:
    authority = "owner_session_feedback"

    def __init__(self, root):
        self.root = Path(root).resolve()

    def _actor(self, principal):
        return verify_principal(self.root, principal)

    def _expected_actor(self):
        from owner_auth import ACTOR
        return ACTOR

    def _identity(self, command_id):
        return "feedback_" + digest(command_id)

    def _path(self, relative):
        return guarded_path(self.root, self.root / relative)

    def _source_index(self):
        sources = {}
        for path in sorted(self._path("raw/events").rglob("*.jsonl")):
            for row in read_rows(self.root, path):
                event_id = row.get("event_id")
                if not isinstance(event_id, str):
                    continue
                if event_id in sources and digest(sources[event_id]) != digest(row):
                    raise ReviewBlocked("ambiguous_raw_event")
                sources[event_id] = row
        return sources

    def _source(self, event_id, scope, text_path=None, *, sources=None):
        safe_id(event_id)
        _scope(scope)
        row = load_source(self.root, event_id) if sources is None else sources.get(event_id)
        if row is None:
            raise ReviewBlocked("source_event_missing")
        if row.get("agent") != scope:
            raise ReviewBlocked("source_scope_mismatch")
        _privacy(row)
        payload = row.get("payload") or {}
        if not isinstance(payload, dict):
            raise ReviewBlocked("invalid_feedback_source_payload")
        messages = payload.get("messages") or []
        if text_path is None:
            if isinstance(payload.get("text"), str):
                text_path = ["payload", "text"]
            else:
                options = [i for i, item in enumerate(messages[:100])
                           if isinstance(item, dict) and isinstance(item.get("text"), str)] if isinstance(messages, list) else []
                if len(options) > 1:
                    raise ReviewBlocked("feedback_source_text_ambiguous")
                text_path = ["payload", "messages", options[0], "text"] if options else ["payload", "text"]
        text_path = _text_path(text_path)
        selected = payload if len(text_path) == 2 else (
            messages[text_path[2]] if isinstance(messages, list) and text_path[2] < len(messages) else None)
        if not isinstance(selected, dict):
            raise ReviewBlocked("feedback_source_text_missing")
        text = selected.get("text")
        if text is not None and not isinstance(text, str):
            raise ReviewBlocked("invalid_feedback_source_text")
        if row.get("event_type") == "corpus_text":
            # A retained adapter RAW is evidence, not proof that its original
            # source or time interpretation is still valid for display/learning.
            from memory_corpus import verify_canonical
            try:
                verify_canonical(self.root, row, text)
            except (ValueError, OSError, KeyError, TypeError, IndexError):
                raise ReviewBlocked("corpus_original_source_changed_or_unavailable") from None
        # A message selector can never borrow direct-payload user provenance.
        context_row = row if len(text_path) == 2 else {**row, "payload": {"messages": [selected]}}
        context = (_source_context(context_row, text) if isinstance(text, str) else
            {"authorship_verified": False, "fidelity": "unavailable", "speaker": "unknown",
             "occurred_at": semantic_source_time(row if len(text_path) == 2 else selected), "confirmation_authority": False})
        return row, text, text_path, context

    def _runs(self):
        latest, invalid = {}, 0
        for row in read_rows(self.root, self._path("memory/screen/runs.jsonl")):
            try:
                safe_id(row["run_id"])
                safe_id(row["event_id"])
                _scope(row["scope"])
                if row.get("checkpoint_digest") != digest({k: v for k, v in row.items() if k != "checkpoint_digest"}):
                    raise ValueError()
                for key in ("source_digest", "content_digest", "policy_digest"):
                    _hash(row[key])
                latest.pop(row["run_id"], None)
                latest[row["run_id"]] = row
            except (ValueError, KeyError, TypeError):
                invalid += 1
                if isinstance(row.get("run_id"), str):
                    latest.pop(row["run_id"], None)
        return list(reversed(list(latest.values()))), invalid

    def _machine(self, row):
        decision = row.get("screening", {}).get("decision") if isinstance(row.get("screening"), dict) else None
        return {"run_id": row["run_id"], "policy_digest": row["policy_digest"],
                "status": row.get("status") if row.get("status") in _STATES else None,
                "decision": decision if decision in {"keep", "archive_only", "needs_evidence", "conflict"} else None,
                "outcome": row.get("outcome") if row.get("outcome") in _OUTCOMES else None}

    def _matched_runs(self, event_id, scope, source_digest, content_digest):
        runs, _ = self._runs()
        return [row for row in runs if row.get("event_id") == event_id and row.get("scope") == scope
                and row.get("source_digest") == source_digest and row.get("content_digest") == content_digest]

    def _validate_machine_binding(self, binding):
        if binding["run_id"] is None:
            if binding["policy_digest"] != POLICY_DIGEST:
                raise ReviewBlocked("feedback_policy_changed")
        elif not any(row["run_id"] == binding["run_id"] and row["policy_digest"] == binding["policy_digest"]
                for row in self._matched_runs(binding["source_event_id"], binding["scope"],
                                             binding["source_digest"], binding["content_digest"])):
            raise ReviewBlocked("feedback_run_binding_mismatch")
        if binding["triage_id"] is not None:
            triage = _read_triage(self.root, self._path("memory/triage/items/" + binding["triage_id"] + ".json"))["binding"]
            if any(triage[key] != binding[other] for key, other in (
                ("event_id", "source_event_id"), ("scope", "scope"), ("source_digest", "source_digest"),
                ("content_digest", "content_digest"), ("run_id", "run_id"), ("policy_digest", "policy_digest"))):
                raise ReviewBlocked("feedback_triage_binding_mismatch")

    def _read(self, path):
        fd = os.open(guarded_path(self.root, path), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            if os.fstat(handle.fileno()).st_nlink != 1:
                raise ReviewBlocked("hardlinked_memory_file")
            text = handle.read(65537)
        if len(text) > 65536:
            raise ReviewBlocked("invalid_feedback_record")
        row = json.loads(text)
        if (not isinstance(row, dict) or set(row) != {"schema", "feedback_id", "binding", "command_id",
                "label", "actor_id", "authority", "created_at", "record_digest"}
                or row["schema"] != SCHEMA or row["label"] not in LABELS
                or row["authority"] != self.authority):
            raise ReviewBlocked("invalid_feedback_record")
        if row["actor_id"] != self._expected_actor():
            raise ReviewBlocked("feedback_owner_mismatch")
        _binding(row["binding"])
        safe_id(row["command_id"])
        expected = self._identity(row["command_id"])
        if (row["feedback_id"] != expected or path.name != expected + ".json"
                or row["record_digest"] != digest({k: v for k, v in row.items() if k != "record_digest"})):
            raise ReviewBlocked("feedback_integrity_failed")
        if not isinstance(row["created_at"], str) or datetime.fromisoformat(row["created_at"]).tzinfo is None:
            raise ReviewBlocked("invalid_feedback_timestamp")
        return row

    def _records(self):
        rows, invalid = [], 0
        for path in sorted(self._path("memory/feedback/items").glob("*.json")):
            try:
                rows.append(self._read(path))
            except (ValueError, OSError, KeyError, TypeError):
                invalid += 1
        return rows, invalid

    def _latest(self, rows):
        by_id, children, latest = {row["feedback_id"]: row for row in rows}, {}, {}
        for row in rows:
            previous = row["binding"]["supersedes_feedback_id"]
            target = _target(row["binding"])
            if previous is not None:
                if (previous not in by_id or previous in children or previous == row["feedback_id"]
                        or _target(by_id[previous]["binding"]) != target):
                    raise ReviewBlocked("feedback_revision_integrity_failed")
                children[previous] = row["feedback_id"]
            else:
                if target in latest:
                    raise ReviewBlocked("feedback_revision_integrity_failed")
                latest[target] = row
        visited = set()
        for target, row in latest.items():
            while row["feedback_id"] in children:
                if row["feedback_id"] in visited:
                    raise ReviewBlocked("feedback_revision_integrity_failed")
                visited.add(row["feedback_id"])
                row = by_id[children[row["feedback_id"]]]
            visited.add(row["feedback_id"])
            latest[target] = row
        if len(visited) != len(rows):
            raise ReviewBlocked("feedback_revision_integrity_failed")
        return latest

    def _valid_source(self, row, sources=None):
        binding = row["binding"]
        try:
            source, text, path, context = self._source(binding["source_event_id"], binding["scope"], binding["text_path"], sources=sources)
            if digest(source) != binding["source_digest"] or _content(text) != binding["content_digest"]:
                return None
            return source, text, context
        except (ValueError, OSError, KeyError, TypeError):
            return None

    def _project(self, row, latest, sources=None):
        binding = row["binding"]
        current = latest.get(_target(binding), {}).get("feedback_id") == row["feedback_id"]
        valid = self._valid_source(row, sources) is not None
        return {"feedback_id": row["feedback_id"], **binding, "label": row["label"],
                "created_at": row["created_at"], "is_latest": current,
                "source_integrity": "verified" if valid else "changed_or_unavailable",
                "status": "superseded" if not current else "active" if valid else "invalidated",
                "confirmation_authority": False, "authority": row["authority"]}

    def context(self, principal, event_id, scope, *, text_path=None, run_id=None, triage_id=None):
        from raw_time import source_timestamp
        self._actor(principal)
        source, text, text_path, context = self._source(event_id, scope, text_path)
        rows, invalid = self._records()
        if invalid:
            raise ReviewBlocked("feedback_integrity_failed")
        latest = self._latest(rows)
        runs = self._matched_runs(event_id, scope, digest(source), _content(text))
        chosen = next((row for row in runs if row["run_id"] == run_id), None) if run_id else (runs[0] if runs else None)
        if run_id is not None and chosen is None:
            raise ReviewBlocked("feedback_run_binding_mismatch")
        binding = {"source_event_id": event_id, "scope": scope, "source_digest": digest(source),
                   "content_digest": _content(text), "text_path": text_path,
                   "policy_digest": chosen["policy_digest"] if chosen else POLICY_DIGEST,
                   "run_id": chosen["run_id"] if chosen else None, "triage_id": triage_id,
                   "supersedes_feedback_id": None}
        previous = latest.get(_target(binding))
        binding["supersedes_feedback_id"] = previous["feedback_id"] if previous else None
        self._validate_machine_binding(_binding(binding))
        return {"source_event_id": event_id, "scope": scope, "source_text": text,
                "source_context": context, "source_time": context.get("occurred_at"), "bindings": binding,
                "source_times": {"occurred_at": source_timestamp(context.get("occurred_at")),
                                 "received_at": source_timestamp(source.get("received_at")),
                                 "captured_at": source_timestamp(source.get("captured_at"))},
                "machine_decisions": [self._machine(row) for row in runs],
                "latest_feedback": self._project(previous, latest) if previous else None,
                "confirmation_authority": False}

    def record(self, principal, request):
        actor = self._actor(principal)
        if not isinstance(request, dict) or set(request) != _BINDING | {"command_id", "label"}:
            raise ReviewBlocked("invalid_feedback_request")
        safe_id(request["command_id"])
        if not isinstance(request["label"], str) or request["label"] not in LABELS:
            raise ReviewBlocked("invalid_feedback_label")
        binding = _binding({key: request[key] for key in _BINDING})
        feedback_id = self._identity(request["command_id"])
        with _file_lock(self.root, self._path("state/maintenance.lock"), shared=True):
            from task_service import ensure_not_held
            guarded_path(self.root, self._path("state/recovery-hold.json"))
            ensure_not_held(self.root)
            with _file_lock(self.root, self._path("state/locks/memory-feedback.lock")):
                # Authentication can expire while waiting for the write lock.
                if self._actor(principal) != actor:
                    raise ReviewBlocked("owner_principal_not_verified")
                rows, invalid = self._records()
                if invalid:
                    raise ReviewBlocked("feedback_integrity_failed")
                latest = self._latest(rows)
                source, text, _, _ = self._source(binding["source_event_id"], binding["scope"], binding["text_path"])
                if digest(source) != binding["source_digest"] or _content(text) != binding["content_digest"]:
                    raise ReviewBlocked("feedback_source_changed")
                existing = next((row for row in rows if row["feedback_id"] == feedback_id), None)
                if existing:
                    if existing["binding"] != binding or existing["label"] != request["label"] or existing["actor_id"] != actor:
                        raise ReviewBlocked("feedback_command_conflict")
                    return self._project(existing, latest)
                self._validate_machine_binding(binding)
                previous = latest.get(_target(binding))
                if binding["supersedes_feedback_id"] != (previous["feedback_id"] if previous else None):
                    raise ReviewBlocked("feedback_version_changed")
                row = {"schema": SCHEMA, "feedback_id": feedback_id, "binding": binding,
                       "command_id": request["command_id"], "label": request["label"], "actor_id": actor,
                       "authority": self.authority, "created_at": datetime.now(timezone.utc).isoformat()}
                row["record_digest"] = digest(row)
                path = self._path("memory/feedback/items/" + feedback_id + ".json")
                _mkdir(self.root, path.parent)
                fd, temporary = tempfile.mkstemp(prefix=".feedback-", dir=path.parent)
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as handle:
                        if os.fstat(handle.fileno()).st_nlink != 1:
                            raise ReviewBlocked("hardlinked_memory_file")
                        json.dump(row, handle, sort_keys=True, ensure_ascii=False, allow_nan=False)
                        handle.write("\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                    guarded_path(self.root, path)
                    if path.exists():
                        raise ReviewBlocked("feedback_command_conflict")
                    os.replace(temporary, path)
                    _fsync_dir(self.root, path.parent)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(guarded_path(self.root, Path(temporary)))
                latest[_target(binding)] = row
                return self._project(row, latest)

    def list_feedback(self, principal, limit=100):
        self._actor(principal)
        if type(limit) is not int or not 0 <= limit <= 500:
            raise ReviewBlocked("invalid_feedback_query")
        rows, invalid = self._records()
        if invalid:
            # A missing/corrupt revision must not make an older label appear
            # current, even though no feedback can confirm a memory.
            return {"items": [], "total": len(rows) + invalid, "invalid_records": invalid}
        try:
            latest = self._latest(rows)
        except ReviewBlocked:
            return {"items": [], "total": len(rows), "invalid_records": invalid + 1}
        try:
            sources = self._source_index() if rows else {}
        except (ValueError, OSError, KeyError, TypeError):
            sources = {}
        rows.sort(key=lambda row: (row["created_at"], row["feedback_id"]), reverse=True)
        return {"items": [self._project(row, latest, sources) for row in rows[:limit]], "total": len(rows), "invalid_records": invalid}

    def sources(self, principal, limit=100, cursor=None):
        self._actor(principal)
        if type(limit) is not int or not 1 <= limit <= 500 or (cursor is not None and
                (not isinstance(cursor, str) or not re.fullmatch(r"[0-9]{1,10}", cursor))):
            raise ReviewBlocked("invalid_feedback_query")
        runs, invalid = self._runs()
        rows, broken = self._records()
        try:
            latest = self._latest(rows) if not broken else {}
        except ReviewBlocked:
            latest, broken = {}, broken + 1
        try:
            sources = self._source_index() if runs else {}
        except (ValueError, OSError, KeyError, TypeError):
            sources, broken = {}, broken + 1
        items, seen = [], set()
        for run in runs:
            key = (run.get("event_id"), run.get("scope"), run.get("content_digest"))
            if key in seen:
                continue
            seen.add(key)
            try:
                source = sources[key[0]]
                _privacy(source)
                payload = source.get("payload") or {}
                paths = [["payload", "text"]] + [["payload", "messages", i, "text"]
                         for i in range(min(100, len(payload.get("messages") or [])))]
                matching = []
                for path in paths:
                    try:
                        _, text, _, _ = self._source(key[0], key[1], path, sources=sources)
                        if _content(text) == key[2]:
                            matching.append(path)
                    except (ValueError, KeyError, TypeError, IndexError):
                        pass
                if not matching or digest(source) != run["source_digest"]:
                    raise ReviewBlocked("feedback_source_changed")
                path = matching[0]
                previous = latest.get(_target({"source_event_id": key[0], "scope": key[1], "text_path": path}))
                triage_id = None
                for ref in run.get("review_refs", []):
                    if isinstance(ref, str) and re.fullmatch(r"triage_[a-f0-9]{64}", ref):
                        try:
                            b = _read_triage(self.root, self._path("memory/triage/items/" + ref + ".json"))["binding"]
                            if b["event_id"] == key[0] and b["scope"] == key[1] and b["source_digest"] == run["source_digest"] and b["run_id"] == run["run_id"]:
                                triage_id = ref
                                break
                        except (ValueError, OSError, KeyError, TypeError):
                            pass
                items.append({"source_event_id": key[0], "scope": key[1], "text_path": path,
                    **self._machine(run), "triage_id": triage_id, "source_integrity": "verified",
                    "latest_feedback": self._project(previous, latest, sources) if previous else None})
            except (ValueError, OSError, KeyError, TypeError):
                invalid += 1
        start = int(cursor or "0")
        return {"items": items[start:start + limit], "total": len(items),
                "next_cursor": str(start + limit) if start + limit < len(items) else None,
                "invalid_records": invalid + broken}

    def _training(self):
        rows, invalid = self._records()
        counts = {"total_feedback": len(rows), "invalid_records": invalid, "latest_feedback": 0,
                  "invalidated_sources": 0, "missing_text": 0, "missing_time": 0, "invalid_time": 0, "eligible": 0}
        if invalid:
            return [], counts
        try:
            latest = self._latest(rows)
        except ReviewBlocked:
            counts["invalid_records"] += 1
            return [], counts
        counts["latest_feedback"] = len(latest)
        try:
            sources = self._source_index() if latest else {}
        except (ValueError, OSError, KeyError, TypeError):
            sources = {}
        output = []
        for row in latest.values():
            source = self._valid_source(row, sources)
            if source is None:
                counts["invalidated_sources"] += 1
                continue
            original, text, context = source
            if not isinstance(text, str) or not text.strip():
                counts["missing_text"] += 1
                continue
            from raw_time import source_timestamp
            value = context.get("occurred_at")
            time_record=original
            if len(row["binding"]["text_path"])==4:
                time_record=original["payload"]["messages"][row["binding"]["text_path"][2]]
            if time_record.get("time_basis")=="source_time_invalid":
                counts["invalid_time"] += 1
                continue
            if value is None:
                # Screening feedback is about candidate value, not an assertion
                # of a fact's validity date. Preserve unknown time without invention.
                counts["missing_time"] += 1
            else:
                if source_timestamp(value) is None:
                    counts["invalid_time"] += 1
                    continue
            binding = row["binding"]
            groups = {"source:" + binding["source_digest"], "text:" + binding["content_digest"],
                      "raw_event:" + digest(binding["source_event_id"])}
            payload = original.get("payload") or {}
            metadata = [original, payload]
            if len(binding["text_path"]) == 4:
                metadata.append(payload["messages"][binding["text_path"][2]])
            for item in metadata:
                for key, prefix in (("task_id", "task:"), ("thread_id", "thread:"), ("conversation_id", "thread:")):
                    if isinstance(item.get(key), str) and item[key]:
                        groups.add(prefix + digest(item[key]))
            output.append({"feedback_id": row["feedback_id"], "source_event_id": binding["source_event_id"],
                "scope": binding["scope"], "source_digest": binding["source_digest"],
                "content_digest": binding["content_digest"], "source_text": text, "text_path": binding["text_path"],
                "label": row["label"], "policy_digest": binding["policy_digest"], "run_id": binding["run_id"],
                "source_context": context, "source_time": value, "group_keys": sorted(groups),
                "source_event_type": original.get("event_type"), "source_completeness": original.get("completeness")})
        counts["eligible"] = len(output)
        return sorted(output, key=lambda row: row["feedback_id"]), counts

    def training_rows(self):
        """Local read-only export. Only valid latest human labels become examples."""
        return self._training()[0]

    def training_status(self):
        """Body-free exclusion counts for evaluation/UI diagnostics."""
        return self._training()[1]


class LocalMemoryFeedback(MemoryFeedback):
    """Local-browser corrections, independently stored from owner attestations.

    HTTP callers must pass the memory session returned by the server's CSRF and
    loopback checks. This capability never confirms a fact or grants task access.
    Offline learning reads this separate store without needing a browser session.
    """
    authority = "local_user_feedback"

    def _actor(self, principal):
        import time
        if (not isinstance(principal, dict) or principal.get('kind') != 'local_memory'
                or type(principal.get('expires')) not in (int, float)
                or principal['expires'] <= time.time()):
            raise ReviewBlocked('local_memory_session_required')
        return self._expected_actor()

    def _expected_actor(self):
        return 'local-user'

    def _identity(self, command_id):
        return 'feedback_' + digest({'authority': self.authority, 'command_id': command_id})

    def _path(self, relative):
        if relative.startswith('memory/feedback/'):
            relative = relative.replace('memory/feedback/', 'memory/local-feedback/', 1)
        if relative == 'state/locks/memory-feedback.lock':
            relative = 'state/locks/memory-local-feedback.lock'
        return super()._path(relative)
