"""Owner-reviewed memory policy shared by ledger queries and Type B.

No text, status flag or caller-supplied actor establishes owner authority.
Authentication is delegated to owner_auth; absence always fails closed.
"""
from __future__ import annotations
import hashlib
import importlib
import json
import re
import sys
import copy
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

SCHEMA = "javis.owner-memory.v1"
SEMANTIC_FIELDS = (
    "fact_id", "subject_id", "subject_label", "predicate", "value", "unit",
    "valid_from", "valid_to", "recorded_at", "source_event_id", "raw_refs",
    "status", "superseded_by", "supersedes", "revision_of", "notes",
)

class ReviewBlocked(ValueError):
    pass

def digest(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def safe_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", value):
        raise ReviewBlocked("invalid_identifier")
    return value

def guarded_path(root, path):
    root, path = Path(root).resolve(), Path(path)
    if not path.is_absolute() or not path.is_relative_to(root):
        raise ReviewBlocked("path_outside_root")
    for part in (path, *path.parents):
        if part == root:
            break
        if part.is_symlink():
            raise ReviewBlocked("linked_memory_path")
        if part.exists() and part.is_file() and part.stat().st_nlink != 1:
            raise ReviewBlocked("hardlinked_memory_file")
    return path

def read_rows(root, path):
    path = guarded_path(root, path)
    if not path.exists():
        return []
    if not path.is_file():
        raise ReviewBlocked("memory_path_not_file")
    rows = []
    # JSON strings may contain U+0085/U+2028/U+2029 verbatim. Only physical LF
    # separates JSONL records; str.splitlines() would split inside those strings.
    for line in path.read_text(encoding="utf-8").split('\n'):
        if line.strip():
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ReviewBlocked("invalid_ledger_row")
            rows.append(row)
    return rows

_SOURCE_BATCH = ContextVar("memory_raw_source_batch", default=None)


def _raw_signature(root):
    base = guarded_path(root, root / "raw/events")
    result = []
    for path in sorted(base.rglob("*.jsonl")):
        guarded_path(root, path)
        st = path.stat()
        result.append((str(path.relative_to(root)), st.st_dev, st.st_ino, st.st_size,
                       st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink))
    return tuple(result)


def _read_raw_snapshot(root):
    signature = _raw_signature(root)
    rows, pins, ambiguous, file_hashes = {}, {}, set(), {}
    for entry in signature:
        path = guarded_path(root, root / entry[0])
        data = path.read_bytes()
        file_hashes[entry[0]] = hashlib.sha256(data).hexdigest()
        for line in data.split(b'\n'):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ReviewBlocked("invalid_ledger_row")
            eid = row.get("event_id")
            if not isinstance(eid, str):
                continue
            pin = digest(row)
            if eid in pins and pins[eid] != pin:
                ambiguous.add(eid)
            rows[eid], pins[eid] = row, pin
    if _raw_signature(root) != signature:
        raise ReviewBlocked("raw_snapshot_changed")
    return {"root": root, "signature": signature, "rows": rows, "pins": pins,
            "ambiguous": ambiguous, "file_hashes": file_hashes}


def _raw_data(root):
    root = Path(root).resolve()
    cached = _SOURCE_BATCH.get()
    if cached is not None and cached["root"] == root:
        if _raw_signature(root) != cached["signature"]:
            raise ReviewBlocked("raw_snapshot_changed")
        return cached
    return _read_raw_snapshot(root)


@contextmanager
def batch_source_snapshot(root):
    """Bound a local batch; no cache survives the call or ignores RAW changes."""
    root = Path(root).resolve()
    previous = _SOURCE_BATCH.get()
    if previous is not None and previous["root"] == root:
        _raw_data(root)
        yield
        return
    snapshot = _read_raw_snapshot(root)
    token = _SOURCE_BATCH.set(snapshot)
    try:
        yield
    finally:
        try:
            if _raw_signature(root) != snapshot["signature"]:
                raise ReviewBlocked("raw_snapshot_changed")
            for rel, pin in snapshot["file_hashes"].items():
                path = guarded_path(root, root / rel)
                if hashlib.sha256(path.read_bytes()).hexdigest() != pin:
                    raise ReviewBlocked("raw_snapshot_changed")
        finally:
            _SOURCE_BATCH.reset(token)


def _verify_corpus(root, row):
    if row.get("event_type") == "corpus_text":
        scripts = str(Path(__file__).resolve().parents[3] / "scripts")
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        try:
            importlib.import_module("memory_corpus").verify_canonical(root, row)
        except Exception:
            raise ReviewBlocked("corpus_original_source_changed_or_unavailable") from None


def source_rows(root, event_ids):
    wanted = set(event_ids)
    if not wanted or any(not isinstance(x, str) or not x for x in wanted):
        raise ReviewBlocked("source_event_required")
    snapshot = _raw_data(root)
    if wanted & snapshot["ambiguous"]:
        raise ReviewBlocked("ambiguous_raw_event")
    if not wanted <= set(snapshot["rows"]):
        raise ReviewBlocked("source_event_missing")
    for eid in wanted:
        _verify_corpus(Path(root).resolve(), snapshot["rows"][eid])
    return {eid: copy.deepcopy(snapshot["rows"][eid]) for eid in wanted}


def source_digests(root, event_ids):
    return {eid: digest(row) for eid, row in source_rows(root, event_ids).items()}

def semantic(fact):
    row = fact.to_dict() if hasattr(fact, "to_dict") else fact
    return {k: row.get(k) for k in SEMANTIC_FIELDS}

def store_context(store):
    p = Path(store.meta_dir).absolute()
    if p.parent.name != "structured" or p.parent.parent.name != "memory":
        return None
    root, scope = p.parent.parent.parent.resolve(), safe_id(p.name)
    guarded_path(root, p)
    return root, scope

def official_group(root, scope):
    return "javis-memory-" + hashlib.sha256(str(Path(root).resolve()).encode()).hexdigest()[:12] + "-owner-v1-" + safe_id(scope)

def protected_group(group):
    return isinstance(group, str) and group.startswith("javis-memory-")

def check_group(store, group):
    context = store_context(store)
    if context is not None:
        if group != official_group(*context):
            raise ReviewBlocked("official_memory_requires_owner_namespace")
    elif protected_group(group):
        raise ReviewBlocked("official_group_requires_official_ledger")
    return context

def owner_module():
    # Trusted installed code location, never a task/root supplied plugin path.
    scripts = str(Path(__file__).resolve().parents[3] / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    try:
        return importlib.import_module("owner_auth")
    except ImportError:
        raise ReviewBlocked("owner_auth_unavailable") from None

def verify_principal(root, principal):
    try:
        result = owner_module().verify_principal(Path(root), principal)
    except ReviewBlocked:
        raise
    except Exception:
        raise ReviewBlocked("owner_principal_not_verified") from None
    if not isinstance(result, dict) or not isinstance(result.get("actor_id"), str) or not result["actor_id"]:
        raise ReviewBlocked("owner_principal_not_verified")
    return result["actor_id"]

def verified_proof(root, binding, *, assertion=None, proof_id=None, expected_actor=None):
    try:
        module = owner_module()
        result = (module.verify_recorded_decision(Path(root), proof_id, binding) if proof_id is not None
                  else module.verify_decision(Path(root), assertion, binding))
    except ReviewBlocked:
        raise
    except Exception:
        raise ReviewBlocked("owner_decision_not_verified") from None
    if (not isinstance(result, dict)
            or not all(isinstance(result.get(k), str) and result[k] for k in ("actor_id", "proof_id", "binding_hash"))
            or result["binding_hash"] != digest(binding)
            or (proof_id is not None and result["proof_id"] != proof_id)
            or (expected_actor is not None and result["actor_id"] != expected_actor)):
        raise ReviewBlocked("owner_decision_not_verified")
    return {k: result[k] for k in ("actor_id", "proof_id", "binding_hash")}

def validate_payload_sources(root, payload):
    if payload.get("schema") != SCHEMA:
        raise ReviewBlocked("unsupported_review_version")
    expected = payload.get("source_digests")
    if not isinstance(expected, dict) or source_digests(root, expected) != expected:
        raise ReviewBlocked("review_source_changed")

def owner_confirmed(store, fact):
    """Fail closed for missing/forged/stale approval or changed RAW/version."""
    context = store_context(store)
    if context is None:
        return False
    root, scope = context
    try:
        if fact.status not in ("confirmed", "superseded") or not fact.confirmation_event_id:
            return False
        confirmations = [r for r in read_rows(root, store.confirmations_path)
                         if r.get("confirmation_event_id") == fact.confirmation_event_id]
        if len(confirmations) != 1:
            return False
        row = confirmations[0]
        binding, payload, proof = row["binding"], row["review_payload"], row["owner_proof"]
        if (binding.get("action") != "confirm" or binding.get("scope") != scope
                or payload.get("scope") != scope or digest(payload) != binding.get("version_digest")
                or row.get("schema") != SCHEMA):
            return False
        safe_id(binding["candidate_id"]); safe_id(binding["command_id"])
        if verified_proof(root, binding, proof_id=proof["proof_id"], expected_actor=proof["actor_id"]) != proof:
            return False
        decisions = [r for r in read_rows(root, root / "memory/review/decisions.jsonl")
                     if r.get("binding", {}).get("command_id") == binding["command_id"]]
        if (len(decisions) != 1 or decisions[0].get("binding") != binding
                or decisions[0].get("owner_proof") != proof or decisions[0].get("review_payload") != payload):
            return False
        if semantic(fact) not in payload.get("effects", []):
            return False
        validate_payload_sources(root, payload)
        from .entity_registry import validate_entity_dependencies
        validate_entity_dependencies(root, scope, fact)
        return True
    except (ReviewBlocked, ValueError, OSError, TypeError, KeyError):
        return False

def official_facts(store, facts=None):
    values = store.load_facts() if facts is None else facts
    return [f for f in values if owner_confirmed(store, f)]


AI_REVIEW_SCHEMA = "javis.ai-memory-review.v1"
AI_POLICY_SCHEMA = "javis.memory-autoreview.policy.v1"
AI_REVIEW_PATH = "memory/ai-review/decisions.jsonl"


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _ai_policy(root, row, cache):
    """A pause affects future reviews, not the validity of prior decisions."""
    pin = row.get("policy_digest")
    if not _sha(pin) or not isinstance(row.get("policy_version"), str):
        return False
    if pin not in cache:
        path = guarded_path(root, root / "memory/ai-review/policies" / (pin + ".json"))
        if not path.is_file() or path.stat().st_size > 1_000_000:
            cache[pin] = None
        else:
            doc = json.loads(path.read_text(encoding="utf-8"))
            cache[pin] = doc if isinstance(doc, dict) and digest(doc) == pin else None
    doc = cache[pin]
    return bool(doc and doc.get("schema") == AI_POLICY_SCHEMA
        and doc.get("policy_version") == row["policy_version"]
        and doc.get("mode") == "automatic" and doc.get("scope") == "memory_only"
        and isinstance(doc.get("permitted_actions"), list)
        and row.get("action") in doc["permitted_actions"])


def _ai_snapshot(store, *, as_of=None):
    """Read the independent AI audit once. A status flag alone grants nothing."""
    context = store_context(store)
    if context is None:
        return {}
    root, scope = context
    from .validity import parse_ts
    try:
        rows = read_rows(root, root / AI_REVIEW_PATH)
        policy_cache, accepts, revokes, seen, duplicate_ids = {}, {}, [], set(), set()
        for row in rows:
            if row.get("action") not in ("accept", "revoke") or row.get("scope") != scope:
                continue
            rid = safe_id(row.get("review_event_id"))
            if rid in seen:
                duplicate_ids.add(rid)
            seen.add(rid)
            stamp = parse_ts(row.get("decided_at"))
            if (row.get("schema") != AI_REVIEW_SCHEMA or stamp is None
                    or (as_of is not None and stamp > as_of)
                    or not _ai_policy(root, row, policy_cache)):
                continue
            if row["action"] == "revoke":
                safe_id(row.get("target_review_event_id"))
                revokes.append(row)
                continue
            effect = row.get("effect")
            if not isinstance(effect, dict) or set(effect) != set(SEMANTIC_FIELDS):
                continue
            if (effect.get("status") != "ai_reviewed"
                    or effect.get("superseded_by") or effect.get("supersedes") or effect.get("revision_of")
                    or not _sha(row.get("effect_digest")) or digest(effect) != row["effect_digest"]
                    or not _sha(row.get("version_digest"))):
                continue
            for field in ("candidate_id", "run_id"):
                safe_id(row.get(field))
            safe_id(effect.get("fact_id"))
            safe_id(effect.get("source_event_id"))
            refs = effect.get("raw_refs")
            expected = row.get("source_digests")
            if (not isinstance(refs, list) or any(not isinstance(v, str) for v in refs)
                    or not isinstance(expected, dict)
                    or set(expected) != {effect["source_event_id"], *refs}
                    or any(not _sha(v) for v in expected.values())):
                continue
            accepts[rid] = row
        for rid in duplicate_ids:
            accepts.pop(rid, None)
        for row in revokes:
            target = accepts.get(row["target_review_event_id"])
            if (row["review_event_id"] not in duplicate_ids and target
                    and parse_ts(row["decided_at"]) >= parse_ts(target["decided_at"])):
                accepts.pop(row["target_review_event_id"], None)
        # Validate all referenced RAW in one scan, rather than once per fact.
        wanted = {eid for row in accepts.values() for eid in row["source_digests"]}
        if not wanted:
            return {}
        # A missing source must not suppress unrelated valid AI memories.
        snapshot = _raw_data(root)
        found, ambiguous = snapshot["pins"], set(snapshot["ambiguous"])
        for eid in wanted:
            if eid in snapshot["rows"]:
                try:
                    _verify_corpus(root, snapshot["rows"][eid])
                except ReviewBlocked:
                    ambiguous.add(eid)
        return {rid: row for rid, row in accepts.items()
            if all(eid not in ambiguous and found.get(eid) == pin
                   for eid, pin in row["source_digests"].items())}
    except (ReviewBlocked, ValueError, OSError, TypeError, KeyError, AttributeError):
        return {}


def _matches_ai(fact, audit):
    rid = getattr(fact, "ai_review_event_id", None)
    row = audit.get(rid) if isinstance(rid, str) else None
    return bool(row and fact.status == "ai_reviewed" and not fact.confirmation_event_id
                and semantic(fact) == row["effect"])


def ai_reviewed(store, fact, *, as_of=None):
    """AI authority is distinct from owner confirmation, including on replay."""
    return _matches_ai(fact, _ai_snapshot(store, as_of=as_of)) and _entity_dependencies_valid(store, fact)


def _entity_dependencies_valid(store, fact):
    context = store_context(store)
    if context is None:
        return True
    try:
        from .entity_registry import validate_entity_dependencies
        return validate_entity_dependencies(*context, fact)
    except (ReviewBlocked, ValueError, OSError, TypeError, KeyError):
        return False


def usable_facts(store, facts=None, *, as_of=None):
    values = store.load_facts() if facts is None else facts
    audit = _ai_snapshot(store, as_of=as_of) if any(
        getattr(f, "ai_review_event_id", None) for f in values) else {}
    return [f for f in values if (not getattr(f, "ai_review_event_id", None) and owner_confirmed(store, f))
            or (_matches_ai(f, audit) and _entity_dependencies_valid(store, f))]


def review_origin(fact):
    """Use only after the corresponding proof/AI audit has been verified."""
    return "ai_reviewed" if fact.status == "ai_reviewed" and getattr(fact, "ai_review_event_id", None) else "owner_confirmed"


def memory_slot(fact):
    """A source may have several complementary attributed notes, not one value."""
    from .normalization import metadata
    meta = metadata(fact.to_dict())
    if meta.get('cardinality') == 'many':
        return (fact.subject_id, fact.predicate, digest({'value': fact.value, 'unit': fact.unit}))
    return (fact.subject_id, fact.predicate,
            fact.fact_id if fact.predicate == 'source_attributed_memory' else '')
