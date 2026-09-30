"""Persistent structured fact ledger (not Neo4j-only, not overlay-only).

Files under meta_dir:
  facts.jsonl           — structured facts (stable fact_id)
  confirmations.jsonl   — user confirmation events
  corrections.jsonl     — user correction events (also kept)
  source_events.jsonl   — RAW-linked ingest events (existing)
  rebuild_checkpoint.json — Type B idempotency
"""
from __future__ import annotations

import hashlib
import json
import uuid
import fcntl
import os
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Iterable, Optional


class _TransactionState:
    def __init__(self):
        self.mutex = threading.RLock()
        self.depth = 0
        self.file = None


_transaction_states: dict[tuple[int, str], _TransactionState] = {}
_transaction_states_guard = threading.Lock()


def store_transaction(fn):
    """Serialize a synchronous ledger operation, including nested store calls."""
    @wraps(fn)
    def wrapped(store, *args, **kwargs):
        with store.transaction():
            return fn(store, *args, **kwargs)
    return wrapped


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso(dt: datetime | str | None) -> Optional[str]:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def stable_fact_id(
    *,
    subject_id: str,
    predicate: str,
    value: Any,
    unit: Optional[str],
    valid_from: Optional[str],
    source_event_id: str,
) -> str:
    raw = "|".join(
        [
            subject_id.strip(),
            predicate.strip(),
            json.dumps(value, ensure_ascii=False, sort_keys=True) if not isinstance(value, str) else value,
            unit or "",
            valid_from or "",
            source_event_id,
        ]
    )
    return "fact_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


@dataclass
class StructuredFact:
    fact_id: str
    subject_id: str
    subject_label: str
    predicate: str
    value: Any
    unit: Optional[str]
    valid_from: Optional[str]
    valid_to: Optional[str]
    recorded_at: str
    source_event_id: str
    raw_refs: list[str] = field(default_factory=list)
    status: str = "extracted"  # extracted | confirmed | superseded
    confirmation_event_id: Optional[str] = None
    superseded_by: Optional[str] = None
    supersedes: Optional[str] = None
    revision_of: Optional[str] = None
    graph_sync_status: str = "unknown"  # synced | pending_sync | n/a
    notes: list[str] = field(default_factory=list)
    ai_review_event_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "StructuredFact":
        return StructuredFact(**{k: d.get(k) for k in StructuredFact.__dataclass_fields__.keys()})


class StructuredStore:
    def __init__(self, meta_dir: Path):
        self.meta_dir = Path(meta_dir)
        self.meta_dir.mkdir(parents=True, exist_ok=True)
        self.facts_path = self.meta_dir / "facts.jsonl"
        self.confirmations_path = self.meta_dir / "confirmations.jsonl"
        self.corrections_path = self.meta_dir / "corrections.jsonl"
        self.checkpoint_path = self.meta_dir / "rebuild_checkpoint.json"

    @contextmanager
    def transaction(self):
        """A directory-wide writer/read-snapshot lock, reentrant across instances.

        The RLock serializes threads; flock serializes independent processes.
        Keep this synchronous scope free of awaits. This protects concurrent
        operations, not rollback of an interrupted multi-file disk write.
        """
        key = (os.getpid(), str(self.meta_dir.resolve()))
        with _transaction_states_guard:
            state = _transaction_states.setdefault(key, _TransactionState())
        with state.mutex:
            outermost = state.depth == 0
            if outermost:
                handle = (self.meta_dir / '.ledger.lock').open('a')
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX)
                except BaseException:
                    handle.close()
                    raise
                state.file = handle
            state.depth += 1
            try:
                yield
            finally:
                state.depth -= 1
                if outermost:
                    try:
                        fcntl.flock(state.file, fcntl.LOCK_UN)
                    finally:
                        state.file.close()
                        state.file = None

    def _append(self, path: Path, row: dict) -> None:
        with path.open("a", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            f.flush(); os.fsync(f.fileno())

    def _read_jsonl(self, path: Path) -> list[dict]:
        if not path.exists():
            return []
        out = []
        with path.open('r',encoding='utf-8') as f:
            fcntl.flock(f,fcntl.LOCK_SH)
            text = f.read()
        for line in text.split('\n'):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f'Invalid ledger JSON in {path}') from exc
        return out

    @store_transaction
    def load_facts(self, as_of: Optional[datetime] = None) -> list[StructuredFact]:
        # last write wins per fact_id
        by_id: dict[str, StructuredFact] = {}
        for row in self._read_jsonl(self.facts_path):
            if as_of is not None:
                stamp = row.get('ledger_recorded_at') or row.get('recorded_at')
                if not stamp:
                    continue
                dt = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
                if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
                if dt > as_of: continue
                # Older rows lack revision timestamps; confirmation events still
                # provide a reliable lower bound for when that state was known.
                if 'ledger_recorded_at' not in row and row.get('confirmation_event_id'):
                    conf = next((c for c in self.load_confirmations() if c.get('confirmation_event_id') == row['confirmation_event_id']), None)
                    if conf:
                        stamp = conf.get('persisted_at') or conf.get('confirmed_at')
                        if stamp and datetime.fromisoformat(stamp.replace('Z','+00:00')) > as_of:
                            row = {**row, 'status':'extracted', 'confirmation_event_id':None}
            f = StructuredFact.from_dict(row)
            by_id[f.fact_id] = f
        return list(by_id.values())

    def get_fact(self, fact_id: str) -> Optional[StructuredFact]:
        for f in self.load_facts():
            if f.fact_id == fact_id:
                return f
        return None

    @store_transaction
    def upsert_fact(self, fact: StructuredFact) -> StructuredFact:
        from .review_policy import store_context, owner_confirmed, ai_reviewed, ReviewBlocked
        if store_context(self) is not None and not ((not fact.ai_review_event_id and owner_confirmed(self, fact)) or ai_reviewed(self, fact)):
            raise ReviewBlocked('formal_ledger_requires_owner_review')
        self._append(self.facts_path, {**fact.to_dict(), 'ledger_recorded_at': _now()})
        return fact

    @store_transaction
    def mark_graph_synced(self, snapshot: StructuredFact) -> bool:
        """Mark only the semantic version actually projected by a rebuild.

        A confirmation/correction received during graph I/O must remain pending
        and must never be overwritten by that I/O's earlier snapshot.
        """
        current = self.get_fact(snapshot.fact_id)
        if current is None:
            return False
        current_fields = current.to_dict()
        snapshot_fields = snapshot.to_dict()
        current_fields.pop('graph_sync_status', None)
        snapshot_fields.pop('graph_sync_status', None)
        if current_fields != snapshot_fields:
            return False
        if current.graph_sync_status != 'synced':
            current.graph_sync_status = 'synced'
            self.upsert_fact(current)
        return True

    @store_transaction
    def write_confirmation(
        self,
        *,
        confirmation_event_id: str,
        fact_id: str,
        confirmed_at: datetime | str,
        actor: str = "fixture_test",
        note: str = "",
    ) -> dict:
        from .review_policy import store_context, ReviewBlocked
        if store_context(self) is not None:
            raise ReviewBlocked('owner_review_required')
        if not confirmation_event_id:
            raise ValueError('confirmation_event_id is required')
        for existing in self.load_confirmations():
            if existing.get('confirmation_event_id') == confirmation_event_id:
                if existing.get('fact_id') != fact_id:
                    raise ValueError('confirmation_event_id already belongs to another fact')
                # Retrying an old confirmation must not resurrect a fact which
                # was subsequently superseded by a correction/state change.
                return existing
        facts = self.load_facts()
        if any(f.confirmation_event_id == confirmation_event_id and f.fact_id != fact_id for f in facts):
            raise ValueError('confirmation_event_id already belongs to another fact')
        fact = next((f for f in facts if f.fact_id == fact_id), None)
        if fact is None:
            raise ValueError(f'fact_not_found: {fact_id}')
        if fact.status == 'superseded' or fact.superseded_by:
            raise ValueError(f'cannot_confirm_superseded_fact: {fact_id}')
        row = {
            "confirmation_event_id": confirmation_event_id,
            "fact_id": fact_id,
            "confirmed_at": _iso(confirmed_at),
            "actor": actor,
            "note": note,
            "persisted_at": _now(),
        }
        self._append(self.confirmations_path, row)
        fact.status = "confirmed"
        fact.confirmation_event_id = confirmation_event_id
        fact.graph_sync_status = 'pending_sync'
        self.upsert_fact(fact)
        return row

    @store_transaction
    def write_correction_event(self, row: dict) -> dict:
        row = dict(row)
        row.setdefault("persisted_at", _now())
        self._append(self.corrections_path, row)
        return row

    @store_transaction
    def load_confirmations(self) -> list[dict]:
        return self._read_jsonl(self.confirmations_path)

    @store_transaction
    def load_corrections(self) -> list[dict]:
        return self._read_jsonl(self.corrections_path)

    @store_transaction
    def export_snapshot(self) -> dict:
        return {
            "exported_at": _now(),
            "facts": [f.to_dict() for f in self.load_facts()],
            "confirmations": self.load_confirmations(),
            "corrections": self.load_corrections(),
        }

    def save_checkpoint(self, data: dict) -> None:
        import tempfile
        fd, name = tempfile.mkstemp(dir=self.meta_dir, prefix='.checkpoint-')
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as f:
                json.dump(data,f,ensure_ascii=False,indent=2); f.flush(); os.fsync(f.fileno())
            os.replace(name,self.checkpoint_path)
        finally:
            if os.path.exists(name): os.unlink(name)

    @contextmanager
    def rebuild_lock(self):
        with (self.meta_dir / '.rebuild.lock').open('a') as f:
            fcntl.flock(f,fcntl.LOCK_EX)
            try: yield
            finally: fcntl.flock(f,fcntl.LOCK_UN)

    def load_checkpoint(self) -> dict:
        if not self.checkpoint_path.exists():
            return {"applied_fact_ids": []}
        return json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
