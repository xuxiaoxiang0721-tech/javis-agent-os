from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class ConflictStatus(str, Enum):
    OK = "ok"
    CONFLICT = "conflict"
    PENDING = "pending"  # unknown times / unresolved
    EMPTY = "empty"


@dataclass
class FactRecord:
    fact_uuid: str
    fact: str
    name: Optional[str]
    group_id: str
    valid_at: Optional[str]  # event-time start (ISO) or None=unknown
    invalid_at: Optional[str]  # event-time end exclusive; None=open
    expired_at: Optional[str]  # system-time when marked expired (Graphiti)
    created_at: Optional[str]  # system ingest time
    episodes: list[str] = field(default_factory=list)
    source_event_ids: list[str] = field(default_factory=list)
    object_refs: list[str] = field(default_factory=list)
    conflict_status: ConflictStatus = ConflictStatus.OK
    notes: list[str] = field(default_factory=list)
    fact_id: Optional[str] = None
    subject_id: Optional[str] = None
    predicate: Optional[str] = None
    value: Any = None
    unit: Optional[str] = None
    status: Optional[str] = None
    confirmation_event_id: Optional[str] = None
    ai_review_event_id: Optional[str] = None
    review_origin: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["conflict_status"] = self.conflict_status.value
        return d


@dataclass
class QueryResult:
    as_of: str
    mode: str  # current | as_of
    facts: list[FactRecord]
    conflict_status: ConflictStatus
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of,
            "mode": self.mode,
            "conflict_status": self.conflict_status.value,
            "facts": [f.to_dict() for f in self.facts],
            "conflicts": self.conflicts,
            "notes": self.notes,
        }


@dataclass
class WriteResult:
    ok: bool
    source_event_id: str
    episode_uuid: Optional[str]
    group_id: str
    nodes: int
    edges: int
    edge_facts: list[str]
    error: Optional[str] = None
    deduped: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HealthStatus:
    ok: bool
    neo4j_bolt: bool
    neo4j_http: bool
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
