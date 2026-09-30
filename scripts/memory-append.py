#!/usr/bin/env python3
"""Append a Javis memory JSONL record (schema javis-memory-2).

Adds confidence + temporal + kind + memory_class + sensitivity.
Keeps secret filter and path layout from v1.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from memory_sources import legacy_gate_enabled, stage_legacy_candidate, _ensure_not_held
from javis_memory_adapter.review_policy import guarded_path, safe_id
from raw_storage import _append_line
from runtime_io import lock

SECRET_RE = re.compile(
    r"(password|secret|token|api[_-]?key|sk-[A-Za-z0-9_-]{10,})", re.I
)
CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_iso(s: Optional[str]) -> Optional[str]:
    if s is None or s == "":
        return None
    # Accept as-is after a light sanity check (datetime.fromisoformat handles +08:00)
    try:
        raw = s.replace("Z", "+00:00")
        datetime.fromisoformat(raw)
    except ValueError as e:
        raise SystemExit(f"ERROR: invalid ISO8601 timestamp: {s!r} ({e})") from e
    return s


def resolve_path(root: Path, tier: str, role: str) -> Path:
    if role in ("ide-lab", "idea-lab"):
        return root / "memory" / "ide-lab" / "facts.jsonl"
    if tier == "confirmed":
        if role == "shared":
            return root / "memory" / "confirmed" / "shared" / "facts.jsonl"
        return root / "memory" / "confirmed" / "by-role" / role / "facts.jsonl"
    return root / "memory" / "candidates" / "by-role" / role / "facts.jsonl"


def main() -> int:
    ap = argparse.ArgumentParser(description="Append javis-memory-2 record")
    ap.add_argument("--tier", choices=["candidate", "confirmed"], required=True)
    ap.add_argument("--role", required=True)
    ap.add_argument("--fact", required=True)
    ap.add_argument("--tag", action="append", default=[])
    ap.add_argument("--task-id", default=None)
    ap.add_argument("--raw-event", action="append", default=[])
    ap.add_argument("--raw-object", action="append", default=[])
    ap.add_argument(
        "--confidence",
        choices=["high", "medium", "low"],
        default=None,
        help="default: medium if candidate, high if confirmed",
    )
    ap.add_argument(
        "--kind",
        choices=["fact", "rule", "decision", "preference", "open_loop"],
        default="fact",
    )
    ap.add_argument(
        "--memory-class",
        choices=["semantic", "episodic_ref", "procedural_ref"],
        default="semantic",
    )
    ap.add_argument("--valid-from", default=None, help="ISO8601")
    ap.add_argument("--valid-to", default=None, help="ISO8601")
    ap.add_argument("--as-of", default=None, help="ISO8601; default now UTC")
    ap.add_argument("--learned-at", default=None, help="ISO8601; default now UTC")
    ap.add_argument(
        "--temporal-kind",
        choices=["point", "interval", "open_ended"],
        default="open_ended",
    )
    ap.add_argument("--supersedes", default=None, help="memory_id this supersedes")
    ap.add_argument(
        "--sensitivity",
        choices=["normal", "sensitive", "l4_blocked"],
        default="normal",
    )
    args = ap.parse_args()

    if SECRET_RE.search(args.fact):
        print("ERROR: secret-like fact rejected", file=sys.stderr)
        return 3

    root = Path(os.environ.get("JAVIS_ROOT", Path.home() / "javis")).resolve()
    safe_id(args.role)

    confidence = args.confidence
    if confidence is None:
        confidence = "high" if args.tier == "confirmed" else "medium"

    now = now_utc_iso()
    as_of = parse_iso(args.as_of) or now
    learned_at = parse_iso(args.learned_at) or now
    valid_from = parse_iso(args.valid_from)
    valid_to = parse_iso(args.valid_to)

    temporal: dict[str, Any] = {
        "kind": args.temporal_kind,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "as_of": as_of,
        "learned_at": learned_at,
    }

    rec = {
        "schema_version": "javis-memory-2",
        "memory_id": f"m-{uuid.uuid4().hex[:12]}",
        "tier": args.tier,
        "role_id": args.role,
        "fact": args.fact,
        "kind": args.kind,
        "memory_class": args.memory_class,
        "confidence": confidence,
        "sensitivity": args.sensitivity,
        "temporal": temporal,
        "source": {
            "raw_event_ids": args.raw_event,
            "raw_object_sha256": args.raw_object,
            "task_id": args.task_id,
        },
        "created_at": now,
        "confirmed_at": now if args.tier == "confirmed" else None,
        "confirmed_by": "explicit" if args.tier == "confirmed" else None,
        "tags": args.tag,
        "supersedes": args.supersedes,
    }

    with lock(guarded_path(root, root / 'state/maintenance.lock'), shared=True):
        _ensure_not_held(root)
        if legacy_gate_enabled(root):
            # A default capture clock is not the source's as-of/learned-at time.
            if not args.as_of:
                rec['temporal']['as_of'] = None
            if not args.learned_at:
                rec['temporal']['learned_at'] = None
            result = stage_legacy_candidate(root, rec,
                source_ref={'producer': 'memory-append.py', 'is_original_user_input': False})
            print(json.dumps(result, ensure_ascii=False))
            return 0
        path = guarded_path(root, resolve_path(root, args.tier, args.role))
        with lock(guarded_path(root, root / 'state/locks/legacy-memory-append.lock')):
            _append_line(path, rec)

    print(
        json.dumps(
            {"ok": True, "status": "legacy_compatibility", "effective_tier": args.tier,
             "path": str(path), "memory_id": rec["memory_id"], "schema_version": "javis-memory-2"},
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(json.dumps({'ok': False, 'status': 'blocked',
            'reason': 'legacy_memory_validation_failed', 'error_type': type(exc).__name__}))
        raise SystemExit(2)
