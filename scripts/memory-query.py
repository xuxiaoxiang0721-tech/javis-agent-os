#!/usr/bin/env python3
"""Query Javis memory facts with confidence + temporal filters (javis-memory-2)."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def load_jsonl(p: Path) -> List[dict]:
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").split('\n'):
        if line.strip():
            out.append(json.loads(line))
    return out


def parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def conf_of(rec: dict) -> str:
    c = rec.get("confidence")
    if c in CONF_RANK:
        return c
    # v1 records: treat confirmed as high, candidate as medium
    if rec.get("tier") == "confirmed":
        return "high"
    return "medium"


def still_valid(rec: dict, now: datetime) -> bool:
    temporal = rec.get("temporal") or {}
    valid_from = parse_dt(temporal.get("valid_from") if isinstance(temporal, dict) else None)
    if valid_from is not None:
        if valid_from.tzinfo is None:
            valid_from = valid_from.replace(tzinfo=timezone.utc)
        if now < valid_from:
            return False
    valid_to = parse_dt(temporal.get("valid_to") if isinstance(temporal, dict) else None)
    if valid_to is None:
        return True
    # compare aware
    if valid_to.tzinfo is None:
        valid_to = valid_to.replace(tzinfo=timezone.utc)
    return now < valid_to


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", required=True)
    ap.add_argument('--query', help='Search reviewed structured memory with hybrid retrieval')
    ap.add_argument('--local-only', action='store_true', help='Disable provider embeddings for this query')
    ap.add_argument('--legacy', action='store_true', help='Inspect the legacy flat-file store')
    ap.add_argument("--tier", choices=["confirmed", "candidate", "both"], default="confirmed")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument(
        "--min-confidence",
        choices=["high", "medium", "low"],
        default=None,
        help="default: high for confirmed tier; medium when tier=candidate (or both→medium)",
    )
    ap.add_argument(
        "--valid-now",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="filter out records where valid_to < now (default True)",
    )
    ap.add_argument(
        "--include-expired",
        action="store_true",
        help="disable valid-now filter",
    )
    ap.add_argument("--keyword", default=None, help="optional substring filter on fact")
    args = ap.parse_args()

    if args.include_expired:
        args.valid_now = False

    if args.min_confidence is None:
        # Default: only inject-ready = high + still valid when tier=confirmed
        if args.tier == "confirmed":
            args.min_confidence = "high"
        else:
            args.min_confidence = "medium"

    root = Path(os.environ.get("JAVIS_ROOT", Path.home() / "javis"))
    if not args.legacy and args.tier == 'confirmed':
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/memory-adapter'))
        from javis_memory_adapter.hybrid_retrieval import retrieve
        result = retrieve(root, args.role, args.query or args.keyword or '',
            limit=args.limit if args.limit > 0 else 10000, allow_provider=not args.local_only)
        print(json.dumps({'ok': True, 'count': len(result['facts']), **result}, ensure_ascii=False, indent=2))
        return 0
    paths: List[Path] = []
    if args.tier in ("confirmed", "both"):
        if args.role == "shared":
            paths.append(root / "memory" / "confirmed" / "shared" / "facts.jsonl")
        elif args.role in ("ide-lab", "idea-lab"):
            paths.append(root / "memory" / "ide-lab" / "facts.jsonl")
        else:
            paths.append(root / "memory" / "confirmed" / "by-role" / args.role / "facts.jsonl")
            paths.append(root / "memory" / "confirmed" / "shared" / "facts.jsonl")
    if args.tier in ("candidate", "both"):
        if args.role in ("ide-lab", "idea-lab"):
            paths.append(root / "memory" / "ide-lab" / "facts.jsonl")
        else:
            paths.append(root / "memory" / "candidates" / "by-role" / args.role / "facts.jsonl")

    # de-dupe paths preserving order
    seen = set()
    uniq_paths = []
    for p in paths:
        sp = str(p)
        if sp not in seen:
            seen.add(sp)
            uniq_paths.append(p)

    items: List[dict] = []
    for p in uniq_paths:
        items.extend(load_jsonl(p))

    now = datetime.now(timezone.utc)
    min_rank = CONF_RANK[args.min_confidence]
    filtered: List[dict] = []
    for rec in items:
        if CONF_RANK.get(conf_of(rec), 0) < min_rank:
            continue
        if args.valid_now and not still_valid(rec, now):
            continue
        if args.keyword and args.keyword not in (rec.get("fact") or ""):
            continue
        filtered.append(rec)

    # newest-ish: keep tail by created_at if present
    def sort_key(r: dict) -> str:
        return r.get("created_at") or r.get("temporal", {}).get("learned_at") or ""

    filtered.sort(key=sort_key)
    limited = filtered[-args.limit :] if args.limit > 0 else filtered

    print(
        json.dumps(
            {
                "ok": True,
                "count": len(limited),
                "count_before_limit": len(filtered),
                "filters": {
                    "min_confidence": args.min_confidence,
                    "valid_now": args.valid_now,
                    "keyword": args.keyword,
                    "tier": args.tier,
                },
                "facts": limited,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    # also print count after filter on stderr-friendly last line for humans
    print(f"# filtered_count={len(limited)} (pre_limit={len(filtered)})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
