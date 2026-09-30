#!/usr/bin/env python3
from __future__ import annotations
import argparse, asyncio, json, os
from datetime import datetime, timezone
from pathlib import Path
from .adapter import MemoryAdapter

def _dt(s: str | None) -> datetime:
    if not s:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

async def amain():
    p = argparse.ArgumentParser(prog="javis-memory")
    p.add_argument("--group-id", default=None, help="required for Graphiti write/query/health")
    p.add_argument("--meta-dir", default=None, help="structured ledger dir")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health")

    w = sub.add_parser("write")
    w.add_argument("--source-event-id", required=True)
    w.add_argument("--body", required=True)
    w.add_argument("--event-time", required=True)
    w.add_argument("--event-kind", default="observation")
    w.add_argument("--object-ref", action="append", default=[])
    w.add_argument("--allow-duplicate-source", action="store_true")

    q = sub.add_parser("query-current")
    q.add_argument("--slot-hint")
    q.add_argument("--now")

    a = sub.add_parser("query-as-of")
    a.add_argument("--as-of", required=True)
    a.add_argument("--slot-hint")

    t = sub.add_parser("trace")
    t.add_argument("--fact-uuid", required=True)

    # structured ledger
    qe = sub.add_parser("ledger-effective")
    qe.add_argument("--at", required=True, help="event time ISO")

    qk = sub.add_parser("ledger-known")
    qk.add_argument("--as-of", required=True, help="system recorded-at ISO")

    snap = sub.add_parser("ledger-snapshot")

    rb = sub.add_parser("typeb-rebuild")
    rb.add_argument("--target-group-id", required=True)
    rb.add_argument("--interrupt-after", type=int, default=None)

    args = p.parse_args()

    if args.cmd in {"ledger-effective", "ledger-known", "ledger-snapshot", "typeb-rebuild"}:
        if not args.meta_dir:
            raise SystemExit("--meta-dir required for ledger/typeb commands")
        from .structured_store import StructuredStore
        from .ledger_query import query_effective, query_known
        store = StructuredStore(Path(args.meta_dir))
        if args.cmd == "ledger-effective":
            print(json.dumps(query_effective(store, _dt(args.at)), ensure_ascii=False, indent=2))
        elif args.cmd == "ledger-known":
            print(json.dumps(query_known(store, _dt(args.as_of)), ensure_ascii=False, indent=2))
        elif args.cmd == "ledger-snapshot":
            print(json.dumps(store.export_snapshot(), ensure_ascii=False, indent=2))
        elif args.cmd == "typeb-rebuild":
            from .type_b import rebuild_group_from_store
            # load neo4j env from graphiti .env if present
            envp = Path.home() / "javis/tools/graphiti/.env"
            if envp.exists():
                for line in envp.read_text().splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip('"'))
            r = await rebuild_group_from_store(
                store=store,
                target_group_id=args.target_group_id,
                neo4j_uri=os.environ["NEO4J_URI"],
                neo4j_user=os.environ["NEO4J_USER"],
                neo4j_password=os.environ["NEO4J_PASSWORD"],
                interrupt_after=args.interrupt_after,
            )
            print(json.dumps(r, ensure_ascii=False, indent=2))
        return

    if not args.group_id:
        raise SystemExit("--group-id required for Graphiti commands")
    ad = MemoryAdapter(args.group_id, meta_dir=Path(args.meta_dir) if args.meta_dir else None)
    try:
        if args.cmd == "health":
            print(json.dumps((await ad.health()).to_dict(), ensure_ascii=False, indent=2))
        elif args.cmd == "write":
            r = await ad.write_event(
                source_event_id=args.source_event_id,
                body=args.body,
                event_time=_dt(args.event_time),
                object_refs=args.object_ref,
                event_kind=args.event_kind,
                allow_duplicate_source=args.allow_duplicate_source,
            )
            print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
        elif args.cmd == "query-current":
            r = await ad.query_current(now=_dt(args.now) if args.now else None, slot_hint=args.slot_hint)
            print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
        elif args.cmd == "query-as-of":
            r = await ad.query_as_of(_dt(args.as_of), slot_hint=args.slot_hint)
            print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
        elif args.cmd == "trace":
            print(json.dumps(await ad.trace_sources(args.fact_uuid), ensure_ascii=False, indent=2))
    finally:
        await ad.close()

def main():
    asyncio.run(amain())

if __name__ == "__main__":
    main()
