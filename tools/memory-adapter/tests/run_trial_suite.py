#!/usr/bin/env python3
"""Trial suite: query intervals, two corrections, dedupe, rebuild A/B, fresh samples."""
from __future__ import annotations
import asyncio, json, os, sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

# allow running from package root
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from javis_memory_adapter.adapter import MemoryAdapter
from javis_memory_adapter.models import ConflictStatus
from javis_memory_adapter.validity import is_effective_at

OUT = Path.home() / "javis/lab/memory-adapter/trial"
OUT.mkdir(parents=True, exist_ok=True)

def dt(s: str) -> datetime:
    return datetime.fromisoformat(s)

async def main():
    report = {"started_at": datetime.now().isoformat(timespec="seconds"), "tests": []}
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    g = f"javis_memadapt_trial_{run_id}"
    ad = MemoryAdapter(g)

    def add_test(tid, status, **kw):
        row = {"id": tid, "status": status, **kw}
        report["tests"].append(row)
        print("TEST", tid, status, flush=True)

    try:
        h = await ad.health()
        add_test("health", "PASS" if h.ok else "FAIL", health=h.to_dict())
        if not h.ok:
            raise SystemExit("neo4j not healthy")

        # --- unit: validity edges ---
        now = dt("2026-05-01T00:00:00+08:00")
        cases = [
            ("in", "2026-01-01T00:00:00+08:00", None, True),
            ("ended", "2026-01-01T00:00:00+08:00", "2026-04-01T00:00:00+08:00", False),
            ("future", "2026-12-01T00:00:00+08:00", None, False),
            ("unknown", None, None, False),
            ("boundary_end_exclusive", "2026-01-01T00:00:00+08:00", "2026-05-01T00:00:00+08:00", False),
            ("boundary_start_inclusive", "2026-05-01T00:00:00+08:00", None, True),
        ]
        unit_ok = True
        unit_detail = []
        for name, v, inv, expect in cases:
            ok, reason = is_effective_at(v, inv, now)
            unit_detail.append({"name": name, "ok": ok, "reason": reason, "expect": expect})
            if ok != expect:
                unit_ok = False
        add_test("validity_unit", "PASS" if unit_ok else "FAIL", detail=unit_detail)

        # --- seed base sales timeline via adapter ---
        w1 = await ad.write_event(
            source_event_id=f"{run_id}:sales-3000",
            body="许明公司年度销售目标定为3000万美元。",
            event_time=dt("2026-04-02T10:00:00+08:00"),
            object_refs=["obj:sales_target"],
            event_kind="observation",
        )
        w2 = await ad.write_event(
            source_event_id=f"{run_id}:sales-6000",
            body="在引入AI后，许明把公司年度销售目标调整为6000万美元。原来的3000万美元目标不再是当前目标。",
            event_time=dt("2026-06-20T16:00:00+08:00"),
            object_refs=["obj:sales_target"],
            event_kind="observation",
        )
        add_test("seed_sales", "PASS" if w1.ok and w2.ok else "FAIL", w1=w1.to_dict(), w2=w2.to_dict())

        # current should prefer interval logic
        cur = await ad.query_current(now=dt("2026-07-01T00:00:00+08:00"), slot_hint="sales_target")
        add_test(
            "query_current_sales",
            "PASS" if cur.conflict_status in {ConflictStatus.OK, ConflictStatus.CONFLICT, ConflictStatus.PENDING} else "FAIL",
            result=cur.to_dict(),
            note="If CONFLICT, correct behavior is not guessing",
        )
        hist = await ad.query_as_of(dt("2026-05-01T00:00:00+08:00"), slot_hint="sales_target")
        add_test("query_as_of_may", "PASS" if hist.facts is not None else "FAIL", result=hist.to_dict())

        # --- correction A: state change from today 6000 -> 9000 ---
        gA = f"{g}_corrA"
        adA = MemoryAdapter(gA)
        await adA.write_event(source_event_id=f"{run_id}:A-6000", body="当前销售目标为6000万美元。",
                              event_time=dt("2026-06-20T16:00:00+08:00"), object_refs=["obj:sales_target"])
        await adA.write_event(
            source_event_id=f"{run_id}:A-change-9000",
            body="【状态变化】从今天起，销售目标由6000万美元改为9000万美元。",
            event_time=dt("2026-09-18T00:00:00+08:00"),
            object_refs=["obj:sales_target"],
            event_kind="correction_state_change",
        )
        curA = await adA.query_current(now=dt("2026-09-18T12:00:00+08:00"), slot_hint="sales_target")
        pastA = await adA.query_as_of(dt("2026-07-01T00:00:00+08:00"), slot_hint="sales_target")
        add_test("correction_state_change", "PARTIAL", current=curA.to_dict(), as_of_july=pastA.to_dict(),
                 expect="current~9000 effective; july history~6000; keep revision chain via source_event_ids")
        await adA.close()

        # --- correction B: historical record was wrong ---
        gB = f"{g}_corrB"
        adB = MemoryAdapter(gB)
        await adB.write_event(source_event_id=f"{run_id}:B-wrong-6000",
                              body="（错误录入）当时销售目标为6000万美元。",
                              event_time=dt("2026-04-02T10:00:00+08:00"), object_refs=["obj:sales_target"])
        await adB.write_event(
            source_event_id=f"{run_id}:B-fix-was-9000",
            body="【历史纠错】之前录错了：当时（2026-04-02）目标就是9000万美元，不是6000。6000口径作废。",
            event_time=dt("2026-04-02T10:00:00+08:00"),  # same event-time as corrected reality
            object_refs=["obj:sales_target"],
            event_kind="correction_historical",
        )
        # system known time is created_at; event time is valid_at
        curB = await adB.query_as_of(dt("2026-04-15T00:00:00+08:00"), slot_hint="sales_target")
        add_test("correction_historical", "PARTIAL", as_of_apr=curB.to_dict(),
                 expect="as-of Apr should favor corrected 9000 or CONFLICT/PENDING — never silent guess")
        await adB.close()

        # --- T6 revalidate: same source_event_id ---
        gD = f"{g}_dedupe"
        adD = MemoryAdapter(gD)
        d1 = await adD.write_event(source_event_id=f"{run_id}:dup-same", body="许明入职销售部。",
                                   event_time=dt("2026-01-08T10:00:00+08:00"), object_refs=["obj:person:xuming"])
        d2 = await adD.write_event(source_event_id=f"{run_id}:dup-same", body="许明入职销售部。",
                                   event_time=dt("2026-01-08T10:00:00+08:00"), object_refs=["obj:person:xuming"])
        ents = await adD.list_entities()
        # same content different sources
        e1 = await adD.write_event(source_event_id=f"{run_id}:src-mail", body="产品A单价为120美元。",
                                   event_time=dt("2026-07-05T15:00:00+08:00"), object_refs=["obj:productA"])
        e2 = await adD.write_event(source_event_id=f"{run_id}:src-sheet", body="产品A单价为120美元。",
                                   event_time=dt("2026-07-05T15:00:00+08:00"), object_refs=["obj:productA"])
        ents2 = await adD.list_entities()
        add_test(
            "T6_dedupe_revalidate",
            "PASS" if (d1.ok and d2.ok and d2.deduped and e1.ok and e2.ok) else "FAIL",
            same_source={"first": d1.to_dict(), "second": d2.to_dict(), "entities_after_first_pair": ents},
            same_content_diff_source={"mail": e1.to_dict(), "sheet": e2.to_dict(), "entities_after": ents2},
            expect="same source_event_id => no second ingest; diff sources allowed but entity explosion watched",
        )
        await adD.close()

        # --- rebuild A vs B reports (compare entities from previous run) ---
        rebuild_path = Path.home() / "javis/lab/memory-benchmark/runs/run-20260917-233131/rebuild-verify.json"
        rebuild_note = {}
        if rebuild_path.exists():
            rb = json.loads(rebuild_path.read_text(encoding="utf-8"))
            src = set()
            # pull live entity lists if neo available via temp adapters pointing at groups
            ad_src = MemoryAdapter("javis_graphiti_run-20260917-233131")
            ad_dst = MemoryAdapter("javis_graphiti_run-20260917-233131_rebuild")
            try:
                es = await ad_src.list_entities()
                ed = await ad_dst.list_entities()
                ns = {e["norm"] for e in es}
                nd = {e["norm"] for e in ed}
                rebuild_note = {
                    "type_A_from_raw_reextract": {
                        "status": "DOCUMENTED",
                        "src_entities": [e["name"] for e in es],
                        "dst_entities": [e["name"] for e in ed],
                        "only_dst": sorted(nd - ns),
                        "only_src": sorted(ns - nd),
                        "explanation": "dst-only 3000万美元/6000万美元 = amount strings extracted as Entity nodes (LLM non-determinism on re-extract)",
                        "verdict": "NOT identical semantic entity set — expected for Type A",
                    },
                    "type_B_from_confirmed_structured": {
                        "status": "NOT_IMPLEMENTED_YET",
                        "note": "Requires confirmed fact ledger snapshot replay into indexes without re-LLM-extract. Adapter meta source_events is a start; full Type B rebuild is custom thin layer — marked 未验证 until implemented.",
                    },
                    "prior_rebuild_counts": rb.get("src_counts"),
                    "prior_dst_counts": rb.get("dst_counts"),
                }
                add_test("rebuild_diff_A_vs_B", "PARTIAL", **rebuild_note)
            finally:
                await ad_src.close(); await ad_dst.close()
        else:
            add_test("rebuild_diff_A_vs_B", "未验证", note="prior rebuild-verify.json missing")

        # --- fresh samples not used in prior 6-ep debug ---
        gF = f"{g}_fresh"
        adF = MemoryAdapter(gF)
        fresh = [
            ("fresh-1", "2026-02-01T09:00:00+08:00", "周衡加入采购组，职级为专员。"),
            ("fresh-2", "2026-05-10T11:00:00+08:00", "周衡升任采购主管。专员职级废止。"),
            ("fresh-3", "2026-03-01T10:00:00+08:00", "仓库安全库存目标为200箱。"),
            ("fresh-4", "2026-08-01T10:00:00+08:00", "仓库安全库存目标调整为350箱。200箱目标废止。"),
        ]
        fok = True
        for sid, ts, body in fresh:
            r = await adF.write_event(source_event_id=f"{run_id}:{sid}", body=body, event_time=dt(ts), object_refs=[f"obj:{sid}"])
            fok = fok and r.ok
        curF = await adF.query_current(now=dt("2026-09-01T00:00:00+08:00"))
        pastF = await adF.query_as_of(dt("2026-04-01T00:00:00+08:00"))
        add_test("fresh_samples_smoke", "PASS" if fok else "FAIL", current=curF.to_dict(), as_of=pastF.to_dict(),
                 note="new persons/slots not in prior 6-ep set; not production proof")
        await adF.close()

        # patch T6 label reminder into report
        add_test("T6_legacy_label", "SUPERSEDED", note="Legacy T6 PASS from count-only is obsolete; use T6_dedupe_revalidate")

    finally:
        await ad.close()

    report["finished_at"] = datetime.now().isoformat(timespec="seconds")
    report["group_id"] = g
    path = OUT / f"trial-suite-{run_id}.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "trial-suite-latest.json").write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    print("WROTE", path)
    for t in report["tests"]:
        print("SUMMARY", t["id"], t["status"])

if __name__ == "__main__":
    asyncio.run(main())
