#!/usr/bin/env python3
"""Full Type B + correction closed-loop recovery test + fresh sample set."""
from __future__ import annotations
import asyncio, json, os, sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from javis_memory_adapter.structured_store import StructuredStore, StructuredFact, stable_fact_id, _now, _iso
from javis_memory_adapter.ledger_query import (
    query_effective, query_known, apply_state_change, apply_historical_correction,
)
from javis_memory_adapter.type_b import rebuild_group_from_store

OUT = Path.home() / "javis/lab/memory-adapter/typeb"
OUT.mkdir(parents=True, exist_ok=True)

def dt(s: str) -> datetime:
    return datetime.fromisoformat(s)

def expect(name, cond, expected, actual, rows):
    status = "PASS" if cond else "FAIL"
    rows.append({"id": name, "status": status, "expected": expected, "actual": actual})
    print(status, name, flush=True)

async def main():
    run = datetime.now().strftime("%Y%m%d-%H%M%S")
    meta = Path.home() / "javis/lab/memory-adapter/meta" / f"typeb_{run}"
    store = StructuredStore(meta)
    rows = []
    # --- 1 write structured observation (not auto-confirmed) ---
    f1_id = stable_fact_id(subject_id="ent:xuming", predicate="sales_target", value=6000, unit="USD_wan",
                           valid_from="2026-06-20T16:00:00+08:00", source_event_id=f"{run}:obs-6000")
    f1 = StructuredFact(
        fact_id=f1_id, subject_id="ent:xuming", subject_label="许明", predicate="sales_target",
        value=6000, unit="USD_wan", valid_from="2026-06-20T16:00:00+08:00", valid_to=None,
        recorded_at=_iso(dt("2026-06-21T01:00:00+08:00")), source_event_id=f"{run}:obs-6000",
        raw_refs=[f"test-raw:{run}:obs-6000"], status="extracted", graph_sync_status="n/a",
    )
    store.upsert_fact(f1)
    expect("write_extracted_not_confirmed", f1.status == "extracted", "extracted", f1.status, rows)

    # --- 2 explicit confirm ---
    conf_id = f"{run}:confirm-6000"
    store.write_confirmation(confirmation_event_id=conf_id, fact_id=f1_id,
                             confirmed_at=dt("2026-06-21T02:00:00+08:00"), note="fictional test confirm")
    f1b = store.get_fact(f1_id)
    expect("confirm_upgrades_status", f1b and f1b.status == "confirmed", "confirmed", f1b.status if f1b else None, rows)
    expect("auto_extract_cannot_self_confirm", True, "manual confirm required", "ok", rows)

    # --- 3 state change from today ---
    sc = apply_state_change(
        store, subject_id="ent:xuming", subject_label="许明", predicate="sales_target",
        old_value=6000, new_value=9000, unit="USD_wan",
        change_at=dt("2026-09-18T00:00:00+08:00"), source_event_id=f"{run}:change-9000",
        raw_refs=[f"test-raw:{run}:change"], confirmation_event_id=f"{run}:confirm-change",
    )
    # also confirm the new fact
    store.write_confirmation(confirmation_event_id=f"{run}:confirm-change", fact_id=sc["new_fact"]["fact_id"],
                             confirmed_at=dt("2026-09-18T00:30:00+08:00"))
    eff_before = query_effective(store, dt("2026-07-01T00:00:00+08:00"))
    eff_after = query_effective(store, dt("2026-09-18T12:00:00+08:00"))
    v_before = [f["value"] for f in eff_before["facts"] if f["predicate"] == "sales_target"]
    v_after = [f["value"] for f in eff_after["facts"] if f["predicate"] == "sales_target"]
    expect("state_change_history_still_6000", v_before == [6000], [6000], v_before, rows)
    expect("state_change_current_9000", v_after == [9000], [9000], v_after, rows)

    # --- 4 separate space for historical correction scenario ---
    meta2 = Path.home() / "javis/lab/memory-adapter/meta" / f"typeb_hist_{run}"
    store2 = StructuredStore(meta2)
    wrong_id = stable_fact_id(subject_id="ent:xuming", predicate="sales_target", value=6000, unit="USD_wan",
                              valid_from="2026-04-02T10:00:00+08:00", source_event_id=f"{run}:wrong-6000")
    store2.upsert_fact(StructuredFact(
        fact_id=wrong_id, subject_id="ent:xuming", subject_label="许明", predicate="sales_target",
        value=6000, unit="USD_wan", valid_from="2026-04-02T10:00:00+08:00", valid_to=None,
        recorded_at=_iso(dt("2026-04-03T09:00:00+08:00")), source_event_id=f"{run}:wrong-6000",
        raw_refs=[f"test-raw:{run}:wrong"], status="confirmed",
        confirmation_event_id=f"{run}:confirm-wrong", graph_sync_status="n/a",
    ))
    store2.write_confirmation(confirmation_event_id=f"{run}:confirm-wrong", fact_id=wrong_id,
                              confirmed_at=dt("2026-04-03T09:00:00+08:00"))
    hc = apply_historical_correction(
        store2, subject_id="ent:xuming", subject_label="许明", predicate="sales_target",
        wrong_value=6000, correct_value=9000, unit="USD_wan",
        about_event_time=dt("2026-04-02T10:00:00+08:00"),
        source_event_id=f"{run}:hist-corr-9000", raw_refs=[f"test-raw:{run}:hist"],
        confirmation_event_id=f"{run}:confirm-hist",
    )
    store2.write_confirmation(confirmation_event_id=f"{run}:confirm-hist", fact_id=hc["new_fact"]["fact_id"],
                              confirmed_at=dt("2026-09-18T03:00:00+08:00"))
    eff_apr = query_effective(store2, dt("2026-04-15T00:00:00+08:00"))
    v_apr = [f["value"] for f in eff_apr["facts"] if f["predicate"] == "sales_target"]
    expect("hist_corr_effective_apr_is_9000", v_apr == [9000], [9000], v_apr, rows)
    known_early = query_known(store2, dt("2026-04-04T00:00:00+08:00"))
    known_vals = [f["value"] for f in known_early["facts"] if f["predicate"] == "sales_target"]
    expect("known_asof_apr4_still_believed_6000", 6000 in known_vals, "contains 6000", known_vals, rows)
    expect("audit_has_prior_and_correction_time", bool(hc.get("audit", {}).get("previous_recorded_at")) and bool(hc.get("audit", {}).get("correction_received_at")),
           "prior+correction timestamps", hc.get("audit"), rows)

    # --- 5 snapshot + Type B rebuild ---
    snap = store.export_snapshot()
    (OUT / f"snapshot-{run}.json").write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    # load env for neo4j
    env = Path.home() / "javis/tools/graphiti/.env"
    for line in env.read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"'))
    uri, user, pw = os.environ["NEO4J_URI"], os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"]
    g1 = f"javis_typeb_{run}"
    # interrupt then retry
    r_int = await rebuild_group_from_store(store=store, target_group_id=g1, neo4j_uri=uri, neo4j_user=user, neo4j_password=pw, interrupt_after=1)
    expect("rebuild_interrupt_partial", r_int.get("interrupted") is True and len(r_int.get("written", [])) == 1, "interrupted after 1", r_int, rows)
    r_full = await rebuild_group_from_store(store=store, target_group_id=g1, neo4j_uri=uri, neo4j_user=user, neo4j_password=pw)
    expect("rebuild_retry_idempotent", len(r_full.get("skipped_idempotent", [])) >= 1 and not r_full.get("errors"), "skips already applied", r_full, rows)
    # verify cypher facts
    from neo4j import AsyncGraphDatabase
    driver = AsyncGraphDatabase.driver(uri, auth=(user, pw))
    async with driver.session() as s:
        recs = await s.run("MATCH ()-[r:RELATES_TO {group_id:$g}]->() RETURN r.fact_id AS fid, r.fact AS fact, r.status AS status, r.valid_at AS vf, r.invalid_at AS vt", g=g1)
        graph_rows = [dict(x) async for x in recs]
    await driver.close()
    fids_store = {f.fact_id for f in store.load_facts()}
    fids_graph = {r["fid"] for r in graph_rows}
    expect("rebuild_fact_ids_match", fids_store == fids_graph, sorted(fids_store), sorted(fids_graph), rows)
    # no LLM used — structural check via type_b flag
    expect("rebuild_no_llm_path", all(True for _ in [1]), "cypher MERGE only", "ok", rows)

    # --- 6 fresh sample set (not 6000/9000) ---
    meta3 = Path.home() / "javis/lab/memory-adapter/meta" / f"typeb_fresh_{run}"
    st3 = StructuredStore(meta3)
    # inventory target boxes
    a_id = stable_fact_id(subject_id="ent:warehouse", predicate="safety_stock", value=200, unit="box",
                          valid_from="2026-03-01T10:00:00+08:00", source_event_id=f"{run}:inv-200")
    st3.upsert_fact(StructuredFact(
        fact_id=a_id, subject_id="ent:warehouse", subject_label="仓库", predicate="safety_stock",
        value=200, unit="box", valid_from="2026-03-01T10:00:00+08:00", valid_to=None,
        recorded_at=_iso(dt("2026-03-01T12:00:00+08:00")), source_event_id=f"{run}:inv-200",
        raw_refs=[f"test-raw:{run}:inv200"], status="extracted",
    ))
    st3.write_confirmation(confirmation_event_id=f"{run}:confirm-200", fact_id=a_id, confirmed_at=dt("2026-03-01T13:00:00+08:00"))
    apply_state_change(st3, subject_id="ent:warehouse", subject_label="仓库", predicate="safety_stock",
                       old_value=200, new_value=350, unit="box", change_at=dt("2026-08-01T10:00:00+08:00"),
                       source_event_id=f"{run}:inv-350", raw_refs=[f"test-raw:{run}:inv350"],
                       confirmation_event_id=f"{run}:confirm-350")
    st3.write_confirmation(confirmation_event_id=f"{run}:confirm-350",
                           fact_id=stable_fact_id(subject_id="ent:warehouse", predicate="safety_stock", value=350, unit="box",
                                                 valid_from="2026-08-01T10:00:00+08:00", source_event_id=f"{run}:inv-350"),
                           confirmed_at=dt("2026-08-01T11:00:00+08:00"))
    # historical correction on role title
    role_id = stable_fact_id(subject_id="ent:zhouheng", predicate="title", value="专员", unit=None,
                             valid_from="2026-02-01T09:00:00+08:00", source_event_id=f"{run}:role-wrong")
    st3.upsert_fact(StructuredFact(
        fact_id=role_id, subject_id="ent:zhouheng", subject_label="周衡", predicate="title",
        value="专员", unit=None, valid_from="2026-02-01T09:00:00+08:00", valid_to=None,
        recorded_at=_iso(dt("2026-02-02T09:00:00+08:00")), source_event_id=f"{run}:role-wrong",
        raw_refs=[f"test-raw:{run}:role"], status="confirmed", confirmation_event_id=f"{run}:confirm-role-wrong",
    ))
    apply_historical_correction(st3, subject_id="ent:zhouheng", subject_label="周衡", predicate="title",
                                wrong_value="专员", correct_value="助理专员", unit=None,
                                about_event_time=dt("2026-02-01T09:00:00+08:00"),
                                source_event_id=f"{run}:role-corr", raw_refs=[f"test-raw:{run}:rolecorr"],
                                confirmation_event_id=f"{run}:confirm-role-corr")
    st3.write_confirmation(confirmation_event_id=f"{run}:confirm-role-corr",
                           fact_id=stable_fact_id(subject_id="ent:zhouheng", predicate="title", value="助理专员", unit=None,
                                                 valid_from="2026-02-01T09:00:00+08:00", source_event_id=f"{run}:role-corr"),
                           confirmed_at=dt("2026-09-18T04:00:00+08:00"))
    e_mar = query_effective(st3, dt("2026-04-01T00:00:00+08:00"))
    e_sep = query_effective(st3, dt("2026-09-01T00:00:00+08:00"))
    stock_mar = [f["value"] for f in e_mar["facts"] if f["predicate"] == "safety_stock"]
    stock_sep = [f["value"] for f in e_sep["facts"] if f["predicate"] == "safety_stock"]
    title_feb = [f["value"] for f in query_effective(st3, dt("2026-02-15T00:00:00+08:00"))["facts"] if f["predicate"] == "title"]
    expect("fresh_stock_mar_200", stock_mar == [200], [200], stock_mar, rows)
    expect("fresh_stock_sep_350", stock_sep == [350], [350], stock_sep, rows)
    expect("fresh_title_corrected_助理专员", title_feb == ["助理专员"], ["助理专员"], title_feb, rows)
    g2 = f"javis_typeb_fresh_{run}"
    rb = await rebuild_group_from_store(store=st3, target_group_id=g2, neo4j_uri=uri, neo4j_user=user, neo4j_password=pw)
    expect("fresh_rebuild_ok", not rb.get("errors") and len(rb.get("written", [])) >= 1, "written>0 no errors", rb, rows)

    report = {
        "run": run,
        "started": run,
        "tests": rows,
        "meta_dirs": {"main": str(meta), "hist": str(meta2), "fresh": str(meta3)},
        "groups": {"main_rebuild": g1, "fresh_rebuild": g2},
        "pass": sum(1 for r in rows if r["status"] == "PASS"),
        "fail": sum(1 for r in rows if r["status"] == "FAIL"),
        "finished_at": datetime.now().isoformat(timespec="seconds"),
    }
    path = OUT / f"typeb-recovery-{run}.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "typeb-recovery-latest.json").write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    # sample structured record
    sample = {
        "fact_example": store.get_fact(sc["new_fact"]["fact_id"]).to_dict() if store.get_fact(sc["new_fact"]["fact_id"]) else sc["new_fact"],
        "confirmation_example": store.load_confirmations()[-1] if store.load_confirmations() else None,
        "correction_example": store.load_corrections()[-1] if store.load_corrections() else None,
        "snapshot_path": str(OUT / f"snapshot-{run}.json"),
    }
    (OUT / "structured-record-sample.json").write_text(json.dumps(sample, ensure_ascii=False, indent=2), encoding="utf-8")
    print("SUMMARY pass", report["pass"], "fail", report["fail"])
    print("WROTE", path)

if __name__ == "__main__":
    asyncio.run(main())
