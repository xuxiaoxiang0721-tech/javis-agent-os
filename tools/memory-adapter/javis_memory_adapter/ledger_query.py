"""Dual-time queries over structured ledger (authoritative for confirmed corrections)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from .structured_store import StructuredFact, StructuredStore, store_transaction
from .validity import is_effective_at, parse_ts


@store_transaction
def query_effective(store: StructuredStore, at_event_time: datetime) -> dict[str, Any]:
    """What is actually effective at event-time (after applying confirmed corrections)."""
    if at_event_time.tzinfo is None:
        at_event_time = at_event_time.replace(tzinfo=timezone.utc)
    facts = store.load_facts()
    from .review_policy import store_context, usable_facts, memory_slot
    if store_context(store) is not None:
        facts = usable_facts(store, facts)
    selected = []
    for f in facts:
        if f.status == 'superseded' and ('historically_corrected' in (f.notes or []) or
                any(x.revision_of == f.fact_id for x in facts)):
            continue
        if f.status == "superseded":
            # still check interval — superseded facts should have valid_to set
            pass
        ok, reason = is_effective_at(f.valid_from, f.valid_to, at_event_time)
        if not ok:
            continue
        # Prefer confirmed over extracted when both effective for same subject+predicate
        selected.append(f)
    # Collapse same-slot duplicate evidence, retaining conflicts only among the
    # highest-confidence candidates. A closed state-change fact keeps its
    # original confirmation authority inside its historical validity interval.
    best: dict[tuple[str, str], StructuredFact] = {}
    conflicts = []
    groups: dict[tuple[str, str], list[StructuredFact]] = {}
    for f in selected:
        groups.setdefault(memory_slot(f), []).append(f)
    for key, rows in groups.items():
        confirmed = [f for f in rows if f.status == 'confirmed' or
                     (f.status == 'superseded' and f.confirmation_event_id)]
        candidates = confirmed or rows
        floor = datetime.min.replace(tzinfo=timezone.utc)
        best[key] = max(candidates, key=lambda f: (
            parse_ts(f.valid_from) or floor,
            parse_ts(f.recorded_at) or floor,
            f.fact_id,
        ))
        if len({(str(f.value), f.unit) for f in candidates}) > 1:
            conflicts.append({
                'slot': f'{key[0]}:{key[1]}',
                'status': 'conflict' if confirmed else 'pending',
                'reason': 'two_confirmed_effective' if confirmed else 'ambiguous_extracted',
                'fact_ids': [f.fact_id for f in candidates],
                'values': [f.value for f in candidates],
                'units': [f.unit for f in candidates],
            })

    return {
        "mode": "effective_at_event_time",
        "at_event_time": at_event_time.isoformat(),
        "facts": [x.to_dict() for x in best.values()],
        "conflicts": conflicts,
        "status": "conflict" if any(c.get("status") == "conflict" for c in conflicts) else (
            "pending" if any(c.get("status") == "pending" for c in conflicts) else "ok"
        ),
    }


@store_transaction
def query_known(store: StructuredStore, as_of_recorded_at: datetime) -> dict[str, Any]:
    """What the system knew as of recorded_at (ignore facts/corrections recorded later)."""
    if as_of_recorded_at.tzinfo is None:
        as_of_recorded_at = as_of_recorded_at.replace(tzinfo=timezone.utc)
    all_facts = store.load_facts(as_of=as_of_recorded_at)
    from .review_policy import store_context, usable_facts, memory_slot
    if store_context(store) is not None:
        all_facts = usable_facts(store, all_facts, as_of=as_of_recorded_at)
    by_id = {f.fact_id: f for f in all_facts}
    facts = []
    for f in all_facts:
        rec = parse_ts(f.recorded_at)
        if rec is None:
            continue
        if rec <= as_of_recorded_at:
            facts.append(f)
    # Also include confirmation/correction audit for transparency
    confs = [c for c in store.load_confirmations() if (parse_ts(c.get("persisted_at") or c.get("confirmed_at")) or datetime.max.replace(tzinfo=timezone.utc)) <= as_of_recorded_at]
    corrs = [c for c in store.load_corrections() if (parse_ts(c.get("persisted_at")) or datetime.max.replace(tzinfo=timezone.utc)) <= as_of_recorded_at]
    if store_context(store) is not None:
        from .review_policy import SCHEMA
        approved = {f.confirmation_event_id for f in all_facts}
        confs = [c for c in confs if c.get("schema") == SCHEMA and c.get("confirmation_event_id") in approved]
        corrs = [c for c in corrs if c.get("schema") == SCHEMA and c.get("owner_confirmation_event_id") in approved]
    # Restore prior belief when supersession was recorded AFTER as_of (look up superseder in full store).
    visible = []
    for f in facts:
        if f.status == "superseded" and f.superseded_by:
            sup = by_id.get(f.superseded_by)
            sup_rec = parse_ts(sup.recorded_at) if sup else None
            if (sup is None) or (sup_rec is not None and sup_rec > as_of_recorded_at):
                f2 = StructuredFact(**{**f.to_dict(), "status": "confirmed" if f.confirmation_event_id else "extracted", "superseded_by": None})
                visible.append(f2)
                continue
        visible.append(f)
    # Keep the record-time snapshot above: later corrections must not change
    # an earlier belief. Within each slot prefer what that snapshot believed
    # current, rather than letting a newly recorded correction to a closed
    # interval replace a still-current fact. This is not an event-time filter:
    # future-only/closed-only knowledge remains visible when no current row
    # exists. A scheduled state change can leave its predecessor current until
    # the future boundary, even though the predecessor is marked superseded.
    best: dict[tuple[str, str], StructuredFact] = {}
    revised = {f.revision_of for f in visible if f.revision_of}
    floor = datetime.min.replace(tzinfo=timezone.utc)
    def priority(f):
        current, _ = is_effective_at(f.valid_from, f.valid_to, as_of_recorded_at)
        confirmed = f.status == 'confirmed' or (f.status == 'superseded' and bool(f.confirmation_event_id))
        return (current, confirmed, parse_ts(f.recorded_at) or floor,
                parse_ts(f.valid_from) or floor, f.fact_id)
    for f in visible:
        if f.status == "superseded":
            if (f.fact_id in revised or 'historically_corrected' in (f.notes or [])
                    or not is_effective_at(f.valid_from, f.valid_to, as_of_recorded_at)[0]):
                continue
        key = memory_slot(f)
        if key not in best or priority(f) > priority(best[key]):
            best[key] = f
    return {
        "mode": "known_as_of_recorded_at",
        "as_of_recorded_at": as_of_recorded_at.isoformat(),
        "facts": [x.to_dict() for x in best.values()],
        "confirmations_known": confs,
        "corrections_known": corrs,
        "status": "ok",
        "note": "This is system-knowledge time, not event effective time.",
    }


@store_transaction
def query_semantic_memory(store: StructuredStore, *, at_time: Optional[datetime] = None) -> dict[str, Any]:
    """Ordinary recall may use undated memories without calling them current.

    Exact event-time APIs remain unchanged: unknown validity never becomes a
    dated fact. An owner-confirmed value takes precedence over an AI value.
    """
    at = at_time or datetime.now(timezone.utc)
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    from .review_policy import store_context, usable_facts, review_origin, memory_slot
    facts = store.load_facts()
    if store_context(store) is not None:
        facts = usable_facts(store, facts)
    revised = {f.revision_of for f in facts if f.revision_of}
    groups = {}
    for f in facts:
        if f.fact_id in revised or 'historically_corrected' in (f.notes or []):
            continue
        if f.status not in ('confirmed', 'ai_reviewed'):
            continue
        unknown = f.valid_from is None and f.valid_to is None
        if not unknown and not is_effective_at(f.valid_from, f.valid_to, at)[0]:
            continue
        groups.setdefault(memory_slot(f), []).append(f)
    selected, conflicts = [], []
    floor = datetime.min.replace(tzinfo=timezone.utc)
    for (subject, predicate, _), rows in groups.items():
        owner = [f for f in rows if f.status == 'confirmed' and f.confirmation_event_id]
        values = owner or rows
        if len({(str(f.value), f.unit) for f in values}) > 1:
            conflicts.append({'slot': f'{subject}:{predicate}', 'status': 'conflict',
                'reason': 'semantic_memory_values_conflict',
                'fact_ids': [f.fact_id for f in values]})
        best = max(values, key=lambda f: (parse_ts(f.recorded_at) or floor,
                                         parse_ts(f.valid_from) or floor, f.fact_id))
        selected.append({**best.to_dict(), 'review_origin': review_origin(best),
            'validity_state': 'unknown' if best.valid_from is None else 'effective_at_query_time'})
    return {'mode': 'ordinary_semantic_memory', 'at_time': at.isoformat(),
            'facts': selected, 'conflicts': conflicts,
            'validated_fact_ids': sorted({f.fact_id for rows in groups.values() for f in rows}),
            'status': 'conflict' if conflicts else 'ok',
            'note': 'Unknown validity is remembered information, not a claim of current temporal validity.'}


@store_transaction
def apply_state_change(
    store: StructuredStore,
    *,
    subject_id: str,
    subject_label: str,
    predicate: str,
    old_value: Any,
    new_value: Any,
    unit: Optional[str],
    change_at: datetime,
    source_event_id: str,
    raw_refs: list[str],
    confirmation_event_id: Optional[str] = None,
) -> dict[str, Any]:
    """From change_at: close old fact, open new confirmed/extracted fact."""
    from .review_policy import store_context, ReviewBlocked
    if store_context(store) is not None:
        raise ReviewBlocked('owner_review_required')
    from .structured_store import stable_fact_id, StructuredFact, _iso, _now

    if change_at.tzinfo is None:
        change_at = change_at.replace(tzinfo=timezone.utc)
    change_s = _iso(change_at)
    candidates = []
    for f in store.load_facts():
        if (f.subject_id != subject_id or f.predicate != predicate or
                f.status == 'superseded' or str(f.value) != str(old_value) or f.unit != unit):
            continue
        if is_effective_at(f.valid_from, f.valid_to, change_at)[0]:
            candidates.append(f)
    if len(candidates) > 1:
        ids = ', '.join(sorted(f.fact_id for f in candidates))
        raise ValueError(f'ambiguous_state_change: multiple facts cover {change_s}: {ids}')
    closed = []
    for f in candidates:
        new_id = stable_fact_id(
            subject_id=subject_id, predicate=predicate, value=new_value, unit=unit,
            valid_from=change_s, source_event_id=source_event_id,
        )
        f.valid_to = change_s
        f.status = "superseded"
        f.superseded_by = new_id
        f.graph_sync_status = "pending_sync"
        store.upsert_fact(f)
        closed.append(f.fact_id)
    new_fact = StructuredFact(
        fact_id=stable_fact_id(
            subject_id=subject_id, predicate=predicate, value=new_value, unit=unit,
            valid_from=change_s, source_event_id=source_event_id,
        ),
        subject_id=subject_id,
        subject_label=subject_label,
        predicate=predicate,
        value=new_value,
        unit=unit,
        valid_from=change_s,
        valid_to=None,
        recorded_at=_now(),
        source_event_id=source_event_id,
        raw_refs=raw_refs,
        status="confirmed" if confirmation_event_id else "extracted",
        confirmation_event_id=confirmation_event_id,
        supersedes=closed[0] if closed else None,
        graph_sync_status="pending_sync",
        notes=["state_change"],
    )
    store.upsert_fact(new_fact)
    store.write_correction_event({
        "correction_event_id": source_event_id,
        "kind": "state_change",
        "subject_id": subject_id,
        "predicate": predicate,
        "old_value": old_value,
        "new_value": new_value,
        "unit": unit,
        "event_time": change_s,
        "closed_fact_ids": closed,
        "new_fact_id": new_fact.fact_id,
    })
    return {"closed": closed, "new_fact": new_fact.to_dict()}


@store_transaction
def apply_historical_correction(
    store: StructuredStore,
    *,
    subject_id: str,
    subject_label: str,
    predicate: str,
    wrong_value: Any,
    correct_value: Any,
    unit: Optional[str],
    about_event_time: datetime,
    source_event_id: str,
    raw_refs: list[str],
    confirmation_event_id: Optional[str] = None,
) -> dict[str, Any]:
    """Correct what was true at about_event_time; keep audit of previous system belief."""
    from .review_policy import store_context, ReviewBlocked
    if store_context(store) is not None:
        raise ReviewBlocked('owner_review_required')
    from .structured_store import stable_fact_id, StructuredFact, _iso, _now

    if about_event_time.tzinfo is None:
        about_event_time = about_event_time.replace(tzinfo=timezone.utc)
    about_s = _iso(about_event_time)
    facts = store.load_facts()
    already_revised = {f.revision_of for f in facts if f.revision_of}
    candidates = []
    for f in facts:
        if f.subject_id != subject_id or f.predicate != predicate:
            continue
        if str(f.value) != str(wrong_value) or f.unit != unit:
            continue
        # A state-change predecessor remains valid in its old interval, while
        # a historically corrected belief must never be corrected a second time.
        if f.fact_id in already_revised or 'historically_corrected' in (f.notes or []):
            continue
        ok, _ = is_effective_at(f.valid_from, f.valid_to, about_event_time)
        if ok:
            candidates.append(f)
    if len(candidates) > 1:
        ids = ', '.join(sorted(f.fact_id for f in candidates))
        raise ValueError(f'ambiguous_historical_correction: multiple facts cover {about_s}: {ids}')
    for f in candidates:
            new_id = stable_fact_id(
                subject_id=subject_id, predicate=predicate, value=correct_value, unit=unit,
                valid_from=f.valid_from or about_s, source_event_id=source_event_id,
            )
            f.status = "superseded"
            f.superseded_by = new_id
            f.graph_sync_status = "pending_sync"
            f.notes = list(f.notes or []) + ["historically_corrected"]
            store.upsert_fact(f)
            corr = StructuredFact(
                fact_id=new_id,
                subject_id=subject_id,
                subject_label=subject_label,
                predicate=predicate,
                value=correct_value,
                unit=unit,
                valid_from=f.valid_from or about_s,
                valid_to=f.valid_to,
                recorded_at=_now(),
                source_event_id=source_event_id,
                raw_refs=raw_refs,
                status="confirmed" if confirmation_event_id else "extracted",
                confirmation_event_id=confirmation_event_id,
                supersedes=f.fact_id,
                revision_of=f.fact_id,
                graph_sync_status="pending_sync",
                notes=["historical_correction"],
            )
            store.upsert_fact(corr)
            store.write_correction_event({
                "correction_event_id": source_event_id,
                "kind": "historical_correction",
                "subject_id": subject_id,
                "predicate": predicate,
                "wrong_value": wrong_value,
                "correct_value": correct_value,
                "about_event_time": about_s,
                "revised_fact_id": f.fact_id,
                "new_fact_id": new_id,
                "prior_recorded_at": f.recorded_at,
            })
            return {
                "revised_fact_id": f.fact_id,
                "new_fact": corr.to_dict(),
                "audit": {
                    "system_previously_recorded": wrong_value,
                    "previous_fact_id": f.fact_id,
                    "previous_recorded_at": f.recorded_at,
                    "correction_received_at": corr.recorded_at,
                },
            }
    # no existing wrong fact — still record correct belief
    new_id = stable_fact_id(
        subject_id=subject_id, predicate=predicate, value=correct_value, unit=unit,
        valid_from=about_s, source_event_id=source_event_id,
    )
    corr = StructuredFact(
        fact_id=new_id,
        subject_id=subject_id,
        subject_label=subject_label,
        predicate=predicate,
        value=correct_value,
        unit=unit,
        valid_from=about_s,
        valid_to=None,
        recorded_at=_now(),
        source_event_id=source_event_id,
        raw_refs=raw_refs,
        status="confirmed" if confirmation_event_id else "extracted",
        confirmation_event_id=confirmation_event_id,
        graph_sync_status="pending_sync",
        notes=["historical_correction_no_prior"],
    )
    store.upsert_fact(corr)
    store.write_correction_event({
        "correction_event_id": source_event_id,
        "kind": "historical_correction",
        "new_fact_id": new_id,
        "about_event_time": about_s,
        "correct_value": correct_value,
        "wrong_value": wrong_value,
    })
    return {"revised_fact_id": None, "new_fact": corr.to_dict(), "audit": {"system_previously_recorded": None}}
