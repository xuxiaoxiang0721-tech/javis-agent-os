"""Type B rebuild: structured facts → Neo4j without LLM deciding semantics."""
from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from typing import Any, Optional
from pathlib import Path

from .structured_store import StructuredFact, StructuredStore
from .normalization import metadata


def relation_target(fact):
    """Versioned verified endpoints; legacy source notes retain literal nodes."""
    meta = metadata(fact.to_dict())
    if (meta.get('target_id') and meta.get('target_label')
            and meta.get('evidence', {}).get('source_event_id') == fact.source_event_id):
        return meta['target_id'], meta['target_label'], meta
    return f"val:{fact.predicate}:{fact.value}:{fact.unit or ''}", f"{fact.value}{fact.unit or ''}", meta


def _parse(s: Optional[str]):
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


async def rebuild_group_from_store(**kwargs) -> dict[str, Any]:
    """Project a stable, source-validated ledger snapshot without model calls."""
    from .review_policy import check_group, batch_source_snapshot
    context = check_group(kwargs['store'], kwargs['target_group_id'])
    if context is not None:
        with batch_source_snapshot(context[0]):
            return await _rebuild_group_from_store(**kwargs)
    return await _rebuild_group_from_store(**kwargs)


async def _rebuild_group_from_store(
    *,
    store: StructuredStore,
    target_group_id: str,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    embed: bool = False,
    embedding_model: Optional[str] = None,
    interrupt_after: Optional[int] = None,
) -> dict[str, Any]:
    """Create/update Entity + RELATES_TO from confirmed/extracted structured facts.

    Idempotent on fact_id via checkpoint + MERGE on fact_id property.
    Does NOT call LLM for entity/value/time/relation decisions.
    """
    from .review_policy import check_group, usable_facts, review_origin
    context = check_group(store, target_group_id)
    from neo4j import AsyncGraphDatabase

    if embed:
        raise ValueError('Type B does not build embeddings; use the explicit embedding rebuild pipeline')
    checkpoint = store.load_checkpoint()
    # The graph may have been lost even when the checkpoint survived. Always
    # replay MERGE, also updating facts whose confirmation/validity changed.
    applied = set(checkpoint.get("applied_fact_ids") or []) if checkpoint.get('target_group_id') == target_group_id else set()
    facts = [f for f in store.load_facts() if f.status in {"extracted", "confirmed", "superseded", "ai_reviewed"}]
    if context is not None:
        facts = usable_facts(store, facts)
    # Prefer non-superseded for "current graph projection"; still write superseded for audit edges
    report = {
        "target_group_id": target_group_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "embed": embed,
        "embedding_model": embedding_model if embed else None,
        "planned": len(facts),
        "applied_before": len(applied),
        "written": [],
        "skipped_idempotent": [],
        "errors": [],
        "interrupted": False,
    }

    driver = AsyncGraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    try:
        n = 0
        async with driver.session() as session:
            if context is not None:
                # Keep history, but remove revoked/invalid AI versions from the
                # active projection. Owner-confirmed relationships are untouched.
                invalidated = await session.run(
                    """MATCH ()-[r:RELATES_TO {group_id: $g}]->()
                    WHERE r.ai_review_event_id IS NOT NULL
                      AND NOT r.ai_review_event_id IN $active_ai_reviews
                    SET r.ai_review_active = false, r.status = 'revoked'
                    """, g=target_group_id,
                    active_ai_reviews=[f.ai_review_event_id for f in facts if f.ai_review_event_id])
                await invalidated.consume()
            for fact in facts:
                if interrupt_after is not None and n >= interrupt_after:
                    report["interrupted"] = True
                    break
                try:
                    # MERGE entity by stable subject_id in this group
                    await session.run(
                        """
                        MERGE (s:Entity {group_id: $g, stable_id: $sid})
                        ON CREATE SET s.uuid = randomUUID(), s.name = $slabel, s.created_at = datetime()
                        ON MATCH SET s.name = $slabel
                        """,
                        g=target_group_id,
                        sid=fact.subject_id,
                        slabel=fact.subject_label,
                    )
                    # New verified metadata gives the actual entity endpoint;
                    # old notes remain readable without guessing a new target.
                    obj_sid, obj_label, structure = relation_target(fact)
                    await session.run(
                        """
                        MERGE (o:Entity {group_id: $g, stable_id: $oid})
                        ON CREATE SET o.uuid = randomUUID(), o.name = $olabel, o.created_at = datetime()
                        ON MATCH SET o.name = $olabel
                        """,
                        g=target_group_id,
                        oid=obj_sid,
                        olabel=obj_label,
                    )
                    # relationship with stable fact_id
                    result = await session.run(
                        """
                        MATCH (s:Entity {group_id: $g, stable_id: $sid})
                        MATCH (o:Entity {group_id: $g, stable_id: $oid})
                        MERGE (s)-[r:RELATES_TO {group_id: $g, fact_id: $fid}]->(o)
                        ON CREATE SET r.uuid = randomUUID(), r.created_at = datetime()
                        SET r.name = $pred,
                            r.fact = $fact_text,
                            r.valid_at = CASE WHEN $vf IS NULL THEN NULL ELSE datetime($vf) END,
                            r.invalid_at = CASE WHEN $vt IS NULL THEN NULL ELSE datetime($vt) END,
                            r.status = $status,
                            r.source_event_id = $seid,
                            r.confirmation_event_id = $ceid,
                            r.ai_review_event_id = $ai_review_event_id,
                            r.ai_review_active = $ai_review_active,
                            r.review_origin = $review_origin,
                            r.superseded_by = $sup_by,
                            r.revision_of = $rev,
                            r.subject_id = $sid,
                            r.predicate = $pred,
                            r.value_json = $value_json,
                            r.unit = $unit,
                            r.raw_refs = $raw_refs,
                            r.object_id = $oid,
                            r.object_label = $olabel,
                            r.structure_version = $structure_version,
                            r.predicate_cardinality = $predicate_cardinality,
                            r.identity_resolution = $identity_resolution,
                            r.target_identity_resolution = $target_identity_resolution,
                            r.evidence_start = $evidence_start,
                            r.evidence_end = $evidence_end,
                            r.evidence_offset_unit = $evidence_offset_unit,
                            r.evidence_quote_sha256 = $evidence_quote_sha256,
                            r.evidence_source_text_sha256 = $evidence_source_text_sha256,
                            r.structure_notes = $structure_notes,
                            r.historically_corrected = $historically_corrected,
                            r.type_b = true,
                            r.episodes = []
                        """,
                        g=target_group_id,
                        sid=fact.subject_id,
                        oid=obj_sid,
                        olabel=obj_label,
                        fid=fact.fact_id,
                        pred=fact.predicate,
                        fact_text=_fact_text(fact),
                        vf=fact.valid_from,
                        vt=fact.valid_to,
                        status=fact.status,
                        seid=fact.source_event_id,
                        ceid=fact.confirmation_event_id,
                        ai_review_event_id=fact.ai_review_event_id,
                        ai_review_active=True if fact.ai_review_event_id else None,
                        review_origin=review_origin(fact) if context is not None else None,
                        sup_by=fact.superseded_by,
                        rev=fact.revision_of,
                        value_json=json.dumps(fact.value, ensure_ascii=False, sort_keys=True),
                        unit=fact.unit,
                        raw_refs=fact.raw_refs or [],
                        structure_version=structure.get('version'),
                        predicate_cardinality=structure.get('cardinality'),
                        identity_resolution=structure.get('identity_resolution'),
                        target_identity_resolution=structure.get('target_identity_resolution'),
                        evidence_start=structure.get('evidence', {}).get('start'),
                        evidence_end=structure.get('evidence', {}).get('end'),
                        evidence_offset_unit=structure.get('evidence', {}).get('offset_unit'),
                        evidence_quote_sha256=structure.get('evidence', {}).get('quote_sha256'),
                        evidence_source_text_sha256=structure.get('evidence', {}).get('source_text_sha256'),
                        structure_notes=fact.notes or [],
                        historically_corrected=('historically_corrected' in (fact.notes or []) or
                            any(f.revision_of == fact.fact_id for f in facts)),
                    )
                    # Auto-commit errors may surface when the result is consumed.
                    # Never report ledger synchronization before that succeeds.
                    await result.consume()
                    applied.add(fact.fact_id)
                    n += 1
                    report["written"].append(fact.fact_id)
                    # optional: mark sync
                    if not store.mark_graph_synced(fact):
                        report['errors'].append({'fact_id':fact.fact_id,
                            'error':'ledger_changed_during_rebuild; replay required'})
                except Exception as e:
                    report["errors"].append({"fact_id": fact.fact_id, "error": type(e).__name__})
            store.save_checkpoint({"applied_fact_ids": sorted(applied), "updated_at": datetime.now(timezone.utc).isoformat(), "target_group_id": target_group_id})
    finally:
        await driver.close()

    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["applied_after"] = len(applied)
    return report


def _fact_text(f: StructuredFact) -> str:
    unit = f.unit or ""
    return f"{f.subject_label} {f.predicate}={f.value}{unit}"
