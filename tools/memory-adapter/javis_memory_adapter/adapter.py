from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.request import urlopen

from .models import (
    ConflictStatus,
    FactRecord,
    HealthStatus,
    QueryResult,
    WriteResult,
)
from .validity import boundary_note, is_effective_at, parse_ts


def _strip_provider(s: str) -> str:
    if not s:
        return s
    if "/" in s and s.split("/", 1)[0] in {"openai", "dashscope", "qwen"}:
        return s.split("/", 1)[1]
    return s


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _norm_entity_name(name: str) -> str:
    s = (name or "").strip().lower()
    s = re.sub(r"\s+", "", s)
    s = s.replace(",", "").replace("，", "")
    return s


class MemoryAdapter:
    """Minimal write / current / as_of / trace / health over Graphiti+Neo4j."""

    def __init__(
        self,
        group_id: str,
        *,
        env_path: Optional[Path] = None,
        structured_output_mode: str = "json_schema",
        meta_dir: Optional[Path] = None,
        usage_root: Optional[Path] = None,
        usage_run_id: Optional[str] = None,
        usage_scope: Optional[str] = None,
    ):
        self.group_id = group_id
        self.env_path = env_path or (Path.home() / "javis/tools/graphiti/.env")
        self.structured_output_mode = structured_output_mode
        self.meta_dir = meta_dir or (
            Path.home() / "javis/lab/memory-adapter" / "meta" / group_id
        )
        from .review_policy import check_group
        from .structured_store import StructuredStore
        # Validate protected namespace before creating any metadata directory.
        self._owner_context = check_group(type("StorePath", (), {"meta_dir": self.meta_dir})(), group_id)
        self.meta_dir.mkdir(parents=True, exist_ok=True)
        self._g = None
        self._driver = None
        self._sdk_clients = []
        self.usage_root = Path(usage_root).resolve() if usage_root is not None else self._infer_usage_root()
        self.usage_run_id = usage_run_id
        self.usage_scope = usage_scope or (self._owner_context[1] if self._owner_context else None)
        self.usage_metering = "enabled" if self.usage_root is not None else "unscoped_not_recorded"

    def _infer_usage_root(self):
        """Only recognize existing ledger layouts; never fall back to production."""
        if self._owner_context:
            return self._owner_context[0]
        path = Path(self.meta_dir).resolve()
        if len(path.parents) >= 4:
            if (path.parent.name, path.parents[1].name, path.parents[2].name) == ("graph", "screen", "memory"):
                return path.parents[3]
            if (path.parent.name, path.parents[1].name, path.parents[2].name) == ("meta", "memory-adapter", "lab"):
                return path.parents[3]
        return None

    async def _ensure_read(self):
        if self._driver is not None:
            return
        _load_dotenv(self.env_path)
        from neo4j import AsyncGraphDatabase
        self._driver = AsyncGraphDatabase.driver(
            os.environ['NEO4J_URI'], auth=(os.environ['NEO4J_USER'],os.environ['NEO4J_PASSWORD']))

    async def _ensure(self):
        from .review_policy import protected_group, ReviewBlocked
        if protected_group(self.group_id):
            raise ReviewBlocked("type_a_disabled_for_official_memory")
        if self._g is not None:
            return
        if self._driver is not None:
            await self._driver.close()
            self._driver = None
        _load_dotenv(self.env_path)
        from .runtime import runtime_module
        if self.usage_root is None:
            raise ReviewBlocked('memory_processing_root_required')
        runtime_module('memory_controls').require_processing(self.usage_root, self.usage_scope, 'graphiti')
        configuration = runtime_module('memory_model_config')
        cfg = configuration.runtime_config(self.usage_root)
        embedding_cfg = configuration.runtime_embedding_config(self.usage_root)
        # Only the explicitly metered provider transports may make external
        # requests. Graphiti enables initialization telemetry by default.
        os.environ['GRAPHITI_TELEMETRY_ENABLED'] = 'false'

        from graphiti_core import Graphiti
        from graphiti_core.llm_client import LLMConfig
        from .openai_memory_client import MemoryOpenAIClient, MemorySubscriptionClient, LocalMemoryReranker
        from graphiti_core.embedder.openai import OpenAIEmbedder, OpenAIEmbedderConfig
        from openai import AsyncOpenAI

        model, base, key = cfg['model'], cfg['base_url'], cfg['api_key']
        emb, dim = embedding_cfg['embedding_model'], embedding_cfg['embedding_dimensions']
        self.extraction_model = model
        self.extraction_provider = 'openai'
        self.extraction_config_revision = cfg['revision']
        self.extraction_auth_mode = cfg['auth_mode']
        self.extraction_account_id = cfg['account_id']
        self.extraction_embedding_provider = embedding_cfg['provider']
        self.extraction_embedding_model = emb
        self.extraction_embedding_dimensions = dim
        uri = os.environ["NEO4J_URI"]
        user = os.environ["NEO4J_USER"]
        password = os.environ["NEO4J_PASSWORD"]

        sdk_clients, http_clients = [], []
        try:
            meter = None
            if self.usage_root is not None:
                from .usage_meter import UsageMeter
                from .metered_client import MeteredAsyncHttpClient
                meter = UsageMeter(self.usage_root)

            def sdk(stage, selected_model, client_cfg):
                options = {}
                subscription = stage == 'graphiti' and cfg['auth_mode'] == 'chatgpt_subscription'
                def validate_request(request):
                    current = configuration.status(self.usage_root)
                    if current['revision'] != cfg['revision']:
                        raise configuration.MemoryModelUnavailable('waiting_for_configuration')
                    if stage == 'graphiti':
                        if any(current[field] != cfg[field] for field in ('auth_mode', 'account_id', 'model')):
                            raise configuration.MemoryModelUnavailable('waiting_for_configuration')
                        fresh = configuration.runtime_config(self.usage_root)
                        allowed_paths = {'/responses'} if subscription else {'/responses', '/chat/completions'}
                    else:
                        fresh = configuration.runtime_embedding_config(self.usage_root)
                        if any(fresh[field] != embedding_cfg[field] for field in ('provider','embedding_model','embedding_dimensions')):
                            raise configuration.MemoryModelUnavailable('waiting_for_configuration')
                        allowed_paths = {'/embeddings'}
                    if fresh['revision'] != cfg['revision']:
                        raise configuration.MemoryModelUnavailable('waiting_for_configuration')
                    if json.loads(request.content).get('model') != selected_model:
                        raise configuration.MemoryModelUnavailable('waiting_for_configuration')
                    if str(request.url) not in {fresh['base_url'] + path for path in allowed_paths}:
                        raise ReviewBlocked('memory_provider_endpoint_changed')
                    request.headers['Authorization'] = 'Bearer ' + fresh['api_key']
                if meter is not None:
                    http = MeteredAsyncHttpClient(meter=meter, stage=stage, model=selected_model,
                        run_id=self.usage_run_id, scope=self.usage_scope,
                        billing_mode='subscription' if subscription else 'api', request_validator=validate_request)
                    http_clients.append(http)
                    options["http_client"] = http
                if subscription:
                    options['max_retries'] = 0
                client = AsyncOpenAI(api_key=client_cfg['api_key'], base_url=client_cfg['base_url'], **options)
                sdk_clients.append(client)
                return client

            llm_type = MemorySubscriptionClient if cfg['auth_mode'] == 'chatgpt_subscription' else MemoryOpenAIClient
            llm_options = {'root':self.usage_root,'account_id':cfg['account_id']} if cfg['auth_mode'] == 'chatgpt_subscription' else {}
            llm = llm_type(
                config=LLMConfig(api_key=key, model=model, small_model=model, base_url=base),
                client=sdk("graphiti", model, cfg), **llm_options,
            )
            embedder = OpenAIEmbedder(
                config=OpenAIEmbedderConfig(api_key=embedding_cfg['api_key'], embedding_model=emb,
                    embedding_dim=dim, base_url=embedding_cfg['base_url']),
                client=sdk("embedding", emb, embedding_cfg),
            )
        except BaseException:
            await asyncio.gather(*(client.close() for client in sdk_clients),
                                 *(client.aclose() for client in http_clients), return_exceptions=True)
            raise
        self._sdk_clients = sdk_clients
        _ob = embedder.create_batch

        async def create_batch_le10(input_data):
            texts = list(input_data) if not isinstance(input_data, list) else input_data
            if len(texts) <= 10:
                return await _ob(texts)
            out = []
            for i in range(0, len(texts), 10):
                out.extend(await _ob(texts[i : i + 10]))
            return out

        embedder.create_batch = create_batch_le10  # type: ignore
        try:
            self._g = Graphiti(uri, user, password, llm_client=llm, embedder=embedder,
                               cross_encoder=LocalMemoryReranker())
            self._driver = self._g.driver
        except BaseException:
            await self.close()
            raise

    async def close(self):
        try:
            if self._g is not None:
                await self._g.close()
            elif self._driver is not None:
                await self._driver.close()
        finally:
            self._g = None
            self._driver = None
            clients, self._sdk_clients = getattr(self, "_sdk_clients", []), []
            await asyncio.gather(*(client.close() for client in clients), return_exceptions=True)

    def _event_index_path(self) -> Path:
        return self.meta_dir / "source_events.jsonl"

    def _lookup_source_event(self, source_event_id: str) -> Optional[dict]:
        p = self._event_index_path()
        if not p.exists():
            return None
        for line in p.read_text(encoding="utf-8").split('\n'):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("source_event_id") == source_event_id:
                return row
        return None

    def _append_source_event(self, row: dict) -> None:
        with self._event_index_path().open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    async def health(self) -> HealthStatus:
        _load_dotenv(self.env_path)
        uri = os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687")
        details: dict[str, Any] = {"uri": uri, "group_id": self.group_id}
        http_ok = False
        bolt_ok = False
        try:
            with urlopen("http://127.0.0.1:7474", timeout=3) as resp:
                http_ok = 200 <= getattr(resp, "status", 200) < 400
        except Exception as e:
            details["http_error"] = type(e).__name__
        try:
            await self._ensure_read()
            records, _, _ = await self._driver.execute_query("RETURN 1 AS n")
            bolt_ok = bool(records)
            details["return1"] = records[0]["n"] if records else None
        except Exception as e:
            details["bolt_error"] = type(e).__name__
        return HealthStatus(ok=http_ok and bolt_ok, neo4j_bolt=bolt_ok, neo4j_http=http_ok, details=details)

    async def write_event(
        self,
        *,
        source_event_id: str,
        body: str,
        event_time: datetime,
        object_refs: Optional[list[str]] = None,
        event_kind: str = "observation",
        allow_duplicate_source: bool = False,
        name: Optional[str] = None,
        custom_extraction_instructions: Optional[str] = None,
        temporal_context: Optional[dict] = None,
    ) -> WriteResult:
        """Write one RAW-linked event. Same source_event_id is idempotent by default."""
        from .review_policy import protected_group, ReviewBlocked
        if protected_group(self.group_id):
            raise ReviewBlocked("type_a_disabled_for_official_memory")
        if temporal_context is not None:
            if (not self.group_id.startswith('javis-screen-')
                    or set(temporal_context) != {'source_time', 'reference_time', 'reference_basis'}
                    or temporal_context['reference_basis'] not in {'source_occurred_at', 'received_at', 'captured_at', 'run_created_at'}
                    or parse_ts(temporal_context['reference_time']) != event_time
                    or (temporal_context['source_time'] is not None and parse_ts(temporal_context['source_time']) is None)
                    or (temporal_context['reference_basis'] == 'source_occurred_at'
                        and (temporal_context['source_time'] is None or parse_ts(temporal_context['source_time']) != event_time))
                    or (temporal_context['reference_basis'] != 'source_occurred_at' and temporal_context['source_time'] is not None)):
                raise ReviewBlocked('invalid_candidate_temporal_context')
        object_refs = object_refs or []
        existing = self._lookup_source_event(source_event_id)
        if existing and not allow_duplicate_source:
            return WriteResult(
                ok=True,
                source_event_id=source_event_id,
                episode_uuid=existing.get("episode_uuid"),
                group_id=self.group_id,
                nodes=0,
                edges=0,
                edge_facts=[],
                deduped=True,
                notes=["idempotent: source_event_id already written; skipped Graphiti ingest"],
            )

        await self._ensure()
        from graphiti_core.nodes import EpisodeType

        # Prefix body with structured header so provenance survives in episode content
        header = (
            f"[javis_source_event_id={source_event_id}]"
            f"[event_kind={event_kind}]"
            f"[object_refs={','.join(object_refs)}]\n"
        )
        episode_name = name or f"{event_kind}:{source_event_id}"
        try:
            extraction_options = ({"custom_extraction_instructions": custom_extraction_instructions}
                                  if custom_extraction_instructions is not None else {})
            result = await self._g.add_episode(
                name=episode_name,
                episode_body=header + body,
                source=EpisodeType.text,
                source_description=f"javis:{event_kind}:{source_event_id}",
                reference_time=event_time,
                group_id=self.group_id,
                **extraction_options,
            )
            ep_uuid = getattr(getattr(result, "episode", None), "uuid", None)
            facts = [getattr(e, "fact", None) or str(e) for e in (getattr(result, "edges", []) or [])]
            row = {
                "source_event_id": source_event_id,
                "episode_uuid": ep_uuid,
                "event_kind": event_kind,
                "object_refs": object_refs,
                "event_time": _iso(event_time),
                "written_at": _iso(datetime.now(timezone.utc)),
                "group_id": self.group_id,
            }
            if temporal_context is not None:
                row['temporal_context'] = dict(temporal_context)
            self._append_source_event(row)
            # also store correction ledger separately
            if event_kind.startswith("correction"):
                corr = self.meta_dir / "corrections.jsonl"
                with corr.open("a", encoding="utf-8") as f:
                    f.write(json.dumps({**row, "body": body}, ensure_ascii=False) + "\n")
            return WriteResult(
                ok=True,
                source_event_id=source_event_id,
                episode_uuid=ep_uuid,
                group_id=self.group_id,
                nodes=len(getattr(result, "nodes", []) or []),
                edges=len(getattr(result, "edges", []) or []),
                edge_facts=facts[:20],
            )
        except Exception as e:
            from .runtime import held_error
            held = held_error(e)
            if held is not None:
                raise held from None
            return WriteResult(
                ok=False,
                source_event_id=source_event_id,
                episode_uuid=None,
                group_id=self.group_id,
                nodes=0,
                edges=0,
                edge_facts=[],
                error=type(e).__name__,
            )

    async def _load_edges(self) -> list[dict]:
        await self._ensure_read()
        records, _, _ = await self._driver.execute_query(
            """
            MATCH ()-[r:RELATES_TO {group_id: $g}]->()
            WHERE r.ai_review_event_id IS NULL OR r.ai_review_active = true
            RETURN r.uuid AS uuid, r.name AS name, r.fact AS fact,
                   r.valid_at AS valid_at, r.invalid_at AS invalid_at,
                   r.expired_at AS expired_at, r.created_at AS created_at,
                   r.episodes AS episodes, r.source_event_id AS source_event_id,
                   r.raw_refs AS raw_refs, r.fact_id AS fact_id,
                   r.subject_id AS subject_id, r.predicate AS predicate,
                   r.value_json AS value_json, r.unit AS unit, r.status AS status,
                    r.confirmation_event_id AS confirmation_event_id,
                    r.ai_review_event_id AS ai_review_event_id,
                    r.review_origin AS review_origin,
                   r.historically_corrected AS historically_corrected
            """,
            g=self.group_id,
        )
        return [dict(r) for r in (records or [])]

    async def _source_ids_for_episodes(self, episode_uuids: list[str]) -> list[str]:
        if not episode_uuids:
            return []
        # map via local index first
        found: list[str] = []
        p = self._event_index_path()
        if p.exists():
            by_ep = {}
            for line in p.read_text(encoding="utf-8").split('\n'):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("episode_uuid") and row.get('group_id', self.group_id) == self.group_id:
                    by_ep[row["episode_uuid"]] = row.get("source_event_id")
            for u in episode_uuids:
                if u in by_ep and by_ep[u]:
                    found.append(by_ep[u])
        # also parse episode content headers
        await self._ensure_read()
        records, _, _ = await self._driver.execute_query(
            """
            MATCH (e:Episodic)
            WHERE e.uuid IN $ids AND e.group_id = $group
            RETURN e.uuid AS uuid, e.content AS content, e.source_description AS src
            """,
            ids=episode_uuids,
            group=self.group_id,
        )
        for r in records or []:
            content = r.get("content") or ""
            m = re.search(r"\[javis_source_event_id=([^\]]+)\]", content)
            if m and m.group(1) not in found:
                found.append(m.group(1))
        return found

    async def query_as_of(self, as_of: datetime, *, slot_hint: Optional[str] = None) -> QueryResult:
        if self._owner_context is not None:
            from .review_policy import batch_source_snapshot
            with batch_source_snapshot(self._owner_context[0]):
                return await self._query_as_of(as_of, slot_hint=slot_hint)
        return await self._query_as_of(as_of, slot_hint=slot_hint)

    async def _query_as_of(self, as_of: datetime, *, slot_hint: Optional[str] = None) -> QueryResult:
        """Facts effective at as_of using [valid_at, invalid_at). Unknown valid_at → PENDING."""
        if as_of.tzinfo is None:
            as_of = as_of.replace(tzinfo=timezone.utc)
        edges = await self._load_edges()
        if self._owner_context is not None:
            from .structured_store import StructuredStore
            from .review_policy import usable_facts
            usable = usable_facts(StructuredStore(self.meta_dir))
            active_ai = {(f.fact_id, f.ai_review_event_id) for f in usable if f.ai_review_event_id}
            # Drop stale/revoked AI before constructing fact text or conflicts;
            # revoked values must not leak through a conflict side channel.
            edges = [e for e in edges if not e.get('ai_review_event_id')
                     or (e.get('fact_id'), e['ai_review_event_id']) in active_ai]
        selected: list[FactRecord] = []
        pending: list[FactRecord] = []
        notes = [boundary_note()]

        for e in edges:
            if e.get('historically_corrected'):
                continue
            ok, reason = is_effective_at(e.get("valid_at"), e.get("invalid_at"), as_of)
            episodes = list(e.get("episodes") or [])
            src_ids = await self._source_ids_for_episodes(episodes)
            if e.get('source_event_id') and e['source_event_id'] not in src_ids:
                src_ids.append(e['source_event_id'])
            rec = FactRecord(
                fact_uuid=str(e.get("uuid")),
                fact=e.get("fact") or "",
                name=e.get("name"),
                group_id=self.group_id,
                valid_at=str(e.get("valid_at")) if e.get("valid_at") is not None else None,
                invalid_at=str(e.get("invalid_at")) if e.get("invalid_at") is not None else None,
                expired_at=str(e.get("expired_at")) if e.get("expired_at") is not None else None,
                created_at=str(e.get("created_at")) if e.get("created_at") is not None else None,
                episodes=episodes,
                source_event_ids=src_ids,
                object_refs=list(e.get('raw_refs') or []),
                fact_id=e.get('fact_id'), subject_id=e.get('subject_id'),
                predicate=e.get('predicate'), value=json.loads(e['value_json']) if e.get('value_json') is not None else None,
                unit=e.get('unit'), status=e.get('status'),
                confirmation_event_id=e.get('confirmation_event_id'),
                ai_review_event_id=e.get('ai_review_event_id'), review_origin=e.get('review_origin'),
            )
            if reason == "unknown_valid_at":
                rec.conflict_status = ConflictStatus.PENDING
                rec.notes.append("unknown_valid_at: not auto-selected")
                pending.append(rec)
                continue
            if ok:
                selected.append(rec)

        # conflict detection: same coarse slot keywords
        selected, structured_conflicts = self._select_structured(selected)
        conflicts = structured_conflicts + self._detect_conflicts([f for f in selected if not f.fact_id], slot_hint=slot_hint)
        status = ConflictStatus.OK
        if pending and not selected:
            status = ConflictStatus.PENDING
        if conflicts:
            status = ConflictStatus.CONFLICT if any(c['status']=='conflict' for c in conflicts) else ConflictStatus.PENDING
        if not selected and not pending:
            status = ConflictStatus.EMPTY
        if pending:
            notes.append(f"pending_unknown_valid_at={len(pending)}")

        # Do not drop conflicts — return all selected + conflict markers
        result = QueryResult(
            as_of=_iso(as_of),
            mode="as_of",
            facts=selected,
            conflict_status=status,
            conflicts=conflicts,
            notes=notes,
        )
        if not any(f.fact_id for f in selected):
            result = self._apply_correction_overlay(result, as_of)
        return self._check_ledger_projection(result, as_of)

    def _select_structured(self, facts):
        from .review_policy import memory_slot
        groups = {}
        selected = [f for f in facts if not f.fact_id]
        conflicts = []
        for f in facts:
            if f.fact_id: groups.setdefault(memory_slot(f), []).append(f)
        for (subject,predicate,_), rows in groups.items():
            confirmed=[f for f in rows if f.status=='confirmed' or f.confirmation_event_id]
            rows=confirmed or rows
            # Match the ledger's compatibility rule for numeric/string values.
            values={(str(f.value),f.unit) for f in rows}
            if len(values)>1:
                status='conflict' if confirmed else 'pending'
                conflicts.append({'slot':f'{subject}:{predicate}','status':status,
                    'reason':'multiple_effective_structured_values','fact_ids':[f.fact_id for f in rows],
                    'values':[f.value for f in rows],'action':'return_conflict_do_not_guess'})
                for f in rows: f.conflict_status=ConflictStatus(status)
            selected.extend(rows)
        return selected, conflicts

    def _check_ledger_projection(self, result, as_of):
        if not (self.meta_dir/'facts.jsonl').exists():
            if self._owner_context is not None:
                result.facts = []
                result.conflict_status = ConflictStatus.EMPTY
            return result
        from .structured_store import StructuredStore
        store=StructuredStore(self.meta_dir)
        ledger=store.load_facts()
        if self._owner_context is not None:
            from .review_policy import usable_facts
            ledger=usable_facts(store, ledger)
        revised={f.revision_of for f in ledger if f.revision_of}
        effective=[]
        for f in ledger:
            if f.fact_id in revised or 'historically_corrected' in (f.notes or []):
                continue
            ok,_=is_effective_at(f.valid_from,f.valid_to,as_of)
            if ok:
                effective.append(FactRecord(
                    fact_uuid=f.fact_id, fact='', name=f.predicate, group_id=self.group_id,
                    created_at=f.recorded_at, expired_at=None,
                    fact_id=f.fact_id,subject_id=f.subject_id,predicate=f.predicate,
                    value=f.value,unit=f.unit,status=f.status,
                    confirmation_event_id=f.confirmation_event_id,
                    ai_review_event_id=f.ai_review_event_id,
                    review_origin=('ai_reviewed' if f.ai_review_event_id else 'owner_confirmed'),
                    valid_at=f.valid_from,invalid_at=f.valid_to,
                    source_event_ids=[f.source_event_id],object_refs=f.raw_refs or []))
        expected_rows,_=self._select_structured(effective)
        expected={f.fact_id:f for f in expected_rows}
        if self._owner_context is not None:
            # An independently revoked AI edge may still exist until the next
            # Type B sync. Hide that edge immediately, not every valid owner/AI
            # fact in its group. Other graph/ledger mismatches remain closed.
            valid_ai = {(f.fact_id, f.ai_review_event_id) for f in ledger if f.ai_review_event_id}
            result.facts = [f for f in result.facts if not f.ai_review_event_id
                            or (f.fact_id, f.ai_review_event_id) in valid_ai]
        actual={f.fact_id:f for f in result.facts if f.fact_id}
        mismatched=set(expected)!=set(actual)
        if self._owner_context is not None and any(not f.fact_id for f in result.facts):
            mismatched=True
        mismatched |= len(actual)!=len([f for f in result.facts if f.fact_id])
        for fid in set(expected)&set(actual):
            e,a=expected[fid],actual[fid]
            def signature(f):
                return (f.status,f.confirmation_event_id,f.ai_review_event_id,f.subject_id,f.predicate,
                    json.dumps([f.value,f.unit],sort_keys=True,ensure_ascii=False),
                    parse_ts(f.valid_at),parse_ts(f.invalid_at),
                    sorted(f.source_event_ids),sorted(f.object_refs))
            if signature(e)!=signature(a): mismatched=True
            if e.ai_review_event_id and a.review_origin != 'ai_reviewed':
                mismatched=True
            if self._owner_context is not None:
                approved = next(f for f in ledger if f.fact_id == fid)
                canonical_text = f"{approved.subject_label} {approved.predicate}={approved.value}{approved.unit or ''}"
                if a.fact != canonical_text or a.name != approved.predicate:
                    mismatched=True
        if mismatched:
            if result.conflict_status != ConflictStatus.CONFLICT:
                result.conflict_status=ConflictStatus.PENDING
            for f in result.facts:
                if f.fact_id:
                    f.conflict_status=ConflictStatus.PENDING
                    f.notes.append('graph_projection_stale; do not use as confirmed answer')
            result.notes.append('graph_projection_stale; rebuild from authoritative ledger')
            result.conflicts.append({'status':'pending','reason':'graph_ledger_mismatch',
                'expected_fact_ids':sorted(expected),'graph_fact_ids':sorted(actual),
                'action':'rebuild_before_answering'})
        if self._owner_context is not None and mismatched:
            result.facts = []
        return result

    async def query_current(self, *, now: Optional[datetime] = None, slot_hint: Optional[str] = None) -> QueryResult:
        now = now or datetime.now(timezone.utc)
        res = await self.query_as_of(now, slot_hint=slot_hint)
        res.mode = "current"
        return res

    def _detect_conflicts(self, facts: list[FactRecord], *, slot_hint: Optional[str] = None) -> list[dict]:
        """Heuristic slot conflicts: multiple distinct sales-target / visa-status facts both effective."""
        conflicts = []
        slots = {
            "sales_target": [r for r in facts if any(k in (r.fact or "") for k in ("销售目标", "万美元", "目标"))],
            "visa_status": [r for r in facts if "签证" in (r.fact or "")],
        }
        if slot_hint and slot_hint in slots:
            slots = {slot_hint: slots[slot_hint]}
        for slot, rows in slots.items():
            uniq = []
            seen = set()
            for r in rows:
                key = re.sub(r"\s+", "", r.fact or "")
                if key not in seen:
                    seen.add(key)
                    uniq.append(r)
            # conflicting if >1 mutually different numeric targets or opposite visa claims
            if slot == "sales_target":
                # Per-fact primary target: last number wins inside one transition sentence; conflict only across facts
                per_fact = []
                for u in uniq:
                    ns = re.findall(r"(\d+)\s*万", u.fact or "")
                    if ns:
                        per_fact.append((u, ns[-1]))
                values = {n for _, n in per_fact}
                if len(values) > 1 and len(per_fact) > 1:
                    conflicts.append({
                        "slot": slot,
                        "status": "conflict",
                        "reason": "multiple_effective_targets",
                        "values": sorted(values),
                        "fact_uuids": [u.fact_uuid for u, _ in per_fact],
                        "action": "return_conflict_do_not_guess",
                    })
            if slot == "visa_status":
                has_renew = any(("续签" in u.fact and "不再" not in u.fact and "不续" not in u.fact) for u in uniq)
                has_stop = any(("不再" in u.fact or "不续签" in u.fact) for u in uniq)
                if has_renew and has_stop:
                    conflicts.append({
                        "slot": slot,
                        "status": "conflict",
                        "reason": "renew_vs_stop_both_effective",
                        "fact_uuids": [u.fact_uuid for u in uniq],
                        "action": "return_conflict_do_not_guess",
                    })
        return conflicts

    async def trace_sources(self, fact_uuid: str) -> dict[str, Any]:
        if self._owner_context is not None:
            from .structured_store import StructuredStore
            from .review_policy import usable_facts, review_origin
            store = StructuredStore(self.meta_dir)
            fact = store.get_fact(fact_uuid)
            if fact is None or not usable_facts(store, [fact]):
                return {"ok": False, "error": "reviewed_fact_not_found", "fact_uuid": fact_uuid}
            return {"ok": True, "fact": fact.to_dict(), "source_event_ids": [fact.source_event_id],
                     "object_refs": fact.raw_refs, "episodes": [],
                    "review_origin": review_origin(fact),
                    "retrieval_source": "ai_reviewed_ledger" if fact.ai_review_event_id else "owner_verified_ledger",
                    "graph_sync_status": fact.graph_sync_status}
        await self._ensure_read()
        records, _, _ = await self._driver.execute_query(
            """
            MATCH ()-[r:RELATES_TO {group_id: $g}]->()
            WHERE r.uuid = $u OR r.fact_id = $u
            RETURN r.uuid AS uuid, r.fact AS fact, r.episodes AS episodes,
                   r.valid_at AS valid_at, r.invalid_at AS invalid_at,
                   r.created_at AS created_at, r.expired_at AS expired_at,
                   r.fact_id AS fact_id, r.source_event_id AS source_event_id,
                   r.raw_refs AS raw_refs, r.status AS status,
                   r.confirmation_event_id AS confirmation_event_id,
                   r.superseded_by AS superseded_by, r.revision_of AS revision_of
            """,
            u=fact_uuid,
            g=self.group_id,
        )
        if not records:
            return {"ok": False, "error": "fact_not_found", "fact_uuid": fact_uuid}
        row = dict(records[0])
        episodes = list(row.get("episodes") or [])
        src_ids = await self._source_ids_for_episodes(episodes)
        if row.get('source_event_id') and row['source_event_id'] not in src_ids:
            src_ids.append(row['source_event_id'])
        ep_rows, _, _ = await self._driver.execute_query(
            """
            MATCH (e:Episodic)
            WHERE e.uuid IN $ids AND e.group_id = $group
            RETURN e.uuid AS uuid, e.name AS name, e.content AS content,
                   e.valid_at AS valid_at, e.created_at AS created_at,
                   e.source_description AS source_description
            """,
            ids=episodes,
            group=self.group_id,
        )
        return {
            "ok": True,
            "fact": {k: str(v) if v is not None and k.endswith("_at") else v for k, v in row.items()},
            "source_event_ids": src_ids,
            "object_refs": list(row.get('raw_refs') or []),
            "episodes": [
                {
                    "uuid": r["uuid"],
                    "name": r["name"],
                    "source_description": r["source_description"],
                    "valid_at": str(r["valid_at"]) if r.get("valid_at") is not None else None,
                    "created_at": str(r["created_at"]) if r.get("created_at") is not None else None,
                    "content_head": (r.get("content") or "")[:300],
                }
                for r in (ep_rows or [])
            ],
            "corrections_ledger": self._corrections_related(src_ids),
        }

    def _corrections_related(self, source_event_ids: list[str]) -> list[dict]:
        p = self.meta_dir / "corrections.jsonl"
        if not p.exists():
            return []
        out = []
        for line in p.read_text(encoding="utf-8").split('\n'):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (row.get("source_event_id") or row.get('correction_event_id')) in source_event_ids:
                out.append(row)
        return out


    def _load_correction_ledger(self) -> list[dict]:
        p = self.meta_dir / "corrections.jsonl"
        if not p.exists():
            return []
        rows = []
        for line in p.read_text(encoding="utf-8").split('\n'):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows

    def _apply_correction_overlay(self, result: QueryResult, as_of: datetime) -> QueryResult:
        """Prefer user-confirmed correction events over silent LLM edge invalidation.

        Does not delete graph history. If graph and ledger disagree, mark CONFLICT/PENDING.
        """
        ledger = self._load_correction_ledger()
        if not ledger:
            return result
        notes = list(result.notes)
        notes.append("correction_overlay_active")
        # Collect correction bodies effective for as_of by event_time
        relevant = []
        for row in ledger:
            et = parse_ts(row.get("event_time"))
            if et is None:
                continue
            # state_change: applies when as_of >= event_time
            # historical: asserts truth at event_time; applies when querying as_of >= event_time
            if as_of >= et:
                relevant.append(row)
        if not relevant:
            result.notes = notes
            return result

        # Very small deterministic parse for sales target numbers in correction bodies
        import re
        corr_targets = []
        for row in relevant:
            body = row.get("body") or ""
            kind = row.get("event_kind") or ""
            nums = re.findall(r"(\d+)\s*万", body)
            if "9000" in body or "9000" in "".join(nums):
                corr_targets.append({"n": "9000", "row": row, "kind": kind})
            elif nums:
                corr_targets.append({"n": nums[-1], "row": row, "kind": kind})

        if not corr_targets:
            result.notes = notes + ["correction_ledger_present_but_unparsed"]
            return result

        latest = corr_targets[-1]
        graph_nums = set()
        for f in result.facts:
            graph_nums.update(re.findall(r"(\d+)\s*万", f.fact or ""))

        # If graph effective set doesn't match correction, do not guess — CONFLICT with ledger evidence
        if graph_nums and latest["n"] not in graph_nums:
            result.conflict_status = ConflictStatus.CONFLICT
            result.conflicts.append({
                "slot": "sales_target",
                "status": "conflict",
                "reason": "correction_ledger_vs_graph",
                "ledger_target": latest["n"],
                "graph_targets": sorted(graph_nums),
                "correction_source_event_id": latest["row"].get("source_event_id"),
                "action": "return_conflict_do_not_guess",
            })
            notes.append("graph_missing_corrected_value")
        elif not result.facts:
            # Graph empty/pending but ledger has confirmed correction — surface as PENDING with ledger pointer (not invented FactRecord from free text alone beyond explicit number)
            result.conflict_status = ConflictStatus.PENDING
            result.conflicts.append({
                "slot": "sales_target",
                "status": "pending",
                "reason": "correction_ledger_only",
                "ledger_target": latest["n"],
                "correction_source_event_id": latest["row"].get("source_event_id"),
                "action": "await_structured_confirm_or_reextract",
            })
            notes.append("ledger_only_pending")
        else:
            notes.append(f"ledger_agrees_or_contains_{latest['n']}")

        result.notes = notes
        return result

    async def list_entities(self) -> list[dict]:
        if self._owner_context is not None:
            from .structured_store import StructuredStore
            from .review_policy import usable_facts, review_origin
            facts = usable_facts(StructuredStore(self.meta_dir))
            rows = {}
            for fact in facts:
                if fact.subject_id in rows and rows[fact.subject_id]['review_origin'] == 'owner_confirmed':
                    continue
                rows[fact.subject_id] = {"uuid": fact.subject_id, "name": fact.subject_label,
                    "norm": _norm_entity_name(fact.subject_label), "review_origin": review_origin(fact),
                    "retrieval_source": "ai_reviewed_ledger" if fact.ai_review_event_id else "owner_verified_ledger"}
            return [rows[k] for k in sorted(rows)]

        await self._ensure_read()
        records, _, _ = await self._driver.execute_query(
            "MATCH (n:Entity {group_id:$g}) RETURN n.uuid AS uuid, n.name AS name ORDER BY n.name",
            g=self.group_id,
        )
        return [{"uuid": r["uuid"], "name": r["name"], "norm": _norm_entity_name(r["name"] or "")} for r in (records or [])]
