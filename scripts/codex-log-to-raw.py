#!/usr/bin/env python3
"""Parse Codex exec log + task dir into RAW events (controllable side).

- Links: task_id, session_id, event_id, model, call_path
- Captures: user prompt, model text, exec tool req/result, errors, artifacts
- Excludes: credentials, hidden reasoning (not present when reasoning=none)
- Dedup: stable event_id from (task_id, kind, fingerprint); skip if already in day jsonl
- Marks record_source + completeness; never pretends agent summary is tool log
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, sys, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from runtime_io import lock, atomic_json
from raw_policy import sanitize, CredentialFileBlocked
from raw_storage import append_event as durable_append, snapshot_file as durable_snapshot
from native_permissions import secure_input_bytes
from raw_cursor import ingest_jsonl
from raw_time import native_time

SECRET_KEY_RE = re.compile(r"(password|passwd|secret|token|api[_-]?key|authorization|bearer|cookie|private[_-]?key)", re.I)
SECRET_VAL_RE = re.compile(r"(sk-[A-Za-z0-9_-]{10,}|Bearer\s+[A-Za-z0-9._\-]+)", re.I)

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def stable_id(*parts: str) -> str:
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]
    return f"ev-codex-{h}"

def scrub(obj: Any) -> Any:
    return sanitize(obj)

def parse_codex_log(text: str) -> dict:
    lines = [x for x in text.split('\n') if x.strip()]
    if lines and (lines[0].lstrip().startswith('{') or any(line.lstrip().startswith('{') and '"type"' in line for line in lines)):
        return parse_json_events(lines)
    meta = {"session_id": None, "model": None, "provider": None, "workdir": None}
    m = re.search(r"session id:\s*(\S+)", text)
    if m:
        meta["session_id"] = m.group(1)
    m = re.search(r"^model:\s*(\S+)", text, re.M)
    if m:
        meta["model"] = m.group(1)
    m = re.search(r"^provider:\s*(\S+)", text, re.M)
    if m:
        meta["provider"] = m.group(1)
    m = re.search(r"^workdir:\s*(.+)$", text, re.M)
    if m:
        meta["workdir"] = m.group(1).strip()

    user_prompt = None
    um = re.search(r"(?m)^user\n(.*?)(?=\n(?:warning:|codex|exec)\b)", text, re.S)
    if um:
        user_prompt = um.group(1).strip()

    tools = []
    # Real Codex format:
    # exec
    # /bin/bash -lc "..." in /workdir
    #  succeeded in 0ms:
    # <stdout>
    for em in re.finditer(
        r"(?m)^exec\n(.+?)\n\s*(succeeded|failed)(?: in [^:\n]*)?:\n(.*?)(?=\n(?:codex|exec|tokens used)\b|\Z)",
        text,
        re.S,
    ):
        tools.append({
            "request": em.group(1).strip(),
            "result": em.group(3).strip(),
            "status": em.group(2),
        })

    summaries = re.findall(r"(?m)^SUMMARY:\s*(.+)", text)
    model_texts = []
    for cm in re.finditer(r"(?m)^codex\n(.*?)(?=\n(?:exec|tokens used)\b|\Z)", text, re.S):
        t = cm.group(1).strip()
        if not t:
            continue
        if t.startswith("SUMMARY:"):
            continue
        t = re.split(r"(?m)^SUMMARY:", t)[0].strip()
        if t:
            model_texts.append(t)

    errors = []
    for line in text.splitlines():
        if re.search(r"\berror\b|\bfailed\b|Traceback|EXIT", line, re.I):
            if "succeeded" in line:
                continue
            errors.append(line)

    return {
        "meta": meta,
        "user_prompt": user_prompt,
        "tools": tools,
        "model_texts": model_texts,
        "summaries": summaries,
        "errors": errors,
    }

def parse_json_events(lines):
    meta = {"session_id": None, "model": None, "provider": None, "workdir": None}
    tools, texts, errors = [], [], []
    for line in lines:
        try: e = json.loads(line)
        except json.JSONDecodeError:
            errors.append('invalid JSON event'); continue
        if e.get('type') == 'thread.started': meta['session_id'] = e.get('thread_id')
        if e.get('type') in ('error', 'turn.failed'): errors.append(json.dumps(e, ensure_ascii=False))
        item = e.get('item') or {}
        if e.get('type') != 'item.completed': continue
        kind = item.get('type')
        if kind == 'agent_message': texts.append(item.get('text', ''))
        elif kind == 'command_execution':
            tools.append({'request': item.get('command', ''), 'result': item.get('aggregated_output', ''),
                          'status': 'succeeded' if item.get('exit_code') == 0 else 'failed', 'tool': kind})
        elif kind != 'reasoning':
            # Preserve all non-reasoning items even when their schema is unfamiliar.
            tools.append({'request': json.dumps({k:v for k,v in item.items() if k not in ('result','output')},ensure_ascii=False),
                          'result': json.dumps(item,ensure_ascii=False), 'status': item.get('status','unknown'), 'tool':kind or 'unknown'})
    return {'meta':meta,'user_prompt':None,'tools':tools,'model_texts':texts,'summaries':[], 'errors':errors}

def load_existing_ids(events_path: Path) -> set:
    ids = set()
    if not events_path.exists():
        return ids
    for line in events_path.read_text(encoding="utf-8", errors="replace").split('\n'):
        if not line.strip():
            continue
        try:
            ids.add(json.loads(line).get("event_id"))
        except Exception:
            pass
    return ids

def append_event(root: Path, event: dict, existing: set) -> Optional[str]:
    event = dict(event)
    if event.pop('_replay', False) or event.get('payload', {}).get('record_source') == 'codex_log_parse':
        # Derived legacy text has no source clock. Only an attached original
        # native event can substantiate a replay occurrence, never a wrapper now().
        payload = event.get('payload') or {}
        native = (payload.get('event') if payload.get('record_source') == 'codex_json_stream' else
                  payload.get('native_event') if payload.get('record_source') == 'codex_native_jsonl' else None)
        occurred, basis, field = native_time(native)
        event.update(occurred_at=occurred, time_basis=basis)
        if field is not None: event['source_time_field'] = ('payload.event.' if payload.get('record_source') == 'codex_json_stream' else 'payload.native_event.') + field
        if occurred is None: event.setdefault('missing_reason', 'original_event_timestamp_unavailable')
        event['completeness'] = 'partial'
    return durable_append(root, event, existing)

def snapshot_file(root: Path, file_path: Path, task_id: str, label: str, **kwargs) -> dict:
    return durable_snapshot(root, file_path, task_id, label, **kwargs)

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task-dir", required=True)
    ap.add_argument("--root", default=str(Path.home() / "javis"))
    ap.add_argument("--call-path", default="cards-master-run>run-task>codex-exec")
    ap.add_argument("--attempt", type=int, default=1)
    ap.add_argument("--input-kind", default="original", choices=["original", "append", "wrapper_prompt", "grok_forwarded_summary"])
    ap.add_argument("--gap", action="append", default=[], help="explicit collection gap codes")
    ap.add_argument("--runtime-owns-lifecycle", action="store_true",
                    help="record worker completion separately; runtime owns final task status")
    args = ap.parse_args()
    root = Path(args.root)
    task_dir = Path(args.task_dir)
    packet = json.loads((task_dir / "packet.json").read_text(encoding="utf-8")) if (task_dir / "packet.json").exists() else {}
    result = json.loads((task_dir / "result.json").read_text(encoding="utf-8")) if (task_dir / "result.json").exists() else {}
    log_path = task_dir / "codex.log"
    log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    parsed = parse_codex_log(log_text) if log_text else {"meta": {}, "user_prompt": None, "tools": [], "model_texts": [], "summaries": [], "errors": []}

    tid = packet.get("task_id") or result.get("task_id") or task_dir.name
    role = packet.get("role_id") or result.get("role_id")
    frm = packet.get("from_agent_id") or result.get("from_agent_id")
    session_id = parsed["meta"].get("session_id")
    model = parsed["meta"].get("model")
    day = datetime.now().strftime("%Y%m%d")
    existing = load_existing_ids(root / "raw" / "events" / f"{day}.jsonl")
    written = []
    gaps = list(args.gap)
    cursor_report = None
    json_log = log_text.lstrip().startswith('{') or any(line.lstrip().startswith('{') and '"type"' in line for line in log_text.split('\n'))
    if json_log:
        cursor_report = ingest_jsonl(root, log_path, task_id=tid, attempt=args.attempt, agent=role)
        written.extend(cursor_report['written_event_ids'])
        gaps.extend(cursor_report['gaps'])
    gaps.append('grok_bubble_not_auto_raw')
    gaps.append('historical_tool_timestamps_unavailable')

    base = {
        "schema_version": "javis-raw-event-1",
        "timezone": "UTC",
        "_replay": True,
        "entry": "codex_cli",
        "model": model,
        "execution_path": args.call_path,
        "task_id": tid,
        "session_id": session_id,
        "actor": {"agent_id": frm, "role_id": role},
        "agent": role,
        "payload": {},
    }

    goal = packet.get("goal")
    input_source = args.input_kind
    if input_source == "original":
        completeness = "complete" if goal else "partial"
        is_orig = True
    elif input_source == "append":
        completeness = "complete"
        is_orig = True
    elif input_source == "grok_forwarded_summary":
        completeness = "partial"
        is_orig = False
        gaps.append("grok_forwarded_summary_not_original_user_input")
    else:
        completeness = "partial"
        is_orig = False
        gaps.append("wrapper_prompt_not_raw_user_bubble")

    uid = stable_id(tid, "user_input", str(args.attempt), input_source, hashlib.sha256((goal or "").encode()).hexdigest()[:16])
    ev = {
        **base,
        "event_id": uid,
        "event_type": "user_input",
        "occurred_at": now_iso(),
        "captured_at": now_iso(),
        "completeness": completeness,
        "missing_reason": None if is_orig else "not_original_user_bubble",
        "payload": {
            "text": goal,
            "input_kind": input_source,
            "is_original_user_input": is_orig,
            "record_source": "javis_packet" if is_orig or input_source == "append" else input_source,
            "attempt": args.attempt,
            "model": model,
            "call_path": args.call_path,
        },
    }
    if append_event(root, ev, existing):
        written.append(uid)

    if log_text and not json_log and '\nexec\n' in log_text and not parsed["tools"]:
        gaps.append("codex_log_present_but_exec_blocks_unparsed")
    for i, t in enumerate(parsed["tools"]):
        rid = stable_id(tid, "tool_call", str(args.attempt), str(i), hashlib.sha256(t["request"].encode()).hexdigest()[:16])
        ev = {
            **base,
            "event_id": rid,
            "event_type": "tool_call",
            "occurred_at": now_iso(),
            "captured_at": now_iso(),
            "completeness": "partial",
            "missing_reason": "original_tool_timestamp_unavailable",
            "payload": {
                "tool": t.get("tool", "exec"),
                "request": t["request"],
                "attempt": args.attempt,
                "is_original_tool_log": True,
                "record_source": "codex_log_parse",
                "model": model,
                "call_path": args.call_path,
                "session_id": session_id,
            },
        }
        if append_event(root, ev, existing):
            written.append(rid)
        sid = stable_id(tid, "tool_result", str(args.attempt), str(i), hashlib.sha256((t["request"] + t["result"]).encode()).hexdigest()[:16])
        ev = {
            **base,
            "event_id": sid,
            "event_type": "tool_result",
            "occurred_at": now_iso(),
            "captured_at": now_iso(),
            "completeness": "partial",
            "missing_reason": "original_tool_timestamp_unavailable",
            "payload": {
                "tool": t.get("tool", "exec"),
                "status": t["status"],
                "result": t["result"],
                "attempt": args.attempt,
                "is_original_tool_log": True,
                "record_source": "codex_log_parse",
                "model": model,
                "call_path": args.call_path,
            },
        }
        if append_event(root, ev, existing):
            written.append(sid)

    for i, mt in enumerate(parsed["model_texts"]):
        mid = stable_id(tid, "model_output", str(args.attempt), str(i), hashlib.sha256(mt.encode()).hexdigest()[:16])
        ev = {
            **base,
            "event_id": mid,
            "event_type": "model_output",
            "occurred_at": now_iso(),
            "captured_at": now_iso(),
            "completeness": "partial",
            "missing_reason": "hidden_reasoning_not_collected_by_policy",
            "payload": {
                "text": mt,
                "record_source": "codex_log_parse",
                "is_hidden_reasoning": False,
                "model": model,
                "call_path": args.call_path,
                "attempt": args.attempt,
            },
        }
        if append_event(root, ev, existing):
            written.append(mid)

    summary = result.get("summary_zh") or (parsed["summaries"][-1] if parsed["summaries"] else None)
    if summary and summary not in [re.sub(r'^SUMMARY:\s*', '', text).strip() for text in parsed['model_texts']]:
        mid = stable_id(tid, "agent_summary", str(args.attempt), hashlib.sha256(summary.encode()).hexdigest()[:16])
        ev = {
            **base,
            "event_id": mid,
            "event_type": "model_output",
            "occurred_at": now_iso(),
            "captured_at": now_iso(),
            "completeness": "complete",
            "payload": {
                "text": summary,
                "record_source": "agent_summary",
                "is_original_tool_log": False,
                "is_original_user_input": False,
                "model": model,
                "call_path": args.call_path,
                "attempt": args.attempt,
            },
        }
        if append_event(root, ev, existing):
            written.append(mid)

    status = result.get("status") or "unknown"
    ec = result.get("exit_code")
    if status != "ok" or (ec not in (0, None)):
        eid = stable_id(tid, "error", str(args.attempt), str(ec), status)
        ev = {
            **base,
            "event_id": eid,
            "event_type": "error",
            "occurred_at": now_iso(),
            "captured_at": now_iso(),
            "completeness": "complete",
            "payload": {
                "status": status,
                "exit_code": ec,
                "errors": parsed["errors"],
                "record_source": "javis_wrapper",
                "attempt": args.attempt,
                "call_path": args.call_path,
            },
        }
        if append_event(root, ev, existing):
            written.append(eid)

    lid = stable_id(tid, "task_lifecycle", str(args.attempt), status)
    ev = {
        **base,
        "event_id": lid,
        "event_type": "worker_execution" if args.runtime_owns_lifecycle else "task_lifecycle",
        "occurred_at": now_iso(),
        "captured_at": now_iso(),
        "completeness": "complete",
        "payload": {
            "phase": "worker_finished" if args.runtime_owns_lifecycle else "finished",
            "status": status,
            "exit_code": ec,
            "attempt": args.attempt,
            "session_id": session_id,
            "model": model,
            "call_path": args.call_path,
            "record_source": "javis_wrapper",
        },
    }
    if append_event(root, ev, existing):
        written.append(lid)

    art_refs = []
    out = task_dir / "out"
    if out.exists():
        for fp in sorted(out.rglob("*")):
            if re.fullmatch(r'\.memory-proposals-attempt-[1-9][0-9]*\.json',fp.name):
                continue
            if fp.is_symlink():
                gaps.append('linked_output_not_captured')
                continue
            if fp.is_file():
                if not fp.resolve().is_relative_to(task_dir.resolve()):
                    gaps.append('external_artifact_symlink_not_captured')
                    continue
                try:
                    captured=secure_input_bytes(fp)
                    ref = snapshot_file(root, fp, tid, fp.name, relation='output', capture_key=f'attempt-{args.attempt}',captured_bytes=captured)
                except (CredentialFileBlocked, OSError, ValueError):
                    gaps.append('output_snapshot_failed_or_credential_blocked')
                    continue
                art_refs.append(ref)

    if gaps or not log_text:
        if not log_text:
            gaps.append("codex_log_missing")
        gid = stable_id(tid, "gap", str(args.attempt), ",".join(sorted(set(gaps)))[:80])
        ev = {
            **base,
            "event_id": gid,
            "event_type": "status",
            "occurred_at": now_iso(),
            "captured_at": now_iso(),
            "completeness": "partial",
            "missing_reason": ";".join(sorted(set(gaps))),
            "payload": {
                "kind": "recording_gap",
                "gaps": sorted(set(gaps)),
                "record_source": "javis_wrapper",
                "attempt": args.attempt,
            },
        }
        if append_event(root, ev, existing):
            written.append(gid)

    report = {
        "task_id": tid,
        "session_id": session_id,
        "model": model,
        "attempt": args.attempt,
        "written_event_ids": written,
        "dedup_skipped": True,
        "tool_events": len(parsed["tools"]),
        "artifacts": art_refs,
        "gaps": sorted(set(gaps)),
        "call_path": args.call_path,
        "stream_cursor": cursor_report,
    }
    atomic_json(task_dir / "raw-record-report.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
