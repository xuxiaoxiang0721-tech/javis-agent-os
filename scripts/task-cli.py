#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal JSON task CLI for ~/javis/state (design §8).

Commands:
  create --goal TEXT [--task-id ID]
  update TASK_ID --state STATE [--session-id S] [--failure REASON] [--attempt N]
  list [--state STATE]
  get TASK_ID

States: created, running, waiting_user, paused, completed, failed, cancelled
NOT_VERIFIED_ON_TARGET
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from functools import wraps
from runtime_io import atomic_json, lock
from raw_policy import sanitize
from task_control import state_event

def locked_write(fn):
    @wraps(fn)
    def wrapped(args):
        root=root_dir()
        if not args.task_id: args.task_id=f't-{uuid.uuid4().hex[:12]}'
        task_path(root,args.task_id)
        with lock(root/'state/maintenance.lock',shared=True),lock(root/'state/locks'/f'{args.task_id}.lock',blocking=False):
            return fn(args)
    return wrapped

STATES = {
    "created",
    "running",
    "waiting_user",
    "paused",
    "completed",
    "failed",
    "cancelled",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def root_dir() -> Path:
    return Path(os.environ.get("JAVIS_ROOT", Path.home() / "javis"))


def tasks_dir(root: Path) -> Path:
    d = root / "state" / "tasks"
    d.mkdir(parents=True, exist_ok=True)
    return d


def task_path(root: Path, task_id: str) -> Path:
    safe = "".join(c for c in task_id if c.isalnum() or c in "-_")
    if safe != task_id or not task_id:
        raise ValueError("invalid task_id")
    return tasks_dir(root) / f"{task_id}.json"


def load_task(root: Path, task_id: str) -> Dict[str, Any]:
    p = task_path(root, task_id)
    if not p.exists():
        raise FileNotFoundError(task_id)
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save_task(root: Path, task: Dict[str, Any]) -> Path:
    p = task_path(root, task["task_id"])
    atomic_json(p,sanitize(task))
    state_event(root,sanitize(task),'manual_state_update')
    return p


@locked_write
def cmd_create(args: argparse.Namespace) -> int:
    root = root_dir()
    tid = args.task_id or f"t-{uuid.uuid4().hex[:12]}"
    if task_path(root, tid).exists():
        print(f"ERROR: task exists: {tid}", file=sys.stderr)
        return 1
    task = {
        "task_id": tid,
        "state": "created",
        "goal": sanitize(args.goal),
        "entry": args.entry or "codex_cli",
        "agent": "gpt_star",
        "model": None,
        "session_id": None,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "artifact_refs": [],
        "risk": None,
        "approval_refs": [],
        "failure_reason": None,
        "memory_write_refs": [],
        "attempt": 0,
        "role_id": "gpt-star",
        "state_origin": "manual_task_create",
    }
    p = save_task(root, task)
    # workspace folder
    ws = root / "workspace" / "tasks" / tid
    ws.mkdir(parents=True, exist_ok=True)
    print(json.dumps({"ok": True, "path": str(p), "task": task}, ensure_ascii=False))
    return 0


@locked_write
def cmd_update(args: argparse.Namespace) -> int:
    root = root_dir()
    task = load_task(root, args.task_id)
    if task.get('control_managed'):
        raise ValueError('managed task metadata is runtime-owned; use common submit/command/status/result')
    if args.state:
        if args.state in {'running','paused','cancelled','completed'}:
            raise ValueError('runtime states require runner/task-control; metadata update cannot prove execution stopped or completed')
        if args.state not in STATES:
            print(f"ERROR: state must be one of {sorted(STATES)}", file=sys.stderr)
            return 2
        task["state"] = args.state
    if args.session_id is not None:
        task["session_id"] = args.session_id
    if args.failure is not None:
        task["failure_reason"] = args.failure
    if args.attempt is not None:
        task["attempt"] = int(args.attempt)
    if args.model is not None:
        task["model"] = args.model
    task["updated_at"] = now_iso()
    task["state_origin"] = "manual_metadata_update"
    p = save_task(root, task)
    print(json.dumps({"ok": True, "path": str(p), "task": sanitize(task)}, ensure_ascii=False))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    root = root_dir()
    items: List[Dict[str, Any]] = []
    for p in sorted(tasks_dir(root).glob("*.json")):
        with open(p, encoding="utf-8") as f:
            t = json.load(f)
        if args.state and t.get("state") != args.state:
            continue
        items.append(
            {
                "task_id": t.get("task_id"),
                "state": t.get("state"),
                "goal": t.get("goal"),
                "updated_at": t.get("updated_at"),
            }
        )
    print(json.dumps({"ok": True, "count": len(items), "tasks": items}, ensure_ascii=False, indent=2))
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    root = root_dir()
    task = load_task(root, args.task_id)
    print(json.dumps({"ok": True, "task": task}, ensure_ascii=False, indent=2))
    return 0


def cmd_common(args):
    from task_control import ControlService
    from task_service import local_principal
    service=ControlService(root_dir());principal=local_principal()
    request=json.loads(Path(args.request_file).read_text(encoding='utf-8-sig')) if getattr(args,'request_file',None) else None
    if args.cmd=='submit':result=service.submit(principal,request)
    elif args.cmd=='command':result=service.command(principal,args.task_id,request)
    elif args.cmd=='status':result=service.status(principal,args.task_id)
    elif args.cmd=='result':result=service.result(principal,args.task_id,args.attempt)
    else:result=service.list_tasks(principal)
    print(json.dumps(result,ensure_ascii=False,indent=2));return 0

def main() -> int:
    ap = argparse.ArgumentParser(description="Javis minimal task CLI (JSON)")
    sp = ap.add_subparsers(dest="cmd", required=True)
    for name in ('submit','command','status','result','tasks'):
        common=sp.add_parser(name)
        if name in {'command','status','result'}:common.add_argument('task_id')
        if name in {'submit','command'}:common.add_argument('--request-file',required=True)
        if name=='result':common.add_argument('--attempt',type=int)
        common.set_defaults(func=cmd_common)

    c = sp.add_parser("create")
    c.add_argument("--goal", required=True)
    c.add_argument("--task-id", default=None)
    c.add_argument("--entry", default="codex_cli")
    c.set_defaults(func=cmd_create)

    u = sp.add_parser("update")
    u.add_argument("task_id")
    u.add_argument("--state", default=None)
    u.add_argument("--session-id", default=None)
    u.add_argument("--failure", default=None)
    u.add_argument("--attempt", type=int, default=None)
    u.add_argument("--model", default=None)
    u.set_defaults(func=cmd_update)

    l = sp.add_parser("list")
    l.add_argument("--state", default=None)
    l.set_defaults(func=cmd_list)

    g = sp.add_parser("get")
    g.add_argument("task_id")
    g.set_defaults(func=cmd_get)

    args = ap.parse_args()
    try:
        return args.func(args)
    except BlockingIOError:
        print('ERROR: task running; use task-control to request pause/cancel',file=sys.stderr)
        return 75
    except FileNotFoundError as e:
        print(f"ERROR: not found: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
