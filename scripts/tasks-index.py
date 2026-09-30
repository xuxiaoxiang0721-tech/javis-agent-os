#!/usr/bin/env python3
"""Rebuild ~/javis/state/tasks.json index from state/tasks/*.json"""
from __future__ import annotations
import json, os
from pathlib import Path
from datetime import datetime, timezone

root = Path(os.environ.get("JAVIS_ROOT", Path.home() / "javis"))
td = root / "state" / "tasks"
td.mkdir(parents=True, exist_ok=True)
items = []
for p in sorted(td.glob("*.json")):
    if p.name.endswith(".tmp"):
        continue
    with open(p, encoding="utf-8") as f:
        t = json.load(f)
    items.append({
        "task_id": t.get("task_id"),
        "state": t.get("state"),
        "goal": t.get("goal"),
        "session_id": t.get("session_id"),
        "updated_at": t.get("updated_at"),
        "path": str(p),
    })
idx = {
    "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    "count": len(items),
    "tasks": items,
}
out = root / "state" / "tasks.json"
out.write_text(json.dumps(idx, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"ok": True, "path": str(out), "count": len(items)}, ensure_ascii=False))
