#!/usr/bin/env python3
"""Run the real task-control path with synthetic input and no external services."""
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from task_service import ControlService, Principal


def main():
    with tempfile.TemporaryDirectory(prefix="javis-demo-") as directory:
        root = Path(directory)
        service = ControlService(root)
        principal = Principal(
            "demo:local", "local_owner", frozenset({"invest"}),
            frozenset({"task:create", "task:read"}), "offline-demo",
        )
        request = {
            "command_id": "demo-research-001", "role_id": "invest",
            "original_text": "Summarize a synthetic project note.",
            "permission": "R0", "source_line": 2,
        }
        first = service.submit(principal, request)
        replay = service.submit(principal, request)
        state = service.status(principal, first["task_id"])
        summary = {
            "same_task_on_replay": first["task_id"] == replay["task_id"],
            "replayed": replay["replayed"],
            "state": state["state"],
            "attempt": state["attempt"],
            "event_journal_present": any((root / "raw/events").rglob("*.jsonl")),
        }
        assert summary == {
            "same_task_on_replay": True, "replayed": True,
            "state": "queued", "attempt": 0, "event_journal_present": True,
        }, summary
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
