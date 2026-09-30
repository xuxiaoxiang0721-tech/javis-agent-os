"""Read-only, body-free summary for a Codex task to surface memory review work.

This is not owner authentication and cannot review or confirm a fact. Delivery
and its cursor belong to the calling Codex task, not to this snapshot reader.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

ROOT_CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_CODE / "tools/memory-adapter"))
from javis_memory_adapter.review_policy import digest, guarded_path, read_rows
from memory_triage import pending_view


def snapshot(root):
    root = Path(root).resolve()
    pending, reasons, invalid = [], Counter(), 0
    quarantine = guarded_path(root, root / "memory/quarantine")
    for path in sorted(quarantine.glob("*/candidates.jsonl")):
        try:
            rows = read_rows(root, guarded_path(root, path))
            latest = {}
            for row in rows:
                cid = row.get("candidate_id")
                if (not isinstance(cid, str) or not re.fullmatch(r"candidate_[a-f0-9]{32}", cid)
                        or digest(row.get("payload")) != row.get("version_digest")
                        or row.get("status") not in {"pending_review", "confirmed", "rejected"}):
                    raise ValueError("invalid_candidate")
                latest[cid] = row
            for row in latest.values():
                if row["status"] == "pending_review":
                    pending.append("candidate:" + row["candidate_id"] + ":" + row["version_digest"])
        except (ValueError, OSError, KeyError, TypeError):
            invalid += 1
    candidates = len(pending)
    triage = pending_view(root)
    for row in triage["items"]:
        if row["status"] == "needs_review":
            pending.append("triage:" + row["triage_id"])
            reasons[row["reason_code"]] += 1
    invalid += triage["invalid_records"] + triage["invalid_run_records"]
    owner_file = guarded_path(root, root / "state/owner-auth/owner.json")
    value = {"schema": "javis.memory-attention.v1", "pending_tokens": sorted(set(pending)),
             "candidates": candidates, "triage_items": sum(reasons.values()),
             "superseded_triage_items": triage["superseded_count"],
             "reason_counts": dict(sorted(reasons.items())), "invalid_records": invalid,
             "owner_enrolled": owner_file.is_file(), "review_url": "http://localhost:8766/#memory",
             "source_bodies_included": False, "confirmation_authority": False,
             "integrity_scope": "record_hashes; source bindings are rechecked by the owner review page"}
    value["digest"] = digest(value)
    return value


def changes(current, previous=None):
    previous = previous or {}
    new = set(current["pending_tokens"]) - set(previous.get("pending_tokens", []))
    integrity_changed = (current["invalid_records"] > 0 and
                         current["invalid_records"] != previous.get("invalid_records"))
    return {"notify": bool(new or integrity_changed), "new_items": len(new),
            "candidates": current["candidates"], "triage_items": current["triage_items"],
            "invalid_records": current["invalid_records"],
            "owner_registration_required": not current["owner_enrolled"],
            "review_url": current["review_url"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/home/user/javis")
    args = parser.parse_args()
    print(json.dumps(snapshot(args.root), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
