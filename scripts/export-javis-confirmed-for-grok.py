#!/usr/bin/env python3
"""Export still-valid Javis confirmed facts for Grok bot durable memory writeback.

Run on 0号机. Writes JSONL for parent/box to apply into agent-data memory files.

With config/memory-pipeline.json enabled, only the export list of an owner
passkey-authorized mirror manifest (mirror_batch_review.py) is written; without
such a decision the command still fails closed and leaves --out untouched.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from memory_sources import legacy_gate_enabled
import mirror_batch_review as mirror

SECRET_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|sk-[A-Za-z0-9_-]{10,}|\bPIN\b|private[_-]?key|credential|保险箱|密钥)",
    re.I,
)
L4_RE = re.compile(r"\bL4\b|strict\s*L4|医疗病历|身份证号|护照号", re.I)

ROLE_TO_BOT = {
    "gpt-star": ("Grok Star", "00000000-0000-4000-8000-000000000003"),
    "cards-master": ("Cards Master", "00000000-0000-4000-8000-000000000009"),
    "invest": ("Private Invest bot", "00000000-0000-4000-8000-000000000012"),
    "personal-life": ("Personal Life", "00000000-0000-4000-8000-000000000007"),
    "operations": ("Operations", "00000000-0000-4000-8000-000000000001"),
    "property": ("地产", "00000000-0000-4000-8000-000000000006"),
    "idea-lab": ("Idea Lab", "00000000-0000-4000-8000-000000000002"),
    "ai-data": ("AI 数据", "00000000-0000-4000-8000-000000000010"),
    "domestic-fund": ("国内fund", "00000000-0000-4000-8000-000000000008"),
    "video-man": ("video man", "00000000-0000-4000-8000-000000000011"),
    "shared": ("Grok Star", "00000000-0000-4000-8000-000000000003"),  # shared → Star
}


def still_valid(rec: dict) -> bool:
    temporal = rec.get("temporal") or {}
    vt = temporal.get("valid_to")
    if not vt:
        return True
    try:
        end = datetime.fromisoformat(vt.replace("Z", "+00:00"))
        return end >= datetime.now(timezone.utc)
    except Exception:
        return True


def export_authorized(manifest: dict, auth: dict, out: Path, root: Path | None = None) -> int:
    """Write exactly the owner-authorized export list (re-filtered defensively).

    Entries retired in Javis after the manifest was signed (valid_to tombstone or the
    retirement registry) are dropped, never written back to Grok.
    """
    authz = {k: auth[k] for k in ("mode", "batch_id", "proof_id", "binding_hash", "policy_id") if k in auth}
    retired = mirror.retired_keys(root) if root is not None else {}
    retired_ids = {v for v in retired.values() if v}
    rows, skipped, retired_skipped = [], 0, 0
    for r in manifest["export"]:
        fact = r.get("fact") or ""
        bot_name, agent_id = ROLE_TO_BOT.get(r.get("role"), (None, None))
        if fact and (mirror.norm_key(fact) in retired or (r.get("memory_id") and r.get("memory_id") in retired_ids)):
            retired_skipped += 1
            continue
        if (not fact or SECRET_RE.search(fact) or L4_RE.search(fact)
                or mirror.is_friday_bot(r) or not agent_id):
            skipped += 1
            continue
        rows.append({"role": r["role"], "bot_name": bot_name, "agent_id": agent_id, "fact": fact,
                     "as_of": r.get("as_of"), "learned_at": r.get("learned_at"),
                     "memory_id": r.get("memory_id"), "source": "javis-confirmed",
                     "package_id": manifest["package_id"], "owner_authorization": authz})
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name("." + out.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    tmp.replace(out)
    meta = {"status": "exported", "count": len(rows), "skipped": skipped,
            "retired_skipped": retired_skipped, "out": str(out),
            "package_id": manifest["package_id"], "authorization": authz}
    print(json.dumps(meta, ensure_ascii=False, indent=2))
    (out.parent / "EXPORT-META.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--javis-root", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--package", default=None,
                    help="gate on: package whose owner-authorized manifest defines the export "
                         "(default: memory/imports/grok-javis-bidir-latest)")
    args = ap.parse_args()
    root = Path(args.javis_root or Path.home() / "javis").expanduser().resolve()
    out = Path(args.out).expanduser()
    if legacy_gate_enabled(root):
        pkg = (Path(args.package).expanduser() if args.package
               else root / "memory/imports/grok-javis-bidir-latest").resolve()
        try:
            manifest, auth = mirror.authorization(root, pkg)
        except (ValueError, OSError, KeyError):
            manifest, auth = None, None
        if manifest is None:
            # Never overwrite or erase an earlier user-selected export on rejection.
            # Consumers must check this command's success before using an output.
            print(json.dumps({'status': 'blocked', 'reason': 'owner_review_required',
                'detail': 'legacy_confirmed_records_are_not_current_owner_reviewed_memory',
                'hint': 'prepare with mirror_batch_review.py and confirm with Windows Hello at http://localhost:8766',
                'package': pkg.name, 'export_written': False, 'existing_output_unchanged': True,
                'out': str(out)}, ensure_ascii=False))
            return 2
        return export_authorized(manifest, auth, out, root)
    out.parent.mkdir(parents=True, exist_ok=True)

    files = []
    conf = root / "memory/confirmed"
    shared = conf / "shared" / "facts.jsonl"
    if shared.exists():
        files.append(("shared", shared))
    by_role = conf / "by-role"
    if by_role.exists():
        for d in sorted(by_role.iterdir()):
            f = d / "facts.jsonl"
            if f.exists():
                files.append((d.name, f))

    rows = []
    skipped = 0
    for role, path in files:
        for line in path.read_text(encoding="utf-8").split('\n'):
            if not line.strip():
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            if o.get("tier") and o.get("tier") != "confirmed":
                continue
            if not still_valid(o):
                skipped += 1
                continue
            fact = o.get("fact") or o.get("text") or ""
            if not fact or SECRET_RE.search(fact) or L4_RE.search(fact) or mirror.is_friday_bot({**o, "role": role}):
                skipped += 1
                continue
            # skip facts that originated from grok-mirror to avoid echo loops (optional keep if want)
            tags = o.get("tags") or []
            bot_name, agent_id = ROLE_TO_BOT.get(role, (None, None))
            if not agent_id:
                skipped += 1
                continue
            temporal = o.get("temporal") or {}
            rows.append(
                {
                    "role": role,
                    "bot_name": bot_name,
                    "agent_id": agent_id,
                    "fact": fact,
                    "as_of": temporal.get("as_of") or o.get("as_of"),
                    "learned_at": temporal.get("learned_at") or o.get("learned_at"),
                    "memory_id": o.get("memory_id"),
                    "tags": tags,
                    "source": "javis-confirmed",
                }
            )

    with out.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    meta = {"count": len(rows), "skipped": skipped, "out": str(out)}
    print(json.dumps(meta, ensure_ascii=False, indent=2))
    (out.parent / "EXPORT-META.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(json.dumps({'status': 'blocked', 'reason': 'legacy_export_validation_failed',
            'error_type': type(exc).__name__, 'export_written': False}))
        raise SystemExit(2)
