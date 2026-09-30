#!/usr/bin/env python3
"""Apply staged grok-mirror facts as Javis confirmed. Run on 0号机 WSL as user.

Usage:
  python3 apply-confirmed-on-machine0.py \
    --package ~/javis/memory/imports/<YYYYMMDD>-grok-javis-bidir

With config/memory-pipeline.json enabled, rows become confirmed only when an
owner passkey decision (mirror_batch_review.py) covers this exact package stage;
otherwise they stay local candidates exactly as before.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import memory_sources as sources
import mirror_batch_review as mirror
from javis_memory_adapter.review_policy import digest, guarded_path, safe_id
from raw_storage import _append_line
from runtime_io import atomic_json, lock

SECRET_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|sk-[A-Za-z0-9_-]{10,}|\bPIN\b|private[_-]?key|credential|保险箱|密钥)",
    re.I,
)
L4_RE = re.compile(r"\bL4\b|strict\s*L4|医疗病历|身份证号|护照号", re.I)


def norm_key(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())[:180]


def load_existing(root: Path, role: str) -> dict[str, dict]:
    paths = []
    if role == "shared":
        paths.append(root / "memory/confirmed/shared/facts.jsonl")
    else:
        paths.append(root / "memory/confirmed/by-role" / role / "facts.jsonl")
        paths.append(root / "memory/confirmed/shared/facts.jsonl")
    out = {}
    for p in paths:
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8").split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            fact = o.get("fact") or o.get("text") or ""
            if not fact:
                continue
            # skip invalidated
            temporal = o.get("temporal") or {}
            vt = temporal.get("valid_to")
            if vt:
                try:
                    end = datetime.fromisoformat(vt.replace("Z", "+00:00"))
                    if end < datetime.now(timezone.utc):
                        continue
                except Exception:
                    pass
            k = norm_key(fact)
            as_of = (temporal.get("as_of") or temporal.get("learned_at") or o.get("as_of") or "")
            prev = out.get(k)
            if prev is None or as_of >= (prev.get("_as_of") or ""):
                out[k] = {**o, "_as_of": as_of}
    return out


def apply_pending(root, pkg, *, dry_run=False, limit=0):
    """New installations retain old imports only as local unconfirmed evidence."""
    pkg = guarded_path(root, pkg)
    stage = guarded_path(root, pkg / 'confirmed-stage/ALL-CONFIRMED-READY.jsonl')
    data = stage.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    parsed = list(sources._records(data, '.jsonl'))
    if any(record is None for record, _ in parsed):
        raise ValueError('invalid_legacy_stage_record')
    if limit < 0:
        raise ValueError('limit_must_be_nonnegative')
    if limit:
        parsed = parsed[:limit]
    for record, _ in parsed:
        safe_id(record.get('role') or 'shared')
        if not isinstance(record.get('fact'), str) or not record['fact'].strip():
            raise ValueError('legacy_stage_fact_required')
    result = {'ok': True, 'status': 'pending_evidence_and_owner_review',
        'effective_tier': 'candidate', 'written': 0, 'written_candidates': 0,
        'confirmed_written': 0, 'replayed': 0, 'skipped_secret': 0,
        'error_count': 0, 'package': str(pkg), 'dry_run': dry_run,
        'cloud_eligible': False, 'source_file_sha256': digest}
    def apply_rows():
        snapshot = None
        if not dry_run:
            sources._guard_outputs(root)
            artifact_id = 'legacy-stage-' + hashlib.sha256(str(stage.relative_to(root)).encode()).hexdigest()[:24]
            snapshot = sources._snapshot_source(root, stage, data, artifact_id, 'derived_import_stage')
        for record, location in parsed:
            if SECRET_RE.search(record['fact']) or L4_RE.search(record['fact']):
                result['skipped_secret'] += 1
                continue
            if dry_run:
                result['written_candidates'] += 1
                continue
            source_ref = {'path': stage.relative_to(root).as_posix(),
                'original_file_sha256': digest, **location, 'source_kind': 'derived_memory',
                'snapshot_id': snapshot['snapshot_id'], 'object_sha256': snapshot['sha256'],
                'is_original_user_input': False}
            candidate = sources.stage_legacy_candidate(root,
                {**record, 'role_id': record.get('role') or 'shared', 'tier': 'confirmed',
                 'tags': ['grok-mirror', 'legacy-import-gated']},
                source_key='legacy-import:' + stage.relative_to(root).as_posix() + ':' + str(location['line']),
                source_ref=source_ref)
            result['written_candidates'] += candidate['candidate_written']
            result['replayed'] += candidate['replayed']
        result['written'] = result['written_candidates']
        if not dry_run:
            # No confirmed/watermark/latest-success pointers are advanced.
            atomic_json(guarded_path(root, pkg / 'APPLY-CANDIDATE-RESULT.json'), result)
    if dry_run:
        apply_rows()
    else:
        with lock(guarded_path(root, root / 'state/maintenance.lock'), shared=True), \
             lock(guarded_path(root, root / 'state/locks/legacy-import-gate.lock')):
            sources._ensure_not_held(root)
            apply_rows()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _package_tag(pkg: Path) -> str:
    """bidir-YYYYMMDD from the package id (was hardcoded bidir-20260923)."""
    m = re.match(r"(\d{8})", pkg.name)
    return "bidir-" + (m.group(1) if m else pkg.name[:40])


def _advance_pointers(root: Path, pkg: Path, result: dict) -> None:
    """Watermark + latest pointers for the package actually applied (was hardcoded 20260923)."""
    imports = root / "memory/imports"
    imports.mkdir(parents=True, exist_ok=True)
    stamp = root / "state/grok-all-bots-archive"
    stamp.mkdir(parents=True, exist_ok=True)
    wm_src = pkg / "watermark-after.json"
    if wm_src.exists():
        (stamp / "watermark.json").write_text(wm_src.read_text(encoding="utf-8"), encoding="utf-8")
        (stamp / "latest-import-id.txt").write_text(pkg.name + "\n", encoding="utf-8")
    try:
        for name in ("grok-all-bots-incr-latest", "grok-javis-bidir-latest"):
            link = imports / name
            if pkg.parent.resolve() != imports.resolve():
                continue
            if link.is_symlink() and link.resolve() == pkg.resolve():
                continue
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(pkg.name)
    except Exception as e:
        result["pointer_error"] = str(e)


def _confirmed_path(root: Path, role: str) -> Path:
    if role == "shared":
        return root / "memory/confirmed/shared/facts.jsonl"
    # idea-lab gets a clean confirmed file; the mixed memory/ide-lab file is never touched.
    return root / "memory/confirmed/by-role" / safe_id("idea-lab" if role == "ide-lab" else role) / "facts.jsonl"


def apply_owner_authorized(root: Path, pkg: Path, manifest: dict, auth: dict, *, dry_run=False) -> int:
    """Write the owner-signed manifest's promote list as confirmed. Idempotent."""
    pkg = guarded_path(root, pkg)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    result = {"ok": True, "status": "owner_authorized", "effective_tier": "confirmed",
              "authorization": {k: auth[k] for k in ("mode", "batch_id", "proof_id", "binding_hash", "policy_id") if k in auth},
              "package": str(pkg), "dry_run": dry_run, "confirmed_written": 0, "replayed": 0,
              "skipped_dup": 0, "skipped_secret": 0, "skipped_friday": 0, "skipped_retired": 0, "conflicts": [],
              "manifest_counts": manifest["counts"], "per_role": {}}
    tag = _package_tag(pkg)
    authz = {k: auth[k] for k in ("mode", "batch_id", "proof_id", "binding_hash", "policy_id") if k in auth}

    retired = mirror.retired_keys(root)  # RULES §3.2 tombstones: never re-promote a retired fact

    def rows():
        cache = {}
        for item in manifest["promote"]:
            role, fact = item["role"], item["fact"]
            safe_id(role)
            if mirror.is_secret_or_l4(fact):  # defense in depth; manifest already filtered
                result["skipped_secret"] += 1
                continue
            if mirror.is_friday_bot(item):
                result["skipped_friday"] += 1
                continue
            mid = "m-mirror-" + digest([pkg.name, item["line"], item["fact_sha256"]])[:24]
            path = guarded_path(root, _confirmed_path(root, role))
            ids = cache.setdefault(str(path), {r.get("memory_id") for r in mirror._json_rows(path)} if path.exists() else set())
            if mid in ids:
                result["replayed"] += 1
                continue
            ex = mirror.existing_confirmed(root, role).get(mirror.norm_key(fact))
            if ex is None and mirror.norm_key(fact) in retired:
                result["skipped_retired"] += 1
                continue
            as_of = item.get("as_of") or item.get("learned_at") or ""
            if ex is not None:
                ex_as = ex.get("_as_of") or ""
                if as_of and ex_as and as_of == ex_as:
                    result["skipped_dup"] += 1
                    continue
                if not (as_of and ex_as and as_of > ex_as):
                    result["conflicts"].append({"role": role, "fact": fact[:120], "as_of": as_of,
                        "existing_as_of": ex_as, "reason": "changed_since_owner_review_not_overwritten"})
                    continue
            rec = {"schema_version": "javis-memory-2", "memory_id": mid, "tier": "confirmed",
                   "role_id": role, "fact": fact,
                   "kind": item.get("kind") if item.get("kind") in ("fact", "rule", "decision", "preference", "open_loop") else "fact",
                   "memory_class": "semantic", "confidence": "high", "sensitivity": "normal",
                   "temporal": {"kind": "open_ended", "valid_from": None, "valid_to": None,
                                "as_of": item.get("as_of") or None, "learned_at": item.get("learned_at") or None},
                   "source": {"raw_event_ids": [], "raw_object_sha256": [], "task_id": None,
                              "package_id": pkg.name, "stage_path": manifest["stage_path"],
                              "stage_sha256": manifest["stage_sha256"], "stage_line": item["line"],
                              "claimed_legacy_source": "grok-mirror"},
                   "created_at": now, "confirmed_at": now, "confirmed_by": auth.get("actor_id", "owner:local"),
                   "owner_authorization": authz,
                   "tags": ["grok-mirror", tag, "owner-passkey"], "supersedes": item.get("supersedes")}
            if not dry_run:
                _append_line(path, rec)
                ids.add(mid)
            result["confirmed_written"] += 1
            result["per_role"][role] = result["per_role"].get(role, 0) + 1

    if dry_run:
        rows()
    else:
        with lock(guarded_path(root, root / "state/maintenance.lock"), shared=True), \
             lock(guarded_path(root, root / "state/locks/legacy-memory-append.lock")):
            sources._ensure_not_held(root)
            rows()
            atomic_json(guarded_path(root, pkg / "APPLY-CONFIRMED-RESULT.json"), result)
            _advance_pointers(root, pkg, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", required=True)
    ap.add_argument("--javis-root", default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    pkg = Path(args.package).expanduser().resolve()
    root = Path(args.javis_root or Path.home() / "javis").expanduser().resolve()
    if sources.legacy_gate_enabled(root):
        manifest, auth = mirror.authorization(root, pkg, persist=not args.dry_run)
        if manifest is not None and not args.limit:
            return apply_owner_authorized(root, pkg, manifest, auth, dry_run=args.dry_run)
        return apply_pending(root, pkg, dry_run=args.dry_run, limit=args.limit)
    append = root / "scripts/memory-append.py"
    if not append.exists():
        print(json.dumps({"ok": False, "error": f"missing {append}"}))
        return 2
    stage = pkg / "confirmed-stage" / "ALL-CONFIRMED-READY.jsonl"
    if not stage.exists():
        print(json.dumps({"ok": False, "error": f"missing {stage}"}))
        return 2

    rows = []
    for line in stage.read_text(encoding="utf-8").split('\n'):
        if line.strip():
            rows.append(json.loads(line))
    if args.limit:
        rows = rows[: args.limit]

    by_role: dict[str, list] = {}
    for r in rows:
        by_role.setdefault(r.get("role") or "shared", []).append(r)

    written = 0
    skipped_dup = 0
    skipped_secret = 0
    skipped_friday = 0
    skipped_older = 0
    conflicts = []
    errors = []
    per_role = {}

    for role, items in by_role.items():
        existing = load_existing(root, role)
        role_ok = 0
        for it in items:
            fact = it.get("fact") or ""
            if SECRET_RE.search(fact) or L4_RE.search(fact):
                skipped_secret += 1
                continue
            if mirror.is_friday_bot({**it, "role": role}):
                skipped_friday += 1
                continue
            k = norm_key(fact)
            as_of = it.get("as_of") or ""
            ex = existing.get(k)
            if ex is not None:
                ex_as = ex.get("_as_of") or ""
                if ex_as and as_of and as_of < ex_as:
                    skipped_older += 1
                    continue
                if ex_as and as_of and as_of == ex_as:
                    # same age — treat as dup
                    skipped_dup += 1
                    continue
                if ex_as and as_of and as_of > ex_as:
                    # newer — write superseding; record soft conflict resolved by newer
                    pass
                elif not as_of or not ex_as:
                    conflicts.append({"role": role, "fact": fact[:120], "reason": "cannot_compare_as_of"})
                    continue
                else:
                    skipped_dup += 1
                    continue
            if args.dry_run:
                written += 1
                role_ok += 1
                continue
            cmd = [
                sys.executable,
                str(append),
                "--tier",
                "confirmed",
                "--role",
                role,
                "--fact",
                fact,
                "--confidence",
                "high",
                "--kind",
                it.get("kind") or "fact",
                "--tag",
                "grok-mirror",
                "--tag",
                _package_tag(pkg),
                "--as-of",
                as_of or datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds"),
                "--learned-at",
                it.get("learned_at") or as_of,
                "--temporal-kind",
                "open_ended",
                "--sensitivity",
                "normal",
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, env={**dict(**{k: v for k, v in __import__('os').environ.items()}), "JAVIS_ROOT": str(root)})
            if r.returncode == 0:
                written += 1
                role_ok += 1
                existing[k] = {"_as_of": as_of, "fact": fact}
            else:
                errors.append({"role": role, "fact": fact[:80], "err": (r.stderr or r.stdout)[:300]})
        per_role[role] = role_ok

    result = {
        "ok": True,
        "written": written,
        "skipped_dup": skipped_dup,
        "skipped_older": skipped_older,
        "skipped_secret": skipped_secret,
        "skipped_friday": skipped_friday,
        "conflicts": conflicts,
        "errors": errors[:20],
        "error_count": len(errors),
        "per_role": per_role,
        "package": str(pkg),
        "dry_run": args.dry_run,
    }
    out_path = pkg / "APPLY-CONFIRMED-RESULT.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not args.dry_run:
        _advance_pointers(root, pkg, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(json.dumps({'ok': False, 'status': 'blocked',
            'reason': 'legacy_import_validation_failed', 'error_type': type(exc).__name__}))
        raise SystemExit(2)
