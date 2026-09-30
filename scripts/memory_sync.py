#!/usr/bin/env python3
"""Immutable Invest audit snapshots. This module never merges memory.

run(root, now=None, side='codex_invest') publishes a content-addressed version.
Grok publication additionally requires an explicit separate source_root export.
status(root, now=None) is read-only and returns an allowlisted public summary.
Neither importing this module nor calling status creates directories or files.
Grok and Codex must invoke run independently; one never impersonates the other.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

TZ = timezone(timedelta(hours=8))
SIDES = ("codex_invest", "grok_invest")
SCHEMA = "invest-daily-sync-2"
SYNC_ROOT = Path("memory/sync/0_codex_invest")
HEX = re.compile(r"[a-f0-9]{64}")


def _time(now=None):
    value = now or datetime.now(TZ)
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")
    return value.astimezone(TZ)


def _encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _safe(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("unsafe_path")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink_path")
    return current


def _read(root, relative):
    return json.loads(_safe(root, relative).read_text(encoding="utf-8"))


def recovery_held(root):
    """A released hold file is valid; corrupt, untyped or linked holds fail closed."""
    root = Path(root).resolve()
    try:
        path = _safe(root, "state/recovery-hold.json")
        if not path.exists():
            return False
        value = json.loads(path.read_text(encoding="utf-8"))
        return not (isinstance(value, dict) and value.get("hold") is False)
    except (OSError, ValueError, TypeError):
        return True


@contextlib.contextmanager
def _lock(path, shared=False):
    """Process-scoped lock; a crash releases it without a stale lock-file policy."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, "r+b") as stream:
        if os.name == "nt":
            import msvcrt
            if stream.seek(0, os.SEEK_END) == 0:
                stream.write(b"0"); stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def _atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".sync-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(_encoded(value) + b"\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _sync_directory(path):
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _sources(side):
    # Explicit allowlist: never sweep arbitrary folders or credential stores.
    values = [("memory/profiles/invest.json", "profile")]
    for scope in ("invest", "shared"):
        legacy = f"memory/confirmed/by-role/{scope}/facts.jsonl" if scope != "shared" else "memory/confirmed/shared/facts.jsonl"
        values.append((legacy, "legacy_confirmed"))
        for name in ("facts.jsonl", "confirmations.jsonl", "corrections.jsonl", "source_events.jsonl"):
            values.append((f"memory/structured/{scope}/{name}", "structured_ledger"))
    values += [("docs/invest-core-rules-bundle-20260922.md", "rules_document"),
               ("docs/美股投研与FCN定价锚体系_v1.0_20260921.md", "rules_document")]
    if side == "codex_invest":
        values.append(("state/invest-codex-memory-notes.md", "notes"))
    return values


def _capture(root, side):
    blobs, records, absent = {}, [], []
    for relative, source_format in _sources(side):
        path = _safe(root, relative)
        if not path.exists():
            absent.append(relative)
            continue
        if not path.is_file():
            raise ValueError("source_not_file")
        if path.stat().st_nlink != 1:
            raise ValueError("source_hardlink_rejected")
        data = path.read_bytes()
        blobs[relative] = data
        records.append({"path": relative, "sha256": _hash(data), "size": len(data), "source_format": source_format})
    # Do not seal a capture when a producer was still modifying a source.
    for relative, _ in _sources(side):
        path = _safe(root, relative)
        if relative in blobs:
            if not path.is_file() or path.stat().st_nlink != 1 or path.read_bytes() != blobs[relative]:
                raise ValueError("source_changed_during_snapshot")
        elif path.exists():
            raise ValueError("source_changed_during_snapshot")
    missing = []
    if "memory/profiles/invest.json" not in blobs:
        missing.append("invest_profile")
    old = "memory/confirmed/by-role/invest/facts.jsonl" in blobs
    new = "memory/structured/invest/facts.jsonl" in blobs
    if not (old or new):
        missing.append("invest_memory_facts")
    source_format = "mixed" if old and new else "structured" if new else "legacy" if old else "none"
    return blobs, records, absent, missing, source_format


def _verify(root, relative, side, day, version, expected_manifest_hash):
    """Verify sealed metadata and every payload; return metadata only to callers."""
    manifest = _read(root, relative / "manifest.json")
    if not isinstance(manifest, dict):
        raise ValueError("invalid_manifest")
    unsigned = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    actual_hash = _hash(_encoded(unsigned))
    if actual_hash != expected_manifest_hash or manifest.get("manifest_sha256") != actual_hash:
        raise ValueError("manifest_hash_mismatch")
    if (manifest.get("schema") != SCHEMA or manifest.get("side") != side
            or manifest.get("day") != day or manifest.get("version") != version
            or manifest.get("merge_state") != "not_attempted"):
        raise ValueError("manifest_identity_mismatch")
    content = {k: manifest[k] for k in ("schema", "side", "day", "files", "absent_sources", "missing_required", "source_format")}
    if _hash(_encoded(content)) != version:
        raise ValueError("version_hash_mismatch")
    allowed = dict(_sources(side))
    seen = set()
    for entry in manifest["files"]:
        name = entry["path"]
        if name not in allowed or name in seen or entry.get("source_format") != allowed[name]:
            raise ValueError("invalid_manifest_source")
        seen.add(name)
        data = _safe(root, relative / "files" / name).read_bytes()
        if len(data) != entry["size"] or _hash(data) != entry["sha256"]:
            raise ValueError("payload_hash_mismatch")
    if not set(manifest["missing_required"]).issubset({"invest_profile", "invest_memory_facts"}):
        raise ValueError("invalid_missing_sources")
    if manifest["source_format"] not in {"legacy", "structured", "mixed", "none"}:
        raise ValueError("invalid_source_format")
    return manifest


def run(root, now=None, side="codex_invest", source_root=None):
    """Publish only the requested local producer's snapshot; no merge or schedule."""
    if side not in SIDES:
        raise ValueError("unknown_sync_side")
    root = Path(root).resolve()
    if side == "grok_invest" and (source_root is None or Path(source_root).resolve() == root):
        raise ValueError("grok_requires_separate_source_export")
    if side == "codex_invest" and source_root is not None:
        raise ValueError("codex_uses_local_source_root")
    source = Path(source_root).resolve() if source_root is not None else root
    stamp = _time(now); day = stamp.strftime("%Y%m%d")
    if recovery_held(root):
        return {"ok": False, "state": "blocked", "reason": "recovery_hold", "side": side, "day": day, "merge_state": "not_attempted"}
    base = SYNC_ROOT / ("from_" + side) / day
    with _lock(_safe(root, "state/maintenance.lock"), shared=True), _lock(_safe(root, SYNC_ROOT / ("." + side + ".lock"))):
        if recovery_held(root):
            return {"ok": False, "state": "blocked", "reason": "recovery_hold", "side": side, "day": day, "merge_state": "not_attempted"}
        blobs, files, absent, missing, source_format = _capture(source, side)
        content = {"schema": SCHEMA, "side": side, "day": day, "files": files,
                   "absent_sources": absent, "missing_required": missing, "source_format": source_format}
        version = _hash(_encoded(content))
        relative = base / "versions" / version
        destination = _safe(root, relative)
        replayed = destination.exists()
        if replayed:
            old = _read(root, relative / "manifest.json")
            manifest = _verify(root, relative, side, day, version, old["manifest_sha256"])
        else:
            manifest = {**content, "version": version, "created_at": stamp.isoformat(), "merge_state": "not_attempted",
                        "capture_kind": "file_snapshot_not_cross_file_transaction"}
            manifest["manifest_sha256"] = _hash(_encoded(manifest))
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            staging = Path(tempfile.mkdtemp(prefix=".capture-", dir=destination.parent))
            try:
                for relative_source, data in blobs.items():
                    _write(staging / "files" / relative_source, data)
                _write(staging / "manifest.json", _encoded(manifest) + b"\n")
                for directory in sorted((p for p in staging.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
                    _sync_directory(directory)
                _sync_directory(staging)
                os.rename(staging, destination)
                _sync_directory(destination.parent)
            finally:
                if staging.exists():
                    resolved_staging = staging.resolve()
                    if (resolved_staging.parent != destination.parent.resolve()
                            or not resolved_staging.name.startswith(".capture-")):
                        raise ValueError("unsafe_staging_cleanup")
                    shutil.rmtree(resolved_staging)
        # This replaceable discovery pointer is not itself the immutable snapshot.
        pointer = {"schema": SCHEMA, "side": side, "day": day, "version": version,
                   "manifest_sha256": manifest["manifest_sha256"]}
        pointer_path = _safe(root, base / "LATEST.json")
        if not pointer_path.exists() or _read(root, base / "LATEST.json") != pointer:
            _atomic_json(pointer_path, pointer)
        return {"ok": not missing, "state": "snapshot_ready" if not missing else "snapshot_incomplete",
                "side": side, "day": day, "version": version, "replayed": replayed,
                "manifest_sha256": manifest["manifest_sha256"], "source_format": source_format,
                "file_count": len(files), "missing_required": missing, "merge_state": "not_attempted"}


def _side_status(root, side, day):
    base = SYNC_ROOT / ("from_" + side) / day
    result = {"present": False, "verified": False, "state": "missing", "format": "none", "source_format": "unknown", "file_count": 0}
    try:
        pointer_path = _safe(root, base / "LATEST.json")
        if pointer_path.exists():
            result.update(present=True, format=SCHEMA)
            pointer = _read(root, base / "LATEST.json")
            if not isinstance(pointer, dict) or any(pointer.get(k) != v for k, v in (("schema", SCHEMA), ("side", side), ("day", day))):
                raise ValueError("invalid_pointer")
            version, digest = pointer.get("version"), pointer.get("manifest_sha256")
            if not isinstance(version, str) or not HEX.fullmatch(version) or not isinstance(digest, str) or not HEX.fullmatch(digest):
                raise ValueError("invalid_pointer")
            manifest = _verify(root, base / "versions" / version, side, day, version, digest)
            missing = manifest["missing_required"]
            result.update(verified=True, state="snapshot_incomplete" if missing else "snapshot_ready", version=version,
                          manifest_sha256=digest, source_format=manifest["source_format"], file_count=len(manifest["files"]), missing_required=missing)
            return result, {row["path"]: row["sha256"] for row in manifest["files"]}
        legacy_path = _safe(root, base / "SYNC_OK.json")
        if legacy_path.exists():
            result.update(present=True, format="invest-daily-sync-1", source_format="legacy")
            legacy = _read(root, base / "SYNC_OK.json")
            if not isinstance(legacy, dict) or legacy.get("schema") != "invest-daily-sync-1" or legacy.get("side") != side or legacy.get("day") != day:
                raise ValueError("invalid_legacy_marker")
            files = legacy.get("files")
            if not isinstance(files, list) or any(not isinstance(name, str) or Path(name).name != name or name in {".", ".."} for name in files):
                raise ValueError("invalid_legacy_file_list")
            present = sum(_safe(root, base / name).is_file() for name in files)
            result.update(state="legacy_unverified" if present == len(files) else "legacy_incomplete", file_count=present)
            return result, {}
    except (OSError, ValueError, TypeError, KeyError):
        result.update(state="invalid", verified=False, error="snapshot_integrity_failed")
    return result, {}


def status(root, now=None):
    """Privacy-safe, read-only daily reconciliation, never a merge success claim."""
    root = Path(root).resolve(); day = _time(now).strftime("%Y%m%d")
    sides, hashes = {}, {}
    for side in SIDES:
        sides[side], hashes[side] = _side_status(root, side, day)
    missing = [side for side in SIDES if not sides[side]["present"]]
    verified = all(sides[side]["verified"] and sides[side]["state"] == "snapshot_ready" for side in SIDES)
    common = set(hashes[SIDES[0]]) & set(hashes[SIDES[1]])
    mismatches = sum(hashes[SIDES[0]][key] != hashes[SIDES[1]][key] for key in common)
    # The Codex-local notes file has no Grok counterpart by design.
    comparable = {side: set(hashes[side]) - {"state/invest-codex-memory-notes.md"} for side in SIDES}
    asymmetric = {side: len(comparable[side] - comparable[other]) for side, other in (SIDES, tuple(reversed(SIDES)))}
    return {"schema": "invest-sync-status-2", "day": day, "sides": sides, "missing_sides": missing,
            "both_sides_present": not missing, "both_snapshots_verified": verified,
            "state": "missing_side" if missing else "snapshots_verified" if verified else "attention_required",
            "comparison": {"comparable_file_count": len(common), "different_file_count": mismatches, "files_only_on_side": asymmetric},
            "merge_state": "not_attempted", "attention_required": not verified or bool(mismatches) or any(asymmetric.values())}


def main(default_side="codex_invest"):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=os.environ.get("JAVIS_ROOT", str(Path.home() / "javis")))
    parser.add_argument("--side", choices=SIDES, default=default_side)
    parser.add_argument("--source-root", help="Required separate Grok export root for --side grok_invest")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()
    value = status(args.root) if args.status else run(args.root, side=args.side, source_root=args.source_root)
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return 0 if args.status or value["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
