#!/usr/bin/env python3
"""Prepare or apply an audited WSL systemd switch; never terminates WSL.

Default is a read-only plan. --apply installs the units and edits wsl.conf,
leaving current processes untouched; the operator coordinates a later restart.
"""
from __future__ import annotations
import argparse
import configparser
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

UNITS = ("javis-neo4j.service", "javis-recovery.service")
LEGACY_BOOT = "/usr/local/bin/javis-neo4j-boot"


def new_config(text):
    c = configparser.ConfigParser(interpolation=None)
    c.read_string(text)
    command = c.get("boot", "command", fallback=None)
    if command not in (None, "", LEGACY_BOOT):
        raise ValueError("Unrecognized boot command; review manually without overwriting it")
    lines, section, replaced, found_boot = [], None, False, False
    for line in text.splitlines():
        header = re.match(r"^\s*\[([^]]+)\]", line)
        if header:
            if section == "boot" and not replaced:
                lines.append("systemd=true")
                replaced = True
            section = header.group(1).lower()
            found_boot |= section == "boot"
        if section == "boot" and re.match(r"^\s*systemd\s*=", line, re.I):
            lines.append("systemd=true")
            replaced = True
        elif section == "boot" and re.match(r"^\s*command\s*=", line, re.I):
            lines.append("# Legacy Javis Neo4j boot hook replaced by javis-neo4j.service")
        else:
            lines.append(line)
    if not found_boot:
        lines += ["", "[boot]", "systemd=true"]
    elif not replaced:
        lines.append("systemd=true")
    return "\n".join(lines) + "\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic_write(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".javis-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def build_plan(etc, unit_dir):
    conf = etc / "wsl.conf"
    original = conf.read_bytes() if conf.exists() else b""
    updated = new_config(original.decode("utf-8"))
    units = {}
    for name in UNITS:
        content = (unit_dir / name).read_bytes()
        target = etc / "systemd/system" / name
        if target.exists() and target.read_bytes() != content:
            raise ValueError(f"Existing unit differs, review before replacement: {target}")
        units[name] = {"sha256": digest(content), "target": str(target), "content": content.decode()}
    return {"operation": "enable_systemd_on_next_distribution_start", "applied": False,
            "wsl_config": str(conf), "original_sha256": digest(original),
            "new_wsl_conf": updated, "new_sha256": digest(updated.encode()), "units": units,
            "restart_performed": False, "requires_coordinated_wsl_restart": True}


def apply_plan(etc, unit_dir, plan, backup):
    conf = etc / "wsl.conf"
    current = conf.read_bytes() if conf.exists() else b""
    if digest(current) != plan["original_sha256"]:
        raise ValueError("wsl.conf changed since plan was prepared")
    for name in UNITS:
        target = etc / "systemd/system" / name
        if target.exists() and digest(target.read_bytes()) != plan["units"][name]["sha256"]:
            raise ValueError(f"Existing unit changed or differs: {target}")
    backup.mkdir(parents=True, exist_ok=False)
    changes = []
    for path in [conf] + [etc / "systemd/system" / n for n in UNITS]:
        rel = path.relative_to(etc)
        if path.exists():
            copy = backup / rel
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, copy)
        changes.append({"relative_path": str(rel), "existed": path.exists()})
    for name in UNITS:
        link = etc / "systemd/system/multi-user.target.wants" / name
        if link.exists() or link.is_symlink():
            raise ValueError(f"Enablement link already exists; review manually: {link}")
    atomic_write(backup / "manifest.json", json.dumps({"originals": changes, "plan": plan}, indent=2).encode())
    try:
        for name in UNITS:
            atomic_write(etc / "systemd/system" / name, plan["units"][name]["content"].encode())
            link = etc / "systemd/system/multi-user.target.wants" / name
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(Path("..") / name)
        atomic_write(conf, plan["new_wsl_conf"].encode())
    except BaseException:
        rollback(etc, backup, check_current=False)
        raise
    return {**plan, "applied": True, "backup": str(backup)}


def rollback(etc, backup, check_current=True):
    manifest = json.loads((backup / "manifest.json").read_text())
    plan = manifest["plan"]
    if check_current:
        for item in manifest["originals"]:
            rel = Path(item["relative_path"])
            current = etc / rel
            expected = plan["new_sha256"] if str(rel) == "wsl.conf" else plan["units"][rel.name]["sha256"]
            if not current.exists() or digest(current.read_bytes()) != expected:
                raise ValueError(f"Current file changed after installation; refusing rollback: {current}")
    for name in UNITS:
        link = etc / "systemd/system/multi-user.target.wants" / name
        if link.is_symlink() and os.readlink(link) == str(Path("..") / name):
            link.unlink()
    for item in manifest["originals"]:
        target = etc / item["relative_path"]
        if item["existed"]:
            atomic_write(target, (backup / item["relative_path"]).read_bytes())
        else:
            target.unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser()
    local_units=Path(__file__).resolve().parent / "systemd"
    p.add_argument("--unit-dir", type=Path, default=local_units if local_units.is_dir() else Path(__file__).resolve().parent.parent / "systemd")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--rollback", type=Path)
    args = p.parse_args()
    etc = Path("/etc")
    if args.apply and args.rollback:
        p.error("Choose --apply or --rollback")
    if args.apply or args.rollback:
        if os.geteuid() != 0:
            p.error("Changes require Linux root; default plan does not")
        if args.apply and Path("/proc/1/comm").read_text().strip() == "systemd":
            p.error("This staged migration is for WSL init only. Active systemd changes require reviewed service stop/start.")
    if args.rollback:
        systemd_active = Path("/proc/1/comm").read_text().strip() == "systemd"
        if systemd_active:
            for unit in UNITS:
                result = subprocess.run(["systemctl", "is-active", "--quiet", unit])
                if result.returncode == 0:
                    p.error(f"Stop {unit} before restoring the previous boot configuration")
        rollback(etc, args.rollback.resolve())
        if systemd_active:
            subprocess.run(["systemctl", "daemon-reload"], check=True)
        print(json.dumps({"rolled_back": True, "restart_performed": False}))
        return
    plan = build_plan(etc, args.unit_dir)
    if args.apply:
        for dependency in ("/home/user/javis/tools/neo4j/bin/neo4j", "/home/user/javis/tools/jdk-21/bin/java", "/home/user/javis/scripts/task-control.py"):
            if not Path(dependency).is_file():
                p.error(f"Required file missing: {dependency}")
        package = subprocess.run(["dpkg-query", "-W", "-f=${Status}", "systemd-sysv"], capture_output=True, text=True)
        if package.returncode or package.stdout != "install ok installed":
            p.error("systemd-sysv must be installed before activation")
        backup = Path("/var/backups") / ("javis-systemd-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
        plan = apply_plan(etc, args.unit_dir, plan, backup)
    print(json.dumps(plan, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
