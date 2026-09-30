#!/usr/bin/env python3
"""Read-only Javis Linux preflight. Does not read credentials or task contents."""
from __future__ import annotations

import argparse
import configparser
import datetime as dt
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import socket
import subprocess
import urllib.request


def command(args, timeout=12, env=None):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
        return {"exit_code": p.returncode, "output": (p.stdout + p.stderr).strip()[:2000]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"exit_code": None, "error": type(exc).__name__}


def ini_value(path, section, key):
    c = configparser.ConfigParser(interpolation=None)
    try:
        c.read(path)
        return c.get(section, key, fallback=None)
    except configparser.Error:
        return None


def neo4j_health():
    result = {"http_ok": False, "bolt_tcp_ok": False, "authentication_query": "not_tested"}
    try:
        with urllib.request.urlopen("http://127.0.0.1:7474/", timeout=2) as r:
            data = json.load(r)
            result.update(http_ok=r.status == 200, version=data.get("neo4j_version"), edition=data.get("neo4j_edition"))
    except Exception as exc:
        result["http_error"] = type(exc).__name__
    try:
        with socket.create_connection(("127.0.0.1", 7687), timeout=2):
            result["bolt_tcp_ok"] = True
    except OSError as exc:
        result["bolt_error"] = type(exc).__name__
    return result


def service_state(unit):
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        return {"active": "unavailable", "reason": "systemd_not_pid1"}
    r = command(["systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,Result,UnitFileState"], 5)
    r["properties"] = dict(line.split("=", 1) for line in r.get("output", "").splitlines() if "=" in line)
    r.pop("output", None)
    return r


def health(root):
    root = Path(root).resolve()
    user = pwd.getpwuid(os.getuid()).pw_name
    pid1 = Path("/proc/1/comm").read_text().strip()
    neo = neo4j_health()
    services = {name: service_state(name) for name in ("javis-neo4j.service", "javis-recovery.service")}
    return {
        "schema_version": "javis.lifecycle.v1", "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "user": user, "uid": os.getuid(), "root": str(root), "root_exists": root.is_dir(),
        "root_owner_uid": root.stat().st_uid if root.exists() else None,
        "pid1": pid1, "systemd_configured": ini_value("/etc/wsl.conf", "boot", "systemd"),
        "boot_command": ("/usr/local/bin/javis-neo4j-boot" if ini_value("/etc/wsl.conf", "boot", "command") == "/usr/local/bin/javis-neo4j-boot"
                         else "other_command_configured" if ini_value("/etc/wsl.conf", "boot", "command") else None),
        "neo4j": neo, "services": services,
        "local_graph_reachable": bool(neo["http_ok"] and neo["bolt_tcp_ok"]),
        "lifecycle_ready": bool(pid1 == "systemd" and neo["http_ok"] and neo["bolt_tcp_ok"]
                                and services["javis-neo4j.service"].get("properties", {}).get("ActiveState") == "active"
                                and services["javis-recovery.service"].get("properties", {}).get("Result") == "success"
                                and services["javis-recovery.service"].get("properties", {}).get("ActiveState") == "active"),
    }


def preflight(root):
    r = health(root)
    os_release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k in ("NAME", "VERSION", "VERSION_ID", "VERSION_CODENAME"):
                os_release[k] = v.strip('"')
    usage = shutil.disk_usage(root)
    r.update(hostname=socket.gethostname(), kernel=platform.release(), architecture=platform.machine(),
             distribution=os_release, timezone=command(["date", "+%Z %z"]),
             disk={"total_bytes": usage.total, "free_bytes": usage.free},
             filesystem=command(["findmnt", "-T", str(root), "-n", "-o", "FSTYPE,TARGET"]),
             networking_mode=command([shutil.which("wslinfo") or "/usr/bin/wslinfo", "--networking-mode"]),
             systemd_packages=command(["dpkg-query", "-W", "-f=${Package} ${Status} ${Version}\n", "systemd", "systemd-sysv"]),
             dependencies={})
    for name, args in {"codex": ["codex", "--version"], "node": ["node", "--version"],
                       "npm": ["npm", "--version"], "python3": ["python3", "--version"],
                       "git": ["git", "--version"]}.items():
        path = shutil.which(name)
        r["dependencies"][name] = {"path": path, "resolved_path": str(Path(path).resolve()) if path else None, **command(args)}
    runner_env = os.environ.copy()
    runner_env["PATH"] = str(Path.home() / ".local/node/bin") + ":" + runner_env.get("PATH", "")
    runner_codex = shutil.which("codex", path=runner_env["PATH"])
    r["runner_codex"] = {"path": runner_codex, "resolved_path": str(Path(runner_codex).resolve()) if runner_codex else None,
                         "selection_basis": "task-runner.py prepends ~/.local/node/bin to PATH", **command([runner_codex or "codex", "--version"], env=runner_env)}
    r["multiple_codex_installations"] = r["dependencies"]["codex"]["resolved_path"] != r["runner_codex"]["resolved_path"]
    return r


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", default=os.environ.get("JAVIS_ROOT", str(Path.home() / "javis")))
    p.add_argument("--health-only", action="store_true")
    args = p.parse_args()
    print(json.dumps(health(args.root) if args.health_only else preflight(args.root), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
