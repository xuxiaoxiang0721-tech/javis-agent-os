#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SHA-256 helper for Javis RAW object registration.

Usage:
  hash-file.py PATH [PATH ...]
  hash-file.py --json PATH

Prints hex digest; with --json also size and mtime.
NOT_VERIFIED_ON_TARGET
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="SHA-256 file helper")
    ap.add_argument("--json", action="store_true", help="JSON output with size/mtime")
    ap.add_argument("paths", nargs="+", type=Path)
    args = ap.parse_args()

    results = []
    for p in args.paths:
        if not p.is_file():
            print(f"ERROR: not a file: {p}", file=sys.stderr)
            return 1
        digest = sha256_file(p)
        st = p.stat()
        item = {
            "path": str(p),
            "sha256": digest,
            "size": st.st_size,
            "mtime": st.st_mtime,
        }
        results.append(item)
        if not args.json:
            print(f"{digest}  {p}")

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
