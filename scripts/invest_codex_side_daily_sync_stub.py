#!/usr/bin/env python3
"""Compatibility entry point for the independent Codex Invest daily snapshot."""
from memory_sync import run, status, main


if __name__ == "__main__":
    raise SystemExit(main(default_side="codex_invest"))
