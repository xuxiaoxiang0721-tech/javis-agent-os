#!/usr/bin/env python3
"""Prepare, compare and explicitly activate owner-feedback routing profiles."""
import argparse
import asyncio
import json
from pathlib import Path
from memory_learning import MemoryLearning, LearningBlocked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("status", "prepare", "evaluate", "activate", "rollback", "advance"))
    parser.add_argument("--root", default=str(Path.home() / "javis"))
    parser.add_argument("--scope")
    parser.add_argument("--model", default="jev-1.13.0")
    parser.add_argument("--version")
    parser.add_argument("--max-calls", type=int, default=4, help="Maximum screen requests this invocation (advance: at most 4)")
    parser.add_argument("--retry-failed", action="store_true", help="Explicitly permit one bounded retry of failed/uncertain evaluation cases")
    args = parser.parse_args()
    learning = MemoryLearning(args.root)
    try:
        if args.command == "status":
            result = learning.status(args.scope)
        elif args.command == "prepare":
            result = learning.prepare(args.scope, args.model)
        elif args.command == "evaluate":
            if not args.version:
                parser.error("evaluate requires --version")
            result = asyncio.run(learning.evaluate(args.version, retry_failed=args.retry_failed, max_calls=args.max_calls))
        elif args.command == "advance":
            result = asyncio.run(learning.advance(max_calls=args.max_calls))
        elif args.command == "activate":
            if not args.version:
                parser.error("activate requires --version")
            result = learning.activate(args.version)
        else:
            result = learning.rollback(args.scope, args.version)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as exc:
        # Never serialize arbitrary exception text or original feedback sources.
        code = exc.code if isinstance(exc, LearningBlocked) else "learning_operation_failed"
        print(json.dumps({"status": "blocked", "reason": code, "error_type": type(exc).__name__}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
