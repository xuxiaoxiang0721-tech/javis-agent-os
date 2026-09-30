#!/usr/bin/env python3
"""Compatibility entry point: text/--by never grants owner confirmation.

Authenticated clients use MemoryReview.binding_for() followed by review().
The owner_auth module verifies a fresh, exact-version decision.
"""
import argparse
import json
import sys

from memory_review import MemoryReview, ReviewBlocked

def confirm(root, memory_id, actor="user"):
    raise ReviewBlocked("owner_review_required")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("memory_id", nargs="?")
    parser.add_argument("--by", default="user")
    parser.parse_args()
    print(json.dumps({"status": "BLOCKED", "memory_status": "pending_review",
                      "reason": "authenticated_owner_review_of_exact_version_required"}))
    return 2

if __name__ == "__main__":
    sys.exit(main())
