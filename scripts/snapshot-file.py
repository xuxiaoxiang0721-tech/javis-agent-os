#!/usr/bin/env python3
"""Capture a versioned RAW snapshot after explicit credential filtering."""
import argparse
import json
import os
import sys
from pathlib import Path
from raw_storage import snapshot_file, append_event, stable_id, now_iso


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('path', type=Path)
    ap.add_argument('source_label', nargs='?')
    ap.add_argument('--root', type=Path, default=Path(os.environ.get('JAVIS_ROOT', Path.home() / 'javis')))
    ap.add_argument('--task-id', default=None)
    ap.add_argument('--artifact-id')
    ap.add_argument('--capture-key')
    ap.add_argument('--windows-path')
    ap.add_argument('--relation', default='artifact')
    args = ap.parse_args()
    try:
        result = snapshot_file(args.root, args.path, args.task_id or 'unassigned', args.source_label,
                               artifact_id=args.artifact_id, capture_key=args.capture_key,
                               windows_path=args.windows_path, relation=args.relation)
    except (ValueError, OSError) as exc:
        gap = {'event_id': stable_id('snapshot-failure', args.task_id, str(args.path), now_iso()),
               'task_id': args.task_id, 'event_type': 'status', 'occurred_at': now_iso(),
               'completeness': 'partial', 'missing_reason': 'file_snapshot_failed_or_credential_blocked',
               'payload': {'kind': 'recording_gap', 'error_type': type(exc).__name__}}
        append_event(args.root, gap)
        print(json.dumps({'ok': False, 'error': gap['missing_reason']}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__': raise SystemExit(main())
