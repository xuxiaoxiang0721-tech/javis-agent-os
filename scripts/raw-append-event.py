#!/usr/bin/env python3
"""Append a normalized, credential-filtered event; unknown occurrence time stays null."""
import argparse
import json
import os
import sys
from pathlib import Path
from raw_storage import normalize_event, append_event


def validate(event):
    if not isinstance(event, dict): raise ValueError('event must be a JSON object')
    if not isinstance(event.get('event_type'), str) or not event['event_type']: raise ValueError('event_type required')
    return normalize_event(event)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, default=Path(os.environ.get('JAVIS_ROOT', Path.home() / 'javis')))
    ap.add_argument('--file', default=None)
    ap.add_argument('json_arg', nargs='?')
    args = ap.parse_args()
    try:
        event = validate(json.loads(args.json_arg if args.json_arg is not None else sys.stdin.read()))
        written = append_event(args.root, event, relative_path=args.file)
    except (ValueError, OSError):
        # Never echo input or exception content that might include credentials.
        print(json.dumps({'ok': False, 'error': 'invalid_event_or_RAW_write_failed'}), file=sys.stderr)
        return 3
    print(json.dumps({'ok': True, 'event_id': event['event_id'], 'deduplicated': written is None}))
    return 0


if __name__ == '__main__': raise SystemExit(main())
