#!/usr/bin/env python3
"""Rebuild a task view from RAW alone; the state cache is never an authority."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
from raw_storage import now_iso
from runtime_io import atomic_json


def load_events(root, task_id):
    events, issues, seen = [], [], set()
    for path in sorted((Path(root) / 'raw/events').rglob('*.jsonl')):
        for number, line in enumerate(path.read_text(encoding='utf-8', errors='replace').split('\n'), 1):
            if not line.strip(): continue
            try: row = json.loads(line)
            except json.JSONDecodeError:
                issues.append({'path': str(path), 'line': number, 'reason': 'invalid_JSON_RAW_line'})
                continue
            if not isinstance(row, dict):
                issues.append({'path': str(path), 'line': number, 'reason': 'RAW_line_not_event_object'})
                continue
            if row.get('task_id') != task_id: continue
            eid = row.get('event_id')
            if eid and eid in seen: continue
            if eid: seen.add(eid)
            events.append(row)
    # Capture order represents when ledger evidence became known; null historical
    # occurrence times must not override newer confirmed state snapshots.
    events.sort(key=lambda e: e.get('captured_at') or e.get('occurred_at') or '')
    return events, issues


def rebuild(root, task_id):
    events, issues = load_events(root, task_id)
    state = {'task_id': task_id, 'goal': None, 'state': 'unknown', 'status': 'unknown', 'session_id': None,
             'attempt': None, 'artifacts': [], 'memory_writes': []}
    snapshots = []
    for event in events:
        payload = event.get('payload') or {}
        if not isinstance(payload, dict): continue
        kind = event.get('event_type')
        if kind == 'user_input' and state['goal'] is None: state['goal'] = payload.get('text')
        if kind == 'task_lifecycle':
            saved = payload.get('state_snapshot')
            if isinstance(saved, dict):
                state.update(saved)
                canonical = saved.get('state') or saved.get('status') or 'unknown'
                canonical = {'ok': 'completed', 'error': 'failed'}.get(canonical, canonical)
                state['state'] = state['status'] = canonical
            else:
                status = payload.get('status')
                if status: state['state'] = state['status'] = {'ok': 'completed', 'error': 'failed'}.get(status, status)
                for field in ('session_id', 'attempt', 'model', 'failure_reason'):
                    if payload.get(field) is not None: state[field] = payload[field]
            state['updated_at'] = event.get('occurred_at') or event.get('captured_at')
        if event.get('session_id'): state['session_id'] = event['session_id']
        if kind == 'file_snapshot':
            snapshots.append(payload)
    # Old manifests may predate file_snapshot events. Keep provenance without state.
    known = {s.get('snapshot_id') or (s.get('sha256'), s.get('source_path')) for s in snapshots}
    for path in sorted((Path(root) / 'raw/manifests').glob('objects-*.jsonl')):
        for line in path.read_text(encoding='utf-8', errors='replace').split('\n'):
            if not line.strip():continue
            try: row = json.loads(line)
            except json.JSONDecodeError:
                issues.append({'path': str(path), 'reason': 'invalid_JSON_manifest_line'})
                continue
            if not isinstance(row, dict):
                issues.append({'path': str(path), 'reason': 'manifest_line_not_object'})
                continue
            key = row.get('snapshot_id') or (row.get('sha256'), row.get('source_path'))
            if row.get('task_id') == task_id and key not in known:
                snapshots.append(row); known.add(key)
    for snapshot in snapshots:
        digest = snapshot.get('sha256')
        if digest and (not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest)):
            issues.append({'reason': 'invalid_RAW_object_hash_reference'})
            continue
        obj = Path(root) / 'raw/objects' / (digest or 'missing')
        if digest and not obj.is_file():
            issues.append({'reason': 'referenced_RAW_object_missing', 'sha256': digest})
        elif digest:
            actual = hashlib.sha256()
            with obj.open('rb') as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b''): actual.update(chunk)
            if actual.hexdigest() != digest:
                issues.append({'reason': 'referenced_RAW_object_hash_mismatch', 'sha256': digest})
    state['artifacts'] = snapshots
    if not events: issues.append({'reason': 'no_RAW_events_for_task'})
    return {'task_id': task_id, 'rebuilt_at': now_iso(), 'rebuilt_from': 'raw_events+raw_manifests',
            'event_count': len(events), 'state': state, 'events': events, 'artifacts': snapshots,
            'user_inputs': [e.get('payload') for e in events if e.get('event_type') == 'user_input'],
            'model_outputs': [e.get('payload') for e in events if e.get('event_type') == 'model_output'],
            'tool_events': [e for e in events if e.get('event_type') in ('tool_call', 'tool_result')],
            'recording_gaps': [e for e in events if (e.get('payload') or {}).get('kind') == 'recording_gap'],
            'rebuild_issues': issues}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('task_id')
    ap.add_argument('--root', type=Path, default=Path(os.environ.get('JAVIS_ROOT', Path.home() / 'javis')))
    ap.add_argument('--out')
    args = ap.parse_args()
    view = rebuild(args.root, args.task_id)
    out = Path(args.out) if args.out else args.root / 'workspace/tasks' / args.task_id / 'rebuilt-view.json'
    if not args.out and not out.resolve().is_relative_to((args.root / 'workspace/tasks').resolve()): raise ValueError('invalid_task_id')
    atomic_json(out, view)
    print(json.dumps({'ok': bool(view['event_count']) and not view['rebuild_issues'], 'path': str(out),
                      'event_count': view['event_count'], 'issues': view['rebuild_issues']}, ensure_ascii=False))
    return 0 if view['event_count'] and not view['rebuild_issues'] else 1


if __name__ == '__main__': raise SystemExit(main())
