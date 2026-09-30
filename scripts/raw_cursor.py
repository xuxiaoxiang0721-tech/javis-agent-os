"""Durable JSONL collection cursor, replay deduplication, and explicit gap records."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from raw_storage import append_event, now_iso, stable_id, _read_rows
from raw_policy import sanitize
from runtime_io import lock, atomic_json
from raw_time import native_time, received_fields


def ingest_jsonl(root, source, *, task_id, attempt=1, agent=None, entry='codex_cli', final=True):
    root, source = Path(root), Path(source)
    source_key = hashlib.sha256((task_id + '|' + str(attempt) + '|' + str(source.resolve())).encode()).hexdigest()[:32]
    state_path = root / 'state/collectors' / (source_key + '.json')
    gaps, written = [], []
    with lock(root / 'state/locks' / ('collector-' + source_key + '.lock')):
        state = json.loads(state_path.read_text()) if state_path.exists() else {}
        data = source.read_bytes()
        offset = state.get('byte_offset', 0)
        generation = state.get('generation', 0)
        changed = offset > len(data) or (offset and hashlib.sha256(data[:offset]).hexdigest() != state.get('prefix_sha256'))
        if changed:
            generation += 1; offset = 0
            gaps.append('source_replaced_or_truncated;previous_unread_range_unknown')
            state = {}
        line_number = state.get('line_number', 0)
        session_id = state.get('session_id')
        turn_id = state.get('turn_id')
        committed_state = dict(state, generation=generation, byte_offset=offset,
                               prefix_sha256=hashlib.sha256(data[:offset]).hexdigest(), line_number=line_number)
        live_rows = {}
        for row in _read_rows((root / 'raw/events').glob('*.jsonl')):
            payload = row.get('payload') or {}
            if row.get('task_id') == task_id and row.get('event_type') == 'codex_stream_event' and payload.get('attempt') == attempt:
                live_rows[payload.get('native_sequence')] = payload.get('event')
        segment = data[offset:]
        # In-progress partial records are retried on the next invocation. On final
        # collection a valid non-newline JSON record is complete; invalid is a gap.
        chunks = segment.splitlines(keepends=True)
        pending = 0
        if chunks and not final and not chunks[-1].endswith((b'\n', b'\r')):
            pending = len(chunks.pop())
        try:
            for chunk in chunks:
                current_offset = offset
                line_number += 1
                if not chunk.strip(): offset += len(chunk); continue
                try:
                    native = json.loads(chunk.decode('utf-8'))
                    if not isinstance(native, dict): raise ValueError()
                except (ValueError, UnicodeError):
                    gap = 'invalid_or_incomplete_JSON_record'
                    gaps.append(gap)
                    eid = stable_id(source_key, generation, current_offset, gap)
                    append_event(root, {'event_id': eid, 'event_type': 'status', 'task_id': task_id,
                        'entry': entry, 'agent': agent, 'occurred_at': now_iso(), 'completeness': 'partial',
                        'missing_reason': gap, 'payload': {'kind': 'recording_gap', 'source_path': str(source),
                        'byte_start': current_offset, 'byte_end': current_offset + len(chunk), 'attempt': attempt}})
                    offset += len(chunk)
                    continue
                kind = native.get('type') or 'unknown'
                if kind == 'thread.started': session_id = native.get('thread_id') or session_id
                turn_id = native.get('turn_id') or turn_id
                item = native.get('item') or {}
                source_event_id = native.get('event_id') or native.get('id')
                item_id = item.get('id') if isinstance(item, dict) else None
                # The live runner's zero-based line sequence and this collector's
                # one-based physical line number refer to the same safe log line.
                live = live_rows.get(line_number - 1)
                if live is not None and sanitize(live) == sanitize(native):
                    offset += len(chunk)
                    continue
                if live is not None:
                    gaps.append('live_and_replayed_native_event_differ')
                # Native item ids identify an item, not each delta/update event.
                eid = stable_id(source_key, generation, current_offset, 'native')
                mode = 'final' if kind.endswith('.completed') else 'delta' if 'delta' in kind else 'lifecycle'
                occurred, basis, timestamp_field = native_time(native)
                event = {'event_id': eid, 'event_type': 'other', 'task_id': task_id,
                    'session_id': session_id, 'turn_id': turn_id, 'source_event_id': source_event_id,
                    'entry': entry, 'agent': agent, **received_fields(occurred_at=occurred, received_at=now_iso(), basis=basis),
                    'source_time_field': 'payload.native_event.' + timestamp_field if timestamp_field else None,
                    'model': native.get('model'), 'execution_path': 'codex_exec_jsonl', 'completeness': 'partial',
                    'missing_reason': 'source_event_id_unavailable' if not source_event_id else None,
                    'evidence_refs': [{'source_path': str(source), 'byte_start': current_offset,
                        'byte_end': current_offset + len(chunk), 'line_number': line_number}],
                    'payload': {'record_source': 'codex_native_jsonl', 'stream_mode': mode,
                        'native_item_id': item_id, 'native_event': native, 'attempt': attempt,
                        'native_sequence': line_number, 'source_generation': generation}}
                if append_event(root, event): written.append(eid)
                offset += len(chunk)
            if pending: gaps.append('partial_JSON_record_waiting_for_next_collection')
            for gap in gaps:
                append_event(root, {'event_id': stable_id(source_key, generation, offset, gap),
                    'task_id': task_id, 'event_type': 'status', 'occurred_at': now_iso(),
                    'entry': entry, 'agent': agent, 'completeness': 'partial', 'missing_reason': gap,
                    'payload': {'kind': 'recording_gap', 'source_path': str(source), 'attempt': attempt}})
            result = {'source_path': str(source), 'task_id': task_id, 'attempt': attempt,
                'generation': generation, 'byte_offset': offset, 'source_size': len(data),
                'prefix_sha256': hashlib.sha256(data[:offset]).hexdigest(), 'line_number': line_number,
                'session_id': session_id, 'turn_id': turn_id, 'updated_at': now_iso(),
                'status': 'partial' if gaps else 'caught_up', 'gaps': gaps, 'pending_bytes': pending}
            atomic_json(state_path, result)
        except Exception as exc:
            # Cursor remains at last committed offset. Idempotent RAW ids make
            # replay safe if the process dies after append and before checkpoint.
            atomic_json(state_path, dict(committed_state, source_path=str(source), task_id=task_id,
                        status='failed', updated_at=now_iso(), error_type=type(exc).__name__))
            raise
    return {'written_event_ids': written, 'cursor': str(state_path), 'gaps': gaps,
            'byte_offset': offset, 'pending_bytes': pending}
