"""Synthetic legacy-clock compatibility tests; no cloud or production IO."""
import asyncio
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / 'scripts'))
from raw_time import semantic_source_time
from memory_screen import _source_context, _temporal_context, screen, source_digest
from memory_feedback import MemoryFeedback
from memory_triage import get_pending
from test_jev_policy import FakeClient

STAMP = '2026-09-24T09:00:00.123456789Z'
CAPTURE = '2026-09-25T10:00:00Z'


class SemanticSourceTimeTests(unittest.TestCase):
    def test_fourteen_legacy_clock_shapes_have_no_semantic_anchor(self):
        rows = [{'occurred_at': STAMP, 'missing_reason': 'occurred_at_defaulted_to_captured_at'} for _ in range(2)]
        for source, count in (('wrapper_prompt', 3), ('grok_forwarded_summary', 1), ('codex_log_parse', 4), ('agent_summary', 4)):
            rows.extend({'occurred_at': STAMP, 'captured_at': CAPTURE, 'payload': {'record_source': source}} for _ in range(count))
        original = copy.deepcopy(rows)
        self.assertEqual(len(rows), 14)
        self.assertEqual([semantic_source_time(row) for row in rows], [None] * 14)
        self.assertEqual(rows, original)

    def test_explicit_source_basis_preserves_real_native_clock_and_nanoseconds(self):
        for source in ('codex_native_jsonl', 'codex_json_stream', 'codex_log_parse'):
            row = {'occurred_at': STAMP, 'time_basis': 'source_timestamp', 'payload': {'record_source': source}}
            self.assertEqual(semantic_source_time(row), STAMP)

    def test_defaulted_clock_marker_precedes_even_source_timestamp_basis(self):
        row = {'occurred_at': STAMP, 'time_basis': 'source_timestamp',
               'missing_reason': 'legacy_gap;occurred_at_defaulted_to_captured_at'}
        self.assertIsNone(semantic_source_time(row))

    def test_explicit_capture_invalid_and_unknown_basis_never_supply_source_clock(self):
        for basis in ('local_received', 'capture_only', 'source_time_invalid', 'unrecognized'):
            with self.subTest(basis=basis):
                self.assertIsNone(semantic_source_time({'occurred_at': STAMP, 'time_basis': basis}))
        for stamp in (None, '2026-09-24T09:00:00', '2026-09-24T09:00:00-00:00'):
            self.assertIsNone(semantic_source_time({'occurred_at': stamp, 'time_basis': 'source_timestamp'}))

    def test_no_basis_compatibility_and_equal_capture_do_not_invent_a_rejection(self):
        for record in ({'occurred_at': STAMP, 'captured_at': STAMP},
                       {'occurred_at': STAMP, 'payload': {'record_source': 'codex_native_jsonl'}},
                       {'occurred_at': STAMP, 'speaker': 'user'}):
            self.assertEqual(semantic_source_time(record), STAMP)
        for record in ({'occurred_at': STAMP, 'input_kind': 'wrapper_prompt'},
                       {'occurred_at': STAMP, 'payload': {'input_kind': 'grok_forwarded_summary'}}):
            self.assertIsNone(semantic_source_time(record))

    def test_source_context_and_reference_view_leave_original_record_unchanged(self):
        row = {'event_type': 'model_output', 'occurred_at': STAMP, 'captured_at': CAPTURE,
               'payload': {'text': 'Synthetic output', 'record_source': 'agent_summary'}}
        original = copy.deepcopy(row)
        context = _source_context(row, row['payload']['text'])
        self.assertIsNone(context['occurred_at'])
        temporal = _temporal_context(row, context, STAMP)
        self.assertIsNone(temporal['source_time'])
        self.assertEqual(temporal['reference_basis'], 'captured_at')
        self.assertEqual(row, original)

    def test_message_clock_uses_its_own_provenance_and_never_container_clock(self):
        row = {'occurred_at': STAMP, 'time_basis': 'source_timestamp', 'payload': {'messages': [
            {'text': 'No own clock'},
            {'text': 'True clock', 'occurred_at': CAPTURE},
            {'text': 'Legacy clock', 'occurred_at': CAPTURE, 'input_kind': 'wrapper_prompt'}]}}
        self.assertIsNone(_source_context(row, 'No own clock')['occurred_at'])
        self.assertEqual(_source_context(row, 'True clock')['occurred_at'], CAPTURE)
        self.assertIsNone(_source_context(row, 'Legacy clock')['occurred_at'])
        row['missing_reason'] = 'occurred_at_defaulted_to_captured_at'
        self.assertEqual(_source_context(row, 'True clock')['occurred_at'], CAPTURE)

    def test_feedback_without_text_uses_semantic_time_and_message_own_clock(self):
        with tempfile.TemporaryDirectory(prefix='semantic-feedback-') as directory:
            feedback = MemoryFeedback(Path(directory))
            row = {'event_id': 'source-one', 'agent': 'invest', 'occurred_at': STAMP,
                   'missing_reason': 'occurred_at_defaulted_to_captured_at', 'payload': {}}
            result = feedback._source('source-one', 'invest', sources={'source-one': row})
            self.assertIsNone(result[3]['occurred_at'])
            row['payload'] = {'messages': [{'occurred_at': CAPTURE}, {}]}
            result = feedback._source('source-one', 'invest', ['payload', 'messages', 0, 'text'], sources={'source-one': row})
            self.assertEqual(result[3]['occurred_at'], CAPTURE)
            result = feedback._source('source-one', 'invest', ['payload', 'messages', 1, 'text'], sources={'source-one': row})
            self.assertIsNone(result[3]['occurred_at'])

    def test_legacy_relative_time_reaches_graph_then_review_without_anchor_or_raw_change(self):
        text = 'Alice joins Orion tomorrow.'
        row = {'event_id': 'legacy-relative', 'event_type': 'model_output', 'agent': 'invest',
               'occurred_at': STAMP, 'captured_at': CAPTURE, 'payload': {'text': text, 'record_source': 'codex_log_parse'}}
        class Graph:
            def __init__(self): self.calls = []
            async def extract(self, **kwargs):
                self.calls.append(kwargs)
                return {'episode_uuid': 'synthetic-episode', 'model': 'synthetic-graph', 'facts': [{
                    'graph_edge_id': 'synthetic-edge', 'subject_id': 'alice', 'subject_label': 'Alice',
                    'predicate': 'JOINS', 'value': text, 'object_label': 'Orion', 'valid_from': None, 'valid_to': None}]}
        with tempfile.TemporaryDirectory(prefix='semantic-screen-') as directory:
            root = Path(directory)
            from memory_controls import update
            update(root, 0, global_enabled=True)
            path = root / 'raw/events/legacy.jsonl'
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(row) + '\n')
            original = path.read_bytes()
            graph, client = Graph(), FakeClient()
            result = asyncio.run(screen(root, event_id=row['event_id'], scope='invest', text=text,
                source_digest=source_digest(row), model='jev-1.13.0', model_client=client, graph_client=graph))
            self.assertEqual(result['outcome'], 'needs_evidence', result)
            self.assertEqual(len(graph.calls), 1)
            self.assertEqual(len(client.calls), 1)
            self.assertIsNone(result['temporal_context']['source_time'])
            self.assertEqual(result['temporal_context']['reference_basis'], 'captured_at')
            self.assertEqual(get_pending(root, result['review_refs'][0])['policy_reason'], 'relative_time_unanchored')
            self.assertEqual(result['candidates'], [])
            self.assertEqual(path.read_bytes(), original)
            self.assertFalse((root / 'memory/structured').exists())


if __name__ == '__main__': unittest.main()
