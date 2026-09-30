"""Offline compatibility checks: fake graph client, no model or database calls."""
import sys
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from javis_memory_adapter import MemoryAdapter, PERSONAL_MEMORY_EXTRACTION_INSTRUCTIONS
from javis_memory_adapter.extraction import normalize_candidate_times, extraction_instructions


class ExtractionInstructionsTests(unittest.IsolatedAsyncioTestCase):
    def adapter(self):
        value = MemoryAdapter.__new__(MemoryAdapter)
        value.group_id = 'javis-screen-synthetic-instruction-test'
        value._lookup_source_event = Mock(return_value=None)
        value._append_source_event = Mock()
        value._ensure = AsyncMock()
        result = types.SimpleNamespace(episode=types.SimpleNamespace(uuid='synthetic-episode'),
                                       nodes=[], edges=[])
        value._g = types.SimpleNamespace(add_episode=AsyncMock(return_value=result))
        return value

    async def write(self, adapter, **options):
        module = types.ModuleType('graphiti_core.nodes')
        module.EpisodeType = types.SimpleNamespace(text='text')
        with patch.dict(sys.modules, {'graphiti_core.nodes': module}):
            return await adapter.write_event(source_event_id='synthetic-event',
                body='Alice manages Orion.', event_time=datetime(2026, 9, 24, tzinfo=timezone.utc), **options)

    async def test_default_call_preserves_prior_graphiti_options(self):
        adapter = self.adapter()
        result = await self.write(adapter)
        self.assertTrue(result.ok)
        self.assertNotIn('custom_extraction_instructions', adapter._g.add_episode.call_args.kwargs)

    async def test_explicit_instructions_forwarded_without_rewriting_original(self):
        adapter = self.adapter()
        result = await self.write(adapter, custom_extraction_instructions=PERSONAL_MEMORY_EXTRACTION_INSTRUCTIONS)
        self.assertTrue(result.ok)
        kwargs = adapter._g.add_episode.call_args.kwargs
        self.assertEqual(kwargs['custom_extraction_instructions'], PERSONAL_MEMORY_EXTRACTION_INSTRUCTIONS)
        self.assertTrue(kwargs['episode_body'].endswith('\nAlice manages Orion.'))
        self.assertEqual(kwargs['group_id'], adapter.group_id)
        self.assertEqual(adapter._append_source_event.call_args.args[0]['source_event_id'], 'synthetic-event')

    async def test_deduplicated_source_does_not_call_model_with_new_instructions(self):
        adapter = self.adapter()
        adapter._lookup_source_event.return_value = {'episode_uuid': 'already-recorded'}
        result = await self.write(adapter, custom_extraction_instructions=PERSONAL_MEMORY_EXTRACTION_INSTRUCTIONS)
        self.assertTrue(result.deduped)
        adapter._g.add_episode.assert_not_called()

    def temporal(self, **changes):
        return {'source_time': None, 'reference_time': '2026-09-24T09:00:00+00:00',
                'reference_basis': 'captured_at', **changes}

    def normalize(self, text='Alice prefers Orion.', **changes):
        edge = {'value': text, 'valid_from': '2026-09-24T09:00:00.000000000Z', 'valid_to': None, **changes}
        return normalize_candidate_times([edge], text, self.temporal())[0]

    def test_only_exact_reference_default_becomes_unknown_and_original_is_audited(self):
        result = self.normalize()
        self.assertIsNone(result['valid_from'])
        self.assertEqual(result['temporal_provenance']['graphiti_valid_from'], '2026-09-24T09:00:00.000000000Z')
        self.assertEqual(result['temporal_provenance']['normalization'], 'reference_default_to_unknown')
        self.assertEqual(self.normalize(valid_from='2026-09-24T09:00:00.000000001Z')['valid_from'], '2026-09-24T09:00:00.000000001Z')
        self.assertEqual(self.normalize(valid_from='2026-09-24T00:00:00Z')['valid_from'], '2026-09-24T00:00:00Z')
        for boundary in ('2026-09-24T17:00:00+08:00', '2026-09-24T09:00:00-00:00'):
            self.assertEqual(self.normalize(valid_from=boundary)['valid_from'], boundary)

    def test_explicit_dates_and_relative_words_are_never_erased(self):
        for source in ('Alice prefers Orion from 2026-09-24.', 'Alice begins Orion tomorrow.',
                       'Alice joined Orion in 2025.', 'Alice明天加入Orion。', 'Alice不再负责Orion。'):
            result = self.normalize(text=source)
            self.assertIsNotNone(result['valid_from'])
            self.assertEqual(result['temporal_provenance']['normalization'], 'preserved')

    def test_end_boundary_and_arbitrary_unsubstantiated_date_are_preserved_for_review(self):
        result = self.normalize(valid_to='2026-09-25T00:00:00Z')
        self.assertIsNotNone(result['valid_from'])
        self.assertEqual(result['valid_to'], '2026-09-25T00:00:00Z')
        self.assertEqual(self.normalize(valid_from='2025-01-01T00:00:00Z')['valid_from'], '2025-01-01T00:00:00Z')

    def test_unknown_message_instructions_do_not_allow_capture_relative_resolution(self):
        instructions = extraction_instructions(self.temporal())
        self.assertIn('occurrence time is UNKNOWN', instructions)
        self.assertIn('Do not resolve today, tomorrow', instructions)

    async def test_candidate_receipt_preserves_separate_source_and_reference_time(self):
        adapter = self.adapter()
        context = self.temporal(reference_time='2026-09-24T00:00:00+00:00')
        result = await self.write(adapter, temporal_context=context)
        self.assertTrue(result.ok)
        self.assertEqual(adapter._append_source_event.call_args.args[0]['temporal_context'], context)
        self.assertEqual(adapter._g.add_episode.call_args.kwargs['reference_time'], datetime(2026, 9, 24, tzinfo=timezone.utc))

    async def test_candidate_temporal_mismatch_is_blocked_before_graph_call(self):
        adapter = self.adapter()
        with self.assertRaises(Exception):
            await self.write(adapter, temporal_context=self.temporal())
        adapter._g.add_episode.assert_not_called()

    async def test_local_reference_cannot_be_labeled_as_authenticated_source_time(self):
        for context in (self.temporal(reference_time='2026-09-24T00:00:00+00:00', reference_basis='source_occurred_at'),
                        self.temporal(reference_time='2026-09-24T00:00:00+00:00', source_time='2026-09-24T00:00:00Z')):
            adapter = self.adapter()
            with self.assertRaises(Exception):
                await self.write(adapter, temporal_context=context)
            adapter._g.add_episode.assert_not_called()


if __name__ == '__main__':
    unittest.main()
