import concurrent.futures
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE / 'scripts'), str(CODE / 'tools/memory-adapter')]
import memory_controls as controls
from javis_memory_adapter.review_policy import ReviewBlocked


class ControlsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def enable(self, **kwargs):
        return controls.update(self.root, controls.status(self.root)['revision'],
                               global_enabled=True, **kwargs)

    def test_missing_configuration_is_paused_and_read_only(self):
        value = controls.status(self.root)
        self.assertFalse(value['global_enabled'])
        self.assertTrue(value['raw_capture_enabled'])
        self.assertEqual(value['daily_call_limit'], 200)
        self.assertEqual(len(value['roles']), 12)
        self.assertTrue(all(value['roles'].values()))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_inherit_existing_pause_without_rewriting_legacy(self):
        p = self.root / 'memory/ai-review/control.json'
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps({'enabled': False, 'revision': 2}))
        before = p.read_bytes()
        self.assertEqual(controls.status(self.root)['revision'], 2)
        self.enable(command_id='resume-once')
        self.assertEqual(p.read_bytes(), before)
        self.assertTrue(controls.status(self.root)['global_enabled'])

    def test_strict_role_boolean_and_revision_validation(self):
        for kwargs in ({'global_enabled': 1}, {'roles': {'invest': 0}},
                       {'roles': {'shared': True}}, {'roles': {'unknown': False}},
                       {'daily_call_limit': True}, {'daily_call_limit': -1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ReviewBlocked):
                controls.update(self.root, 0, **kwargs)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cas_and_command_id_are_idempotent(self):
        first = self.enable(command_id='one')
        self.assertEqual(controls.update(self.root, 0, global_enabled=True, command_id='one'), first)
        with self.assertRaisesRegex(ReviewBlocked, 'command_id_conflict'):
            controls.update(self.root, 0, global_enabled=False, command_id='one')
        with self.assertRaisesRegex(ReviewBlocked, 'stale_controls_revision'):
            controls.update(self.root, 0, global_enabled=False)

    def test_role_hold_is_isolated_and_raw_append_still_succeeds(self):
        self.enable(roles={'invest': False})
        with self.assertRaisesRegex(controls.MemoryProcessingHeld, 'role_paused'):
            controls.require_processing(self.root, 'invest', 'screening')
        controls.require_processing(self.root, 'cards-master', 'screening')
        from raw_storage import append_event
        append_event(self.root, {'event_id': 'still-save', 'event_type': 'user_input',
            'agent': 'invest', 'payload': {'text': 'Synthetic original preserved'}})
        self.assertTrue(list((self.root / 'raw/events').glob('*.jsonl')))

    def test_actual_attempt_budget_deduplicates_only_identical_attempt(self):
        self.enable(daily_call_limit=2)
        controls.reserve_call(self.root, 'invest', 'graphiti', 'send-one')
        self.assertTrue(controls.reserve_call(self.root, 'invest', 'graphiti', 'send-one')['replayed'])
        with self.assertRaisesRegex(ReviewBlocked, 'binding_conflict'):
            controls.reserve_call(self.root, 'cards-master', 'graphiti', 'send-one')
        controls.reserve_call(self.root, 'invest', 'graphiti', 'send-retry-two')
        with self.assertRaisesRegex(controls.MemoryProcessingHeld, 'daily_budget_exhausted'):
            controls.reserve_call(self.root, 'invest', 'graphiti', 'send-three')
        self.assertEqual(controls.status(self.root)['budget']['reserved_calls'], 2)

    def test_concurrent_attempts_cannot_exceed_hard_limit(self):
        self.enable(daily_call_limit=2)
        def attempt(i):
            try:
                controls.reserve_call(self.root, 'invest', 'embedding', 'attempt-' + str(i))
                return True
            except controls.MemoryProcessingHeld:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(8))), 2)
        self.assertEqual(controls.status(self.root)['budget']['reserved_calls'], 2)

    def test_zero_budget_stops_network_but_allows_local_completion(self):
        self.enable(daily_call_limit=0)
        with self.assertRaises(controls.MemoryProcessingHeld):
            controls.require_processing(self.root, 'invest', 'verification')
        controls.require_processing(self.root, 'invest', 'local_accept')
        with self.assertRaises(controls.MemoryProcessingHeld):
            controls.reserve_call(self.root, 'invest', 'local_accept', 'cannot-bypass')

    def test_utc_day_rollover_preserves_previous_reservations(self):
        self.enable(daily_call_limit=1)
        with patch.object(controls, '_now', return_value=datetime(2026, 9, 30, tzinfo=timezone.utc)):
            controls.reserve_call(self.root, 'invest', 'screening', 'day-one')
        with patch.object(controls, '_now', return_value=datetime(2026, 10, 1, tzinfo=timezone.utc)):
            self.assertEqual(controls.status(self.root)['budget']['reserved_calls'], 0)
            controls.reserve_call(self.root, 'invest', 'screening', 'day-two')
        self.assertEqual(len(list((self.root / 'state/memory-controls/budget').glob('*.json'))), 2)

    def test_tampered_configuration_fails_closed(self):
        self.enable()
        p = self.root / controls.PATH
        row = json.loads(p.read_text()); row['daily_call_limit'] = 10000
        p.write_text(json.dumps(row))
        with self.assertRaisesRegex(ReviewBlocked, 'memory_controls_invalid'):
            controls.require_processing(self.root, 'invest', 'screening')

    def test_hardlink_and_recovery_hold_block_writes(self):
        self.enable()
        p = self.root / controls.PATH
        os.link(p, self.root / 'linked-copy')
        with self.assertRaises(ReviewBlocked):
            controls.update(self.root, 1, global_enabled=False)
        (self.root / 'linked-copy').unlink()
        before = p.read_bytes()
        (self.root / 'state/recovery-hold.json').write_text('{"hold":true}')
        with self.assertRaises(Exception):
            controls.update(self.root, 1, global_enabled=False)
        self.assertEqual(p.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
