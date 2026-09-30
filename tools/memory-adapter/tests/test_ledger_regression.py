"""Offline ledger regressions; writes only to disposable temporary directories."""
import concurrent.futures
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

sys.dont_write_bytecode = True
CODE = Path(os.environ.get('JAVIS_MEMORY_TEST_CODE', Path(__file__).parent))
sys.path.insert(0, str(CODE))
from javis_memory_adapter.structured_store import StructuredFact, StructuredStore
from javis_memory_adapter.ledger_query import (
    apply_historical_correction, apply_state_change, query_effective, query_known,
)

JAN = '2026-01-01T00:00:00+00:00'
FEB = '2026-02-01T00:00:00+00:00'
MAR = '2026-03-01T00:00:00+00:00'
APR = '2026-04-01T00:00:00+00:00'


def dt(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))


class LedgerRegression(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='javis-ledger-regression-')
        self.addCleanup(self.tmp.cleanup)
        self.store = StructuredStore(Path(self.tmp.name))

    def fact(self, fid='f1', value=10, start=JAN, end=None, unit=None, **kw):
        return StructuredFact(
            fact_id=fid, subject_id='subject', subject_label='Subject', predicate='count',
            value=value, unit=unit, valid_from=start, valid_to=end,
            recorded_at=JAN, source_event_id='source-' + fid, **kw,
        )

    def put(self, f, at=JAN):
        with patch('javis_memory_adapter.structured_store._now', return_value=at):
            self.store.upsert_fact(f)
        return f

    def correct(self, at=MAR, **kw):
        args = dict(
            subject_id='subject', subject_label='Subject', predicate='count',
            wrong_value=10, correct_value=11, unit=None, about_event_time=dt(at),
            source_event_id='correction-1', raw_refs=['raw-correction'],
            confirmation_event_id='correct-confirm',
        )
        args.update(kw)
        with patch('javis_memory_adapter.structured_store._now', return_value=APR):
            return apply_historical_correction(self.store, **args)

    def confirm(self, fid='f1', cid='confirmation-1', at=MAR):
        with patch('javis_memory_adapter.structured_store._now', return_value=at):
            return self.store.write_confirmation(
                confirmation_event_id=cid, fact_id=fid, confirmed_at=at,
            )

    def change(self, at=MAR, **kw):
        args = dict(
            subject_id='subject', subject_label='Subject', predicate='count',
            old_value=10, new_value=20, unit=None, change_at=dt(at),
            source_event_id='state-change-1', raw_refs=['raw-change'],
            confirmation_event_id='change-confirm',
        )
        args.update(kw)
        with patch('javis_memory_adapter.structured_store._now', return_value=APR):
            return apply_state_change(self.store, **args)

    def test_historical_correction_selects_requested_interval(self):
        self.put(self.fact('january', end=FEB))
        self.put(self.fact('march', start=MAR))
        result = self.correct()
        self.assertEqual(result['revised_fact_id'], 'march')
        self.assertEqual(query_effective(self.store, dt(JAN))['facts'][0]['value'], 10)
        self.assertEqual(query_effective(self.store, dt(MAR))['facts'][0]['value'], 11)
        self.assertEqual(self.store.get_fact('january').status, 'extracted')

    def test_historical_correction_respects_exclusive_end(self):
        self.put(self.fact('first', end=FEB))
        self.put(self.fact('next', start=FEB))
        self.assertEqual(self.correct(at=FEB)['revised_fact_id'], 'next')

    def test_historical_correction_matches_unit(self):
        self.put(self.fact('usd', unit='USD'))
        self.put(self.fact('cny', unit='CNY'))
        self.assertEqual(self.correct(unit='CNY')['revised_fact_id'], 'cny')
        self.assertEqual(self.store.get_fact('usd').status, 'extracted')

    def test_historical_correction_refuses_ambiguous_candidates_without_writes(self):
        self.put(self.fact('a'))
        self.put(self.fact('b'))
        before = self.store.facts_path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'ambiguous_historical_correction.*a, b'):
            self.correct()
        self.assertEqual(self.store.facts_path.read_bytes(), before)
        self.assertEqual(self.store.load_corrections(), [])

    def test_can_correct_state_change_predecessor_in_its_old_interval(self):
        self.put(self.fact('old', end=FEB, status='superseded', superseded_by='new'))
        self.put(self.fact('new', value=20, start=FEB, status='confirmed'))
        self.assertEqual(self.correct(at=JAN)['revised_fact_id'], 'old')
        self.assertEqual(query_effective(self.store, dt(JAN))['facts'][0]['value'], 11)
        self.assertEqual(query_effective(self.store, dt(MAR))['facts'][0]['value'], 20)

    def test_historical_correction_does_not_revise_an_already_corrected_ancestor(self):
        self.put(self.fact('ancestor', status='superseded', superseded_by='revision', notes=['historically_corrected']))
        self.put(self.fact('revision', revision_of='ancestor'))
        self.assertEqual(self.correct()['revised_fact_id'], 'revision')

    def test_correction_keeps_original_knowledge_before_it_arrived(self):
        self.put(self.fact())
        self.correct(at=JAN)
        before = query_known(self.store, dt(FEB))
        after = query_known(self.store, dt(APR))
        self.assertEqual(before['facts'][0]['value'], 10)
        self.assertEqual(before['facts'][0]['status'], 'extracted')
        self.assertEqual(before['corrections_known'], [])
        self.assertEqual(after['facts'][0]['value'], 11)
        self.assertEqual(len(after['corrections_known']), 1)

    def test_state_change_does_not_close_a_future_fact(self):
        self.put(self.fact('future', start=APR))
        result = self.change()
        self.assertEqual(result['closed'], [])
        future = self.store.get_fact('future')
        self.assertIsNone(future.valid_to)
        self.assertEqual(future.status, 'extracted')

    def test_state_change_requires_matching_old_value_and_unit(self):
        self.put(self.fact('wrong-value', value=99, unit='CNY'))
        self.put(self.fact('wrong-unit', unit='USD'))
        self.put(self.fact('correct', unit='CNY'))
        result = self.change(unit='CNY')
        self.assertEqual(result['closed'], ['correct'])
        self.assertIsNone(self.store.get_fact('wrong-value').valid_to)
        self.assertIsNone(self.store.get_fact('wrong-unit').valid_to)

    def test_state_change_refuses_ambiguous_matches_without_writes(self):
        self.put(self.fact('a'))
        self.put(self.fact('b'))
        before = self.store.facts_path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'ambiguous_state_change.*a, b'):
            self.change()
        self.assertEqual(self.store.facts_path.read_bytes(), before)
        self.assertEqual(self.store.load_corrections(), [])

    def test_state_change_preserves_confirmation_priority_in_past_interval(self):
        self.put(self.fact(status='confirmed', confirmation_event_id='original-confirm'))
        self.put(self.fact('uncertain', value=99))
        self.change()
        result = query_effective(self.store, dt(FEB))
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['facts'][0]['fact_id'], 'f1')
        self.assertEqual(result['facts'][0]['status'], 'superseded')
        self.assertEqual(result['facts'][0]['value'], 10)

    def test_effective_equal_numbers_in_different_units_conflict(self):
        self.put(self.fact('usd', unit='USD', status='confirmed'))
        self.put(self.fact('cny', unit='CNY', status='confirmed'))
        result = query_effective(self.store, dt(MAR))
        self.assertEqual(result['status'], 'conflict')
        self.assertEqual(set(result['conflicts'][0]['units']), {'USD', 'CNY'})

    def test_effective_same_value_sources_use_latest_start_without_conflict(self):
        self.put(self.fact('old', status='confirmed'))
        self.put(self.fact('new', start=FEB, status='confirmed'))
        result = query_effective(self.store, dt(MAR))
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['facts'][0]['fact_id'], 'new')
        self.assertEqual(len(result['facts']), 1)
        self.assertEqual(len(self.store.load_facts()), 2)

    def test_effective_confirmed_candidate_resolves_earlier_extracted_conflict(self):
        self.put(self.fact('extracted-a', value=1))
        self.put(self.fact('extracted-b', value=2))
        self.put(self.fact('confirmed', value=3, status='confirmed'))
        result = query_effective(self.store, dt(MAR))
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['facts'][0]['value'], 3)
        self.assertEqual(result['conflicts'], [])

    def test_effective_two_different_extracted_values_remain_pending(self):
        self.put(self.fact('a', value=1))
        self.put(self.fact('b', value=2))
        result = query_effective(self.store, dt(MAR))
        self.assertEqual(result['status'], 'pending')
        self.assertEqual(result['conflicts'][0]['reason'], 'ambiguous_extracted')

    def test_confirmation_rejects_missing_fact_without_audit_write(self):
        with self.assertRaisesRegex(ValueError, 'fact_not_found'):
            self.confirm()
        self.assertEqual(self.store.load_confirmations(), [])
        self.assertEqual(self.store.load_facts(), [])

    def test_confirmation_cannot_resurrect_corrected_fact(self):
        self.put(self.fact())
        self.correct(at=JAN)
        before = self.store.facts_path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'cannot_confirm_superseded_fact'):
            self.confirm()
        self.assertEqual(self.store.facts_path.read_bytes(), before)
        self.assertEqual(self.store.load_confirmations(), [])
        result = query_effective(self.store, dt(MAR))
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['facts'][0]['value'], 11)

    def test_confirmation_id_is_idempotent_and_does_not_rebind(self):
        self.put(self.fact())
        self.put(self.fact('other', value=12))
        result = self.confirm()
        facts_before = self.store.facts_path.read_bytes()
        self.assertEqual(self.confirm(at=APR), result)
        self.assertEqual(self.store.facts_path.read_bytes(), facts_before)
        with self.assertRaisesRegex(ValueError, 'already belongs to another fact'):
            self.confirm(fid='other')
        self.assertEqual(len(self.store.load_confirmations()), 1)
        self.assertEqual(self.store.get_fact('other').status, 'extracted')

    def test_old_confirmation_retry_after_correction_does_not_resurrect(self):
        self.put(self.fact())
        original = self.confirm()
        self.correct(at=JAN)
        before = self.store.facts_path.read_bytes()
        self.assertEqual(self.confirm(at=APR), original)
        self.assertEqual(self.store.facts_path.read_bytes(), before)
        self.assertEqual(self.store.get_fact('f1').status, 'superseded')

    def test_confirmation_id_cannot_rebind_an_embedded_confirmation(self):
        self.put(self.fact(confirmation_event_id='embedded', status='confirmed'))
        self.put(self.fact('other'))
        with self.assertRaisesRegex(ValueError, 'already belongs to another fact'):
            self.confirm(fid='other', cid='embedded')
        self.assertEqual(self.store.load_confirmations(), [])

    def test_stale_graph_sync_cannot_erase_a_new_confirmation(self):
        self.put(self.fact(graph_sync_status='synced'))
        snapshot = self.store.get_fact('f1')
        self.confirm()
        self.assertFalse(self.store.mark_graph_synced(snapshot))
        current = self.store.get_fact('f1')
        self.assertEqual(current.status, 'confirmed')
        self.assertEqual(current.confirmation_event_id, 'confirmation-1')
        self.assertEqual(current.graph_sync_status, 'pending_sync')

    def test_stale_graph_sync_cannot_erase_a_historical_correction(self):
        self.put(self.fact(graph_sync_status='synced'))
        snapshot = self.store.get_fact('f1')
        self.correct(at=JAN)
        self.assertFalse(self.store.mark_graph_synced(snapshot))
        current = self.store.get_fact('f1')
        self.assertEqual(current.status, 'superseded')
        self.assertIn('historically_corrected', current.notes)
        self.assertEqual(current.graph_sync_status, 'pending_sync')

    def test_graph_sync_only_changes_sync_status_and_is_idempotent(self):
        snapshot = self.put(self.fact(graph_sync_status='pending_sync'))
        before = snapshot.to_dict()
        self.assertTrue(self.store.mark_graph_synced(snapshot))
        expected = {**before, 'graph_sync_status': 'synced'}
        self.assertEqual(self.store.get_fact('f1').to_dict(), expected)
        persisted = self.store.facts_path.read_bytes()
        self.assertTrue(self.store.mark_graph_synced(snapshot))
        self.assertEqual(self.store.facts_path.read_bytes(), persisted)
        self.assertEqual(snapshot.to_dict(), before)
        self.assertFalse(self.store.mark_graph_synced(self.fact('missing')))

    def test_transaction_reentrant_across_instances_of_the_same_directory(self):
        other = StructuredStore(Path(self.tmp.name) / '.')
        with self.store.transaction():
            with other.transaction():
                other.upsert_fact(self.fact())
                self.confirm()
        self.assertEqual(other.get_fact('f1').status, 'confirmed')

    def test_reader_cannot_observe_half_of_a_correction(self):
        self.put(self.fact())
        midway, resume, reader_started, reader_done = [threading.Event() for _ in range(4)]
        original_append = self.store._append

        def paused_append(path, row):
            original_append(path, row)
            if path == self.store.facts_path and row.get('status') == 'superseded':
                midway.set()
                if not resume.wait(5):
                    raise RuntimeError('test did not resume correction')

        def reader():
            reader_started.set()
            result = query_effective(StructuredStore(Path(self.tmp.name)), dt(MAR))
            reader_done.set()
            return result

        with patch.object(self.store, '_append', side_effect=paused_append):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                writer = pool.submit(self.correct, JAN)
                try:
                    self.assertTrue(midway.wait(5))
                    reading = pool.submit(reader)
                    self.assertTrue(reader_started.wait(5))
                    self.assertFalse(reader_done.wait(.1))
                finally:
                    resume.set()
                writer.result(timeout=5)
                result = reading.result(timeout=5)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['facts'][0]['value'], 11)

    def test_confirmation_idempotency_across_processes(self):
        self.put(self.fact())
        code = '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from javis_memory_adapter.structured_store import StructuredStore
s = StructuredStore(Path(sys.argv[2]))
for i in range(8):
    s.write_confirmation(confirmation_event_id='same-process-event', fact_id='f1', confirmed_at='2026-03-01T00:00:00Z')
'''
        command = [sys.executable, '-B', '-c', code, str(CODE), self.tmp.name]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            calls = [pool.submit(subprocess.run, command, capture_output=True, text=True, timeout=15) for _ in range(4)]
            results = [call.result(timeout=20) for call in calls]
        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.store.load_confirmations()), 1)
        self.assertEqual(self.store.get_fact('f1').confirmation_event_id, 'same-process-event')


if __name__ == '__main__':
    unittest.main(verbosity=2)
