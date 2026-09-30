"""All snapshot/health checks operate on isolated temporary data."""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import memory_sync as sync


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


health = load('memory_health_test', 'three-lines-health.py')
NOW = datetime(2026, 9, 24, 12, tzinfo=timezone(timedelta(hours=8)))


class MemorySyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def fixture(self):
        self.write('memory/profiles/invest.json', '{"private_profile":"PROFILE_SECRET"}')
        self.write('memory/confirmed/by-role/invest/facts.jsonl', '{"text":"FACT_SECRET","actor":"ACTOR_SECRET"}\n')

    def base(self, side='codex_invest'):
        return self.root / sync.SYNC_ROOT / ('from_' + side) / '20260924'

    def grok(self):
        # Simulate an independently delivered export, never label the local
        # Codex source as a successful second producer in the implementation.
        export = self.root / 'grok-export-fixture'
        for relative, _ in sync._sources('grok_invest'):
            source = self.root / relative
            if source.is_file():
                target = export / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
        return sync.run(self.root, NOW, 'grok_invest', source_root=export)

    def test_import_and_status_are_read_only(self):
        with patch('pathlib.Path.mkdir', side_effect=AssertionError('import or status wrote a directory')), \
                patch('os.open', side_effect=AssertionError('import or status wrote a file')):
            load('sync_entry_test', 'invest_codex_side_daily_sync_stub.py')
            result = sync.status(self.root, NOW)
        self.assertEqual(result['missing_sides'], list(sync.SIDES))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_repeat_is_idempotent_and_same_day_change_is_new_version(self):
        self.fixture()
        first = sync.run(self.root, NOW)
        manifest = self.base() / 'versions' / first['version'] / 'manifest.json'
        before = manifest.read_bytes()
        again = sync.run(self.root, NOW + timedelta(hours=1))
        self.assertTrue(again['replayed'])
        self.assertEqual(first['version'], again['version'])
        self.assertEqual(first['manifest_sha256'], again['manifest_sha256'])
        self.write('memory/profiles/invest.json', '{"revised":true}')
        changed = sync.run(self.root, NOW + timedelta(hours=2))
        self.assertNotEqual(first['version'], changed['version'])
        self.assertEqual(before, manifest.read_bytes())
        self.assertEqual(len(list((self.base() / 'versions').iterdir())), 2)

    def test_each_side_independent_and_no_snapshot_claims_merge(self):
        self.fixture()
        sync.run(self.root, NOW, 'codex_invest')
        first = sync.status(self.root, NOW)
        self.assertEqual(first['missing_sides'], ['grok_invest'])
        self.grok()
        both = sync.status(self.root, NOW)
        self.assertTrue(both['both_snapshots_verified'])
        self.assertFalse(both['attention_required'])
        self.assertEqual(both['merge_state'], 'not_attempted')
        next_day = sync.status(self.root, NOW + timedelta(days=1))
        self.assertEqual(next_day['missing_sides'], list(sync.SIDES))

    def test_different_sides_are_reconciled_by_hash(self):
        self.fixture()
        sync.run(self.root, NOW)
        self.write('memory/profiles/invest.json', '{"revision":2}')
        self.grok()
        result = sync.status(self.root, NOW)
        self.assertTrue(result['both_snapshots_verified'])
        self.assertEqual(result['comparison']['different_file_count'], 1)
        self.assertTrue(result['attention_required'])

    def test_missing_required_sources_are_not_success(self):
        result = sync.run(self.root, NOW)
        self.assertFalse(result['ok'])
        self.assertEqual(result['missing_required'], ['invest_profile', 'invest_memory_facts'])
        value = sync.status(self.root, NOW)['sides']['codex_invest']
        self.assertTrue(value['verified'])
        self.assertEqual(value['state'], 'snapshot_incomplete')

    def test_legacy_marker_is_not_verified_or_merged(self):
        self.fixture()
        sync.run(self.root, NOW)
        marker = {'schema': 'invest-daily-sync-1', 'side': 'grok_invest', 'day': '20260924',
                  'files': ['invest.profile.json'], 'note': 'SECRET_PRIVATE_NOTE', 'actor': 'IDENTITY_SECRET'}
        self.write(str(self.base('grok_invest').relative_to(self.root) / 'SYNC_OK.json'), json.dumps(marker))
        self.write(str(self.base('grok_invest').relative_to(self.root) / 'invest.profile.json'), '{}')
        result = sync.status(self.root, NOW)
        self.assertEqual(result['sides']['grok_invest']['state'], 'legacy_unverified')
        self.assertFalse(result['both_snapshots_verified'])
        self.assertNotIn('SECRET', json.dumps(result))

    def test_new_and_mixed_source_formats(self):
        self.write('memory/profiles/invest.json', '{}')
        self.write('memory/structured/invest/facts.jsonl', '')
        result = sync.run(self.root, NOW)
        self.assertEqual(result['source_format'], 'structured')
        self.write('memory/confirmed/by-role/invest/facts.jsonl', '')
        result = sync.run(self.root, NOW)
        self.assertEqual(result['source_format'], 'mixed')

    def test_source_missing_on_one_side_requires_attention(self):
        self.fixture()
        sync.run(self.root, NOW)
        self.write('memory/structured/invest/facts.jsonl', '')
        self.grok()
        result = sync.status(self.root, NOW)
        self.assertEqual(result['comparison']['files_only_on_side']['grok_invest'], 1)
        self.assertTrue(result['attention_required'])

    def test_codex_only_notes_do_not_create_false_divergence(self):
        self.fixture()
        self.write('state/invest-codex-memory-notes.md', 'PRIVATE_NOTES')
        sync.run(self.root, NOW)
        self.grok()
        result = sync.status(self.root, NOW)
        self.assertFalse(result['attention_required'])
        self.assertNotIn('PRIVATE_NOTES', json.dumps(result))

    def test_payload_tampering_fails_closed_and_is_not_overwritten(self):
        self.fixture()
        result = sync.run(self.root, NOW)
        payload = self.base() / 'versions' / result['version'] / 'files/memory/profiles/invest.json'
        payload.write_text('tampered', encoding='utf-8')
        value = sync.status(self.root, NOW)['sides']['codex_invest']
        self.assertEqual(value['state'], 'invalid')
        with self.assertRaisesRegex(ValueError, 'payload_hash_mismatch'):
            sync.run(self.root, NOW)
        self.assertEqual(payload.read_text(), 'tampered')

    def test_grok_cannot_impersonate_independent_sync_with_local_sources(self):
        self.fixture()
        for source_root in (None, self.root):
            with self.assertRaisesRegex(ValueError, 'grok_requires_separate_source_export'):
                sync.run(self.root, NOW, 'grok_invest', source_root=source_root)
        self.assertFalse((self.root / sync.SYNC_ROOT).exists())

    def test_hardlinked_source_is_rejected(self):
        self.fixture()
        source = self.root / 'memory/profiles/invest.json'
        os.link(source, self.root / 'hardlink.json')
        with self.assertRaisesRegex(ValueError, 'source_hardlink_rejected'):
            sync.run(self.root, NOW)
        self.assertFalse((self.base() / 'LATEST.json').exists())

    def test_manifest_tampering_and_pointer_traversal(self):
        self.fixture()
        result = sync.run(self.root, NOW)
        manifest_path = self.base() / 'versions' / result['version'] / 'manifest.json'
        data = json.loads(manifest_path.read_text())
        data['side'] = 'grok_invest'
        manifest_path.write_text(json.dumps(data))
        self.assertEqual(sync.status(self.root, NOW)['sides']['codex_invest']['state'], 'invalid')
        pointer_path = self.base() / 'LATEST.json'
        pointer = json.loads(pointer_path.read_text()); pointer['version'] = '../../elsewhere'
        pointer_path.write_text(json.dumps(pointer))
        self.assertEqual(sync.status(self.root, NOW)['sides']['codex_invest']['state'], 'invalid')

    def test_unstable_source_does_not_publish(self):
        self.fixture()
        original = Path.read_bytes
        calls = 0
        def changing(path):
            nonlocal calls
            data = original(path)
            if path.name == 'invest.json':
                calls += 1
                if calls > 1:
                    return data + b' '
            return data
        with patch.object(Path, 'read_bytes', changing):
            with self.assertRaisesRegex(ValueError, 'source_changed_during_snapshot'):
                sync.run(self.root, NOW)
        self.assertFalse((self.base() / 'LATEST.json').exists())

    def test_recovery_hold_false_true_corrupt_and_wrong_types(self):
        self.assertFalse(sync.recovery_held(self.root))
        for raw, expected in [(' {"hold":false}', False), ('{"hold":true}', True), ('{"hold":"false"}', True), ('{}', True), ('[]', True), ('broken', True)]:
            with self.subTest(raw=raw):
                self.write('state/recovery-hold.json', raw)
                self.assertEqual(sync.recovery_held(self.root), expected)
                self.assertEqual(health.recovery_held(self.root), expected)
        self.assertEqual(sync.run(self.root, NOW)['reason'], 'recovery_hold')
        self.assertFalse((self.root / sync.SYNC_ROOT).exists())

    def test_public_pipeline_summary_uses_latest_status_and_redacts_identity(self):
        self.write('memory/screen/runs.jsonl', '\n'.join([
            json.dumps({'run_id': 'RUN_SECRET', 'status': 'retry', 'text': 'BODY_SECRET', 'actor': 'ACTOR_SECRET'}),
            json.dumps({'run_id': 'RUN_SECRET', 'status': 'completed', 'raw_refs': ['PATH_SECRET']}),
            json.dumps({'run_id': 'RUN2_SECRET', 'status': 'MODEL_CONTROLLED_SECRET'}), 'broken']))
        result = health.memory_health(self.root)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(result['pipeline']['run_count'], 2)
        self.assertEqual(result['pipeline']['by_status']['completed'], 1)
        self.assertEqual(result['pipeline']['by_status']['retry'], 0)
        self.assertEqual(result['pipeline']['by_status']['other'], 1)
        self.assertEqual(result['pipeline']['malformed_record_count'], 1)

    def test_complete_pipeline_state_is_not_an_alarm(self):
        self.write('memory/screen/runs.jsonl', '{"run_id":"private-run","status":"complete"}\n')
        value = health.memory_health(self.root)['pipeline']
        self.assertEqual(value['by_status']['complete'], 1)
        self.assertFalse(value['attention_required'])

    def test_timezone_and_invalid_naive_time(self):
        now = datetime(2026, 9, 23, 17, tzinfo=timezone.utc)
        self.assertEqual(sync.status(self.root, now)['day'], '20260924')
        with self.assertRaises(ValueError):
            sync.status(self.root, datetime(2026, 9, 24))


if __name__ == '__main__':
    unittest.main()
