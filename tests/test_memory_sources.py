import hashlib
import fcntl
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import memory_sources as ms


class MemorySourcesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, rel, rows):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(rows, bytes):
            path.write_bytes(rows)
        else:
            path.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows))
        return path

    def rows(self, rel):
        return [json.loads(s) for s in (self.root / rel).read_text().splitlines() if s.strip()]

    def event(self, **extra):
        return {'id': 'message-1', 'body': 'A synthetic test preference.',
                'occurred_at': '2026-09-24T08:00:00Z', 'attachments': [], **extra}

    def legacy(self, fact='A synthetic test preference.'):
        return {'memory_id': 'm-old', 'tier': 'confirmed', 'fact': fact, 'role_id': 'test',
                'created_at': '2026-09-24T08:00:00Z', 'source': {'raw_event_ids': []}}

    def test_dry_run_writes_nothing_and_marks_missing_native_fields(self):
        row = ms.reconcile_source(self.root, 'x', {'fact': 'synthetic'}, 'legacy_memory')
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(set(row['missing']), {'missing_source_time', 'missing_source_id', 'original_conversation_unproven', 'attachment_inventory_unknown'})
        self.assertFalse(row['cloud_eligible'])

    def test_idempotent_replay_and_changed_version(self):
        one = ms.reconcile_source(self.root, 'connector:x', self.event(), 'original_message', apply=True)
        two = ms.reconcile_source(self.root, 'connector:x', self.event(), 'original_message', apply=True)
        three = ms.reconcile_source(self.root, 'connector:x', self.event(body='changed'), 'original_message', apply=True)
        self.assertTrue(one['changed'])
        self.assertFalse(two['changed'])
        self.assertEqual(three['version'], 2)
        self.assertEqual(len(self.rows('memory/provenance/sources.jsonl')), 2)
        self.assertEqual(three['previous_observation_sha256'], one['observation_sha256'])

    def test_gaps_resolve_then_reopen_without_losing_history(self):
        ms.reconcile_source(self.root, 'x', {}, 'original_message', apply=True)
        ms.reconcile_source(self.root, 'x', self.event(), 'original_message', apply=True)
        ms.reconcile_source(self.root, 'x', {}, 'original_message', apply=True)
        rows = self.rows('memory/provenance/gaps.jsonl')
        for reason in ('missing_body', 'missing_source_time', 'missing_source_id'):
            events = [r for r in rows if r['reason'] == reason]
            self.assertEqual([r['status'] for r in events], ['open', 'resolved', 'open'])
            self.assertEqual([r['transition'] for r in events], [1, 2, 3])

    def test_naive_source_time_not_accepted_or_substituted_by_capture_time(self):
        row = ms.reconcile_source(self.root, 'x', self.event(occurred_at='2026-09-24T08:00:00'), 'original_message')
        self.assertIsNone(row['source_time'])
        self.assertIn('missing_source_time', row['missing'])
        self.assertNotIn('missing_source_time', ms.reconcile_source(self.root, 'y', {'id': 'x', 'content': 'a', 'timestampMs': 0}, 'original_message')['missing'])

    def test_attachment_missing_recovered_archived_and_hash_mismatch(self):
        record = self.event(attachments=[{'id': 'a', 'path': 'attachments/a.txt'}])
        one = ms.reconcile_source(self.root, 'x', record, 'original_message', apply=True)
        self.assertIn('missing_attachment', one['missing'])
        self.put('attachments/a.txt', b'synthetic artifact')
        two = ms.reconcile_source(self.root, 'x', record, 'original_message', apply=True)
        self.assertNotIn('missing_attachment', two['missing'])
        ref = two['attachment_refs'][0]
        self.assertEqual((self.root / 'raw/objects' / ref['object_sha256']).read_bytes(), b'synthetic artifact')
        record['attachments'][0]['sha256'] = '0' * 64
        self.assertIn('attachment_hash_mismatch', ms.reconcile_source(self.root, 'x', record)['missing'])

    def test_attachment_escape_does_not_read_external_file(self):
        row = ms.reconcile_source(self.root, 'x', self.event(attachments=[{'path': '../other.txt'}]))
        self.assertIn('attachment_path_unavailable', row['missing'])
        self.assertIn('missing_attachment', row['missing'])

    def test_unknown_attachment_inventory_is_explicit(self):
        record = self.event()
        del record['attachments']
        row = ms.reconcile_source(self.root, 'x', record, 'original_message')
        self.assertIn('attachment_inventory_unknown', row['missing'])

    def test_apply_rejects_linked_provenance_and_hardlinked_source(self):
        dest = self.root / 'outside'
        dest.mkdir()
        (self.root / 'memory').mkdir()
        (self.root / 'memory/provenance').symlink_to(dest, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'linked_memory_path'):
            ms.reconcile_source(self.root, 'x', self.event(), apply=True)
        (self.root / 'memory/provenance').unlink()
        source = self.put('attachments/a.txt', b'synthetic')
        os.link(source, self.root / 'attachments/b.txt')
        row = ms.reconcile_source(self.root, 'x', self.event(attachments=[{'path': 'attachments/a.txt'}]))
        self.assertIn('attachment_path_unavailable', row['missing'])

    def test_apply_rejects_hardlinked_provenance(self):
        source = self.put('memory/provenance/sources.jsonl', b'')
        os.link(source, self.root / 'copy.jsonl')
        with self.assertRaisesRegex(ValueError, 'hardlinked_memory_file'):
            ms.audit_legacy(self.root, apply=True)

    def test_mutation_holds_shared_maintenance_lock(self):
        original = ms._commit
        def probe(*args):
            with (self.root / 'state/maintenance.lock').open('a') as handle:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return original(*args)
        with patch.object(ms, '_commit', side_effect=probe):
            ms.reconcile_source(self.root, 'x', self.event(), 'original_message', apply=True)
        with (self.root / 'state/maintenance.lock').open('a') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(handle, fcntl.LOCK_UN)

    def test_recovery_hold_blocks_all_source_writes_but_allows_audit(self):
        self.put('state/recovery-hold.json', b'{"hold":true}')
        self.put('memory/confirmed/shared/facts.jsonl', [self.legacy()])
        with self.assertRaisesRegex(ValueError, 'held for review'):
            ms.reconcile_source(self.root, 'x', self.event(), 'original_message', apply=True)
        with self.assertRaisesRegex(ValueError, 'held for review'):
            ms.audit_legacy(self.root, apply=True)
        with self.assertRaisesRegex(ValueError, 'held for review'):
            ms.stage_legacy_candidate(self.root, self.legacy())
        self.assertFalse((self.root / 'raw').exists())
        self.assertFalse((self.root / 'memory/provenance').exists())
        self.assertFalse((self.root / 'memory/candidates').exists())
        self.assertEqual(ms.audit_legacy(self.root)['stats']['legacy_records'], 1)
        self.assertEqual(ms.reconcile_source(self.root, 'x', self.event())['source_key'], 'x')
        self.put('state/recovery-hold.json', b'{"hold":false}')
        self.assertTrue(ms.reconcile_source(self.root, 'x', self.event(), apply=True)['changed'])
        self.assertEqual(ms.audit_legacy(self.root, apply=True)['stats']['source_maps_added'], 1)
        self.assertEqual(ms.stage_legacy_candidate(self.root, self.legacy())['candidate_written'], 1)

    def test_attachment_revert_is_a_new_observed_version(self):
        record = self.event(attachments=[{'id': 'a', 'path': 'attachments/a.txt'}])
        for content in (b'first', b'second', b'first'):
            self.put('attachments/a.txt', content)
            ms.reconcile_source(self.root, 'x', record, 'original_message', apply=True)
        manifests = [json.loads(line) for p in (self.root / 'raw/manifests').glob('*.jsonl') for line in p.read_text().splitlines()]
        self.assertEqual([r['version'] for r in manifests], [1, 2, 3])
        self.assertEqual(manifests[0]['sha256'], manifests[2]['sha256'])
        self.assertNotEqual(manifests[0]['snapshot_id'], manifests[2]['snapshot_id'])
        replay = ms.reconcile_source(self.root, 'x', record, 'original_message', apply=True)
        self.assertFalse(replay['changed'])

    def test_legacy_exact_import_match_is_derived_not_confirmed(self):
        legacy = self.put('memory/confirmed/by-role/test/facts.jsonl', [self.legacy()])
        original = legacy.read_bytes()
        self.put('memory/imports/20260924-test/confirmed-stage/ALL.jsonl', [{'fact': self.legacy()['fact'], 'tier': 'confirmed'}])
        dry = ms.audit_legacy(self.root)
        self.assertFalse((self.root / 'raw').exists())
        self.assertEqual(dry['stats']['legacy_with_exact_import_match'], 1)
        applied = ms.audit_legacy(self.root, apply=True)
        row = applied['mappings'][0]
        self.assertEqual(row['memory_status'], 'provenance_only')
        self.assertIn('original_conversation_unproven', row['missing'])
        self.assertEqual(row['source_ref']['matching_imports'][0]['source_kind'], 'derived_memory')
        self.assertEqual(legacy.read_bytes(), original)
        replay = ms.audit_legacy(self.root, apply=True)
        self.assertEqual(replay['stats']['source_maps_added'], 0)
        self.assertEqual(len(self.rows('memory/provenance/sources.jsonl')), 1)
        self.assertEqual(applied['stats']['confirmed_written'], 0)
        self.assertNotIn(self.legacy()['fact'], json.dumps(applied))

    def test_original_match_preserves_speaker_and_bytes_but_never_confirms(self):
        self.put('memory/confirmed/shared/facts.jsonl', [self.legacy()])
        path = self.put('memory/imports/20260924-test/transcripts/dialog.jsonl', [self.event(content=self.legacy()['fact'], role='assistant')])
        row = ms.audit_legacy(self.root, apply=True)['mappings'][0]
        match = row['source_ref']['matching_imports'][0]
        self.assertEqual(match['source_kind'], 'original_message')
        self.assertEqual(match['speaker_role'], 'assistant')
        self.assertEqual(match['original_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(match['byte_start'], 0)
        self.assertEqual(match['byte_end'], path.stat().st_size)
        self.assertFalse(row['source_ref']['original_evidence_verified'])

    def test_no_fuzzy_match_into_a_negation(self):
        self.put('memory/confirmed/shared/facts.jsonl', [self.legacy('I own the card')])
        self.put('memory/imports/20260924-test/memory.md', b'I do not own the card\n')
        row = ms.audit_legacy(self.root)['mappings'][0]
        self.assertEqual(row['source_ref']['matching_imports'], [])
        self.assertIn('import_source_not_matched', row['missing'])

    def test_corrupt_import_records_audited_and_original_bytes_retained(self):
        self.put('memory/confirmed/shared/facts.jsonl', [self.legacy()])
        self.put('memory/imports/20260924-test/transcripts/partial.jsonl', b'{invalid\n')
        result = ms.audit_legacy(self.root, apply=True)
        self.assertEqual(result['stats']['import_invalid_records'], 1)
        self.assertEqual(result['issues'][0]['reason'], 'invalid_import_record')
        self.assertEqual(result['issues'][0]['line'], 1)

    def test_backup_secret_and_symlink_trees_are_excluded(self):
        self.put('memory/imports/20260924-test/backups/facts.jsonl', [self.legacy()])
        self.put('memory/imports/20260924-test/credentials.json', b'{}')
        self.put('memory/imports/20260924-test/profile.md', b'synthetic')
        (self.root / 'memory/imports/latest').symlink_to(self.root / 'memory/imports/20260924-test', target_is_directory=True)
        result = ms.audit_legacy(self.root)
        self.assertEqual(len(result['inventory']), 1)
        self.assertTrue(result['inventory'][0]['path'].endswith('profile.md'))

    def test_original_hash_survives_credential_redaction(self):
        p = self.put('memory/confirmed/shared/facts.jsonl', [self.legacy('password=synthetic-secret')])
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        result = ms.audit_legacy(self.root, apply=True)
        snap = result['mappings'][0]['source_ref']['snapshot']
        self.assertEqual(snap['original_sha256'], digest)
        self.assertNotEqual(snap['object_sha256'], digest)
        self.assertEqual(snap['content_form'], 'credential_redacted_copy')
        self.assertNotIn(b'synthetic-secret', (self.root / 'raw/objects' / snap['object_sha256']).read_bytes())

    def test_corrupt_audit_history_fails_closed(self):
        self.put('memory/provenance/sources.jsonl', b'{broken\n')
        with self.assertRaisesRegex(ValueError, 'source_audit_ledger_corrupt'):
            ms.reconcile_source(self.root, 'x', self.event(), apply=True)


if __name__ == '__main__':
    unittest.main()
