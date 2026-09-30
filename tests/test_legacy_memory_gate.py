import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


class LegacyMemoryGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, rel, content):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding='utf-8')
        return p

    def enable(self, value=True):
        self.put('config/memory-pipeline.json', json.dumps({'enabled': value, 'model': 'jev-1.13.0'}))

    def run_script(self, name, *args):
        return subprocess.run([sys.executable, '-B', str(SCRIPTS / name), *map(str, args)],
            capture_output=True, text=True,
            env={**os.environ, 'JAVIS_ROOT': str(self.root), 'PYTHONPATH': str(SCRIPTS)})

    def rows(self, rel):
        return [json.loads(s) for s in (self.root / rel).read_text().splitlines() if s.strip()]

    def append(self, **kwargs):
        return self.run_script('memory-append.py', '--tier', kwargs.get('tier', 'confirmed'),
            '--role', kwargs.get('role', 'cards-master'), '--fact', kwargs.get('fact', 'Synthetic preference'),
            '--confidence', 'high')

    def test_enabled_direct_confirmed_becomes_replayable_candidate(self):
        self.enable()
        out = self.append()
        self.assertEqual(out.returncode, 0, out.stderr)
        result = json.loads(out.stdout)
        self.assertEqual(result['status'], 'pending_evidence_and_owner_review')
        self.assertEqual(result['effective_tier'], 'candidate')
        self.assertEqual(result['confirmed_written'], 0)
        self.assertFalse((self.root / 'memory/confirmed').exists())
        row = self.rows('memory/candidates/by-role/cards-master/facts.jsonl')[0]
        self.assertEqual(row['tier'], 'candidate')
        self.assertIsNone(row['confirmed_at'])
        self.assertIsNone(row['confirmed_by'])
        self.assertIsNone(row['temporal']['as_of'])
        self.assertFalse(row['cloud_eligible'])
        self.assertIn('original_conversation_unproven', row['missing'])
        replay = self.append()
        self.assertEqual(json.loads(replay.stdout)['candidate_written'], 0)
        self.assertEqual(len(self.rows('memory/candidates/by-role/cards-master/facts.jsonl')), 1)
        events = [json.loads(s) for p in (self.root / 'raw/events').glob('*.jsonl') for s in p.read_text().splitlines()]
        source = next(e for e in events if e['event_id'] == row['source']['raw_event_ids'][0])
        self.assertFalse(source['cloud_eligible'])
        self.assertEqual(source['payload']['content_form'], 'local_only_original')
        self.assertFalse(source['payload']['text_available'])
        sys.path.insert(0, str(SCRIPTS))
        from raw_storage import read_preserved_original
        reference = source['raw_preservation']['original']
        original = json.loads(read_preserved_original(self.root, reference, allow_sensitive=True))
        self.assertEqual(original['payload']['source_kind'], 'derived_memory')
        self.assertFalse(original['payload']['cloud_eligible'])
        self.assertFalse((self.root / 'memory/structured').exists())
        self.assertFalse((self.root / 'memory/retrieval').exists())

    def test_missing_and_disabled_config_preserve_legacy_behavior(self):
        for enabled in (None, False):
            if enabled is not None:
                self.enable(enabled)
            out = self.append(fact='Synthetic ' + str(enabled))
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(json.loads(out.stdout)['effective_tier'], 'confirmed')
        rows = self.rows('memory/confirmed/by-role/cards-master/facts.jsonl')
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r['tier'] == 'confirmed' and r['confirmed_at'] for r in rows))

    def test_idea_lab_new_mode_does_not_touch_mixed_legacy_file(self):
        self.enable()
        old = self.put('memory/ide-lab/facts.jsonl', '{"tier":"confirmed","fact":"old"}\n')
        before = old.read_bytes()
        out = self.append(role='ide-lab')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(old.read_bytes(), before)
        self.assertTrue((self.root / 'memory/candidates/by-role/idea-lab/facts.jsonl').is_file())

    def test_newer_import_never_supersedes_existing_confirmed(self):
        self.enable()
        old = self.put('memory/confirmed/by-role/cards-master/facts.jsonl', json.dumps({
            'tier': 'confirmed', 'fact': 'Synthetic preference', 'memory_id': 'old',
            'temporal': {'as_of': '2026-09-01T00:00:00Z'}}) + '\n')
        before = old.read_bytes()
        pkg = self.root / 'memory/imports/20260924-test'
        self.put('memory/imports/20260924-test/confirmed-stage/ALL-CONFIRMED-READY.jsonl', json.dumps({
            'fact': 'Synthetic preference', 'role': 'cards-master', 'tier': 'confirmed',
            'as_of': '2026-09-24T00:00:00Z', 'source': 'grok-mirror', 'supersedes': 'old'}) + '\n')
        out = self.run_script('apply-confirmed-on-machine0.py', '--package', pkg, '--javis-root', self.root)
        self.assertEqual(out.returncode, 0, out.stderr)
        result = json.loads(out.stdout)
        self.assertEqual(result['confirmed_written'], 0)
        self.assertEqual(result['written_candidates'], 1)
        self.assertEqual(old.read_bytes(), before)
        candidate = self.rows('memory/candidates/by-role/cards-master/facts.jsonl')[0]
        self.assertIsNone(candidate['supersedes'])
        self.assertEqual(candidate['requested_supersedes'], 'old')
        self.assertFalse((pkg / 'APPLY-CONFIRMED-RESULT.json').exists())
        self.assertFalse((self.root / 'state/grok-all-bots-archive/watermark.json').exists())
        replay = self.run_script('apply-confirmed-on-machine0.py', '--package', pkg, '--javis-root', self.root)
        self.assertEqual(json.loads(replay.stdout)['written_candidates'], 0)
        self.assertEqual(json.loads(replay.stdout)['replayed'], 1)

    def test_new_import_dry_run_does_not_write(self):
        self.enable()
        pkg = self.root / 'memory/imports/20260924-test'
        self.put('memory/imports/20260924-test/confirmed-stage/ALL-CONFIRMED-READY.jsonl',
                 json.dumps({'role': 'cards-master', 'fact': 'synthetic'}) + '\n')
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        out = self.run_script('apply-confirmed-on-machine0.py', '--package', pkg, '--javis-root', self.root, '--dry-run')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)['confirmed_written'], 0)
        self.assertEqual(before, {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_import_old_behavior_without_config(self):
        pkg = self.root / 'memory/imports/20260924-test'
        self.put('memory/imports/20260924-test/confirmed-stage/ALL-CONFIRMED-READY.jsonl',
                 json.dumps({'role': 'cards-master', 'fact': 'synthetic',
                             'as_of': '2026-09-24T00:00:00Z', 'learned_at': '2026-09-24T00:00:00Z'}) + '\n')
        (self.root / 'scripts').mkdir()
        shutil.copyfile(SCRIPTS / 'memory-append.py', self.root / 'scripts/memory-append.py')
        out = self.run_script('apply-confirmed-on-machine0.py', '--package', pkg, '--javis-root', self.root)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)['written'], 1)
        self.assertEqual(self.rows('memory/confirmed/by-role/cards-master/facts.jsonl')[0]['tier'], 'confirmed')

    def test_export_blocks_and_preserves_existing_user_file(self):
        self.enable()
        target = self.put('user-archive.jsonl', 'existing user archive\n')
        out = self.run_script('export-javis-confirmed-for-grok.py', '--javis-root', self.root, '--out', target)
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertEqual(json.loads(out.stdout)['status'], 'blocked')
        self.assertEqual(target.read_text(), 'existing user archive\n')
        self.assertFalse((self.root / 'EXPORT-META.json').exists())

    def test_export_old_behavior_without_config(self):
        self.put('memory/confirmed/by-role/cards-master/facts.jsonl', json.dumps({
            'tier': 'confirmed', 'fact': 'Synthetic preference', 'memory_id': 'old'}) + '\n')
        target = self.root / 'export/facts.jsonl'
        out = self.run_script('export-javis-confirmed-for-grok.py', '--javis-root', self.root, '--out', target)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)['count'], 1)

    def test_invalid_gate_config_cannot_fall_back_to_confirmation(self):
        self.enable('true')
        out = self.append()
        self.assertNotEqual(out.returncode, 0)
        self.assertEqual(json.loads(out.stdout)['status'], 'blocked')
        self.assertFalse((self.root / 'memory/confirmed').exists())

    def test_role_path_traversal_rejected_before_writes(self):
        self.enable()
        out = self.append(role='../../outside')
        self.assertNotEqual(out.returncode, 0)
        self.assertFalse((self.root / 'outside').exists())

    def test_recovery_hold_blocks_append_and_import_dry_run_still_works(self):
        self.enable()
        self.put('state/recovery-hold.json', '{"hold":true}')
        pkg = self.root / 'memory/imports/20260924-test'
        self.put('memory/imports/20260924-test/confirmed-stage/ALL-CONFIRMED-READY.jsonl',
                 json.dumps({'role': 'cards-master', 'fact': 'synthetic'}) + '\n')
        self.assertEqual(self.append().returncode, 2)
        args = ('--package', pkg, '--javis-root', self.root)
        blocked = self.run_script('apply-confirmed-on-machine0.py', *args)
        self.assertEqual(blocked.returncode, 2, blocked.stderr)
        self.assertFalse((self.root / 'raw').exists())
        self.assertFalse((self.root / 'memory/candidates').exists())
        self.assertFalse((pkg / 'APPLY-CANDIDATE-RESULT.json').exists())
        dry = self.run_script('apply-confirmed-on-machine0.py', *args, '--dry-run')
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.put('state/recovery-hold.json', '{"hold":false}')
        self.assertEqual(self.append().returncode, 0)
        applied = self.run_script('apply-confirmed-on-machine0.py', *args)
        self.assertEqual(applied.returncode, 0, applied.stderr)


if __name__ == '__main__':
    unittest.main()
