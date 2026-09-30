"""Mirror batch/policy tests. Fake owner proofs exist only inside TemporaryDirectory roots."""
import contextlib
import copy
import importlib
import importlib.util
import io
import json
import shutil
import subprocess
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT / 'tools/memory-adapter'))
from javis_memory_adapter.review_policy import ReviewBlocked, digest  # noqa: E402


def load_script(name, alias):
    spec = importlib.util.spec_from_file_location(alias, SCRIPTS / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class MirrorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='javis-mirror-test-')
        self.root = Path(self.tmp.name).resolve()
        self.principal = object()
        self.assertion = 'TEST-ONLY-ASSERTION'
        self.proofs, self.counter = {}, 0
        fake = types.ModuleType('owner_auth')
        def principal(root, value):
            self.assertEqual(Path(root).resolve(), self.root)
            if value is not self.principal:
                raise PermissionError('not authenticated')
            return {'actor_id': 'owner:local'}
        def decision(root, assertion, binding):
            self.assertEqual(Path(root).resolve(), self.root)
            if assertion != self.assertion:
                raise PermissionError('bad assertion')
            self.counter += 1
            proof = {'actor_id': 'owner:local', 'proof_id': 'test-proof-%d' % self.counter, 'binding_hash': digest(binding)}
            self.proofs[proof['proof_id']] = (copy.deepcopy(binding), proof)
            return proof
        def recorded(root, proof_id, binding):
            self.assertEqual(Path(root).resolve(), self.root)
            old, proof = self.proofs[proof_id]
            if old != binding:
                raise PermissionError('binding changed')
            return copy.deepcopy(proof)
        fake.verify_principal, fake.verify_decision, fake.verify_recorded_decision = principal, decision, recorded
        self.patch = patch.dict(sys.modules, {'owner_auth': fake})
        self.patch.start()
        import mirror_batch_review
        self.m = importlib.reload(mirror_batch_review)
        self.pkg = self.root / 'memory/imports/20260928-grok-javis-bidir'

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def put(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding='utf-8')
        return p

    def jl(self, rows):
        return ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows)

    def enable(self):
        self.put('config/memory-pipeline.json', json.dumps({'enabled': True, 'model': 'jev-1.13.0'}))

    def stage(self, rows):
        self.put('memory/imports/20260928-grok-javis-bidir/confirmed-stage/ALL-CONFIRMED-READY.jsonl', self.jl(rows))
        self.put('memory/imports/20260928-grok-javis-bidir/watermark-after.json', '{"w": 1}')

    def confirmed(self, role, rows):
        rel = 'memory/confirmed/shared/facts.jsonl' if role == 'shared' else f'memory/confirmed/by-role/{role}/facts.jsonl'
        self.put(rel, self.jl(rows))

    def rows(self, rel):
        p = self.root / rel
        return [json.loads(s) for s in p.read_text(encoding='utf-8').split('\n') if s.strip()] if p.exists() else []

    def sample(self):
        self.confirmed('invest', [
            {'tier': 'confirmed', 'fact': 'Same fact', 'memory_id': 'a', 'temporal': {'as_of': '2026-09-01T00:00:00+08:00'}},
            {'tier': 'confirmed', 'fact': 'Old version fact', 'memory_id': 'b', 'temporal': {'as_of': '2026-09-01T00:00:00+08:00'}},
            {'tier': 'confirmed', 'fact': 'Newer in Javis', 'memory_id': 'c', 'temporal': {'as_of': '2026-09-20T00:00:00+08:00'}},
            {'tier': 'confirmed', 'fact': 'Javis only fact for Grok', 'memory_id': 'd', 'temporal': {'as_of': '2026-09-22T00:00:00+08:00'}},
            {'tier': 'confirmed', 'fact': 'friday 角色的私人设置', 'memory_id': 'e', 'temporal': {'as_of': '2026-09-22T00:00:00+08:00'}},
        ])
        self.stage([
            {'role': 'invest', 'fact': 'Brand new fact', 'as_of': '2026-09-27T12:00:00+08:00'},
            {'role': 'invest', 'fact': 'Same fact', 'as_of': '2026-09-01T00:00:00+08:00'},
            {'role': 'invest', 'fact': 'Old version fact', 'as_of': '2026-09-10T00:00:00+08:00'},
            {'role': 'invest', 'fact': 'Newer in Javis', 'as_of': '2026-09-02T00:00:00+08:00'},
            {'role': 'invest', 'fact': 'No time known', 'as_of': ''},
            {'role': 'invest', 'fact': 'api_key is sk-abcdefghijklmnop', 'as_of': '2026-09-27T00:00:00+08:00'},
            {'role': 'invest', 'fact': 'strict L4 medical note', 'as_of': '2026-09-27T00:00:00+08:00'},
            {'role': 'gpt-star', 'fact': 'friday 是用户设计的普通角色，排除出共享记忆', 'as_of': '2026-09-27T00:00:00+08:00'},
            {'role': 'invest', 'fact': '2026-09-25（周五）收盘未敲出', 'as_of': '2026-09-27T00:00:00+08:00'},
            {'role': 'invest', 'fact': 'SAP closed on Friday below KO', 'as_of': '2026-09-27T00:00:00+08:00'},
        ])
        self.confirmed('invest', self.rows('memory/confirmed/by-role/invest/facts.jsonl') + [
            {'tier': 'confirmed', 'fact': 'No time known', 'memory_id': 'f', 'temporal': {'as_of': '2026-09-01T00:00:00+08:00'}}])

    def confirm_batch(self):
        prep = self.m.prepare(self.root, self.pkg)
        req = {'action': 'confirm_mirror_batch', 'batch_id': prep['batch_id'], 'command_id': 'cmd-1'}
        self.assertEqual(self.m.review(self.root, self.principal, req, self.assertion)['status'], 'confirmed')
        return prep

    # --- filters ---------------------------------------------------------
    def test_friday_filter_is_bot_not_weekday(self):
        f = self.m.is_friday_bot
        self.assertTrue(f({'role': 'friday', 'fact': 'x'}))
        self.assertTrue(f({'role': 'gpt-star', 'fact': 'Javis、toolgo、friday 都是搭建设计用的 bot'}))
        self.assertTrue(f({'role': 'gpt-star', 'fact': 'Friday bot 的目录'}))
        for text in ('周五 12:00 跑周报台账', '2026-09-25（周五）收盘', '星期五开会',
                     'SAP closed on Friday below KO', 'Friday close 221.54', 'every Friday at noon'):
            self.assertFalse(f({'role': 'invest', 'fact': text}), text)

    def test_manifest_classification_and_conflict_rule(self):
        self.sample()
        m = self.m.build_manifest(self.root, self.pkg)
        promoted = {x['fact']: x['reason'] for x in m['promote']}
        self.assertEqual(promoted, {'Brand new fact': 'new', 'Old version fact': 'newer_than_confirmed',
                                    '2026-09-25（周五）收盘未敲出': 'new', 'SAP closed on Friday below KO': 'new'})
        conflicts = {x['fact']: x['reason'] for x in m['excluded']['conflicts']}
        self.assertEqual(conflicts, {'Newer in Javis': 'older_than_confirmed', 'No time known': 'cannot_compare_as_of'})
        self.assertEqual(m['counts']['secret_or_l4'], 2)
        self.assertEqual([x['fact'][:6] for x in m['excluded']['friday_bot']], ['friday'])
        self.assertEqual(m['counts']['duplicates'], 1)
        exported = {x['fact'] for x in m['export']}
        self.assertIn('Javis only fact for Grok', exported)
        self.assertNotIn('friday 角色的私人设置', exported)
        self.assertNotIn('Same fact', exported)

    # --- owner decision --------------------------------------------------
    def test_prepare_confirms_nothing_and_review_requires_assertion(self):
        self.sample()
        prep = self.m.prepare(self.root, self.pkg)
        self.assertEqual(self.m.verified_batch(self.root, self.pkg), (None, None))
        req = {'action': 'confirm_mirror_batch', 'batch_id': prep['batch_id'], 'command_id': 'cmd-x'}
        with self.assertRaises(ReviewBlocked):
            self.m.review(self.root, self.principal, req, 'forged')
        with self.assertRaises(ReviewBlocked):
            self.m.review(self.root, object(), req, self.assertion)
        self.assertEqual(self.m.verified_batch(self.root, self.pkg), (None, None))

    def test_verified_batch_rejects_tampering_and_stage_change(self):
        self.sample()
        prep = self.confirm_batch()
        manifest, row = self.m.verified_batch(self.root, self.pkg)
        self.assertEqual(row['binding']['batch_id'], prep['batch_id'])
        path = self.root / self.m.BATCH_DIR / (prep['batch_id'] + '.json')
        original = path.read_bytes()
        data = json.loads(original); data['promote'].append({'role': 'invest', 'fact': 'injected', 'line': 99})
        path.write_text(json.dumps(data), encoding='utf-8')
        self.assertEqual(self.m.verified_batch(self.root, self.pkg), (None, None))
        path.write_bytes(original)
        self.assertIsNotNone(self.m.verified_batch(self.root, self.pkg)[0])
        stage = self.pkg / 'confirmed-stage/ALL-CONFIRMED-READY.jsonl'
        stage.write_text(stage.read_text(encoding='utf-8') + json.dumps({'role': 'invest', 'fact': 'late'}) + '\n', encoding='utf-8')
        self.assertEqual(self.m.verified_batch(self.root, self.pkg), (None, None))

    def test_rejected_batch_never_authorizes(self):
        self.sample()
        prep = self.m.prepare(self.root, self.pkg)
        req = {'action': 'reject_mirror_batch', 'batch_id': prep['batch_id'], 'command_id': 'cmd-r'}
        self.assertEqual(self.m.review(self.root, self.principal, req, self.assertion)['status'], 'rejected')
        self.assertEqual(self.m.authorization(self.root, self.pkg), (None, None))

    # --- apply / export --------------------------------------------------
    def run_main(self, mod, argv):
        buf = io.StringIO()
        with patch.object(sys, 'argv', argv), contextlib.redirect_stdout(buf):
            code = mod.main()
        return code, buf.getvalue()

    def test_apply_writes_only_authorized_promote_rows_idempotently(self):
        self.enable(); self.sample()
        apply = load_script('apply-confirmed-on-machine0.py', 'apply_mirror_test')
        code, out = self.run_main(apply, ['x', '--package', str(self.pkg), '--javis-root', str(self.root)])
        self.assertEqual(json.loads(out)['confirmed_written'], 0)  # no decision -> candidates only
        self.assertFalse(any('m-mirror-' in json.dumps(r) for r in self.rows('memory/confirmed/by-role/invest/facts.jsonl')))
        self.confirm_batch()
        code, out = self.run_main(apply, ['x', '--package', str(self.pkg), '--javis-root', str(self.root)])
        res = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(res['status'], 'owner_authorized')
        self.assertEqual(res['confirmed_written'], 4)
        rows = self.rows('memory/confirmed/by-role/invest/facts.jsonl')
        mine = [r for r in rows if r['memory_id'].startswith('m-mirror-')]
        self.assertEqual(len(mine), 4)
        self.assertTrue(all(r['confirmed_by'] == 'owner:local' and r['owner_authorization']['proof_id'] for r in mine))
        self.assertTrue(all('bidir-20260928' in r['tags'] and 'bidir-20260923' not in r['tags'] for r in mine))
        self.assertFalse(any('sk-' in r['fact'] or 'L4' in r['fact'] for r in rows))
        self.assertEqual([r['fact'] for r in rows if r['fact'] == 'Newer in Javis'], ['Newer in Javis'])
        self.assertEqual((self.root / 'state/grok-all-bots-archive/latest-import-id.txt').read_text().strip(), self.pkg.name)
        code, out = self.run_main(apply, ['x', '--package', str(self.pkg), '--javis-root', str(self.root)])
        self.assertEqual(json.loads(out)['confirmed_written'], 0)
        self.assertEqual(json.loads(out)['replayed'], 4)

    def test_export_blocked_without_decision_and_exact_list_with_decision(self):
        self.enable(); self.sample()
        export = load_script('export-javis-confirmed-for-grok.py', 'export_mirror_test')
        target = self.put('user-archive.jsonl', 'existing user archive\n')
        code, out = self.run_main(export, ['x', '--javis-root', str(self.root), '--out', str(target), '--package', str(self.pkg)])
        self.assertEqual(code, 2)
        self.assertEqual(target.read_text(), 'existing user archive\n')
        self.confirm_batch()
        code, out = self.run_main(export, ['x', '--javis-root', str(self.root), '--out', str(target), '--package', str(self.pkg)])
        self.assertEqual(code, 0)
        rows = [json.loads(s) for s in target.read_text(encoding='utf-8').splitlines()]
        facts = {r['fact'] for r in rows}
        self.assertIn('Javis only fact for Grok', facts)
        self.assertNotIn('friday 角色的私人设置', facts)
        self.assertTrue(all(r['owner_authorization']['proof_id'] and r['as_of'] and r['source'] == 'javis-confirmed' for r in rows))

    def test_retired_fact_is_not_reimported_or_reexported(self):
        self.enable(); self.sample()
        rows = self.rows('memory/confirmed/by-role/invest/facts.jsonl') + [
            {'tier': 'confirmed', 'fact': 'Stale rule retired by owner', 'memory_id': 'r1',
             'temporal': {'as_of': '2026-09-16T00:00:00+08:00', 'valid_to': '2026-09-20T00:00:00+08:00'}},
            {'tier': 'confirmed', 'fact': 'Retired after signing', 'memory_id': 'r2',
             'temporal': {'as_of': '2026-09-16T00:00:00+08:00'}}]
        self.confirmed('invest', rows)
        stage = self.rows('memory/imports/20260928-grok-javis-bidir/confirmed-stage/ALL-CONFIRMED-READY.jsonl')
        self.stage(stage + [{'role': 'invest', 'fact': 'Stale rule retired by owner', 'as_of': '2026-09-27T00:00:00+08:00'}])
        m = self.m.build_manifest(self.root, self.pkg)
        self.assertNotIn('Stale rule retired by owner', {x['fact'] for x in m['promote']})
        self.assertEqual([x['retired_memory_id'] for x in m['excluded']['retired_in_javis']], ['r1'])
        self.assertEqual(m['counts']['retired_in_javis'], 1)
        self.assertIn('Retired after signing', {x['fact'] for x in m['export']})
        self.confirm_batch()
        # retire r2 via the registry after the batch was signed -> export must drop it
        self.put(self.m.RETIRED_REGISTRY, self.jl([{'action': 'retire', 'memory_id': 'r2', 'fact': 'Retired after signing'}]))
        rows = self.rows('memory/confirmed/by-role/invest/facts.jsonl')
        for r in rows:
            if r.get('memory_id') == 'r2':
                r['temporal']['valid_to'] = '2026-09-20T00:00:00+08:00'
        self.confirmed('invest', rows)
        export = load_script('export-javis-confirmed-for-grok.py', 'export_retire_test')
        target = self.root / 'out.jsonl'
        code, out = self.run_main(export, ['x', '--javis-root', str(self.root), '--out', str(target), '--package', str(self.pkg)])
        self.assertEqual(code, 0)
        facts = {json.loads(s)['fact'] for s in target.read_text(encoding='utf-8').splitlines()}
        self.assertNotIn('Retired after signing', facts)
        self.assertNotIn('Stale rule retired by owner', facts)
        self.assertEqual(json.loads(out)['retired_skipped'], 1)
        # a still-valid row with the same text revives it (retired key no longer blocks)
        self.assertNotIn(self.m.norm_key('Same fact'), self.m.retired_keys(self.root))

    # --- standing policy -------------------------------------------------
    def sign_policy(self):
        p = self.m.prepare_policy(self.root, '按 9/23 规矩放开', '2026-09-28 08:44 SGT', 'Grok Star chat decision widget')
        req = {'policy_id': p['policy_id'], 'command_id': 'pol-1'}
        self.assertEqual(self.m.review_mirror_policy(self.root, self.principal, req, self.assertion)['status'], 'confirmed')
        return p

    def test_policy_authorizes_routine_packages_until_revoked_or_filters_change(self):
        self.sample()
        self.assertEqual(self.m.authorization(self.root, self.pkg), (None, None))
        self.sign_policy()
        manifest, auth = self.m.authorization(self.root, self.pkg)
        self.assertEqual(auth['mode'], 'owner_policy')
        self.assertEqual(manifest['counts']['promote'], 4)
        other = self.root / 'memory/imports/adhoc-import'
        shutil.copytree(self.pkg, other)
        self.assertEqual(self.m.authorization(self.root, other), (None, None))
        with patch.object(self.m, 'L4_RE', __import__('re').compile('weaker')):
            self.assertEqual(self.m.authorization(self.root, self.pkg), (None, None))
        self.m.revoke_policies(self.root, 'test')
        self.assertEqual(self.m.authorization(self.root, self.pkg), (None, None))


class LegacyPathFixTests(unittest.TestCase):
    def test_legacy_path_uses_package_tag_and_latest_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / 'memory/imports/20260928-grok-javis-bidir'
            (pkg / 'confirmed-stage').mkdir(parents=True)
            (pkg / 'confirmed-stage/ALL-CONFIRMED-READY.jsonl').write_text(
                json.dumps({'role': 'cards-master', 'fact': 'synthetic', 'as_of': '2026-09-28T00:00:00Z'}) + '\n'
                + json.dumps({'role': 'cards-master', 'fact': 'friday 角色', 'as_of': '2026-09-28T00:00:00Z'}) + '\n', encoding='utf-8')
            (pkg / 'watermark-after.json').write_text('{}')
            (root / 'scripts').mkdir()
            shutil.copyfile(SCRIPTS / 'memory-append.py', root / 'scripts/memory-append.py')
            out = subprocess.run([sys.executable, '-B', str(SCRIPTS / 'apply-confirmed-on-machine0.py'),
                                  '--package', str(pkg), '--javis-root', str(root)], capture_output=True, text=True,
                                 env={**os.environ, 'JAVIS_ROOT': str(root), 'PYTHONPATH': str(SCRIPTS)})
            self.assertEqual(out.returncode, 0, out.stderr + out.stdout)
            res = json.loads(out.stdout)
            self.assertEqual((res['written'], res['skipped_friday']), (1, 1))
            row = json.loads((root / 'memory/confirmed/by-role/cards-master/facts.jsonl').read_text().splitlines()[0])
            self.assertIn('bidir-20260928', row['tags'])
            self.assertEqual((root / 'state/grok-all-bots-archive/latest-import-id.txt').read_text().strip(), pkg.name)


if __name__ == '__main__':
    unittest.main(verbosity=2)
