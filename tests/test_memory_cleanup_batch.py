"""One-signature cleanup batch tests (Javis260928 追加三). Fake owner proofs exist only in TemporaryDirectory roots."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'tools/memory-adapter'))
import test_owner_memory_review as owner_tests  # noqa: E402  (module import: do not re-collect its tests)
import test_memory_triage as triage_tests  # noqa: E402
from javis_memory_adapter.review_policy import ReviewBlocked, digest, source_digests  # noqa: E402
import memory_triage as triage  # noqa: E402
import memory_cleanup_batch as cleanup  # noqa: E402
from memory_attention import snapshot  # noqa: E402

LEGACY_FACT = 'Synthetic retired legacy text about a synthetic account.'


class CleanupBatchTests(unittest.TestCase):
    def setUp(self):
        self.o = owner_tests.OwnerMemoryTest('test_candidate_is_isolated_and_idempotent')
        self.o.setUp()
        self.addCleanup(self.o.tearDown)
        self.root, self.principal, self.assertion = self.o.root, self.o.principal, self.o.assertion
        self.proofs, self.review, self.candidate = self.o.proofs, self.o.review, self.o.candidate
        self.request, self.source = self.o.request, self.o.source
        self.source('input-two', 'synthetic task log')
        text_hash = source_digests(self.root, {'input-two'})['input-two']
        self.tbinding = dict(event_id='input-two', scope='cards-master', source_digest=text_hash,
                             run_id='synthetic_run', policy_version='jev-typed-v2',
                             policy_digest=digest('synthetic-policy-v2'), stage='screening',
                             reason_code='screen_needs_evidence', content_digest=digest('synthetic task log'))
        self.item = triage.record_pending(self.root, **self.tbinding)
        self.legacy_path = self.root / 'memory/candidates/by-role/gpt-star/facts.jsonl'
        self.legacy_path.parent.mkdir(parents=True)
        self.legacy_path.write_text(json.dumps({'schema_version': 'javis-memory-2', 'memory_id': 'm-pending-synthetic',
            'tier': 'candidate', 'role_id': 'gpt-star', 'fact': LEGACY_FACT,
            'memory_status': 'pending_evidence_and_owner_review'}, ensure_ascii=False) + '\n', encoding='utf-8')
        self.spec = {'title': 'synthetic cleanup', 'basis': 'synthetic owner request',
                     'quarantine': [{'scope': 'cards-master', 'candidate_id': self.candidate['candidate_id'],
                                     'version_digest': self.candidate['version_digest'], 'category': 'task_mechanics'}],
                     'triage': [{'triage_id': self.item['triage_id'], 'task_id': 'task-one'}],
                     'legacy': [{'role': 'gpt-star', 'memory_id': 'm-pending-synthetic'}],
                     'excluded': [{'id': 'candidate_keep', 'short': 'genuine owner fact kept pending'}]}

    def files(self):
        return {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file() and 'locks' not in p.parts}

    def cq(self, **kw):
        return {'cleanup_batch_id': self.bid, 'command_id': 'cleanup-cmd-1', 'action': 'archive_cleanup_batch', **kw}

    def prepare(self):
        out = cleanup.prepare(self.root, self.spec)
        self.bid = out['batch_id']
        return out

    def sign(self, **kw):
        req = self.cq(**kw)
        cleanup.binding_for(self.root, self.principal, req)
        return cleanup.review(self.root, self.principal, req, self.assertion)

    def test_prepare_is_write_once_pending_and_changes_no_memory(self):
        before = self.files()
        out = self.prepare()
        self.assertEqual((out['status'], out['quarantine'], out['triage'], out['legacy'], out['total']),
                         ('pending_owner_review', 1, 1, 1, 3))
        self.assertTrue(out['batch_id'].startswith('cleanup_'))
        after = self.files()
        added = set(after) - set(before)
        self.assertEqual(len(added), 1)
        self.assertIn('cleanup-batches', next(iter(added)))
        self.assertEqual({k: v for k, v in after.items() if k in before}, before)
        self.assertEqual(self.prepare()['batch_id'], out['batch_id'])  # idempotent write-once
        self.assertEqual(len(self.review.list_pending(self.principal)), 1)
        self.assertEqual(triage.list_pending(self.root)['total'], 1)
        listed = cleanup.list_batches(self.root, self.principal)
        self.assertEqual([b['status'] for b in listed], ['pending_owner_review'])
        self.assertEqual(cleanup.archived(self.root)['triage'], {})

    def test_signed_archive_rejects_archives_and_never_confirms(self):
        self.prepare()
        quarantine = self.root / 'memory/quarantine/cards-master/candidates.jsonl'
        q_lines = len(quarantine.read_text().splitlines())
        result = self.sign()
        self.assertEqual(result['status'], 'archived')
        self.assertEqual((result['applied']['quarantine_rejected'], result['applied']['legacy_rejected'],
                          result['applied']['triage_archived']), (1, 1, 1))
        rows = [json.loads(x) for x in quarantine.read_text().splitlines()]
        self.assertEqual(len(rows), q_lines + 1)
        self.assertEqual([r['status'] for r in rows], ['pending_review', 'rejected'])
        self.assertEqual(rows[-1]['owner_batch_id'], self.bid)
        self.assertFalse((self.root / 'memory/structured').exists())
        self.assertFalse((self.root / 'memory/confirmed').exists())
        self.assertEqual(self.review.list_pending(self.principal), [])
        with self.assertRaises(ReviewBlocked):
            self.review.binding_for(self.principal, self.request('confirm'))
        self.assertEqual(triage.get_pending(self.root, self.item['triage_id'])['status'], 'archived')
        self.assertEqual(triage.list_pending(self.root)['total'], 0)
        self.assertEqual(len(list((self.root / 'memory/triage/items').glob('*.json'))), 1)
        snap = snapshot(self.root)
        self.assertEqual((snap['candidates'], snap['triage_items'], snap['invalid_records']), (0, 0, 0))
        legacy = [json.loads(x) for x in self.legacy_path.read_text(encoding='utf-8').splitlines()]
        self.assertEqual([r['memory_status'] for r in legacy], ['pending_evidence_and_owner_review', 'rejected_by_owner_batch'])
        self.assertEqual(legacy[0]['fact'], LEGACY_FACT)
        self.assertNotIn('fact', legacy[1])
        decision = json.loads((self.root / cleanup.DECISIONS).read_text())
        self.assertNotIn(self.assertion, json.dumps(decision))
        self.assertEqual(cleanup.list_batches(self.root, self.principal)[0]['status'], 'archived')

    def test_replay_is_idempotent_and_batch_cannot_be_decided_twice(self):
        self.prepare()
        self.sign()
        snapshot_files = self.files()
        again = self.sign()
        self.assertTrue(again['replayed'])
        self.assertEqual(self.files(), snapshot_files)
        with self.assertRaises(ReviewBlocked):
            self.sign(command_id='cleanup-cmd-2')
        with self.assertRaises(ReviewBlocked):
            cleanup.review(self.root, self.principal, self.cq(action='decline_cleanup_batch'), self.assertion)

    def test_bad_assertion_unauthenticated_or_tampered_manifest_rejected(self):
        self.prepare()
        before = self.files()
        with self.assertRaises(ReviewBlocked):
            cleanup.review(self.root, self.principal, self.cq(), 'WRONG')
        with self.assertRaises(Exception):
            cleanup.review(self.root, object(), self.cq(), self.assertion)
        self.assertEqual(self.files(), before)
        path = self.root / cleanup.BATCH_DIR / (self.bid + '.json')
        doc = json.loads(path.read_text())
        doc['triage'] = []
        path.write_text(json.dumps(doc))
        with self.assertRaises(ReviewBlocked):
            cleanup.binding_for(self.root, self.principal, self.cq())

    def test_unverifiable_decision_fails_closed_back_to_pending(self):
        self.prepare()
        self.sign()
        self.proofs.clear()
        self.assertEqual(cleanup.archived(self.root)['triage'], {})
        self.assertEqual(triage.get_pending(self.root, self.item['triage_id'])['status'], 'needs_review')
        self.assertEqual(triage.list_pending(self.root)['total'], 1)

    def test_decline_changes_nothing_but_the_decision(self):
        self.prepare()
        before = self.files()
        result = self.sign(action='decline_cleanup_batch')
        self.assertEqual(result['status'], 'declined')
        changed = {k for k in set(self.files()) | set(before) if self.files().get(k) != before.get(k)}
        self.assertEqual(changed, {str(self.root / cleanup.DECISIONS)})
        self.assertEqual(len(self.review.list_pending(self.principal)), 1)
        self.assertEqual(triage.list_pending(self.root)['total'], 1)

    def test_non_pending_items_cannot_be_prepared(self):
        self.review.review(self.principal, self.request('reject'), self.assertion)
        with self.assertRaises(ReviewBlocked):
            cleanup.prepare(self.root, self.spec)
        spec = dict(self.spec, quarantine=[], triage=['triage_' + 'a' * 64])
        with self.assertRaises(ReviewBlocked):
            cleanup.prepare(self.root, spec)

    def test_rejected_run_candidate_keeps_old_triage_superseded_only_with_verified_batch(self):
        old = self.item
        helper = triage_tests.TriageTests('test_idempotent_immutable_reference_only_record')
        text_hash = source_digests(self.root, {'input-one'})['input-one']
        helper.root = self.root
        helper.binding = dict(self.tbinding, event_id='input-one', source_digest=text_hash, content_digest=digest('remember blue'))
        old = triage.record_pending(self.root, **helper.binding)
        run = helper.current_run()
        run.update(outcome='pending_review', candidates=[self.candidate])
        helper.save_run(run)
        self.assertEqual(triage.get_pending(self.root, old['triage_id'])['status'], 'superseded')
        self.spec['triage'] = [{'triage_id': self.item['triage_id']}]
        self.prepare()
        self.sign()
        view = triage.list_pending(self.root, include_superseded=True)
        self.assertEqual(view['invalid_run_records'], 0)
        self.assertEqual(triage.get_pending(self.root, old['triage_id'])['status'], 'superseded')
        self.proofs.clear()
        self.assertGreater(triage.list_pending(self.root)['invalid_run_records'], 0)
        self.assertGreater(snapshot(self.root)['invalid_records'], 0)


if __name__ == '__main__':
    unittest.main()
