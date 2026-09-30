"""Offline AI authority fixtures only; never import credentials or contact APIs."""
import asyncio
import copy
import json
import sys
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, AsyncMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'tools/memory-adapter'))
from test_owner_memory_review import OwnerMemoryTest
from javis_memory_adapter import review_policy as policy
from javis_memory_adapter.structured_store import StructuredFact
from javis_memory_adapter.ledger_query import query_effective, query_known, query_semantic_memory
from javis_memory_adapter.adapter import MemoryAdapter
from javis_memory_adapter.type_b import rebuild_group_from_store
from javis_memory_adapter.models import FactRecord, QueryResult, ConflictStatus
import task_memory


class AIAdapterTests(unittest.TestCase):
    def setUp(self):
        self.owner = OwnerMemoryTest(methodName='runTest')
        self.owner.setUp()
        self.addCleanup(self.owner.tearDown)
        self.root, self.store = self.owner.root, self.owner.store()
        self.log = self.root / policy.AI_REVIEW_PATH
        self.doc = {'schema': policy.AI_POLICY_SCHEMA, 'policy_version': 'ai-review-v1',
            'mode': 'automatic', 'scope': 'memory_only',
            'permitted_actions': ['accept', 'archive', 'needs_information', 'revoke']}
        self.pin = policy.digest(self.doc)
        self.pp = self.root / 'memory/ai-review/policies' / (self.pin + '.json')
        self.pp.parent.mkdir(parents=True)
        self.pp.write_text(json.dumps(self.doc), encoding='utf-8')

    def append(self, row):
        self.log.parent.mkdir(parents=True, exist_ok=True)
        with self.log.open('a', encoding='utf-8') as out:
            out.write(json.dumps(row, ensure_ascii=False) + '\n')

    def accept(self, fid='ai-one', *, save=True, valid='2026-01-01T00:00:00+00:00', **changes):
        fact = self.owner.fact(fact_id=fid, status='ai_reviewed', valid_from=valid,
            ai_review_event_id='ai-review-' + fid, confirmation_event_id=None, **changes)
        row = {'schema': policy.AI_REVIEW_SCHEMA, 'review_event_id': fact.ai_review_event_id,
            'action': 'accept', 'scope': 'cards-master', 'candidate_id': 'candidate-' + fid,
            'version_digest': 'a' * 64, 'run_id': 'run-' + fid,
            'policy_version': self.doc['policy_version'], 'policy_digest': self.pin,
            'effect': policy.semantic(fact), 'effect_digest': policy.digest(policy.semantic(fact)),
            'source_digests': policy.source_digests(self.root, [fact.source_event_id, *fact.raw_refs]),
            'decided_at': '2026-01-02T00:00:00+00:00'}
        self.append(row)
        if save:
            self.store.upsert_fact(fact)
        return fact, row

    def revoke(self, fact):
        self.append({'schema': policy.AI_REVIEW_SCHEMA, 'action': 'revoke',
            'review_event_id': 'revoke-' + fact.fact_id, 'target_review_event_id': fact.ai_review_event_id,
            'scope': 'cards-master', 'policy_version': self.doc['policy_version'],
            'policy_digest': self.pin, 'decided_at': '2026-01-03T00:00:00+00:00'})

    def test_accept_is_ai_authority_never_owner_proof(self):
        f, _ = self.accept()
        self.assertTrue(policy.ai_reviewed(self.store, f))
        self.assertFalse(policy.owner_confirmed(self.store, f))
        self.assertEqual(policy.official_facts(self.store), [])
        self.assertEqual([x.fact_id for x in policy.usable_facts(self.store)], [f.fact_id])
        self.assertIsNone(f.confirmation_event_id)

    def test_bare_flag_and_notes_cannot_authorize(self):
        f = self.owner.fact(status='ai_reviewed', ai_review_event_id='pretend', notes=['AI approved'])
        with self.assertRaises(policy.ReviewBlocked):
            self.store.upsert_fact(f)

    def test_modified_effect_or_source_invalidates(self):
        f, _ = self.accept()
        changed = copy.deepcopy(f); changed.value = 'red'
        self.assertFalse(policy.ai_reviewed(self.store, changed))
        path = next((self.root / 'raw/events').glob('*.jsonl'))
        rows = [json.loads(line) for line in path.read_text().split('\n') if line.strip()]
        rows[0]['payload']['text'] = 'changed source'
        path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n')
        self.assertFalse(policy.ai_reviewed(self.store, f))

    def test_missing_or_tampered_policy_invalidates(self):
        f, _ = self.accept()
        self.pp.write_text(json.dumps({**self.doc, 'mode': 'manual'}))
        self.assertFalse(policy.ai_reviewed(self.store, f))
        self.pp.unlink()
        self.assertEqual(policy.usable_facts(self.store), [])

    def test_pause_does_not_revoke_prior_accept_but_revoke_does(self):
        f, _ = self.accept()
        (self.root / 'memory/ai-review/control.json').write_text('{"enabled":false}')
        self.assertTrue(policy.ai_reviewed(self.store, f))
        self.revoke(f)
        self.assertFalse(policy.ai_reviewed(self.store, f))
        self.assertEqual(query_semantic_memory(self.store)['facts'], [])

    def test_duplicate_accept_id_is_not_an_unrevocation(self):
        f, row = self.accept()
        self.revoke(f); self.append(row)
        self.assertFalse(policy.ai_reviewed(self.store, f))

    def test_wrong_scope_and_bad_effect_digest_rejected(self):
        f, row = self.accept(save=False)
        for changed in ({**row, 'scope': 'invest'}, {**row, 'effect_digest': '0' * 64}):
            self.log.write_text(json.dumps(changed) + '\n')
            self.assertFalse(policy.ai_reviewed(self.store, f))

    def test_nonaccept_dispositions_never_authorize(self):
        f, row = self.accept(save=False)
        for action in ('archive', 'needs_information'):
            self.log.write_text(json.dumps({**row, 'action': action}) + '\n')
            self.assertFalse(policy.ai_reviewed(self.store, f))

    def test_unknown_validity_is_recalled_without_becoming_current(self):
        f, _ = self.accept(valid=None)
        now = datetime(2026, 3, 1, tzinfo=timezone.utc)
        self.assertEqual(query_effective(self.store, now)['facts'], [])
        result = query_semantic_memory(self.store, at_time=now)
        self.assertEqual(result['facts'][0]['validity_state'], 'unknown')
        self.assertEqual(result['facts'][0]['review_origin'], 'ai_reviewed')
        self.assertIsNone(result['facts'][0]['valid_from'])

    def test_future_and_closed_facts_not_recalled_as_ordinary(self):
        self.accept(valid='2999-01-01T00:00:00+00:00')
        self.accept('closed', valid_to='2026-01-03T00:00:00+00:00')
        self.assertEqual(query_semantic_memory(self.store, at_time=datetime(2026, 3, 1, tzinfo=timezone.utc))['facts'], [])

    def test_owner_precedence_and_original_proof_survives(self):
        self.owner.confirm()
        self.accept(value='red')
        result = query_semantic_memory(self.store)
        self.assertEqual(result['facts'][0]['value'], 'blue')
        self.assertEqual(result['facts'][0]['review_origin'], 'owner_confirmed')
        self.assertEqual(result['conflicts'], [])
        self.assertTrue(policy.owner_confirmed(self.store, self.store.get_fact('fact_one')))

    def test_conflicting_ai_values_remain_visible_as_conflict(self):
        self.accept('blue'); self.accept('red', value='red')
        result = query_semantic_memory(self.store)
        self.assertEqual(result['status'], 'conflict')
        self.assertEqual(set(result['conflicts'][0]['fact_ids']), {'blue', 'red'})

    def test_attributed_notes_from_one_source_are_complementary(self):
        self.accept('first', predicate='source_attributed_memory', value='first note')
        self.accept('second', predicate='source_attributed_memory', value='second note')
        result = query_semantic_memory(self.store)
        self.assertEqual({r['fact_id'] for r in result['facts']}, {'first', 'second'})
        self.assertEqual(result['conflicts'], [])
        now = datetime.now(timezone.utc)
        self.assertEqual(len(query_effective(self.store, now)['facts']), 2)
        adapter = MemoryAdapter(policy.official_group(self.root, 'cards-master'), meta_dir=self.store.meta_dir)
        selected, conflicts = adapter._select_structured([self.graph_record(f) for f in self.store.load_facts()])
        self.assertEqual(len(selected), 2); self.assertEqual(conflicts, [])

    def test_task_recall_contains_ai_origin_and_unknown_time(self):
        f, _ = self.accept(valid=None)
        self.owner.source('query-one', 'user color')
        task = self.root / 'workspace/tasks/task-one'; task.mkdir(parents=True)
        packet = {'task_id': 'task-one', 'role_id': 'cards-master', 'goal': 'user color',
                  'original_user_input': 'user color'}
        with patch.object(task_memory, '_graph', return_value={'status': 'ok', 'scopes': {'cards-master': {'status': 'ok', 'fact_ids': []}}}):
            result = task_memory.prepare(self.root, task, packet, 1, 'query-one')
        self.assertEqual([r['fact_id'] for r in result['read_refs']], [f.fact_id])
        self.assertEqual(result['read_refs'][0]['review_origin'], 'ai_reviewed')
        self.assertEqual(result['read_refs'][0]['retrieval_source'], 'ledger_unknown_time')
        self.assertIn('not personally confirmed', result['prompt'])

    def test_trace_and_entities_do_not_claim_owner_confirmation(self):
        f, _ = self.accept()
        adapter = MemoryAdapter(policy.official_group(self.root, 'cards-master'), meta_dir=self.store.meta_dir)
        result = asyncio.run(adapter.trace_sources(f.fact_id))
        self.assertEqual(result['retrieval_source'], 'ai_reviewed_ledger')
        self.assertEqual(asyncio.run(adapter.list_entities())[0]['review_origin'], 'ai_reviewed')
        self.revoke(f)
        self.assertFalse(asyncio.run(adapter.trace_sources(f.fact_id))['ok'])

    def graph_record(self, f):
        return FactRecord(fact_uuid=f.fact_id, fact=f'{f.subject_label} {f.predicate}={f.value}{f.unit or ""}',
            name=f.predicate, group_id=policy.official_group(self.root, 'cards-master'), valid_at=f.valid_from,
            invalid_at=f.valid_to, expired_at=None, created_at=f.recorded_at, source_event_ids=[f.source_event_id],
            object_refs=f.raw_refs, fact_id=f.fact_id, subject_id=f.subject_id, predicate=f.predicate,
            value=f.value, unit=f.unit, status=f.status, confirmation_event_id=f.confirmation_event_id,
            ai_review_event_id=f.ai_review_event_id, review_origin=policy.review_origin(f))

    def test_revoked_stale_graph_does_not_hide_unrelated_owner(self):
        self.owner.confirm(); owner = self.store.get_fact('fact_one')
        f, _ = self.accept(predicate='other')
        self.revoke(f)
        adapter = MemoryAdapter(policy.official_group(self.root, 'cards-master'), meta_dir=self.store.meta_dir)
        now = datetime.now(timezone.utc)
        result = QueryResult(as_of=now.isoformat(), mode='current',
            facts=[self.graph_record(owner), self.graph_record(f)], conflict_status=ConflictStatus.OK)
        result = adapter._check_ledger_projection(result, now)
        self.assertEqual([r.fact_id for r in result.facts], ['fact_one'])
        self.assertEqual(result.conflict_status, ConflictStatus.OK)

    def test_revoked_graph_value_cannot_leak_through_conflict(self):
        old, _ = self.accept('old', value='revoked synthetic secret')
        active, _ = self.accept('active', value='blue')
        self.revoke(old)
        adapter = MemoryAdapter(policy.official_group(self.root, 'cards-master'), meta_dir=self.store.meta_dir)
        rows = []
        for f in (old, active):
            rows.append({'uuid': f.fact_id, 'fact_id': f.fact_id,
                'fact': f'{f.subject_label} {f.predicate}={f.value}', 'name': f.predicate,
                'valid_at': f.valid_from, 'invalid_at': None, 'created_at': f.recorded_at,
                'source_event_id': f.source_event_id, 'raw_refs': f.raw_refs,
                'subject_id': f.subject_id, 'predicate': f.predicate, 'value_json': json.dumps(f.value),
                'status': 'ai_reviewed', 'ai_review_event_id': f.ai_review_event_id, 'review_origin': 'ai_reviewed'})
        with patch.object(adapter, '_load_edges', AsyncMock(return_value=rows)):
            result = asyncio.run(adapter.query_current()).to_dict()
        self.assertEqual(result['conflict_status'], 'ok')
        self.assertNotIn('revoked synthetic secret', json.dumps(result))
        self.assertEqual([r['fact_id'] for r in result['facts']], ['active'])

    def test_typeb_marks_revoked_ai_inactive_and_preserves_owner(self):
        self.owner.confirm(); f, _ = self.accept(); self.revoke(f)
        calls = []
        class Result:
            async def consume(self): pass
        class Session:
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass
            async def run(self, query, **kwargs): calls.append((query, kwargs)); return Result()
        class Driver:
            def session(self): return Session()
            async def close(self): pass
        neo4j = types.ModuleType('neo4j')
        neo4j.AsyncGraphDatabase = types.SimpleNamespace(driver=lambda *a, **k: Driver())
        with patch.dict(sys.modules, {'neo4j': neo4j}):
            report = asyncio.run(rebuild_group_from_store(store=self.store,
                target_group_id=policy.official_group(self.root, 'cards-master'),
                neo4j_uri='synthetic', neo4j_user='synthetic', neo4j_password='synthetic'))
        self.assertEqual(report['written'], ['fact_one'])
        prune = [kw for q, kw in calls if 'ai_review_active = false' in q]
        self.assertEqual(prune[0]['active_ai_reviews'], [])
        projected = [kw for q, kw in calls if 'fact_text' in kw]
        self.assertEqual(projected[0]['review_origin'], 'owner_confirmed')

    def test_batch_reuses_one_index_and_returns_detached_rows(self):
        f, _ = self.accept()
        with patch.object(policy, '_read_raw_snapshot', wraps=policy._read_raw_snapshot) as read:
            with policy.batch_source_snapshot(self.root):
                for _ in range(3):
                    rows = policy.source_rows(self.root, ['input-one'])
                    rows['input-one']['payload']['text'] = 'caller mutation'
                    self.assertTrue(policy.ai_reviewed(self.store, f))
                self.assertEqual(read.call_count, 1)
            self.assertNotEqual(policy.source_rows(self.root, ['input-one'])['input-one']['payload']['text'], 'caller mutation')
            self.assertEqual(read.call_count, 2)

    def test_batch_detects_change_during_and_after_access(self):
        with self.assertRaisesRegex(policy.ReviewBlocked, 'raw_snapshot_changed'):
            with policy.batch_source_snapshot(self.root):
                self.owner.source('another-source', 'new input')
                policy.source_rows(self.root, ['input-one'])
        # A failed batch never leaks its cache to the next request.
        self.assertIn('another-source', policy.source_rows(self.root, ['another-source']))

    def test_batch_rechecks_corpus_on_every_access(self):
        path = self.root / 'raw/events/corpus-fixture.jsonl'
        path.write_text(json.dumps({'event_id': 'corpus', 'event_type': 'corpus_text', 'payload': {}})+'\n')
        module = types.ModuleType('memory_corpus'); module.verify_canonical = lambda *a: None
        with patch.dict(sys.modules, {'memory_corpus': module}), patch.object(module, 'verify_canonical') as verify:
            with policy.batch_source_snapshot(self.root):
                policy.source_rows(self.root, ['corpus'])
                policy.source_rows(self.root, ['corpus'])
            self.assertEqual(verify.call_count, 2)

    def test_usable_facts_scans_raw_once_for_multiple_ai_facts(self):
        self.accept('a'); self.accept('b', predicate='second')
        with patch.object(policy, '_read_raw_snapshot', wraps=policy._read_raw_snapshot) as read:
            self.assertEqual(len(policy.usable_facts(self.store)), 2)
            self.assertEqual(read.call_count, 1)

    def test_hardlinked_policy_and_raw_rejected(self):
        import os
        f, _ = self.accept()
        os.link(self.pp, self.pp.with_suffix('.copy'))
        self.assertFalse(policy.ai_reviewed(self.store, f))
        self.pp.with_suffix('.copy').unlink()
        raw = next((self.root / 'raw/events').glob('*.jsonl'))
        os.link(raw, raw.with_suffix('.copy'))
        self.assertFalse(policy.ai_reviewed(self.store, f))


if __name__ == '__main__':
    unittest.main()
