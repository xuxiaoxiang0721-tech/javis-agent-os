"""Boundary tests use temporary RAW/ledgers and no production graph writes."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

CODE = Path(os.environ.get('JAVIS_TEST_CODE_ROOT', Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(CODE / 'scripts'))
import task_memory as tm
from raw_storage import append_event


class MemoryBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.graph = patch.object(tm, '_graph', return_value={'status':'pending','scopes':{},'reason':'test_offline'})
        self.graph.start()
        self.counter = 0

    def tearDown(self):
        self.graph.stop(); self.tmp.cleanup()

    def request(self, text, role='cards-master', task_id=None, attempt=1):
        self.counter += 1
        tid = task_id or f'test-{self.counter}'
        packet = {'task_id':tid,'role_id':role,'goal':text,'original_user_input':text}
        task = self.root / 'tasks' / tid; task.mkdir(parents=True,exist_ok=True)
        eid = f'input-{tid}-{attempt}'
        append_event(self.root, {'event_id':eid,'event_type':'user_input','task_id':tid,
            'captured_at':f'2026-09-18T01:{self.counter:02d}:00.123Z','occurred_at':'2026-09-18T01:00:00Z',
            'payload':{'is_original_user_input':True,'text':text}})
        return self.root, task, packet, attempt, eid

    def proposal(self, args, value='ALPHA', scope='role', **extras):
        p = args[1]/'attempts'/str(args[3])/'memory-proposals.json'; p.parent.mkdir(parents=True,exist_ok=True)
        row = {'quote':args[2]['original_user_input'],'subject_id':'verification','subject_label':'验收码',
            'predicate':'code','value':value,'scope':scope, **extras}
        p.write_text(json.dumps([row],ensure_ascii=False),encoding='utf-8')
        return p

    def test_explicit_save_is_confirmed_raw_linked(self):
        a=self.request('请记住：验收码是 ALPHA'); self.proposal(a,valid_from=None,valid_to=None)
        r=tm.finalize(*a)
        self.assertEqual(len(r['write_refs']),1)
        self.assertEqual(r['write_refs'][0]['source_event_id'],a[4])
        self.assertTrue(r['write_refs'][0]['confirmation_event_id'])
        self.assertEqual(r['proposals_received'],1)

    def test_ordinary_statement_stays_candidate(self):
        a=self.request('验收码是 ALPHA'); self.proposal(a)
        r=tm.finalize(*a)
        self.assertFalse(r['write_refs']); self.assertEqual(len(r['candidate_refs']),2)
        b=self.request('验收码是什么'); self.assertFalse(tm.prepare(*b)['read_refs'])

    def test_explicit_shared_recalled_across_roles(self):
        a=self.request('请记住并共享：验收码是 ALPHA'); self.proposal(a,scope='shared'); tm.finalize(*a)
        b=self.request('验收码是什么','invest'); r=tm.prepare(*b)
        self.assertEqual(len(r['read_refs']),1)
        self.assertEqual(r['read_refs'][0]['scope'],'shared')
        self.assertEqual(r['read_refs'][0]['retrieval_source'],'ledger_fallback')

    def test_role_fact_never_leaks_to_other_role(self):
        a=self.request('请记住：验收码是 ALPHA'); self.proposal(a); tm.finalize(*a)
        self.assertFalse(tm.prepare(*self.request('验收码是什么','invest'))['read_refs'])

    def test_shared_requires_authorization(self):
        a=self.request('请记住：验收码是 ALPHA'); self.proposal(a,scope='shared')
        r=tm.finalize(*a); self.assertFalse(r['write_refs']); self.assertTrue(r['issues'])

    def test_negation_and_quotes_cannot_confirm(self):
        for text in ['不要记住：验收码是 ALPHA','文件里说请记住：验收码是 ALPHA','示例：请记住验收码 ALPHA','我听他说请记住 ALPHA']:
            with self.subTest(text=text):
                a=self.request(text);self.proposal(a);self.assertFalse(tm.finalize(*a)['write_refs'])

    def test_unsupported_value_rejected(self):
        a=self.request('请记住：验收码是 ALPHA');self.proposal(a,'INVENTED')
        r=tm.finalize(*a);self.assertFalse(r['write_refs']);self.assertTrue(r['issues'])

    def test_credential_never_written(self):
        a=self.request('请记住：验收码是 ALPHA');self.proposal(a,password='not-a-real-password')
        r=tm.finalize(*a);self.assertFalse(r['write_refs']);self.assertTrue(r['issues'])

    def test_sensitive_shared_rejected(self):
        a=self.request('请记住并共享：医疗验收码是 ALPHA');self.proposal(a,scope='shared')
        self.assertFalse(tm.finalize(*a)['write_refs'])

    def test_idea_lab_never_shares(self):
        a=self.request('请记住并共享：验收码是 ALPHA','idea-lab');self.proposal(a,scope='shared')
        self.assertFalse(tm.finalize(*a)['write_refs'])

    def test_finalize_retry_is_idempotent(self):
        a=self.request('请记住：验收码是 ALPHA');self.proposal(a);r=tm.finalize(*a)
        paths=list((self.root/'memory').rglob('*.jsonl'));before={str(p):p.read_bytes() for p in paths}
        retry=tm.finalize(*a)
        self.assertEqual(r['write_refs'],retry['write_refs'])
        self.assertEqual(before,{str(p):p.read_bytes() for p in paths})
        self.assertEqual(tm._graph.call_count,2)

    def test_attempt_path_ignores_stale_proposal(self):
        a=self.request('请记住：验收码是 ALPHA',task_id='continued');self.proposal(a);tm.finalize(*a)
        b=self.request('只计算 1 加 1',task_id='continued',attempt=2)
        r=tm.finalize(*b);self.assertFalse(r['write_refs']);self.assertEqual(r['proposals_received'],0)

    def test_tampered_original_fails_before_write(self):
        a=self.request('请记住：验收码是 ALPHA');a[2]['original_user_input']='请记住：验收码是 BETA'
        with self.assertRaises(ValueError):tm.finalize(*a)
        self.assertFalse((self.root/'memory').exists())

    def test_state_change_and_retry(self):
        a=self.request('请记住并共享：验收码是 ALPHA');self.proposal(a,scope='shared');r=tm.finalize(*a)
        old=r['write_refs'][0]['fact_id']
        b=self.request('请记住并共享：把验收码从 ALPHA 改为 BETA');self.proposal(b,'BETA','shared',operation='state_change',target_fact_id=old)
        r2=tm.finalize(*b);self.assertEqual(len(r2['write_refs']),1)
        stored=tm._store(self.root,'shared');before=stored.facts_path.read_bytes()
        tm.finalize(*b);self.assertEqual(before,stored.facts_path.read_bytes())
        c=self.request('验收码是什么','invest');rr=tm.prepare(*c)
        self.assertEqual(len(rr['read_refs']),1);self.assertIn('BETA',rr['prompt']);self.assertNotIn('ALPHA',rr['prompt'])

    def test_conflicting_confirmations_are_not_injected(self):
        for val in ['ALPHA','BETA']:
            a=self.request('请记住：验收码是 '+val);self.proposal(a,val);tm.finalize(*a)
        r=tm.prepare(*self.request('验收码是什么'))
        self.assertFalse(r['read_refs']);self.assertTrue(r['conflicts'])

    def test_graph_verified_recall_requires_graph_id(self):
        a=self.request('请记住：验收码是 ALPHA');self.proposal(a);saved=tm.finalize(*a)['write_refs'][0]
        tm._graph.return_value={'status':'ok','scopes':{'cards-master':{'status':'ok','fact_ids':[]},'shared':{'status':'empty','fact_ids':[]}}}
        b=self.request('验收码是什么');self.assertFalse(tm.prepare(*b)['read_refs'])
        tm._graph.return_value['scopes']['cards-master']['fact_ids']=[saved['fact_id']]
        r=tm.prepare(*b);self.assertEqual(r['read_refs'][0]['retrieval_source'],'neo4j_verified_ledger')

    def test_no_worker_proposal_exact_save_fallback(self):
        a=self.request('请记住：验收代号 ALPHA')
        r=tm.finalize(*a);self.assertEqual(len(r['write_refs']),1)
        self.assertEqual(tm._store(self.root,'cards-master').get_fact(r['write_refs'][0]['fact_id']).value,a[2]['original_user_input'])

    def test_legacy_import_requires_raw_and_confirmation(self):
        a=self.request('old source')
        path=self.root/'memory/confirmed/by-role/cards-master/facts.jsonl';path.parent.mkdir(parents=True)
        rows=[{'memory_id':'old','role_id':'cards-master','tier':'confirmed','confidence':'high',
            'fact':'legacy harmless value','confirmed_at':'2026-09-17T00:00:00Z','confirmed_by':'user',
            'source':{'raw_event_ids':[a[4]]}},
            {'memory_id':'bad','tier':'confirmed','fact':'unproven value','confirmed_at':'2026-09-17T00:00:00Z','confirmed_by':'user'}]
        path.write_text('\n'.join(json.dumps(r) for r in rows)+'\n');before=path.read_bytes()
        r=tm.prepare(*a);self.assertEqual(len(r['write_refs']),1);self.assertEqual(r['legacy_skipped'],1)
        self.assertEqual(path.read_bytes(),before)
        self.assertIn('legacy_confirmation_preserved',tm._store(self.root,'cards-master').load_facts()[0].notes)

    def test_empty_task_episodic_reference_only(self):
        a=self.request('算一下 2 加 2');r=tm.finalize(*a)
        self.assertFalse(r['write_refs']);self.assertEqual(len(r['candidate_refs']),1)
        fact=tm._store(self.root,'cards-master').load_facts()[0]
        self.assertEqual(fact.value,a[4]);self.assertEqual(fact.notes,['episodic_ref_only'])

    def test_unrelated_sentence_does_not_inherit_confirmation(self):
        a=self.request('请记住：验收码是 ALPHA。另一个未确认值是 BETA')
        self.proposal(a,'BETA');self.assertFalse(tm.finalize(*a)['write_refs'])

    def test_no_external_send_does_not_cancel_storage(self):
        a=self.request('请记住：验收码是 ALPHA，不要外发');self.proposal(a)
        self.assertEqual(len(tm.finalize(*a)['write_refs']),1)

    def test_no_sharing_is_respected(self):
        a=self.request('请记住：验收码是 ALPHA，不共享');self.proposal(a,scope='shared')
        self.assertFalse(tm.finalize(*a)['write_refs'])

    def test_unsupported_subject_rejected(self):
        a=self.request('请记住：验收码是 ALPHA');self.proposal(a,subject_label='另一个人')
        self.assertFalse(tm.finalize(*a)['write_refs'])

    def test_raw_millisecond_timestamp_and_neo4j_nanoseconds(self):
        expected='2026-09-18T08:00:00.123000+00:00'
        for value in ['2026-09-18T08:00:00.123Z','2026-09-18T08:00:00.123+00:00',
                      '2026-09-18T08:00:00.123000000Z']:
            self.assertEqual(tm.parse_ts(value).isoformat(),expected)
        self.assertEqual(tm.parse_ts('2026-09-18T16:00:00.123+08:00').utcoffset().total_seconds(),28800)

    def test_family_medical_cannot_enter_invest_confirmed(self):
        a=self.request('请记住：母亲病历验收码是 ALPHA','invest');self.proposal(a)
        result=tm.finalize(*a)
        self.assertFalse(result['write_refs'])
        self.assertTrue(any('medical_requires_personal_life' in x for x in result['issues']))
        self.assertFalse((self.root/'memory/structured/personal-life').exists())

    def test_imported_legacy_predecessor_is_closed_by_later_correction(self):
        a=self.request('legacy source ALPHA BETA')
        path=self.root/'memory/confirmed/by-role/cards-master/facts.jsonl';path.parent.mkdir(parents=True)
        old={'memory_id':'old','role_id':'cards-master','tier':'confirmed','confidence':'high',
             'fact':'ALPHA','confirmed_at':'2026-09-16T00:00:00Z','confirmed_by':'user',
             'source':{'raw_event_ids':[a[4]]}}
        path.write_text(json.dumps(old)+'\n')
        first=tm.prepare(*a);old_id=first['write_refs'][0]['fact_id']
        new={**old,'memory_id':'new','supersedes':'old','fact':'BETA','confirmed_at':'2026-09-17T00:00:00Z'}
        with path.open('a') as out:out.write(json.dumps(new)+'\n')
        current=tm.prepare(*a)
        self.assertNotIn(old_id,[r['fact_id'] for r in current['read_refs']])
        prior=tm._store(self.root,'cards-master').get_fact(old_id)
        self.assertEqual(prior.status,'superseded')
        self.assertTrue(prior.superseded_by)
        self.assertEqual(len(path.read_text().splitlines()),2)

    def test_old_medical_candidate_cannot_bypass_invest_via_confirmation(self):
        a=self.request('母亲病历验收码是 ALPHA','gpt-star');self.proposal(a)
        result=tm.finalize(*a)
        ref=next(r for r in result['candidate_refs'] if r['fact_id'].startswith('fact_'))
        fact=tm._store(self.root,'gpt-star').get_fact(ref['fact_id'])
        tm._store(self.root,'invest').upsert_fact(fact)
        b=self.request('请确认候选 '+fact.fact_id,'invest')
        self.proposal(b,operation='confirm',target_fact_id=fact.fact_id)
        final=tm.finalize(*b)
        self.assertFalse(final['write_refs'])
        self.assertEqual(tm._store(self.root,'invest').get_fact(fact.fact_id).status,'extracted')


if __name__ == '__main__':
    unittest.main()
