"""Real Neo4j integration tests, isolated groups and synthetic memory only."""
import asyncio, json, os, subprocess, sys, tempfile, unittest, uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
STAGE=Path(__file__).parent
CODE=Path(os.environ.get('JAVIS_MEMORY_TEST_CODE',STAGE))
sys.path.insert(0,str(CODE)); sys.dont_write_bytecode=True
from javis_memory_adapter.structured_store import StructuredStore, StructuredFact, stable_fact_id
from javis_memory_adapter.ledger_query import apply_historical_correction, apply_state_change, query_known, query_effective
from javis_memory_adapter.type_b import rebuild_group_from_store
from javis_memory_adapter.adapter import MemoryAdapter, _load_dotenv
from neo4j import GraphDatabase
_load_dotenv(Path.home()/'javis/tools/graphiti/.env')
KW={k:os.environ[e] for k,e in [('neo4j_uri','NEO4J_URI'),('neo4j_user','NEO4J_USER'),('neo4j_password','NEO4J_PASSWORD')]}
def dt(s): return datetime.fromisoformat(s.replace('Z','+00:00'))
JAN='2026-01-01T00:00:00Z'; FEB='2026-02-01T00:00:00Z'; MAR='2026-03-01T00:00:00Z'

class MemoryChain(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='javis-memory-chain-'); self.meta=Path(self.tmp.name)
        self.store=StructuredStore(self.meta); self.group='javis_memcheck_'+uuid.uuid4().hex
        self.d=GraphDatabase.driver(KW['neo4j_uri'],auth=(KW['neo4j_user'],KW['neo4j_password']))
    def tearDown(self):
        assert self.group.startswith('javis_memcheck_')
        self.d.execute_query('MATCH (n {group_id:$g}) DETACH DELETE n',g=self.group)
        self.d.close(); self.tmp.cleanup()
    def seed(self,value=100,event='source-original',valid=JAN,status='confirmed'):
        fid=stable_fact_id(subject_id='stock',predicate='quantity',value=value,unit='pcs',valid_from=valid,source_event_id=event)
        f=StructuredFact(fact_id=fid,subject_id='stock',subject_label='测试库存',predicate='quantity',value=value,unit='pcs',
            valid_from=valid,valid_to=None,recorded_at=JAN,source_event_id=event,raw_refs=['sha256:synthetic-source'],status=status,
            confirmation_event_id='confirm-'+event if status=='confirmed' else None)
        with patch('javis_memory_adapter.structured_store._now',return_value=JAN): self.store.upsert_fact(f)
        return f
    def rebuild(self):
        r=asyncio.run(rebuild_group_from_store(store=self.store,target_group_id=self.group,**KW)); self.assertEqual(r['errors'],[])
    def query(self,at=MAR):
        async def go():
            a=MemoryAdapter(self.group,meta_dir=self.meta)
            try: return (await a.query_as_of(dt(at))).to_dict()
            finally: await a.close()
        return asyncio.run(go())
    def trace(self,fid):
        async def go():
            a=MemoryAdapter(self.group,meta_dir=self.meta)
            try: return await a.trace_sources(fid)
            finally: await a.close()
        return asyncio.run(go())
    def correct(self):
        with patch('javis_memory_adapter.structured_store._now',return_value=FEB):
            return apply_historical_correction(self.store,subject_id='stock',subject_label='测试库存',predicate='quantity',
                wrong_value=100,correct_value=90,unit='pcs',about_event_time=dt(JAN),source_event_id='source-correction',
                raw_refs=['sha256:synthetic-correction'],confirmation_event_id='confirm-correction')
    def test_graph_query_preserves_sources(self):
        f=self.seed(); self.rebuild(); q=self.query()
        self.assertEqual(q['facts'][0]['source_event_ids'],['source-original'])
        self.assertEqual(q['facts'][0]['object_refs'],['sha256:synthetic-source'])
        self.assertEqual(q['facts'][0]['fact_id'],f.fact_id)
    def test_historical_correction_excludes_wrong_value(self):
        self.seed(); self.correct(); self.rebuild(); q=self.query(JAN)
        self.assertEqual(len(q['facts']),1,q)
        self.assertEqual(q['facts'][0]['value'],90)
        self.assertEqual(q['facts'][0]['source_event_ids'],['source-correction'])
        self.assertEqual(query_known(self.store,dt('2026-01-15T00:00:00Z'))['facts'][0]['value'],100)
    def test_trace_stable_id_after_rebuild(self):
        old=self.seed(); c=self.correct(); self.rebuild()
        traced=self.trace(c['new_fact']['fact_id'])
        self.assertTrue(traced['ok'],traced)
        self.assertIn('source-correction',traced['source_event_ids'])
        self.assertTrue(traced['corrections_ledger'])
        historical=self.trace(old.fact_id); self.assertTrue(historical['ok'])
        self.assertEqual(historical['fact']['status'],'superseded')
    def test_state_change_preserves_past_interval(self):
        self.seed()
        with patch('javis_memory_adapter.structured_store._now',return_value=FEB):
            apply_state_change(self.store,subject_id='stock',subject_label='测试库存',predicate='quantity',old_value=100,new_value=120,
                unit='pcs',change_at=dt(FEB),source_event_id='source-change',raw_refs=['raw:change'],confirmation_event_id='c-change')
        self.rebuild()
        self.assertEqual([f['value'] for f in self.query(JAN)['facts']],[100])
        self.assertEqual([f['value'] for f in self.query(FEB)['facts']],[120])
    def test_fresh_process_query_and_trace(self):
        self.seed(); correction=self.correct(); self.rebuild()
        env={**os.environ,'PYTHONPATH':str(CODE),'PYTHONDONTWRITEBYTECODE':'1'}
        p=subprocess.run([sys.executable,'-m','javis_memory_adapter','--group-id',self.group,'--meta-dir',str(self.meta),
            'query-as-of','--as-of',MAR],env=env,capture_output=True,text=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stderr); q=json.loads(p.stdout)
        self.assertEqual(q['facts'][0]['source_event_ids'],['source-correction'])
        p=subprocess.run([sys.executable,'-m','javis_memory_adapter','--group-id',self.group,'--meta-dir',str(self.meta),
            'trace','--fact-uuid',correction['new_fact']['fact_id']],env=env,capture_output=True,text=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stderr); traced=json.loads(p.stdout)
        self.assertTrue(traced['ok'],traced)
        self.assertTrue(traced['corrections_ledger'],traced)
        self.assertEqual(traced['object_refs'],['sha256:synthetic-correction'])
    def test_missing_graph_is_pending_until_rebuilt(self):
        self.seed(); q=self.query()
        self.assertEqual(q['conflict_status'],'pending',q)
        self.assertTrue(any(c['reason']=='graph_ledger_mismatch' for c in q['conflicts']))
        self.rebuild(); self.assertEqual(self.query()['conflict_status'],'ok')
    def test_stale_graph_after_correction_is_pending(self):
        self.seed(); self.rebuild(); self.correct(); q=self.query()
        self.assertEqual(q['conflict_status'],'pending',q)
        self.assertEqual(q['facts'][0]['conflict_status'],'pending')
        self.rebuild(); self.assertEqual(self.query()['conflict_status'],'ok')
    def test_conflict_added_to_ledger_requires_graph_sync(self):
        self.seed(100,'source-a'); self.rebuild(); self.seed(200,'source-b')
        self.assertEqual(self.query()['conflict_status'],'pending')
        self.rebuild(); self.assertEqual(self.query()['conflict_status'],'conflict')
    def test_same_value_keeps_both_sources_without_conflict(self):
        self.seed(100,'source-a'); self.seed(100,'source-b'); self.rebuild(); q=self.query()
        self.assertEqual(q['conflict_status'],'ok',q)
        self.assertEqual({s for f in q['facts'] for s in f['source_event_ids']},{'source-a','source-b'})
    def test_numeric_string_compatibility_matches_ledger(self):
        self.seed(100,'source-a'); self.seed('100','source-b'); self.rebuild()
        self.assertEqual(query_effective(self.store,dt(MAR))['status'],'ok')
        self.assertEqual(self.query()['conflict_status'],'ok')
    def test_deleted_graph_rebuilt_twice_without_duplicates(self):
        self.seed(); self.correct(); self.rebuild()
        self.d.execute_query('MATCH (n {group_id:$g}) DETACH DELETE n',g=self.group)
        self.assertEqual(self.query()['conflict_status'],'pending')
        self.rebuild(); self.rebuild(); q=self.query()
        self.assertEqual(q['conflict_status'],'ok',q)
        self.assertEqual([f['value'] for f in q['facts']],[90])
        rows,_,_=self.d.execute_query('MATCH ()-[r:RELATES_TO {group_id:$g}]->() RETURN count(r) AS n',g=self.group)
        self.assertEqual(rows[0]['n'],2)
    def test_confirmation_during_rebuild_does_not_get_overwritten(self):
        f=self.seed(status='extracted'); mark=self.store.mark_graph_synced
        def confirm_then_mark(snapshot):
            self.store.write_confirmation(fact_id=f.fact_id,confirmation_event_id='concurrent-confirm',confirmed_at=FEB,actor='synthetic-test')
            return mark(snapshot)
        with patch.object(self.store,'mark_graph_synced',side_effect=confirm_then_mark):
            report=asyncio.run(rebuild_group_from_store(store=self.store,target_group_id=self.group,**KW))
        self.assertTrue(report['errors'],report)
        self.assertIn('ledger_changed_during_rebuild',report['errors'][0]['error'])
        latest=self.store.load_facts()[0]
        self.assertEqual(latest.status,'confirmed')
        self.assertEqual(latest.graph_sync_status,'pending_sync')
        self.assertEqual(self.query()['conflict_status'],'pending')
        self.rebuild(); self.assertEqual(self.query()['conflict_status'],'ok')
    def test_generic_conflict_is_visible(self):
        self.seed(100,'source-a'); self.seed(200,'source-b'); self.rebuild(); q=self.query()
        self.assertEqual(q['conflict_status'],'conflict',q)
        self.assertEqual(len(q['facts']),2)
    def test_confirmed_preferred_over_candidate(self):
        self.seed(100,'source-a'); self.seed(200,'source-b',status='extracted'); self.rebuild(); q=self.query()
        self.assertEqual([x['value'] for x in q['facts']],[100]); self.assertEqual(q['conflict_status'],'ok')
    def test_rebuild_without_llm_credentials(self):
        f=self.seed(); self.rebuild()
        empty=self.meta/'db-only.env'; empty.write_text('\n'.join(f'{k}={os.environ[k]}' for k in ['NEO4J_URI','NEO4J_USER','NEO4J_PASSWORD']))
        async def go():
            a=MemoryAdapter(self.group,env_path=empty,meta_dir=self.meta)
            try:
                with patch.object(a,'_ensure',side_effect=AssertionError('read path must not initialize LLM')):
                    return await a.query_as_of(dt(MAR))
            finally: await a.close()
        self.assertEqual(len(asyncio.run(go()).facts),1)

if __name__=='__main__': unittest.main(verbosity=2)
