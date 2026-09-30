#!/usr/bin/env python3
"""Offline integration/regression tests; only temporary roots and fake Codex."""
import asyncio, concurrent.futures, importlib.util, json, os, shutil, subprocess, sys, tempfile, time, unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
ROOT=Path(os.environ.get('JAVIS_TEST_CODE_ROOT',Path(__file__).parent))
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tools/memory-adapter')]
if os.environ.get('JAVIS_MEMORY_TEST_CODE'):
    sys.path.insert(0,os.environ['JAVIS_MEMORY_TEST_CODE'])
sys.dont_write_bytecode=True
from javis_memory_adapter.structured_store import StructuredStore, StructuredFact
from javis_memory_adapter.ledger_query import query_known
from javis_memory_adapter.type_b import rebuild_group_from_store
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
rec=load('rec',ROOT/'scripts/codex-log-to-raw.py')
mq=load('mq',ROOT/'scripts/memory-query.py')

FAKE='''#!/usr/bin/env python3
import sys,json,time,os
from pathlib import Path
args=sys.argv[1:]; prompt=sys.stdin.read(); final=Path(args[args.index('--output-last-message')+1])
goal=prompt.split('Goal:\\n')[1].split('\\nWhen done')[0]
def emit(x): print(json.dumps(x),flush=True)
emit({'type':'thread.started','thread_id':'fake-'+goal})
emit({'type':'item.completed','item':{'id':'c1','type':'command_execution','command':'echo sample','aggregated_output':'x'*9000,'exit_code':0}})
emit({'type':'item.completed','item':{'id':'m1','type':'mcp_tool_call','server':'fake','tool':'read','result':{'value':'sample'},'status':'completed'}})
if goal=='timeout': time.sleep(30)
if goal=='slow': time.sleep(0.7)
if goal=='fail': sys.exit(7)
if goal=='no-final': sys.exit(0)
final.write_text('SUMMARY: '+goal)
emit({'type':'item.completed','item':{'id':'a1','type':'agent_message','text':'SUMMARY: '+goal}})
emit({'type':'turn.completed','usage':{}})
'''

class Reliability(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='javis-fix-tests-'); self.r=Path(self.tmp.name)
        shutil.copytree(ROOT/'scripts',self.r/'scripts')
        shutil.copytree(ROOT/'tools/raw-index',self.r/'tools/raw-index')
        for role in ['cards-master','invest']: (self.r/'workspace/roles'/role).mkdir(parents=True)
        self.fake=self.r/'fake-codex'; self.fake.write_text(FAKE); self.fake.chmod(0o755)
        self.env={**os.environ,'JAVIS_ROOT':str(self.r),'JAVIS_CODEX_BIN':str(self.fake),'JAVIS_TASK_TIMEOUT':'10',
                  'PYTHONDONTWRITEBYTECODE':'1'}
    def tearDown(self): self.tmp.cleanup()
    def run_task(self,tid,goal='hello',role='cards-master',env=None):
        p=self.r/(tid+'.json'); p.write_text(json.dumps({'task_id':tid,'role_id':role,'from_agent_id':'test','goal':goal}))
        return subprocess.run(['bash',str(self.r/'scripts'/f'{role}-run.sh'),'--packet',str(p)],env=env or self.env,capture_output=True,text=True,timeout=20)
    def result(self,tid): return json.loads((self.r/'workspace/tasks'/tid/'result.json').read_text())
    def state(self,tid): return json.loads((self.r/'state/tasks'/f'{tid}.json').read_text())
    def test_parallel_result_binding(self):
        with concurrent.futures.ThreadPoolExecutor() as pool:
            a=pool.submit(self.run_task,'task-slow','slow'); time.sleep(.1); b=pool.submit(self.run_task,'task-fast','fast')
            x,y=a.result(),b.result()
        self.assertEqual(x.returncode,0,x.stderr); self.assertEqual(y.returncode,0,y.stderr)
        self.assertIn('slow',self.result('task-slow')['user_reply_zh']); self.assertNotIn('fast',self.result('task-slow')['user_reply_zh'])
        self.assertEqual(self.state('task-fast')['state'],'completed')
    def test_failure_status_propagates(self):
        p=self.run_task('failure','fail'); self.assertEqual(p.returncode,7,p.stderr)
        self.assertEqual(self.state('failure')['state'],'failed'); self.assertEqual(self.result('failure')['exit_code'],7)
    def test_timeout_is_recorded(self):
        p=self.run_task('deadline','timeout',env={**self.env,'JAVIS_TASK_TIMEOUT':'.2'})
        self.assertEqual(p.returncode,124,p.stderr); self.assertEqual(self.state('deadline')['state'],'failed')
    def test_empty_success_rejected(self): self.assertNotEqual(self.run_task('empty','no-final').returncode,0)
    def test_retry_preserves_previous_attempt(self):
        self.run_task('retry','fail'); p=self.run_task('retry','hello')
        self.assertEqual(p.returncode,0,p.stderr); self.assertEqual(self.result('retry')['attempt'],2)
        old=self.r/'workspace/tasks/retry/attempts/1/result.json'; self.assertEqual(json.loads(old.read_text())['exit_code'],7)
    def test_same_task_rejected_while_running(self):
        with concurrent.futures.ThreadPoolExecutor() as pool:
            a=pool.submit(self.run_task,'same','slow')
            for _ in range(80):
                if (self.r/'state/tasks/same.json').exists(): break
                time.sleep(.02)
            b=self.run_task('same','slow'); self.assertEqual(b.returncode,75,b.stderr); self.assertEqual(a.result().returncode,0)
    def test_raw_and_index_full_length(self):
        p=self.run_task('record','hello'); self.assertEqual(p.returncode,0,p.stderr)
        rows=[json.loads(l) for f in (self.r/'raw/events').glob('*.jsonl') for l in f.read_text().splitlines()]
        self.assertTrue(any(len(e.get('payload',{}).get('result',''))==9000 for e in rows))
        self.assertTrue(any(e['event_type']=='codex_stream_event' for e in rows))
        self.assertTrue(any(e.get('payload',{}).get('tool')=='mcp_tool_call' for e in rows))
        import sqlite3
        db=sqlite3.connect(self.r/'raw/index/events.sqlite'); self.assertEqual(db.execute('select count(*) from events').fetchone()[0],len(rows)); db.close()
    def test_recorder_failure_not_success(self):
        (self.r/'scripts/codex-log-to-raw.py').write_text((self.r/'scripts/codex-log-to-raw.py').read_text().replace('return 0\n\nif __name__','return 9\n\nif __name__'))
        p=self.run_task('badrec','hello'); self.assertEqual(p.returncode,74,p.stderr); self.assertEqual(self.result('badrec')['recording_status'],'failed')
    def test_cross_day_and_concurrent_raw_dedup(self):
        ev={'event_id':'same-event','event_type':'status','payload':{}}
        old=self.r/'raw/events/20000101.jsonl'; old.parent.mkdir(parents=True); old.write_text(json.dumps(ev)+'\n')
        self.assertIsNone(rec.append_event(self.r,ev,set()))
        ev2={**ev,'event_id':'second'}
        with concurrent.futures.ThreadPoolExecutor() as p: written=list(p.map(lambda _:rec.append_event(self.r,ev2,set()),range(12)))
        self.assertEqual(sum(x is not None for x in written),1)
    def test_legacy_long_output_and_timestamp(self):
        parsed=rec.parse_codex_log('exec\necho test\n succeeded in 1ms:\n'+'x'*9000+'\ncodex\nSUMMARY: ok\n')
        self.assertEqual(len(parsed['tools'][0]['result']),9000)
        rec.append_event(self.r,{'event_id':'legacy','event_type':'tool_result','occurred_at':'now','payload':{'record_source':'codex_log_parse'}},set())
        row=json.loads(next((self.r/'raw/events').glob('*.jsonl')).read_text()); self.assertIsNone(row['occurred_at'])
    def test_future_and_boundary_memory(self):
        now=datetime(2026,1,1,tzinfo=timezone.utc)
        self.assertFalse(mq.still_valid({'temporal':{'valid_from':'2099-01-01T00:00:00Z'}},now))
        self.assertFalse(mq.still_valid({'temporal':{'valid_to':'2026-01-01T00:00:00Z'}},now))
    def fact(self):
        return StructuredFact(fact_id='f1',subject_id='s',subject_label='s',predicate='p',value=1,unit=None,
            valid_from='2026-01-01T00:00:00Z',valid_to=None,recorded_at='2026-01-01T00:00:00Z',source_event_id='e1')
    def test_historical_confirmation(self):
        store=StructuredStore(self.r/'meta')
        with patch('javis_memory_adapter.structured_store._now',return_value='2026-01-01T00:00:00Z'): store.upsert_fact(self.fact())
        with patch('javis_memory_adapter.structured_store._now',return_value='2026-02-01T00:00:00Z'):
            store.write_confirmation(confirmation_event_id='c1',fact_id='f1',confirmed_at='2026-02-01T00:00:00Z')
        q=query_known(store,datetime(2026,1,15,tzinfo=timezone.utc)); self.assertEqual(q['facts'][0]['status'],'extracted')
        q=query_known(store,datetime(2026,3,1,tzinfo=timezone.utc)); self.assertEqual(q['facts'][0]['status'],'confirmed')
    def test_rebuild_replays_surviving_checkpoint(self):
        store=StructuredStore(self.r/'meta'); store.upsert_fact(self.fact()); store.save_checkpoint({'applied_fact_ids':['f1'],'target_group_id':'old'})
        calls=[]
        class Result:
            async def consume(self): pass
        class Session:
            async def __aenter__(self): return self
            async def __aexit__(self,*a): pass
            async def run(self,*a,**kw):
                calls.append(kw)
                return Result()
        class Driver:
            def session(self): return Session()
            async def close(self): pass
        with patch('neo4j.AsyncGraphDatabase.driver',return_value=Driver()):
            for group in ['new','new']:
                q=asyncio.run(rebuild_group_from_store(store=store,target_group_id=group,neo4j_uri='unused',neo4j_user='test',neo4j_password='unused'))
                self.assertEqual(q['written'],['f1']); self.assertEqual(q['errors'],[])
        self.assertEqual(len(calls),6)
    def test_graph_commit_failure_does_not_mark_synced(self):
        store=StructuredStore(self.r/'meta'); store.upsert_fact(self.fact())
        class Result:
            async def consume(self): raise RuntimeError('synthetic_commit_failure')
        class Session:
            async def __aenter__(self): return self
            async def __aexit__(self,*a): pass
            async def run(self,*a,**kw): return Result()
        class Driver:
            def session(self): return Session()
            async def close(self): pass
        with patch('neo4j.AsyncGraphDatabase.driver',return_value=Driver()):
            report=asyncio.run(rebuild_group_from_store(store=store,target_group_id='unused',neo4j_uri='unused',neo4j_user='test',neo4j_password='unused'))
        self.assertEqual(report['written'],[])
        self.assertIn('synthetic_commit_failure',report['errors'][0]['error'])
        self.assertNotEqual(store.load_facts()[0].graph_sync_status,'synced')
    def test_backup_contains_ledger_and_restores(self):
        for rel in ['lab/memory-adapter/meta/group/facts.jsonl','state/tasks/sample.json','raw/objects/sample','workspace/tasks/sample/result.json']:
            p=self.r/rel; p.parent.mkdir(parents=True,exist_ok=True); p.write_text('{}\n')
        secret=self.r/'tools/graphiti/.env'; secret.parent.mkdir(parents=True); secret.write_text('dummy=excluded')
        env={**self.env,'JAVIS_BACKUP_DEST':str(self.r/'backups')}
        p=subprocess.run(['bash',str(self.r/'scripts/javis-daily-backup.sh')],env=env,capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr); archive=json.loads(p.stdout)['archive']
        import tarfile
        with tarfile.open(archive) as t:
            self.assertIn('lab/memory-adapter/meta/group/facts.jsonl',t.getnames()); self.assertNotIn('tools/graphiti/.env',t.getnames())
        p=subprocess.run([sys.executable,str(self.r/'scripts/javis-backup.py'),'--verify',archive,'--restore-check'],capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)

if __name__=='__main__': unittest.main(verbosity=2)
