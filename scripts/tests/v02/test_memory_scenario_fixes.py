"""Regressions from actual usage scenarios; synthetic local roots only."""
import concurrent.futures, json, os, subprocess, sys, tempfile, unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode=True
ROOT=Path(os.environ.get('JAVIS_TEST_CODE_ROOT',Path.home()/'javis'))
CODE=Path(os.environ.get('JAVIS_MEMORY_TEST_CODE',ROOT/'tools/memory-adapter'))
sys.path.insert(0,str(CODE))
from javis_memory_adapter.structured_store import StructuredStore,StructuredFact
from javis_memory_adapter.ledger_query import query_known,query_effective,apply_state_change,apply_historical_correction

JAN='2026-01-01T00:00:00+00:00';FEB='2026-02-01T00:00:00+00:00'
MAR='2026-03-01T00:00:00+00:00';APR='2026-04-01T00:00:00+00:00'
def dt(value):return datetime.fromisoformat(value)

class ConfirmationRetry(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='javis-confirm-retry-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def candidate(self,role='shared'):
        path=self.root/('memory/ide-lab/facts.jsonl' if role=='ide-lab' else 'memory/candidates/by-role/'+role+'/facts.jsonl')
        path.parent.mkdir(parents=True,exist_ok=True)
        row=dict(memory_id='synthetic-memory',tier='candidate',role_id=role,fact='SYNTHETIC_TEST preference',
                 confidence='medium',source={'raw_event_ids':['SYNTHETIC_TEST:cards']},
                 temporal={'valid_from':JAN,'valid_to':None,'as_of':JAN,'learned_at':JAN})
        path.write_text(json.dumps(row)+'\n');return path
    def confirm(self,actor='first',memory_id='synthetic-memory'):
        return subprocess.run([sys.executable,str(ROOT/'scripts/memory-confirm.py'),memory_id,'--by',actor],
            env={**os.environ,'JAVIS_ROOT':str(self.root),'PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True,timeout=15)
    def rows(self,path):return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    def test_repeat_keeps_first_record_and_candidate_unchanged(self):
        candidate=self.candidate();original=candidate.read_bytes();first=self.confirm();self.assertEqual(first.returncode,0,first.stderr)
        target=Path(json.loads(first.stdout)['confirmed_path']);saved=target.read_bytes()
        second=self.confirm('different-actor');self.assertEqual(second.returncode,0,second.stderr)
        self.assertEqual(target.read_bytes(),saved);self.assertEqual(candidate.read_bytes(),original)
        record=self.rows(target)[0];self.assertEqual(record['confirmed_by'],'first');self.assertEqual(record['confidence'],'high')
        self.assertEqual(record['source']['raw_event_ids'],['SYNTHETIC_TEST:cards'])
        self.assertEqual(record['temporal']['valid_from'],JAN)
    def test_concurrent_process_retries_append_once(self):
        self.candidate()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda index:self.confirm('actor-'+str(index)),range(8)))
        self.assertEqual([r.returncode for r in results],[0]*8)
        target=Path(json.loads(results[0].stdout)['confirmed_path']);self.assertEqual(len(self.rows(target)),1)
    def test_retry_after_candidate_archival_succeeds(self):
        candidate=self.candidate();first=self.confirm();target=Path(json.loads(first.stdout)['confirmed_path']);saved=target.read_bytes()
        candidate.rename(candidate.with_suffix('.archived'))
        retry=self.confirm();self.assertEqual(retry.returncode,0,retry.stderr);self.assertEqual(target.read_bytes(),saved)
    def test_existing_duplicate_history_is_not_rewritten_or_extended(self):
        self.candidate();first=self.confirm();target=Path(json.loads(first.stdout)['confirmed_path'])
        saved=target.read_bytes()*2;target.write_bytes(saved)
        retry=self.confirm();self.assertEqual(retry.returncode,0);self.assertEqual(target.read_bytes(),saved)
    def test_ide_lab_mixed_candidate_and_confirmed_is_idempotent(self):
        path=self.candidate('ide-lab')
        self.assertEqual(self.confirm().returncode,0);self.assertEqual(self.confirm().returncode,0)
        rows=self.rows(path);self.assertEqual(len(rows),2);self.assertEqual([r['tier'] for r in rows],['candidate','confirmed'])
    def test_role_scoped_confirmation_stays_in_role(self):
        self.candidate('invest');first=self.confirm();self.assertEqual(first.returncode,0)
        target=Path(json.loads(first.stdout)['confirmed_path'])
        self.assertEqual(target,self.root/'memory/confirmed/by-role/invest/facts.jsonl')
        self.assertEqual(self.confirm().returncode,0);self.assertEqual(len(self.rows(target)),1)
    def test_unknown_memory_does_not_append_a_confirmation(self):
        self.candidate();result=self.confirm(memory_id='missing-synthetic')
        self.assertEqual(result.returncode,1);self.assertFalse((self.root/'memory/confirmed').exists())

class KnowledgeTime(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='javis-knowledge-time-');self.addCleanup(self.tmp.cleanup)
        self.store=StructuredStore(Path(self.tmp.name))
    def put(self,fid,value,at=JAN,start=JAN,end=None,status='confirmed'):
        fact=StructuredFact(fact_id=fid,subject_id='SYNTHETIC_TEST:person',subject_label='Synthetic',predicate='format',value=value,
            unit=None,valid_from=start,valid_to=end,recorded_at=at,source_event_id='SYNTHETIC_TEST:'+fid,status=status,
            confirmation_event_id='confirm-'+fid if status=='confirmed' else None)
        with patch('javis_memory_adapter.structured_store._now',return_value=at):self.store.upsert_fact(fact)
        return fact
    def values(self,at):return [row['value'] for row in query_known(self.store,dt(at))['facts']]
    def change(self,received=FEB,effective=FEB):
        with patch('javis_memory_adapter.structured_store._now',return_value=received):
            return apply_state_change(self.store,subject_id='SYNTHETIC_TEST:person',subject_label='Synthetic',predicate='format',
                old_value='long',new_value='brief',unit=None,change_at=dt(effective),source_event_id='SYNTHETIC_TEST:change',
                raw_refs=['SYNTHETIC_TEST:invest'],confirmation_event_id='change-confirm')
    def correct(self):
        with patch('javis_memory_adapter.structured_store._now',return_value=MAR):
            return apply_historical_correction(self.store,subject_id='SYNTHETIC_TEST:person',subject_label='Synthetic',predicate='format',
                wrong_value='long',correct_value='table',unit=None,about_event_time=dt(JAN),source_event_id='SYNTHETIC_TEST:correction',
                raw_refs=['SYNTHETIC_TEST:gpt-star'],confirmation_event_id='correction-confirm')
    def test_late_historical_correction_does_not_replace_current_slot(self):
        self.put('original','long');self.change();self.correct()
        self.assertEqual(self.values(APR),['brief'])
        self.assertEqual([f['value'] for f in query_effective(self.store,dt(JAN))['facts']],['table'])
        self.assertEqual(len(query_known(self.store,dt(APR))['corrections_known']),2)
    def test_later_correction_is_not_visible_in_old_system_snapshot(self):
        self.put('original','long');self.change();self.correct()
        self.assertEqual(self.values('2026-01-15T00:00:00+00:00'),['long'])
        self.assertEqual(query_known(self.store,dt(JAN))['corrections_known'],[])
    def test_future_only_knowledge_is_not_hidden_by_event_time_filter(self):
        self.put('future','scheduled',start=APR)
        self.assertEqual(self.values(FEB),['scheduled'])
        self.assertEqual(query_effective(self.store,dt(FEB))['facts'],[])
    def test_closed_only_knowledge_remains_available(self):
        self.put('past','archived preference',end=FEB)
        self.assertEqual(self.values(MAR),['archived preference'])
        self.assertEqual(query_effective(self.store,dt(MAR))['facts'],[])
    def test_announced_future_change_keeps_predecessor_until_boundary(self):
        self.put('original','long');self.change(received=FEB,effective=APR)
        self.assertEqual(self.values(MAR),['long']);self.assertEqual(self.values(APR),['brief'])
    def test_new_extracted_current_does_not_override_confirmed_current(self):
        self.put('confirmed','confirmed');self.put('guess','unconfirmed',at=FEB,status='extracted')
        self.assertEqual(self.values(MAR),['confirmed'])
    def test_new_closed_confirmed_does_not_override_current_extracted(self):
        self.put('current','current unknown',status='extracted')
        self.put('past','old confirmed',at=MAR,end=FEB)
        self.assertEqual(self.values(APR),['current unknown'])
    def test_new_future_fact_does_not_override_current_fact(self):
        self.put('current','present');self.put('future','planned',at=FEB,start=APR)
        self.assertEqual(self.values(MAR),['present']);self.assertEqual(self.values(APR),['planned'])
    def test_record_time_blocks_fact_received_after_cutoff(self):
        self.put('late','late historical knowledge',at=MAR,start=JAN)
        self.assertEqual(self.values(FEB),[]);self.assertEqual(self.values(APR),['late historical knowledge'])
    def test_unknown_effective_time_is_still_known(self):
        self.put('unknown','unknown interval',start=None)
        self.assertEqual(self.values(FEB),['unknown interval'])

if __name__=='__main__':unittest.main(verbosity=2)
