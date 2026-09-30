"""JSONL delimiters are physical LF, never Unicode inside a JSON string."""
import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

CODE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(CODE/'scripts'),str(CODE/'tools/memory-adapter')]
from raw_storage import append_event, _read_rows
from memory_screen import _source, load_source
from memory_sources import _rows as audit_rows, _records as audit_records
from raw_cursor import ingest_jsonl
from task_service import load_control
from memory_corpus import inventory, build_event, verify_canonical
from javis_memory_adapter.review_policy import read_rows, digest, source_digests
from javis_memory_adapter.structured_store import StructuredStore
from javis_memory_adapter.adapter import MemoryAdapter

TEXT='Synthetic 中文\u0085preserved\u2028line separator\u2029paragraph separator 😀\tquoted "value"\nactual newline\rreturn'


def load_script(name):
    spec=importlib.util.spec_from_file_location('unicode_'+name.replace('-','_'),CODE/'scripts'/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

codex=load_script('codex-log-to-raw')
grok=load_script('grok-sync')
rebuild=load_script('rebuild-task-view')
query=load_script('memory-query')


class JsonlUnicodeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='unicode-jsonl-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def write(self,relative,rows,ending='\n'):
        path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(ending.join(json.dumps(row,ensure_ascii=False) for row in rows).encode()+ending.encode())
        return path
    def source(self):
        append_event(self.root,{'event_id':'unicode-event','event_type':'user_input','agent':'invest','task_id':'task-unicode',
            'payload':{'text':TEXT,'is_original_user_input':True}},relative_path='events/unicode.jsonl')
        return self.root/'raw/events/unicode.jsonl'
    def test_strict_rows_preserve_all_unicode_and_physical_record_count(self):
        rows=[{'event_id':str(i),'text':TEXT} for i in range(3)]
        for ending in ('\n','\r\n'):
            path=self.write('records.jsonl',rows,ending)
            before=path.read_bytes()
            self.assertEqual(read_rows(self.root,path),rows)
            self.assertEqual(list(_read_rows([path])),rows)
            self.assertEqual(path.read_bytes(),before)
            self.assertEqual(before.count(b'\n'),3)
            self.assertGreater(len(before.decode().splitlines()),3)
    def test_raw_append_duplicate_protection_does_not_skip_unicode_record(self):
        path=self.source();before=path.read_bytes()
        self.assertIsNone(append_event(self.root,{'event_id':'unicode-event','event_type':'user_input','payload':{'text':'changed'}},
            relative_path='events/unicode.jsonl'))
        self.assertEqual(path.read_bytes(),before)
        self.assertEqual(len(list(_read_rows([path]))),1)
        self.assertEqual(codex.load_existing_ids(path),{'unicode-event'})
    def test_source_digest_and_screen_guard_preserve_exact_unicode(self):
        path=self.source();event=load_source(self.root,'unicode-event')
        self.assertEqual(event['payload']['text'],TEXT)
        self.assertEqual(_source(self.root,event['event_id'],TEXT,digest(event)),event)
        self.assertEqual(source_digests(self.root,[event['event_id']]),{event['event_id']:digest(event)})
        self.assertEqual(read_rows(self.root,path)[0]['payload']['text'],TEXT)
    def test_structured_and_source_audit_ledgers_round_trip(self):
        row={'fact_id':'unicode-fact','value':TEXT}
        store=StructuredStore(self.root/'ledger')
        store._append(store.facts_path,row)
        self.assertEqual(store._read_jsonl(store.facts_path),[row])
        self.assertEqual(audit_rows(store.facts_path),[row])
        self.assertEqual(query.load_jsonl(store.facts_path),[row])
    def test_graphiti_local_indexes_and_correction_ledgers_preserve_unicode(self):
        adapter=MemoryAdapter.__new__(MemoryAdapter);adapter.meta_dir=self.root/'adapter';adapter.group_id='synthetic-group'
        row={'source_event_id':'unicode-event','episode_uuid':'episode-one','notes':TEXT}
        self.write('adapter/source_events.jsonl',[row])
        self.write('adapter/corrections.jsonl',[row])
        self.assertEqual(adapter._lookup_source_event('unicode-event'),row)
        self.assertEqual(adapter._corrections_related(['unicode-event']),[row])
        self.assertEqual(adapter._load_correction_ledger(),[row])
    def test_native_json_replay_keeps_unicode_body(self):
        row={'type':'item.completed','item':{'type':'agent_message','text':TEXT}}
        parsed=codex.parse_codex_log(json.dumps(row,ensure_ascii=False)+'\n')
        self.assertEqual(parsed['model_texts'],[TEXT]);self.assertEqual(parsed['errors'],[])
    def test_byte_cursor_and_audit_offsets_are_unicode_safe(self):
        rows=[{'type':'item.completed','item':{'type':'agent_message','text':TEXT}}]
        path=self.write('native.jsonl',rows)
        records=list(audit_records(path.read_bytes(),'.jsonl'))
        self.assertEqual(records[0][0],rows[0]);self.assertEqual(records[0][1]['byte_end'],len(path.read_bytes()))
        result=ingest_jsonl(self.root,path,task_id='synthetic-task',attempt=1,agent='invest')
        self.assertEqual(result['gaps'],[])
        events=list(_read_rows((self.root/'raw/events').glob('*.jsonl')))
        found=next(e for e in events if 'native_event' in e.get('payload',{}))
        self.assertEqual(found['payload']['native_event'],rows[0])
    def test_grok_capture_replay_keeps_complete_text_and_deduplicates(self):
        request={'capture_id':'unicode-capture','role_id':'invest','messages':[
            {'speaker':'user','fidelity':'forwarded_original_unverified','text':TEXT}]}
        with patch.object(grok,'_enqueue_captured',return_value={'status':'synthetic'}):
            first=grok.ingest(self.root,request);second=grok.ingest(self.root,request)
        self.assertTrue(second['replayed']);self.assertEqual(first['event_id'],second['event_id'])
        events=read_rows(self.root,next((self.root/'raw/events/grok-sync').glob('*.jsonl')))
        self.assertEqual(len(events),1);self.assertEqual(events[0]['payload']['messages'][0]['text'],TEXT)
    def test_task_projection_recovery_and_raw_rebuild_preserve_unicode(self):
        snapshot={'task_id':'unicode-task','sequence':1,'description':TEXT}
        self.write('raw/events/control/unicode-task.jsonl',[{'event_id':'unicode-control','event_type':'task_control',
            'task_id':'unicode-task','payload':{'control_projection':snapshot}}])
        self.assertEqual(load_control(self.root,'unicode-task'),snapshot)
        events,issues=rebuild.load_events(self.root,'unicode-task')
        self.assertEqual(issues,[]);self.assertEqual(events[0]['payload']['control_projection'],snapshot)
    def test_corpus_canonical_end_to_end_preserves_unicode_and_source_hash(self):
        self.write('memory/imports/synthetic.jsonl',[{'agent':'invest','body_full':TEXT}])
        item=next(i for i in inventory(self.root)['items'] if i['route']=='candidate')
        built=build_event(self.root,item)
        append_event(self.root,built,relative_path='events/corpus.jsonl')
        event=load_source(self.root,built['event_id'])
        self.assertEqual(event['payload']['text'],TEXT)
        self.assertTrue(verify_canonical(self.root,event)['verified'])
        self.assertEqual(_source(self.root,event['event_id'],TEXT,digest(event)),event)
        self.assertEqual(source_digests(self.root,[event['event_id']]),{event['event_id']:digest(event)})


if __name__=='__main__':unittest.main()
