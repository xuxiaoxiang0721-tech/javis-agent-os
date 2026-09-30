"""Original-message entry contract and end-to-end synthetic runner tests."""
import importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path

CODE=Path(os.environ.get('JAVIS_TEST_CODE_ROOT',Path.home()/'javis'))
ENTRY=Path(os.environ.get('JAVIS_ROLE_ENTRY',CODE/'scripts/role-run.py'))
sys.path.insert(0,str(CODE/'scripts'))
spec=importlib.util.spec_from_file_location('role_entry',ENTRY)
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)

FAKE='''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
prompt=sys.stdin.read()
with open(os.environ['FAKE_CALLS'],'a') as out:out.write('call\\n')
for row in [dict(type='thread.started',thread_id='fake-message-session'),
    dict(type='item.completed',item=dict(type='agent_message',text='SUMMARY: 已提交处理，由运行时核验。')),
    dict(type='turn.completed')]:print(json.dumps(row),flush=True)
'''

class MessageEntry(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='javis-message-entry-')
        self.root=Path(self.tmp.name)/'root';self.root.mkdir()
        self.message=Path(self.tmp.name)/'中文 原文.txt'
        self.original='请记住并共享：验收码是 ORIGINAL_Q7。\n中文、空格和第二行。'
        self.message.write_text(self.original,encoding='utf-8-sig')
    def tearDown(self):self.tmp.cleanup()
    def parse(self,role='cards-master',*args):
        return entry.read_packet(role,['--message-file',str(self.message),*args],self.root)
    def test_original_exact_and_legacy_summary_stays_distinct(self):
        p=self.parse();self.assertEqual(p['original_user_input'],self.original)
        self.assertEqual(p['goal'],self.original);self.assertEqual(p['entry'],'grok_bridge')
        for mode in [['summary'],['--goal-file',str(self.message)]]:
            self.assertNotIn('original_user_input',entry.read_packet('cards-master',mode,self.root))
    def test_source_message_id_dedup_is_role_scoped(self):
        a=self.parse('cards-master','--message-id','msg-synthetic')
        self.assertEqual(a,self.parse('cards-master','--message-id','msg-synthetic'))
        self.assertNotEqual(a['task_id'],self.parse('invest','--message-id','msg-synthetic')['task_id'])
        self.assertEqual(a['source_event_id'],'msg-synthetic')
    def test_continuation_requires_explicit_task_and_preserves_source(self):
        with self.assertRaises(ValueError):self.parse('cards-master','--mode','continue')
        p=self.parse('invest','--mode','continue','--task-id','prior','--message-id','next')
        self.assertEqual((p['task_id'],p['mode'],p['source_event_id']),('prior','continue','next'))
    def test_l4_and_permission_still_block(self):
        self.message.write_text('L4: synthetic sensitive body')
        p=entry.checked_packet(self.parse())
        self.assertNotIn('synthetic sensitive body',json.dumps(p))
        self.assertEqual(p['privacy_level'],'L4')
        self.assertEqual(self.parse('cards-master','--permission','R3')['permission'],'R3')
    def test_packet_and_local_gpt_original_interfaces_preserved(self):
        p=self.parse('gpt-star');self.assertEqual(p['from_agent_id'],'local-user')
        path=Path(self.tmp.name)/'packet.json';path.write_text(json.dumps(p))
        self.assertEqual(entry.read_packet('gpt-star',['--packet',str(path)],self.root),p)
        with self.assertRaises(ValueError):entry.read_packet('invest',['--packet',str(path)],self.root)
    @unittest.skipUnless(ENTRY==CODE/'scripts/role-run.py','integration requires installed entry beside its runner')
    def test_actual_wrapper_records_original_confirms_memory_and_dedupes(self):
        (self.root/'workspace/roles/cards-master').mkdir(parents=True)
        fake=Path(self.tmp.name)/'fake-codex';fake.write_text(FAKE);fake.chmod(0o755)
        calls=Path(self.tmp.name)/'calls'
        env={**os.environ,'JAVIS_ROOT':str(self.root),'JAVIS_CODEX_BIN':str(fake),
             'FAKE_CALLS':str(calls),'JAVIS_MEMORY_GRAPH_DISABLED':'1','PYTHONDONTWRITEBYTECODE':'1'}
        command=['bash',str(CODE/'scripts/cards-master-run.sh'),'--message-file',str(self.message),'--message-id','dedupe-1']
        first=subprocess.run(command,env=env,capture_output=True,text=True,timeout=25)
        self.assertEqual(first.returncode,0,first.stderr+first.stdout)
        receipt=json.loads(first.stdout.splitlines()[0]);result=json.loads(Path(receipt['result']).read_text())
        self.assertTrue(result['memory_write_refs'])
        self.assertEqual(result['memory_write_refs'][0]['scope'],'shared')
        facts=[json.loads(line) for line in (self.root/'memory/structured/shared/facts.jsonl').read_text().splitlines()]
        confirmed=[f for f in facts if f.get('status')=='confirmed']
        self.assertTrue(confirmed)
        self.assertEqual(confirmed[-1]['value'],'请记住并共享：验收码是 ORIGINAL_Q7')
        task=self.root/'workspace/tasks'/receipt['task_id']
        self.assertEqual(json.loads((task/'packet.json').read_text())['original_user_input'],self.original)
        rows=[json.loads(line) for p in (self.root/'raw/events').glob('*.jsonl') for line in p.read_text().splitlines()]
        self.assertTrue(any(r['event_type']=='user_input' and r['payload'].get('text')==self.original and r['payload'].get('is_original_user_input') for r in rows))
        again=subprocess.run(command,env=env,capture_output=True,text=True,timeout=25)
        self.assertEqual(again.returncode,0,again.stderr)
        self.assertEqual(calls.read_text().splitlines(),['call'])
        self.message.write_text(self.original+'changed')
        changed=subprocess.run(command,env=env,capture_output=True,text=True,timeout=25)
        self.assertEqual(changed.returncode,2)
        self.assertEqual(calls.read_text().splitlines(),['call'])

if __name__=='__main__':unittest.main(verbosity=2)
