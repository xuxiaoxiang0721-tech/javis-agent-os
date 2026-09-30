"""Preserve completed visible final output independently from SUMMARY protocol."""
import hashlib
import json
from pathlib import Path
import unittest
import test_v02_runtime as support

FAKE=r'''#!/usr/bin/env python3
import json,os,sys
sys.stdin.read()
mode=os.environ['FINAL_MODE']
text=('SUMMARY: ' if mode!='no-summary' else '')+'完整可见原文\n'+('合成正文 1234567890\n'*1024)+'尾部原样  \n'
def emit(row):print(json.dumps(row),flush=True)
emit({'type':'thread.started','thread_id':'synthetic-native-final'})
emit({'type':'item.completed','item':{'type':'agent_message','id':'final','text':text,'phase':'commentary' if mode=='commentary' else 'final_answer'}})
if mode!='incomplete':emit({'type':'turn.completed','usage':{'input_tokens':10,'output_tokens':10}})
'''

class NativeFinal(unittest.TestCase):
    def setUp(self):
        support.RuntimeV02.setUp(self);self.fake.write_text(FAKE)
        self.env['FINAL_MODE']='ok';self.env['JAVIS_MEMORY_GRAPH_DISABLED']='1'
        self.env['JAVIS_EXCHANGE_ROOT']=str(Path(self.tmp.name)/'exchange')
    tearDown=support.RuntimeV02.tearDown
    packet=support.RuntimeV02.packet
    invoke=support.RuntimeV02.invoke
    def result(self):return json.loads((self.r/'workspace/tasks/test/attempts/1/result.json').read_text())
    def expected(self,prefix=True):return ('SUMMARY: ' if prefix else '')+'完整可见原文\n'+('合成正文 1234567890\n'*1024)+'尾部原样  \n'
    def test_summary_long_final_is_exact_in_file_raw_object_and_windows_delivery(self):
        p=self.invoke();self.assertEqual(p.returncode,0,p.stderr);result=self.result()
        self.assertTrue(result['native_final_output_available']);raw=Path(result['native_final_output_ref']).read_bytes()
        self.assertEqual(raw,self.expected().encode());self.assertEqual(result['native_final_output_sha256'],hashlib.sha256(raw).hexdigest())
        artifact=next(a for a in result['artifacts'] if a['kind']=='native_final')
        self.assertEqual(Path(artifact['object_path']).read_bytes(),raw);self.assertEqual(Path(artifact['exchange_path']).read_bytes(),raw)
    def test_no_summary_final_is_preserved_but_remains_protocol_failure(self):
        self.env['FINAL_MODE']='no-summary';p=self.invoke();self.assertEqual(p.returncode,1,p.stderr);result=self.result()
        self.assertEqual(result['failure_category'],'completion_protocol_error');self.assertTrue(result['native_final_output_available'])
        self.assertEqual(Path(result['native_final_output_ref']).read_text(),self.expected(False))
    def test_incomplete_turn_does_not_publish_candidate_as_final(self):
        self.env['FINAL_MODE']='incomplete';self.invoke();self.assertFalse(self.result()['native_final_output_available'])
    def test_commentary_is_not_published_as_final(self):
        self.env['FINAL_MODE']='commentary';self.invoke();self.assertFalse(self.result()['native_final_output_available'])

if __name__=='__main__':unittest.main()
