"""Targeted adapter regressions; synthetic authenticated HTTP session only."""
import json
import unittest
import test_control_http as support
from task_service import load_control, save_control

class AdapterFixes(unittest.TestCase):
    setUp=support.HTTPTests.setUp
    request=support.HTTPTests.request
    def submit(self,role='cards-master',command_id='same-command'):
        code,value=self.request('/api/tasks',{'command_id':command_id,'role_id':role,'original_text':'Synthetic only'},True)
        self.assertEqual(code,202,value);return value['task_id']
    def test_lookup_refuses_owner_cross_role_ambiguity(self):
        one=self.submit();two=self.submit('invest')
        code,value=self.request('/api/commands/same-command',auth=True)
        self.assertEqual(code,409);self.assertEqual(value['error'],'ambiguous_command');self.assertEqual(set(value['matches']),{one,two})
    def test_lookup_keeps_fixed_work_fields_for_unique_task(self):
        tid=self.submit();code,value=self.request('/api/commands/same-command',auth=True)
        self.assertEqual(code,200);self.assertEqual(value['task_id'],tid);self.assertEqual(value['role_id'],'cards-master')
        self.assertEqual(value['source_line'],2);self.assertEqual(len(value['original_text_sha256']),64)
    def test_reviewed_retry_accepted_only_after_explicit_human_check(self):
        tid=self.submit();path=self.root/'state/tasks'/f'{tid}.json';state=json.loads(path.read_text())
        state.update(state='failed',attempt=1,recovery_required=True,failure_reason='synthetic incomplete action')
        path.write_text(json.dumps(state));control=load_control(self.root,tid);control['dispatch']['status']='completed'
        save_control(self.root,control,'synthetic_failure_fixture')
        request={'command_id':'retry-after-review','action':'retry','expected_goal_revision':1,'expected_attempt':1}
        code,value=self.request('/api/tasks/'+tid+'/commands',request,True)
        self.assertEqual(code,409);self.assertEqual(value['error'],'review_required')
        code,value=self.request('/api/tasks/'+tid+'/commands',{**request,'review_confirmed':True},True)
        self.assertEqual(code,202);self.assertEqual(value['status'],'received');self.assertEqual(value['attempt'],1)
        self.assertEqual(load_control(self.root,tid)['dispatch']['status'],'queued')

if __name__=='__main__':unittest.main()
