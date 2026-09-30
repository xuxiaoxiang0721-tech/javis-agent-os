import copy, json, unittest
import test_control_http as support
from task_service import Principal, ControlError
from role_registry import ROLE_IDS, ROLE_REGISTRY

EXPECTED={'gpt-star','invest','operations','property','idea-lab','cards-master','personal-life','ai-data','domestic-fund','javis','friday','toolgo'}

class NineRoleHTTP(unittest.TestCase):
    setUp=support.HTTPTests.setUp
    request=support.HTTPTests.request

    def test_role_catalog_is_owner_only_and_exact(self):
        code,value=self.request('/api/roles');self.assertEqual(code,403)
        code,value=self.request('/api/roles',auth=True);self.assertEqual(code,200)
        self.assertEqual({row['role_id'] for row in value['roles']},EXPECTED)
        self.assertTrue(all(set(row)=={'role_id','label'} for row in value['roles']))

    def test_all_nine_are_persisted_and_replayed_separately(self):
        task_ids=[]
        for role in sorted(EXPECTED):
            with self.subTest(role=role):
                request={'command_id':'same-local-message','role_id':role,'original_text':'Synthetic nine-role routing only\r\nsecond line','source_line':2}
                code,first=self.request('/api/tasks',request,True);self.assertEqual(code,202,first)
                code,again=self.request('/api/tasks',request,True);self.assertEqual(code,202,again)
                self.assertEqual(first['task_id'],again['task_id']);self.assertTrue(again['replayed'])
                self.assertEqual(first['attempt'],0)
                code,detail=self.request('/api/tasks/'+first['task_id'],auth=True)
                self.assertEqual(code,200);self.assertEqual(detail['role_id'],role)
                self.assertEqual(detail['goals'][0]['text'],request['original_text'])
                task_ids.append(first['task_id'])
        self.assertEqual(len(set(task_ids)),len(EXPECTED))

    def test_excluded_roles_cannot_be_submitted(self):
        for role in ['waiting-lounge','saturday','unknown','../invest']:
            with self.subTest(role=role):
                code,value=self.request('/api/tasks',{'command_id':'excluded','role_id':role,'original_text':'Synthetic'},True)
                self.assertEqual(code,403,value)
        self.assertFalse((self.root/'state/tasks').exists())

    def test_expanded_owner_access_does_not_expand_flowise_role(self):
        principal=support.panel.service_principal()
        for role in sorted(EXPECTED-{'invest'}):
            with self.subTest(role=role),self.assertRaises(ControlError) as caught:
                self.app.control.submit(principal,{'command_id':'unauthorized-flowise-role','role_id':role,'original_text':'Synthetic','source_line':3})
            self.assertEqual(caught.exception.code,'forbidden')
        self.assertFalse((self.root/'state/tasks').exists())

class NineRoleCapture(unittest.TestCase):
    setUp=support.CaptureTests.setUp

    def test_each_capture_role_is_archived_separately_without_confirmation(self):
        ids=[]
        for role in sorted(EXPECTED):
            request=copy.deepcopy(self.req);request['role_id']=role
            value=support.capture.ingest(self.root,request);ids.append(value['event_id'])
            self.assertTrue(value['archived']);self.assertFalse(value['memory_confirmed'])
            self.assertTrue(support.capture.ingest(self.root,request)['replayed'])
        self.assertEqual(len(set(ids)),len(EXPECTED))
        events=[json.loads(line) for p in (self.root/'raw/events/grok-sync').glob('*.jsonl') for line in p.read_text().splitlines()]
        self.assertEqual(len(events),len(EXPECTED));self.assertEqual({row['agent'] for row in events},EXPECTED)
        self.assertFalse((self.root/'memory/structured').exists())

    def test_capture_rejects_excluded_roles_before_archival(self):
        for role in ['waiting-lounge','saturday','unknown','../invest']:
            request=copy.deepcopy(self.req);request['role_id']=role
            with self.subTest(role=role),self.assertRaises(ValueError):support.capture.ingest(self.root,request)
        self.assertFalse((self.root/'raw/events').exists())

if __name__=='__main__':unittest.main(verbosity=2)
