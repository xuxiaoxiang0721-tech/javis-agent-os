"""Memory-only HTTP integration, role isolation and local correction flow."""
import http.client
import json
import sys
import types
import unittest
from http.cookies import SimpleCookie
from unittest.mock import patch
import test_control_http as support
from raw_storage import append_event


class MemoryV3HTTPTests(unittest.TestCase):
    def setUp(self):
        support.HTTPTests.setUp(self)
        self.cookie='';self.csrf=''

    def request(self,path,body=None,headers=None):
        h={'Host':'localhost:8766','Origin':support.panel.ORIGIN,'Cookie':self.cookie,'X-Javis-Memory-CSRF':self.csrf}
        if body is not None:h['Content-Type']='application/json'
        h.update(headers or {})
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        conn.request('POST' if body is not None else 'GET',path,json.dumps(body) if body is not None else None,h)
        r=conn.getresponse();data=json.loads(r.read());cookie=r.getheader('Set-Cookie');conn.close()
        return r.status,data,cookie

    def open(self):
        code,value,raw=self.request('/api/memory/session',{});self.assertEqual(code,200)
        jar=SimpleCookie();jar.load(raw);self.cookie='javis_memory='+jar['javis_memory'].value;self.csrf=value['csrf']

    def test_role_switches_work_without_hello_and_do_not_expand_task_access(self):
        self.open()
        code,state,_=self.request('/api/memory/controls');self.assertEqual(code,200)
        self.assertEqual(len(state['roles']),12);self.assertTrue(state['raw_capture_enabled'])
        change={'expected_revision':state['revision'],'roles':{'invest':False},'command_id':'role-off'}
        code,result,_=self.request('/api/memory/controls',change);self.assertEqual(code,200)
        self.assertFalse(result['roles']['invest']);self.assertTrue(result['roles']['cards-master'])
        self.assertFalse(result['global_enabled']);self.assertTrue(result['raw_capture_enabled'])
        self.assertEqual(self.request('/api/tasks')[0],403)
        self.assertEqual(self.request('/api/memory/feedback',{'label':'keep'})[0],403)
        self.assertFalse((self.root/'memory/review').exists())

    def test_controls_require_memory_csrf_and_reject_unknown_roles_and_privilege_fields(self):
        self.assertEqual(self.request('/api/memory/controls')[0],403);self.open()
        _,state,_=self.request('/api/memory/controls')
        base={'expected_revision':state['revision'],'roles':{'invest':False},'command_id':'forged'}
        self.assertEqual(self.request('/api/memory/controls',base,{'X-Javis-Memory-CSRF':''})[0],403)
        for changes in ({'roles':{'unknown-role':True}},{'roles':{'invest':'false'}},{'owner_proof':'forged'},{'raw_capture_enabled':False}):
            self.assertEqual(self.request('/api/memory/controls',{**base,**changes})[0],400)

    def test_source_context_requires_scope_and_never_accepts_arbitrary_file_path(self):
        self.open()
        append_event(self.root,{'event_id':'read-one','agent':'invest','event_type':'user_input',
            'payload':{'text':'每周展示风险变化。','is_original_user_input':True}})
        code,value,_=self.request('/api/memory/sources/context?event_id=read-one&scope=invest')
        self.assertEqual(code,200);self.assertEqual(value['texts'][0]['text'],'每周展示风险变化。')
        self.assertEqual(self.request('/api/memory/sources/context?event_id=read-one&scope=cards-master')[0],400)
        self.assertNotEqual(self.request('/api/memory/sources/original?event_id=read-one&scope=invest&snapshot_id=../../etc/passwd')[0],200)

    def test_local_correction_roundtrip_does_not_write_owner_record(self):
        self.open();append_event(self.root,{'event_id':'feedback-one','agent':'invest','event_type':'user_input',
            'payload':{'text':'我希望报告先给结论。','is_original_user_input':True}})
        code,context,_=self.request('/api/memory/local-feedback/context?event_id=feedback-one&scope=invest')
        self.assertEqual(code,200)
        code,result,_=self.request('/api/memory/local-feedback',{**context['bindings'],'label':'keep','command_id':'correct-one'})
        self.assertEqual(code,200);self.assertEqual(result['authority'],'local_user_feedback')
        self.assertFalse((self.root/'memory/feedback/items').exists())

    def test_key_configuration_does_not_echo_secret_or_accept_extra_identity(self):
        self.open();module=types.ModuleType('memory_model_config');calls=[]
        def configure(root,**body):
            calls.append(body);return {'status':'ready','key_configured':True,'model':body['model'],'revision':1,'verified':False}
        module.configure=configure
        with patch.dict(sys.modules,{'memory_model_config':module}):
            request={'model':'test-model','api_key':'synthetic-secret','expected_revision':0}
            code,value,_=self.request('/api/memory/model',request);self.assertEqual(code,200)
            self.assertNotIn('synthetic-secret',json.dumps(value))
            self.assertFalse(value['verified']);self.assertEqual(calls[0]['api_key'],'synthetic-secret')
            self.assertEqual(self.request('/api/memory/model',{**request,'base_url':'https://evil.example'})[0],400)
            (self.root/'state/recovery-hold.json').write_text(json.dumps({'hold':True}))
            self.assertEqual(self.request('/api/memory/model',request)[0],423)
            self.assertEqual(len(calls),1)


if __name__=='__main__':unittest.main()
