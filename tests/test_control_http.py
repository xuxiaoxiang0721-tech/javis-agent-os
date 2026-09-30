"""HTTP transport tests; isolated session fixture is never a real owner acceptance."""
import importlib.util
import json
import tempfile
import threading
import time
import unittest
import http.client
import sys
from pathlib import Path
from http.server import ThreadingHTTPServer

scripts = Path(__file__).parent if Path(__file__).with_name('control-panel.py').exists() else Path(__file__).parent.parent / 'scripts'
sys.path.insert(0, str(scripts))
spec=importlib.util.spec_from_file_location('panel',scripts/'control-panel.py')
panel=importlib.util.module_from_spec(spec);spec.loader.exec_module(panel)
spec=importlib.util.spec_from_file_location('capture',scripts/'grok-sync.py')
capture=importlib.util.module_from_spec(spec);spec.loader.exec_module(capture)

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='javis-http-test-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.app=panel.App(self.root)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),panel.Handler);self.server.app=self.app
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.app.auth.sessions['test-only-session']={'actor_id':panel.ACTOR,'auth_ref':'test-only-ref','csrf':'test-only-csrf','expires':time.time()+60}

    def request(self,path,body=None,auth=False,headers=None):
        h={'Host':'localhost:8766','Origin':panel.ORIGIN}
        if body is not None:h['Content-Type']='application/json'
        if auth:h.update(Cookie='javis_owner=test-only-session',**{'X-Javis-CSRF':'test-only-csrf'})
        h.update(headers or {})
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        c.request('POST' if body is not None else 'GET',path,json.dumps(body) if body is not None else None,h)
        r=c.getresponse();data=r.read();c.close();return r.status,json.loads(data)

    def test_tasks_hidden_before_owner_login(self):
        code,v=self.request('/api/tasks');self.assertEqual(code,403)
        self.assertNotIn('tasks',v)

    def test_memory_attention_requires_login_and_has_no_confirmation_authority(self):
        code, _ = self.request('/api/memory/attention')
        self.assertEqual(code, 403)
        code, value = self.request('/api/memory/attention', auth=True)
        self.assertEqual(code, 200)
        self.assertEqual(value['pending_tokens'], [])
        self.assertFalse(value['confirmation_authority'])
        self.assertFalse(value['source_bodies_included'])

    def test_fake_owner_fields_not_credentials(self):
        code,_=self.request('/api/tasks',{'actor_id':'owner:local','kind':'owner'})
        self.assertEqual(code,403);self.assertFalse((self.root/'state/tasks').exists())

    def test_host_and_origin_boundaries(self):
        for headers in [{'Host':'evil.example'},{'Origin':'http://evil.example'}]:
            code,_=self.request('/api/tasks',auth=True,headers=headers);self.assertEqual(code,403)

    def test_csrf_required_even_with_cookie(self):
        code,_=self.request('/api/tasks',{'command_id':'csrf'},True,{'X-Javis-CSRF':'invalid'})
        self.assertEqual(code,403)

    def test_submit_persists_then_duplicate_does_not_launch(self):
        req={'command_id':'safe-1','role_id':'cards-master','original_text':'合成只读测试','source_line':2}
        code,r=self.request('/api/tasks',req,True);self.assertEqual(code,202)
        self.assertEqual(r['attempt'],0)
        _,again=self.request('/api/tasks',req,True);self.assertEqual(again['task_id'],r['task_id']);self.assertTrue(again['replayed'])
        _,lookup=self.request('/api/commands/safe-1',auth=True);self.assertEqual(lookup['task_id'],r['task_id'])
        _,status=self.request('/api/tasks/'+r['task_id'],auth=True);self.assertEqual(status['state'],'queued')

    def test_browser_cannot_choose_principal(self):
        req={'command_id':'unsafe-1','role_id':'cards-master','original_text':'test','actor_id':'service:other'}
        code,_=self.request('/api/tasks',req,True);self.assertEqual(code,400)

    def test_body_cannot_enable_enrollment(self):
        code,_=self.request('/api/auth/enroll/begin',{'enrollment_seconds':600,'approved':True})
        self.assertEqual(code,403)

class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='javis-capture-test-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.req={'capture_id':'local-capture-test','role_id':'cards-master','messages':[
            {'speaker':'user','text':'第一行\r\n第二行','fidelity':'forwarded_original_unverified'},
            {'speaker':'grok','text':'摘要仅供参考','fidelity':'summary','urls':['https://example.com/']}],
            'gaps':['not a real Grok export; isolated fixture']}

    def test_exact_text_gaps_and_replay(self):
        first=capture.ingest(self.root,self.req);second=capture.ingest(self.root,self.req)
        self.assertTrue(first['archived']);self.assertTrue(second['replayed']);self.assertFalse(first['memory_confirmed'])
        rows=[json.loads(l) for p in (self.root/'raw/events/grok-sync').glob('*.jsonl') for l in p.read_text().splitlines()]
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['payload']['messages'][0]['text'],'第一行\r\n第二行')
        self.assertIn('URL_references_are_not_saved_page_content',first['gaps'])

    def test_changed_identity_rejected(self):
        capture.ingest(self.root,self.req);self.req['messages'][0]['text']='changed'
        with self.assertRaises(ValueError):capture.ingest(self.root,self.req)

    def test_attachment_outside_intake_is_rejected(self):
        outside=self.root/'private.txt';outside.write_text('synthetic')
        self.req['attachments']=[{'path':str(outside)}]
        with self.assertRaises(ValueError):capture.ingest(self.root,self.req)

    def test_attachment_change_requires_new_capture(self):
        p=self.root/'workspace/inbox/grok-sync/attachments/test.txt';p.parent.mkdir(parents=True);p.write_text('version1')
        self.req['attachments']=[{'path':'test.txt'}];capture.ingest(self.root,self.req);p.write_text('version2')
        with self.assertRaises(ValueError):capture.ingest(self.root,self.req)

    def test_strict_l4_is_retained_locally_without_cloud_queue(self):
        self.req['messages'][0]['text']='L4: test private data'
        result=capture.ingest(self.root,self.req)
        self.assertTrue(result['archived'])
        self.assertEqual(result['screening']['status'],'local_only')
        self.assertFalse(list((self.root/'state/memory-pipeline/queue').glob('*.json')))

if __name__=='__main__':unittest.main(verbosity=2)
