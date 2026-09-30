"""Owner-only read-only triage presentation; no path to approve unresolved sources."""
import copy
import json
import shutil
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE/'scripts'), str(CODE/'tools/memory-adapter')]
import test_control_http as support

class TriageHTTPTests(unittest.TestCase):
    request = support.HTTPTests.request

    def setUp(self):
        support.HTTPTests.setUp(self)
        self.calls = []
        self.data = {'items': [{'triage_id': 'triage_test', 'source_event_id': 'source_1',
            'reason_code': 'verification_uncertain', 'status': 'needs_review',
            'scope': 'invest', 'source_integrity': 'verified', 'stage': 'verification'}],
            'total': 1, 'invalid_records': 0}
        module = types.ModuleType('memory_triage')
        def pending(root, *, limit):
            self.assertEqual(root, self.root)
            self.assertEqual(limit, 100)
            self.calls.append('read')
            return copy.deepcopy(self.data)
        module.list_pending = pending
        mocked = patch.dict(sys.modules, {'memory_triage': module})
        mocked.start(); self.addCleanup(mocked.stop)

    def test_owner_required_before_read(self):
        self.assertEqual(self.request('/api/memory/triage')[0], 403)
        self.assertEqual(self.calls, [])

    def test_owner_get_allowlists_fields(self):
        self.data['items'][0].update(prompt='private-do-not-return', original_source='secret-source')
        code, result = self.request('/api/memory/triage', auth=True)
        self.assertEqual(code, 200)
        self.assertTrue(result['read_only'])
        self.assertEqual(result['total'], 1)
        self.assertNotIn('private-do-not-return', json.dumps(result))
        self.assertNotIn('secret-source', json.dumps(result))

    def test_cannot_confirm_or_mutate_triage(self):
        for action in ('confirm', 'resolve', 'delete'):
            self.assertEqual(self.request('/api/memory/triage', {'action': action}, auth=True)[0], 404)
        self.assertEqual(self.calls, [])

    def test_service_expired_session_host_and_origin_denied(self):
        with patch.object(support.panel.Handler, 'boundary', return_value=True):
            self.assertEqual(self.request('/api/memory/triage')[0], 403)
        for headers in ({'Host': 'evil.example'}, {'Origin': 'https://evil.example'}):
            self.assertEqual(self.request('/api/memory/triage', auth=True, headers=headers)[0], 403)
        self.app.auth.sessions['test-only-session']['expires'] = 1
        self.assertEqual(self.request('/api/memory/triage', auth=True)[0], 403)
        self.assertEqual(self.calls, [])

class TriageRendererTests(unittest.TestCase):
    def test_real_renderer_uses_text_has_no_confirmation_and_exposes_integrity(self):
        source = CODE / 'tools/control-panel/web/app.js'
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node.js required for actual UI rendering test')
        script = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
class Element {constructor(tag){this.tag=tag;this.children=[];this.textContent='';}append(...x){this.children.push(...x);}replaceChildren(...x){this.children=x;}}
const nodes=new Map(),get=id=>{if(!nodes.has(id))nodes.set(id,new Element('div'));return nodes.get(id);};
const context={document:{getElementById:get,createElement:t=>new Element(t),querySelectorAll:()=>[]},
crypto:{randomUUID:()=> 'test'},window:{},setInterval:()=>{},Uint8Array,Map,JSON,Date,Error,
fetch:async()=>({ok:false,status:403,json:async()=>({error:'no-session'})})};
vm.createContext(context);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
vm.runInContext(`renderMemoryTriage({items:[{source_event_id:'<script>marker</script>',scope:'invest',stage:'verification',reason_code:'validity_missing',source_integrity:'changed_or_unavailable',triage_id:'triage_test',prompt:'hidden-marker'}],total:101,invalid_records:1})`,context);
const walk=e=>[e,...e.children.flatMap(walk)],elements=walk(get('memory-triage')),text=elements.map(e=>e.textContent).join(' ');
assert(text.includes('<script>marker</script>'));assert(!elements.some(e=>['script','button','input','a'].includes(e.tag)));
assert(text.includes('来源已变化'));assert(text.includes('生效时间缺少依据'));assert(text.includes('共 101 条'));
assert(!text.includes('hidden-marker'));assert(text.includes('无法验证'));
vm.runInContext('renderMemoryTriage({items:[],total:0,invalid_records:0})',context);
assert(walk(get('memory-triage')).map(e=>e.textContent).join(' ').includes('没有待补充证据'));
'''
        result = subprocess.run([node, '-e', script, str(source)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

if __name__ == '__main__':
    unittest.main()
