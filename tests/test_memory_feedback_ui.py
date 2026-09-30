"""Feedback is owner-session data, never a memory-confirmation shortcut."""
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


class FeedbackHTTPTests(unittest.TestCase):
    request = support.HTTPTests.request

    def setUp(self):
        support.HTTPTests.setUp(self)
        self.calls = []
        calls = self.calls
        class Feedback:
            def __init__(self, root): pass
            def context(self, principal, event_id, scope, **kwargs):
                calls.append(('context', event_id, scope, kwargs))
                return {'source_event_id': event_id, 'scope': scope, 'source_text': 'synthetic only'}
            def sources(self, principal, **kwargs):
                calls.append(('sources', kwargs)); return {'items': [], 'total': 0, 'next_cursor': None}
            def list_feedback(self, principal):
                calls.append(('list',)); return {'items': [], 'total': 0}
            def record(self, principal, request):
                calls.append(('record', copy.deepcopy(request)))
                return {'feedback_id': 'feedback-test', 'label': request['label'], 'memory_confirmed': False}
        class Learning:
            def __init__(self, root): pass
            def status(self): return {'status': 'insufficient_feedback'}
        feedback = types.ModuleType('memory_feedback'); feedback.MemoryFeedback = Feedback
        learning = types.ModuleType('memory_learning'); learning.MemoryLearning = Learning
        mocked = patch.dict(sys.modules, {'memory_feedback': feedback, 'memory_learning': learning})
        mocked.start(); self.addCleanup(mocked.stop)

    def test_all_reads_and_writes_require_owner(self):
        for path in ['/api/memory/feedback', '/api/memory/feedback/sources',
                     '/api/memory/feedback/context?event_id=e1&scope=invest', '/api/memory/learning']:
            self.assertEqual(self.request(path)[0], 403)
        self.assertEqual(self.request('/api/memory/feedback', {'label': 'keep'})[0], 403)
        self.assertEqual(self.calls, [])

    def test_csrf_host_origin_and_service_cannot_write(self):
        for headers in [{'X-Javis-CSRF': 'wrong'}, {'Host': 'evil.example'}, {'Origin': 'https://evil.example'}]:
            self.assertEqual(self.request('/api/memory/feedback', {'label': 'keep'}, True, headers)[0], 403)
        with patch.object(support.panel.Handler, 'boundary', return_value=True):
            self.assertEqual(self.request('/api/memory/feedback', {'label': 'keep'})[0], 403)
        self.assertEqual(self.calls, [])

    def test_feedback_uses_session_without_owner_decision_challenge(self):
        with patch.object(self.app.auth, 'begin', side_effect=AssertionError('unneeded repeated challenge')):
            code, value = self.request('/api/memory/feedback', {'label': 'keep', 'command_id': 'c1'}, True)
        self.assertEqual(code, 200); self.assertFalse(value['memory_confirmed'])
        self.assertEqual(self.calls, [('record', {'label': 'keep', 'command_id': 'c1'})])

    def test_context_and_pagination_are_explicit(self):
        from urllib.parse import urlencode
        query = urlencode({'event_id': 'e1', 'scope': 'invest', 'text_path': json.dumps(['payload','messages',2,'text']),
                           'run_id': 'screen_1', 'triage_id': 'triage_1'})
        self.assertEqual(self.request('/api/memory/feedback/context?'+query, auth=True)[0], 200)
        self.assertEqual(self.calls[-1][3]['text_path'], ['payload','messages',2,'text'])
        self.assertEqual(self.request('/api/memory/feedback/sources?cursor=page2', auth=True)[0], 200)
        self.assertEqual(self.calls[-1], ('sources', {'limit':50,'cursor':'page2'}))

    def test_expired_session_and_learning_mutation_closed(self):
        self.assertEqual(self.request('/api/memory/learning', {'action': 'activate'}, True)[0], 404)
        self.app.auth.sessions['test-only-session']['expires'] = 1
        self.assertEqual(self.request('/api/memory/feedback', {'label': 'keep'}, True)[0], 403)
        self.assertEqual(self.calls, [])


class FeedbackRendererTests(unittest.TestCase):
    def test_source_markup_is_text_and_feedback_never_calls_memory_review(self):
        node = shutil.which('node'); self.assertIsNotNone(node)
        code = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
class Element {constructor(tag){this.tag=tag;this.children=[];this.textContent='';}append(...x){this.children.push(...x);}replaceChildren(...x){this.children=x;}}
const nodes=new Map(),get=id=>{if(!nodes.has(id))nodes.set(id,new Element('div'));return nodes.get(id);};
const calls=[];let count=0;
const context={document:{getElementById:get,createElement:t=>new Element(t),querySelectorAll:()=>[]},
crypto:{randomUUID:()=> 'cmd-'+(++count)},window:{},setInterval:()=>{},Uint8Array,Map,JSON,Date,Error,URLSearchParams,encodeURIComponent,
fetch:async(path,options)=>{calls.push([path,options]);let value={};if(path.includes('/context?'))value={source_event_id:'e1',scope:'invest',source_text:'<script>private-marker</script>',source_context:{authorship_verified:false},bindings:{source_digest:'hash',supersedes_feedback_id:null}};
else if(path==='/api/memory/feedback')value={feedback_id:'f1',label:'keep'};
else if(path==='/api/memory/feedback/sources')value={items:[],total:0};
return {ok:true,status:200,json:async()=>value};}};
vm.createContext(context);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
(async()=>{await vm.runInContext("memoryFeedbackContext({source_event_id:'e1',scope:'invest'})",context);
const walk=e=>[e,...e.children.flatMap(walk)],elements=walk(get('memory-feedback-context'));
assert(elements.some(e=>e.tag==='pre'&&e.textContent==='<script>private-marker</script>'));
assert(!elements.some(e=>e.tag==='script'));
const buttons=elements.filter(e=>e.tag==='button');assert.deepStrictEqual(buttons.map(e=>e.textContent),['应该记住','无需记住','需要补充']);
await buttons[0].onclick();const post=calls.find(([p])=>p==='/api/memory/feedback');const body=JSON.parse(post[1].body);
assert.strictEqual(body.label,'keep');assert.strictEqual(body.source_digest,'hash');assert(!('source_text' in body));
assert(!calls.some(([p])=>p==='/api/memory/review'||p==='/api/memory/challenge'));})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run([node, '-e', code, str(CODE/'tools/control-panel/web/app.js')], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


if __name__ == '__main__': unittest.main()
