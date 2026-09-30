"""Only opaque review references leave the local notification reader."""
import json
import shutil
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from memory_attention import snapshot, changes
from javis_memory_adapter.review_policy import digest


class AttentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def candidate(self, status="pending_review"):
        payload = {"scope": "invest", "private_fact": "NEVER EXPORT THIS BODY"}
        row = {"candidate_id": "candidate_" + "a" * 32, "version_digest": digest(payload),
               "payload": payload, "status": status}
        path = self.root / "memory/quarantine/invest/candidates.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as stream:
            stream.write(json.dumps(row) + "\n")

    def test_empty_read_is_quiet_and_does_not_create_state(self):
        data = snapshot(self.root)
        self.assertFalse(changes(data)["notify"])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_pending_alerts_once_without_exporting_body(self):
        self.candidate()
        data = snapshot(self.root)
        self.assertTrue(changes(data)["notify"])
        self.assertEqual(changes(data)["new_items"], 1)
        self.assertFalse(changes(snapshot(self.root), data)["notify"])
        self.assertNotIn("NEVER EXPORT", json.dumps(data))
        self.assertFalse(data["confirmation_authority"])
        self.candidate("confirmed")
        self.assertEqual(snapshot(self.root)["candidates"], 0)
        self.assertFalse(changes(snapshot(self.root), data)["notify"])

    def test_corrupt_record_is_an_integrity_alert_not_a_candidate(self):
        self.candidate()
        path = self.root / "memory/quarantine/invest/candidates.jsonl"
        path.write_text(path.read_text().replace("NEVER EXPORT", "tampered"))
        data = snapshot(self.root)
        self.assertEqual(data["invalid_records"], 1)
        self.assertEqual(data["candidates"], 0)
        self.assertTrue(changes(data)["notify"])
        self.assertFalse(changes(data, data)["notify"])

    def test_actual_ui_automatic_mode_updates_badge_without_signature_modal(self):
        app = Path(__file__).resolve().parents[1] / 'tools/control-panel/web/app.js'
        script = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const nodes=new Map(),storage=new Map();let showCount=0;
class Element{constructor(tag){this.tag=tag;this.children=[];this.open=false;}append(...x){this.children.push(...x);}replaceChildren(...x){this.children=x;}showModal(){this.open=true;showCount++;}close(){this.open=false;}}
const get=id=>{if(!nodes.has(id))nodes.set(id,new Element('div'));return nodes.get(id);};
const context={document:{getElementById:get,createElement:t=>new Element(t),querySelectorAll:()=>[],querySelector:()=>get('memory-nav'),body:new Element('body')},
crypto:{randomUUID:()=> 'synthetic'},window:{location:{hash:''}},setInterval:()=>{},Uint8Array,Map,JSON,Date,Error,
sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v)},
fetch:async()=>({ok:false,status:403,json:async()=>({error:'synthetic_no_session'})})};
vm.createContext(context);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
const data={pending_tokens:['candidate:synthetic'],candidates:1,triage_items:0};
context.data=data;
vm.runInContext("api=async(path)=>{if(path!='/api/memory/attention')throw Error('unexpected_mutation');return data;}",context);
(async()=>{
await vm.runInContext('memoryAttention()',context);assert.equal(showCount,0);
assert(get('memory-nav').textContent.includes('待整理 1'));
await vm.runInContext('memoryAttention()',context);assert.equal(showCount,0);
data.pending_tokens.push('triage:synthetic');data.triage_items=1;
await vm.runInContext('memoryAttention()',context);assert.equal(showCount,0);
assert(get('memory-nav').textContent.includes('待整理 2'));
vm.runInContext("selectTab('memory')",context);assert.equal(context.window.location.hash,'memory');assert.equal(get('memory').hidden,false);assert.equal(get('tasks').hidden,true);
console.log('PASS: automatic mode badge, no signature modal, memory deep link');
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run([shutil.which('node') or 'node', '-e', script, str(app)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
