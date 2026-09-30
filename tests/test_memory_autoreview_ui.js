'use strict';
// Actual shipped UI in an isolated DOM/API double; no browser, model or network.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const source=fs.readFileSync(path.join(__dirname,'../tools/control-panel/web/app.js'),'utf8');
class Element{
  constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.value='';this.hidden=false;this.disabled=false;this.dataset={};}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=items;}
  set innerHTML(_){throw Error('Unsafe HTML rendering');}
}
const text=e=>e.textContent+' '+e.children.map(text).join(' ');
const buttons=e=>[...(e.tag==='button'?[e]:[]),...e.children.flatMap(buttons)];
const gate=()=>{let resolve;const promise=new Promise(r=>resolve=r);return{promise,resolve};};
const settle=async()=>{for(let i=0;i<8;i++)await new Promise(r=>setImmediate(r));};
async function fixture(options={}){
  const nodes=new Map(),get=id=>{if(!nodes.has(id))nodes.set(id,new Element('div'));return nodes.get(id);};
  get('workspace').hidden=true;
  const nav=['tasks','direct','memory','usage','fixed','system'].map(name=>{const e=new Element('button');e.dataset.tab=name;return e;});
  const calls=[],timers=[],state={enabled:true,revision:4,failStatus:false,failWrite:false,expired:false,writeGate:null,statusGate:null,
    recent:[{decision_id:'ai-review-1',expected_version:'exact-record-digest',kind:'accept',status:'accept',scope:'invest',
      fact:'<img src=x onerror=alert(1)> 这是模型整理的来源说法',source_excerpt:'原文 <script>不执行</script>',reason:'保留来源边界',
      source_event_id:'raw-1',decided_at:'2026-09-30T01:00:00Z',withdrawable:true,human_confirmed:false}]};
  let sessions=0,uuid=0;const response=(status,body)=>({ok:status>=200&&status<300,status,json:async()=>body});
  const status=()=>({mode:'automatic',enabled:state.enabled,revision:state.revision,
    counts:{accepted:state.recent.filter(x=>x.status==='accept').length,archived:2,needs_user:3,withdrawn:state.recent.filter(x=>x.status==='withdrawn').length},
    recent:JSON.parse(JSON.stringify(state.recent))});
  const context={document:{getElementById:get,createElement:tag=>new Element(tag),querySelectorAll:()=>nav,querySelector:()=>nav[2]},
    window:{location:{hash:options.hash??'#memory'},isSecureContext:false},navigator:{},
    sessionStorage:{getItem:()=>null,setItem:()=>{}},crypto:{randomUUID:()=> 'memory-command-'+(++uuid)},
    setInterval:fn=>timers.push(fn),Uint8Array,Map,JSON,Date,Error,URLSearchParams,encodeURIComponent,
    fetch:async(url,request={})=>{
      const body=request.body?JSON.parse(request.body):null;calls.push({url,method:request.method||'GET',body,headers:request.headers||{}});
      if(url==='/api/auth/info')return response(200,{configured:false,enrollment_open:false});
      if(url==='/api/auth/session')return response(403,{error:'owner_verification_required'});
      if(url==='/api/memory/session'){sessions++;state.expired=false;return response(200,{ok:true,kind:'local_memory',csrf:'memory-csrf-'+sessions});}
      if(state.expired)return response(403,{error:'memory_session_required',message:'请重新打开本机记忆'});
      if(url==='/api/memory/autoreview'){
        if(state.failStatus)throw Error('synthetic unavailable');const value=status();
        if(state.statusGate){const pending=state.statusGate;state.statusGate=null;await pending.promise;}
        return response(200,value);
      }
      if(url==='/api/memory/triage')return response(200,{items:[],total:0,invalid_records:0});
      if(url==='/api/memory/attention')return response(200,{candidates:48,triage_items:415,pending_tokens:['old']});
      if(url==='/api/memory/autoreview/control'){
        if(state.writeGate)await state.writeGate.promise;
        if(state.failWrite)return response(400,{error:'stale_autoreview_revision',message:'状态已变化'});
        assert.equal(body.expected_revision,state.revision);state.enabled=body.action==='resume';state.revision++;
        return response(200,{enabled:state.enabled,revision:state.revision});
      }
      if(url==='/api/memory/autoreview/withdraw'){
        if(state.failWrite)return response(400,{error:'stale_ai_decision',message:'记录已变化'});
        const item=state.recent.find(x=>x.decision_id===body.decision_id);assert.equal(body.expected_version,item.expected_version);
        item.status='withdrawn';item.withdrawable=false;return response(200,{action:'revoke'});
      }
      throw Error('Unexpected synthetic endpoint '+url);
    }};
  vm.createContext(context);vm.runInContext(source,context);await settle();
  return{get,state,calls,nav,run:code=>vm.runInContext(code,context),tick:async()=>{timers.forEach(fn=>fn());await settle();},
    count:url=>calls.filter(x=>x.url===url).length,button:(id,label)=>buttons(get(id)).find(x=>x.textContent===label)};
}
let passed=0;const names=[];
async function test(name,fn){await fn();passed++;names.push(name);console.log('PASS '+name);}
(async()=>{
  await test('memory deep link works without WebAuthn, owner session or task access',async()=>{
    const f=await fixture();assert(f.get('auth').hidden);assert(!f.get('workspace').hidden);assert.equal(f.run('memoryOnly'),true);
    assert.equal(f.run('csrf'),'');assert.equal(f.count('/api/memory/session'),1);
    assert(!f.calls.some(x=>x.url.startsWith('/api/auth/')||x.url.startsWith('/api/tasks')));
    assert(f.nav.filter(x=>!['memory','usage'].includes(x.dataset.tab)).every(x=>x.hidden));
    assert(f.get('memory-owner-tools').hidden);assert(text(f.get('memory-list')).includes('AI 已接纳'));
  });
  await test('login page has a usable memory entry on unsupported browsers',async()=>{
    const f=await fixture({hash:''});assert(f.get('login').disabled);assert(!f.get('memory-open').disabled);
    await f.get('memory-open').onclick();assert(f.get('auth').hidden);assert.equal(f.run('memoryOnly'),true);
    assert.equal(f.count('/api/auth/login/begin'),0);
  });
  await test('AI provenance, counts, source excerpt and unsafe text render as plain text',async()=>{
    const f=await fixture(),content=text(f.get('memory-list'));assert(content.includes('<img src=x onerror=alert(1)>'));
    assert(content.includes('原文 <script>不执行</script>'));assert(content.includes('AI 审核编号：ai-review-1'));
    assert(text(f.get('memory-auto-state')).includes('AI 接纳 1 · 归档 2 · 待澄清 3 · 已撤回 0'));
    assert(!content.includes('本人已确认'));assert(text(f.get('memory-auto-state')).includes('不授予交易'));
  });
  await test('pause and resume are exact-version memory CSRF requests with no signature',async()=>{
    const f=await fixture();await f.button('memory-auto-state','暂停自动整理').onclick();
    let sent=f.calls.filter(x=>x.url.endsWith('/control')).at(-1);
    assert.equal(sent.body.action,'pause');assert.equal(sent.body.expected_revision,4);assert.equal(sent.headers['X-Javis-Memory-CSRF'],'memory-csrf-1');
    assert(!('assertion' in sent.body));assert(!('actor_id' in sent.body));assert(f.button('memory-auto-state','恢复自动整理'));
    await f.button('memory-auto-state','恢复自动整理').onclick();sent=f.calls.filter(x=>x.url.endsWith('/control')).at(-1);
    assert.equal(sent.body.action,'resume');assert.equal(sent.body.expected_revision,5);
    assert(!f.calls.some(x=>x.url.includes('/challenge')||x.url.includes('/auth/login')));
  });
  await test('withdraw binds exact decision ID and record version and retains source',async()=>{
    const f=await fixture();await f.button('memory-list','撤回此条整理结果').onclick();
    const sent=f.calls.find(x=>x.url.endsWith('/withdraw')).body;
    assert.equal(sent.decision_id,'ai-review-1');assert.equal(sent.expected_version,'exact-record-digest');assert(sent.command_id);
    assert(text(f.get('memory-list')).includes('已撤回'));assert(text(f.get('memory-list')).includes('原文 <script>不执行</script>'));
    assert(!f.button('memory-list','撤回此条整理结果'));
  });
  await test('concurrent memory controls cannot submit twice',async()=>{
    const f=await fixture();f.state.writeGate=gate();const pending=f.run("memoryControl('pause')");await settle();
    await f.run("memoryControl('pause')");assert.equal(f.count('/api/memory/autoreview/control'),1);
    assert(buttons(f.get('memory-auto-state')).every(x=>x.disabled));assert(buttons(f.get('memory-list')).every(x=>x.disabled));
    f.state.writeGate.resolve();await pending;assert(f.button('memory-auto-state','恢复自动整理'));
  });
  await test('failed control does not optimistically display success or change mode',async()=>{
    const f=await fixture();f.state.failWrite=true;await f.button('memory-auto-state','暂停自动整理').onclick();
    assert(f.button('memory-auto-state','暂停自动整理'));assert(f.get('notice').textContent.includes('状态已变化'));
    assert(!f.get('notice').textContent.includes('已暂停自动整理'));
  });
  await test('failed withdrawal preserves the visible record and gives the server error',async()=>{
    const f=await fixture();f.state.failWrite=true;await f.button('memory-list','撤回此条整理结果').onclick();
    assert(f.button('memory-list','撤回此条整理结果'));assert(f.get('notice').textContent.includes('记录已变化'));
    assert(text(f.get('memory-list')).includes('AI 已接纳'));
  });
  await test('unavailable state clears stale write controls until refresh succeeds',async()=>{
    const f=await fixture();f.state.failStatus=true;await f.get('memory-refresh').onclick();
    assert.equal(f.run('memoryState'),null);assert.equal(buttons(f.get('memory-auto-state')).length,0);assert.equal(buttons(f.get('memory-list')).length,0);
    f.state.failStatus=false;await f.get('memory-refresh').onclick();assert(f.button('memory-auto-state','暂停自动整理'));
  });
  await test('memory capability expiry recovers without redirecting to owner login',async()=>{
    const f=await fixture();f.state.expired=true;await f.get('memory-refresh').onclick();assert.equal(f.run('memoryCsrf'),'');
    assert(f.get('auth').hidden);await f.get('memory-refresh').onclick();assert.equal(f.count('/api/memory/session'),2);
    assert(f.button('memory-auto-state','暂停自动整理'));assert.equal(f.count('/api/auth/login/begin'),0);
  });
  await test('late status response cannot overwrite a newer pause result',async()=>{
    const f=await fixture();const pendingGate=gate();f.state.statusGate=pendingGate;const old=f.run('loadAutoreview()');await settle();
    await f.run("memoryControl('pause')");assert(f.button('memory-auto-state','恢复自动整理'));pendingGate.resolve();await old;
    assert(f.button('memory-auto-state','恢复自动整理'));assert.equal(f.run('memoryState.enabled'),false);
  });
  await test('memory-only navigation cannot reveal task controls',async()=>{
    const f=await fixture();f.run("selectTab('tasks')");assert.equal(f.run('activeTab'),'memory');assert(f.get('tasks').hidden);
    await f.get('owner-workspace').onclick();assert(!f.get('auth').hidden);assert(f.get('workspace').hidden);assert.equal(f.count('/api/tasks'),0);
  });
  await test('large pending queue updates badge without modal or signed actions',async()=>{
    const f=await fixture();await f.run('memoryAttention()');assert(f.nav[2].textContent.includes('463'));
    assert(!f.get('memory-attention-dialog').open);assert(!f.calls.some(x=>x.url.includes('/challenge')));
  });
  await test('ordinary memory remains usable after an owner session expires',async()=>{
    const f=await fixture();f.run("memoryOnly=false;csrf='expired-owner';activeTab='memory'");await f.run('refresh()');
    assert(f.get('auth').hidden);assert.equal(f.count('/api/tasks'),0);assert.equal(f.count('/api/memory/learning'),0);
    assert(f.button('memory-auto-state','暂停自动整理'));
  });
  await test('not-configured mode and unknown counts are not shown as completed zero work',async()=>{
    const f=await fixture();f.run("renderAutoreview({mode:'not_configured',enabled:false,revision:0,counts:{},recent:[]})");
    assert(text(f.get('memory-auto-state')).includes('尚未启用'));assert(text(f.get('memory-auto-state')).includes('AI 接纳 未知'));
    assert(f.button('memory-auto-state','启用自动整理'));assert(text(f.get('memory-list')).includes('未经处理的旧记录'));
  });
  console.log(JSON.stringify({status:'PASS',passed,real_model_calls:false,real_network_calls:false,cases:names}));
})().catch(error=>{console.error(error);process.exitCode=1;});
