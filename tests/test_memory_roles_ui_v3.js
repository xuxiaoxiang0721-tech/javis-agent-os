'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
class E{
  constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.value='';this.disabled=false;this.attrs={};}
  append(...x){this.children.push(...x);} replaceChildren(...x){this.children=x;}
  setAttribute(k,v){this.attrs[k]=v;} querySelectorAll(tag){return this.children.flatMap(x=>[...(x.tag===tag?[x]:[]),...x.querySelectorAll(tag)]);}
  get childElementCount(){return this.children.length;} scrollIntoView(){} focus(){}
  set innerHTML(x){throw Error('untrusted HTML forbidden');}
}
const clone=x=>JSON.parse(JSON.stringify(x)),text=e=>e.textContent+' '+e.children.map(text).join(' ');
async function main(){
  const nodes=new Map(),get=id=>{if(!nodes.has(id))nodes.set(id,new E('div'));return nodes.get(id);};
  let counter=0,waitWrite=null,fail=false;
  let state={revision:2,global_enabled:false,roles:{invest:true,'cards-master':true,'idea-lab':true,operations:true,property:true,'gpt-star':true,'personal-life':true,'ai-data':true,'domestic-fund':true,javis:true,friday:true,toolgo:true},role_labels:{invest:'Invest bot'},daily_call_limit:200,budget:{reserved_calls:0,remaining_calls:200}};
  const calls=[];
  const context={Map,JSON,Number,String,Object,URLSearchParams,Error,Promise,
    document:{activeElement:null},window:{location:{search:''}},$:get,el:(tag,t)=>{const e=new E(tag);if(t!==undefined)e.textContent=t;return e;},
    usageCount:n=>n??'未知',usageTime:x=>x||'未知',uuid:()=>`command-${++counter}`,
    memoryApi:async(url,body)=>{
      calls.push({url,body:body&&clone(body)});
      if(url==='/api/memory/model')return {revision:0,status:'waiting_for_key',model:'gpt-test-2026-09-30',key_configured:false};
      if(url==='/api/memory/supplements')return {items:[{scope:'invest',state:'accepted_pending_resolution',message_zh:'补充已形成记忆，原问题仍待核验'}]};
      assert.equal(url,'/api/memory/controls');
      if(body){if(waitWrite)await waitWrite;if(fail)throw Error('状态已变化');assert.equal(body.expected_revision,state.revision);state={...state,...body,roles:{...state.roles,...body.roles},revision:state.revision+1};}
      return clone(state);
    }};
  context.action=(title,fn,disabled=false)=>{const e=new E('button');e.textContent=title;e.disabled=disabled;e.onclick=fn;return e;};
  vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../tools/control-panel/web/memory-v3.js'),'utf8'),context);
  const run=code=>vm.runInContext(code,context);
  await run('loadMemoryV3()');
  const switches=()=>get('memory-role-controls').querySelectorAll('button').filter(b=>b.attrs.role==='switch');
  assert.equal(switches().length,12);assert(text(get('memory-role-controls')).includes('RAW 始终接收并保存'));
  assert(text(get('memory-supplement-status')).includes('原问题仍待核验'));
  await run("saveMemoryControls({roles:{invest:false}})");
  assert.equal(state.roles.invest,false);assert.equal(state.roles['cards-master'],true);assert.equal(state.global_enabled,false);
  assert(switches().every(b=>!b.disabled),'buttons recover after successful write');
  assert.deepEqual(calls.find(x=>x.body).body.roles,{invest:false});
  assert(!JSON.stringify(calls).includes('raw_capture_enabled'));
  const old=clone(state);old.revision--;old.roles.invest=true;context.old=old;run('renderRoleMemory(old)');
  assert.equal(run('roleMemoryState.roles.invest'),false,'late read cannot revive an old role setting');
  let release;waitWrite=new Promise(r=>release=r);const pending=run('saveMemoryControls({global_enabled:true})');
  await Promise.resolve();await run('saveMemoryControls({roles:{friday:false}})');
  assert.equal(calls.filter(x=>x.body).length,2,'overlapping controls are not double submitted');
  release();await pending;waitWrite=null;assert.equal(state.roles.friday,true);
  fail=true;await assert.rejects(run('saveMemoryControls({roles:{invest:true}})'),/状态已变化/);
  assert.equal(run('roleMemoryState.roles.invest'),false);assert(switches().every(b=>!b.disabled));fail=false;
  const stateBefore=clone(state);await run('saveMemoryControls({daily_call_limit:0})');assert.equal(state.daily_call_limit,0);assert.deepEqual(state.roles,stateBefore.roles);
  console.log('PASS: 12 role switches, RAW independence, exact CAS, concurrency, stale response, failed-write recovery, zero budget');
}
main().catch(e=>{console.error(e);process.exitCode=1;});
