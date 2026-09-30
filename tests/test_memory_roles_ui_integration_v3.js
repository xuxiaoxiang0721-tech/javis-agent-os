'use strict';
// Run both shipped scripts in index.html order. Only DOM/HTTP/browser facilities
// are doubles: uuid, memoryApi, action and the rendered button callbacks are real.
// This fixture never contacts a browser, a production server or a model.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert'),path=require('node:path');
const {webcrypto,createHash}=require('node:crypto');
const web=path.join(__dirname,'../tools/control-panel/web');
const html=fs.readFileSync(path.join(web,'index.html'),'utf8');
const nodes=new Map();
class Element {
  constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.value='';this.disabled=false;this.hidden=false;this.dataset={};this.attrs={};}
  set id(value){this._id=value;nodes.set(value,this);} get id(){return this._id;}
  append(...values){this.children.push(...values);}
  insertBefore(value,before){let index=this.children.indexOf(before);if(index<0)index=this.children.length;this.children.splice(index,0,value);}
  replaceChildren(...values){this.children=values;}
  setAttribute(key,value){this.attrs[key]=value;}
  querySelectorAll(tag){return this.children.flatMap(child=>[...(child.tag===tag?[child]:[]),...child.querySelectorAll(tag)]);}
  get childElementCount(){return this.children.length;}
  scrollIntoView(){} focus(){} close(){}
  set innerHTML(_){throw Error('Unsafe HTML rendering');}
}
for(const match of html.matchAll(/id="([^"]+)"/g)){const element=new Element('div');element.id=match[1];}
const nav=['tasks','direct','memory','usage','fixed','system'].map(tab=>{const element=new Element('button');element.dataset.tab=tab;return element;});
const clone=value=>JSON.parse(JSON.stringify(value));
const initial={revision:3,global_enabled:false,roles:{invest:true,'cards-master':true},
  role_labels:{invest:'Invest'},daily_call_limit:200,budget:{reserved_calls:0,remaining_calls:200}};
let state=clone(initial);
const calls=[],reply=value=>({ok:true,status:200,json:async()=>clone(value)});
const context={
  document:{activeElement:null,getElementById:id=>nodes.get(id)||null,createElement:tag=>new Element(tag),
    querySelectorAll:()=>nav,querySelector:()=>nav[2]},
  window:{location:{hash:''},isSecureContext:true},navigator:{},
  sessionStorage:{getItem:()=>null,setItem:()=>{}},setInterval:()=>{},
  crypto:webcrypto,URLSearchParams,Uint8Array,Date,Map,JSON,Error,encodeURIComponent,
  fetch:async(url,request={})=>{
    const body=request.body?JSON.parse(request.body):null;
    calls.push({url,method:request.method||'GET',body,headers:request.headers||{}});
    if(url==='/api/auth/info')return reply({configured:false,enrollment_open:false});
    if(url==='/api/auth/session')return {ok:false,status:403,json:async()=>({error:'owner_verification_required'})};
    if(url==='/api/memory/session')return reply({ok:true,kind:'local_memory',csrf:'fixture-memory-csrf'});
    if(url==='/api/memory/controls'){
      if(body){
        assert.equal(request.method,'POST');
        assert.equal(body.expected_revision,state.revision,'request uses current CAS revision');
        assert.equal(request.headers['X-Javis-Memory-CSRF'],'fixture-memory-csrf');
        assert.equal(request.headers['Content-Type'],'application/json');
        assert.match(body.command_id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
          'command ID comes from the real UUID generator');
        assert.deepEqual(Object.keys(body).sort(),['command_id','expected_revision','roles']);
        state={...state,roles:{...state.roles,...body.roles},revision:state.revision+1};
      }
      return reply(state);
    }
    if(url==='/api/memory/model')return reply({revision:0,status:'waiting_for_key',model:'gpt-fixture',key_configured:false});
    if(url==='/api/memory/autoreview')return reply({mode:'paused',enabled:false,revision:3,counts:{},recent:[]});
    if(url==='/api/memory/triage'||url==='/api/memory/supplements')return reply({items:[],total:0});
    throw Error('Unexpected fixture route '+url);
  }
};

async function main(){
  // Do not supply the shared helpers that single-module tests can accidentally
  // mask. Both files must cooperate through the actual browser global scope.
  for(const name of ['uuid','memoryApi','action'])assert(!(name in context));
  vm.createContext(context);
  const scripts=[...html.matchAll(/<script\s+src="\/([^"?]+)(?:\?[^"]*)?"/g)].map(match=>match[1]);
  assert.deepEqual(scripts,['memory-v3.js','app.js'],'follow the shipped classic-script order');
  const sourceHashes={};
  for(const filename of scripts){
    const source=fs.readFileSync(path.join(web,filename),'utf8');
    sourceHashes[filename]=createHash('sha256').update(source).digest('hex');
    vm.runInContext(source,context,{filename});
  }
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(vm.runInContext('typeof uuid',context),'function');
  await vm.runInContext('openMemory()',context);
  const switches=()=>nodes.get('memory-role-controls').querySelectorAll('button')
    .filter(button=>button.attrs.role==='switch');
  const invest=switches().find(button=>button.attrs['aria-label']==='Invest 结构化处理');
  assert(invest,'Invest switch is rendered by the actual application');
  assert.equal(invest.disabled,false);assert.equal(invest.attrs['aria-checked'],'true');
  assert.equal(calls.filter(call=>call.url==='/api/memory/controls'&&call.method==='POST').length,0);

  // Exercise the real action wrapper and callback, not saveMemoryControls().
  await invest.onclick();
  const posts=calls.filter(call=>call.url==='/api/memory/controls'&&call.method==='POST');
  assert.equal(posts.length,1,'one actual button activation submits exactly once');
  assert.deepEqual(posts[0].body.roles,{invest:false});assert.equal(posts[0].body.expected_revision,3);
  assert.equal(state.revision,4);assert.equal(state.roles.invest,false);
  assert.equal(state.global_enabled,initial.global_enabled,'a role click never opens the global paid-processing gate');
  assert.equal(state.roles['cards-master'],initial.roles['cards-master']);
  assert.equal(state.daily_call_limit,initial.daily_call_limit);
  const updated=switches().find(button=>button.attrs['aria-label']==='Invest 结构化处理');
  assert.equal(updated.attrs['aria-checked'],'false');assert.equal(updated.disabled,false);
  assert.equal(vm.runInContext('roleMemoryState.revision',context),4);
  assert(nodes.get('notice').textContent.includes('已保存结构化处理设置'));
  assert(!calls.some(call=>call.url.startsWith('/api/tasks')||call.url.includes('/challenge')||call.url.includes('/auth/login')||call.url.includes('/auth/enroll')));
  assert.equal(calls.filter(call=>call.method==='POST'&&call.url!=='/api/memory/session').length,1);
  console.log(JSON.stringify({status:'PASS',scenario:'shipped_page_invest_switch_click',scripts,source_hashes:sourceHashes,
    controls_posts:posts.length,revision:state.revision,invest_enabled:state.roles.invest,global_enabled:state.global_enabled,
    checks:['real_shared_helpers','actual_button_callback','single_POST','memory_CSRF','CAS','UUID_v4',
      'other_role_unchanged','global_pause_unchanged','rendered_switch_updated','no_owner_confirmation'],
    production_writes:0,real_network_calls:0,real_model_calls:0}));
}
main().catch(error=>{console.error(error);process.exitCode=1;});
