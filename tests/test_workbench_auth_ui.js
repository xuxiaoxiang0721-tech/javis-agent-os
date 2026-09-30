'use strict';
// Executes the shipped browser code with isolated DOM/HTTP/WebAuthn doubles.
// No browser credential, production data, network, or model call is used.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const source=fs.readFileSync(path.join(__dirname,'../tools/control-panel/web/app.js'),'utf8');
class Element {
  constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.value='';this.disabled=false;this.hidden=false;this.open=false;}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=items;}
  close(){this.open=false;}
  showModal(){this.open=true;}
}
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
const settle=async()=>{for(let i=0;i<5;i++)await new Promise(resolve=>setImmediate(resolve));};
async function fixture(options={}){
  const nodes=new Map(),get=id=>{if(!nodes.has(id))nodes.set(id,new Element('div'));return nodes.get(id);};
  get('workspace').hidden=true;for(const name of ['direct','memory','usage','fixed','system'])get(name).hidden=true;
  const state={info:{configured:options.configured??false,enrollment_open:options.enrollment_open??false},
    failInfo:!!options.failInfo,sessionStatus:options.sessionStatus??403,failSession:false,protectedStatus:200,failRoles:!!options.failRoles,
    credentialError:null,credentialGate:null,infoGate:options.infoGate||null,sessionGate:null};
  const calls=[],timers=[];let credentials=0;
  const response=(status,body)=>({ok:status>=200&&status<300,status,json:async()=>body});
  const context={document:{getElementById:get,createElement:tag=>new Element(tag),querySelectorAll:()=>[],querySelector:()=>get('memory-tab')},
    window:{location:{hash:''},isSecureContext:true},sessionStorage:{getItem:()=>null,setItem:()=>{}},
    crypto:{randomUUID:()=> 'synthetic-command'},setInterval:fn=>timers.push(fn),Uint8Array,Map,JSON,Date,Error,URLSearchParams,encodeURIComponent,
    atob:s=>Buffer.from(s,'base64').toString('binary'),btoa:s=>Buffer.from(s,'binary').toString('base64'),
    fetch:async(url,request={})=>{
      calls.push({url,method:request.method||'GET',body:request.body?JSON.parse(request.body):null});
      if(url==='/api/auth/info'){
        if(state.infoGate)await state.infoGate.promise;
        if(state.failInfo)throw Error('synthetic network unavailable');
        return response(200,{...state.info});
      }
      if(url==='/api/auth/session'){
        if(state.sessionGate)await state.sessionGate.promise;
        if(state.failSession)throw Error('synthetic session probe offline');
        return state.sessionStatus===200?response(200,{ok:true,csrf:'restored-session'}):response(state.sessionStatus,{error:'owner_verification_required',message:'synthetic session status'});
      }
      if(/^\/api\/auth\/(login|enroll)\/begin$/.test(url))return response(200,{request_id:'synthetic-challenge',options:{publicKey:{challenge:'AA'}}});
      if(/^\/api\/auth\/(login|enroll)\/complete$/.test(url)){state.sessionStatus=200;state.info={configured:true,enrollment_open:false};return response(200,{ok:true,csrf:'new-session'});}
      if(state.protectedStatus!==200)return response(state.protectedStatus,{error:'owner_verification_required',message:'synthetic protected error'});
      if(url==='/api/roles'){if(state.failRoles)throw Error('synthetic role catalog offline');return response(200,{roles:[{role_id:'cards-master',label:'Cards'},{role_id:'invest',label:'Invest'}]});}
      if(url==='/api/tasks')return response(200,{tasks:[]});
      if(url==='/api/memory/attention')return response(200,{candidates:0,triage_items:0,pending_tokens:[]});
      throw Error('Unexpected synthetic endpoint '+url);
    }};
  if(options.supported!==false){
    context.PublicKeyCredential=function(){};
    const makeCredential=async()=>{credentials++;if(state.credentialError)throw state.credentialError;if(state.credentialGate)await state.credentialGate.promise;return{toJSON:()=>({id:'synthetic-only'})};};
    context.navigator={credentials:{create:makeCredential,get:makeCredential}};
  }
  vm.createContext(context);vm.runInContext(source,context);await settle();
  return{nodes,get,state,calls,tick:async()=>{for(const timer of timers)timer();await settle();},
    run:code=>vm.runInContext(code,context),credentials:()=>credentials,count:url=>calls.filter(call=>call.url===url).length};
}
let passed=0;const results=[];
async function test(name,fn){await fn();passed++;results.push(name);console.log('PASS '+name);}
(async()=>{
  await test('closed enrollment opens and closes without page reload',async()=>{
    const f=await fixture();assert(f.get('login').disabled);assert(f.get('enroll').disabled);assert(!f.get('auth-refresh').disabled);
    f.state.info.enrollment_open=true;await f.tick();assert(!f.get('enroll').disabled);assert(f.get('auth-info').textContent.includes('窗口已开启'));
    f.state.info.enrollment_open=false;await f.tick();assert(f.get('enroll').disabled);assert.equal(f.count('/api/auth/info'),3);
    assert(!f.calls.some(call=>call.method==='POST'));
  });
  await test('first network failure recovers automatically and clears only stale network error',async()=>{
    const f=await fixture({failInfo:true});assert(f.get('auth-error').textContent.includes('读取登录状态失败'));
    f.state.failInfo=false;await f.tick();assert.equal(f.get('auth-error').textContent,'');assert(f.get('connection').textContent.includes('服务在线'));
  });
  await test('manual retry restores an existing browser session',async()=>{
    const f=await fixture({configured:true});f.state.sessionStatus=200;await f.get('auth-refresh').onclick();
    assert(f.get('auth').hidden);assert(!f.get('workspace').hidden);assert.equal(f.run('csrf'),'restored-session');
    assert(!f.calls.some(call=>call.method==='POST'));
  });
  await test('active login blocks duplicate credentials and background status replacement',async()=>{
    const f=await fixture({configured:true});f.state.credentialGate=deferred();const pending=f.run('login()');await settle();
    const infoCalls=f.count('/api/auth/info'),text=f.get('auth-info').textContent;
    await f.run('login()');await f.get('auth-refresh').onclick();await f.tick();
    assert.equal(f.count('/api/auth/login/begin'),1);assert.equal(f.credentials(),1);assert.equal(f.count('/api/auth/info'),infoCalls);
    assert.equal(f.get('auth-info').textContent,text);assert(f.get('login').disabled);assert(f.get('auth-refresh').disabled);
    f.state.credentialGate.resolve();await pending;assert(f.get('auth').hidden);assert(!f.get('workspace').hidden);
  });
  await test('enrollment is attempted only after its explicit button action',async()=>{
    const f=await fixture({enrollment_open:true});await f.tick();assert.equal(f.count('/api/auth/enroll/begin'),0);
    await f.run('login(true)');assert.equal(f.count('/api/auth/enroll/begin'),1);assert.equal(f.count('/api/auth/enroll/complete'),1);
    assert(!f.calls.some(call=>/open|enable/.test(call.url)));
  });
  await test('unsupported WebAuthn gives a local browser route without any POST',async()=>{
    const f=await fixture({configured:true,supported:false});assert(f.get('login').disabled);assert(f.get('enroll').disabled);
    assert(f.get('auth-info').textContent.includes('Microsoft Edge 或 Chrome'));assert(f.get('auth-info').textContent.includes('http://localhost:8766'));
    await f.run('login()');assert(!f.calls.some(call=>call.method==='POST'));
  });
  await test('cancelled Windows Hello remains recoverable with a Chinese explanation',async()=>{
    const f=await fixture({configured:true});f.state.credentialError=Object.assign(Error('synthetic cancelled'),{name:'NotAllowedError'});
    await f.run('login()');assert(f.get('auth-error').textContent.includes('已取消或等待超时'));assert(!f.get('login').disabled);
    await f.tick();assert(f.get('auth-error').textContent.includes('已取消或等待超时'));assert.equal(f.count('/api/auth/login/complete'),0);
    f.state.credentialError=null;await f.run('login()');assert(f.get('auth').hidden);assert.equal(f.count('/api/auth/login/complete'),1);
  });
  await test('expired session reveals login, closes modal, and keeps task and source drafts',async()=>{
    const f=await fixture({configured:true});f.state.protectedStatus=403;
    f.run("csrf='expired';detailView={tid:'draft-task',input:{value:'unsubmitted 中文'}};$('auth').hidden=true;$('workspace').hidden=false;$('memory-attention-dialog').open=true");
    f.get('new-text').value='another unsubmitted task';const sourceDraft=new Element('textarea');sourceDraft.value='source correction';f.get('memory-feedback-context').append(sourceDraft);
    await assert.rejects(f.run("api('/api/tasks')"));assert.equal(f.run('csrf'),'');assert(!f.get('auth').hidden);assert(f.get('workspace').hidden);
    assert.equal(f.run("drafts.get('draft-task')"),'unsubmitted 中文');assert.equal(f.get('new-text').value,'another unsubmitted task');
    assert.strictEqual(f.get('memory-feedback-context').children[0],sourceDraft);assert.equal(sourceDraft.value,'source correction');assert(!f.get('memory-attention-dialog').open);
    assert(f.get('auth-error').textContent.includes('重新使用 Windows Hello'));assert.equal(f.count('/api/auth/session'),2);
  });
  await test('CSRF or permission failure with valid session never forces logout',async()=>{
    const f=await fixture({configured:true});f.state.protectedStatus=403;f.state.sessionStatus=200;
    f.run("csrf='valid';$('auth').hidden=true;$('workspace').hidden=false");
    await assert.rejects(f.run("api('/api/memory/challenge',{action:'confirm'})"),error=>error.status===403&&error.code==='owner_verification_required');
    assert.equal(f.run('csrf'),'valid');assert(f.get('auth').hidden);assert(!f.get('workspace').hidden);
    assert.equal(f.count('/api/memory/challenge'),1);
  });
  await test('concurrent protected failures use one read-only session probe',async()=>{
    const f=await fixture({configured:true});f.state.protectedStatus=403;f.state.sessionStatus=200;f.state.sessionGate=deferred();f.run("csrf='valid'");
    const pending=f.run("Promise.allSettled([api('/api/tasks'),api('/api/memory/pending'),api('/api/memory/triage')])");await settle();
    assert.equal(f.count('/api/auth/session'),2);f.state.sessionGate.resolve();await pending;assert.equal(f.count('/api/auth/session'),2);assert.equal(f.run('csrf'),'valid');
  });
  await test('probe network failure does not invent an expired session',async()=>{
    const f=await fixture({configured:true});f.state.protectedStatus=403;f.state.failSession=true;f.run("csrf='valid';$('auth').hidden=true;$('workspace').hidden=false");
    await assert.rejects(f.run("api('/api/tasks')"));assert.equal(f.run('csrf'),'valid');assert(f.get('auth').hidden);
  });
  await test('late expired response cannot erase a newer successful login',async()=>{
    const f=await fixture({configured:true});f.state.protectedStatus=403;f.state.sessionGate=deferred();f.run("csrf='old';$('auth').hidden=true");
    const request=f.run("api('/api/tasks').catch(error=>error.status)");await settle();f.run("csrf='newer-login'");f.state.sessionGate.resolve();await request;
    assert.equal(f.run('csrf'),'newer-login');assert(f.get('auth').hidden);
  });
  await test('in-flight status refresh is shared and cannot overlap credential entry',async()=>{
    const gate=deferred(),f=await fixture({configured:true,infoGate:gate});assert(f.get('auth-refresh').disabled);
    await f.tick();const manual=f.get('auth-refresh').onclick();await f.run('login()');assert.equal(f.count('/api/auth/info'),1);assert.equal(f.credentials(),0);
    gate.resolve();await manual;await settle();assert(!f.get('auth-refresh').disabled);assert(!f.get('login').disabled);
  });
  await test('startup restores a valid cookie without fresh WebAuthn or mutation',async()=>{
    const f=await fixture({configured:true,sessionStatus:200});assert(f.get('auth').hidden);assert(!f.get('workspace').hidden);
    assert.equal(f.credentials(),0);assert.equal(f.run('csrf'),'restored-session');assert(!f.calls.some(call=>call.method==='POST'));
  });
  await test('role catalog outage never locks a verified owner out and retries next refresh',async()=>{
    const f=await fixture({configured:true,sessionStatus:200,failRoles:true});assert(f.get('auth').hidden);assert(!f.get('workspace').hidden);
    assert.equal(f.run('csrf'),'restored-session');assert(f.get('role').disabled);assert(f.get('submit').disabled);assert(f.get('notice').textContent.includes('稍后自动重试'));
    assert.equal(f.count('/api/tasks'),1);assert.equal(f.count('/api/roles'),1);f.state.failRoles=false;await f.tick();
    assert.equal(f.count('/api/roles'),2);assert(!f.get('role').disabled);assert(!f.get('submit').disabled);assert(f.get('auth').hidden);assert.equal(f.get('notice').textContent,'');
  });
  await test('relogin preserves draft role and text when the role remains authorized',async()=>{
    const f=await fixture({configured:true,sessionStatus:200});f.get('role').value='invest';f.get('new-text').value='original draft 中文';
    f.state.sessionStatus=403;f.state.protectedStatus=403;await assert.rejects(f.run("api('/api/tasks')"));assert(f.get('submit').disabled);
    f.state.protectedStatus=200;await f.run('login()');assert.equal(f.get('role').value,'invest');assert.equal(f.get('new-text').value,'original draft 中文');
    assert(!f.get('submit').disabled);assert(!f.get('workspace').hidden);
  });
  console.log(JSON.stringify({status:'PASS',passed,real_model_calls:false,real_network_calls:false,cases:results}));
})().catch(error=>{console.error(error);process.exitCode=1;});
