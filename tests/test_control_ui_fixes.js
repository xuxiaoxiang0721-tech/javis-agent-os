// Runs the actual UI functions with a minimal local DOM and synthetic backend.
const fs=require('fs'), vm=require('vm'), assert=require('assert');
const path=require('path');const staged=path.join(__dirname,'web/app.js');
const source=fs.readFileSync(fs.existsSync(staged)?staged:path.join(__dirname,'../tools/control-panel/web/app.js'),'utf8');
class Element {
  constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.value='';this.disabled=false;this.hidden=false;}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=[...items];}
}
async function fixture(){
  const nodes=new Map();const get=id=>{if(!nodes.has(id))nodes.set(id,new Element('div'));return nodes.get(id);};
  for(const id of ['direct','memory','fixed','system'])get(id).hidden=true;
  let status={ok:true,task_id:'task-test',role_id:'cards-master',state:'failed',goal_revision:1,applied_goal_revision:1,attempt:1,
    commands:[],goals:[],dispatch:{status:'completed'},failure_reason:'synthetic last action',memory_status:'ok',delivery_status:[]};
  const calls=[],confirms=[];let agree=false, failTasks=false, clock='08:00:00';
  const context={document:{getElementById:get,createElement:tag=>new Element(tag),querySelectorAll:()=>[],querySelector:()=>get('memory-tab')},
    crypto:{randomUUID:()=> 'synthetic-command'},window:{confirm:text=>{confirms.push(text);return agree;}},
    setInterval:()=>{},Uint8Array,Map,JSON,Date:class extends Date{toLocaleTimeString(){return clock;}},Error,
    fetch:async(path,options={})=>{
      const body=options.body?JSON.parse(options.body):null;calls.push({path,body});let value;
      if(path==='/api/auth/info')value={configured:true,enrollment_open:false};
      else if(path==='/api/auth/session')return{ok:false,status:403,json:async()=>({error:'not_logged_in'})};
      else if(path==='/api/roles')value={ok:true,roles:['gpt-star','invest','operations','property','idea-lab','cards-master','personal-life','ai-data','domestic-fund'].map(role_id=>({role_id,label:'Label '+role_id}))};
      else if(path==='/api/tasks'){if(failTasks)throw new Error('synthetic connection failure');value={ok:true,tasks:[status]};}
      else if(path==='/api/memory/attention')value={candidates:0,triage_items:0,pending_tokens:[]};
      else if(path==='/api/tasks/task-test')value={...status};
      else if(path.endsWith('/commands'))value={ok:true,status:'received',goal_revision:1,applied_goal_revision:1};
      else if(path.endsWith('/result'))return{ok:false,status:404,json:async()=>({error:'result_pending'})};
      else throw new Error('Unexpected synthetic endpoint '+path);
      return{ok:true,status:200,json:async()=>value};
    }};
  vm.createContext(context);vm.runInContext(source,context);await new Promise(resolve=>setImmediate(resolve));
  await vm.runInContext("detail('task-test')",context);
  return{context,nodes,calls,confirms,setStatus:change=>Object.assign(status,change),agree:value=>agree=value,
    run:code=>vm.runInContext(code,context),offline:value=>failTasks=value,time:value=>clock=value};
}
(async()=>{
  const f=await fixture();
  await f.run("taskCommand('retry')");assert.equal(f.confirms.length,1);assert.equal(f.calls.filter(x=>x.path.endsWith('/commands')).length,0);
  f.agree(true);await f.run("taskCommand('retry')");const sent=f.calls.filter(x=>x.path.endsWith('/commands')).at(-1).body;
  assert.equal(sent.review_confirmed,true);assert.equal(sent.expected_attempt,1);
  f.setStatus({state:'running'});const previousConfirms=f.confirms.length;await f.run("taskCommand('pause')");
  assert.equal(f.confirms.length,previousConfirms);assert.equal(f.calls.filter(x=>x.path.endsWith('/commands')).at(-1).body.review_confirmed,undefined);
  await f.run("detail('task-test')");const input=f.run('detailView.input');input.value='Draft remains exactly\r\n中文';input.oninput();
  f.setStatus({state:'paused',attempt:2,goal_revision:2,applied_goal_revision:1});await f.run('refresh()');
  assert.strictEqual(f.run('detailView.input'),input);assert.equal(input.value,'Draft remains exactly\r\n中文');
  assert.equal(f.run('detailView.state.state'),'paused');assert.equal(f.run('detailView.buttons.continue.disabled'),false);
  f.setStatus({state:'failed',memory_repair_required:true});await f.run("detail('task-test')");
  assert.equal(f.run('detailView.buttons.retry.disabled'),true);const count=f.calls.filter(x=>x.path.endsWith('/commands')).length;
  await f.run("taskCommand('retry')");assert.equal(f.calls.filter(x=>x.path.endsWith('/commands')).length,count);
  const connection=await fixture();connection.offline(true);await connection.run('refresh()');
  assert.equal(connection.nodes.get('connection').textContent,'失联/未登录 · 从未成功连接');
  connection.offline(false);connection.time('09:41:23');await connection.run('refresh()');
  assert.equal(connection.nodes.get('connection').textContent,'已连接 · 09:41:23');
  connection.time('09:42:59');connection.offline(true);await connection.run('refresh()');
  assert.equal(connection.nodes.get('connection').textContent,'失联/未登录 · 最后成功更新时间：09:41:23');
  assert.equal(connection.nodes.get('notice').textContent,'synthetic connection failure');
  connection.time('09:43:59');await connection.run('refresh()');
  assert.equal(connection.nodes.get('connection').textContent,'失联/未登录 · 最后成功更新时间：09:41:23');
  connection.offline(false);connection.time('09:45:00');await connection.run('refresh()');
  assert.equal(connection.nodes.get('connection').textContent,'已连接 · 09:45:00');
  const roles=await fixture();await roles.run('loadRoles()');const select=roles.nodes.get('role');assert.equal(select.children.length,9);assert.equal(select.children.find(o=>o.value==='property').textContent,'Label property');assert.equal(select.children.some(o=>o.value==='waiting-lounge'),false);assert.equal(select.value,'cards-master');assert.equal(select.disabled,false);assert.equal(roles.nodes.get('submit').disabled,false);
  console.log('PASS 7 UI behavior cases: nine-role catalog,  explicit reviewed retry, cancel review, normal pause, live draft preservation, memory repair guard, last successful refresh time survives connection failures');
})().catch(error=>{console.error(error);process.exitCode=1;});
