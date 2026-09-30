'use strict';
// Shipped classic scripts, real button handlers and memoryApi; only DOM/HTTP doubles.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert'),path=require('node:path');
const {webcrypto}=require('node:crypto');
const web=path.join(__dirname,'../tools/control-panel/web');
const html=fs.readFileSync(path.join(web,'index.html'),'utf8'),nodes=new Map();
class E{
  constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.value='';this.disabled=false;this.hidden=false;this.attrs={};this.dataset={};}
  set id(value){this._id=value;nodes.set(value,this);}get id(){return this._id;}
  append(...children){this.children.push(...children);}replaceChildren(...children){this.children=children;}
  insertBefore(child){this.children.push(child);}setAttribute(key,value){this.attrs[key]=value;}
  querySelectorAll(tag){return this.children.flatMap(e=>[...(e.tag===tag?[e]:[]),...e.querySelectorAll(tag)]);}
  get childElementCount(){return this.children.length;}scrollIntoView(){}focus(){}close(){}
  set innerHTML(_){throw Error('unsafe HTML');}
}
for(const match of html.matchAll(/id="([^"]+)"/g)){const node=new E('div');node.id=match[1];}
const nav=['tasks','direct','memory','usage','fixed','system'].map(tab=>{const node=new E('button');node.dataset.tab=tab;return node;});
const clone=x=>JSON.parse(JSON.stringify(x));
let config={revision:1,auth_mode:'api_key',model:'gpt-test',embedding_provider:'openai',status:'waiting_for_key',key_configured:false};
let subscription={account_id:null,accounts:[],connected:false,plan_usage:false};
let authorizationURL='https://auth.openai.com/api/accounts/authorize?state=fixture';
const calls=[],reply=value=>({ok:true,status:200,json:async()=>clone(value)});
const context={document:{activeElement:null,getElementById:id=>nodes.get(id)||null,createElement:tag=>new E(tag),querySelectorAll:()=>nav,querySelector:()=>nav[2]},
  window:{location:{hash:''},isSecureContext:true},navigator:{},sessionStorage:{getItem:()=>null,setItem:()=>{}},setInterval:()=>{},
  crypto:webcrypto,URLSearchParams,Uint8Array,Date,Map,JSON,Error,encodeURIComponent,
  fetch:async(url,request={})=>{
    const body=request.body?JSON.parse(request.body):null;calls.push({url,body});
    if(url==='/api/auth/info')return reply({configured:false,enrollment_open:false});
    if(url==='/api/auth/session')return {ok:false,status:403,json:async()=>({error:'owner_verification_required'})};
    if(url==='/api/memory/session')return reply({csrf:'local-fixture'});
    if(body)assert.equal(request.headers['X-Javis-Memory-CSRF'],'local-fixture');
    if(url==='/api/memory/controls'){assert.equal(body,null);return reply({revision:5,global_enabled:false,roles:{invest:true},daily_call_limit:200,budget:{}});}
    if(url==='/api/memory/model'){
      if(body){assert.equal(body.expected_revision,config.revision);config={...config,...body,revision:config.revision+1};}
      return reply(config);
    }
    if(url==='/api/memory/subscription')return reply(subscription);
    if(url==='/api/memory/subscription/begin')return reply({authorization_url:authorizationURL,expires_in:600});
    if(url==='/api/memory/subscription/models')return reply({account_id:'acct_fixture',models:[{slug:'gpt-subscribed',display_name:'<untrusted model label>'}]});
    if(url==='/api/memory/autoreview')return reply({mode:'paused',enabled:false,counts:{},recent:[]});
    if(url==='/api/memory/triage'||url==='/api/memory/supplements')return reply({items:[]});
    throw Error('Unexpected fixture route '+url);
  }};
async function main(){
  vm.createContext(context);
  for(const filename of [...html.matchAll(/<script\s+src="\/([^"?]+)(?:\?[^\"]*)?"/g)].map(match=>match[1]))vm.runInContext(fs.readFileSync(path.join(web,filename),'utf8'),context,{filename});
  await new Promise(resolve=>setImmediate(resolve));await vm.runInContext('openMemory()',context);
  const button=(id,text)=>{const found=nodes.get(id).querySelectorAll('button').find(e=>e.textContent===text);assert(found,text);return found;};
  const mode=nodes.get('memory-gpt-auth-mode'),key=nodes.get('memory-gpt-key');
  key.value='DO_NOT_SUBMIT_SUBSCRIPTION_AS_API';mode.value='chatgpt_subscription';await mode.onchange();
  assert.equal(key.value,'');assert.equal(nodes.get('memory-subscription-panel').hidden,false);
  assert(!calls.some(c=>c.url==='/api/memory/model'&&c.body));
  await button('memory-subscription-panel','Continue with ChatGPT · 登录').onclick();
  const link=nodes.get('memory-subscription-login-link').children[0];
  assert.equal(link.href,authorizationURL);assert.equal(link.rel,'noopener noreferrer');
  assert.equal(context.window.location.hash,'memory','login only prepares an explicit external link');
  subscription={account_id:'acct_fixture',accounts:[{account_id:'acct_fixture',label:'Local account',connected:true}],connected:true,plan_usage:true};
  await vm.runInContext('loadMemorySubscription()',context);
  await button('memory-subscription-panel','读取订阅可用模型').onclick();
  const choice=nodes.get('memory-subscription-model-choice');choice.value='gpt-subscribed';
  assert.equal(choice.children[0].textContent,'<untrusted model label>');
  await button('memory-subscription-models','使用所选模型').onclick();
  key.value='NEVER_LEAK_HIDDEN_KEY';nodes.get('memory-embedding-provider').value='dashscope';nodes.get('memory-use-legacy-embedding').checked=true;
  await button('memory-model-form','保存 GPT 设置').onclick();
  const saved=calls.find(c=>c.url==='/api/memory/model'&&c.body).body;
  assert.deepEqual(saved,{expected_revision:1,model:'gpt-subscribed',auth_mode:'chatgpt_subscription',embedding_provider:'dashscope',account_id:'acct_fixture',use_legacy_embedding:true});
  assert.equal(key.value,'');assert.equal(nodes.get('memory-use-legacy-embedding').checked,false);
  assert(!calls.some(c=>JSON.stringify(c).includes('NEVER_LEAK')));
  authorizationURL='https://evil.example/authorize';await button('memory-subscription-panel','Continue with ChatGPT · 登录').onclick();
  assert(nodes.get('notice').textContent.includes('官方登录地址无效'));
  assert(!calls.some(c=>c.url==='/api/memory/controls'&&c.body));
  console.log('PASS: official subscription UI, real handlers, explicit login, CSRF, safe model text, account binding, no API fallback, no global enable');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
