'use strict';
const $=id=>document.getElementById(id);let csrf='', selected=null, fixed=null, busy=false, activeTab='tasks';
let detailView=null, detailRequest=0, taskCommandBusy=false, lastSuccessTime=null;const drafts=new Map();
const uuid=()=>crypto.randomUUID();
let memoryCsrf='',memoryOnly=false,memorySessionPromise=null,memoryState=null,memoryOperationBusy=false,memoryLoadVersion=0;
async function ensureMemorySession(){
  if(memoryCsrf)return;if(memorySessionPromise)return memorySessionPromise;
  memorySessionPromise=(async()=>{const r=await fetch('/api/memory/session',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});const v=await r.json();if(!r.ok||v.ok===false)throw new Error(v.message||'无法打开本机记忆管理');memoryCsrf=v.csrf;})();
  try{await memorySessionPromise;}finally{memorySessionPromise=null;}
}
async function memoryApi(path,body){
  await ensureMemorySession();
  const requestCsrf=memoryCsrf;
  const r=await fetch(path,{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json','X-Javis-Memory-CSRF':requestCsrf}:{},body:body?JSON.stringify(body):undefined});
  const v=await r.json();if(!r.ok||v.ok===false){if(v.error==='memory_session_required'&&memoryCsrf===requestCsrf)memoryCsrf='';const error=new Error(v.message||v.error||'记忆服务暂不可用');error.status=r.status;throw error;}return v;
}
function workspaceAccess(){
  for(const b of document.querySelectorAll('[data-tab]'))b.hidden=memoryOnly&&!['memory','usage'].includes(b.dataset.tab);
  $('owner-workspace').hidden=!memoryOnly;$('memory-owner-tools').hidden=memoryOnly;
}
async function openMemory(){
  if(authBusy)return;memoryOnly=true;
  try{await ensureMemorySession();workspaceAccess();$('auth').hidden=true;$('workspace').hidden=false;selectTab('memory');await refresh();}
  catch(error){memoryOnly=false;$('auth-error').textContent='打开记忆管理失败：'+error.message;}
}
async function openOwnerWorkspace(){memoryOnly=false;workspaceAccess();if(csrf)await enter();else{showLogin('任务工作台仍需要本人登录；记忆自动整理继续运行。');await refreshAuthState({restoreSession:true});}}
let authBusy=false,authInfo=null,authRefreshPromise=null,sessionProbePromise=null,authStatusError='',rolesReady=false,roleStatusError='';
function authSupported(){return typeof PublicKeyCredential!=='undefined'&&typeof navigator!=='undefined'&&typeof navigator.credentials?.create==='function'&&typeof navigator.credentials?.get==='function'&&window.isSecureContext!==false;}
function authMessage(error){
  if(error?.name==='NotAllowedError')return 'Windows Hello 已取消或等待超时，没有完成验证。请再次点击登录或登记。';
  if(error?.name==='NotSupportedError'||error?.code==='webauthn_unavailable')return '当前浏览器不支持本机通行密钥验证。请在本机 Microsoft Edge 或 Chrome 打开 http://localhost:8766，再使用 Windows Hello。';
  if(error?.name==='SecurityError')return '此页面无法使用通行密钥。请在本机浏览器打开 http://localhost:8766 后重试。';
  if(error?.name==='InvalidStateError')return '通行密钥状态不匹配。请刷新登录状态；已经登记过的设备请使用登录。';
  if(error?.code==='owner_verification_required')return '验证未完成或登记窗口已关闭。请刷新登录状态后重试。';
  return error?.message||'暂时无法连接，请刷新登录状态后重试。';
}
function renderAuthState(){
  const waiting=authBusy||!!authRefreshPromise,supported=authSupported();
  $('login').disabled=waiting||!supported||!authInfo?.configured;
  $('enroll').disabled=waiting||!supported||!authInfo?.enrollment_open;
  $('auth-refresh').disabled=waiting;
  $('memory-open').disabled=authBusy;
  if(authBusy)return;
  if(!authInfo){$('auth-info').textContent='正在读取本人登录状态；连接恢复后会自动重试，也可手动刷新。';return;}
  $('auth-info').textContent=!supported?authMessage({code:'webauthn_unavailable'}):authInfo.configured?'请本人使用 Windows Hello 登录。登录有效期为 15 分钟，过期后可在此重新登录。':authInfo.enrollment_open?'登记窗口已开启。请点击“登记本机通行密钥”，由你亲自完成 Windows Hello 验证。':'尚未登记本人通行密钥，登记窗口未开启。需先由你同意开启；窗口开启后此页会自动更新，也可点击“刷新登录状态”。';
}
function showLogin(message){
  if(detailView)drafts.set(detailView.tid,detailView.input.value);
  csrf='';rolesReady=false;$('role').disabled=true;$('submit').disabled=true;$('workspace').hidden=true;$('auth').hidden=false;
  const dialog=$('memory-attention-dialog');if(dialog?.open)dialog.close();
  $('auth-error').textContent=message;$('connection').textContent='服务在线 · 请重新登录';renderAuthState();
}
async function checkExpiredSession(expectedCsrf){
  if(!expectedCsrf||csrf!==expectedCsrf)return;
  if(sessionProbePromise){await sessionProbePromise;return;}
  sessionProbePromise=(async()=>{
    try{
      // Only this read-only endpoint can distinguish an expired session from a
      // CSRF, permission, or fact-bound verification failure on another route.
      const response=await fetch('/api/auth/session');
      if(response.status===403&&csrf===expectedCsrf)showLogin('登录已过期或服务已重启，请重新使用 Windows Hello 登录。未提交的内容已留在本页。');
    }catch(_){/* A network failure does not prove that the session expired. */}
    finally{sessionProbePromise=null;}
  })();
  await sessionProbePromise;
}
async function api(path,body){const requestCsrf=csrf;const r=await fetch(path,{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json','X-Javis-CSRF':requestCsrf}:{},body:body?JSON.stringify(body):undefined});const v=await r.json();if(!r.ok||v.ok===false){const error=new Error((v.error||r.status)+': '+(v.message||''));error.status=r.status;error.code=v.error;if(r.status===403&&!path.startsWith('/api/auth/'))await checkExpiredSession(requestCsrf);throw error;}return v;}
async function refreshAuthState({restoreSession=false,manual=false}={}){
  if(authBusy)return;if(authRefreshPromise)return authRefreshPromise;
  if(manual)$('auth-error').textContent='';
  authRefreshPromise=(async()=>{
    try{
      authInfo=await api('/api/auth/info');
      if(authStatusError&&$('auth-error').textContent===authStatusError)$('auth-error').textContent='';authStatusError='';
      if(restoreSession&&!csrf&&!memoryOnly){
        try{const s=await api('/api/auth/session');csrf=s.csrf;if(!memoryOnly)await enter();}
        catch(error){if(error.status!==403)throw error;}
      }
      if(!csrf)$('connection').textContent='服务在线 · 待本人登录';
    }catch(error){authStatusError='读取登录状态失败：'+authMessage(error);$('auth-error').textContent=authStatusError;$('connection').textContent='连接暂不可用 · 将自动重试';}
    finally{authRefreshPromise=null;renderAuthState();}
  })();
  renderAuthState();return authRefreshPromise;
}
function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
function action(text,fn,disabled=false){const b=el('button',text);b.disabled=disabled;b.onclick=async()=>{b.disabled=true;try{await fn();}catch(e){$('notice').textContent=e.message;}finally{b.disabled=disabled;}};return b;}
function decode(s){return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));}
function encode(b){return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function credential(begin,create=false){if(!authSupported()){const error=new Error('WebAuthn unavailable');error.code='webauthn_unavailable';throw error;}const p=begin.options.publicKey;p.challenge=decode(p.challenge);if(p.user)p.user.id=decode(p.user.id);for(const key of ['allowCredentials','excludeCredentials'])for(const c of p[key]||[])c.id=decode(c.id);const c=await navigator.credentials[create?'create':'get']({publicKey:p});if(c.toJSON)return c.toJSON();const r=c.response;return {id:c.id,rawId:encode(c.rawId),type:c.type,response:{clientDataJSON:encode(r.clientDataJSON),...(r.attestationObject?{attestationObject:encode(r.attestationObject)}:{authenticatorData:encode(r.authenticatorData),signature:encode(r.signature),userHandle:r.userHandle?encode(r.userHandle):null})},clientExtensionResults:c.getClientExtensionResults()};}
async function login(enroll=false){if(authBusy||authRefreshPromise)return;if(!authSupported()){$('auth-error').textContent=authMessage({code:'webauthn_unavailable'});return;}authBusy=true;$('auth-error').textContent='';renderAuthState();$('auth-info').textContent='请在 Windows Hello 窗口中完成本人验证；等待期间无需重复点击。';try{const kind=enroll?'enroll':'login';const b=await api('/api/auth/'+kind+'/begin',{});const response=await credential(b,enroll);const s=await api('/api/auth/'+kind+'/complete',{request_id:b.request_id,response});csrf=s.csrf;await enter();}catch(e){$('auth-error').textContent=authMessage(e);}finally{authBusy=false;renderAuthState();if(!csrf)await refreshAuthState();}}
async function loadRoles(){const v=await api('/api/roles');if(!Array.isArray(v.roles)||!v.roles.length)throw new Error('没有可用的本机角色');const select=$('role'),previous=select.value;select.replaceChildren();for(const role of v.roles){const option=el('option',role.label);option.value=role.role_id;select.append(option);}select.value=v.roles.some(r=>r.role_id===previous)?previous:v.roles.some(r=>r.role_id==='cards-master')?'cards-master':v.roles[0].role_id;select.disabled=false;$('submit').disabled=false;rolesReady=true;if(roleStatusError&&$('notice').textContent===roleStatusError)$('notice').textContent='';roleStatusError='';}
function selectTab(name){if(!['tasks','direct','memory','usage','fixed','system'].includes(name))name='tasks';if(memoryOnly&&!['memory','usage'].includes(name))name='memory';activeTab=name;for(const id of ['tasks','direct','memory','usage','fixed','system'])$(id).hidden=id!==name;window.location.hash=name;}
async function enter(){memoryOnly=false;workspaceAccess();$('auth').hidden=true;$('workspace').hidden=false;selectTab(window.location.hash.slice(1)||'tasks');await refresh();}
let attentionSeen=[];
try{const saved=JSON.parse(sessionStorage.getItem('javis-memory-attention')||'[]');if(Array.isArray(saved))attentionSeen=saved.filter(x=>typeof x==='string');}catch(_){}
async function memoryAttention(){
  const data=await api('/api/memory/attention');
  const button=document.querySelector('[data-tab="memory"]');
  button.textContent=`记忆 · 待整理 ${usageCount(data.candidates+data.triage_items)}`;
}
async function taskCommand(actionName,text,taskId=selected){
  if(taskCommandBusy)return;const tid=taskId;taskCommandBusy=true;
  try{
    const t=await api('/api/tasks/'+tid);
    const req={command_id:uuid(),action:actionName,expected_goal_revision:t.goal_revision,expected_attempt:t.attempt};
    const recovery=['retry','resume','continue'].includes(actionName);
    if(recovery&&t.memory_repair_required)throw new Error('执行已完成，当前只需修复记忆记录；普通重试已禁用，以免再次执行模型。');
    if(recovery&&['failed','waiting_user'].includes(t.state)){
      const agreed=window.confirm('请先核对这次任务的 RAW 和已生成产物，确认最后成功的动作，避免重复执行。\n任务：'+tid+'\n现有记录：'+(t.failure_reason||'上次执行结果仍需核对')+'\n\n我已核对以上记录，明确继续此任务的新一轮执行。');
      if(!agreed)return;req.review_confirmed=true;
    }
    if(text!==undefined)req.original_text=text;
    const v=await api('/api/tasks/'+tid+'/commands',req);
    $('notice').textContent='命令 '+v.status+'；目标版本 '+v.goal_revision+'，已应用 '+v.applied_goal_revision;
    if(actionName==='append'){
      if(drafts.get(tid)===text)drafts.delete(tid);
      if(detailView?.tid===tid&&detailView.input.value===text)detailView.input.value='';
    }
  }catch(e){$('notice').textContent=e.message;}
  finally{taskCommandBusy=false;if(selected)await detail(selected).catch(e=>$('notice').textContent=e.message);}
}
function newDetailView(tid){
  if(detailView)drafts.set(detailView.tid,detailView.input.value);
  const view={tid,status:el('p'),revision:el('p'),projection:el('pre'),reason:el('p'),input:el('textarea'),result:el('section'),raw:el('section'),buttons:{},state:null};
  view.input.placeholder='追加要求：原文保存，显示已接收；新执行安全点才应用';view.input.value=drafts.get(tid)||'';
  view.input.oninput=()=>drafts.set(tid,view.input.value);
  const buttons=el('div');
  for(const [name,label] of [['append','追加'],['pause','暂停'],['continue','继续'],['cancel','取消'],['retry','重试'],['reconcile_memory','只补记忆记录']]){
    const button=el('button',label);view.buttons[name]=button;
    button.onclick=()=>taskCommand(name==='continue'&&view.state?.state==='paused'?'resume':name,name==='append'?view.input.value:undefined,tid);
    buttons.append(button);
  }
  buttons.append(action('查看可见执行与RAW',async()=>{const v=await api('/api/tasks/'+tid+'/raw');view.raw.replaceChildren(el('pre',JSON.stringify(v,null,2)));}));
  $('task-detail').replaceChildren(el('h2',tid),view.status,view.revision,view.projection,view.reason,view.input,buttons,view.result,view.raw);
  return view;
}
async function detail(tid){
  selected=tid;const request=++detailRequest;const t=await api('/api/tasks/'+tid);
  if(selected!==tid||request!==detailRequest)return;
  if(!detailView||detailView.tid!==tid)detailView=newDetailView(tid);
  const view=detailView;view.state=t;
  view.status.textContent=`业务：${t.state} · RAW：${t.recording_status} · 交付：${JSON.stringify(t.delivery_status)} · 记忆：${t.memory_status}`;
  view.revision.textContent=`目标 ${t.goal_revision} / 已应用 ${t.applied_goal_revision} / 尝试 ${t.attempt} / 会话 ${t.session_id||'未启动'} / 当前目标完成：${t.current_goal_completed?'是':'否'}`;
  view.projection.textContent=JSON.stringify({追加与原文:t.goals,执行:t.dispatch,暂停请求:t.pending_stop,命令确认:t.commands},null,2);
  view.reason.textContent=t.memory_repair_required?'执行已完成，但记忆记录待修复；普通继续和重试已禁用，不会重跑模型。':(t.failure_reason||'');
  view.buttons.append.disabled=taskCommandBusy;
  for(const name of ['pause','cancel'])view.buttons[name].disabled=taskCommandBusy||!['queued','created','running'].includes(t.state);
  view.buttons.continue.disabled=taskCommandBusy||t.memory_repair_required||!['paused','completed','waiting_user'].includes(t.state);
  view.buttons.retry.disabled=taskCommandBusy||t.memory_repair_required||t.state!=='failed';
  view.buttons.reconcile_memory.disabled=taskCommandBusy||!t.memory_repair_required||['queued','created','running'].includes(t.state);
  try{
    const v=await api('/api/tasks/'+tid+'/result');if(detailView!==view||request!==detailRequest)return;
    view.result.replaceChildren(el('h3','执行器正式交付'),el('pre',v.result.user_reply_zh||JSON.stringify(v.result,null,2)));
    (v.result.artifacts||[]).forEach((a,i)=>{const label=a.kind==='native_final'?'下载可见最终原文 native-final.txt':'下载产物 '+(i+1);const link=el('a',label+' · 版本 '+v.attempt+' · '+a.sha256.slice(0,12));link.href='/api/tasks/'+tid+'/artifact?attempt='+v.attempt+'&index='+i;view.result.append(link,el('br'));});
  }catch(e){if(detailView===view&&request===detailRequest)view.result.replaceChildren(el('small','本次正式交付尚不可用：'+e.message));}
}
async function tasks(){const v=await api('/api/tasks');const list=$('task-list');list.replaceChildren();for(const t of v.tasks.slice().reverse()){const row=el('article');row.append(el('strong',t.role_id+' · 线路 '+t.source_line),el('p',t.task_id),el('span',`${t.state} / 目标${t.goal_revision} / 尝试${t.attempt}`,'badge'),action('查看与操作',()=>detail(t.task_id)));list.append(row);}if(!v.tasks.length)list.append(el('p','尚无公共控制层任务。旧任务未迁移为新任务。'));}
async function memoryControl(actionName){
  if(memoryOperationBusy||!memoryState)return;memoryLoadVersion++;memoryOperationBusy=true;renderAutoreview(memoryState);
  try{await memoryApi('/api/memory/autoreview/control',{action:actionName,expected_revision:memoryState.revision,command_id:uuid()});$('notice').textContent=actionName==='pause'?'已暂停自动整理；已有记忆和原文保留。':'已恢复自动整理。';}
  finally{memoryOperationBusy=false;await loadAutoreview();}
}
async function memoryWithdraw(item){
  if(memoryOperationBusy||!memoryState||!item.withdrawable)return;memoryLoadVersion++;memoryOperationBusy=true;renderAutoreview(memoryState);
  try{await memoryApi('/api/memory/autoreview/withdraw',{decision_id:item.decision_id,expected_version:item.expected_version,command_id:uuid(),reason:'用户在本机记忆管理中撤回'});$('notice').textContent='已撤回这条 AI 整理结果；原文和审核记录保留。';}
  finally{memoryOperationBusy=false;await loadAutoreview();}
}
function renderAutoreview(data){
  memoryState=data;const state=$('memory-auto-state'),counts=data.counts||{};
  state.replaceChildren(el('h2',data.mode==='not_configured'?'AI 自动整理 · 尚未启用':data.enabled===true?'AI 自动整理 · 已启用':data.enabled===false?'AI 自动整理 · 已暂停':'AI 自动整理 · 状态待核对'),
    el('p','普通记忆由 AI 整理，无需逐条确认或 Windows Hello。处理结果标记为 AI 审核；事实是否真实仍取决于原始证据。'),
    el('p',`AI 接纳 ${usageCount(counts.accepted)} · 归档 ${usageCount(counts.archived)} · 待澄清 ${usageCount(counts.needs_user)} · 已撤回 ${usageCount(counts.withdrawn)}`));
  // The original memory UI remains usable if the optional role panel cannot load.
  if(typeof loadMemoryV3!=='function'&&typeof data.enabled==='boolean'&&data.revision!==undefined)state.append(action(data.enabled?'暂停自动整理':data.mode==='not_configured'?'启用自动整理':'恢复自动整理',()=>memoryControl(data.enabled?'pause':'resume'),memoryOperationBusy));
  state.append(el('small','记忆整理不授予交易、转账、发送消息或修改执行权限。暂停不会删除已有记忆；撤回会保留原文和历史。'));
  const list=$('memory-list');list.replaceChildren();
  const labels={accepted:'AI 已接纳',accept:'AI 已接纳',archived:'AI 已归档',archive:'AI 已归档',archive_only:'AI 已归档',needs_user:'待你澄清',needs_information:'待你澄清',withdrawn:'已撤回',rejected:'AI 已归档',reject:'AI 已归档',modify:'AI 已改写'};
  for(const item of data.recent||[]){
    const row=el('article');row.append(el('strong',labels[item.status]||labels[item.kind]||'AI 整理记录'),
      el('p','范围：'+(item.scope||'未知')+' · 整理时间：'+usageTime(item.decided_at)),
      el('p',item.fact||item.proposed_fact_zh||'此记录未生成新的事实'),
      el('p','依据：'+(item.reason_zh||item.reason||'未提供')),
      el('small','来源：'+(item.source_event_id||'未提供')+' · AI 审核编号：'+item.decision_id));
    if(item.source_excerpt){const original=el('details');original.append(el('summary','查看原文引用'),el('pre',item.source_excerpt));row.append(original);}
    if(typeof memorySourcePanel==='function'&&item.source_event_id&&item.scope)row.append(action('打开原始资料',()=>memorySourcePanel(item)));
    if(item.question_zh)row.append(el('p','待澄清：'+item.question_zh));
    if(item.status==='needs_information'&&item.candidate_id&&item.version_digest)row.append(action('补充信息',()=>showSupplement(item)));
    if(item.withdrawable&&item.decision_id&&item.expected_version)row.append(action('撤回此条整理结果',()=>memoryWithdraw(item),memoryOperationBusy));
    list.append(row);
  }
  if(!(data.recent||[]).length)list.append(el('p','尚无 AI 审核记录。待整理内容会在处理后显示；这里不会把未经处理的旧记录视为已完成。'));
  if(data.recent_total>(data.recent||[]).length)list.append(el('p',`共 ${usageCount(data.recent_total)} 条审核记录，当前显示最近 ${data.recent.length} 条。`));
  const button=document.querySelector('[data-tab="memory"]');button.textContent='记忆 · 待澄清 '+usageCount(counts.needs_user);
}
async function loadAutoreview(){
  const request=++memoryLoadVersion;
  try{const data=await memoryApi('/api/memory/autoreview');if(request===memoryLoadVersion)renderAutoreview(data);}
  catch(error){if(request!==memoryLoadVersion)return;memoryState=null;$('memory-auto-state').replaceChildren(el('p','自动整理状态读取失败：'+error.message+'；暂时不能操作，请刷新重试。','error'));$('memory-list').replaceChildren(el('p','请重新读取最新审核记录后再撤回。'));throw error;}
}
async function memories(){
  if(typeof loadMemoryV3==='function')await loadMemoryV3();await loadAutoreview();renderMemoryTriage(await memoryApi('/api/memory/triage'));
}
async function ownerMemoryTools(){renderMemoryLearning(await api('/api/memory/learning'));await memoryFeedbackSources();await mirrorBatches();}
const CLEANUP_STATUS={pending_owner_review:'待本人确认',archived:'已由本人确认归档',declined:'本人未归档',integrity_failed:'完整性校验失败'};
const MIRROR_STATUS={pending_owner_review:'待本人确认',confirmed:'已由本人确认',rejected:'已拒绝',integrity_failed:'完整性校验失败'};
function mirrorList(title,items,fmt){const d=el('details');d.append(el('summary',title+'（'+items.length+'）'),el('pre',items.length?items.map(fmt).join('\n'):'无'));return d;}
async function mirrorDecide(request,label){const ch=await api('/api/memory/mirror/challenge',request);const response=await credential(ch);const r=await api('/api/memory/mirror/review',{request,assertion:{request_id:ch.request_id,response}});$('notice').textContent=label+'：'+JSON.stringify(r);await mirrorBatches();}
async function mirrorBatches(){
  const v=await api('/api/memory/mirror');const box=$('mirror-batches');box.replaceChildren();
  for(const b of v.batches||[]){
    const row=el('article');
    if(b.status==='integrity_failed'||!b.manifest){row.append(el('strong',b.batch_id),el('p','批次完整性校验失败，不能确认。','error'));box.append(row);continue;}
    const m=b.manifest,c=m.counts;
    row.append(el('strong',m.package_id+' · '+b.batch_id),
      el('p',`状态：${MIRROR_STATUS[b.status]||b.status} · 写入正式记忆 ${c.promote} 条 · 回写 Grok ${c.export} 条 · 冲突 ${c.conflicts} 条（不覆盖） · Friday 排除 ${c.friday_bot} 条 · 密钥/L4 排除 ${c.secret_or_l4} 条 · 已存在 ${c.duplicates} 条`),
      el('p','规则：'+m.policy),el('small','清单摘要 '+b.manifest_digest));
    row.append(mirrorList('写入正式记忆',m.promote,x=>`[${x.role}] ${x.as_of||'时间未知'}${x.reason==='newer_than_confirmed'?' （较新，取代旧版）':''} ${x.fact}`),
      mirrorList('回写 Grok',m.export,x=>`[${x.role}] ${x.as_of||'时间未知'} ${x.fact}`),
      mirrorList('冲突（不覆盖，需另行处理）',m.excluded.conflicts,x=>`[${x.role}] ${x.as_of||'未知'} ↔ 现有 ${x.existing_as_of||'未知'} ${x.fact}`),
      mirrorList('Friday 相关（排除）',m.excluded.friday_bot,x=>`[${x.role}] ${x.fact}`));
    if(b.status==='pending_owner_review'){
      row.append(action(`用 Windows Hello 确认整批（${c.promote} 条写入 + ${c.export} 条回写）`,async()=>{if(!window.confirm(`确认后：${c.promote} 条写入正式记忆，${c.export} 条回写 Grok。冲突、Friday、密钥/L4 项不会写入。继续？`))return;await mirrorDecide({action:'confirm_mirror_batch',batch_id:b.batch_id,command_id:uuid()},'镜像批次已确认');}),
        action('拒绝此批次',async()=>{await mirrorDecide({action:'reject_mirror_batch',batch_id:b.batch_id,command_id:uuid()},'镜像批次已拒绝');}));
    }
    box.append(row);
  }
  for(const p of v.policies||[]){
    const row=el('article');
    if(p.status==='integrity_failed'||!p.document){row.append(el('strong',p.policy_id),el('p','长期授权文件完整性校验失败。','error'));box.append(row);continue;}
    const d=p.document;
    row.append(el('strong','长期镜像授权 · '+p.policy_id),el('p','状态：'+(MIRROR_STATUS[p.status]||p.status)+(p.filters_current?'':' · 过滤规则已变化，此授权失效')),
      el('p','规则：'+d.policy),el('p','适用：每次例行包（'+d.package_pattern+'），无需逐批确认；可随时撤销。'),
      el('p','本人原话（仅作背景，授权以 Windows Hello 签名为准）：'+d.owner_statement.text+' · '+d.owner_statement.stated_at+' · '+d.owner_statement.source),
      el('small','授权摘要 '+p.policy_digest));
    if(p.status==='pending_owner_review'&&p.filters_current)row.append(action('用 Windows Hello 签署长期镜像授权',async()=>{if(!window.confirm('签署后，之后每次例行 Grok↔Javis 包会按上述规则自动写入正式记忆并回写 Grok（冲突仍只报告）。继续？'))return;await mirrorDecide({policy_id:p.policy_id,command_id:uuid()},'长期授权已签署');}));
    box.append(row);
  }
  for(const b of v.cleanups||[]){
    const row=el('article');
    if(b.status==='integrity_failed'||!b.manifest){row.append(el('strong',b.cleanup_batch_id),el('p','清理批次完整性校验失败，不能确认。','error'));box.append(row);continue;}
    const m=b.manifest,c=m.counts;
    row.append(el('strong','待核实记忆清理批次 · '+b.cleanup_batch_id),
      el('p',`状态：${CLEANUP_STATUS[b.status]||b.status} · 隔离候选 ${c.quarantine} 条 · 筛查待办 ${c.triage} 条（来源 ${c.triage_source_events} 个） · 旧候选 ${c.legacy} 条 · 合计 ${c.total} 条 · 另列排除 ${c.excluded_groups} 组（保持待核实）`),
      el('p','结果：整批拒绝/归档，不写入正式记忆；原记录保留供审计。'+(m.basis?' 依据：'+m.basis:'')),el('small','清单摘要 '+b.manifest_digest));
    row.append(mirrorList('隔离候选（拒绝）',m.quarantine,x=>`[${x.scope}] ${x.category} · ${x.predicate} · ${x.short}`),
      mirrorList('筛查待办（归档）',m.triage,x=>`[${x.scope}] ${x.task_id||''} · ${x.source_event_id} · ${x.reason_code}`),
      mirrorList('旧候选（拒绝）',m.legacy,x=>`[${x.role}] ${x.memory_id} · ${x.short}`),
      mirrorList('排除（不在本批，请另行确认）',m.excluded,x=>Object.values(x).join(' · ')));
    if(b.status==='pending_owner_review')row.append(el('p','这是旧版人工清理清单，仅供查阅；当前普通记忆由 AI 自动整理。'));
    box.append(row);
  }
  if(!(v.batches||[]).length&&!(v.policies||[]).length&&!(v.cleanups||[]).length)box.append(el('p','没有镜像批次或长期授权。'));
}
function renderMemoryTriage(data){
  const list=$('memory-triage');list.replaceChildren();
  if(data.invalid_records>0)list.append(el('p',`${data.invalid_records} 条待办记录无法验证，请检查本地记录。`,'error'));
  for(const item of data.items||[]){
    const row=el('article');
    row.append(el('strong',item.source_event_id),el('p',`范围：${item.scope} · 阶段：${TRIAGE_STAGES[item.stage]||'待核对'}`),
      el('p','待核对原因：'+(TRIAGE_POLICY_REASONS[item.policy_reason]||TRIAGE_REASONS[item.reason_code]||'需要人工核对')),
      el('p','进入待办：'+usageTime(item.created_at)+'（北京时间，非事实生效时间）'),
      el('p',item.source_integrity==='verified'?'原始来源校验通过':'原始来源已变化或不可读取；需要先修复来源',item.source_integrity==='verified'?'':'error'),
      el('small','待办编号：'+item.triage_id));
    if(item.source_integrity==='verified'){
      row.append(action('打开原始资料',()=>memorySourcePanel(item)),action('纠正筛选判断',()=>localFeedbackContext(item)));
      if(item.version_digest)row.append(action('补充信息',()=>showSupplement(item)),action('恢复未完成步骤',()=>retryMemoryItem(item)));
    }
    list.append(row);
  }
  if(!data.items?.length)list.append(el('p','没有待补充证据的记录。'));
  if(data.total>(data.items?.length||0))list.append(el('p',`共 ${data.total} 条，当前显示前 ${data.items.length} 条。`));
}
let memoryFeedbackCursor=null;
const FEEDBACK_LABELS={keep:'应该记住',archive:'无需记住',needs_evidence:'需要补充'};
const MEMORY_ROUTES={keep:'继续提取',archive_only:'仅归档原文',needs_evidence:'待补充证据',conflict:'存在冲突'};
async function memoryFeedbackContext(item){
  const query=new URLSearchParams({event_id:item.source_event_id,scope:item.scope});
  for(const field of ['run_id','triage_id'])if(item[field])query.set(field,item[field]);
  if(item.text_path)query.set('text_path',JSON.stringify(item.text_path));
  const context=await api('/api/memory/feedback/context?'+query);
  const box=$('memory-feedback-context');box.replaceChildren(el('h3','标记这份原始内容'),
    el('p','请判断这份内容是否值得继续提取。反馈用于改进筛选，不能确认其中的事实，也不会直接写入正式记忆。'),
    el('p','范围：'+context.scope+' · 来源：'+context.source_event_id),
    el('p','原消息时间：'+usageTime(context.source_times?.occurred_at)+' · 本机收到：'+usageTime(context.source_times?.received_at)+' · 保存：'+usageTime(context.source_times?.captured_at)+'（北京时间；接收与保存时间不代表事实生效）'),
    el('p',context.source_context?.authorship_verified?'记录为用户原始输入':'来源归属未经验证，反馈不会改变归属'),
    el('pre',context.source_text));
  if(context.latest_feedback)box.append(el('p','当前标记：'+(FEEDBACK_LABELS[context.latest_feedback.label]||'已记录')));
  const buttons=el('div');let submitting=false;
  for(const [label,title] of Object.entries(FEEDBACK_LABELS)){
    const command=uuid();
    buttons.append(action(title,async()=>{
      if(submitting)return;submitting=true;
      try{await api('/api/memory/feedback',{...context.bindings,label,command_id:command});
        box.replaceChildren(el('p','反馈已保存：'+title+'。达到独立评测条件后才能更新筛选策略。'));
        renderMemoryLearning(await api('/api/memory/learning'));await memoryFeedbackSources();
      }finally{submitting=false;}
    }));
  }
  box.append(buttons);box.scrollIntoView?.({behavior:'smooth',block:'nearest'});
}
async function memoryFeedbackSources(cursor=memoryFeedbackCursor){
  const data=await api('/api/memory/feedback/sources'+(cursor?'?cursor='+encodeURIComponent(cursor):''));
  memoryFeedbackCursor=cursor;
  const box=$('memory-feedback-sources');box.replaceChildren();
  if(data.invalid_records)box.append(el('p','部分记录未通过完整性检查，未作为反馈来源。','error'));
  for(const item of data.items||[]){const row=el('article');row.append(el('strong',item.source_event_id),
    el('p','范围：'+item.scope+' · 筛选：'+(MEMORY_ROUTES[item.decision]||'待核对')),
    el('p','你的标记：'+(FEEDBACK_LABELS[item.latest_feedback?.label]||'未标记')),
    action('查看原文并标记',()=>memoryFeedbackContext(item),item.source_integrity==='changed_or_unavailable'));box.append(row);}
  if(!data.items?.length)box.append(el('p','还没有可标记的已处理来源。'));
  box.append(el('p','共 '+(data.total||0)+' 份已处理来源；仅归档的内容也可标记。'));
  if(data.next_cursor)box.append(action('下一页',()=>memoryFeedbackSources(data.next_cursor)));
  if(cursor)box.append(action('返回首页',()=>memoryFeedbackSources(null)));
}
function renderMemoryLearning(data){
  const box=$('memory-learning');box.replaceChildren(el('h3','反馈与改进进度'));
  box.append(el('p','至少积累 18 组独立样本，每种标记在开发与验收中各至少 3 组。队列空闲时分批评测；误拦减少、误放不增加且验收中没有误放，才启用新策略。'));
  box.append(el('p','有效反馈：'+usageCount(data.feedback_count||0)+' · '+Object.entries(FEEDBACK_LABELS).map(([k,v])=>v+' '+usageCount(data.label_counts?.[k]||0)).join(' · ')));
  for(const scope of data.scopes||[]){const row=el('article');row.append(el('strong',scope.scope),
    el('p',scope.active_version?'当前已启用反馈策略：'+scope.active_version:'当前使用基础筛选策略'),
    el('p',(scope.prepare_readiness==='ready'||scope.ready===true)?'已具备独立评测条件，等待空闲队列处理。':'继续积累相互独立的反馈；同一任务和重复原文不重复计数。'));
    if(scope.active_integrity==='feedback_or_source_changed'||scope.active_valid===false)row.append(el('p','关联反馈或来源发生变化，旧策略需要重新核验。','error'));
    if(scope.last_change?.action==='deactivate')row.append(el('p','先前策略因关联反馈或来源变化已撤回，当前恢复基础筛选。'));
    box.append(row);}
  if(!data.scopes?.length)box.append(el('p','尚无有效反馈。标记下方来源后，这里会显示积累进度。'));
  const phases={prepared:'待评测',evaluating:'评测中',qualified:'评测达标',active:'已启用',incomplete:'评测未完成',not_qualified:'未达启用条件'};
  for(const version of (data.versions||[]).slice(-5)){const row=el('article');
    row.append(el('p',version.scope+' · '+(phases[version.status]||'待核对')+' · '+usageCount(version.evaluated_cases)+' / '+usageCount(version.total_cases)+' 项比较'));
    if(version.metrics?.profile)row.append(el('p','候选策略：误拦 '+usageCount(version.metrics.profile.false_blocks)+'，错误放行 '+usageCount(version.metrics.profile.false_accepts)));
    if(version.status==='incomplete')row.append(el('p','存在失败或未完成调用，结果不会计作通过，也不会自动重试已尝试的请求。','error'));
    box.append(row);}
}
const TRIAGE_STAGES={screening:'前置筛选',verification:'事实复核',source_time:'来源时间',proposal:'候选生成',graphiti:'结构化提取'};
const TRIAGE_POLICY_REASONS={relative_time_unanchored:'原文使用“明天、下周”等相对时间，但原消息时间未知，需要补充时间依据',validity_not_in_source:'提取出的生效日期在原文中没有依据，需要核对',validity_precision_unproven:'原文不能支持提取出的时间精度，需要核对',quantity_not_in_source:'提取出的数字在原文中没有依据，需要核对',typed_low_confidence:'模型判断不够确定，需要人工核对',typed_insufficient:'原文不足以支持整条事实，需要补充证据',typed_subject_unproven:'事实主体缺少依据，需要核对',typed_modality_unproven:'意图、条件或否定含义可能有变化，需要核对',typed_attribution_unproven:'事实归属或说话人缺少依据，需要核对',typed_numbers_unproven:'事实中的数字尚未核实',typed_dates_unproven:'事实中的日期尚未核实',source_too_large:'原文超过本次处理长度，需保留上下文后拆分',candidate_too_large:'提取出的候选过长，需要核对并拆分'};
const TRIAGE_REASONS={source_too_large:'原文超过本次可处理长度，需拆分或补充明确引用',screen_needs_evidence:'原文需要补充证据或澄清',screen_conflict:'来源存在冲突，需要核对',verification_uncertain:'候选事实的依据不足，需要核对',validity_missing:'事实生效时间缺少依据，需要澄清',validity_invalid:'事实时间范围无效，需要核对',source_time_missing:'原始来源缺少时间，需要补充',graph_no_facts:'未能提取精确事实，需要补充明确表述',model_response_invalid:'模型答复未通过格式校验，需人工复核'};
const USAGE_STAGES={screening:'筛选',screen:'筛选',jev_screen:'筛选',graphiti:'Graphiti',verification:'复核',verify:'复核',jev_verify:'复核',embedding:'Embedding'};
const USAGE_STATUSES={pending:'未完成',completed:'已完成',success:'已完成',succeeded:'已完成',error:'失败',failed:'失败',http_error:'接口失败',transport_error:'网络失败',invalid_response:'响应无效',cancelled:'已取消',timeout:'超时'};
function usageCount(value){return typeof value==='number'&&Number.isFinite(value)&&value>=0?value.toLocaleString('zh-CN'):'未知';}
function usageMoney(value,currency='CNY'){const prefix={CNY:'¥',USD:'US$'}[currency];return prefix&&typeof value==='string'&&/^\d+(\.\d+)?(?:[eE][+-]?\d+)?$/.test(value)?prefix+value:'未知';}
function usageTime(value){if(!value)return '未知时间';const date=new Date(value);return Number.isNaN(date.getTime())?'未知时间':date.toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false});}
function usageStage(value){return USAGE_STAGES[value]||value||'未知阶段';}
function usageStatus(value){return USAGE_STATUSES[value]||value||'未知状态';}
function usageTokenLine(tokens){tokens=tokens||{};return `输入 ${usageCount(tokens.input)} · 输出 ${usageCount(tokens.output)} · 缓存 ${usageCount(tokens.cached)}`;}
function usageWindowTokens(row){if(!row||row.calls===0)return '—';if(row.tokens?.total===null||row.tokens?.total===undefined)return '未知';const known=row.usage_coverage?(row.usage_coverage.complete_requests||0)+(row.usage_coverage.partial_requests||0):(row.completed||0)-(row.unknown_usage||0);if(known<=0)return '未知';return ((row.unknown_usage>0||row.pending>0)?'已知 ':'')+usageCount(row.tokens.total);}
function usageWindowCost(row){
  if(!row||row.calls===0)return '暂无计量记录';
  if(row.subscription_requests===row.calls)return '使用订阅额度';
  const costs=usageCurrencies(row);
  if(!costs.length)return '金额待核对';
  return costs.map(cost=>cost.amount!=null?usageMoney(cost.amount,cost.currency):(costs.length>1?(cost.currency==='USD'?'US$ ':'¥ '):'')+'金额待核对').join('\n');
}
function usageCurrencies(row){
  const groups=row?.estimated_cost_by_currency;
  if(groups&&typeof groups==='object'&&Object.keys(groups).length)return ['CNY','USD'].filter(currency=>groups[currency]&&typeof groups[currency]==='object').map(currency=>({...groups[currency],currency}));
  const cost=row?.estimated_cost;return cost&&['CNY','USD'].includes(cost.currency)?[cost]:[];
}
function usageCostDetail(row){
  if(!row||row.calls===0)return '没有新记录不代表历史调用免费。';
  if(row.subscription_requests===row.calls)return '订阅调用不折算 API 金额；剩余额度请在 ChatGPT 查看。';
  const costs=usageCurrencies(row);
  if(costs.length&&costs.every(cost=>cost.amount!=null))return costs.length>1?'按保存的价格分别估算；人民币与美元不相加。':'按各次调用保存的价格估算。';
  if(!(row.pricing_coverage?.priced_requests>0))return '尚无可估价调用；未知部分未计入。';
  const known=costs.filter(cost=>cost.priced_requests===undefined||cost.priced_requests>0).map(cost=>usageMoney(cost.known_amount,cost.currency)).filter(value=>value!=='未知');
  return (known.length?'已计价部分 '+known.join('；')+'；':'')+'未知或未完成部分未计入。';
}
function usageTable(headers,rows){
  const table=el('table');const head=el('thead');const titles=el('tr');
  headers.forEach(label=>titles.append(el('th',label)));head.append(titles);table.append(head);
  const body=el('tbody');for(const values of rows){const row=el('tr');for(const value of values)row.append(el('td',value));body.append(row);}table.append(body);return table;
}
function renderMemoryUsage(data){
  const summary=data.summary||{};const cards=$('usage-cards');cards.replaceChildren();
  $('usage-coverage').textContent=(summary.meter_started_at?'计量开始：'+usageTime(summary.meter_started_at)+'。':'尚未记录新的 API 调用。')+' 更早历史未计量；未知用量和未知价格不会按零计算。统计按北京时间。';
  for(const [key,title] of [['today','今日'],['month','本月'],['all','累计']]){
    const row=summary[key]||{};const card=el('article',undefined,'usage-card');
    card.append(el('h3',title),el('p',usageWindowCost(row),'usage-amount'),el('p',usageCostDetail(row),'usage-muted'));
    const metrics=el('dl',undefined,'usage-metrics');
    for(const [label,value] of [['外部调用',usageCount(row.calls)],['其中订阅调用',usageCount(row.subscription_requests??0)],['Provider tokens',usageWindowTokens(row)],['未知用量',usageCount(row.unknown_usage)],['未完成调用',usageCount(row.pending)],['未知价格',usageCount(row.unknown_price)],['完成但未估价',usageCount(row.unpriced_requests)]])metrics.append(el('dt',label),el('dd',value));
    card.append(metrics,el('p',row.calls===0?'输入 / 输出 / 缓存：暂无记录':usageTokenLine(row.tokens),'usage-muted'));cards.append(card);
  }
  const breakdown=summary.all?.breakdown||[];const groups=$('usage-breakdown');groups.replaceChildren();
  if(!breakdown.length)groups.append(el('p','暂无阶段用量记录。','usage-muted'));
  else groups.append(usageTable(['阶段 / 模型','调用','已知 tokens','按价估算','未知用量 / 未完成 / 未知价'],breakdown.map(row=>[
    usageStage(row.stage)+' / '+(row.model||'未知模型'),usageCount(row.calls),usageWindowTokens(row),usageWindowCost(row)+(row.estimated_cost?.amount==null?'；'+usageCostDetail(row):''),
    [row.unknown_usage,row.pending,row.unknown_price].map(usageCount).join(' / ')])));
  const recent=$('usage-recent');recent.replaceChildren();const records=Array.isArray(data.recent)?data.recent:[];
  if(!records.length)recent.append(el('p','暂无调用记录。历史未计量，不能据此判断没有费用。','usage-muted'));
  else recent.append(usageTable(['时间 / 阶段','模型','状态','Provider tokens','按价估算'],records.map(row=>{
    const tokens=row.tokens||{};const cost=row.estimated_cost||{};
    const amount=row.billing_mode==='subscription'?'使用订阅额度（不折算 API 金额）':cost.amount==null?(row.status==='pending'?'待完成':row.pricing_status==='unknown'?'未知价格':'未知金额'):usageMoney(cost.amount,cost.currency);
    const tokenText=usageCount(tokens.total)+(row.usage_known===false?'（用量未完整返回）':'')+'；'+usageTokenLine(tokens);
    return [usageTime(row.started_at)+' / '+usageStage(row.stage),row.actual_model||(row.model?row.model+'（请求型号）':'未知模型'),usageStatus(row.status),tokenText,amount];
  })));
  const integrity=summary.integrity||{};const issues=(integrity.invalid_rows||0)+(integrity.conflicting_rows||0);$('usage-integrity').hidden=issues===0;
  $('usage-integrity').textContent=issues?`计量记录需要核对：${usageCount(integrity.invalid_rows)} 条格式异常，${usageCount(integrity.conflicting_rows)} 条冲突。显示值可能不完整。`:'';
  $('usage-updated').textContent='数据截至 '+usageTime(summary.as_of)+'；页面打开时自动刷新。';
}
async function memoryUsage(){
  try{renderMemoryUsage(await (memoryOnly?memoryApi:api)('/api/memory/usage'));}
  catch(error){$('usage-updated').textContent='用量刷新失败，当前显示可能是旧数据。';throw error;}
}
async function fixedRefresh(){fixed=await api('/api/fixed-work');$('fixed-state').replaceChildren(el('pre',JSON.stringify(fixed,null,2)));const job=fixed.job||fixed;$('fixed-toggle').disabled=false;$('fixed-toggle').textContent=job.enabled?'停用固定工作':'启用固定工作';$('fixed-run').disabled=false;}
async function fixedCommand(actionName){const job=fixed.job||fixed;const result=await api('/api/fixed-work',{command_id:uuid(),action:actionName,expected_version:job.version});$('notice').textContent=JSON.stringify(result);await fixedRefresh();}
async function directCaptures(){const v=await api('/api/grok-captures');const list=$('direct-list');list.replaceChildren();for(const c of v.captures.slice().reverse()){const row=el('article');row.append(el('strong',c.event_id),el('p','本机收到时间：'+c.captured_at));for(const m of c.payload.messages)row.append(el('span',m.speaker+' · '+({forwarded_original_unverified:'入口逐字转发，来源身份未独立核实',relay:'转述',summary:'摘要'}[m.fidelity]||m.fidelity),'badge'),el('pre',m.text));row.append(el('p','采集缺口：'+c.payload.gaps.join('；')));list.append(row);}if(!v.captures.length)list.append(el('p','尚无实际收到的Grok直接对话记录；不能据此声称云端同步已通过。'));}
async function refresh(){if(busy)return;busy=true;try{if(memoryOnly||activeTab=== 'memory'){if(activeTab==='usage')await memoryUsage();else await memories();lastSuccessTime=new Date().toLocaleTimeString();$('connection').textContent='本机记忆已连接 · '+lastSuccessTime;return;}if(!rolesReady){try{await loadRoles();}catch(error){$('role').disabled=true;$('submit').disabled=true;roleStatusError='新任务角色暂时无法读取，稍后自动重试：'+error.message;$('notice').textContent=roleStatusError;}}await tasks();await memoryAttention();if(selected&&!$('tasks').hidden)await detail(selected);if(!$('direct').hidden)await directCaptures();if(!$('memory').hidden)await memories();if(activeTab==='usage')await memoryUsage();if(!$('fixed').hidden)await fixedRefresh();if(!$('system').hidden)$('system-state').textContent=JSON.stringify(await api('/api/system'),null,2);lastSuccessTime=new Date().toLocaleTimeString();$('connection').textContent='已连接 · '+lastSuccessTime;}catch(e){$('connection').textContent='失联/未登录 · '+(lastSuccessTime?'最后成功更新时间：'+lastSuccessTime:'从未成功连接');$('notice').textContent=e.message;}finally{busy=false;}}
for(const b of document.querySelectorAll('[data-tab]'))b.onclick=async()=>{selectTab(b.dataset.tab);await refresh();};
$('login').onclick=()=>login();$('enroll').onclick=()=>login(true);$('submit').onclick=async()=>{try{const v=await api('/api/tasks',{command_id:uuid(),role_id:$('role').value,original_text:$('new-text').value,permission:'R1',source_line:2,entry:'owner_monitor'});$('notice').textContent='已持久接收 '+v.task_id+'；执行尚未完成';await refresh();await detail(v.task_id);}catch(e){$('notice').textContent=e.message;}};
$('fixed-toggle').onclick=()=>fixedCommand((fixed.job||fixed).enabled?'disable':'enable').catch(e=>$('notice').textContent=e.message);$('fixed-run').onclick=()=>fixedCommand('run_once').catch(e=>$('notice').textContent=e.message);
$('auth-refresh').onclick=()=>refreshAuthState({restoreSession:true,manual:true});
$('memory-open').onclick=()=>openMemory();$('owner-workspace').onclick=()=>openOwnerWorkspace();$('memory-refresh').onclick=()=>memories().catch(error=>$('notice').textContent=error.message);
$('memory-owner-refresh').onclick=()=>ownerMemoryTools().catch(error=>$('notice').textContent=error.message);
if(window.location?.hash==='#memory')openMemory();else refreshAuthState({restoreSession:true});
setInterval(()=>{if(memoryOnly){refresh();return;}if(authBusy||authRefreshPromise)return;if(csrf)refresh();else refreshAuthState();},8000);
