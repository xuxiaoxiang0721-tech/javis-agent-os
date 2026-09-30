'use strict';
let roleMemoryState=null,roleMemoryBusy=false,roleMemoryStamp='',memoryModelState=null,memorySubscriptionState=null,memorySubscriptionStamp='';
const supplementDrafts=new Map();

function ensureMemoryV3(){
  if($('memory-role-controls'))return;
  const memory=$('memory'),controls=el('div');controls.id='memory-role-controls';
  const model=el('details');model.append(el('summary','GPT 接入与资料覆盖'));
  const state=el('p');state.id='memory-model-state';const form=el('div');form.id='memory-model-form';
  model.append(state,form,el('p','可使用官方 ChatGPT 订阅或独立 API Key。连接账号和保存设置不会启动整理；仍由总开关和角色开关控制。'),
    action('检查 RAW 覆盖情况',()=>showMemoryCoverage()),action('查看筛选学习状态',async()=>{
      const data=await memoryApi('/api/memory/local-learning');const box=$('memory-local-feedback');
      box.replaceChildren(el('h3','筛选学习状态'),el('p','纠错记录会先组成独立评测样本；误拦改善且误放不增加后，才启用新策略。'));
      for(const scope of data.scopes||[])box.append(el('p',(roleMemoryState?.role_labels?.[scope.scope]||scope.scope)+'：'+(scope.active_version?'已有启用的策略':'尚未启用新策略')+'；应该记住 '+usageCount(scope.label_counts?.keep)+'，无需记住 '+usageCount(scope.label_counts?.archive)+'，需要补充 '+usageCount(scope.label_counts?.needs_evidence)));
      if(!data.scopes?.length)box.append(el('p','目前还没有可用于评测的纠错记录。'));
    }));
  memory.insertBefore(controls,$('memory-auto-state'));memory.insertBefore(model,$('memory-auto-state'));
  for(const id of ['memory-coverage','memory-source-view','memory-local-feedback','memory-supplement-status','memory-supplement-form']){
    const box=el('div');box.id=id;memory.insertBefore(box,$('memory-list'));
  }
}

async function saveMemoryControls(change){
  if(roleMemoryBusy||!roleMemoryState)return;
  roleMemoryBusy=true;
  for(const button of $('memory-role-controls').querySelectorAll('button'))button.disabled=true;
  try{
    const result=await memoryApi('/api/memory/controls',{...change,expected_revision:roleMemoryState.revision,command_id:uuid()});
    renderRoleMemory(result,true);
    $('notice').textContent='已保存结构化处理设置。所有角色的 RAW 继续接收保存。';
  }finally{roleMemoryBusy=false;roleMemoryStamp='';await loadMemoryV3();}
}

function renderRoleMemory(data,force=false){
  if(roleMemoryState&&data.revision<roleMemoryState.revision)return;
  roleMemoryState=data;
  const stamp=JSON.stringify([data.revision,data.global_enabled,data.roles,data.daily_call_limit,data.budget]);
  if(!force&&stamp===roleMemoryStamp)return;
  roleMemoryStamp=stamp;
  const box=$('memory-role-controls');
  const priorLimit=$('memory-daily-limit');
  const editedLimit=priorLimit&&document.activeElement===priorLimit?priorLimit.value:null;
  box.replaceChildren(el('h2','按角色整理记忆'),
    el('p','RAW 始终接收并保存。以下开关控制各角色新增结构化处理；关闭期间的资料保留，重新开启后接续处理。'));
  const state=el('div',undefined,'memory-control-bar');
  state.append(el('strong',data.global_enabled?'结构化处理总开关：开启':'结构化处理总开关：暂停'),
    action(data.global_enabled?'暂停全部付费处理':'开启结构化处理',()=>saveMemoryControls({global_enabled:!data.global_enabled}),roleMemoryBusy));
  box.append(state,el('small','暂停后不再发起新的模型请求；已发出的请求可能完成。已有记忆仍可查询。'));
  const grid=el('div',undefined,'memory-role-grid');
  for(const [role,enabled] of Object.entries(data.roles||{})){
    const row=el('article',undefined,'memory-role-card');
    const heading=el('div',undefined,'memory-control-bar');
    heading.append(el('strong',data.role_labels?.[role]||role),el('span','RAW 保留','badge'));
    const button=action(enabled?'结构化：已开启':'结构化：已关闭',()=>saveMemoryControls({roles:{[role]:!enabled}}),roleMemoryBusy);
    button.setAttribute('role','switch');button.setAttribute('aria-checked',String(enabled));button.setAttribute('aria-label',(data.role_labels?.[role]||role)+' 结构化处理');
    row.append(heading,el('small',role),button,el('p',!enabled?'只保留原始资料，结构化待处理':data.global_enabled?'随队列自动整理':'角色已开启，等待总开关恢复'));
    grid.append(row);
  }
  box.append(grid);
  box.append(action('全部角色开启结构化',()=>saveMemoryControls({roles:Object.fromEntries(Object.keys(data.roles||{}).map(k=>[k,true]))}),roleMemoryBusy),
    action('全部角色只存 RAW',()=>saveMemoryControls({roles:Object.fromEntries(Object.keys(data.roles||{}).map(k=>[k,false]))}),roleMemoryBusy));
  const budget=el('div',undefined,'memory-control-bar');const label=el('label','每日 API 请求上限 ');
  const input=el('input');input.type='number';input.id='memory-daily-limit';input.min='0';input.max='100000';input.step='1';input.value=editedLimit??String(data.daily_call_limit??200);label.append(input);
  budget.append(label,action('保存上限',()=>{
    const value=Number(input.value);if(!Number.isSafeInteger(value)||value<0||value>100000)throw new Error('请输入 0 至 100000 的整数');
    return saveMemoryControls({daily_call_limit:value});
  },roleMemoryBusy));
  box.append(budget,el('small',`0 表示不允许外部请求。每日按 UTC 计数；已预留 ${usageCount(data.budget?.reserved_calls)} 次，剩余 ${usageCount(data.budget?.remaining_calls)} 次。预留包含可能未完成的请求，不等于已结算账单。`));
}

function renderMemoryModel(data){
  if(memoryModelState&&data.revision<memoryModelState.revision)return;
  memoryModelState=data;
  const status=$('memory-model-state');
  const names={ready:'已配置，尚不代表已通过真实调用验证',waiting_for_key:'等待填写 OpenAI API Key',waiting_for_configuration:'等待设置 GPT 型号和账号',waiting_for_embedding_key:'等待配置向量服务',waiting_for_embedding_configuration:'等待核对向量服务设置',chatgpt_subscription_login_required:'等待登录 ChatGPT',chatgpt_subscription_account_changed:'订阅账号已变化，请重新保存设置',chatgpt_subscription_access_denied:'订阅授权暂不可用，请重新登录',chatgpt_subscription_usage_limit_exceeded:'订阅额度暂不可用，等待恢复',chatgpt_subscription_usage_unavailable:'订阅服务暂不可用，等待恢复'};
  status.textContent=(names[data.status]||data.status||'待配置')+' · GPT：'+(data.model||'未设置')+' · '+(data.auth_mode==='chatgpt_subscription'?'官方订阅模式':'API Key 模式')+' · 向量化：'+(data.embedding_provider||'openai');
  const form=$('memory-model-form');if(form.childElementCount)return;
  const modeLabel=el('label','GPT 使用方式 '),mode=el('select');mode.id='memory-gpt-auth-mode';
  for(const [value,label] of [['chatgpt_subscription','官方 ChatGPT 订阅'],['api_key','独立 API Key（按量计费）']]){const option=el('option',label);option.value=value;mode.append(option);}
  mode.value=new URLSearchParams(window.location.search||'').get('memory_login')==='chatgpt'?'chatgpt_subscription':data.auth_mode||'api_key';modeLabel.append(mode);
  const modelLabel=el('label','GPT 型号（可修改） '),model=el('input');model.type='text';model.id='memory-gpt-model';model.value=data.model||'gpt-5.4-mini-2026-03-17';model.placeholder='填写支持结构化输出的 GPT 型号';model.autocomplete='off';modelLabel.append(model);
  const keyLabel=el('label','OpenAI API Key '),key=el('input');key.type='password';key.id='memory-gpt-key';key.autocomplete='new-password';key.placeholder=data.key_configured?'已保存；留空保持不变':'仅在本机填写，不要粘贴到聊天';keyLabel.append(key);
  const subscription=el('div');subscription.id='memory-subscription-panel';
  const embedLabel=el('label','向量化服务（独立计费） '),embed=el('select');embed.id='memory-embedding-provider';
  for(const [value,label] of [['dashscope','已有阿里云向量接口'],['openai','OpenAI 向量接口']]){const option=el('option',label);option.value=value;embed.append(option);}
  embed.value=data.embedding_provider||'openai';embedLabel.append(embed);
  const legacyLabel=el('label','复用已配置的阿里云向量凭据（仍按量计费） '),legacy=el('input');legacy.type='checkbox';legacy.id='memory-use-legacy-embedding';legacyLabel.append(legacy);
  const embedKeyLabel=el('label','独立向量 API Key（可选） '),embedKey=el('input');embedKey.type='password';embedKey.id='memory-embedding-key';embedKey.autocomplete='new-password';embedKey.placeholder='留空保留现有凭据';embedKeyLabel.append(embedKey);
  const display=()=>{const subscribed=mode.value==='chatgpt_subscription';keyLabel.hidden=subscribed;subscription.hidden=!subscribed;legacyLabel.hidden=embed.value!=='dashscope';};
  mode.onchange=async()=>{display();key.value='';if(mode.value==='chatgpt_subscription')try{await loadMemorySubscription();}catch(error){$('notice').textContent=error.message;}};
  embed.onchange=()=>{legacy.checked=false;display();};
  form.append(modeLabel,modelLabel,keyLabel,subscription,embedLabel,legacyLabel,embedKeyLabel,action('保存 GPT 设置',async()=>{
    const request={expected_revision:memoryModelState.revision,model:model.value.trim(),auth_mode:mode.value,embedding_provider:embed.value};
    if(mode.value==='api_key'&&key.value.trim())request.api_key=key.value.trim();
    if(mode.value==='chatgpt_subscription'){
      request.account_id=$('memory-subscription-account')?.value||null;
      if(!request.account_id)throw new Error('请先连接并选择官方 ChatGPT 账号。');
      if(memorySubscriptionState?.account_id!==request.account_id)renderMemorySubscription(await memoryApi('/api/memory/subscription/select',{account_id:request.account_id}));
    }
    if(embed.value==='dashscope'&&legacy.checked)request.use_legacy_embedding=true;
    if(embedKey.value.trim())request.embedding_api_key=embedKey.value.trim();
    try{const result=await memoryApi('/api/memory/model',request);renderMemoryModel(result);$('notice').textContent='GPT 设置已保存；保存设置不会自动启动付费处理。';}
    finally{key.value='';embedKey.value='';legacy.checked=false;}
  }));
  display();
}

async function loadMemorySubscription(){
  const data=await memoryApi('/api/memory/subscription');renderMemorySubscription(data);return data;
}

function renderMemorySubscription(data){
  memorySubscriptionState=data;
  const box=$('memory-subscription-panel');if(!box)return;
  if(!box.childElementCount){
    const state=el('p');state.id='memory-subscription-state';
    const label=el('label','ChatGPT 账号 '),account=el('select');account.id='memory-subscription-account';label.append(account);
    const linkBox=el('p');linkBox.id='memory-subscription-login-link';
    const modelBox=el('div');modelBox.id='memory-subscription-models';
    const begin=async(id)=>{
      const result=await memoryApi('/api/memory/subscription/begin',id?{account_id:id}:{});
      if(typeof result.authorization_url!=='string'||!result.authorization_url.startsWith('https://auth.openai.com/api/accounts/authorize?'))throw new Error('官方登录地址无效。');
      const link=el('a','打开官方 ChatGPT 登录与授权');link.href=result.authorization_url;link.target='_blank';link.rel='noopener noreferrer';
      linkBox.replaceChildren(link,el('span','；完成后回到此页选择模型并保存。登录链接会过期。'));
      linkBox.scrollIntoView({block:'center'});
    };
    account.onchange=()=>{modelBox.replaceChildren();linkBox.replaceChildren();};
    const buttons=el('div',undefined,'memory-control-bar');
    buttons.append(action('Continue with ChatGPT · 登录',()=>begin(account.value)),action('添加另一个官方账号',()=>begin(null)),
      action('读取订阅可用模型',async()=>{
        if(!account.value)throw new Error('请先完成官方 ChatGPT 登录。');
        const selected=account.value;
        if(memorySubscriptionState?.account_id!==selected)renderMemorySubscription(await memoryApi('/api/memory/subscription/select',{account_id:selected}));
        const result=await memoryApi('/api/memory/subscription/models',{});
        if(result.account_id!==selected)throw new Error('账号已变化，请重新读取模型。');
        const modelLabel=el('label','订阅可用模型 '),choices=el('select');choices.id='memory-subscription-model-choice';
        for(const item of result.models||[]){const option=el('option',item.display_name||item.slug);option.value=item.slug;choices.append(option);}
        if(!choices.childElementCount)throw new Error('此账号暂未返回可用模型。');
        const current=$('memory-gpt-model').value;if((result.models||[]).some(item=>item.slug===current))choices.value=current;
        modelLabel.append(choices);modelBox.replaceChildren(modelLabel,action('使用所选模型',()=>{$('memory-gpt-model').value=choices.value;$('notice').textContent='型号已选择，请保存 GPT 设置。';}));
      }),action('断开所选订阅账号',async()=>{
        if(!account.value)throw new Error('没有已保存的订阅账号。');
        const result=await memoryApi('/api/memory/subscription/disconnect',{account_id:account.value});renderMemorySubscription(result);
        modelBox.replaceChildren();linkBox.replaceChildren();
        $('notice').textContent=result.remote_revocation_confirmed?'订阅连接已断开。':'本机已停止使用此连接；远端撤销未确认，可在 ChatGPT 设置中断开应用。';
      }));
    const usage=el('a','在 ChatGPT 中查看订阅用量与应用权限');usage.href='https://chatgpt.com/settings/usage';usage.target='_blank';usage.rel='noopener noreferrer';
    box.append(state,label,buttons,linkBox,modelBox,el('p','GPT 消耗订阅额度；额度不足时排队等待，不会自动切换到付费 API。Jev 和向量化各自独立计费。'),usage);
  }
  const hold={usage_limit_exceeded:'订阅额度暂不可用，整理已等待；不会自动切换到付费 API。',usage_unavailable:'订阅服务暂不可用，整理已等待。',access_denied:'订阅权限暂不可用，请重新登录并检查账号授权。',login_required:'订阅登录需要更新，请重新登录。'};
  $('memory-subscription-state').textContent=hold[data.availability_code]||(data.connected&&data.plan_usage&&!data.requires_login?'已连接官方订阅；具体模型仍需完成真实调用验证。':'等待官方登录，或当前账号尚未授权订阅用量。');
  const stamp=JSON.stringify([data.account_id,data.accounts]);
  if(stamp!==memorySubscriptionStamp){
    const account=$('memory-subscription-account'),prior=account.value;account.replaceChildren();
    for(const item of data.accounts||[]){const option=el('option',(item.label||item.email||item.account_id)+(item.connected&&!item.requires_login?'':'（需登录）'));option.value=item.account_id;account.append(option);}
    if(!(data.accounts||[]).length){const option=el('option','尚未连接账号');option.value='';account.append(option);}
    account.value=(data.accounts||[]).some(item=>item.account_id===prior)?prior:data.account_id||'';
    memorySubscriptionStamp=stamp;
  }
}

async function loadMemoryV3(){
  ensureMemoryV3();
  const values=await Promise.allSettled([memoryApi('/api/memory/controls'),memoryApi('/api/memory/model')]);
  if(values[0].status==='fulfilled')renderRoleMemory(values[0].value);
  else{$('memory-role-controls').replaceChildren(el('p','角色开关读取失败：'+values[0].reason.message,'error'));roleMemoryState=null;roleMemoryStamp='';}
  if(values[1].status==='fulfilled')renderMemoryModel(values[1].value);
  else $('memory-model-state').textContent='GPT 配置读取失败：'+values[1].reason.message;
  if($('memory-gpt-auth-mode')?.value==='chatgpt_subscription')try{await loadMemorySubscription();}catch(error){$('notice').textContent='订阅状态读取失败：'+error.message;}
  const box=$('memory-supplement-status');
  try{
    const data=await memoryApi('/api/memory/supplements');box.replaceChildren();
    if(data.items?.length)box.append(el('h3','已提交的补充'));
    for(const item of data.items||[])box.append(el('p',(roleMemoryState?.role_labels?.[item.scope]||item.scope)+' · '+usageTime(item.created_at)+' · '+(item.message_zh||({awaiting_processing:'补充已保存，等待处理',source_changed_or_unavailable:'来源已变化，需要重新核对'}[item.state])||'补充已保存')));
  }catch(error){box.replaceChildren(el('p','补充状态暂时无法读取：'+error.message));}
}

async function memorySourcePanel(item){
  const query=new URLSearchParams({event_id:item.source_event_id,scope:item.scope});
  const data=await memoryApi('/api/memory/sources/context?'+query);
  const box=$('memory-source-view');box.replaceChildren(el('h2','原始资料'),
    el('p',(roleMemoryState?.role_labels?.[data.scope]||data.scope)+' · '+data.event_id),
    el('p','来源时间：'+usageTime(data.times?.occurred_at)+' · 采集时间：'+usageTime(data.times?.captured_at)));
  for(const part of data.texts||[])box.append(el('small','内容类型：'+(part.fidelity||'已保存文本')),el('pre',part.text));
  for(const file of data.attachments||[]){
    const row=el('p',(file.original_name||file.source_label||file.snapshot_id)+' · '+usageCount(file.original?.size??file.size)+' 字节');
    if(file.original?.available&&file.original?.storage==='raw_object'){
      const link=el('a','下载保存的原文件');const q=new URLSearchParams({event_id:data.event_id,scope:data.scope,snapshot_id:file.snapshot_id});link.href='/api/memory/sources/original?'+q;link.target='_blank';row.append(el('br'),link);
    }else row.append(el('small',' · 原件受本地访问限制或未保存，详情见缺口'));
    box.append(row);
  }
  if(data.gaps?.length)box.append(el('p','采集说明：'+data.gaps.map(g=>typeof g==='string'?g:JSON.stringify(g)).join('；')));
  box.append(action('标记这份资料，帮助改进筛选',()=>localFeedbackContext(item)));
  box.scrollIntoView({behavior:'smooth',block:'start'});
}

async function localFeedbackContext(item){
  const query=new URLSearchParams({event_id:item.source_event_id,scope:item.scope});
  for(const field of ['run_id','triage_id'])if(item[field])query.set(field,item[field]);
  if(item.text_path)query.set('text_path',JSON.stringify(item.text_path));
  const context=await memoryApi('/api/memory/local-feedback/context?'+query);
  const box=$('memory-local-feedback');box.replaceChildren(el('h3','帮助改进筛选'),
    el('p','这是你的本机反馈，用于评测和改进筛选；不会直接确认其中的事实。'),el('pre',context.source_text));
  if(context.latest_feedback)box.append(el('p','当前标记：'+FEEDBACK_LABELS[context.latest_feedback.label]));
  const buttons=el('div');let sending=false;
  for(const [label,title] of Object.entries(FEEDBACK_LABELS)){
    const command=uuid();buttons.append(action(title,async()=>{
      if(sending)return;sending=true;
      try{await memoryApi('/api/memory/local-feedback',{...context.bindings,label,command_id:command});$('notice').textContent='已保存你的反馈；达到独立评测条件后才更新策略。';await localFeedbackContext(item);}
      finally{sending=false;}
    }));
  }
  box.append(buttons);box.scrollIntoView({behavior:'smooth',block:'start'});
}

async function showSupplement(item){
  const target=item.triage_id||item.candidate_id,version=item.version_digest;
  if(!target||!version)throw new Error('此记录缺少版本绑定，请刷新后重试');
  const box=$('memory-supplement-form');box.replaceChildren(el('h3','补充这条记忆'),
    el('p',item.question_zh||'请补充完整的主体、事实和时间；不知道的部分请注明未知。'),
    el('small','请写成可以独立理解的完整句子。补充内容会作为新的 RAW 保存，再按这个角色的开关处理。'));
  const input=el('textarea');input.value=supplementDrafts.get(target)||'';input.maxLength=4000;
  input.placeholder='例如：这里提到的账户属于……；这是一项计划，尚未执行。';
  input.oninput=()=>supplementDrafts.set(target,input.value);box.append(input);
  const command=uuid();box.append(action('保存补充并排队',async()=>{
    const result=await memoryApi('/api/memory/supplements',{target_id:target,scope:item.scope,expected_version:version,text:input.value,command_id:command});
    supplementDrafts.delete(target);input.value='';
    $('notice').textContent='补充已保存；状态：'+(result.queue_status||result.state)+'。完成核验后才形成正式记忆。';await memories();
  }));box.scrollIntoView({behavior:'smooth',block:'start'});input.focus();
}

async function retryMemoryItem(item){
  const result=await memoryApi('/api/memory/retry',{triage_id:item.triage_id,expected_digest:item.version_digest,command_id:uuid()});
  $('notice').textContent=result.status==='not_retryable'?'此项需要补充资料后重新处理；已完成的模型调用不会重复执行。':'已登记恢复请求，按角色开关继续处理。';
  if(result.can_supplement)await showSupplement(item);
}

async function showMemoryCoverage(){
  const data=await memoryApi('/api/memory/coverage');
  const box=$('memory-coverage');box.replaceChildren(el('h3','原始资料覆盖清单'),
    el('p',`已保存 ${usageCount(data.raw?.rows)} 条 RAW 记录，来自 ${usageCount(data.raw?.files)} 个记录文件；另有 ${usageCount(data.imports?.files)} 份导入文件。RAW 包含消息、回执和来源记录，不等于有效记忆条数。`),
    el('p',`模型已处理 ${usageCount(data.processing?.unique_screened_sources)} 个不同来源。保存资料和模型处理是两种进度。`));
  const rows=Object.entries(data.raw?.by_role||{}).map(([role,count])=>[roleMemoryState?.role_labels?.[role]||(role==='unresolved'?'待归属资料':role),usageCount(count),roleMemoryState?.roles?.[role]===true?'开启':roleMemoryState?.roles?.[role]===false?'关闭':'待归属']);
  box.append(usageTable(['角色板块','RAW 记录','结构化处理设置'],rows),
    el('p',`需要对账：缺少事件编号 ${usageCount(data.raw?.missing_event_id)} 条；编号内容冲突 ${usageCount(data.raw?.conflicting_event_ids)} 项；无法解析 ${usageCount(data.raw?.invalid_json_records)} 条。`),
    el('small','统计截至 '+usageTime(data.generated_at)+'。本次检查只读取资料，不会发送模型或加入处理队列。'));
}
