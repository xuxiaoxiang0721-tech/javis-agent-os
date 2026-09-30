"""Generate the single allowed deterministic Flowise Agentflow V2 definition."""
from pathlib import Path
import json
WORKFLOW_ID='invest-fixed-review-v1'
SOCKET='/home/user/javis/state/control/flowise.sock'
FIXTURE=(Path(__file__).parent/(WORKFLOW_ID+'.txt')).read_text(encoding='utf-8')
COMMON=r'''
const http = require('http');
const crypto = require('crypto');
const socketPath = __SOCKET__;
async function control(method, path, body) {
  return await new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const request = http.request({socketPath, path, method, headers:{'Content-Type':'application/json','Content-Length':payload === undefined ? '0' : String(Buffer.byteLength(payload))}}, response => {
      let data = ''; let size = 0;
      response.setEncoding('utf8');
      response.on('data', chunk => { size += Buffer.byteLength(chunk); if(size>1048576) {request.destroy(); reject(new Error('Control response too large'));} else data += chunk; });
      response.on('end', () => {
        try { resolve({code:response.statusCode,body:JSON.parse(data)}); }
        catch (_) {reject(new Error('Control response was not JSON'));}
      });
    });
    request.setTimeout(10000, () => request.destroy(new Error('Control request timed out')));
    request.on('error', () => reject(new Error('Control connection unavailable; do not resubmit blindly')));
    request.end(payload);
  });
}
function requireOK(response) { if(response.code<200 || response.code>=300 || response.body.ok === false) throw new Error('Control rejected request: HTTP '+response.code); return response.body; }
'''
SUBMIT=r'''
const supplied = typeof $flow.input === 'string' ? JSON.parse($flow.input) : $flow.input;
const original_text = __FIXTURE__;
if(!supplied || typeof supplied.command_id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(supplied.command_id)) throw new Error('Invalid stable command_id');
if(supplied.original_text !== undefined && supplied.original_text !== original_text) throw new Error('Fixed workflow rejects altered input');
const payload = {command_id:supplied.command_id,role_id:'invest',original_text,source_line:3,permission:'R1',workflow_id:'invest-fixed-review-v1'};
const expectedHash = crypto.createHash('sha256').update(original_text,'utf8').digest('hex');
let lookup = await control('GET','/api/commands/'+encodeURIComponent(supplied.command_id));
let result;
if(lookup.code===404) {
  try { result = requireOK(await control('POST','/api/tasks',payload)); }
  catch(error) {
    lookup=await control('GET','/api/commands/'+encodeURIComponent(supplied.command_id));
    if(lookup.code!==200) throw new Error('Submission status unknown; retain command_id for reviewed recovery');
    result=requireOK(lookup);
  }
} else result=requireOK(lookup);
// A found command must bind this immutable fixture; it is not permission to reuse an unrelated task.
if(result.original_text_sha256!==expectedHash || result.role_id!=='invest' || result.source_line!==3 || result.permission!=='R1' || result.workflow_id!=='invest-fixed-review-v1') throw new Error('Existing command identity/input mismatch');
if(typeof result.task_id!=='string' || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/.test(result.task_id)) throw new Error('No authoritative task_id; do not submit again');
return {task_id:result.task_id,command_id:supplied.command_id,original_text_sha256:expectedHash};
'''
STATUS=r'''
const task_id=$flow.state.task_id;
if(typeof task_id!=='string'||!task_id) throw new Error('Missing task_id');
const status=requireOK(await control('GET','/api/tasks/'+encodeURIComponent(task_id)));
return {task_id,state:status.state,attempt:status.attempt,current_goal_completed:status.current_goal_completed===true};
'''
RESULT=r'''
const task_id=$flow.state.task_id;
const status=typeof $flow.state.task_status==='string'?JSON.parse($flow.state.task_status):$flow.state.task_status;
const terminal=['completed','succeeded','failed','cancelled','blocked','needs_review','interrupted'];
if(!status.current_goal_completed && !terminal.includes(status.state)) return {...status,pending:true};
const response=await control('GET','/api/tasks/'+encodeURIComponent(task_id)+'/result');
if(response.code===404) return {...status,pending:false,result_available:false};
const result=requireOK(response);
return {...status,pending:false,result:result.result,result_ref:result.result_ref,result_sha256:result.result_sha256,current_goal_completed:result.current_goal_completed===true};
'''

def build_flow(socket_path=SOCKET):
    common=COMMON.replace('__SOCKET__',json.dumps(socket_path))
    def node(name,id,label,kind,inputs,x):
        return {'id':id,'type':'agentFlow','position':{'x':x,'y':100},'data':{'id':id,'label':label,'name':name,'type':kind,'version':1.4 if kind=='Start' else 1.1,'category':'Agent Flows','baseClasses':[kind],'color':'#7EE787' if kind=='Start' else '#E4B7FF','inputs':inputs,'inputParams':[],'inputAnchors':[],'outputAnchors':[{'id':id+'-output-'+name,'label':label,'name':name}],'outputs':{}}}
    nodes=[node('startAgentflow','startAgentflow_0','固定工作入口','Start',{'startInputType':'chatInput','startEphemeralMemory':True,'startPersistState':False,'startState':[{'key':'task_id','value':''},{'key':'task_status','value':''}]},0)]
    for index,(label,code,updates) in enumerate([
        ('核对去重并提交',SUBMIT.replace('__FIXTURE__',json.dumps(FIXTURE,ensure_ascii=False)),[{'key':'task_id','value':'{{ output.task_id }}'}]),
        ('查询权威任务状态',STATUS,[{'key':'task_status','value':'{{ output }}'}]),
        ('读取权威执行结果',RESULT,[])],1):
        nodes.append(node('customFunctionAgentflow',f'customFunctionAgentflow_{index}',label,'CustomFunction',{'customFunctionInputVariables':[],'customFunctionJavascriptFunction':common+code,'customFunctionUpdateState':updates},index*270))
    edges=[]
    for source,target in zip(nodes,nodes[1:]):
        edges.append({'id':source['id']+'-'+target['id'],'source':source['id'],'sourceHandle':source['id']+'-output-'+source['data']['name'],'target':target['id'],'targetHandle':target['id'],'type':'agentFlow','data':{'sourceColor':source['data']['color'],'targetColor':target['data']['color'],'isHumanInput':False}})
    return {'nodes':nodes,'edges':edges,'viewport':{'x':0,'y':0,'zoom':0.8}}

if __name__=='__main__':
    print(json.dumps(build_flow(),ensure_ascii=False,indent=2))
