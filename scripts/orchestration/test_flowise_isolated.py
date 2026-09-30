#!/usr/bin/env python3
"""Isolated real Flowise import/prediction against a fake Unix control endpoint."""
import hashlib,json,pathlib,socketserver,threading,urllib.request,urllib.error
from http.server import BaseHTTPRequestHandler
from flowise_session import FlowiseSession
from flowise_flow import build_flow,FIXTURE,WORKFLOW_ID

class FakeControl(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
    daemon_threads=True
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def send(self,code,data):
        raw=json.dumps(data,ensure_ascii=False).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        self.server.paths.append(('GET',self.path))
        if self.path.startswith('/api/commands/'):
            data=self.server.commands.get(self.path.rsplit('/',1)[-1]);return self.send(200 if data else 404,data or {'ok':False})
        if self.path=='/api/tasks/t-isolated-flowise-1':return self.send(200,{'ok':True,'state':'completed','attempt':1,'current_goal_completed':True})
        if self.path=='/api/tasks/t-isolated-flowise-1/result':return self.send(200,{'ok':True,'result':{'summary':'FAKE ENDPOINT: no model or business task ran'},'result_ref':'fake://test/result.json','result_sha256':'f'*64,'current_goal_completed':True})
        self.send(404,{'ok':False})
    def do_POST(self):
        self.server.paths.append(('POST',self.path))
        body=json.loads(self.rfile.read(int(self.headers['Content-Length']))) if 'Content-Length' in self.headers else None
        if body is None:
            # Node http.request uses chunked transfer without explicit Content-Length.
            chunks=[]
            while True:
                n=int(self.rfile.readline().strip(),16)
                if n==0:self.rfile.readline();break
                chunks.append(self.rfile.read(n));self.rfile.read(2)
            body=json.loads(b''.join(chunks))
        if self.path!='/api/tasks' or body.get('original_text')!=FIXTURE or body.get('workflow_id')!=WORKFLOW_ID:return self.send(400,{'ok':False})
        self.server.post_count+=1
        receipt={k:body[k] for k in ('command_id','role_id','source_line','permission','workflow_id')}
        receipt.update(ok=True,task_id='t-isolated-flowise-1',original_text_sha256=hashlib.sha256(FIXTURE.encode()).hexdigest())
        self.server.commands[body['command_id']]=receipt;self.send(202,receipt)

session=FlowiseSession();fake=None
try:
    socket_path=session.run_dir/'fake-control.sock'
    fake=FakeControl(str(socket_path),Handler);fake.commands={};fake.paths=[];fake.post_count=0
    threading.Thread(target=fake.serve_forever,daemon=True).start()
    session.start()
    flow=build_flow(str(socket_path))
    _,imported=session.request('POST','/api/v1/chatflows',{'name':'Javis isolated deterministic fixture','flowData':json.dumps(flow,ensure_ascii=False),'type':'AGENTFLOW','isPublic':False,'deployed':True})
    flow_id=imported['id']
    body={'question':json.dumps({'command_id':'isolated-fixed-test-1'},ensure_ascii=False),'streaming':False}
    first_status,first=session.request('POST','/api/v1/prediction/'+flow_id,body,timeout=90)
    second_status,second=session.request('POST','/api/v1/prediction/'+flow_id,body,timeout=90)
    # Public calls must be rejected even when the caller knows this flow ID.
    anon=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req=urllib.request.Request(session.url+'/api/v1/prediction/'+flow_id,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'},method='POST')
    try:
        with anon.open(req,timeout=10) as r:anonymous_status=r.status
    except urllib.error.HTTPError as e:anonymous_status=e.code;e.read()
    assert first_status==200 and second_status==200
    assert fake.post_count==1,('duplicate submission',fake.post_count)
    assert anonymous_status==401,anonymous_status
    assert any(p.endswith('/result') for _,p in fake.paths)
    changed_rejected=False
    try:session.request('POST','/api/v1/prediction/'+flow_id,{'question':json.dumps({'command_id':'isolated-fixed-test-1','original_text':FIXTURE+' changed'}),'streaming':False},timeout=90)
    except RuntimeError:changed_rejected=True
    assert changed_rejected and fake.post_count==1
    fake.commands['isolated-fixed-test-1']['original_text_sha256']='0'*64
    rebound_rejected=False
    try:session.request('POST','/api/v1/prediction/'+flow_id,body,timeout=90)
    except RuntimeError:rebound_rejected=True
    assert rebound_rejected and fake.post_count==1
    print(json.dumps({'phase':'isolated_flowise_import_prediction','passed':True,'flow_id':flow_id,'version':'3.1.4','node_types':[n['data']['name'] for n in flow['nodes']],'fake_control_submissions':fake.post_count,'successful_prediction_runs':2,'anonymous_status':anonymous_status,'changed_text_rejected':changed_rejected,'rebound_command_rejected':rebound_rejected,'business_submissions':0,'model_requests':0,'result':json.loads(first['text'])},ensure_ascii=False))
except Exception:
    print('SANITIZED_SERVER_TAIL',session.safe_log());raise
finally:
    if fake:fake.shutdown();fake.server_close()
    session.close()
    print(json.dumps({'phase':'cleanup','tmpfs_removed':not session.run_dir.exists(),'plaintext_secret_files':session.secret_leak_files}))
