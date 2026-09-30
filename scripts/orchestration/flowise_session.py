#!/usr/bin/env python3
"""One-run Flowise instance: loopback listener, tmpfs DB, in-memory credentials.
No Javis business submission is performed by this module itself.
"""
from __future__ import annotations
import collections, http.cookiejar, json, os, pathlib, re, secrets, shutil, socket
import subprocess, tempfile, threading, time, urllib.error, urllib.request

BASE = pathlib.Path('/home/user/javis/tools/flowise')

class FlowiseSession:
    def __init__(self, base=BASE):
        self.base=pathlib.Path(base).resolve()
        runtime=pathlib.Path('/run/user') / str(os.getuid())
        if not runtime.is_dir() or runtime.stat().st_uid != os.getuid():
            raise RuntimeError('Owned tmpfs runtime directory is required')
        mounts=pathlib.Path('/proc/mounts').read_text().splitlines()
        relevant=[line.split() for line in mounts if str(runtime).startswith(line.split()[1].rstrip('/')+'/') or str(runtime)==line.split()[1]]
        if not relevant or max(relevant,key=lambda x:len(x[1]))[2] != 'tmpfs':
            raise RuntimeError('Runtime directory must be on tmpfs')
        self.runtime=runtime
        self.run_dir=pathlib.Path(tempfile.mkdtemp(prefix='javis-flowise-',dir=runtime))
        self.proc=None; self.log_tail=collections.deque(maxlen=80); self.secret_values=[]
        self.password=secrets.token_urlsafe(36)+'Aa1!'; self.secret_values.append(self.password)
        self.email='javis-once-'+secrets.token_hex(8)+'@localhost.invalid'
        self.cookies=http.cookiejar.CookieJar()
        self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies),urllib.request.ProxyHandler({}))
        with socket.socket() as s:
            s.bind(('127.0.0.1',0)); self.port=s.getsockname()[1]
        self.url='http://127.0.0.1:'+str(self.port)

    def request(self,method,path,payload=None,authenticated=True,timeout=30):
        raw=None if payload is None else json.dumps(payload,ensure_ascii=False).encode('utf-8')
        headers={'Content-Type':'application/json','Origin':self.url}
        if authenticated: headers['x-request-from']='internal'
        req=urllib.request.Request(self.url+path,data=raw,headers=headers,method=method)
        try:
            with self.client.open(req,timeout=timeout) as r:
                data=r.read(2*1024*1024); status=r.status
        except urllib.error.HTTPError as e:
            # Never print response bodies from credential endpoints.
            e.read(); raise RuntimeError(f'Flowise HTTP {e.code} {method} {path}') from None
        try: body=json.loads(data)
        except (ValueError,UnicodeError): body=data.decode(errors='replace')
        return status,body

    def start(self):
        for name in ('database','logs','storage','secret'):(self.run_dir/name).mkdir(mode=0o700)
        env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','HOST':'127.0.0.1','PORT':str(self.port),
             'APP_URL':self.url,'DATABASE_TYPE':'sqlite','DATABASE_PATH':str(self.run_dir/'database'),
             'SECRETKEY_PATH':str(self.run_dir/'secret'),'LOG_PATH':str(self.run_dir/'logs'),
             'BLOB_STORAGE_PATH':str(self.run_dir/'storage'),'STORAGE_TYPE':'local','MODE':'main',
             'DEBUG':'false','LOG_LEVEL':'error','DISABLE_FLOWISE_TELEMETRY':'true',
             'EXPIRE_AUTH_TOKENS_ON_RESTART':'true','JWT_TOKEN_EXPIRY_IN_MINUTES':'30',
             'JWT_REFRESH_TOKEN_EXPIRY_IN_MINUTES':'30','JWT_ISSUER':'javis-once','JWT_AUDIENCE':'javis-once',
             'TRUST_PROXY':'false','CORS_ORIGINS':self.url,'IFRAME_ORIGINS':self.url,
             'SHOW_COMMUNITY_NODES':'false','TOOL_FUNCTION_BUILTIN_DEP':'http',
             'ALLOW_BUILTIN_DEP':'false','CUSTOM_MCP_SECURITY_CHECK':'true',
             'DENYLIST_URLS':'/api/v1/prediction/,/api/v1/public-chatflows,/api/v1/public-executions',
             'LOG_SANITIZE_BODY_FIELDS':'credential,password,user,token,apiKey,secret',
             'LOG_SANITIZE_HEADER_FIELDS':'authorization,cookie,set-cookie'}
        for name in ('FLOWISE_SECRETKEY_OVERWRITE','TOKEN_HASH_SECRET','EXPRESS_SESSION_SECRET','JWT_AUTH_TOKEN_SECRET','JWT_REFRESH_TOKEN_SECRET'):
            value=secrets.token_urlsafe(48); env[name]=value; self.secret_values.append(value)
        allowed={'startAgentflow','customFunctionAgentflow','directReplyAgentflow'}
        found=set()
        for p in (self.base/'node_modules/flowise-components/dist/nodes').rglob('*.js'):
            found.update(re.findall(r"this\.name\s*=\s*['\"]([^'\"]+)",p.read_text(errors='replace')))
        env['DISABLED_NODES']=','.join(sorted(found-allowed))
        self.proc=subprocess.Popen(['/usr/bin/node',str(self.base/'node_modules/flowise/bin/run'),'start'],
            cwd=self.run_dir,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True)
        def drain():
            for line in self.proc.stdout:self.log_tail.append(line.rstrip())
        self.log_thread=threading.Thread(target=drain,daemon=True);self.log_thread.start()
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            if self.proc.poll() is not None:
                raise RuntimeError('Flowise exited before readiness; '+self.safe_log())
            try:
                status,_=self.request('GET','/api/v1/ping',authenticated=False,timeout=1)
                if status==200:break
            except (OSError,RuntimeError):time.sleep(0.3)
        else:raise RuntimeError('Flowise readiness timeout; '+self.safe_log())
        self.request('POST','/api/v1/account/register',{'user':{'name':'Javis Ephemeral Runner','email':self.email,'credential':self.password}},authenticated=False)
        self.request('POST','/api/v1/auth/login',{'email':self.email,'password':self.password},authenticated=False)
        # No account, password, cookie or API key is written outside this tmpfs session.
        return self

    def safe_log(self):
        result='\n'.join(self.log_tail)[-3000:]
        for value in self.secret_values:result=result.replace(value,'[REDACTED]')
        result=result.replace(self.email,'[EPHEMERAL_USER]')
        return result

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=5)
        if hasattr(self,'log_thread'):self.log_thread.join(timeout=2)
        leaked=[]
        for p in self.run_dir.rglob('*'):
            if p.is_file() and p.stat().st_size<20*1024*1024:
                data=p.read_bytes()
                if any(v.encode() in data for v in self.secret_values):leaked.append(str(p.relative_to(self.run_dir)))
        self.secret_leak_files=leaked
        # Delete only this newly created, ownership-checked tmpfs directory.
        if self.run_dir.parent==self.runtime and self.run_dir.name.startswith('javis-flowise-') and self.run_dir.stat().st_uid==os.getuid():
            shutil.rmtree(self.run_dir)
        if leaked:raise RuntimeError('Ephemeral credential unexpectedly present in session files: '+','.join(leaked))

    def __enter__(self):
        try:return self.start()
        except BaseException:
            self.close();raise
    def __exit__(self,*args):self.close()

if __name__=='__main__':
    with FlowiseSession() as session:
        status,data=session.request('GET','/api/v1/chatflows')
        print(json.dumps({'phase':'isolated_startup_auth','status':'passed','version':'3.1.4','host':'127.0.0.1','port':session.port,'authenticated_status':status,'model_requests':0,'business_submissions':0}))
    print(json.dumps({'phase':'cleanup','tmpfs_removed':not session.run_dir.exists(),'plaintext_secret_files':session.secret_leak_files}))