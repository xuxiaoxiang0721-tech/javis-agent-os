#!/usr/bin/env python3
"""One fixed Invest workflow, durable command identity, CAS scheduling controls."""
from __future__ import annotations
import argparse, contextlib, datetime as dt, fcntl, hashlib, json, os, pathlib, re
import subprocess, sys, uuid, time
from zoneinfo import ZoneInfo

JOB_ID='invest-fixed-review-v1'
TIMER='javis-invest-fixed-review.timer'
HERE=pathlib.Path(__file__).resolve().parent
ACTIVE={'queued','starting','running'}

def now():return dt.datetime.now(ZoneInfo('Asia/Shanghai')).isoformat()
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def check_id(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}',value):raise ValueError('Invalid command_id')
    return value

def fixed_text():return (HERE/(JOB_ID+'.txt')).read_text(encoding='utf-8')

def recovery_held(root):
    path=pathlib.Path(root)/'state/recovery-hold.json'
    if not path.exists() and not path.is_symlink():return False
    try:return not (isinstance(value:=read(path),dict) and value.get('hold') is False)
    except (OSError,ValueError,TypeError):return True

def validate_submission(root,body):
    allowed={'command_id','role_id','original_text','source_line','permission','workflow_id','source_event_id'}
    required=allowed-{'source_event_id'}
    if not isinstance(body,dict) or set(body)-allowed or required-set(body):raise ValueError('Fixed workflow field allowlist violation')
    check_id(body['command_id'])
    if (body['workflow_id']!=JOB_ID or body['role_id']!='invest' or type(body['source_line']) is not int or body['source_line']!=3 or body['permission']!='R1' or body['original_text']!=fixed_text() or body.get('source_event_id') is not None):
        raise ValueError('Fixed workflow identity or immutable fixture mismatch')
    return {'command_id':body['command_id'],'role_id':'invest','original_text':body['original_text'],'source_line':3,'permission':'R1','source_event_id':None,'entry':'flowise:'+JOB_ID}

def atomic(path,value):
    path=pathlib.Path(path)
    if path.is_symlink():raise ValueError('State path must not be a symlink')
    tmp=path.with_name('.'+path.name+'.'+uuid.uuid4().hex+'.tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as stream:
            json.dump(value,stream,ensure_ascii=False,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if tmp.exists():tmp.unlink()

def read(path):
    path=pathlib.Path(path)
    if path.is_symlink():raise ValueError('State path must not be a symlink')
    return json.loads(path.read_text(encoding='utf-8'))

class FixedWorkManager:
    def __init__(self,root,systemd=None,launcher=None):
        self.root=pathlib.Path(root).resolve();self.base=self.root/'state/fixed-work';self.runs=self.base/'runs';self.commands=self.base/'commands'
        for path in (self.base,self.runs,self.commands):
            if path.is_symlink():raise ValueError('Fixed work directory must not be a symlink')
            path.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.systemd=systemd or self._systemd
        self.launcher=launcher or self._launch
        self.job_path=self.base/(JOB_ID+'.json')
        with self.lock():
            if not self.job_path.exists():atomic(self.job_path,{'schema_version':1,'job_id':JOB_ID,'name':'Invest 合成资料摘要','role_id':'invest','enabled':False,'version':1,'timezone':'Asia/Shanghai','schedule':'每天09:00（默认停用）','systemd_timer':TIMER,'created_at':now(),'updated_at':now(),'original_text_sha256':hashlib.sha256(fixed_text().encode()).hexdigest()})

    @contextlib.contextmanager
    def lock(self):
        path=self.base/'.lock'
        if path.is_symlink():raise ValueError('Lock must not be a symlink')
        with path.open('a') as f:
            fcntl.flock(f,fcntl.LOCK_EX)
            try:yield
            finally:fcntl.flock(f,fcntl.LOCK_UN)

    @staticmethod
    def _systemd(*args):
        env=dict(os.environ);env['XDG_RUNTIME_DIR']='/run/user/'+str(os.getuid());env['DBUS_SESSION_BUS_ADDRESS']='unix:path='+env['XDG_RUNTIME_DIR']+'/bus'
        p=subprocess.run(['systemctl','--user',*args],env=env,capture_output=True,text=True,timeout=15)
        return {'returncode':p.returncode,'stdout':p.stdout.strip(),'stderr':p.stderr.strip()[:500]}

    def _launch(self,run_id):
        log=self.runs/(run_id+'.log')
        fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:
            return subprocess.Popen([sys.executable,'-B',str(HERE/'flowise_runner.py'),'--root',str(self.root),'--run-id',run_id],stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True,close_fds=True)

    def _check_job(self,job_id):
        if job_id!=JOB_ID:raise ValueError('Unknown fixed workflow')

    def _cached(self,command_id,fingerprint):
        path=self.commands/(hashlib.sha256(command_id.encode()).hexdigest()+'.json')
        if path.exists():
            old=read(path)
            if old['fingerprint']!=fingerprint:raise ValueError('command_id_conflict')
            return path,old
        return path,None

    def list_jobs(self):return [self.status(JOB_ID)['job']]

    def status(self,job_id=JOB_ID):
        self._check_job(job_id)
        with self.lock():
            job=read(self.job_path)
            runs=[read(p) for p in self.runs.glob('fw-*.json')]
        runs.sort(key=lambda x:x.get('created_at',''),reverse=True)
        state=self.systemd('is-active',TIMER)
        job['timer_active']=state['stdout']=='active';job['timer_status']=state['stdout'] or 'unknown'
        job['effective_schedule_enabled']=job['enabled'] and job['timer_active']
        job['attention_required']=job['enabled']!=job['timer_active']
        job['recovery_hold']=recovery_held(self.root)
        job['effective_schedule_enabled']=job['effective_schedule_enabled'] and not job['recovery_hold']
        job['attention_required']=job['attention_required'] or job['recovery_hold']
        return {'ok':True,'job':job,'runs':runs[:20]}

    def set_enabled(self,job_id,enabled,expected_version,command_id,actor='local-user'):
        self._check_job(job_id);check_id(command_id)
        if type(enabled) is not bool or type(expected_version) is not int:raise ValueError('enabled and expected_version must be typed')
        fp=digest({'job_id':job_id,'action':'enable' if enabled else 'disable','expected_version':expected_version})
        with self.lock():
            path,old=self._cached(command_id,fp)
            if old:return {**old['response'],'replayed':True}
            if enabled and recovery_held(self.root):raise ValueError('recovery_hold')
            job=read(self.job_path)
            if job['version']!=expected_version:raise ValueError('version_conflict')
            intent={'fingerprint':fp,'command_id':command_id,'actor':str(actor)[:160],'created_at':now(),'response':{'ok':False,'state':'needs_review','reason':'schedule_transition_interrupted','job':job}}
            atomic(path,intent)
            result=self.systemd('enable' if enabled else 'disable','--now',TIMER)
            if result['returncode']:
                response={'ok':False,'state':'failed','reason':'systemd_transition_failed','job':job,'systemd':result}
            else:
                job.update(enabled=enabled,version=job['version']+1,updated_at=now());atomic(self.job_path,job)
                response={'ok':True,'job':job,'command_id':command_id,'replayed':False}
            intent['response']=response;atomic(path,intent)
            return response

    def run_once(self,job_id,command_id,actor='local-user',scheduled_at=None,expected_version=None):
        self._check_job(job_id);check_id(command_id)
        if scheduled_at is not None:
            stamp=dt.datetime.fromisoformat(scheduled_at)
            if stamp.tzinfo is None:raise ValueError('scheduled_at needs timezone')
        # Trigger time is provenance of the first delivery, not a new command.
        # A manual replay of the same scheduled command keeps that provenance.
        fp=digest({'job_id':job_id,'action':'run_once'})
        with self.lock():
            path,old=self._cached(command_id,fp)
            if old:
                record=read(self.runs/(old['run_id']+'.json'))
                return {'ok':record['state']!='launch_failed','run':record,'run_id':record['run_id'],'task_id':record.get('task_id'),'replayed':True}
            if expected_version is not None:
                if type(expected_version) is not int or read(self.job_path)['version']!=expected_version:
                    raise ValueError('version_conflict')
            if recovery_held(self.root):raise ValueError('recovery_hold')
            if scheduled_at is not None and not read(self.job_path)['enabled']:raise ValueError('schedule_disabled')
            for item in self.runs.glob('fw-*.json'):
                if read(item)['state'] in ACTIVE:raise ValueError('fixed_work_busy_or_needs_review')
            run_id='fw-'+hashlib.sha256((job_id+'\0'+command_id).encode()).hexdigest()[:24]
            record={'schema_version':1,'run_id':run_id,'job_id':job_id,'command_id':command_id,'actor':str(actor)[:160],'scheduled_at':scheduled_at,'actual_at':None,'timezone':'Asia/Shanghai','task_id':None,'attempt':None,'state':'queued','created_at':now(),'updated_at':now(),'original_text_sha256':hashlib.sha256(fixed_text().encode()).hexdigest()}
            atomic(self.runs/(run_id+'.json'),record)
            atomic(path,{'fingerprint':fp,'command_id':command_id,'run_id':run_id,'created_at':now()})
            try:
                child=self.launcher(run_id);record['runner_pid']=child.pid
            except Exception as error:record.update(state='launch_failed',error_type=type(error).__name__)
            atomic(self.runs/(run_id+'.json'),record)
            return {'ok':record['state']!='launch_failed','run':record,'run_id':run_id,'task_id':None,'replayed':False}

    def update_run(self,run_id,**changes):
        if not re.fullmatch(r'fw-[a-f0-9]{24}',run_id):raise ValueError('Invalid run_id')
        with self.lock():
            path=self.runs/(run_id+'.json');record=read(path);record.update(changes,updated_at=now());atomic(path,record);return record

    def scheduled(self,scheduled_at=None):
        current=dt.datetime.now(ZoneInfo('Asia/Shanghai'))
        stamp=dt.datetime.fromisoformat(scheduled_at) if scheduled_at else current.replace(hour=9,minute=0,second=0,microsecond=0)
        if not scheduled_at and stamp>current:stamp-=dt.timedelta(days=1)
        if stamp.tzinfo is None:raise ValueError('scheduled_at needs timezone')
        slot=stamp.isoformat()
        command_id='schedule-'+hashlib.sha256((JOB_ID+'\0'+slot).encode()).hexdigest()[:32]
        return self.run_once(JOB_ID,command_id,actor='systemd:'+TIMER,scheduled_at=slot)

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=pathlib.Path,default=pathlib.Path('/home/user/javis'));p.add_argument('action',choices=['status','scheduled']);p.add_argument('--scheduled-at');args=p.parse_args()
    manager=FixedWorkManager(args.root)
    result=manager.status() if args.action=='status' else manager.scheduled(args.scheduled_at)
    if args.action=='scheduled' and result.get('ok'):
        # Keep the oneshot service alive until its child finishes. Do not orphan
        # a model task when systemd closes the service control group.
        deadline=time.monotonic()+1150
        while time.monotonic()<deadline:
            record=read(manager.runs/(result['run_id']+'.json'))
            if record['state'] not in ACTIVE:
                result={'ok':record['state']=='completed','run':record};break
            time.sleep(2)
        else:result={'ok':False,'state':'needs_review','reason':'scheduled_wait_timeout','run_id':result['run_id']}
    print(json.dumps(result,ensure_ascii=False));return 0 if result.get('ok') else 1
if __name__=='__main__':raise SystemExit(main())
