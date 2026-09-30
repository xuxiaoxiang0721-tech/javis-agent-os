#!/usr/bin/env python3
"""Read-only post-boot check. Never submits a task or enables a schedule."""
import argparse,json,os,socket,subprocess,time,urllib.request
from pathlib import Path
from memory_sync import recovery_held, status as memory_sync_status
from memory_pipeline import status as memory_pipeline_status


def memory_health(root):
    """Public counters only: no source text, RAW refs, actors, IDs or paths."""
    root = Path(root).resolve()
    value = {'sync': memory_sync_status(root), 'pipeline': {'configured': False}}
    try:value['queue']=memory_pipeline_status(root)
    except (OSError,ValueError,TypeError):value['queue']={'status':'unavailable'}
    path = root / 'memory/screen/runs.jsonl'
    states = ('pending', 'running', 'complete', 'completed', 'retry', 'blocked', 'failed', 'other')
    try:
        for parent in (root/'memory', root/'memory/screen', path):
            if parent.is_symlink():
                raise ValueError('unsafe_pipeline_path')
        if not path.exists():
            return value
        latest = {}; malformed = 0
        with path.open(encoding='utf-8') as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    run_id = row.get('run_id') if isinstance(row, dict) else None
                    state = row.get('status') if isinstance(row, dict) else None
                    if not isinstance(run_id, str) or not run_id:
                        raise ValueError('invalid_run')
                    latest[run_id] = state if isinstance(state, str) and state in states else 'other'
                except (ValueError, TypeError):
                    malformed += 1
        counts = {state: sum(item == state for item in latest.values()) for state in states}
        value['pipeline'] = {'configured': True, 'run_count': len(latest), 'by_status': counts,
                             'malformed_record_count': malformed,
                             'attention_required': bool(malformed or counts['retry'] or counts['blocked'] or counts['failed'] or counts['other'])}
    except (OSError, ValueError, TypeError):
        value['pipeline'] = {'configured': True, 'attention_required': True, 'error': 'pipeline_status_unreadable'}
    return value

def check(root):
    root=Path(root).resolve();value={'checked_at':time.time(),'root':str(root),'read_only':True,
        'wsl_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'issues':[]}
    env={**os.environ,'XDG_RUNTIME_DIR':'/run/user/'+str(os.getuid()),'DBUS_SESSION_BUS_ADDRESS':'unix:path=/run/user/'+str(os.getuid())+'/bus'}
    result=subprocess.run(['systemctl','--user','show','javis-control-panel.service','javis-task-dispatch.service',
        'javis-invest-fixed-review.timer','javis-memory-pipeline.timer','--property=Id,ActiveState,SubState,MainPID,UnitFileState','--no-pager'],env=env,capture_output=True,text=True,timeout=5)
    value['units']=[dict(line.split('=',1) for line in block.splitlines() if '=' in line) for block in result.stdout.strip().split('\n\n') if block]
    try:value['monitor']=json.loads(urllib.request.urlopen('http://localhost:8766/api/auth/info',timeout=4).read())
    except Exception as exc:value['issues'].append('monitor:'+type(exc).__name__)
    health=root/'state/drop-bridge/health.json'
    if health.exists():
        value['drop_bridge']=json.loads(health.read_text());value['drop_bridge']['stale']=time.time()-value['drop_bridge'].get('updated_at',0)>30
        if value['drop_bridge']['stale']:value['issues'].append('drop_bridge_heartbeat_stale')
    else:value['issues'].append('drop_bridge_health_missing')
    value['neo4j']={}
    for port in [7474,7687]:
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=2):value['neo4j'][str(port)]='reachable'
        except OSError:value['neo4j'][str(port)]='unreachable'
    value['active_tasks']=[];value['managed_tasks']=[]
    for path in (root/'state/control').glob('t-*.json'):
        c=json.loads(path.read_text());s=root/'state/tasks'/path.name
        state=json.loads(s.read_text()) if s.exists() else {}
        item={k:state.get(k) for k in ('task_id','role_id','state','attempt','session_id')}
        item.update(goal_revision=c.get('goal_revision'),applied_goal_revision=c.get('applied_goal_revision'))
        value['managed_tasks'].append(item)
        if item['state'] in {'created','running','queued'}:value['active_tasks'].append(item)
    value['recovery_hold']=recovery_held(root)
    value['memory']=memory_health(root)
    job=root/'state/fixed-work/invest-fixed-review-v1.json'
    value['fixed_work']=json.loads(job.read_text()) if job.exists() else {'configured':False}
    p=root/'state/backup/last-success.json';value['last_successful_backup']=json.loads(p.read_text()) if p.exists() else None
    value['vault_initialized']={'personal':Path('/mnt/c/Users/user/Javis-Vault/personal/personal.kdbx').is_file(),
        'program':Path('/mnt/c/Users/user/Javis-Vault/program/program.kdbx').is_file()}
    value['strict_L4_local_chain']='BLOCKED: no verified fully local reasoning/OCR/embedding chain'
    value['off_machine_backup']='known gap: same-machine copy only'
    return value

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',default=str(Path.home()/'javis'));p.add_argument('--output')
    a=p.parse_args();value=check(a.root);data=json.dumps(value,ensure_ascii=False,indent=2)
    if a.output:
        path=Path(a.output);path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('x',encoding='utf-8') as f:f.write(data+'\n')
    print(data)
