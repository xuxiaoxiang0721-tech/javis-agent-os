#!/usr/bin/env python3
"""Authorized role interface; return only the packet's own result."""
import argparse, hashlib, json, os, subprocess, sys, uuid
from pathlib import Path
from runtime_io import atomic_json
from raw_policy import sanitize
from task_runtime import checked_packet, render_user_reply
from role_registry import get_role

def read_packet(role,args,root):
    role_info=get_role(role)
    if not args: raise ValueError('goal | --goal-file FILE | --message-file FILE | --packet FILE required')
    if args[0]=='--packet':
        packet=json.loads(Path(args[1]).read_text(encoding='utf-8-sig'))
        if packet.get('role_id')!=role: raise ValueError('packet role_id does not match wrapper')
    elif args[0]=='--message-file':
        parser=argparse.ArgumentParser(prog=role+'-run.sh')
        parser.add_argument('--message-file',required=True)
        parser.add_argument('--task-id')
        parser.add_argument('--message-id')
        parser.add_argument('--mode',choices=['run','continue','resume','retry','checkpoint'],default='run')
        parser.add_argument('--permission',choices=['R0','R1','R2','R3'],default='R1')
        options=parser.parse_args(args)
        if options.mode!='run' and not options.task_id:
            raise ValueError('continuing a message requires its existing --task-id')
        original=Path(options.message_file).read_bytes().decode('utf-8-sig')
        origin='local-user' if role=='gpt-star' else role_info['origin_id']
        packet=dict(role_id=role,from_agent_id=origin,goal=original,
            original_user_input=original,entry='codex_cli' if role=='gpt-star' else 'grok_bridge',
            mode=options.mode,permission=options.permission,input_transport='original_message_file')
        if options.message_id:
            if len(options.message_id)>160 or not options.message_id.strip():
                raise ValueError('invalid source message id')
            packet['source_event_id']=options.message_id
        if options.task_id: packet['task_id']=options.task_id
        elif options.message_id:
            # Redelivery of the same upstream message resolves to the same
            # task; changed content is rejected by the existing identity check.
            key=json.dumps([role,origin,options.message_id],ensure_ascii=False)
            packet['task_id']='t-'+role+'-'+hashlib.sha256(key.encode()).hexdigest()[:20]
    else:
        goal=Path(args[1]).read_text(encoding='utf-8') if args[0]=='--goal-file' else args[0]
        packet={'role_id':role,'goal':goal,'permission':'R1','cwd_hint':str(root/'workspace/roles'/role),
                'from_agent_id':role_info['origin_id']}
        if role=='gpt-star':
            packet.update(from_agent_id='local-user',entry='codex_cli',original_user_input=goal)
    return packet

def main():
    role=sys.argv[1]; args=sys.argv[2:]
    root=Path(os.environ.get('JAVIS_ROOT',Path.home()/'javis')).resolve()
    packet=read_packet(role,args,root)
    packet=checked_packet(packet)
    tid=packet.setdefault('task_id',f't-{role}-{uuid.uuid4().hex[:16]}')
    import re
    if not isinstance(tid,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}',tid): raise ValueError('invalid task_id')
    # Staging input separate from final packet; the runner owns task/packet.json.
    inbox=root/'workspace/inbox/packets'/f'{tid}-{uuid.uuid4().hex}.json'
    atomic_json(inbox,packet)
    env=os.environ.copy(); env['JAVIS_ROOT']=str(root); env['JAVIS_CALL_PATH']=f'{role}-run>run-task>codex-exec'
    try: p=subprocess.run(['bash',str(Path(__file__).with_name('run-task.sh')),str(inbox)],env=env,capture_output=True,text=True)
    finally: inbox.unlink(missing_ok=True)
    if p.stdout: print(p.stdout,end='')
    if p.stderr: print(sanitize(p.stderr),end='',file=sys.stderr)
    # Bind the reply to the immutable result returned by this invocation.
    # The next continuation may already own the mutable task/result.json.
    receipt=None
    for line in p.stdout.splitlines():
        try: row=json.loads(line)
        except json.JSONDecodeError: continue
        if row.get('task_id')==tid and row.get('result'): receipt=row
    if p.returncode in (2,75) or receipt is None: return p.returncode or 1
    result_path=Path(receipt['result']).resolve()
    if not result_path.is_relative_to((root/'workspace/tasks'/tid).resolve()): raise ValueError('result path outside task')
    if not result_path.exists(): return p.returncode or 1
    result=json.loads(result_path.read_text())
    if result.get('task_id')!=tid or result.get('role_id')!=role: raise ValueError('result identity mismatch')
    reply=result.get('user_reply_zh') or render_user_reply(result)
    print('--- user-reply ---\n'+reply+'\n---\n'+str(result_path))
    return p.returncode

if __name__=='__main__':
    try: sys.exit(main())
    except (ValueError,IndexError,KeyError,FileNotFoundError) as e: print(str(e),file=sys.stderr); sys.exit(2)
