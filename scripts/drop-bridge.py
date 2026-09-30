#!/usr/bin/env python3
"""Local drop consumer. One lock, immutable delivery receipts, no implicit replay."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from runtime_io import lock

from role_registry import DROP_DIRS as ROLES, ROLE_ORIGINS as ORIGINS, get_role
IDENT = re.compile(r'^[A-Za-z0-9_-]{1,80}$')
DELIVERY = re.compile(r'^[A-Za-z0-9_-]{1,120}$')
MAX_MESSAGE = 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    temp = Path(temporary)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def write_json(path, value):
    atomic(path, (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


class Reject(Exception):
    pass


def regular_bytes(path, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise Reject('input is not a bounded ordinary file (links are not accepted)')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        current = os.fstat(handle.fileno())
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise Reject('input changed while opening')
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise Reject('input is too large')
    return data


def ordinary_dir(path):
    if path.is_symlink() or not path.is_dir():
        raise Reject('queue path is not an ordinary directory')


def validate(package, recovery=False):
    ordinary_dir(package)
    names = set(p.name for p in package.iterdir())
    allowed = {'request.json', 'message.txt'} | ({'receipt.json', 'result.out', 'result.err','accepted.json'} if recovery else set())
    if not {'request.json', 'message.txt'} <= names or names - allowed:
        raise Reject('package must contain only request.json and message.txt')
    request = json.loads(regular_bytes(package / 'request.json', 16384).decode('utf-8-sig'))
    if not isinstance(request, dict) or set(request) - {'schema_version', 'submission_id', 'message_id'}:
        raise Reject('unknown request fields')
    if type(request.get('schema_version')) is not int or request['schema_version'] != 1:
        raise Reject('schema_version must be 1')
    sid = request.get('submission_id')
    if not isinstance(sid, str) or not IDENT.fullmatch(sid):
        raise Reject('submission_id must be 1..80 ASCII letters, numbers, underscore or hyphen')
    mid = request.get('message_id')
    if mid is not None and (not isinstance(mid, str) or not mid.strip() or len(mid) > 160 or not mid.isprintable()):
        raise Reject('message_id must be a real printable upstream ID, at most 160 characters')
    data = regular_bytes(package / 'message.txt', MAX_MESSAGE)
    text = data.decode('utf-8-sig')
    if not text.strip() or '\x00' in text:
        raise Reject('message.txt must be nonempty UTF-8 text without NUL')
    return request, data, text.replace('\r\n', '\n').replace('\r', '\n')


class Bridge:
    def __init__(self, root, base, runner=None):
        self.root, self.base = Path(root), Path(base)
        self.state = self.root / 'state/drop-bridge'
        self.runner = runner or self.execute
        # An injected runner is retained for isolated legacy compatibility tests.
        # Production's default is durable common acceptance; never synchronous inference.
        self.common = runner is None

    def common_service(self,role):
        from task_control import Principal,ControlService
        principal=Principal('service:drop:'+role,'service',frozenset({role}),frozenset({'task:create','task:read'}),'local-drop-filesystem')
        return ControlService(self.root),principal

    def common_accept(self,package,role,delivery,key,identity,base,journal,record,data,original):
        """Accept once, then collect only the common controller's sealed receipt."""
        from task_control import ControlError
        from raw_storage import snapshot_file,append_event,stable_id
        service,principal=self.common_service(role)
        command_id='drop-'+key
        # New intake preserves text line endings as received. Existing journals
        # retain their previous normalized identity for replay/crash recovery.
        text_format=(record or {}).get('input_text_format') or ('verbatim_line_endings_v1' if not record else 'legacy_normalized')
        if text_format=='verbatim_line_endings_v1':original=data.decode('utf-8-sig')
        request={'command_id':command_id,'role_id':role,'original_text':original,
            'source_line':2,'entry':'grok_drop','permission':'R1'}
        if identity['message_id'] is not None:request['source_event_id']=identity['message_id']
        if not record or record.get('phase')=='preflight_failed':
            record=dict(identity,engine='common_control',phase='preflight_failed',command_id=command_id,first_delivery_id=delivery,input_text_format=text_format)
            write_json(journal,record)
            try:
                spool=self.root/'workspace/inbox/messages/drop'/role/(key+'.txt')
                atomic(spool,data)
                if regular_bytes(spool,MAX_MESSAGE)!=data:raise Reject('original message copy verification failed')
                transport=snapshot_file(self.root,spool,identity['task_id'],relation='input',capture_key='drop-original-'+key)
                append_event(self.root,{'event_id':stable_id(identity['task_id'],'drop-transport',key),
                    'event_type':'input_transport','task_id':identity['task_id'],'agent':role,'source_event_id':identity['message_id'],
                    'payload':{'source_line':2,'submission_id':identity['submission_id'],'input_sha256':identity['input_sha256'],
                        'transport':'local_drop_original_bytes','provenance':'filesystem_received; upstream authorship not independently verified','snapshot':transport}})
                # Persist acceptance intent first. A crash may have committed submit; re-submit is idempotent.
                record.update(phase='accepting',input_snapshot=transport);write_json(journal,record)
            except (OSError,ValueError,Reject):
                return self.finish(package,role,delivery,dict(base,status='failed',failure_stage='preflight',
                    reason='verified original input storage unavailable; no common task accepted; same identity may be redelivered'))
        if record.get('phase')=='accepting':
            try:accepted=service.submit(principal,request)
            except ControlError as exc:
                # A rejected API request has not launched a model; keep a precise immutable explanation.
                receipt=dict(base,status='rejected',failure_stage='acceptance',reason=exc.code+': '+str(exc))
                write_json(journal,dict(record,phase='terminal',receipt=receipt))
                return self.finish(package,role,delivery,receipt)
            if accepted['task_id']!=identity['task_id']:raise Reject('common acceptance returned unexpected task identity')
            record.update(phase='accepted',accepted=accepted);write_json(journal,record)
        if record.get('phase')!='accepted':raise Reject('unknown common-control journal phase')
        accepted=dict(record['accepted'],schema_version=1,delivery_id=delivery,role_id=role,submission_id=identity['submission_id'],
            message_id=identity['message_id'],input_sha256=identity['input_sha256'],replayed=base['replayed'])
        write_json(package/'accepted.json',accepted)
        status=service.status(principal,identity['task_id'])
        # Appends, a pause, or a new explicit attempt can be pending while the package stays processing.
        if status['state'] in {'queued','created','running','paused','waiting_user'} or status.get('dispatch_status') in {'queued','claimed','started'}:
            return accepted
        if status['state']=='completed' and not status['current_goal_completed']:
            return accepted
        if status['state']=='cancelled' and status['attempt']==0:
            outcome=dict(attempt=0,status='failed',failure_stage='cancelled',reason='Task cancelled before execution; no model was started',user_reply_zh='任务已在执行前取消。')
        elif status['state'] in {'completed','failed','cancelled'}:
            try:sealed=service.result(principal,identity['task_id'])
            except ControlError as exc:
                if exc.code=='result_pending':return accepted
                outcome=dict(status='needs_review',failure_stage='receipt_integrity',reason=exc.code+': '+str(exc))
            else:
                result=sealed['result'];ok=result.get('status')=='ok' and result.get('exit_code')==0 and status['current_goal_completed']
                outcome=dict(attempt=sealed['attempt'],status='succeeded' if ok else 'failed',
                    failure_stage=None if ok else ('completion_protocol' if result.get('failure_category')=='completion_protocol_error' else 'executor'),
                    reason='common controller sealed the authoritative result' if ok else (result.get('failure_reason') or 'executor returned '+str(result.get('status'))),
                    result_path=sealed['result_ref'],result_sha256=sealed['result_sha256'],user_reply_zh=result.get('user_reply_zh',''))
                outcome.update({k:result.get(k) for k in ('native_final_output_ref','native_final_output_sha256','native_final_output_available')})
        else:
            outcome=dict(status='needs_review',failure_stage='execution_uncertain',reason='Common task requires inspection; no automatic replay')
        receipt=dict(base,**outcome)
        if receipt['status']!='needs_review':write_json(journal,dict(record,phase='terminal',receipt=receipt))
        return self.finish(package,role,delivery,receipt)

    def prepare(self):
        self.state.mkdir(parents=True, exist_ok=True)
        ordinary_dir(self.base)
        for role in ROLES:
            queue = self.base / ROLES[role]
            queue.mkdir(exist_ok=True)
            ordinary_dir(queue)
            for name in ('inbox', 'processing', 'done', 'fail'):
                (queue / name).mkdir(exist_ok=True)
                ordinary_dir(queue / name)

    def execute(self, role, spool, tid, mid):
        args = ['bash', str(self.root / 'scripts' / (role + '-run.sh')),
                '--message-file', str(spool), '--task-id', tid]
        if mid is not None:
            args += ['--message-id', mid]
        # RAW and native logs belong to the executor. Never echo its raw stderr into a drop receipt.
        return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, env={**os.environ, 'JAVIS_ROOT': str(self.root)}).returncode

    def collect(self, record, expected):
        """Trust only executor attempt 1 and the exact original packet, never worker out/receipt.json."""
        task = self.root / 'workspace/tasks' / record['task_id']
        archived_packet = task / 'attempts/1/packet.json'
        packet = read_json(archived_packet if archived_packet.exists() else task / 'packet.json')
        if (packet.get('task_id') != record['task_id'] or packet.get('role_id') != record['role_id']
                or str(packet.get('from_agent_id')) != ORIGINS[record['role_id']]
                or packet.get('source_event_id') != record['message_id']
                or packet.get('original_user_input') != expected):
            raise Reject('executor packet does not match original delivery')
        result_path = task / 'attempts/1/result.json'
        if result_path.is_symlink() or not result_path.resolve().is_relative_to(task.resolve()):
            raise Reject('invalid executor result path')
        raw = regular_bytes(result_path, 8 * MAX_MESSAGE)
        result = json.loads(raw)
        if (result.get('task_id') != record['task_id'] or result.get('role_id') != record['role_id']
                or result.get('attempt') != 1 or not isinstance(result.get('user_reply_zh'), str)):
            raise Reject('executor receipt identity is invalid')
        ok = result.get('status') == 'ok' and result.get('exit_code') == 0
        category = result.get('failure_category')
        stage = None if ok else ('completion_protocol' if category == 'completion_protocol_error' else 'executor')
        reason = ('executor completed and published an immutable result' if ok else
                  'native turn completed without required SUMMARY; review existing execution, do not replay' if stage == 'completion_protocol'
                  else 'executor returned status %s, exit %s; inspect the authoritative result before explicit recovery' %
                  (result.get('status'), result.get('exit_code')))
        return dict(attempt=1, status='succeeded' if ok else 'failed', failure_stage=stage,
                    reason=reason, result_path=str(result_path), result_sha256=digest(raw),
                    user_reply_zh=result['user_reply_zh'])

    def finish(self, package, role, delivery, receipt):
        receipt = dict(receipt, schema_version=1, delivery_id=delivery, role_id=role)
        queue = self.base / ROLES[role]
        target = queue / ('done' if receipt['status'] == 'succeeded' else 'fail') / delivery
        if target.exists():
            # A duplicate physical ID must never overwrite an old receipt.
            raise Reject('delivery_id already archived; existing evidence kept')
        write_json(package / 'receipt.json', receipt)
        output = dict(receipt)
        text = json.dumps(output, ensure_ascii=False) + '\n'
        if receipt.get('result_path'):
            text += '--- result-source ---\n' + receipt['result_path'] + '\n'
        atomic(package / 'result.out', text.encode('utf-8'))
        error = '' if receipt['status'] == 'succeeded' else '%s: %s\n' % (receipt['failure_stage'], receipt['reason'])
        atomic(package / 'result.err', error.encode('utf-8'))
        package.rename(target)
        return receipt

    def process(self, package, role, recovery=False):
        get_role(role)
        delivery = package.name.removesuffix('.ready')
        base = dict(submission_id=None, message_id=None, input_sha256=None, task_id=None, attempt=None,
                    result_path=None, result_sha256=None, user_reply_zh='', replayed=False)
        try:
            if not DELIVERY.fullmatch(delivery):
                raise Reject('invalid delivery_id')
            request, data, original = validate(package, recovery=recovery)
        except (Reject, OSError, UnicodeError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, Reject) else 'unreadable, incomplete or invalid UTF-8/JSON input'
            return self.finish(package, role, delivery, dict(base, status='rejected', failure_stage='validation', reason=reason))
        sid, mid = request['submission_id'], request.get('message_id')
        key = digest(json.dumps([role, 'message' if mid is not None else 'submission', mid if mid is not None else sid],
                                ensure_ascii=False).encode('utf-8'))
        tid = 't-drop-' + role + '-' + key[:20]
        journal = self.state / role / (key + '.json')
        try:prior_record=read_json(journal) if journal.exists() else None
        except (OSError,ValueError):prior_record={}
        common_delivery=(prior_record or {}).get('engine')=='common_control' or (self.common and not journal.exists())
        if common_delivery:
            service,principal=self.common_service(role)
            tid=service.task_id_for(principal,role,'drop-'+key)
        identity = dict(role_id=role, submission_id=sid, message_id=mid, input_sha256=digest(data), task_id=tid)
        base.update(identity)
        # Input-side receipts never establish success. Recovery may replace bridge files only
        # after the Linux identity journal proves execution was already claimed.
        extras = set(p.name for p in package.iterdir()) - {'request.json', 'message.txt'}
        if extras and not journal.exists():
            return self.finish(package, role, delivery, dict(base, status='rejected', failure_stage='validation',
                               reason='untrusted package contains result files without an execution journal'))
        alias = self.state / role / 'submissions' / (digest(sid.encode('ascii')) + '.json')
        if alias.exists():
            try:
                prior = read_json(alias)
            except (OSError, ValueError):
                prior = None
            if prior != identity:
                return self.finish(package, role, delivery, dict(base, status='rejected', failure_stage='identity',
                                   reason='submission_id is already bound to different original bytes or source metadata'))
        else:
            write_json(alias, identity)
        record = None
        if journal.exists():
            try:
                record = read_json(journal)
            except (OSError, ValueError):
                return self.finish(package, role, delivery, dict(base, status='needs_review', failure_stage='journal',
                                   reason='identity journal cannot be read; no execution attempted'))
            if any(record.get(k) != v for k, v in identity.items()):
                return self.finish(package, role, delivery, dict(base, status='rejected', failure_stage='identity',
                                   reason='same identity was delivered with different metadata or original bytes'))
            base['replayed'] = True
            if common_delivery:base['replayed']=delivery!=record.get('first_delivery_id')
            if record.get('phase') == 'terminal':
                saved = dict(record['receipt'], replayed=True)
                # Detect missing or changed authoritative result; never quietly replay altered evidence.
                if saved.get('result_path'):
                    try:
                        expected_path = self.root / 'workspace/tasks' / tid / 'attempts'/str(saved.get('attempt') or 1)/'result.json'
                        if common_delivery:
                            from task_service import load_control
                            control=load_control(self.root,tid)
                            authorities=list(control.get('attempt_receipts',{}).values())+list(control.get('memory_repairs',{}).values())
                            authority=next((r for r in authorities if r['path']==saved['result_path'] and r['sha256']==saved['result_sha256']),None)
                            if authority is None:raise Reject('cached receipt has no common-control authority')
                            expected_path=Path(authority['path'])
                            if not expected_path.resolve().is_relative_to((self.root/'workspace/tasks'/tid).resolve()):raise Reject('cached receipt path outside task')
                        if saved['result_path'] != str(expected_path) or digest(regular_bytes(expected_path, 8 * MAX_MESSAGE)) != saved['result_sha256']:
                            raise Reject('result changed')
                    except (OSError, ValueError, Reject):
                        saved.update(status='needs_review', failure_stage='receipt_integrity',
                                     reason='immutable executor receipt is missing or changed; no execution attempted', user_reply_zh='')
                return self.finish(package, role, delivery, saved)
            if common_delivery and record.get('phase') in {'accepting','accepted','preflight_failed'}:
                return self.common_accept(package,role,delivery,key,identity,base,journal,record,data,original)
            if record.get('phase') == 'executing':
                try:
                    outcome = self.collect(record, original)
                except (OSError, ValueError, Reject):
                    outcome = dict(status='needs_review', failure_stage='execution_uncertain',
                                   reason='execution may have started; no sealed matching result yet; automatic replay is disabled')
                receipt = dict(base, **outcome)
                # Leave executing unresolved if the old child is still finishing; a later delivery may collect its result.
                if receipt['status'] != 'needs_review':
                    write_json(journal, dict(record, phase='terminal', receipt=receipt))
                return self.finish(package, role, delivery, receipt)
            if record.get('phase') != 'preflight_failed':
                return self.finish(package, role, delivery, dict(base, status='needs_review', failure_stage='journal',
                                   reason='unknown journal phase; no execution attempted'))
            if extras:
                return self.finish(package, role, delivery, dict(base, status='rejected', failure_stage='validation',
                                   reason='pre-execution package contains untrusted result files'))
        if common_delivery:
            return self.common_accept(package,role,delivery,key,identity,base,journal,record,data,original)
        record = dict(identity, phase='preflight_failed')
        # A known pre-execution retry starts its first worker; it is not a cached reply.
        base['replayed'] = False
        # Identity is bound even on preflight errors; a corrected deployment may retry these safely.
        write_json(journal, record)
        try:
            script = self.root / 'scripts' / (role + '-run.sh')
            if script.is_symlink() or not script.is_file():
                raise Reject('role wrapper missing or not an ordinary file')
            spool = self.root / 'workspace/inbox/messages/drop' / role / (key + '.txt')
            atomic(spool, data)
            if regular_bytes(spool, MAX_MESSAGE) != data:
                raise Reject('original message copy verification failed')
        except (OSError, Reject):
            return self.finish(package, role, delivery, dict(base, status='failed', failure_stage='preflight',
                               reason='role wrapper or verified input copy unavailable; no executor was started; same identity may be redelivered'))
        record['phase'] = 'executing'
        write_json(journal, record)
        try:
            code = self.runner(role, spool, tid, mid)
        except OSError:
            # Even launch errors are deliberately conservative: do not guess whether a descendant started.
            code = None
        try:
            outcome = self.collect(record, original)
        except (OSError, ValueError, Reject):
            outcome = dict(status='needs_review', failure_stage='execution_uncertain',
                           reason='executor exit %s without a sealed matching result; inspect runtime state; automatic replay is disabled' % code)
        receipt = dict(base, **outcome)
        if receipt['status'] != 'needs_review':
            write_json(journal, dict(record, phase='terminal', receipt=receipt))
        return self.finish(package, role, delivery, receipt)

    def once(self):
        count = 0
        for role, dirname in ROLES.items():
            queue = self.base / dirname
            # Recover only already claimed packages, never process legacy root *.txt.
            for package in sorted((queue / 'processing').glob('*.ready')):
                if package.is_symlink() or not package.is_dir():
                    continue
                if not DELIVERY.fullmatch(package.name.removesuffix('.ready')):
                    self.queue_issue(package, role, 'invalid delivery_id; package retained without execution')
                    continue
                self.safe_process(package, role, recovery=True)
                count += 1
            for source in sorted((queue / 'inbox').glob('*.ready')):
                if source.is_symlink() or not source.is_dir():
                    continue
                delivery = source.name.removesuffix('.ready')
                if not DELIVERY.fullmatch(delivery):
                    self.queue_issue(source, role, 'invalid delivery_id; package retained without execution')
                    continue
                if any((queue / name / delivery).exists() for name in ('done', 'fail')):
                    # Keep suspicious physical-ID collisions untouched and visible to operator.
                    self.queue_issue(source, role, 'delivery_id already archived; use a new delivery_id with the same logical identity; original evidence kept')
                    continue
                package = queue / 'processing' / source.name
                if package.exists():
                    self.queue_issue(source, role, 'delivery_id already claimed; package retained without execution')
                    continue
                source.rename(package)
                self.safe_process(package, role)
                count += 1
        return count

    def queue_issue(self, package, role, reason):
        issue = self.state / 'issues' / role / (digest(package.name.encode('utf-8')) + '.json')
        write_json(issue, dict(status='rejected', failure_stage='delivery_identity', reason=reason))
        atomic(package / 'result.err', ('delivery_identity: ' + reason + '\n').encode('utf-8'))

    def safe_process(self, package, role, recovery=False):
        try:
            self.process(package, role, recovery=recovery)
        except Exception as exc:
            # A damaged package must not starve other deliveries. Do not follow paths or print its input.
            issue = self.state / 'issues' / role / (digest(package.name.encode('utf-8')) + '.json')
            write_json(issue, dict(status='needs_review', failure_stage='queue_io',
                                  error_type=type(exc).__name__, reason='package could not be finalized; original package retained; no automatic reset'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(os.environ.get('JAVIS_ROOT', Path.home() / 'javis')))
    parser.add_argument('--base', type=Path, default=Path(os.environ.get('JAVIS_DROP_BASE', Path.home() / 'javis-drop')))
    parser.add_argument('--watch', action='store_true')
    args = parser.parse_args()
    bridge = Bridge(args.root, args.base)
    with lock(args.root/'state/maintenance.lock',shared=True):
        bridge.prepare()
    with open(bridge.state / 'watcher.lock', 'a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('drop bridge already running; no second consumer started')
            return 0
        while True:
            with lock(args.root/'state/maintenance.lock',shared=True):
                try:
                    count = bridge.once()
                    write_json(bridge.state / 'health.json', dict(pid=os.getpid(), updated_at=time.time(), processed=count, status='ready'))
                except Exception as exc:
                    # No arbitrary exception text: it can contain user input or secrets.
                    write_json(bridge.state / 'health.json', dict(pid=os.getpid(), updated_at=time.time(), status='error', error_type=type(exc).__name__))
                    if not args.watch:
                        raise
            if not args.watch:
                return 0
            time.sleep(2)


if __name__ == '__main__':
    raise SystemExit(main())
