"""Common task acceptance/control. RAW is authoritative; control JSON is a projection.

Only a trusted adapter constructs Principal. Never deserialize one from a request body.
No worker is started by this module; task_dispatch consumes persisted commands.
"""
import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from runtime_io import atomic_json, lock
from raw_policy import sanitize
from raw_storage import append_event, stable_id
from raw_time import received_fields, utc_timestamp

from role_registry import ROLE_ORIGINS as ROLES

@dataclass(frozen=True)
class Principal:
    actor_id: str
    kind: str
    role_ids: frozenset = field(default_factory=frozenset)
    capabilities: frozenset = field(default_factory=frozenset)
    authentication_ref: str | None = None

class ControlError(ValueError):
    def __init__(self, code, message, status_code=409, **details):
        super().__init__(message)
        self.code, self.status_code, self.details = code, status_code, details

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()

def _now():
    from task_control import now
    return now()

def _id(value):
    from task_control import safe_id
    try: return safe_id(value)
    except ValueError: raise ControlError('invalid_id', 'Invalid identifier', 400)

def load_control(root, tid):
    """Repair a missing/stale projection from the latest committed RAW snapshot."""
    root=Path(root); path=root/'state/control'/f'{tid}.json'
    value=json.loads(path.read_text()) if path.exists() else {}
    # A task-specific RAW stream bounds recovery cost and shares RAW's fsync lock.
    journal=root/'raw/events/control'/f'{tid}.jsonl'
    if journal.exists():
        for line in journal.read_text().split('\n'):
            try: event=json.loads(line)
            except ValueError: continue
            snapshot=event.get('payload', {}).get('control_projection')
            if snapshot and snapshot.get('sequence', 0)>value.get('sequence', 0): value=snapshot
    return value

def save_control(root, value, phase, command_id=None):
    value['sequence']=value.get('sequence', 0)+1
    value['updated_at']=_now()
    safe=sanitize(value)
    append_event(root, {'event_id':stable_id(value['task_id'], 'control', value['sequence']),
        'event_type':'task_control', 'task_id':value['task_id'], 'agent':value['role_id'],
        'occurred_at':value['updated_at'], 'captured_at':value['updated_at'], 'completeness':'complete',
        'payload':{'phase':phase, 'command_id':command_id, 'control_projection':safe}},
        relative_path=f"events/control/{value['task_id']}.jsonl")
    atomic_json(Path(root)/'state/control'/f"{value['task_id']}.json", safe)

def control_ids(root):
    root=Path(root)
    return sorted({p.stem for p in (root/'state/control').glob('*.json')} |
                  {p.stem for p in (root/'raw/events/control').glob('*.jsonl')})

def ensure_not_held(root):
    path=Path(root)/'state/recovery-hold.json'
    if not path.exists():return
    try: value=json.loads(path.read_text())
    except (OSError,ValueError):raise ControlError('recovery_hold','Recovery hold cannot be verified; mutations are blocked',423)
    if not isinstance(value,dict) or value.get('hold') is not False:
        raise ControlError('recovery_hold','Restored environment is held for review; no task can be accepted or dispatched',423)

class ControlService:
    def __init__(self, root): self.root=Path(root).resolve()

    def _state(self, tid):
        path=self.root/'state/tasks'/f'{tid}.json'
        return json.loads(path.read_text()) if path.exists() else {}

    def _permission(self, principal, role, capability, owner=None):
        if not isinstance(principal, Principal) or not principal.actor_id or role not in ROLES or role not in principal.role_ids:
            raise ControlError('forbidden', 'Actor has no access to this role', 403)
        if capability not in principal.capabilities and capability+':any' not in principal.capabilities:
            raise ControlError('forbidden', 'Actor lacks required capability', 403)
        if owner and principal.actor_id!=owner and capability+':any' not in principal.capabilities:
            raise ControlError('forbidden', 'Task belongs to another actor', 403)

    def _request(self, request, allowed):
        if not isinstance(request, dict) or set(request)-allowed:
            raise ControlError('invalid_request', 'Unknown or forbidden request fields', 400)
        req=dict(request); _id(req.get('command_id'))
        return req

    def _text(self, text):
        if not isinstance(text, str) or not text.strip() or len(text.encode())>1048576:
            raise ControlError('invalid_text', 'Original text must contain 1–1048576 UTF-8 bytes', 400)
        if re.match(r'^\s*(?:L4\s*[:：]|(?:隐私等级|数据等级)\s*[:：]?\s*L4)',text,re.I):
            raise ControlError('local_model_unavailable','L4 input cannot be accepted by the connected external worker',403)
        return sanitize(text)

    def _receipt(self, c, cmd, replayed=False):
        return {'ok':True, 'task_id':c['task_id'], 'command_id':cmd['command_id'], 'status':cmd['status'],
            'action':cmd['action'], 'goal_revision':c['goal_revision'], 'applied_goal_revision':c.get('applied_goal_revision', 0),
            'attempt':self._state(c['task_id']).get('attempt', 0), 'replayed':replayed,
            'received_at':cmd['received_at'], 'applied_at':cmd.get('applied_at'), 'reason':cmd.get('reason'),
            'result_ref':cmd.get('result_ref'),'result_sha256':cmd.get('result_sha256')}

    def _duplicate(self, c, req):
        old=c.get('commands', {}).get(req['command_id'])
        if old:
            if old['fingerprint']!=digest(req): raise ControlError('identity_conflict', 'command_id was already used for different content')
            return self._receipt(c, old, True)

    def _new_command(self, principal, req, action):
        return {'command_id':req['command_id'], 'fingerprint':digest(req), 'action':action,
            'actor_id':principal.actor_id, 'actor_kind':principal.kind,
            'authentication_evidence_sha256':hashlib.sha256(principal.authentication_ref.encode()).hexdigest() if principal.authentication_ref else None,
            'status':'received', 'received_at':utc_timestamp(_now())}

    def _original(self, c, req, text, revision, kind, received_at=None):
        event_id=stable_id(c['task_id'], req['command_id'], kind, digest(req))
        filtered=text!=req.get('original_text')
        event={'event_id':event_id, 'task_id':c['task_id'], 'agent':c['role_id'], 'event_type':'user_input',
            'source_event_id':req.get('source_event_id'), **received_fields(received_at=received_at or _now()),
            'missing_reason':'original_text_filtered_before_control_storage' if filtered else None,
            'payload':{'text':text, 'input_kind':kind, 'is_original_user_input':True,
                'source_line':c['source_line'], 'record_source':'trusted_adapter_received_body',
                'provenance':'transport_received; upstream authorship not independently verified',
                'original_was_filtered':filtered,'redaction_boundary':'explicit_credentials_removed_before_control_storage' if filtered else 'none',
                'goal_revision':revision, 'input_sha256':hashlib.sha256(text.encode()).hexdigest()}}
        original_event={**event,'payload':{**event['payload'],'text':req['original_text'],
            'input_sha256':hashlib.sha256(req['original_text'].encode()).hexdigest()}}
        append_event(self.root, event, original_event=original_event)
        return {'revision':revision, 'text':text, 'event_id':event_id, 'input_sha256':event['payload']['input_sha256'],
            'source_event_id':req.get('source_event_id'), 'command_id':req['command_id']}

    def submit(self, principal, request):
        req=self._request(request, {'command_id','role_id','original_text','permission','source_event_id','entry','source_line','context_budget_bytes','native_context_budget_tokens'})
        role=req.get('role_id'); self._permission(principal, role, 'task:create')
        text=self._text(req.get('original_text')); permission=req.get('permission','R1')
        if permission not in {'R0','R1'}: raise ControlError('external_action_blocked','R2/R3 external actions are not connected',403)
        source_line=req.get('source_line',2)
        if type(source_line) is not int or source_line not in {2,3}: raise ControlError('invalid_source_line','Codex tasks require source_line 2 or 3; line 1 is Grok-only and must use grok-sync archival',400)
        budget=req.get('context_budget_bytes',16384)
        if type(budget) is not int or not 4096<=budget<=65536: raise ControlError('invalid_budget','Context budget must be 4096–65536 bytes',400)
        native_budget=req.get('native_context_budget_tokens',16000)
        if type(native_budget) is not int or not 4096<=native_budget<=128000:raise ControlError('invalid_budget','Native continuation trigger must be 4096–128000 input tokens',400)
        if req.get('source_event_id') is not None and (not isinstance(req['source_event_id'],str) or not req['source_event_id'].strip() or len(req['source_event_id'])>160):
            raise ControlError('invalid_source_event_id','source_event_id must be a real nonblank platform event identifier',400)
        tid=self.task_id_for(principal,role,req['command_id'])
        with lock(self.root/'state/maintenance.lock',shared=True), lock(self.root/'state/locks'/f'{tid}.control.lock'):
            ensure_not_held(self.root)
            c=load_control(self.root,tid)
            if c:
                duplicate=self._duplicate(c,req)
                if duplicate: self._ensure_queued(c); return duplicate
                raise ControlError('identity_conflict','Task identity already exists')
            if self._state(tid): raise ControlError('identity_conflict','Task state already exists without control ownership')
            c={'schema':'javis-control-1','task_id':tid,'role_id':role,'owner_actor_id':principal.actor_id,
                'source_line':source_line,'permission':permission,'entry':sanitize(req.get('entry','common_control')),
                'context_budget_bytes':budget,'native_context_budget_tokens':native_budget,
                'goal_revision':1,'applied_goal_revision':0,'goals':[], 'commands':{},'dispatch':None}
            cmd=self._new_command(principal,req,'create')
            c['goals']=[self._original(c,req,text,1,'original_user',cmd['received_at'])]
            c['commands'][req['command_id']]=cmd
            c['dispatch']={'command_id':req['command_id'],'status':'queued','mode':'run','expected_attempt':0,'goal_revision':1}
            save_control(self.root,c,'received',req['command_id']);self._ensure_queued(c)
            return self._receipt(c,cmd)

    def task_id_for(self,principal,role_id,command_id):
        self._permission(principal,role_id,'task:create');_id(command_id)
        return 't-p1-'+role_id+'-'+digest([principal.actor_id,role_id,command_id])[:20]

    def _ensure_queued(self,c):
        """Recover acceptance crash after RAW commit but before the initial state write."""
        path=self.root/'state/tasks'/f"{c['task_id']}.json"
        if not path.exists():
            d=c.get('dispatch') or {}
            if c.get('attempt_receipts') or d.get('expected_attempt',0)!=0 or d.get('status') not in {'queued','cancelled'}:
                raise ControlError('state_missing','Execution state is missing after dispatch; review required')
            atomic_json(path,{'task_id':c['task_id'],'role_id':c['role_id'],'from_agent_id':ROLES[c['role_id']],
                'state':'queued','attempt':0,'goal':c['goals'][0]['text'],'created_at':c['updated_at'],
                'updated_at':c['updated_at'],'owner_actor_id':c['owner_actor_id'],'control_managed':True})

    def command(self, principal, task_id, request):
        tid=_id(task_id)
        req=self._request(request,{'command_id','action','expected_goal_revision','expected_attempt','original_text','source_event_id','review_confirmed'})
        with lock(self.root/'state/maintenance.lock',shared=True),lock(self.root/'state/locks'/f'{tid}.control.lock'):
            ensure_not_held(self.root)
            c=load_control(self.root,tid)
            if c.get('schema')!='javis-control-1': raise ControlError('not_found','Managed task not found',404)
            self._permission(principal,c['role_id'],'task:control',c['owner_actor_id'])
            duplicate=self._duplicate(c,req)
            if duplicate: return duplicate
            state=self._state(tid); attempt=state.get('attempt',0)
            if type(req.get('expected_goal_revision')) is not int or type(req.get('expected_attempt')) is not int or req.get('expected_goal_revision')!=c['goal_revision'] or req.get('expected_attempt')!=attempt:
                raise ControlError('version_conflict','Task revision or attempt changed',goal_revision=c['goal_revision'],attempt=attempt)
            action=req.get('action')
            if action not in {'append','pause','cancel','resume','continue','retry','reconcile_memory'}: raise ControlError('invalid_action','Unknown task action',400)
            cmd=self._new_command(principal,req,action);queued_stop_state=None
            if action=='append':
                text=self._text(req.get('original_text'));c['goal_revision']+=1
                c['goals'].append(self._original(c,req,text,c['goal_revision'],'append',cmd['received_at']))
                cmd['goal_revision']=c['goal_revision'];cmd['reason']='Stored; applies at the next explicitly started safe attempt'
                if (c.get('dispatch') or {}).get('status')=='queued' and c['dispatch'].get('mode')!='reconcile_memory':c['dispatch']['goal_revision']=c['goal_revision']
            elif action=='reconcile_memory':
                if principal.kind not in {'owner','human','local_owner'}:raise ControlError('human_review_required','Memory reconciliation requires an authenticated human operator',403)
                dispatch=c.get('dispatch') or {}
                if dispatch.get('status') in {'queued','claimed','started'}:raise ControlError('busy','A dispatch is already active')
                if c.get('pending_stop'):raise ControlError('stop_not_acknowledged','Wait for stop acknowledgement before memory repair')
                sealed=memory_repair_guard(self.root,c,state)
                packet_sha=(c.get('attempt_receipts',{}).get(str(attempt),{}).get('packet_sha256') or
                            dispatch.get('original_packet_sha256') or dispatch.get('packet_sha256'))
                if not packet_sha:raise ControlError('packet_identity_missing','Original packet identity is unavailable; repair requires review')
                c['dispatch']={'command_id':req['command_id'],'status':'queued','mode':action,'kind':'memory_repair',
                    'expected_attempt':attempt,'goal_revision':c.get('applied_goal_revision',0),
                    'original_packet_sha256':packet_sha,'source_receipt_ref':sealed['path'],'source_receipt_sha256':sealed['sha256']}
                cmd['reason']='Memory-only reconciliation queued; native worker will not run and attempt will not increment'
            elif action in {'pause','cancel'}:
                if c.get('pending_stop'): raise ControlError('control_pending','A stop request is already pending')
                dispatch=c.get('dispatch') or {}
                if dispatch.get('mode')=='reconcile_memory' and dispatch.get('status') in {'queued','claimed','started'}:
                    raise ControlError('memory_repair_active','A bounded memory-only repair is active; no native worker is running to pause')
                if state.get('state')=='queued' and dispatch.get('status')=='queued':
                    dispatch['status']='cancelled';cmd.update(status='applied',applied_at=_now(),reason='Stopped before execution')
                    state.update(state='paused' if action=='pause' else 'cancelled',updated_at=_now())
                    queued_stop_state=state
                elif state.get('state') in {'created','running'} or dispatch.get('status') in {'claimed','started'}:
                    stop_attempt=dispatch.get('expected_attempt',attempt)+1 if dispatch.get('status')=='claimed' else (dispatch.get('attempt') or attempt or 1)
                    c['pending_stop']={'command_id':req['command_id'],'action':action,'attempt':stop_attempt,'status':'requested'}
                else: raise ControlError('invalid_state','Task is not queued or executing')
            else:
                dispatch=c.get('dispatch') or {}
                if state.get('memory_retry_required'):
                    raise ControlError('memory_repair_required','Worker already finished; ordinary retry is blocked. Repair memory recording on this attempt without rerunning the model.')
                if dispatch.get('status') in {'queued','claimed','started'} or state.get('state') in {'created','running'}:
                    raise ControlError('busy','Execution or dispatch is active')
                if c.get('pending_stop'): raise ControlError('stop_not_acknowledged','Wait for final stop acknowledgement')
                allowed={'resume':{'paused','waiting_user'},'retry':{'failed','waiting_user'},'continue':{'completed','paused','failed','waiting_user'}}
                if state.get('state') not in allowed[action]: raise ControlError('invalid_state','Explicit action is incompatible with task state')
                if state.get('process_cleanup_unverified') or state.get('orphan_worker_may_be_running'):
                    raise ControlError('process_review_required','Verify old process tree before starting another attempt')
                if state.get('risk') in {'R2','R3'}: raise ControlError('external_action_blocked','External action requires separate review',403)
                if state.get('recovery_required') and state.get('state') in {'failed','waiting_user'} and req.get('review_confirmed') is not True:
                    raise ControlError('review_required','Review last recorded action; explicit review_confirmed is required')
                if req.get('review_confirmed') and principal.kind not in {'owner','human','local_owner'}:
                    raise ControlError('human_review_required','A service cannot attest to human review',403)
                c['dispatch']={'command_id':req['command_id'],'status':'queued','mode':action,
                    'expected_attempt':attempt,'goal_revision':c['goal_revision']}
            c['commands'][req['command_id']]=cmd;save_control(self.root,c,'received' if cmd['status']=='received' else 'applied',req['command_id'])
            if queued_stop_state: atomic_json(self.root/'state/tasks'/f'{tid}.json',queued_stop_state)
            return self._receipt(c,cmd)

    def _authorized(self,principal,tid):
        tid=_id(tid); c=load_control(self.root,tid)
        if c.get('schema')!='javis-control-1': raise ControlError('not_found','Managed task not found',404)
        self._permission(principal,c['role_id'],'task:read',c['owner_actor_id']);return c

    def status(self,principal,task_id):
        c=self._authorized(principal,task_id);s=self._state(task_id);d=c.get('dispatch') or {}
        execution_state=s.get('state','queued' if d.get('status')=='queued' and not c.get('attempt_receipts') else 'needs_review')
        if s.get('attempt',0)==0 and d.get('status')=='cancelled':
            terminal=[cmd for cmd in c['commands'].values() if cmd['action'] in {'pause','cancel'} and cmd['status']=='applied']
            if terminal:execution_state='paused' if terminal[-1]['action']=='pause' else 'cancelled'
        return sanitize({'ok':True,'task_id':task_id,'role_id':c['role_id'],'owner_actor_id':c['owner_actor_id'],
            'source_line':c['source_line'],'state':execution_state,'attempt':s.get('attempt',0),
            'original_input_refs':[{'revision':g['revision'],'event_id':g['event_id'],'input_sha256':g['input_sha256']} for g in c['goals']],
            'goal_revision':c['goal_revision'],'applied_goal_revision':c.get('applied_goal_revision',0),
            'current_goal_completed':s.get('state')=='completed' and c['goal_revision']==c.get('applied_goal_revision') and str(s.get('attempt')) in c.get('attempt_receipts',{}),
            'dispatch_status':d.get('status'),'recording_status':s.get('recording_status','pending'),
            'memory_status':s.get('memory_status','pending'),'delivery_status':[a.get('delivery_status') for a in s.get('artifact_refs',[])],
            'memory_repair_required':bool(s.get('memory_retry_required')),
            'memory_repairs':list(c.get('memory_repairs',{}).values()),
            'session_id':s.get('session_id'),'failure_reason':s.get('failure_reason'),
            'commands':list(c.get('commands',{}).values()),'pending_stop':c.get('pending_stop'),
            'created_at':s.get('created_at'),'updated_at':c.get('updated_at')})

    def list_tasks(self,principal):
        result=[]
        for tid in control_ids(self.root):
            try: result.append(self.status(principal,tid))
            except ControlError as e:
                if e.code not in {'forbidden','not_found'}: raise
        return {'ok':True,'tasks':result}

    def lookup_command(self,principal,command_id):
        _id(command_id)
        matches=[]
        for tid in control_ids(self.root):
            try:c=self._authorized(principal,tid)
            except ControlError as exc:
                if exc.code in {'forbidden','not_found'}:continue
                raise
            if command_id in c.get('commands',{}):matches.append(self._receipt(c,c['commands'][command_id],True))
        if not matches:raise ControlError('not_found','Authorized command not found',404)
        if len(matches)>1:raise ControlError('ambiguous_command','Command occurs in multiple tasks; query by task_id',matches=[m['task_id'] for m in matches])
        return matches[0]

    def result(self,principal,task_id,attempt=None):
        c=self._authorized(principal,task_id);s=self._state(task_id)
        selected=s.get('attempt',0) if attempt is None else attempt
        if type(selected) is not int or selected<1: raise ControlError('result_pending','No completed attempt receipt',404)
        committed=sealed_result(self.root,c,selected,latest=attempt is None);p=Path(committed['path']);value=committed['result']
        return {'ok':True,'task_id':task_id,'attempt':selected,'result':sanitize(value),'result_ref':str(p),
            'result_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'current_goal_completed':self.status(principal,task_id)['current_goal_completed']}

def sealed_result(root,c,attempt,latest=True):
    task=Path(root)/'workspace/tasks'/c['task_id']
    committed=c.get('attempt_receipts',{}).get(str(attempt))
    if latest and (c.get('latest_memory_receipt') or {}).get('attempt')==attempt:committed=c['latest_memory_receipt']
    if not committed:raise ControlError('result_pending','Common control has not verified this attempt receipt',404)
    p=Path(committed['path'])
    if p.is_symlink() or not p.resolve().is_relative_to(task.resolve()) or not p.is_file():raise ControlError('receipt_invalid','Immutable receipt path is unavailable or outside task')
    raw=p.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=committed['sha256']:raise ControlError('receipt_invalid','Immutable receipt changed')
    value=json.loads(raw)
    if value.get('task_id')!=c['task_id'] or value.get('role_id')!=c['role_id'] or value.get('attempt')!=attempt:raise ControlError('receipt_invalid','Receipt identity mismatch')
    return {**committed,'result':value}

def memory_repair_guard(root,c,state):
    from task_control import process_identity
    if state.get('state')!='completed' or state.get('worker_execution_completed') is not True or state.get('memory_retry_required') is not True:
        raise ControlError('memory_repair_not_required','Memory repair requires a completed native worker with an outstanding memory failure')
    if state.get('process_cleanup_unverified') or state.get('orphan_worker_may_be_running') or state.get('unconfirmed_processes'):
        raise ControlError('process_review_required','Prior process cleanup must be verified before memory repair')
    for label in ('runner','worker'):
        identity=process_identity(state.get(label+'_pid'))
        if identity and identity==state.get(label+'_identity'):raise ControlError('busy','Previous executor has not stopped')
    sealed=sealed_result(root,c,state['attempt']);result=sealed['result']
    if (result.get('status')!='memory_error' or result.get('exit_code')!=78 or result.get('worker_exit_code')!=0 or
            result.get('native_turn_completed') is not True or result.get('recording_status')!='ok' or result.get('process_cleanup',{}).get('ok') is not True):
        raise ControlError('memory_repair_unproven','Sealed receipt does not prove a memory-only failure after a completed worker')
    return sealed

def seal_memory_repair_locked(root,c,state):
    """Only an immutable, command-bound repair receipt may close a repair dispatch."""
    d=c.get('dispatch') or {};tid=c['task_id'];command_id=d.get('command_id')
    if d.get('mode')!='reconcile_memory':raise ControlError('invalid_repair','Dispatch is not a memory repair')
    task=Path(root)/'workspace/tasks'/tid;p=Path(state.get('result_ref') or task/'missing-memory-receipt')
    if p.is_symlink() or not p.resolve().is_relative_to((task/'memory-retries').resolve()) or not p.is_file():
        raise ControlError('repair_receipt_pending','Memory repair has no sealed receipt')
    raw=p.read_bytes();result=json.loads(raw)
    if (result.get('task_id')!=tid or result.get('role_id')!=c['role_id'] or result.get('attempt')!=d['expected_attempt'] or
            result.get('memory_repair_command_id')!=command_id or result.get('memory_repair_source_sha256')!=d['source_receipt_sha256']):
        raise ControlError('receipt_invalid','Memory repair receipt identity or source differs from its explicit command')
    receipt={'path':str(p),'sha256':hashlib.sha256(raw).hexdigest(),'attempt':result['attempt'],
        'command_id':command_id,'status':result['status'],'exit_code':result['exit_code'],'source_sha256':d['source_receipt_sha256']}
    c.setdefault('memory_repairs',{})[command_id]=receipt;c['latest_memory_receipt']=receipt
    d.update(status='completed',result_attempt=result['attempt'],exit_code=result['exit_code'])
    c['commands'][command_id].update(status='applied',applied_at=_now(),applied_attempt=result['attempt'],
        reason='Memory-only receipt finalized; no native worker was executed',result_ref=str(p),result_sha256=receipt['sha256'])
    save_control(root,c,'memory_repair_finalized',command_id)
    return receipt

def finish_memory_repair(root,tid,command_id):
    with lock(Path(root)/'state/locks'/f'{tid}.control.lock'):
        c=load_control(root,tid)
        if c.get('dispatch',{}).get('command_id')!=command_id:raise ControlError('dispatch_conflict','Memory repair dispatch changed')
        state=json.loads((Path(root)/'state/tasks'/f'{tid}.json').read_text())
        return seal_memory_repair_locked(root,c,state)

def local_principal():
    """Local CLI trust is the OS account, never an actor supplied inside JSON."""
    return Principal('local-uid-'+str(os.getuid()),'local_owner',frozenset(ROLES),
        frozenset({'task:create','task:read:any','task:control:any'}),'os-local-uid-'+str(os.getuid()))

def admit_dispatch(root, packet, state):
    """Called while holding the execution lock. Exactly one persisted launch may enter."""
    tid=packet['task_id']; dispatch_id=packet.get('control_dispatch_id')
    if not dispatch_id:
        if state.get('control_managed'): raise ControlError('managed_task','Managed tasks require the common control dispatcher')
        return False
    with lock(root/'state/locks'/f'{tid}.control.lock'):
        c=load_control(root,tid);d=c.get('dispatch') or {}
        if d.get('command_id')!=dispatch_id or d.get('status')!='claimed' or d.get('packet_sha256')!=digest(packet):
            raise ControlError('dispatch_conflict','Dispatch was not claimed or packet identity changed')
        if state.get('attempt',0)!=d['expected_attempt'] or (d['mode']=='run' and state.get('state')!='queued'):
            raise ControlError('dispatch_conflict','Attempt/state changed since dispatch acceptance')
        d.update(status='started',attempt=d['expected_attempt']+(0 if d.get('mode')=='reconcile_memory' else 1))
        save_control(root,c,'dispatch_started',dispatch_id)
        return True

def prompt_applied(root,packet,attempt):
    if not packet.get('control_dispatch_id'): return
    tid=packet['task_id']
    with lock(root/'state/locks'/f'{tid}.control.lock'):
        c=load_control(root,tid);revision=packet['goal_revision'];c['applied_goal_revision']=revision
        for cmd in c['commands'].values():
            if cmd['command_id']==packet['control_dispatch_id'] or (cmd['action']=='append' and cmd.get('goal_revision',999999)<=revision):
                if cmd['status']=='received':cmd.update(status='applied',applied_at=_now(),applied_attempt=attempt,reason='Included in worker input')
        save_control(root,c,'goal_applied',packet['control_dispatch_id'])

def poll_stop(root,tid,attempt):
    with lock(root/'state/locks'/f'{tid}.control.lock'):
        c=load_control(root,tid)
        if c.get('schema')=='javis-control-1':
            req=c.get('pending_stop')
            if req and req['attempt']==attempt and req['status']=='requested':
                req['status']='stopping';save_control(root,c,'stop_observed',req['command_id']);return req['action']
            return None
        # Existing local CLI tasks retain their cooperative stop interface.
        if c.get('attempt')==attempt and c.get('status')=='requested':
            c.update(status='stopping',accepted_at=_now());atomic_json(root/'state/control'/f'{tid}.json',c);return c['action']
        return None

def finish_control(root,packet,result):
    tid=packet['task_id']
    with lock(root/'state/locks'/f'{tid}.control.lock'):
        c=load_control(root,tid)
        verified=result.get('recording_status')=='ok' and result.get('process_cleanup',{}).get('ok') is True
        if c.get('schema')!='javis-control-1':
            if c.get('status')=='stopping':
                c.update(status='applied' if verified else 'needs_review',applied_at=_now() if verified else None)
                atomic_json(root/'state/control'/f'{tid}.json',c)
            return
        d=c.get('dispatch') or {}
        if d.get('command_id')!=packet.get('control_dispatch_id'): raise ControlError('dispatch_conflict','Final receipt belongs to a different dispatch')
        d.update(status='completed' if verified else 'needs_review',exit_code=result['exit_code'],result_attempt=result['attempt'])
        receipt=Path(root)/'workspace/tasks'/tid/'attempts'/str(result['attempt'])/'result.json'
        c.setdefault('attempt_receipts',{})[str(result['attempt'])]={'path':str(receipt),'sha256':hashlib.sha256(receipt.read_bytes()).hexdigest(),
            'packet_sha256':d.get('packet_sha256')}
        req=c.get('pending_stop')
        if req and req['attempt']==result['attempt']:
            cmd=c['commands'][req['command_id']]
            if verified:
                cmd.update(status='applied',applied_at=_now(),reason='Process tree stopped and RAW receipt finalized',applied_attempt=result['attempt'])
                c['pending_stop']=None
            else:cmd.update(status='needs_review',reason='Stop could not be fully verified; no final acknowledgement')
        save_control(root,c,'execution_finalized',packet.get('control_dispatch_id'))
