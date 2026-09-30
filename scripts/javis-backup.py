#!/usr/bin/env python3
"""Verified application backup with two Shanghai schedule slots and audit records."""
import argparse, hashlib, io, json, os, shutil, sqlite3, sys, tarfile, tempfile, time, uuid
from contextlib import ExitStack
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo
from runtime_io import lock, atomic_json
from raw_policy import is_vault_path, is_vault_bytes

ROOTS=['memory','docs','scripts','tests','config','raw/events','raw/manifests','raw/objects','raw/private-originals',
       'state','workspace','tools/memory-adapter','tools/raw-index',
       'tools/graphiti','tools/cognee','tools/control-panel','lab/memory-adapter/meta']
# Explicit root files only; a same-named directory must never be traversed.
ROOT_FILES=['.gitignore','tools/flowise/package.json','tools/flowise/package-lock.json',
            'tools/control-panel/requirements.lock']
DEPENDENCY_LOCK_FILES={'tools/control-panel/requirements.lock'}
EXCLUDE={'.venv','node_modules','.git','__pycache__','.env','auth.json','credentials.json',
         'cookies.json','sand-secrets.json','.ssh','.aws','.azure','.codex'}
TZ=ZoneInfo('Asia/Shanghai')
SCHEDULE=['03:15','15:15']
SQLITE_HEADER=b'SQLite format 3\x00'


def now():
    return datetime.now(TZ)


def scheduled_slot(moment):
    """Latest due slot; one catch-up run covers all slots missed while offline."""
    local=moment.astimezone(TZ)
    slots=[local.replace(hour=int(t[:2]),minute=int(t[3:]),second=0,microsecond=0) for t in SCHEDULE]
    return max([t for t in slots if t<=local] or [slots[-1]-timedelta(days=1)])


def read_latest(dest):
    path=dest/'latest.json'
    if not path.exists(): return None
    try:
        data=json.loads(path.read_text(encoding='utf-8'))
        archive=Path(data['archive']).resolve()
        # Do not trust a moved/stale latest.json or timestamps on unverified files.
        if not data.get('verified') or archive.parent!=dest.resolve() or not archive.is_file(): return None
        if archive.stat().st_size!=data['bytes']: return None
        return data
    except (ValueError,TypeError,KeyError,OSError):
        return None


def is_due(dest, moment):
    latest=read_latest(dest)
    if latest is None: return True
    try:
        # Use snapshot start, not completion: a long backup crossing a new slot
        # must not accidentally claim it captured changes after that slot.
        completed=datetime.fromisoformat(latest['created_at'])
        if completed.tzinfo is None: return True
        return completed.astimezone(TZ)<scheduled_slot(moment)
    except (ValueError,TypeError,KeyError):
        return True


def audit(root, dest, row):
    """Keep failures locally even when a removable/network destination is unavailable."""
    directory=root/'state/backup'
    directory.mkdir(parents=True,exist_ok=True)
    with lock(directory/'.audit.lock'):
        with (directory/'runs.jsonl').open('a',encoding='utf-8') as handle:
            handle.write(json.dumps(row,ensure_ascii=False)+'\n'); handle.flush(); os.fsync(handle.fileno())
        atomic_json(directory/'last-run.json',row)
        if row['status']=='success': atomic_json(directory/'last-success.json',row)
    # Destination history is secondary; a missing destination must not hide local failures.
    try:
        if dest.is_dir():
            with lock(dest/'.audit.lock'):
                with (dest/'backup-runs.jsonl').open('a',encoding='utf-8') as handle:
                    handle.write(json.dumps(row,ensure_ascii=False)+'\n'); handle.flush(); os.fsync(handle.fileno())
    except OSError:
        pass

def files(root):
    seen=set()
    for part in ROOTS+ROOT_FILES:
        base=root/part
        paths=[base] if base.is_file() else (base.rglob('*') if part in ROOTS and base.exists() else [])
        for p in paths:
            rel=p.relative_to(root)
            if any(x.lower() in EXCLUDE or x.lower().startswith('.env.') for x in rel.parts): continue
            if p.suffix.lower() in ('.pyc','.pid','.pem','.key','.p12','.pfx'): continue
            if (p.name=='.lock' or p.suffix.lower()=='.lock') and rel.as_posix() not in DEPENDENCY_LOCK_FILES: continue
            if p.name.endswith(('-wal','-shm','-journal')): continue
            if p.name.startswith(('.checkpoint-','.facts.','.confirmations.','.corrections.')): continue
            if any(part.startswith('.auth') for part in rel.parts):
                continue
            if p.is_symlink() or not p.is_file() or rel.as_posix() in seen: continue
            if is_vault_path(p): continue
            with p.open('rb') as handle:
                if is_vault_bytes(handle.read(8)): continue
            seen.add(rel.as_posix()); yield p,rel.as_posix()

def verify(archive, extract_to=None):
    with tarfile.open(archive,'r:gz') as t:
        manifest=json.load(t.extractfile('MANIFEST.json'))
        names=[m.name for m in t.getmembers()]
        expected=['MANIFEST.json']+[r['path'] for r in manifest['files']]
        if len(names)!=len(set(names)) or sorted(names)!=sorted(expected): raise ValueError('unexpected or duplicate archive member')
        for row in manifest['files']:
            rel=Path(row['path'])
            if rel.is_absolute() or '..' in rel.parts or '\\' in row['path'] or ':' in row['path']: raise ValueError('unsafe archive path')
            if not t.getmember(row['path']).isfile(): raise ValueError('backup member must be a regular file')
            src=t.extractfile(row['path']); h=hashlib.sha256(); n=0
            dest=None
            if extract_to:
                base=Path(extract_to).resolve(); p=base/rel
                if not p.resolve().is_relative_to(base): raise ValueError('unsafe restore destination')
                p.parent.mkdir(parents=True,exist_ok=True); dest=p.open('wb')
            try:
                while chunk:=src.read(1024*1024):
                    h.update(chunk); n+=len(chunk)
                    if dest: dest.write(chunk)
            finally:
                if dest: dest.close()
            if h.hexdigest()!=row['sha256'] or n!=row['bytes']: raise ValueError('backup checksum mismatch: '+row['path'])
            if extract_to and row.get('snapshot_method')=='sqlite_online_backup':
                with sqlite3.connect(p.as_uri()+'?mode=ro',uri=True) as db:
                    if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]: raise ValueError('SQLite integrity check failed: '+row['path'])
    return manifest


def sqlite_snapshot(path, target):
    deadline=time.monotonic()+60
    def progress(status,remaining,total):
        if time.monotonic()>deadline: raise RuntimeError('SQLite online backup timed out after 60 seconds')
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=30) as source:
        with sqlite3.connect(target) as destination:
            source.backup(destination,pages=256,progress=progress,sleep=0.1)
            if destination.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]: raise RuntimeError('SQLite snapshot integrity check failed')
    return target.read_bytes()


def sqlite_sidecars(path):
    result={}
    for suffix in ('-wal','-journal'):
        sidecar=Path(str(path)+suffix)
        try:
            stat=sidecar.stat()
            # SQLite can create an empty WAL even for a mode=ro connection to
            # an imported database persisted in WAL mode. An absent WAL and
            # a zero-byte WAL both contain no transactions. Keep every nonzero
            # WAL (including a header-only WAL) and rollback journal strict.
            result[suffix]=None if suffix=='-wal' and stat.st_size==0 else [stat.st_size,stat.st_mtime_ns]
        except FileNotFoundError:
            result[suffix]=None
    return result


def create_backup(root, dest, *, if_due=False, destination_kind='same_machine', restore_check=False):
    started=now(); slot=scheduled_slot(started)
    record={'schema_version':2,'run_id':str(uuid.uuid4()),'started_at':started.isoformat(),
            'timezone':'Asia/Shanghai','schedule':SCHEDULE,'scheduled_for':slot.isoformat(),
            'destination':str(dest),'destination_kind':destination_kind,
            'off_machine_backup_verified':False,'status':'running','failure_reason':None}
    pending=None
    try:
        # Serialise attempts locally first so an unavailable destination still has a durable failure record.
        with lock(root/'state/backup/.run.lock'):
            # Mounted destinations must already exist: never silently fall back into an absent mount directory.
            if destination_kind!='same_machine' and not dest.is_dir(): raise RuntimeError('independent backup destination unavailable')
            if dest==root or any(dest.is_relative_to(root/part) for part in ROOTS+ROOT_FILES):
                raise RuntimeError('backup destination must be outside included source directories')
            dest.mkdir(parents=True,exist_ok=True)
            with lock(dest/'.backup.lock'),lock(root/'state/maintenance.lock'),ExitStack() as stack:
                snapshot_started=now(); slot=scheduled_slot(snapshot_started)
                record['scheduled_for']=slot.isoformat()
                if if_due and not is_due(dest,snapshot_started):
                    record.update(status='skipped',skip_reason='latest scheduled slot already covered',finished_at=now().isoformat())
                    audit(root,dest,record); return record
                # Shared ordering with owner confirmation: memory-review -> owner -> ledger.
                # The backup also holds maintenance first and fixed-work before ledger locks.
                for relative in ('state/locks/memory-review.lock','state/owner-auth/.lock','state/fixed-work/.lock'):
                    if (root/relative).parent.is_dir(): stack.enter_context(lock(root/relative))
                initial=list(files(root))
                ledger_dirs=sorted({p.parent for p,rel in initial if p.name=='facts.jsonl'},key=str)
                for directory in ledger_dirs: stack.enter_context(lock(directory/'.ledger.lock'))
                inventory=list(files(root)); size=sum(p.stat().st_size for p,_ in inventory)
                record['source_bytes']=size
                if shutil.disk_usage(dest).free<size+64*1024*1024: raise RuntimeError('insufficient backup disk space')
                stamp=snapshot_started.strftime('%Y%m%d-%H%M%S-%f')+'-'+record['run_id'][:8]
                target=dest/f'javis-full-{stamp}.tar.gz'; pending=dest/(target.name+'.partial')
                manifest={'schema_version':2,'created_at':snapshot_started.isoformat(),'root':str(root),'timezone':'Asia/Shanghai',
                          'scheduled_for':slot.isoformat(),'includes':ROOTS+ROOT_FILES,'excludes':sorted(EXCLUDE),'files':[],
                          'consistency':'maintenance, memory-review, owner-auth, fixed-work then ledger locks; SQLite online backup; concurrent file-set and content-stat checks',
                          'runtime':{'python':sys.version.split()[0],'platform':sys.platform},
                          'credential_policy':'known credential files, private-key containers, authentication directories, Javis-Vault paths and KeePass databases/key files excluded; renamed KeePass databases detected by signature; ordinary content governed by RAW redaction',
                          'destination_kind':destination_kind,'off_machine_backup_verified':False}
                with tempfile.TemporaryDirectory(prefix='javis-sqlite-backup-') as tmp,tarfile.open(pending,'w:gz') as archive:
                    for index,(path,rel) in enumerate(inventory):
                        before=path.stat()
                        with path.open('rb') as handle: sqlite_file=handle.read(16)==SQLITE_HEADER
                        sidecars=sqlite_sidecars(path) if sqlite_file else None
                        method='sqlite_online_backup' if sqlite_file else 'locked_file_copy'
                        data=sqlite_snapshot(path,Path(tmp)/f'{index}.sqlite') if sqlite_file else path.read_bytes()
                        # Recheck the captured bytes before adding them: inventory
                        # and copy are separate operations, even with our locks.
                        if path.is_symlink() or is_vault_path(path) or is_vault_bytes(data):
                            raise RuntimeError('vault or linked source appeared during backup')
                        after=path.stat()
                        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns): raise RuntimeError('source changed during backup: '+rel)
                        info=tarfile.TarInfo(rel); info.size=len(data); info.mode=before.st_mode & 0o777; info.mtime=before.st_mtime
                        archive.addfile(info,io.BytesIO(data))
                        manifest['files'].append({'path':rel,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                                                 'source_bytes':before.st_size,'mtime_ns':before.st_mtime_ns,'snapshot_method':method,
                                                 'sqlite_sidecars':sidecars})
                    for row in manifest['files']:
                        stat=(root/row['path']).stat()
                        if (stat.st_size,stat.st_mtime_ns)!=(row['source_bytes'],row['mtime_ns']): raise RuntimeError('concurrent source write: '+row['path'])
                        if row['sqlite_sidecars'] is not None and sqlite_sidecars(root/row['path'])!=row['sqlite_sidecars']:
                            raise RuntimeError('concurrent SQLite write: '+row['path'])
                    if {rel for _,rel in files(root)}!={row['path'] for row in manifest['files']}: raise RuntimeError('file set changed during backup')
                    data=json.dumps(manifest,ensure_ascii=False,indent=2).encode(); info=tarfile.TarInfo('MANIFEST.json'); info.size=len(data)
                    archive.addfile(info,io.BytesIO(data))
                if restore_check:
                    with tempfile.TemporaryDirectory(prefix='javis-restore-check-') as tmp: verify(pending,tmp)
                else: verify(pending)
                pending.replace(target)
                record.update(status='success',success_at=now().isoformat(),archive=str(target),verified=True,
                              files=len(manifest['files']),bytes=target.stat().st_size,restore_check=restore_check)
                atomic_json(dest/'latest.json',{'archive':str(target),'verified':True,'created_at':manifest['created_at'],
                            'success_at':record['success_at'],'files':len(manifest['files']),'bytes':record['bytes'],
                            'timezone':'Asia/Shanghai','scheduled_for':slot.isoformat(),'destination_kind':destination_kind,
                            'off_machine_backup_verified':False})
                # Keep the existing 14-archive retention limit, and never traverse a symlink during rotation.
                for old in sorted(dest.glob('javis-full-*.tar.gz'),key=lambda p:p.stat().st_mtime)[:-14]:
                    if not old.is_symlink() and old.resolve().parent==dest: old.unlink()
                record['finished_at']=now().isoformat(); audit(root,dest,record); return record
    except Exception as exc:
        record.update(status='failed',finished_at=now().isoformat(),failure_reason=f'{type(exc).__name__}: {exc}')
        audit(root,dest,record)
        return record
    finally:
        if pending: pending.unlink(missing_ok=True)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--if-due',action='store_true'); ap.add_argument('--verify')
    ap.add_argument('--restore-check',action='store_true'); ap.add_argument('--status',action='store_true')
    ap.add_argument('--destination'); ap.add_argument('--destination-kind',choices=['same_machine','independent_unverified'],default='same_machine')
    args=ap.parse_args()
    if args.verify:
        if args.restore_check:
            with tempfile.TemporaryDirectory(prefix='javis-restore-check-') as tmp: manifest=verify(args.verify,tmp)
        else: manifest=verify(args.verify)
        print(json.dumps({'verified':True,'files':len(manifest['files']),'restore_check':args.restore_check})); return 0
    root=Path(os.environ.get('JAVIS_ROOT',os.environ.get('JAVIS_HOME',Path.home()/'javis'))).resolve()
    dest=Path(args.destination or os.environ.get('JAVIS_BACKUP_DEST','/mnt/c/Users/user/Javis-Exchange/backups/daily')).resolve()
    if args.status:
        row={'timezone':'Asia/Shanghai','schedule':SCHEDULE,'scheduled_for':scheduled_slot(now()).isoformat(),
             'due':is_due(dest,now()),'destination':str(dest),'destination_kind':args.destination_kind,'off_machine_backup_verified':False}
        for key,name in [('last_run','last-run.json'),('last_success','last-success.json')]:
            path=root/'state/backup'/name; row[key]=json.loads(path.read_text(encoding='utf-8')) if path.exists() else None
        print(json.dumps(row,ensure_ascii=False)); return 0
    row=create_backup(root,dest,if_due=args.if_due,destination_kind=args.destination_kind,restore_check=args.restore_check)
    print(json.dumps(row,ensure_ascii=False)); return 1 if row['status']=='failed' else 0


if __name__=='__main__': raise SystemExit(main())
