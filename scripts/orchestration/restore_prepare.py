#!/usr/bin/env python3
"""Prepare an already verified isolated restore. Never starts services or edits RAW."""
from __future__ import annotations
import argparse,datetime,hashlib,json,os,pathlib,uuid
from fixed_work import atomic,read,JOB_ID,ACTIVE

def restore_prepare(root, *, source_archive_sha256=None):
    supplied=pathlib.Path(root)
    if supplied.is_symlink():raise ValueError('Restore root must not be a symlink')
    root=supplied.resolve()
    live=pathlib.Path('/home/user/javis')
    if not root.is_dir() or root==live or root in live.parents or root.is_relative_to(live):
        raise ValueError('An existing isolated restore directory outside live Javis is required')
    if source_archive_sha256 is not None and (len(source_archive_sha256)!=64 or any(c not in '0123456789abcdef' for c in source_archive_sha256)):
        raise ValueError('Invalid source archive SHA256')
    state=root/'state'
    if state.is_symlink():raise ValueError('Restore state directory must not be a symlink')
    state.mkdir(mode=0o700,exist_ok=True)
    captured=datetime.datetime.now(datetime.timezone.utc).isoformat()
    report={'schema_version':1,'preparation_id':str(uuid.uuid4()),'captured_at':captured,'restored_root':str(root),'source_archive_sha256':source_archive_sha256,'raw_modified':False,'services_installed_or_started':False,'changes':[]}
    def save(path,value,fields):
        if path.is_symlink():raise ValueError('Restore projection must not be a symlink')
        before=hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        atomic(path,value)
        report['changes'].append({'path':str(path.relative_to(root)),'before_sha256':before,'after_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'fields':fields})
    hold=state/'recovery-hold.json'
    existing=read(hold) if hold.exists() else {}
    if not isinstance(existing,dict):existing={}
    value={'schema_version':1,'hold':True,'reason':'restored_backup_requires_review','created_at':existing.get('created_at',captured),'restored_root':str(root),'blocks':['dispatcher','fixed_work'],'source_archive_sha256':source_archive_sha256}
    if existing!=value:save(hold,value,{'hold':True})
    if (state/'fixed-work').is_symlink():raise ValueError('Restored fixed-work directory must not be a symlink')
    job_path=state/'fixed-work'/(JOB_ID+'.json')
    if job_path.exists():
        job=read(job_path)
        if job.get('job_id')!=JOB_ID:raise ValueError('Unexpected restored fixed job identity')
        if job.get('enabled') is not False:
            before_enabled=job.get('enabled');before_version=job.get('version')
            job.update(enabled=False,version=int(before_version or 0)+1,updated_at=captured)
            save(job_path,job,{'enabled':{'before':before_enabled,'after':False},'version':{'before':before_version,'after':job['version']}})
    runs=state/'fixed-work/runs'
    if runs.is_symlink():raise ValueError('Restored runs directory must not be a symlink')
    if runs.exists():
        for path in sorted(runs.glob('fw-*.json')):
            row=read(path)
            if row.get('state') in ACTIVE:
                old=row['state'];row.update(state='needs_review',reason='restored_without_task_replay',restored_from_state=old,updated_at=captured)
                save(path,row,{'state':{'before':old,'after':'needs_review'}})
    history=state/'restore-preparations.jsonl'
    if history.is_symlink():raise ValueError('Restore history must not be a symlink')
    with history.open('a',encoding='utf-8') as stream:
        stream.write(json.dumps(report,ensure_ascii=False)+'\n');stream.flush();os.fsync(stream.fileno())
    atomic(state/'restore-preparation.json',report)
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=pathlib.Path);p.add_argument('--source-archive-sha256');args=p.parse_args()
    print(json.dumps(restore_prepare(args.root,source_archive_sha256=args.source_archive_sha256),ensure_ascii=False,indent=2))
