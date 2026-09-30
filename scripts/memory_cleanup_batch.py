#!/usr/bin/env python3
"""Owner-signed one-shot cleanup batches for low-value pending memory items (Javis260928 追加三).

A cleanup batch archives/rejects, in one Windows Hello/WebAuthn decision, an exact
manifest of pending items:
  * quarantine candidates   memory/quarantine/<scope>/candidates.jsonl (pending_review)
  * screen triage items     memory/triage/items/triage_<hash>.json      (needs_review)
  * legacy candidates       memory/candidates/by-role/<role>/facts.jsonl (pending_evidence_and_owner_review)

Nothing here ever writes confirmed memory. Preparing a batch changes nothing but a
write-once manifest. After the owner signs the exact manifest digest:
  * quarantine rows get an appended status=rejected version (last_command_id and
    reviewed_at bound to the batch decision; memory_triage re-verifies it offline);
  * triage records stay immutable; memory_triage.pending_view projects them as
    status=archived after re-verifying the batch decision offline;
  * legacy candidates get an appended text-free rejected_by_owner_batch row.
All earlier rows are kept for audit.

CLI (no owner authority; nothing here confirms or rejects):
  python3 memory_cleanup_batch.py preview --selection <spec.json>
  python3 memory_cleanup_batch.py prepare --selection <spec.json>
  python3 memory_cleanup_batch.py status  [--batch <cleanup_id>]
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / 'tools/memory-adapter'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from javis_memory_adapter.review_policy import (  # noqa: E402
    ReviewBlocked, digest, guarded_path, read_rows, safe_id, verified_proof, verify_principal)
from runtime_io import lock  # noqa: E402

SCHEMA = 'javis-cleanup-batch-1'
BATCH_DIR = 'memory/review/cleanup-batches'
DECISIONS = 'memory/review/cleanup-decisions.jsonl'
LOCK = 'state/locks/cleanup-review.lock'
LEGACY_PENDING = 'pending_evidence_and_owner_review'
LEGACY_REJECTED = 'rejected_by_owner_batch'
OUTCOME = 'archived_rejected_not_confirmed'


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _short(text, n=140):
    text = ' '.join(str(text or '').split())
    return text if len(text) <= n else text[:n - 1] + '…'


def _candidate_rel(scope):
    return 'memory/quarantine/' + safe_id(scope) + '/candidates.jsonl'


def _latest_candidate(root, scope, cid):
    safe_id(cid)
    rows = [r for r in read_rows(root, guarded_path(root, root / _candidate_rel(scope))) if r.get('candidate_id') == cid]
    if not rows:
        raise ReviewBlocked('candidate_not_found')
    row = rows[-1]
    if digest(row['payload']) != row['version_digest'] or row['payload'].get('scope') != scope:
        raise ReviewBlocked('candidate_integrity_failed')
    return row


def _legacy_path(root, role):
    return guarded_path(root, root / 'memory/candidates/by-role' / safe_id(role) / 'facts.jsonl')


def _legacy_rows(root, role):
    path = _legacy_path(root, role)
    out = []
    if not path.exists():
        return out
    for line in path.read_text(encoding='utf-8').split('\n'):
        if line.strip():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                out.append(row)
    return out


def _legacy_state(root, role, memory_id):
    rows = [r for r in _legacy_rows(root, role) if r.get('memory_id') == memory_id]
    if not rows:
        raise ReviewBlocked('legacy_candidate_not_found')
    original = next((r for r in rows if isinstance(r.get('fact'), str)), None)
    if original is None:
        raise ReviewBlocked('legacy_candidate_not_found')
    return original, rows[-1].get('memory_status')


def build_manifest(root, spec):
    """Deterministic manifest from a selection spec; validates every item is still pending. Read-only."""
    root = Path(root).resolve()
    if not isinstance(spec, dict) or set(spec) - {'title', 'basis', 'quarantine', 'triage', 'legacy', 'excluded'}:
        raise ReviewBlocked('invalid_cleanup_selection')
    quarantine, triage, legacy = [], [], []
    seen = set()
    for item in spec.get('quarantine') or []:
        scope, cid = item['scope'], item['candidate_id']
        if ('q', scope, cid) in seen:
            raise ReviewBlocked('duplicate_cleanup_item')
        seen.add(('q', scope, cid))
        row = _latest_candidate(root, scope, cid)
        if row['status'] != 'pending_review':
            raise ReviewBlocked('candidate_not_pending')
        if item.get('version_digest') and item['version_digest'] != row['version_digest']:
            raise ReviewBlocked('stale_candidate_version')
        effect = row['payload']['effects'][-1]
        quarantine.append({'scope': scope, 'candidate_id': cid, 'version_digest': row['version_digest'],
                           'predicate': effect.get('predicate'), 'category': str(item.get('category') or 'low_value'),
                           'short': _short(effect.get('value'))})
    if spec.get('triage'):
        import memory_triage
        view = {r['triage_id']: r for r in memory_triage.pending_view(root)['items']}
        for item in spec['triage']:
            tid = item['triage_id'] if isinstance(item, dict) else item
            if ('t', tid) in seen:
                raise ReviewBlocked('duplicate_cleanup_item')
            seen.add(('t', tid))
            row = view.get(tid)
            if row is None or row['status'] != 'needs_review':
                raise ReviewBlocked('triage_item_not_pending')
            triage.append({'triage_id': tid, 'scope': row['scope'], 'source_event_id': row['source_event_id'],
                           'reason_code': row['reason_code'], 'stage': row['stage'],
                           'task_id': (item.get('task_id') if isinstance(item, dict) else None),
                           'category': str((item.get('category') if isinstance(item, dict) else None) or 'codex_task_log')})
    for item in spec.get('legacy') or []:
        role, mid = item['role'], item['memory_id']
        if ('l', role, mid) in seen:
            raise ReviewBlocked('duplicate_cleanup_item')
        seen.add(('l', role, mid))
        original, status = _legacy_state(root, role, mid)
        if status != LEGACY_PENDING:
            raise ReviewBlocked('legacy_candidate_not_pending')
        legacy.append({'role': role, 'memory_id': mid,
                       'fact_sha256': hashlib.sha256(original['fact'].encode('utf-8')).hexdigest(),
                       'category': str(item.get('category') or 'retired_text'), 'short': _short(original['fact'])})
    quarantine.sort(key=lambda x: (x['scope'], x['candidate_id']))
    triage.sort(key=lambda x: (x['scope'], x['triage_id']))
    legacy.sort(key=lambda x: (x['role'], x['memory_id']))
    excluded = [{k: str(v)[:300] for k, v in e.items()} for e in (spec.get('excluded') or [])]

    def by(items, key):
        out = {}
        for x in items:
            out[x[key]] = out.get(x[key], 0) + 1
        return dict(sorted(out.items()))
    counts = {'quarantine': len(quarantine), 'triage': len(triage),
              'triage_source_events': len({x['source_event_id'] for x in triage}), 'legacy': len(legacy),
              'total': len(quarantine) + len(triage) + len(legacy), 'excluded_groups': len(excluded),
              'quarantine_by_scope': by(quarantine, 'scope'), 'triage_by_scope': by(triage, 'scope'),
              'quarantine_by_category': by(quarantine, 'category'), 'legacy_by_role': by(legacy, 'role')}
    return {'schema': SCHEMA, 'title': str(spec.get('title') or 'cleanup')[:200],
            'basis': str(spec.get('basis') or '')[:400], 'outcome': OUTCOME,
            'quarantine': quarantine, 'triage': triage, 'legacy': legacy, 'excluded': excluded, 'counts': counts}


def batch_id(manifest):
    return 'cleanup_' + digest(manifest)[:32]


def _write_once(root, rel, value):
    path = guarded_path(root, root / rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, sort_keys=True, ensure_ascii=False, indent=1).encode('utf-8')
    if path.exists():
        if path.read_bytes() != data:
            raise ReviewBlocked('cleanup_manifest_conflict')
        return path
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    return path


def prepare(root, spec):
    """Persist the exact manifest for owner review. Archives nothing."""
    root = Path(root).resolve()
    manifest = build_manifest(root, spec)
    if not manifest['counts']['total']:
        raise ReviewBlocked('empty_cleanup_batch')
    bid = batch_id(manifest)
    with lock(guarded_path(root, root / LOCK)):
        _write_once(root, f'{BATCH_DIR}/{bid}.json', manifest)
    return {'batch_id': bid, 'manifest_digest': digest(manifest), 'status': 'pending_owner_review',
            **{k: v for k, v in manifest['counts'].items() if not isinstance(v, dict)}}


def load_batch(root, bid):
    safe_id(bid)
    root = Path(root).resolve()
    manifest = json.loads(guarded_path(root, root / BATCH_DIR / f'{bid}.json').read_text(encoding='utf-8'))
    if batch_id(manifest) != bid or manifest.get('schema') != SCHEMA:
        raise ReviewBlocked('cleanup_manifest_integrity_failed')
    return manifest


def _decisions(root):
    root = Path(root).resolve()
    return read_rows(root, guarded_path(root, root / DECISIONS))


def binding_for(root, principal, request):
    """Exact decision the passkey signs: action + batch + manifest digest + counts."""
    verify_principal(root, principal)
    if not isinstance(request, dict) or set(request) - {'cleanup_batch_id', 'command_id', 'action'}:
        raise ReviewBlocked('invalid_cleanup_request')
    action = request.get('action', 'archive_cleanup_batch')
    if action not in ('archive_cleanup_batch', 'decline_cleanup_batch'):
        raise ReviewBlocked('invalid_cleanup_action')
    safe_id(request.get('command_id'))
    manifest = load_batch(root, request.get('cleanup_batch_id'))
    c = manifest['counts']
    return {'action': action, 'cleanup_batch_id': request['cleanup_batch_id'], 'manifest_digest': digest(manifest),
            'outcome': manifest['outcome'], 'quarantine_count': c['quarantine'], 'triage_count': c['triage'],
            'legacy_count': c['legacy'], 'command_id': request['command_id']}


def _append_row(root, rel, row):
    path = guarded_path(root, root / rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as f:
        if os.fstat(f.fileno()).st_nlink != 1:
            raise ReviewBlocked('hardlinked_memory_file')
        f.write(json.dumps(row, sort_keys=True, ensure_ascii=False, allow_nan=False) + '\n'); f.flush(); os.fsync(f.fileno())


def _materialize(root, manifest, decision):
    """Idempotently apply a verified archive decision. Never writes confirmed memory."""
    b = decision['binding']
    done = {'quarantine_rejected': 0, 'quarantine_skipped': [], 'legacy_rejected': 0, 'legacy_skipped': [],
            'triage_archived': len(manifest['triage'])}
    ref = {'cleanup_batch_id': b['cleanup_batch_id'], 'command_id': b['command_id'],
           'proof_id': decision['owner_proof']['proof_id'], 'decided_at': decision['decided_at']}
    with lock(guarded_path(root, root / 'state/locks/memory-review.lock')):
        for item in manifest['quarantine']:
            row = _latest_candidate(root, item['scope'], item['candidate_id'])
            if row.get('last_command_id') == b['command_id'] and row['status'] == 'rejected':
                continue
            if row['status'] != 'pending_review' or row['version_digest'] != item['version_digest']:
                done['quarantine_skipped'].append({'candidate_id': item['candidate_id'], 'status': row['status']})
                continue
            changed = copy.deepcopy(row)
            changed.update(status='rejected', last_command_id=b['command_id'], reviewed_at=decision['decided_at'],
                           owner_batch_id=b['cleanup_batch_id'])
            _append_row(root, _candidate_rel(item['scope']), changed)
            done['quarantine_rejected'] += 1
    if manifest['legacy']:
        with lock(guarded_path(root, root / 'state/locks/legacy-memory-candidates.lock')):
            for item in manifest['legacy']:
                original, status = _legacy_state(root, item['role'], item['memory_id'])
                if status == LEGACY_REJECTED:
                    continue
                if (status != LEGACY_PENDING
                        or hashlib.sha256(original['fact'].encode('utf-8')).hexdigest() != item['fact_sha256']):
                    done['legacy_skipped'].append({'memory_id': item['memory_id'], 'status': status})
                    continue
                _append_row(root, _legacy_path(root, item['role']).relative_to(root).as_posix(), {
                    'schema_version': original.get('schema_version', 'javis-memory-2'),
                    'memory_id': item['memory_id'], 'tier': 'candidate', 'role_id': item['role'],
                    'memory_status': LEGACY_REJECTED, 'previous_memory_status': LEGACY_PENDING,
                    'fact_sha256': item['fact_sha256'], 'confirmed_at': None, 'confirmed_by': None,
                    'status_update_only': True, 'owner_batch': ref, 'recorded_at': decision['decided_at']})
                done['legacy_rejected'] += 1
    return done


def review(root, principal, request, assertion):
    """Verify the fresh passkey assertion for the exact binding, record metadata only, then apply."""
    root = Path(root).resolve()
    actor = verify_principal(root, principal)
    with lock(guarded_path(root, root / LOCK)):
        binding = binding_for(root, principal, request)
        rows = _decisions(root)
        prior = [r for r in rows if r.get('binding', {}).get('command_id') == binding['command_id']]
        if prior:
            if prior[0].get('binding') != binding:
                raise ReviewBlocked('command_id_conflict')
            decision = prior[0]
            verified_proof(root, decision['binding'], proof_id=decision['owner_proof']['proof_id'], expected_actor=actor)
            applied = (_materialize(root, load_batch(root, binding['cleanup_batch_id']), decision)
                       if decision['status'] == 'archived' else {})
            return {'status': decision['status'], 'replayed': True, 'applied': applied, **decision['owner_proof']}
        if any(r.get('binding', {}).get('cleanup_batch_id') == binding['cleanup_batch_id'] for r in rows):
            raise ReviewBlocked('cleanup_batch_already_decided')
        proof = verified_proof(root, binding, assertion=assertion, expected_actor=actor)
        status = 'archived' if binding['action'] == 'archive_cleanup_batch' else 'declined'
        decision = {'schema': SCHEMA, 'binding': binding, 'owner_proof': proof, 'status': status,
                    'decided_at': now_iso()}
        _append_row(root, DECISIONS, decision)
        applied = _materialize(root, load_batch(root, binding['cleanup_batch_id']), decision) if status == 'archived' else {}
        return {'status': status, 'cleanup_batch_id': binding['cleanup_batch_id'], 'applied': applied, **proof}


def list_batches(root, principal):
    verify_principal(root, principal)
    root = Path(root).resolve()
    base = guarded_path(root, root / BATCH_DIR)
    decided = {r.get('binding', {}).get('cleanup_batch_id'): r.get('status') for r in _decisions(root)}
    out = []
    for p in sorted(base.glob('cleanup_*.json')) if base.exists() else []:
        try:
            manifest = load_batch(root, p.stem)
        except (ReviewBlocked, ValueError, OSError, KeyError):
            out.append({'cleanup_batch_id': p.stem, 'status': 'integrity_failed'})
            continue
        out.append({'cleanup_batch_id': p.stem, 'status': decided.get(p.stem, 'pending_owner_review'),
                    'manifest_digest': digest(manifest), 'manifest': manifest})
    return out


def archived(root):
    """Offline re-verified archive decisions -> item index. Fail closed: unverifiable rows are ignored."""
    root = Path(root).resolve()
    result = {'quarantine': {}, 'triage': {}, 'legacy': {}}
    try:
        rows = _decisions(root)
    except (ReviewBlocked, ValueError, OSError):
        return result
    for row in rows:
        b = row.get('binding') or {}
        if row.get('status') != 'archived' or b.get('action') != 'archive_cleanup_batch':
            continue
        try:
            manifest = load_batch(root, b['cleanup_batch_id'])
            if digest(manifest) != b['manifest_digest']:
                continue
            proof = verified_proof(root, b, proof_id=row['owner_proof']['proof_id'],
                                   expected_actor=row['owner_proof']['actor_id'])
        except (ReviewBlocked, KeyError, ValueError, OSError, TypeError):
            continue
        if proof != row['owner_proof']:
            continue
        ref = {'cleanup_batch_id': b['cleanup_batch_id'], 'command_id': b['command_id'],
               'decided_at': row.get('decided_at'), 'proof_id': proof['proof_id']}
        for x in manifest['quarantine']:
            result['quarantine'][(x['scope'], x['candidate_id'], x['version_digest'])] = ref
        for x in manifest['triage']:
            result['triage'][x['triage_id']] = ref
        for x in manifest['legacy']:
            result['legacy'][(x['role'], x['memory_id'])] = ref
    return result


def verified_candidate_rejection(candidate, scope, index):
    """True only if a verified archive decision covers this exact rejected candidate version."""
    ref = index['quarantine'].get((scope, candidate.get('candidate_id'), candidate.get('version_digest')))
    return bool(ref and candidate.get('status') == 'rejected' and candidate.get('last_command_id') == ref['command_id']
                and candidate.get('reviewed_at') == ref['decided_at']
                and candidate.get('owner_batch_id') == ref['cleanup_batch_id'])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('command', choices=['preview', 'prepare', 'status'])
    ap.add_argument('--selection')
    ap.add_argument('--batch')
    ap.add_argument('--javis-root', default=None)
    args = ap.parse_args()
    root = Path(args.javis_root or os.environ.get('JAVIS_ROOT') or Path.home() / 'javis').expanduser().resolve()
    if args.command in ('preview', 'prepare'):
        if not args.selection:
            raise ValueError('selection_required')
        spec = json.loads(Path(args.selection).expanduser().read_text(encoding='utf-8'))
        if args.command == 'preview':
            m = build_manifest(root, spec)
            out = {'batch_id': batch_id(m), 'counts': m['counts'], 'status': 'preview_only'}
        else:
            out = prepare(root, spec)
    else:
        decided = {r.get('binding', {}).get('cleanup_batch_id'): r.get('status') for r in _decisions(root)}
        base = guarded_path(root, root / BATCH_DIR)
        ids = [args.batch] if args.batch else sorted(p.stem for p in base.glob('cleanup_*.json')) if base.exists() else []
        out = [{'batch_id': b, 'status': decided.get(b, 'pending_owner_review'),
                'counts': load_batch(root, b)['counts']} for b in ids]
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(json.dumps({'ok': False, 'status': 'blocked', 'reason': str(exc)[:200],
                          'error_type': type(exc).__name__}, ensure_ascii=False))
        raise SystemExit(2)
