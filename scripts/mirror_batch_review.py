#!/usr/bin/env python3
"""Owner-signed Grok<->Javis mirror batches (9/23 LOCK) while the memory pipeline gate is on.

Preparing a batch never confirms anything. A batch becomes usable only after the
owner signs its exact manifest digest with the enrolled Windows Hello/WebAuthn
passkey through the local control panel (owner_auth.verify_decision). Consumers
(apply-confirmed-on-machine0.py, export-javis-confirmed-for-grok.py) re-verify the
recorded signature offline (owner_auth.verify_recorded_decision) before every use.

Filters applied before anything reaches a manifest: secrets/keys/PIN/vault, L4,
and entries about the Friday bot (the weekday 周五/星期五 is not a Friday match).
Conflict rule: newer as_of wins; same as_of is a duplicate; an older or
undeterminable as_of is reported as a conflict and never overwrites.

CLI (no owner authority; nothing here confirms):
  python3 mirror_batch_review.py preview --package ~/javis/memory/imports/<pkg>
  python3 mirror_batch_review.py prepare --package ~/javis/memory/imports/<pkg>
  python3 mirror_batch_review.py status  --package ~/javis/memory/imports/<pkg>
  python3 mirror_batch_review.py prepare-policy --statement '<owner words>' --stated-at '<time>' --source '<where>'
  python3 mirror_batch_review.py revoke-policy --reason '<why>'
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / 'tools/memory-adapter'))
from javis_memory_adapter.review_policy import (  # noqa: E402
    ReviewBlocked, digest, guarded_path, read_rows, safe_id, verified_proof, verify_principal)
from runtime_io import lock  # noqa: E402

SCHEMA = 'javis-mirror-batch-1'
POLICY_SCHEMA = 'javis-mirror-policy-1'
LOCK_TEXT = ('9/23 LOCK: Grok and Javis memory are bidirectionally synced and identical; '
             'Grok->Javis may write confirmed; Javis confirmed writes back to Grok; newer as_of/learned_at wins; '
             'undeterminable -> report conflict, never overwrite; L4/secrets/passwords/keys/PINs never sync; '
             'Friday is excluded from shared memory.')

SECRET_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|sk-[A-Za-z0-9_-]{10,}|\bPIN\b|private[_-]?key|credential|保险箱|密钥)",
    re.I,
)
L4_RE = re.compile(r"\bL4\b|strict\s*L4|医疗病历|身份证号|护照号", re.I)
# Friday *bot*: an ASCII word "friday" (any case). Chinese weekday forms never match.
FRIDAY_WORD_RE = re.compile(r"(?<![A-Za-z])friday(?![A-Za-z])", re.I)
# English weekday usages are not about the bot.
FRIDAY_WEEKDAY_RE = re.compile(
    r"(?i)\b(?:on|this|next|last|every|each|by|until|till|since|before|after)\s+friday\b"
    r"|\bfriday(?:'s)?\s+(?:close|closing|night|morning|afternoon|evening|session|official|at\b|\d)"
    r"|\bfriday,?\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b")
FRIDAY_ROLES = {'friday'}

BATCH_DIR = 'memory/review/mirror-batches'
DECISIONS = 'memory/review/mirror-decisions.jsonl'
POLICY_DIR = 'memory/review/mirror-policies'


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def norm_key(text):
    return re.sub(r"\s+", " ", text.strip().lower())[:180]


def is_secret_or_l4(text):
    return bool(SECRET_RE.search(text or '') or L4_RE.search(text or ''))


def is_friday_bot(record):
    """True only for entries about the Friday bot/role, not the weekday."""
    role = (record.get('role') or record.get('role_id') or '').strip().lower()
    bot = (record.get('bot_name') or '').strip().lower()
    if role in FRIDAY_ROLES or bot in FRIDAY_ROLES:
        return True
    fact = record.get('fact') or record.get('text') or ''
    hits = list(FRIDAY_WORD_RE.finditer(fact))
    if not hits:
        return False
    weekday_spans = [m.span() for m in FRIDAY_WEEKDAY_RE.finditer(fact)]
    for hit in hits:
        if not any(a <= hit.start() < b for a, b in weekday_spans):
            return True
    return False


def _valid_now(record):
    vt = (record.get('temporal') or {}).get('valid_to')
    if not vt:
        return True
    try:
        return datetime.fromisoformat(vt.replace('Z', '+00:00')) >= datetime.now(timezone.utc)
    except ValueError:
        return True


def confirmed_files(root):
    conf = root / 'memory/confirmed'
    files = []
    if (conf / 'shared/facts.jsonl').exists():
        files.append(('shared', conf / 'shared/facts.jsonl'))
    if (conf / 'by-role').is_dir():
        for d in sorted((conf / 'by-role').iterdir()):
            if (d / 'facts.jsonl').exists():
                files.append((d.name, d / 'facts.jsonl'))
    return files


def _json_rows(path):
    out = []
    for line in path.read_text(encoding='utf-8').split('\n'):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def existing_confirmed(root, role):
    """Latest still-valid confirmed version per normalized fact (role + shared)."""
    paths = [root / 'memory/confirmed/shared/facts.jsonl']
    if role != 'shared':
        paths.insert(0, root / 'memory/confirmed/by-role' / role / 'facts.jsonl')
    if role in ('idea-lab', 'ide-lab'):
        # memory-append.py historically wrote idea-lab (any tier) to this mixed file.
        paths.insert(0, root / 'memory/ide-lab/facts.jsonl')
    out = {}
    for p in paths:
        if not p.exists():
            continue
        for o in _json_rows(guarded_path(root, p)):
            fact = o.get('fact') or o.get('text') or ''
            if not fact or not _valid_now(o) or (o.get('tier') and o.get('tier') != 'confirmed'):
                continue
            t = o.get('temporal') or {}
            as_of = t.get('as_of') or t.get('learned_at') or o.get('as_of') or ''
            k = norm_key(fact)
            if k not in out or as_of >= (out[k].get('_as_of') or ''):
                out[k] = {**o, '_as_of': as_of}
    return out


RETIRED_REGISTRY = 'memory/review/retired-facts.jsonl'


def retired_keys(root):
    """Normalized facts Javis has retired (RULES §3.2 tombstone: valid_to in the past).

    Sources: any confirmed file whose row has an expired valid_to and no still-valid
    row with the same text, plus the append-only retirement registry. Used so a
    retired fact that still lives on the Grok side is never re-promoted or re-exported.
    """
    root = Path(root).resolve()
    retired, alive = {}, set()
    paths = [p for _, p in confirmed_files(root)]
    if (root / 'memory/ide-lab/facts.jsonl').exists():
        paths.append(root / 'memory/ide-lab/facts.jsonl')
    for p in paths:
        for o in _json_rows(guarded_path(root, p)):
            fact = o.get('fact') or o.get('text') or ''
            if not fact or (o.get('tier') and o.get('tier') != 'confirmed'):
                continue
            k = norm_key(fact)
            if _valid_now(o):
                alive.add(k)
            else:
                retired.setdefault(k, o.get('memory_id'))
    reg = root / RETIRED_REGISTRY
    if reg.exists():
        for o in _json_rows(guarded_path(root, reg)):
            fact = o.get('fact') or ''
            if fact and o.get('action', 'retire') == 'retire':
                retired.setdefault(norm_key(fact), o.get('memory_id'))
    return {k: v for k, v in retired.items() if k not in alive}


def _stage(root, pkg):
    pkg = guarded_path(root, Path(pkg))
    stage = guarded_path(root, pkg / 'confirmed-stage/ALL-CONFIRMED-READY.jsonl')
    data = stage.read_bytes()
    rows = []
    for number, raw in enumerate(data.splitlines(), 1):
        if not raw.strip():
            continue
        rec = json.loads(raw)
        if not isinstance(rec, dict) or not isinstance(rec.get('fact'), str) or not rec['fact'].strip():
            raise ReviewBlocked('invalid_stage_record')
        safe_id(rec.get('role') or 'shared')
        rows.append((number, rec))
    return pkg, stage, hashlib.sha256(data).hexdigest(), rows


def _as_of(rec):
    return rec.get('as_of') or rec.get('learned_at') or ''


def build_manifest(root, pkg):
    """Deterministic manifest for a package. Read-only."""
    root = Path(root).resolve()
    pkg, stage, stage_sha, rows = _stage(root, pkg)
    promote, conflicts, friday, dup, secret = [], [], [], 0, 0
    retired, retired_hits = retired_keys(root), []
    cache = {}
    grok_keys = set()
    for line, rec in rows:
        role = rec.get('role') or 'shared'
        fact = rec['fact']
        if is_secret_or_l4(fact):
            secret += 1
            continue
        if is_friday_bot(rec):
            friday.append({'role': role, 'line': line, 'fact': fact[:200], 'as_of': _as_of(rec)})
            continue
        grok_keys.add(norm_key(fact))
        existing = cache.setdefault(role, existing_confirmed(root, role))
        ex = existing.get(norm_key(fact))
        as_of = _as_of(rec)
        item = {'role': role, 'line': line, 'fact': fact, 'as_of': rec.get('as_of') or as_of,
                'learned_at': rec.get('learned_at') or as_of, 'kind': rec.get('kind') or 'fact',
                'fact_sha256': hashlib.sha256(fact.encode('utf-8')).hexdigest()}
        if ex is None and norm_key(fact) in retired:
            retired_hits.append({'role': role, 'line': line, 'fact': fact[:200], 'as_of': as_of,
                                 'retired_memory_id': retired[norm_key(fact)]})
            continue
        if ex is None:
            promote.append({**item, 'reason': 'new'})
            continue
        ex_as = ex.get('_as_of') or ''
        if as_of and ex_as and as_of == ex_as:
            dup += 1
        elif as_of and ex_as and as_of > ex_as:
            promote.append({**item, 'reason': 'newer_than_confirmed', 'supersedes': ex.get('memory_id')})
        else:
            conflicts.append({'role': role, 'line': line, 'fact': fact[:200], 'as_of': as_of,
                              'existing_as_of': ex_as, 'existing_memory_id': ex.get('memory_id'),
                              'reason': 'older_than_confirmed' if (as_of and ex_as) else 'cannot_compare_as_of'})
    # Javis confirmed -> Grok: still-valid confirmed entries absent from the Grok side.
    export, seen = [], set()
    for role, path in confirmed_files(root):
        for o in _json_rows(guarded_path(root, path)):
            fact = o.get('fact') or o.get('text') or ''
            if (not fact or (o.get('tier') and o.get('tier') != 'confirmed') or not _valid_now(o)
                    or is_secret_or_l4(fact) or is_friday_bot({**o, 'role': role})):
                continue
            k = norm_key(fact)
            if k in grok_keys or k in retired or (role, k) in seen:
                continue
            seen.add((role, k))
            t = o.get('temporal') or {}
            export.append({'role': role, 'fact': fact, 'as_of': t.get('as_of') or o.get('as_of'),
                           'learned_at': t.get('learned_at') or o.get('learned_at'),
                           'memory_id': o.get('memory_id'), 'source': 'javis-confirmed',
                           'fact_sha256': hashlib.sha256(fact.encode('utf-8')).hexdigest()})
    return {'schema': SCHEMA, 'package_id': pkg.name,
            'stage_path': stage.relative_to(root).as_posix(), 'stage_sha256': stage_sha,
            'policy': LOCK_TEXT, 'promote': promote, 'export': export,
            'excluded': {'secret_or_l4': secret, 'friday_bot': friday, 'conflicts': conflicts,
                         'already_confirmed_same_as_of': dup, 'retired_in_javis': retired_hits},
            'counts': {'staged': len(rows), 'promote': len(promote), 'export': len(export),
                       'conflicts': len(conflicts), 'friday_bot': len(friday), 'secret_or_l4': secret,
                       'duplicates': dup, 'retired_in_javis': len(retired_hits)}}


def batch_id(manifest):
    return 'mirror_' + digest(manifest)[:32]


def _write_once(root, rel, value):
    path = guarded_path(root, root / rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, sort_keys=True, ensure_ascii=False, indent=1).encode('utf-8')
    if path.exists():
        if path.read_bytes() != data:
            raise ReviewBlocked('mirror_manifest_conflict')
        return path
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    return path


def prepare(root, pkg):
    """Persist the exact manifest for owner review. Confirms nothing."""
    root = Path(root).resolve()
    manifest = build_manifest(root, pkg)
    bid = batch_id(manifest)
    with lock(guarded_path(root, root / 'state/locks/mirror-review.lock')):
        _write_once(root, f'{BATCH_DIR}/{bid}.json', manifest)
    return {'batch_id': bid, 'manifest_digest': digest(manifest), **manifest['counts'],
            'status': 'pending_owner_review'}


def load_batch(root, bid):
    safe_id(bid)
    path = guarded_path(root, Path(root) / BATCH_DIR / f'{bid}.json')
    manifest = json.loads(path.read_text(encoding='utf-8'))
    if batch_id(manifest) != bid or manifest.get('schema') != SCHEMA:
        raise ReviewBlocked('mirror_manifest_integrity_failed')
    return manifest


def _decisions(root):
    return read_rows(Path(root), guarded_path(Path(root), Path(root) / DECISIONS))


def binding_for(root, principal, request):
    """Exact decision the passkey signs: action + batch + manifest digest + counts."""
    verify_principal(root, principal)
    if not isinstance(request, dict) or set(request) - {'batch_id', 'command_id', 'action'}:
        raise ReviewBlocked('invalid_mirror_request')
    action = request.get('action', 'confirm_mirror_batch')
    if action not in ('confirm_mirror_batch', 'reject_mirror_batch'):
        raise ReviewBlocked('invalid_mirror_action')
    safe_id(request.get('command_id'))
    manifest = load_batch(root, request.get('batch_id'))
    return {'action': action, 'batch_id': request['batch_id'], 'manifest_digest': digest(manifest),
            'package_id': manifest['package_id'], 'stage_sha256': manifest['stage_sha256'],
            'promote_count': manifest['counts']['promote'], 'export_count': manifest['counts']['export'],
            'command_id': request['command_id']}


def review(root, principal, request, assertion):
    """Verify the fresh passkey assertion for the exact binding and record metadata only."""
    root = Path(root).resolve()
    actor = verify_principal(root, principal)
    with lock(guarded_path(root, root / 'state/locks/mirror-review.lock')):
        binding = binding_for(root, principal, request)
        prior = [r for r in _decisions(root) if r.get('binding', {}).get('command_id') == binding['command_id']]
        if prior:
            if prior[0].get('binding') != binding:
                raise ReviewBlocked('command_id_conflict')
            return {'status': prior[0]['status'], 'replayed': True, **prior[0]['owner_proof']}
        proof = verified_proof(root, binding, assertion=assertion, expected_actor=actor)
        status = 'confirmed' if binding['action'] == 'confirm_mirror_batch' else 'rejected'
        row = {'schema': SCHEMA, 'binding': binding, 'owner_proof': proof, 'status': status,
               'decided_at': now_iso()}
        path = guarded_path(root, root / DECISIONS)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a', encoding='utf-8') as f:
            f.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + '\n'); f.flush(); os.fsync(f.fileno())
        return {'status': status, 'batch_id': binding['batch_id'], **proof}


def list_batches(root, principal):
    verify_principal(root, principal)
    root = Path(root).resolve()
    base = guarded_path(root, root / BATCH_DIR)
    decided = {}
    for r in _decisions(root):
        decided[r.get('binding', {}).get('batch_id')] = r.get('status')
    out = []
    for p in sorted(base.glob('mirror_*.json')) if base.exists() else []:
        try:
            manifest = load_batch(root, p.stem)
        except (ReviewBlocked, ValueError, OSError):
            out.append({'batch_id': p.stem, 'status': 'integrity_failed'})
            continue
        out.append({'batch_id': p.stem, 'status': decided.get(p.stem, 'pending_owner_review'),
                    'manifest_digest': digest(manifest), 'manifest': manifest})
    return out


def list_policies(root, principal):
    verify_principal(root, principal)
    root = Path(root).resolve()
    base = guarded_path(root, root / POLICY_DIR)
    decided = {r.get('binding', {}).get('policy_id'): r.get('status') for r in _decisions(root)}
    out = []
    for p in sorted(base.glob('mpolicy_*.json')) if base.exists() else []:
        try:
            doc = load_policy(root, p.stem)
        except (ReviewBlocked, ValueError, OSError):
            out.append({'policy_id': p.stem, 'status': 'integrity_failed'}); continue
        out.append({'policy_id': p.stem, 'status': decided.get(p.stem, 'pending_owner_review'),
                    'policy_digest': digest(doc), 'document': doc,
                    'filters_current': doc.get('filters') == current_filters()})
    return out


def verified_batch(root, pkg):
    """Return (manifest, decision) only if a passkey-verified confirm covers this exact package stage."""
    root = Path(root).resolve()
    pkg, stage, stage_sha, _ = _stage(root, pkg)
    for row in reversed(_decisions(root)):
        b = row.get('binding') or {}
        if (row.get('status') != 'confirmed' or b.get('action') != 'confirm_mirror_batch'
                or b.get('package_id') != pkg.name or b.get('stage_sha256') != stage_sha):
            continue
        try:
            manifest = load_batch(root, b['batch_id'])
            if digest(manifest) != b['manifest_digest']:
                continue
            proof = verified_proof(root, b, proof_id=row['owner_proof']['proof_id'],
                                   expected_actor=row['owner_proof']['actor_id'])
        except (ReviewBlocked, KeyError, ValueError, OSError):
            continue
        if proof != row['owner_proof']:
            continue
        return manifest, row
    return None, None


# ---------------------------------------------------------------------------
# Standing mirror policy (optional): one passkey signature authorizes future
# routine packages named YYYYMMDD-grok-javis-bidir under the same filters.
# The policy pins the exact filter patterns; changing a filter invalidates it.
# Revocation only removes authority, so it needs no passkey.
# ---------------------------------------------------------------------------
PACKAGE_RE = re.compile(r'^\d{8}-grok-javis-bidir$')
REVOCATIONS = 'memory/review/mirror-policy-revocations.jsonl'


def current_filters():
    return {'secret': SECRET_RE.pattern, 'l4': L4_RE.pattern, 'friday_word': FRIDAY_WORD_RE.pattern,
            'friday_weekday': FRIDAY_WEEKDAY_RE.pattern, 'friday_roles': sorted(FRIDAY_ROLES),
            'conflict_rule': 'newer_as_of_wins;same_as_of_duplicate;older_or_unknown_reported_not_overwritten'}


def policy_document(approval_text, approved_at, source):
    return {'schema': POLICY_SCHEMA, 'policy': LOCK_TEXT, 'package_pattern': PACKAGE_RE.pattern,
            'filters': current_filters(), 'owner_statement': {'text': approval_text,
            'stated_at': approved_at, 'source': source},
            'note': 'Owner statement is context only; authority comes from the passkey signature.'}


def policy_id(doc):
    return 'mpolicy_' + digest(doc)[:32]


def prepare_policy(root, approval_text, approved_at, source):
    root = Path(root).resolve()
    doc = policy_document(approval_text, approved_at, source)
    pid = policy_id(doc)
    with lock(guarded_path(root, root / 'state/locks/mirror-review.lock')):
        _write_once(root, f'{POLICY_DIR}/{pid}.json', doc)
    return {'policy_id': pid, 'policy_digest': digest(doc), 'status': 'pending_owner_review'}


def load_policy(root, pid):
    safe_id(pid)
    doc = json.loads(guarded_path(root, Path(root) / POLICY_DIR / f'{pid}.json').read_text(encoding='utf-8'))
    if policy_id(doc) != pid or doc.get('schema') != POLICY_SCHEMA:
        raise ReviewBlocked('mirror_policy_integrity_failed')
    return doc


def policy_binding_for(root, principal, request):
    verify_principal(root, principal)
    if not isinstance(request, dict) or set(request) - {'policy_id', 'command_id'}:
        raise ReviewBlocked('invalid_mirror_policy_request')
    safe_id(request.get('command_id'))
    doc = load_policy(root, request.get('policy_id'))
    return {'action': 'confirm_mirror_policy', 'policy_id': request['policy_id'],
            'policy_digest': digest(doc), 'command_id': request['command_id']}


def review_mirror_policy(root, principal, request, assertion):
    root = Path(root).resolve()
    actor = verify_principal(root, principal)
    with lock(guarded_path(root, root / 'state/locks/mirror-review.lock')):
        binding = policy_binding_for(root, principal, request)
        prior = [r for r in _decisions(root) if r.get('binding', {}).get('command_id') == binding['command_id']]
        if prior:
            if prior[0].get('binding') != binding:
                raise ReviewBlocked('command_id_conflict')
            return {'status': prior[0]['status'], 'replayed': True, **prior[0]['owner_proof']}
        proof = verified_proof(root, binding, assertion=assertion, expected_actor=actor)
        row = {'schema': POLICY_SCHEMA, 'binding': binding, 'owner_proof': proof, 'status': 'confirmed',
               'decided_at': now_iso()}
        path = guarded_path(root, root / DECISIONS)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a', encoding='utf-8') as f:
            f.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + '\n'); f.flush(); os.fsync(f.fileno())
        return {'status': 'confirmed', 'policy_id': binding['policy_id'], **proof}


def revoke_policies(root, reason):
    root = Path(root).resolve()
    path = guarded_path(root, root / REVOCATIONS)
    path.parent.mkdir(parents=True, exist_ok=True)
    with lock(guarded_path(root, root / 'state/locks/mirror-review.lock')):
        with path.open('a', encoding='utf-8') as f:
            f.write(json.dumps({'revoked_at': now_iso(), 'reason': str(reason)[:200]}, ensure_ascii=False) + '\n')
            f.flush(); os.fsync(f.fileno())
    return {'status': 'revoked'}


def verified_policy(root):
    """Newest passkey-verified, unrevoked policy whose pinned filters equal the current code."""
    root = Path(root).resolve()
    revoked = [r.get('revoked_at', '') for r in read_rows(root, guarded_path(root, root / REVOCATIONS))]
    last_revoked = max(revoked) if revoked else ''
    for row in reversed(_decisions(root)):
        b = row.get('binding') or {}
        if row.get('status') != 'confirmed' or b.get('action') != 'confirm_mirror_policy':
            continue
        if last_revoked and row.get('decided_at', '') <= last_revoked:
            return None, None
        try:
            doc = load_policy(root, b['policy_id'])
            if digest(doc) != b['policy_digest'] or doc.get('filters') != current_filters():
                continue
            proof = verified_proof(root, b, proof_id=row['owner_proof']['proof_id'],
                                   expected_actor=row['owner_proof']['actor_id'])
        except (ReviewBlocked, KeyError, ValueError, OSError):
            continue
        if proof == row['owner_proof']:
            return doc, row
    return None, None


def authorization(root, pkg, *, persist=True):
    """Per-package signed batch first; else a standing policy for routine packages.

    Returns (manifest, auth) or (None, None). For the policy route the manifest is
    rebuilt now under the pinned filters and persisted write-once for audit.
    """
    root = Path(root).resolve()
    manifest, row = verified_batch(root, pkg)
    if manifest:
        return manifest, {'mode': 'owner_batch', 'actor_id': row['owner_proof']['actor_id'],
                          'batch_id': row['binding']['batch_id'],
                          'proof_id': row['owner_proof']['proof_id'],
                          'binding_hash': row['owner_proof']['binding_hash']}
    real = guarded_path(root, Path(pkg))
    if not PACKAGE_RE.fullmatch(real.name):
        return None, None
    doc, prow = verified_policy(root)
    if not doc:
        return None, None
    manifest = build_manifest(root, real)
    bid = batch_id(manifest)
    if persist:
        with lock(guarded_path(root, root / 'state/locks/mirror-review.lock')):
            _write_once(root, f'{BATCH_DIR}/{bid}.json', manifest)
    return manifest, {'mode': 'owner_policy', 'actor_id': prow['owner_proof']['actor_id'], 'batch_id': bid, 'policy_id': prow['binding']['policy_id'],
                      'proof_id': prow['owner_proof']['proof_id'],
                      'binding_hash': prow['owner_proof']['binding_hash']}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('command', choices=['prepare', 'status', 'preview', 'prepare-policy', 'revoke-policy'])
    ap.add_argument('--package')
    ap.add_argument('--statement', help='prepare-policy: owner statement text (context only)')
    ap.add_argument('--stated-at', help='prepare-policy: when the statement was made')
    ap.add_argument('--source', help='prepare-policy: where the statement was made')
    ap.add_argument('--reason', default='owner request', help='revoke-policy reason')
    ap.add_argument('--javis-root', default=None)
    args = ap.parse_args()
    root = Path(args.javis_root or os.environ.get('JAVIS_ROOT') or Path.home() / 'javis').expanduser().resolve()
    if args.command == 'prepare-policy':
        if not (args.statement and args.stated_at and args.source):
            raise ValueError('statement_stated_at_source_required')
        print(json.dumps(prepare_policy(root, args.statement, args.stated_at, args.source), ensure_ascii=False, indent=2))
        return 0
    if args.command == 'revoke-policy':
        print(json.dumps(revoke_policies(root, args.reason), ensure_ascii=False)); return 0
    if not args.package:
        raise ValueError('package_required')
    pkg = Path(args.package).expanduser().resolve()
    if args.command == 'preview':
        m = build_manifest(root, pkg)
        out = {'batch_id': batch_id(m), **m['counts'], 'conflicts': m['excluded']['conflicts'],
               'friday_bot': m['excluded']['friday_bot']}
    elif args.command == 'prepare':
        out = prepare(root, pkg)
    else:
        manifest, auth = authorization(root, pkg, persist=False)
        out = ({'status': 'owner_authorized', **auth, **manifest['counts']} if manifest
               else {'status': 'pending_owner_review'})
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(json.dumps({'ok': False, 'status': 'blocked', 'reason': str(exc)[:200],
                          'error_type': type(exc).__name__}, ensure_ascii=False))
        raise SystemExit(2)
