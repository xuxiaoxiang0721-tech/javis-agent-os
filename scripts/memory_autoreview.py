"""Source-bound AI memory decisions. Memory-only authority, no owner impersonation.

The append-only decision log is authoritative. RAW and human confirmations are
never edited; projections can be rebuilt after a crash and withdrawals are new
events. This service does not call models or grant permission for external work.
"""
from __future__ import annotations
import copy
import hashlib
import json
import sys
from contextlib import contextmanager
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE / 'tools/memory-adapter'), str(CODE / 'scripts/orchestration')]
from javis_memory_adapter.review_policy import ReviewBlocked, digest, guarded_path, read_rows, safe_id, semantic, source_digests, source_rows
from javis_memory_adapter.structured_store import StructuredFact
from memory_review import MemoryReview
from raw_policy import redact
from runtime_io import atomic_json, lock

SCHEMA = 'javis.ai-memory-review.v1'
POLICY = {'schema': 'javis.memory-autoreview.policy.v1', 'policy_version': 'ai-review-v1',
          'mode': 'automatic', 'scope': 'memory_only',
          'permitted_actions': ['accept', 'archive', 'needs_information', 'revoke'],
          'reviewer_type': 'ai', 'human_confirmed': False,
          'source_bound': True, 'retain_raw': True, 'external_action_authority': False,
          'unknown_time': 'preserve_unknown', 'existing_owner_memory': 'preserve',
          'authorization': 'User explicitly chose complete removal of routine memory signatures on 2026-09-30.'}
POLICY_DIGEST = digest(POLICY)
LOG = 'memory/ai-review/decisions.jsonl'

def now():
    return datetime.now(timezone.utc).isoformat()

class MemoryAutoreview:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.review = MemoryReview(self.root)

    def _path(self, rel):
        return guarded_path(self.root, self.root / rel)

    def _rows(self):
        return read_rows(self.root, self._path(LOG))

    def _state(self):
        from memory_controls import status
        controls = status(self.root)
        return {'enabled': controls['global_enabled'], 'revision': controls['revision'],
                'mode': 'automatic', 'policy_digest': POLICY_DIGEST,
                'updated_at': controls['updated_at'], 'roles': controls['roles']}

    def _enabled(self, scope):
        from memory_controls import require_processing, MemoryProcessingHeld
        try:
            require_processing(self.root, scope, 'local_accept')
        except MemoryProcessingHeld as exc:
            raise ReviewBlocked('autoreview_paused' if exc.code == 'global_paused' else exc.code) from None
        policy = self._path('memory/ai-review/policies/' + POLICY_DIGEST + '.json')
        if policy.exists() and json.loads(policy.read_text()) != POLICY:
            raise ReviewBlocked('autoreview_policy_integrity_failed')
        if not policy.exists():
            from memory_controls import _write
            _write(self.root, str(policy.relative_to(self.root)), POLICY)

    @contextmanager
    def _lock(self):
        with lock(self._path('state/maintenance.lock'), shared=True):
            from task_service import ensure_not_held
            ensure_not_held(self.root)
            with lock(self._path('state/locks/memory-autoreview.lock')):
                yield

    def control(self, action, expected_revision, command_id):
        safe_id(command_id)
        if action not in ('pause', 'resume'):
            raise ReviewBlocked('invalid_autoreview_control')
        from memory_controls import update
        result = update(self.root, expected_revision, global_enabled=action == 'resume', command_id=command_id)
        return {'enabled': result['global_enabled'], 'revision': result['revision'],
                'mode': 'automatic', 'policy_digest': POLICY_DIGEST,
                'updated_at': result['updated_at']}

    def _source(self, event_id, scope, excerpt, content_digest=None):
        found = source_rows(self.root, [event_id]).get(event_id)
        if found is None or found.get('agent') != scope:
            raise ReviewBlocked('source_scope_mismatch')
        from task_memory import _explicit_l4, _safe
        from memory_screen import _cloud_excluded
        if _explicit_l4(found) or _cloud_excluded(found) or not _safe(found):
            raise ReviewBlocked('source_privacy_excluded')
        payload = found.get('payload') or {}
        texts = ([payload['text']] if isinstance(payload.get('text'), str) else [])
        texts += [m['text'] for m in payload.get('messages', []) if isinstance(m, dict) and isinstance(m.get('text'), str)]
        if not isinstance(excerpt, str) or not excerpt.strip():
            raise ReviewBlocked('source_excerpt_required')
        matches = [t for t in texts if excerpt in t and (not content_digest or hashlib.sha256(t.encode()).hexdigest() == content_digest)]
        if not matches:
            raise ReviewBlocked('source_excerpt_not_bound')
        _, changes = redact(excerpt)
        if changes or '[REDACTED:' in excerpt:
            raise ReviewBlocked('sensitive_memory_excluded')
        # Includes canonical-source verification for corpus_text.
        hashes = source_digests(self.root, [event_id])
        return hashes, hashlib.sha256(matches[0].encode()).hexdigest()

    def _base(self, action, scope, item_id, version, reason, excerpt, event_id,
              run_id='', content_digest=None):
        safe_id(scope); safe_id(item_id)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 4000:
            raise ReviewBlocked('review_reason_required')
        hashes, content_hash = self._source(event_id, scope, excerpt, content_digest)
        return {'schema': SCHEMA, 'action': action, 'scope': scope,
                'candidate_id': item_id, 'version_digest': version, 'run_id': run_id or 'local-ai-review',
                'policy_version': POLICY['policy_version'], 'policy_digest': POLICY_DIGEST,
                'source_digests': hashes, 'source_event_id': event_id,
                'content_digest': content_hash, 'source_excerpt': excerpt,
                'reason': reason, 'reviewer_type': 'ai', 'human_confirmed': False}

    def _commit(self, row):
        row = copy.deepcopy(row)
        rid = 'ai-review-' + digest(row)[:40]
        previous = next((r for r in self._rows() if r.get('review_event_id') == rid), None)
        if previous:
            return previous
        if row['action'] != 'revoke':
            for old in self.active():
                if (old.get('candidate_id') == row.get('candidate_id') and old.get('scope') == row.get('scope')
                        and old.get('version_digest') == row.get('version_digest')):
                    raise ReviewBlocked('item_already_reviewed')
        row.update(review_event_id=rid, decided_at=now())
        self.review._append(LOG, row)
        return row

    def _materialize(self, row):
        if row['action'] != 'accept':
            return
        fact = StructuredFact.from_dict({**row['effect'], 'ai_review_event_id': row['review_event_id'],
                                        'confirmation_event_id': None, 'graph_sync_status': 'pending_sync'})
        store = self.review._store(row['scope'])
        current = store.get_fact(fact.fact_id)
        if current is not None and (semantic(current) != semantic(fact) or current.ai_review_event_id != fact.ai_review_event_id):
            raise ReviewBlocked('existing_fact_conflict')
        if current is not None:
            from javis_memory_adapter.review_policy import ai_reviewed
            if not ai_reviewed(store, current):
                raise ReviewBlocked('ai_review_integrity_failed')
            return
        store.upsert_fact(fact)

    def review_candidate(self, scope, candidate_id, version_digest, reason, source_excerpt,
                         run_id='', replacement=None, content_digest=None):
        with self._lock(), self.review._lock():
            self._enabled(scope)
            candidate = self.review._current(scope, candidate_id)
            if candidate['version_digest'] != version_digest:
                raise ReviewBlocked('stale_candidate_version')
            # Replays return the original decision; revocation never creates a new acceptance.
            prior = next((r for r in self._rows() if r.get('action') == 'accept' and
                          r.get('candidate_id') == candidate_id and r.get('version_digest') == version_digest), None)
            if prior:
                if source_digests(self.root, prior['source_digests']) != prior['source_digests']:
                    raise ReviewBlocked('review_source_changed')
                if any(r.get('action') == 'revoke' and r.get('target_review_event_id') == prior['review_event_id'] for r in self._rows()):
                    return {**prior, 'withdrawn': True}
                self._materialize(prior)
                return prior
            if any(r.get('candidate_id') == candidate_id and r.get('action') == 'archive' for r in self.active()):
                raise ReviewBlocked('candidate_archived')
            if candidate['status'] != 'pending_review' or candidate['payload']['operation'] != 'append':
                raise ReviewBlocked('candidate_not_appendable')
            fact = copy.deepcopy(candidate['payload']['effects'][-1])
            if replacement is not None:
                allowed = {'subject_id', 'subject_label', 'predicate', 'value', 'unit', 'valid_from', 'valid_to'}
                if not isinstance(replacement, dict) or set(replacement) - allowed:
                    raise ReviewBlocked('invalid_ai_replacement')
                fact.update(replacement)
            fact['fact_id'] = 'fact_ai_' + digest({'scope': scope, 'candidate': candidate_id, 'fact': fact})[:32]
            validated = self.review._build_payload(scope, fact)
            if validated['source_digests'] != candidate['payload']['source_digests']:
                raise ReviewBlocked('review_source_changed')
            effect = validated['effects'][0]
            from javis_memory_adapter.entity_registry import validate_entity_dependencies
            validate_entity_dependencies(self.root, scope, effect)
            effect['status'] = 'ai_reviewed'
            row = self._base('accept', scope, candidate_id, version_digest, reason, source_excerpt,
                             effect['source_event_id'], run_id, content_digest)
            row.update(effect=effect, effect_digest=digest(effect), source_digests=validated['source_digests'])
            row = self._commit(row)
            self._materialize(row)
            # Queue resolution is derived from the audit log; original candidate stays intact.
            return row

    def review_item(self, *, kind, item_id, scope, version_digest, event_id, action,
                    reason, source_excerpt, run_id='', content_digest=None, value=None):
        """Apply a source-checked local AI audit to one candidate or triage item."""
        if action not in ('archive', 'accept', 'needs_information') or kind not in ('candidate', 'triage'):
            raise ReviewBlocked('invalid_ai_action')
        if kind == 'candidate' and action == 'accept':
            return self.review_candidate(scope, item_id, version_digest, reason, source_excerpt, run_id,
                    replacement={'subject_id': 'source:' + event_id, 'subject_label': '原文记录',
                                 'predicate': 'source_attributed_memory', 'value': value, 'unit': None,
                                 'valid_from': None, 'valid_to': None}, content_digest=content_digest)
        with self._lock(), self.review._lock():
            self._enabled(scope)
            if kind == 'candidate':
                candidate = self.review._current(scope, item_id)
                if candidate['version_digest'] != version_digest or candidate['status'] != 'pending_review':
                    raise ReviewBlocked('stale_candidate_version')
                expected = candidate['payload']['source_digests']
                if candidate['payload']['effects'][-1]['source_event_id'] != event_id:
                    raise ReviewBlocked('candidate_source_mismatch')
                if source_digests(self.root, expected) != expected:
                    raise ReviewBlocked('review_source_changed')
            else:
                from memory_triage import _read
                item = _read(self.root, self._path('memory/triage/items/' + item_id + '.json'))
                b = item['binding']
                if (item['record_digest'] != version_digest or b['event_id'] != event_id or b['scope'] != scope
                        or (content_digest and b['content_digest'] != content_digest) or b['run_id'] != run_id):
                    raise ReviewBlocked('stale_triage_version')
                if source_digests(self.root, [event_id])[event_id] != b['source_digest']:
                    raise ReviewBlocked('review_source_changed')
            row = self._base(action, scope, item_id, version_digest, reason, source_excerpt,
                             event_id, run_id, content_digest)
            row['item_kind'] = kind
            if action == 'accept':
                fact = {'fact_id': 'fact_ai_' + digest({'item': item_id, 'value': value})[:32],
                        'subject_id': 'source:' + event_id, 'subject_label': '原文记录',
                        'predicate': 'source_attributed_memory', 'value': value, 'unit': None,
                        'valid_from': None, 'valid_to': None, 'recorded_at': item['created_at'],
                        'source_event_id': event_id, 'raw_refs': [event_id], 'notes': ['source_claim_not_independently_verified']}
                effect = self.review._build_payload(scope, fact)['effects'][0]
                effect['status'] = 'ai_reviewed'
                row.update(effect=effect, effect_digest=digest(effect))
            row = self._commit(row)
            self._materialize(row)
            return row

    def withdraw(self, decision_id, expected_version, command_id, reason='用户撤回 AI 整理结果'):
        safe_id(command_id)
        with self._lock():
            rows = self._rows()
            target = next((r for r in rows if r.get('review_event_id') == decision_id and r.get('action') != 'revoke'), None)
            if target is None or digest(target) != expected_version:
                raise ReviewBlocked('stale_ai_decision')
            prior = next((r for r in rows if r.get('action') == 'revoke' and r.get('target_review_event_id') == decision_id), None)
            if prior:
                return prior
            return self._commit({'schema': SCHEMA, 'action': 'revoke', 'scope': target['scope'],
                                'target_review_event_id': decision_id, 'command_id': command_id,
                                'policy_version': POLICY['policy_version'], 'policy_digest': POLICY_DIGEST,
                                'reason': reason, 'reviewer_type': 'ai', 'human_confirmed': False})

    def active(self):
        rows = self._rows()
        revoked = {r.get('target_review_event_id') for r in rows if r.get('schema') == SCHEMA and r.get('action') == 'revoke'}
        return [r for r in rows if r.get('schema') == SCHEMA and r.get('action') != 'revoke' and r['review_event_id'] not in revoked]

    def resolved(self):
        """Queue projection only; formal recall independently validates every AI fact."""
        active = [r for r in self.active() if r['action'] in ('accept', 'archive')]
        if not active:
            return {}
        # Validate the set in one RAW scan; do not conceal queue entries if evidence changes.
        expected = {}
        for r in active:
            expected.update(r.get('source_digests', {}))
        try:
            actual = source_digests(self.root, expected)
        except (ValueError, OSError):
            return {}
        output = {}
        from javis_memory_adapter.review_policy import usable_facts
        valid_ids = {}
        for scope in {r['scope'] for r in active if r['action'] == 'accept'}:
            store = self.review._store(scope)
            valid_ids[scope] = {f.fact_id for f in usable_facts(store)}
        for r in active:
            if (r.get('policy_digest') != POLICY_DIGEST or r.get('policy_version') != POLICY['policy_version']
                    or not r.get('source_digests') or any(actual.get(k) != v for k, v in r['source_digests'].items())):
                continue
            try:
                if r['candidate_id'].startswith('triage_'):
                    from memory_triage import _read
                    item = _read(self.root, self._path('memory/triage/items/' + r['candidate_id'] + '.json'))
                    if item['record_digest'] != r['version_digest']:
                        continue
                else:
                    candidate = self.review._current(r['scope'], r['candidate_id'])
                    if candidate['version_digest'] != r['version_digest'] or candidate['status'] != 'pending_review':
                        continue
                if r['action'] == 'accept':
                    if r['effect']['fact_id'] not in valid_ids[r['scope']]:
                        continue
                output[r['candidate_id']] = r
            except (ValueError, OSError, KeyError, TypeError):
                continue
        return output

    def status(self):
        rows = self._rows()
        revoked = {r.get('target_review_event_id') for r in rows if r.get('action') == 'revoke'}
        counts = Counter(r['action'] for r in rows if r.get('review_event_id') not in revoked)
        from memory_interactions import status as supplement_status
        closed = supplement_status(self.root)['closed_targets']
        closed_count = sum(r.get('action') == 'needs_information' and r.get('candidate_id') in closed
                           and r.get('review_event_id') not in revoked for r in rows)
        recent = []
        for r in reversed(rows):
            if r.get('action') == 'revoke':
                continue
            withdrawn = r['review_event_id'] in revoked
            recent.append({'decision_id': r['review_event_id'], 'expected_version': digest(r),
                           'kind': r['action'], 'status': 'withdrawn' if withdrawn else 'supplement_accepted' if r['action']=='needs_information' and r.get('candidate_id') in closed else r['action'],
                           'scope': r['scope'], 'fact': r.get('effect', {}).get('value'),
                           'source_event_id': r.get('source_event_id'), 'source_excerpt': r.get('source_excerpt'),
                            'candidate_id': r.get('candidate_id'), 'version_digest': r.get('version_digest'),
                            'question_zh': (r.get('question_zh') or r.get('question') or
                                ((r.get('reason') or '') + '；请补充完整主体、事实及时间（不知道可写未知）')) if r['action'] == 'needs_information' else None,
                           'reason': r.get('reason'), 'decided_at': r['decided_at'], 'withdrawable': not withdrawn,
                           'review_origin': 'ai', 'human_confirmed': False})
        return {**self._state(), 'policy_version': POLICY['policy_version'],
                'counts': {'accepted': counts['accept'], 'archived': counts['archive'],
                           'needs_user': counts['needs_information'] - closed_count, 'supplement_accepted': closed_count, 'withdrawn': len(revoked)},
                'recent': recent, 'external_action_authority': False}
