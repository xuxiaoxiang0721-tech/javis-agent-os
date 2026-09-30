"""Shared append-only RAW events and content-addressed file snapshots."""
from __future__ import annotations
import hashlib
import json
import os
import tempfile
import sys
import uuid
import stat
import re
from datetime import datetime, timezone
from pathlib import Path
from raw_policy import redact, sanitize, safe_file_bytes, CredentialFileBlocked, is_vault_path, is_vault_bytes
from runtime_io import lock
from raw_time import normalize_time_fields, native_time

FIELDS = ('task_id', 'session_id', 'turn_id', 'source_event_id', 'parent_event_id',
          'entry', 'agent', 'model', 'execution_path', 'risk', 'approval_ref', 'supersedes', 'contradicts')
ORIGINAL_SCHEMA = 'javis.raw-original.aesgcm.v1'
_KEY_RELATIVE = 'state/.auth-raw-originals/key'


def _guard(root, path):
    root, path = Path(root).resolve(), Path(path)
    if not path.is_absolute() or not path.is_relative_to(root):
        raise ValueError('raw_path_outside_root')
    for part in (path, *path.parents):
        if part == root: break
        if part.is_symlink(): raise ValueError('linked_raw_path')
        if part.exists() and part.is_file() and part.stat().st_nlink != 1:
            raise ValueError('hardlinked_raw_file')
    return path


def _read_regular(path):
    """Read through a no-follow descriptor, including when a caller pins bytes."""
    path = Path(path)
    for part in (path, *path.parents):
        if part.is_symlink(): raise ValueError('linked_raw_input')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1: raise ValueError('raw_input_not_regular')
        data = stream.read()
        end = os.fstat(stream.fileno())
        if (st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (end.st_size, end.st_mtime_ns, end.st_ctime_ns):
            raise ValueError('raw_input_changed')
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns,current.st_ctime_ns,current.st_nlink)!=(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns,end.st_nlink):
            raise ValueError('raw_input_replaced')
        return data


def _fsync_directory(path):
    if os.name != 'nt':
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)


def _write_object(root, path, data):
    path = _guard(root, path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _guard(root, path)
    if path.exists():
        if _read_regular(path) != data: raise ValueError('existing_RAW_object_hash_mismatch')
        return
    fd, temporary = tempfile.mkstemp(prefix='.object-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); _fsync_directory(path.parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def _private_key(root, *, create=False):
    path = _guard(root, root / _KEY_RELATIVE)
    if not path.exists() and not create: raise ValueError('original_key_missing_restore_dependency')
    if not path.exists() and create and any((root/'raw/private-originals').glob('*.aesgcm')):
        raise ValueError('original_key_missing_restore_dependency')
    if create:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _guard(root, path)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        except FileExistsError: pass
        else:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(os.urandom(32)); stream.flush(); os.fsync(stream.fileno())
            _fsync_directory(path.parent)
    if os.name != 'nt' and ((path.parent.stat().st_mode & 0o077) or (path.stat().st_mode & 0o077)):
        raise ValueError('original_key_permissions_unsafe')
    value = _read_regular(path)
    if len(value) != 32: raise ValueError('original_key_invalid')
    return value


def _seal_original(root, data):
    """AEAD ciphertext only; the local key is deliberately outside backups."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    root = Path(root).resolve(); digest = hashlib.sha256(data).hexdigest()
    path = _guard(root, root / 'raw/private-originals' / (digest + '.aesgcm'))
    key = _private_key(root, create=True); aad = (ORIGINAL_SCHEMA + '|' + digest).encode()
    if path.exists():
        blob = _read_regular(path)
        try: old = AESGCM(key).decrypt(blob[:12], blob[12:], aad)
        except Exception as exc: raise ValueError('original_decryption_failed') from exc
        if old != data: raise ValueError('original_hash_mismatch')
    else:
        nonce = os.urandom(12); blob = nonce + AESGCM(key).encrypt(nonce, data, aad)
        _write_object(root, path, blob)
    return {'schema': ORIGINAL_SCHEMA, 'sha256': digest, 'size': len(data),
            'storage': 'local_encrypted', 'path': path.relative_to(root).as_posix(),
            'ciphertext_sha256': hashlib.sha256(blob).hexdigest(), 'available': True,
            'cloud_eligible': False, 'fidelity': 'exact_original_bytes',
            'restore_dependency': 'separately_recover_local_original_key'}


def read_preserved_original(root, reference, *, allow_sensitive=False):
    """Internal local capability. Ordinary HTTP/model callers must keep False."""
    root = Path(root).resolve()
    if not isinstance(reference, dict) or not re.fullmatch(r'[a-f0-9]{64}', str(reference.get('sha256', ''))):
        raise ValueError('invalid_original_reference')
    digest = reference['sha256']
    if reference.get('storage') == 'local_encrypted':
        if not allow_sensitive: raise ValueError('sensitive_original_local_access_required')
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        expected = 'raw/private-originals/' + digest + '.aesgcm'
        if reference.get('schema') != ORIGINAL_SCHEMA or reference.get('path') != expected:
            raise ValueError('invalid_original_reference')
        blob = _read_regular(_guard(root, root / expected))
        if hashlib.sha256(blob).hexdigest() != reference.get('ciphertext_sha256'):
            raise ValueError('original_ciphertext_hash_mismatch')
        try: data = AESGCM(_private_key(root)).decrypt(blob[:12], blob[12:], (ORIGINAL_SCHEMA + '|' + digest).encode())
        except ValueError: raise
        except Exception as exc: raise ValueError('original_decryption_failed') from exc
    elif reference.get('storage') == 'raw_object':
        data = _read_regular(_guard(root, root / 'raw/objects' / digest))
    else: raise ValueError('original_unavailable')
    if len(data) != reference.get('size') or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('original_hash_mismatch')
    return data


def _local_sensitive(value):
    if isinstance(value, dict):
        if value.get('cloud_eligible') is False or value.get('privacy') == 'local_only': return True
        if any(str(value.get(k, '')).strip().upper() == 'L4' for k in ('risk', 'risk_level', 'sensitivity','privacy_level','classification','data_classification')): return True
        return any(_local_sensitive(v) for k, v in value.items() if k not in {'original', 'raw_preservation'})
    if isinstance(value, list): return any(_local_sensitive(v) for v in value)
    return isinstance(value,str) and re.match(r'^\s*(?:\[L4\]|L4\s*[:：]|(?:隐私等级|数据等级)\s*[:：]?\s*L4)',value,re.I) is not None


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def stable_id(*parts):
    return 'ev-codex-' + hashlib.sha256('|'.join(map(str, parts)).encode()).hexdigest()[:20]


def normalize_event(event):
    safe, changes = redact(dict(event))
    safe.setdefault('schema_version', 'javis-raw-event-1')
    safe.setdefault('event_id', str(uuid.uuid4()))
    safe.setdefault('timezone', 'UTC')
    safe.setdefault('payload', {})
    safe.setdefault('evidence_refs', [])
    safe.setdefault('completeness', 'partial')
    safe.setdefault('missing_reason', None)
    for field in FIELDS: safe.setdefault(field, None)
    payload = safe.get('payload') or {}
    if isinstance(payload, dict):
        safe['model'] = safe['model'] or payload.get('model')
        safe['execution_path'] = safe['execution_path'] or payload.get('call_path')
        native = payload.get('event')
        if isinstance(native, dict) and payload.get('record_source') == 'codex_json_stream':
            kind = native.get('type') or 'unknown'
            payload.setdefault('stream_mode', 'final' if kind.endswith('.completed') else 'delta' if 'delta' in kind else 'lifecycle')
            payload.setdefault('native_item_id', (native.get('item') or {}).get('id'))
            safe['source_event_id'] = safe['source_event_id'] or native.get('event_id') or native.get('id')
            safe['turn_id'] = safe['turn_id'] or native.get('turn_id')
            safe['model'] = safe['model'] or native.get('model')
            if not safe.get('occurred_at'):
                occurred, basis, field = native_time(native)
                if field is None and safe.get('time_basis') == 'local_received': basis = 'local_received'
                safe.update(occurred_at=occurred, time_basis=basis)
                if field is not None: safe['source_time_field'] = 'payload.event.' + field
    reasons = [safe['missing_reason']] if safe['missing_reason'] else []
    reasons.extend(normalize_time_fields(safe, observed_at=now_iso()))
    if not safe.get('occurred_at'):
        safe['occurred_at'] = None
        reasons.append('original_event_timestamp_unavailable')
        safe['completeness'] = 'partial'
    if changes:
        safe['redactions'] = list(safe.get('redactions') or []) + changes
        reasons.append('explicit_credentials_removed_before_persistence')
        safe['completeness'] = 'partial'
    safe['missing_reason'] = ';'.join(dict.fromkeys(reasons)) or None
    return safe


def _read_rows(paths):
    for path in paths:
        for line in path.read_text(encoding='utf-8', errors='replace').split('\n'):
            if not line.strip(): continue
            try: row = json.loads(line)
            except json.JSONDecodeError: continue
            if isinstance(row, dict): yield row


def _append_line(path, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    separator = False
    recovery = None
    if path.exists() and path.stat().st_size:
        with path.open('rb') as old:
            size = old.seek(0, os.SEEK_END)
            old.seek(size - 1)
            separator = old.read(1) not in (b'\n', b'\r')
            if separator:
                start = max(0, size - 65536); old.seek(start); tail = old.read()
                while start and b'\n' not in tail:
                    earlier = max(0, start - 65536); old.seek(earlier)
                    tail = old.read(start - earlier) + tail; start = earlier
                fragment = tail.rsplit(b'\n', 1)[-1]
                try:
                    complete = isinstance(json.loads(fragment), dict)
                except (ValueError, UnicodeError): complete = False
                if not complete:
                    recovery = {'reason': 'previous_JSONL_record_incomplete',
                                'path': str(path), 'byte_start': size - len(fragment),
                                'byte_end': size, 'original_bytes_preserved': True}
                    row['append_recovery'] = recovery
                    if 'event_type' in row:
                        row['completeness'] = 'partial'
                        row['missing_reason'] = ';'.join(filter(None, [row.get('missing_reason'), recovery['reason']]))
    with path.open('a', encoding='utf-8') as f:
        # Only append a separator: never edit or truncate the original fragment.
        if separator: f.write('\n')
        f.write(json.dumps(row, ensure_ascii=False) + '\n')
        f.flush(); os.fsync(f.fileno())
    if recovery:
        print('RAW recording gap: previous incomplete JSONL record preserved; appended at a new line', file=sys.stderr)
    return recovery


def append_event(root, event, existing=None, *, relative_path=None, original_event=None):
    root = Path(root).resolve()
    submitted = dict(event)
    if original_event is not None and not isinstance(original_event,dict):raise ValueError('original_event_must_be_mapping')
    unfiltered = dict(original_event) if original_event is not None else submitted
    sensitive = _local_sensitive(submitted) or _local_sensitive(unfiltered)
    _, filtered = redact(unfiltered)
    event = normalize_event(submitted)
    if not event.get('event_type'): raise ValueError('event_type required')
    raw = (root / 'raw').resolve()
    out = raw / (relative_path or 'events/' + datetime.now(timezone.utc).strftime('%Y%m%d') + '.jsonl')
    if not out.resolve().is_relative_to(raw) or out.suffix != '.jsonl': raise ValueError('RAW path must be JSONL within raw directory')
    out = _guard(root, out)
    with lock(_guard(root, root / 'state/locks/raw-append.lock')):
        for row in _read_rows([_guard(root, p) for p in raw.rglob('*.jsonl')]):
            if row.get('event_id') == event['event_id']: return None
        if filtered or sensitive:
            original = json.dumps(unfiltered, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
            with lock(_guard(root, root / 'state/locks/raw-private-original.lock')):
                reference = _seal_original(root, original)
            event['raw_preservation'] = {'version': 1, 'original': reference,
                'serialization': 'canonical_submitted_event_json_not_transport_bytes',
                'content_form': 'local_only_metadata' if sensitive else 'credential_redacted_copy',
                'capture_scope': 'new_intake_only_no_historical_reconstruction'}
            if sensitive:
                # Keep routing/clock metadata, never expose private body in the
                # general RAW corpus scanned by model-side source adapters.
                metadata = set(FIELDS) | {'schema_version','event_id','event_type','timezone','completeness','missing_reason',
                    'occurred_at','received_at','captured_at','ingested_at','time_basis','source_time_field','redactions','raw_preservation'}
                event = {key:value for key,value in event.items() if key in metadata}
                for key in ('capture_fingerprint','capture_original_fingerprint'):
                    value=submitted.get(key)
                    if isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value):event[key]=value
                event['payload'] = {'content_form': 'local_only_original', 'text_available': False}
                event['cloud_eligible'] = False
                event['evidence_refs'] = []
                event['missing_reason'] = ';'.join(filter(None, [event.get('missing_reason'), 'original_requires_controlled_local_access']))
                event['completeness'] = 'partial'
        recovery = _append_line(out, event)
        if recovery:
            gap = normalize_event({'event_id': stable_id('raw-tail-gap', str(out), recovery['byte_end']),
                'task_id': event.get('task_id'), 'event_type': 'status', 'entry': 'raw_append_recovery',
                'parent_event_id': event['event_id'], 'occurred_at': now_iso(), 'completeness': 'partial',
                'missing_reason': recovery['reason'], 'payload': {'kind': 'recording_gap', **recovery}})
            _append_line(out, gap)
    if existing is not None: existing.add(event['event_id'])
    return event['event_id']


def _snapshot_event(root, row):
    append_event(root, {'event_id': stable_id(row['snapshot_id']), 'task_id': row['task_id'], 'event_type': 'file_snapshot',
                       'entry': 'javis_snapshot', 'occurred_at': row['captured_at'], 'captured_at': row['captured_at'],
                       'completeness': 'partial' if row['redactions'] else 'complete',
                       'missing_reason': 'explicit_credentials_removed_before_persistence' if row['redactions'] else None,
                       'payload': row, 'evidence_refs': [{'sha256': row['sha256'], 'snapshot_id': row['snapshot_id'], 'artifact_id': row['artifact_id']}],
                       'supersedes': row.get('previous_snapshot_id')})
    if row.get('append_recovery'):
        append_event(root, {'event_id': stable_id('manifest-tail-gap', row['snapshot_id']),
            'task_id': row['task_id'], 'event_type': 'status', 'occurred_at': row['captured_at'],
            'entry': 'raw_append_recovery', 'completeness': 'partial',
            'missing_reason': row['append_recovery']['reason'],
            'payload': {'kind': 'recording_gap', **row['append_recovery']}})


def snapshot_file(root, source, task_id, label=None, *, source_path=None, artifact_id=None,
                  relation='artifact', capture_key=None, windows_path=None, linux_path=None, captured_bytes=None,
                  sensitivity=None, source_locator=None, derived_from=None):
    """Persist safe object then append a versioned manifest; shared runner interface.

    capture_key identifies an individual capture operation for replay idempotency.
    Different event references are kept even for identical object contents.
    """
    root, source = Path(root).resolve(), Path(source)
    if sensitivity not in (None,'L4','local_only'):raise ValueError('invalid_capture_sensitivity')
    for component in (source,*source.parents):
        if component.is_symlink():raise ValueError('linked_raw_input')
    if source.exists() and source.is_file() and source.stat().st_nlink!=1:raise ValueError('raw_input_not_regular')
    origin = str(source_path or source.resolve())
    artifact_id = artifact_id or 'artifact-' + hashlib.sha256((task_id + '|' + origin).encode()).hexdigest()[:24]
    if captured_bytes is not None and not isinstance(captured_bytes, bytes): raise TypeError('captured_bytes must be bytes')
    try:
        # Dedicated credential stores stay under their own lifecycle; preserving
        # an ordinary sensitive attachment never imports a vault or key file.
        if is_vault_path(source) or source.name.lower() in ('auth.json', 'credentials.json', 'id_rsa', 'id_ed25519', '.env') or source.suffix.lower() in ('.p12', '.pfx', '.key'):
            raise CredentialFileBlocked('dedicated_credential_store_excluded')
        original = captured_bytes if captured_bytes is not None else _read_regular(source)
        if is_vault_bytes(original):raise CredentialFileBlocked('dedicated_credential_store_excluded')
        try: data, redactions, scope = safe_file_bytes(source,captured_bytes=original)
        except CredentialFileBlocked as exc:
            if str(exc) != 'explicit_credential_in_binary_file': raise
            data = b'[LOCAL_ONLY_BINARY_ORIGINAL]\n'; redactions = [{'category': 'explicit_credential_in_binary_file', 'count': 1}]
            scope = 'opaque_sensitive_original_local_only'
    except CredentialFileBlocked:
        append_event(root, {'event_id': stable_id('excluded-original',task_id,origin,str(capture_key)),
            'event_type': 'status', 'task_id': task_id, 'entry': 'raw_preservation',
            'payload': {'kind':'recording_gap', 'reason':'dedicated_credential_store_not_captured'},
            'completeness':'partial', 'missing_reason':'dedicated_credential_store_not_captured'})
        raise
    private = bool(redactions) or sensitivity in ('L4', 'local_only')
    if sensitivity in ('L4', 'local_only'):
        data = b'[LOCAL_ONLY_ORIGINAL]\n'
    if source_locator is not None:
        allowed = {'event_id','source_event_id','line_number','byte_start','byte_end','page','selector'}
        if not isinstance(source_locator,dict) or set(source_locator)-allowed: raise ValueError('invalid_source_locator')
        for field in ('line_number','byte_start','byte_end','page'):
            if field in source_locator and (type(source_locator[field]) is not int or source_locator[field]<0):raise ValueError('invalid_source_locator')
        if all(k in source_locator for k in ('byte_start','byte_end')) and source_locator['byte_end']<source_locator['byte_start']:raise ValueError('invalid_source_locator')
    if derived_from is not None and (not isinstance(derived_from,dict) or set(derived_from)-{'snapshot_id','sha256','method','page','byte_start','byte_end'}):
        raise ValueError('invalid_derived_reference')
    digest = hashlib.sha256(data).hexdigest()
    obj = root / 'raw/objects' / digest
    with lock(_guard(root, root / 'state/locks/raw-object.lock')):
        _write_object(root, obj, data)
        if private:
            with lock(_guard(root, root / 'state/locks/raw-private-original.lock')):
                original_ref = _seal_original(root, original)
        else:
            original_ref = {'sha256':digest,'size':len(original),'storage':'raw_object','available':True,
                            'fidelity':'exact_original_bytes'}
        if derived_from:original_ref['fidelity']='exact_captured_derived_bytes_not_source_document'
        rows = list(_read_rows([_guard(root,p) for p in sorted((root / 'raw/manifests').glob('objects-*.jsonl'))]))
        versions = [r for r in rows if r.get('artifact_id') == artifact_id]
        key = str(capture_key) if capture_key is not None else uuid.uuid4().hex
        for row in versions:
            if row.get('capture_key') == key and row.get('sha256') == digest and row.get('original',{}).get('sha256',row.get('sha256')) == original_ref['sha256']:
                _snapshot_event(root, row)
                return row
        previous = versions[-1] if versions else None
        snapshot_id = 'snapshot-' + hashlib.sha256((artifact_id + '|' + key + '|' + digest + '|' + original_ref['sha256']).encode()).hexdigest()[:24]
        row = sanitize({'artifact_id': artifact_id, 'snapshot_id': snapshot_id,
               'capture_key': key, 'task_id': task_id, 'sha256': digest, 'size': len(data),
               'source_path': origin, 'path': str(source.resolve()), 'linux_path': str(linux_path or source.resolve()),
               'windows_path': windows_path, 'original_name': source.name, 'source_label': label or source.name,
               'label': label or source.name, 'captured_at': now_iso(), 'object_path': str(obj),
               'relation': relation, 'previous_snapshot_id': previous.get('snapshot_id') if previous else None,
               'previous_sha256': previous.get('sha256') if previous else None,
               'version': (previous.get('version', 0) + 1) if previous else 1,
               'redactions': redactions, 'credential_check_scope': scope,
               'content_form': 'derived_bytes' if derived_from else 'local_only_safe_placeholder' if sensitivity in ('L4','local_only') or scope=='opaque_sensitive_original_local_only' else 'credential_redacted_copy' if redactions else 'source_bytes',
               'original': original_ref, 'source_locator': source_locator, 'derived_from': derived_from,
               'fidelity': 'derived' if derived_from else 'original',
               'original_access': 'controlled_local' if private else 'local_original',
               'preservation_scope': 'new_capture_only_no_historical_reconstruction'})
        _append_line(_guard(root, root / 'raw/manifests' / ('objects-' + datetime.now(timezone.utc).strftime('%Y%m%d') + '.jsonl')), row)
    _snapshot_event(root, row)
    return row
