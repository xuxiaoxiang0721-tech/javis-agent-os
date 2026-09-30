"""Owner verification via python-fido2. No password, API token or PIN storage.

Only localhost WebAuthn user verification establishes the owner. Task service
principals and model text can never confirm memory. Public signed decision
proofs live outside RAW; offline replay validates the signature and exact binding.
Local account administrators remain inside the trust boundary.
"""
import hashlib
import json
import os
import secrets
import threading
import time
from pathlib import Path

ACTOR = 'owner:local'
ORIGIN = 'http://localhost:8766'
_active = {}
_guard = threading.RLock()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def binding_hash(binding):
    return hashlib.sha256(canonical(binding)).hexdigest()

def private(root):
    p = Path(root) / 'state/owner-auth'
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(p, 0o700)
    return p

def write_once(path, value):
    import fcntl
    data = canonical(value)
    folder = path.parent if path.parent.name == 'owner-auth' else path.parent.parent
    with (folder / '.lock').open('a') as mutex:
        fcntl.flock(mutex, fcntl.LOCK_EX)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())

def server():
    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialRpEntity
    return Fido2Server(PublicKeyCredentialRpEntity(id='localhost', name='Javis owner'),
                      verify_origin=lambda origin: origin == ORIGIN)

def credentials(root, *, create_dir=True):
    from fido2.webauthn import AttestedCredentialData
    from fido2.utils import websafe_decode
    path = (private(root) if create_dir else Path(root) / 'state/owner-auth') / 'owner.json'
    if not path.exists():
        return []
    value = json.loads(path.read_text())
    if value['actor_id'] != ACTOR:
        raise ValueError('owner registry identity mismatch')
    return [AttestedCredentialData(websafe_decode(value['public_credential']))]

class OwnerAuth:
    def __init__(self, root, enrollment_seconds=0):
        self.root = Path(root).resolve()
        self.pending = {}; self.sessions = {}
        self.enrollment_until = time.time() + min(max(enrollment_seconds, 0), 600)
        _active[str(self.root)] = self

    def info(self):
        return {'configured': bool(credentials(self.root)),
                'enrollment_open': time.time() < self.enrollment_until and not credentials(self.root),
                'method': 'WebAuthn; user verification required', 'origin': ORIGIN}

    def begin(self, purpose, session=None, binding=None):
        with _guard:
            creds = credentials(self.root)
            nonce = secrets.token_hex(32)
            if purpose == 'enroll':
                if creds or time.time() >= self.enrollment_until:
                    raise PermissionError('Owner enrollment is closed; owner approval is required')
                options, state = server().register_begin(
                    {'id': b'javis-owner-local', 'name': 'Owner', 'displayName': 'Owner'},
                    user_verification='required', authenticator_attachment='platform')
            else:
                if not creds:
                    raise PermissionError('Owner passkey has not been enrolled')
                if purpose == 'decision':
                    if not session or not binding:
                        raise PermissionError('Authenticated owner and exact decision are required')
                    challenge = hashlib.sha256(b'JAVIS-DECISION-1\x00' + canonical(binding) + bytes.fromhex(nonce)).digest()
                elif purpose == 'login':
                    challenge = None
                else:
                    raise ValueError('Unknown authentication purpose')
                options, state = server().authenticate_begin(creds, user_verification='required', challenge=challenge)
            ref = secrets.token_urlsafe(24)
            self.pending[ref] = {'purpose': purpose, 'state': state, 'expires': time.time() + 120,
                                 'auth_ref': (session or {}).get('auth_ref'), 'binding': binding, 'nonce': nonce}
            return {'request_id': ref, 'options': dict(options)}

    def _take(self, request_id, purpose):
        item = self.pending.pop(request_id, None)
        if not item or item['purpose'] != purpose or item['expires'] < time.time():
            raise PermissionError('Expired or already consumed authentication challenge')
        return item

    def complete(self, purpose, request_id, response):
        from fido2.utils import websafe_encode
        with _guard:
            item = self._take(request_id, purpose)
            if purpose == 'enroll':
                if credentials(self.root) or time.time() >= self.enrollment_until:
                    raise PermissionError('Enrollment window is closed')
                auth = server().register_complete(item['state'], response)
                write_once(private(self.root) / 'owner.json',
                           {'actor_id': ACTOR, 'public_credential': websafe_encode(bytes(auth.credential_data)),
                            'enrolled_at': time.time(), 'method': 'webauthn_uv', 'origin': ORIGIN})
                self.enrollment_until = 0
            elif purpose == 'login':
                server().authenticate_complete(item['state'], credentials(self.root), response)
            else:
                raise ValueError('Use verify_decision for a fact-bound decision')
            token = secrets.token_urlsafe(32)
            session = {'actor_id': ACTOR, 'auth_ref': 'owner-auth-' + secrets.token_hex(16),
                       'expires': time.time() + 900, 'csrf': secrets.token_urlsafe(24)}
            self.sessions[token] = session
            return token, session

    def session(self, token):
        with _guard:
            value = self.sessions.get(token)
            if not value or value['expires'] < time.time():
                self.sessions.pop(token, None)
                raise PermissionError('Owner login required or expired')
            return value

def verify_principal(root, principal):
    owner = _active.get(str(Path(root).resolve()))
    if not owner or getattr(principal, 'actor_id', None) != ACTOR or getattr(principal, 'kind', None) != 'owner':
        raise PermissionError('Verified owner session required')
    ref = getattr(principal, 'authentication_ref', None)
    with _guard:
        if not ref or not any(s['auth_ref'] == ref and s['expires'] > time.time() for s in owner.sessions.values()):
            raise PermissionError('Owner authentication proof is missing or expired')
    return {'actor_id': ACTOR, 'authentication_ref': ref}

def verify_decision(root, assertion, binding):
    owner = _active.get(str(Path(root).resolve()))
    if not owner or not isinstance(assertion, dict):
        raise PermissionError('Owner decision assertion required')
    with _guard:
        item = owner._take(assertion.get('request_id'), 'decision')
        if item['binding'] != binding:
            raise PermissionError('Decision facts or version changed after the owner challenge')
        if not any(s['auth_ref'] == item['auth_ref'] and s['expires'] > time.time() for s in owner.sessions.values()):
            raise PermissionError('Owner session expired before decision')
        response = assertion.get('response')
        server().authenticate_complete(item['state'], credentials(root), response)
        proof_id = 'owner-proof-' + secrets.token_hex(24)
        folder = private(root) / 'decisions'; folder.mkdir(exist_ok=True, mode=0o700)
        proof = {'schema': 1, 'proof_id': proof_id, 'actor_id': ACTOR,
                 'binding': binding, 'binding_hash': binding_hash(binding), 'nonce': item['nonce'],
                 'response': response, 'verified_at': time.time(), 'origin': ORIGIN}
        write_once(folder / (proof_id + '.json'), proof)
        return {'actor_id': ACTOR, 'proof_id': proof_id, 'binding_hash': proof['binding_hash']}

def verify_recorded_decision(root, proof_id, binding):
    import re
    try:
        from fido2.utils import websafe_encode
    except ModuleNotFoundError as exc:
        if not exc.name.startswith('fido2'):
            raise
        # Existing runtime/Graphiti interpreters keep their dependency sets. Use
        # the pinned local verifier, with only public proof IDs and binding JSON.
        import subprocess
        verifier = Path(__file__).resolve()
        python = verifier.parent.parent / 'tools/control-panel/.venv/bin/python'
        proc = subprocess.run([str(python), str(verifier), '--verify-recorded'],
            input=json.dumps({'root': str(Path(root).resolve()), 'proof_id': proof_id, 'binding': binding}),
            text=True, capture_output=True, timeout=10, env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'})
        if proc.returncode != 0:
            raise PermissionError('Recorded owner proof failed pinned local verification')
        return json.loads(proc.stdout)
    if not isinstance(proof_id, str) or not re.fullmatch(r'owner-proof-[a-f0-9]{48}', proof_id):
        raise PermissionError('Invalid owner proof identifier')
    proof = json.loads((Path(root) / 'state/owner-auth/decisions' / (proof_id + '.json')).read_text())
    if proof['actor_id'] != ACTOR or proof['binding'] != binding or proof['binding_hash'] != binding_hash(binding):
        raise PermissionError('Recorded owner proof does not match exact decision')
    challenge = hashlib.sha256(b'JAVIS-DECISION-1\x00' + canonical(binding) + bytes.fromhex(proof['nonce'])).digest()
    server().authenticate_complete({'challenge': websafe_encode(challenge), 'user_verification': 'required'},
                                   credentials(root, create_dir=False), proof['response'])
    return {'actor_id': ACTOR, 'proof_id': proof_id, 'binding_hash': proof['binding_hash']}

if __name__ == '__main__':
    import sys
    if sys.argv[1:] != ['--verify-recorded']:
        raise SystemExit(2)
    try:
        request = json.loads(sys.stdin.read(65536))
        print(json.dumps(verify_recorded_decision(request['root'], request['proof_id'], request['binding'])))
    except Exception:
        print('Owner proof verification failed', file=sys.stderr)
        raise SystemExit(1)
