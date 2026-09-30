"""Official Sign in with ChatGPT, isolated from Codex and from API-key billing.

Protocol: https://developers.openai.com/siwc/token-sharing-open-source/sign-in
Credentials live only in secrets/chatgpt-memory (0700/0600). Public functions
except access_token return allowlisted metadata. This module never runs models.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import ssl
import stat
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ISSUER = 'https://auth.openai.com'
AUTHORIZE = ISSUER + '/api/accounts/authorize'
TOKEN = ISSUER + '/api/accounts/oauth/token'
DISCOVERY = ISSUER + '/.well-known/openid-configuration'
JWKS = ISSUER + '/.well-known/jwks.json'
RESOURCE = 'https://api.openai.com/v1'
MODELS = RESOURCE + '/models'
REDIRECT_URI = 'http://127.0.0.1:8766/auth/chatgpt/callback'
SCOPES = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct'
PLAN_SCOPES = frozenset({'resource.invoke', 'chatgpt.tokens.use.direct'})
USAGE_URL = 'https://chatgpt.com/settings/usage'
DIRECTORY = 'secrets/chatgpt-memory'
STORE = DIRECTORY + '/sessions.json'
PENDING_TTL = 600
MAX_BYTES = 2 * 1024 * 1024
_THREAD_LOCK = threading.RLock()
_JWKS_LOCK = threading.RLock()
_JWKS_CACHE = None
_TERMINAL_REFRESH = frozenset({'invalid_grant', 'invalid_refresh_token', 'token_expired',
    'refresh_token_expired', 'refresh_token_invalidated', 'refresh_token_reused'})
_FAILURES = frozenset({'login_required', 'access_denied', 'usage_limit_exceeded', 'usage_unavailable'})


class SubscriptionError(ValueError):
    """Fixed local code only: never include a token, provider body or exception."""
    def __init__(self, code):
        self.code = 'chatgpt_subscription_' + code
        super().__init__(self.code)


class _ProviderError(Exception):
    """Bounded diagnostics only; never retain provider bodies or exception text."""
    def __init__(self, status=0, code=None, *, category=None, endpoint_kind=None):
        self.status = status if type(status) is int and 100 <= status <= 599 else 0
        self.code = code if isinstance(code, str) and code in _TERMINAL_REFRESH | {'invalid_client'} else None
        self.category = category if isinstance(category, str) and category in {'http', 'transport', 'tls', 'timeout', 'invalid_response'} else (
            'http' if self.status else 'transport')
        self.endpoint_kind = endpoint_kind if isinstance(endpoint_kind, str) and endpoint_kind in {'token', 'jwks', 'discovery', 'models', 'revocation'} else 'provider'
        super().__init__('provider_request_failed')


def _now():
    return time.time()


def _iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace('+00:00', 'Z')


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def _unb64(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise SubscriptionError('invalid_token')
    try:
        return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except (ValueError, TypeError):
        raise SubscriptionError('invalid_token') from None


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate_key')
        value[key] = item
    return value


def _json(data):
    return json.loads(data, object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _text(value, maximum=1024, minimum=1):
    return (isinstance(value, str) and minimum <= len(value) <= maximum
            and all(32 <= ord(c) != 127 for c in value))


def _token(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[\x21-\x7e]{1,32768}', value))


def _client(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9_.-]{3,256}', value)) and value != 'dynamic_agent_client'


def _account_id(client_id):
    return 'acct_' + hashlib.sha256((ISSUER + '\n' + client_id).encode()).hexdigest()[:32]


def _path(root, relative):
    root = Path(root).absolute()
    if root.resolve() != root:
        raise SubscriptionError('unsafe_storage')
    path = root / relative
    if not path.is_relative_to(root):
        raise SubscriptionError('unsafe_storage')
    cursor = root
    for part in path.relative_to(root).parts:
        cursor = cursor / part
        try:
            st = cursor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            raise SubscriptionError('unsafe_storage')
        if stat.S_ISREG(st.st_mode) and st.st_nlink != 1:
            raise SubscriptionError('unsafe_storage')
    return path


def _mkdir(root, relative, private=False):
    path = _path(root, relative)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _path(root, relative)
    if private:
        os.chmod(path, 0o700)
    return path


@contextmanager
def _file_lock(root, relative, shared=False, private=False):
    path = _path(root, relative)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise SubscriptionError('unsafe_storage')
        if private:
            os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


@contextmanager
def _locked(root):
    root = Path(root).absolute()
    with _THREAD_LOCK:
        _mkdir(root, 'state')
        with _file_lock(root, 'state/maintenance.lock', shared=True):
            from task_service import ensure_not_held
            ensure_not_held(root)
            _mkdir(root, 'secrets', private=True)
            _mkdir(root, DIRECTORY, private=True)
            with _file_lock(root, DIRECTORY + '/.lock', private=True):
                yield root


def _empty():
    return {'schema': 1, 'host_id': None, 'selected': None, 'revision': 0, 'accounts': {}, 'pending': {}}


def _read(root):
    path = _path(root, STORE)
    if not path.exists():
        return _empty()
    for relative in ('secrets', DIRECTORY):
        if _path(root, relative).stat().st_mode & 0o077:
            raise SubscriptionError('insecure_storage_permissions')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_BYTES:
            raise SubscriptionError('unsafe_storage')
        if st.st_mode & 0o077:
            raise SubscriptionError('insecure_storage_permissions')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            value = _json(stream.read(MAX_BYTES + 1))
        if (not isinstance(value, dict) or value.get('schema') != 1 or
                not isinstance(value.get('accounts'), dict) or len(value['accounts']) > 32 or
                not isinstance(value.get('pending'), dict) or len(value['pending']) > 8 or
                type(value.get('revision')) is not int or value['revision'] < 0 or
                not isinstance(value.get('host_id'), str) or not re.fullmatch(r'urn:uuid:[a-f0-9-]{36}', value['host_id'])):
            raise ValueError()
        for aid, account in value['accounts'].items():
            if (not isinstance(account, dict) or not _client(account.get('client_id')) or
                    aid != _account_id(account['client_id']) or
                    not isinstance(account.get('scopes'), list) or
                    any(not _text(s, 128) for s in account['scopes']) or
                    (account.get('subject') is not None and not _text(account['subject'])) or
                    not _number(account.get('expires_at', 0)) or not 0 <= account.get('expires_at', 0) < 32503680000 or
                    not _number(account.get('earliest_refresh_at', 0)) or not 0 <= account.get('earliest_refresh_at', 0) < 32503680000 or
                    account.get('availability_code') not in _FAILURES | {None} or
                    (account.get('retry_at') is not None and (not _number(account['retry_at']) or not 0 <= account['retry_at'] < 32503680000))):
                raise ValueError()
            for key in ('access_token', 'refresh_token', 'id_token'):
                if account.get(key) is not None and not _token(account[key]):
                    raise ValueError()
        if value['selected'] is not None and value['selected'] not in value['accounts']:
            raise ValueError()
        for key, pending in value['pending'].items():
            if (not re.fullmatch(r'[a-f0-9]{64}', key) or not isinstance(pending, dict) or
                    not _token(pending.get('nonce')) or not _token(pending.get('verifier')) or
                    not _number(pending.get('expires_at')) or
                    pending.get('redirect_uri') != REDIRECT_URI or
                    type(pending.get('revision')) is not int or
                    (pending.get('account_id') is not None and pending['account_id'] not in value['accounts']) or
                    (pending.get('client_id') is not None and not _client(pending['client_id']))):
                raise ValueError()
        return value
    except SubscriptionError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise SubscriptionError('invalid_storage') from None
    finally:
        os.close(fd)


def _write(root, value):
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(data) > MAX_BYTES:
        raise SubscriptionError('storage_limit')
    target = _path(root, STORE)
    fd, name = tempfile.mkstemp(prefix='.sessions-', dir=target.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _path(root, STORE)
        os.replace(name, target)
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _public(value):
    rows = []
    now = _now()
    for aid, account in value['accounts'].items():
        code = account.get('availability_code')
        retry = account.get('retry_at')
        if code in {'usage_limit_exceeded', 'usage_unavailable'} and retry is not None and retry <= now:
            code, retry = None, None
        connected = bool(account.get('subject') and account.get('access_token') and
                         (account.get('expires_at', 0) > now or account.get('refresh_token')))
        requires_login = not connected or code in {'login_required', 'access_denied'}
        email = account.get('email') if _text(account.get('email'), 254) else None
        rows.append({'account_id': aid, 'label': (email or 'ChatGPT') + ' · ' + aid[-8:], 'email': email,
                     'selected': aid == value['selected'], 'connected': connected,
                     'requires_login': requires_login, 'plan_usage': PLAN_SCOPES <= set(account['scopes']),
                     'expires_at': _iso(account['expires_at']) if account.get('expires_at') else None,
                     'availability_code': code, 'retry_at': _iso(retry) if retry is not None else None})
    selected = next((a for a in rows if a['selected']), {})
    return {'provider': 'chatgpt_subscription', 'account_id': value['selected'], 'accounts': rows,
            'connected': selected.get('connected', False), 'requires_login': selected.get('requires_login', True),
            'plan_usage': selected.get('plan_usage', False), 'availability_code': selected.get('availability_code'),
            'retry_at': selected.get('retry_at'), 'usage_url': USAGE_URL}


def status(root):
    """Read-only, offline metadata. Does not create storage or refresh tokens."""
    return _public(_read(root))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _official_url(url, revocation=False):
    allowed = {TOKEN, DISCOVERY, JWKS, MODELS}
    parsed = urllib.parse.urlsplit(url)
    if revocation:
        valid = (parsed.scheme == 'https' and parsed.netloc == 'auth.openai.com' and
                 not parsed.query and not parsed.fragment and
                 bool(re.fullmatch(r'/[A-Za-z0-9_./-]+', parsed.path)) and '..' not in parsed.path)
    else:
        valid = url in allowed
    if not valid:
        raise SubscriptionError('invalid_endpoint')


def _request(method, url, *, form=None, bearer=None, empty=False, revocation=False):
    """Single HTTP request, bounded body, no redirects or provider error echo."""
    _official_url(url, revocation)
    endpoint_kind = {TOKEN: 'token', JWKS: 'jwks', DISCOVERY: 'discovery', MODELS: 'models'}.get(
        url, 'revocation' if revocation else 'provider')
    headers = {'Accept': 'application/json'}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode('ascii')
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    if bearer is not None:
        headers['Authorization'] = 'Bearer ' + bearer
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    response_status = 0
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=20) as response:
            response_status = response.status
            if response.status != 200:
                raise _ProviderError(response.status, endpoint_kind=endpoint_kind)
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise _ProviderError(response.status, category='invalid_response', endpoint_kind=endpoint_kind)
            if empty and not data.strip():
                return {}
            value = _json(data)
            if not isinstance(value, dict):
                raise ValueError()
            return value
    except urllib.error.HTTPError as exc:
        code = None
        try:
            body = _json(exc.read(16385))
            code = body.get('error') if isinstance(body, dict) else None
            if isinstance(code, dict):
                code = code.get('code')
        except (ValueError, TypeError, OSError):
            pass
        raise _ProviderError(exc.code, code, endpoint_kind=endpoint_kind) from None
    except (_ProviderError, SubscriptionError):
        raise
    except urllib.error.URLError as exc:
        category = 'tls' if isinstance(exc.reason, ssl.SSLError) else (
            'timeout' if isinstance(exc.reason, TimeoutError) else 'transport')
        raise _ProviderError(category=category, endpoint_kind=endpoint_kind) from None
    except ssl.SSLError:
        raise _ProviderError(category='tls', endpoint_kind=endpoint_kind) from None
    except TimeoutError:
        raise _ProviderError(category='timeout', endpoint_kind=endpoint_kind) from None
    except OSError:
        raise _ProviderError(category='transport', endpoint_kind=endpoint_kind) from None
    except (ValueError, UnicodeError):
        raise _ProviderError(response_status, category='invalid_response', endpoint_kind=endpoint_kind) from None


def _jwks(refresh=False):
    global _JWKS_CACHE
    with _JWKS_LOCK:
        if not refresh and _JWKS_CACHE and _JWKS_CACHE[0] > _now():
            return _JWKS_CACHE[1]
        # Fixed URL: a provider-controlled jku/jwks_uri cannot redirect secrets.
        data = _request('GET', JWKS)
        keys = data.get('keys')
        if not isinstance(keys, list) or not 1 <= len(keys) <= 32 or not all(isinstance(k, dict) for k in keys):
            raise SubscriptionError('invalid_token')
        _JWKS_CACHE = (_now() + 300, keys)
        return keys


def _verify_id(token, client_id, *, nonce=None, subject=None):
    try:
        parts = token.split('.')
        if len(parts) != 3 or len(token) > 32768:
            raise ValueError()
        header = _json(_unb64(parts[0]))
        claims = _json(_unb64(parts[1]))
        if (not isinstance(header, dict) or header.get('alg') != 'RS256' or
                not _text(header.get('kid'), 256) or set(header) & {'jku', 'jwk', 'x5u', 'crit'} or
                not isinstance(claims, dict)):
            raise ValueError()
        keys = [k for k in _jwks() if k.get('kid') == header['kid']]
        if not keys:
            keys = [k for k in _jwks(refresh=True) if k.get('kid') == header['kid']]
        if len(keys) != 1:
            raise ValueError()
        key = keys[0]
        if key.get('kty') != 'RSA' or key.get('use', 'sig') != 'sig' or key.get('alg', 'RS256') != 'RS256':
            raise ValueError()
        n, e = int.from_bytes(_unb64(key.get('n')), 'big'), int.from_bytes(_unb64(key.get('e')), 'big')
        if n.bit_length() < 2048:
            raise ValueError()
        rsa.RSAPublicNumbers(e, n).public_key().verify(
            _unb64(parts[2]), (parts[0] + '.' + parts[1]).encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
        now = _now()
        audience = claims.get('aud')
        if isinstance(audience, list):
            aud_valid = (all(isinstance(a, str) for a in audience) and client_id in audience and
                         (len(audience) == 1 or claims.get('azp') == client_id))
        else:
            aud_valid = audience == client_id
        if (claims.get('iss') != ISSUER or not aud_valid or
                ('azp' in claims and claims['azp'] != client_id) or
                not _number(claims.get('exp')) or claims['exp'] <= now or
                not _text(claims.get('sub')) or
                ('iat' in claims and (not _number(claims['iat']) or claims['iat'] > now + 30)) or
                ('nbf' in claims and (not _number(claims['nbf']) or claims['nbf'] > now + 30))):
            raise ValueError()
        if nonce is not None and (not isinstance(claims.get('nonce'), str) or not hmac.compare_digest(claims['nonce'], nonce)):
            raise ValueError()
        if subject is not None and claims['sub'] != subject:
            raise SubscriptionError('account_mismatch')
        return claims
    except (InvalidSignature, ValueError, TypeError, KeyError, UnicodeError, AttributeError) as exc:
        if isinstance(exc, SubscriptionError) and exc.code == 'chatgpt_subscription_account_mismatch':
            raise
        raise SubscriptionError('invalid_token') from None


def _tokens(response, client_id, *, nonce=None, subject=None, previous_scopes=None):
    if not isinstance(response, dict):
        raise SubscriptionError('invalid_token_response')
    access, refresh, identity = (response.get(k) for k in ('access_token', 'refresh_token', 'id_token'))
    lifetime = response.get('expires_in')
    scopes = response.get('scope')
    if scopes is None and previous_scopes is not None:
        scopes = ' '.join(previous_scopes)
    if (not _token(access) or not _token(identity) or
            not isinstance(response.get('token_type'), str) or response['token_type'].lower() != 'bearer' or
            type(lifetime) is not int or not 1 <= lifetime <= 86400 or
            not isinstance(scopes, str) or len(scopes) > 2048 or
            not all(re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', s) for s in scopes.split()) or
            'openid' not in scopes.split() or
            ('offline_access' in scopes.split() and not _token(refresh)) or
            (refresh is not None and not _token(refresh))):
        raise SubscriptionError('invalid_token_response')
    claims = _verify_id(identity, client_id, nonce=nonce, subject=subject)
    earliest = response.get('earliest_refresh_at', 0)
    if isinstance(earliest, str):
        try:
            stamp = datetime.fromisoformat(earliest.replace('Z', '+00:00'))
            if stamp.tzinfo is None:
                raise ValueError()
            earliest = stamp.timestamp()
        except ValueError:
            raise SubscriptionError('invalid_token_response') from None
    if not _number(earliest) or earliest < 0 or earliest > _now() + lifetime:
        raise SubscriptionError('invalid_token_response')
    return {'client_id': client_id, 'subject': claims['sub'],
            'email': claims.get('email') if _text(claims.get('email'), 254) else None,
            'access_token': access, 'refresh_token': refresh, 'id_token': identity,
            'expires_at': _now() + lifetime, 'earliest_refresh_at': earliest,
            'scopes': sorted(set(scopes.split())), 'availability_code': None, 'retry_at': None}


def begin(root, account_id=None, redirect_uri=REDIRECT_URI):
    if redirect_uri != REDIRECT_URI:
        raise SubscriptionError('invalid_redirect_uri')
    with _locked(root) as root:
        value = _read(root)
        account = value['accounts'].get(account_id) if account_id is not None else None
        if account_id is not None and account is None:
            raise SubscriptionError('unknown_account')
        if account is None and len(value['accounts']) >= 32:
            raise SubscriptionError('account_limit')
        value['host_id'] = value['host_id'] or 'urn:uuid:' + str(uuid.uuid4())
        value['pending'] = {k: p for k, p in value['pending'].items() if p.get('expires_at', 0) > _now()}
        if len(value['pending']) >= 8:
            raise SubscriptionError('login_pending_limit')
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        expiry = _now() + PENDING_TTL
        value['pending'][hashlib.sha256(state.encode()).hexdigest()] = {
            'nonce': nonce, 'verifier': verifier, 'expires_at': expiry,
            'account_id': account_id, 'client_id': account['client_id'] if account else None,
            'revision': value['revision'], 'redirect_uri': redirect_uri}
        query = {'client_id': account['client_id'] if account else 'dynamic_agent_client',
                 'ext_agent_host_id': value['host_id'], 'response_type': 'code', 'redirect_uri': redirect_uri,
                 'scope': SCOPES, 'resource': RESOURCE, 'state': state, 'nonce': nonce,
                 'code_challenge_method': 'S256', 'code_challenge': _b64(hashlib.sha256(verifier.encode()).digest())}
        if account is None:
            query['agent_name_hint'] = 'Javis'
        _write(root, value)
        return {'authorization_url': AUTHORIZE + '?' + urllib.parse.urlencode(query),
                'expires_at': _iso(expiry), 'expires_in': PENDING_TTL}


def _query(mapping):
    if not isinstance(mapping, dict) or len(mapping) > 16:
        raise SubscriptionError('invalid_callback')
    result = {}
    for key, value in mapping.items():
        if not _text(key, 64):
            raise SubscriptionError('invalid_callback')
        if isinstance(value, list):
            if len(value) != 1:
                raise SubscriptionError('invalid_callback')
            value = value[0]
        if not _text(value, 8192):
            raise SubscriptionError('invalid_callback')
        result[key] = value
    return result


def complete(root, query_mapping):
    query = _query(query_mapping)
    state = query.get('state')
    if not isinstance(state, str) or not re.fullmatch(r'[A-Za-z0-9_-]{40,128}', state):
        raise SubscriptionError('invalid_state')
    with _locked(root) as root:
        value = _read(root)
        pending = value['pending'].pop(hashlib.sha256(state.encode()).hexdigest(), None)
        if pending is None:
            raise SubscriptionError('invalid_state')
        # Durable consumption precedes every response branch and every HTTP call.
        _write(root, value)
        if pending['expires_at'] <= _now():
            raise SubscriptionError('expired_state')
        if pending['revision'] != value['revision']:
            raise SubscriptionError('stale_login')
        if query.get('iss', ISSUER) != ISSUER:
            raise SubscriptionError('invalid_callback')
        if 'error' in query:
            raise SubscriptionError('authorization_denied')
        if not _token(query.get('code')):
            raise SubscriptionError('invalid_callback')
        client = pending['client_id'] or query.get('client_id')
        if not _client(client) or (query.get('client_id') is not None and query['client_id'] != client):
            raise SubscriptionError('invalid_client_binding')
        aid = _account_id(client)
        previous = value['accounts'].get(aid)
        if previous is None:
            if len(value['accounts']) >= 32:
                raise SubscriptionError('account_limit')
            # Retain the issued registration for retry even if code exchange fails.
            previous = {'client_id': client, 'subject': None, 'email': None, 'scopes': [],
                        'expires_at': 0, 'earliest_refresh_at': 0, 'availability_code': 'login_required', 'retry_at': None}
            value['accounts'][aid] = previous
            _write(root, value)
        try:
            response = _request('POST', TOKEN, form={'grant_type': 'authorization_code', 'client_id': client,
                'code': query['code'], 'code_verifier': pending['verifier'],
                'redirect_uri': pending['redirect_uri'], 'resource': RESOURCE})
            account = _tokens(response, client, nonce=pending['nonce'], subject=previous.get('subject'))
        except _ProviderError as exc:
            if exc.code in _TERMINAL_REFRESH:
                code = 'login_required'
            elif exc.code == 'invalid_client':
                code = 'invalid_client'
            else:
                detail = 'http_' + str(exc.status) if exc.category == 'http' and exc.status else exc.category
                code = 'authorization_' + exc.endpoint_kind + '_' + detail
            raise SubscriptionError(code) from None
        value['accounts'][aid] = account
        value['selected'] = aid
        value['revision'] += 1
        _write(root, value)
        return _public(value)


def _selected(value, expected_account_id):
    aid = value['selected']
    if expected_account_id is not None and expected_account_id != aid:
        raise SubscriptionError('account_mismatch')
    if aid is None:
        raise SubscriptionError('login_required')
    return aid, value['accounts'][aid]


def _clear(account):
    for key in ('access_token', 'refresh_token', 'id_token'):
        account.pop(key, None)
    account.update(expires_at=0, earliest_refresh_at=0, availability_code='login_required', retry_at=None)


def _access_locked(root, value, expected_account_id):
    aid, account = _selected(value, expected_account_id)
    code, retry = account.get('availability_code'), account.get('retry_at')
    if code and (code in {'login_required', 'access_denied'} or retry is None or retry > _now()):
        raise SubscriptionError(code)
    if not account.get('subject') or not account.get('access_token'):
        raise SubscriptionError('login_required')
    if not PLAN_SCOPES <= set(account['scopes']):
        raise SubscriptionError('access_denied')
    if account['expires_at'] > _now() + 60:
        return account['access_token']
    if account['earliest_refresh_at'] > _now():
        if account['expires_at'] > _now():
            return account['access_token']
        raise SubscriptionError('refresh_not_ready')
    if not account.get('refresh_token'):
        if account['expires_at'] > _now():
            return account['access_token']
        raise SubscriptionError('login_required')
    try:
        response = _request('POST', TOKEN, form={'grant_type': 'refresh_token', 'client_id': account['client_id'],
            'refresh_token': account['refresh_token'], 'resource': RESOURCE})
        updated = _tokens(response, account['client_id'], subject=account['subject'], previous_scopes=account['scopes'])
        if not updated.get('refresh_token'):
            raise SubscriptionError('invalid_token_response')
    except _ProviderError as exc:
        if exc.code in _TERMINAL_REFRESH:
            _clear(account)
            _write(root, value)
            raise SubscriptionError('login_required') from None
        raise SubscriptionError('invalid_client' if exc.code == 'invalid_client' else 'refresh_unavailable') from None
    except SubscriptionError:
        # A refresh may already have rotated remotely. Never reuse an unverified set.
        _clear(account)
        _write(root, value)
        raise
    value['accounts'][aid] = updated
    _write(root, value)
    if not PLAN_SCOPES <= set(updated['scopes']):
        raise SubscriptionError('access_denied')
    return updated['access_token']


def access_token(root, expected_account_id=None):
    """SECRET internal result. Serial rotation, account pin, no Codex credentials."""
    with _locked(root) as root:
        return _access_locked(root, _read(root), expected_account_id)


def models(root, expected_account_id=None):
    with _locked(root) as root:
        value = _read(root)
        aid, _ = _selected(value, expected_account_id)
        token = _access_locked(root, value, aid)
        try:
            response = _request('GET', MODELS, bearer=token)
        except _ProviderError as exc:
            raise SubscriptionError('models_unavailable') from None
        rows = response.get('models')
        if not isinstance(rows, list) or len(rows) > 1024:
            raise SubscriptionError('invalid_model_catalog')
        catalog, seen = [], set()
        for row in rows:
            if not isinstance(row, dict):
                raise SubscriptionError('invalid_model_catalog')
            if row.get('visibility') != 'list':
                continue
            slug = row.get('slug')
            if not isinstance(slug, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', slug) or slug in seen:
                raise SubscriptionError('invalid_model_catalog')
            display = row.get('display_name', slug)
            if not _text(display, 256):
                raise SubscriptionError('invalid_model_catalog')
            seen.add(slug)
            catalog.append({'slug': slug, 'display_name': display})
        return {'account_id': aid, 'models': catalog, 'fetched_at': _iso(_now())}


def select_account(root, account_id):
    with _locked(root) as root:
        value = _read(root)
        if account_id not in value['accounts']:
            raise SubscriptionError('unknown_account')
        value['selected'] = account_id
        value['revision'] += 1
        _write(root, value)
        return _public(value)


def disconnect(root, account_id):
    with _locked(root) as root:
        value = _read(root)
        account = value['accounts'].get(account_id)
        if account is None:
            raise SubscriptionError('unknown_account')
        confirmed = False
        had_token = bool(account.get('refresh_token'))
        if had_token:
            try:
                discovery = _request('GET', DISCOVERY)
                endpoint = discovery.get('revocation_endpoint')
                if (discovery.get('issuer') != ISSUER or discovery.get('jwks_uri') != JWKS or
                        not isinstance(endpoint, str)):
                    raise SubscriptionError('invalid_endpoint')
                _official_url(endpoint, revocation=True)
                _request('POST', endpoint, form={'token': account['refresh_token'],
                         'token_type_hint': 'refresh_token', 'client_id': account['client_id']}, empty=True, revocation=True)
                confirmed = True
            except (_ProviderError, SubscriptionError):
                pass
        _clear(account)
        value['pending'] = {k: p for k, p in value['pending'].items() if p.get('account_id') != account_id}
        if value['selected'] == account_id:
            value['selected'] = None
        value['revision'] += 1
        _write(root, value)
        result = _public(value)
        result.update(remote_revocation_confirmed=confirmed,
                      revocation_status='revoked' if confirmed else ('unconfirmed' if had_token else 'no_local_token'))
        return result


def record_inference_failure(root, expected_account_id, code, retry_after_seconds=None):
    """Record fixed, account-bound holds; no response text or headers are stored."""
    if code not in _FAILURES or not expected_account_id:
        raise SubscriptionError('invalid_failure_code')
    with _locked(root) as root:
        value = _read(root)
        # Late responses may mark their original account, never the newly selected one.
        account = value['accounts'].get(expected_account_id)
        if account is None:
            raise SubscriptionError('unknown_account')
        if account.get('availability_code') in {'login_required', 'access_denied'} and code in {'usage_limit_exceeded', 'usage_unavailable'}:
            return _public(value)
        retry = None
        if code in {'usage_limit_exceeded', 'usage_unavailable'}:
            delay = retry_after_seconds if _number(retry_after_seconds) else 900
            retry = _now() + min(3600, max(1, delay))
        account.update(availability_code=code, retry_at=retry)
        _write(root, value)
        return _public(value)
