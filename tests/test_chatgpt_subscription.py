"""Offline protocol and storage tests. No real accounts, auth or model requests."""
import copy
import hashlib
import io
import json
import multiprocessing
import os
import ssl
import stat
import sys
import tempfile
import threading
import time
import traceback
import unittest
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import chatgpt_subscription as sub

NOW = 1800000000


class SubscriptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = cls.key.public_key().public_numbers()
        cls.jwk = {'kid': 'test-key', 'kty': 'RSA', 'use': 'sig', 'alg': 'RS256',
                   'n': sub._b64(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, 'big')),
                   'e': sub._b64(pub.e.to_bytes(3, 'big'))}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = NOW
        self.calls = []
        self.next_response = None
        self.revocation_error = False
        sub._JWKS_CACHE = None
        self.addCleanup(lambda: setattr(sub, '_JWKS_CACHE', None))
        self.addCleanup(patch.stopall)
        patch.object(sub, '_now', lambda: self.now).start()
        self.network = patch.object(sub, '_request', side_effect=self.request).start()

    def jwt(self, claims, header=None, key=None):
        header = header or {'alg': 'RS256', 'kid': 'test-key', 'typ': 'JWT'}
        signing = '.'.join(sub._b64(json.dumps(v, separators=(',', ':')).encode()) for v in (header, claims))
        signature = (key or self.key).sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
        return signing + '.' + sub._b64(signature)

    def response(self, client='oaiapp_alpha', nonce=None, subject='subject-alpha', **changes):
        claims = {'iss': sub.ISSUER, 'sub': subject, 'aud': client, 'exp': self.now + 3600,
                  'iat': self.now, 'email': 'synthetic@example.test'}
        if nonce is not None:
            claims['nonce'] = nonce
        claims.update(changes.pop('claims', {}))
        response = {'access_token': 'synthetic-access-token', 'refresh_token': 'synthetic-refresh-token',
                    'id_token': self.jwt(claims), 'token_type': 'Bearer', 'expires_in': 3600,
                    'scope': sub.SCOPES, 'earliest_refresh_at': 0}
        response.update(changes)
        return response

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, copy.deepcopy(kwargs)))
        if url == sub.JWKS:
            return {'keys': [self.jwk]}
        if url == sub.DISCOVERY:
            return {'issuer': sub.ISSUER, 'jwks_uri': sub.JWKS,
                    'revocation_endpoint': sub.ISSUER + '/api/accounts/oauth/revoke'}
        if url.endswith('/revoke'):
            if self.revocation_error:
                raise sub._ProviderError(503)
            return {}
        if url == sub.MODELS:
            return {'models': [
                {'slug': 'gpt-test', 'display_name': 'Test', 'visibility': 'list', 'secret': 'never project'},
                {'slug': 'internal-test', 'visibility': 'hidden'}]}
        if url == sub.TOKEN:
            if isinstance(self.next_response, Exception):
                raise self.next_response
            if callable(self.next_response):
                return self.next_response(kwargs)
            if self.next_response is None:
                self.fail('Unexpected token call')
            return copy.deepcopy(self.next_response)
        self.fail('Unexpected network endpoint')

    def start(self, aid=None):
        result = sub.begin(self.root, aid)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(result['authorization_url']).query)
        return result, {k: v[0] for k, v in query.items()}

    def login(self, client='oaiapp_alpha', subject='subject-alpha', aid=None, **changes):
        _, query = self.start(aid)
        self.next_response = self.response(client, query['nonce'], subject, **changes)
        result = sub.complete(self.root, {'state': query['state'], 'code': 'synthetic-code', 'client_id': client})
        return result['account_id']

    def mutate(self, action):
        with sub._locked(self.root):
            value = sub._read(self.root)
            action(value)
            sub._write(self.root, value)

    def expect(self, code, function, *args, **kwargs):
        with self.assertRaises(sub.SubscriptionError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, 'chatgpt_subscription_' + code)
        self.assertEqual(str(caught.exception), caught.exception.code)

    def test_empty_status_read_only_no_directory_no_network(self):
        before = list(self.root.iterdir())
        result = sub.status(self.root)
        self.assertFalse(result['connected'])
        self.assertTrue(result['requires_login'])
        self.assertIsNone(result['account_id'])
        self.assertEqual(before, list(self.root.iterdir()))
        self.assertEqual([], self.calls)

    def test_begin_pkce_host_permissions_and_no_secret_hint(self):
        result, query = self.start()
        value = sub._read(self.root)
        pending = next(iter(value['pending'].values()))
        self.assertEqual(query['client_id'], 'dynamic_agent_client')
        self.assertEqual(query['agent_name_hint'], 'Javis')
        self.assertEqual(query['code_challenge_method'], 'S256')
        self.assertEqual(query['code_challenge'], sub._b64(hashlib.sha256(pending['verifier'].encode()).digest()))
        self.assertEqual(query['scope'], sub.SCOPES)
        self.assertEqual(query['resource'], sub.RESOURCE)
        self.assertNotIn('id_token_hint', query)
        self.assertNotIn('login_hint', query)
        self.assertNotIn(pending['verifier'], json.dumps(result))
        self.assertEqual(self.start()[1]['ext_agent_host_id'], query['ext_agent_host_id'])
        for relative in ('secrets', sub.DIRECTORY):
            self.assertEqual(stat.S_IMODE((self.root / relative).stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / sub.STORE).stat().st_mode), 0o600)
        self.assertEqual([], self.calls)

    def test_fixed_redirect_rejects_variants_without_writes(self):
        for uri in ('http://localhost:8766/auth/chatgpt/callback', 'https://127.0.0.1:8766/auth/chatgpt/callback',
                    sub.REDIRECT_URI + '?x=1', 'http://127.0.0.1:8767/auth/chatgpt/callback'):
            self.expect('invalid_redirect_uri', sub.begin, self.root, redirect_uri=uri)
        self.assertFalse((self.root / 'secrets').exists())

    def test_complete_issued_client_exchange_and_safe_status(self):
        aid = self.login()
        result = sub.status(self.root)
        self.assertEqual(aid, sub._account_id('oaiapp_alpha'))
        self.assertTrue(result['connected'])
        self.assertTrue(result['plan_usage'])
        self.assertFalse(result['requires_login'])
        token_call = next(c for c in self.calls if c[1] == sub.TOKEN)
        form = token_call[2]['form']
        self.assertEqual(form['client_id'], 'oaiapp_alpha')
        self.assertEqual(form['resource'], sub.RESOURCE)
        self.assertEqual(form['redirect_uri'], sub.REDIRECT_URI)
        self.assertNotIn('client_secret', form)
        public = json.dumps(result)
        for secret in ('synthetic-access-token', 'synthetic-refresh-token', 'subject-alpha', 'id_token', 'client_id'):
            self.assertNotIn(secret, public)
        self.assertEqual(sub.access_token(self.root, aid), 'synthetic-access-token')

    def test_returning_flow_reuses_issued_client_without_hint(self):
        aid = self.login()
        _, query = self.start(aid)
        self.assertEqual(query['client_id'], 'oaiapp_alpha')
        self.assertNotIn('agent_name_hint', query)
        self.assertNotIn('id_token_hint', query)
        self.next_response = self.response(nonce=query['nonce'])
        self.assertEqual(aid, sub.complete(self.root, {'code': 'code2', 'state': query['state']})['account_id'])

    def test_wrong_state_does_not_exchange_or_consume_valid_state(self):
        _, query = self.start()
        self.expect('invalid_state', sub.complete, self.root, {'code': 'code', 'state': 'X' * 43})
        self.assertEqual(len(sub._read(self.root)['pending']), 1)
        self.assertEqual([], self.calls)
        self.next_response = self.response(nonce=query['nonce'])
        sub.complete(self.root, {'code': 'code', 'state': query['state'], 'client_id': 'oaiapp_alpha'})
        self.expect('invalid_state', sub.complete, self.root, {'code': 'code', 'state': query['state']})

    def test_expired_state_and_denial_consume_without_network(self):
        _, query = self.start()
        self.now += sub.PENDING_TTL
        self.expect('expired_state', sub.complete, self.root, {'code': 'code', 'state': query['state']})
        _, query = self.start()
        self.expect('authorization_denied', sub.complete, self.root,
                    {'state': query['state'], 'error': 'access_denied', 'error_description': 'SECRET provider text'})
        self.assertEqual({}, sub._read(self.root)['pending'])
        self.assertEqual([], self.calls)

    def test_duplicate_query_parameter_rejected(self):
        _, query = self.start()
        self.expect('invalid_callback', sub.complete, self.root, {'state': [query['state'], query['state']], 'code': ['one']})
        self.assertEqual([], self.calls)

    def test_first_callback_requires_issued_client_not_dynamic(self):
        for client in (None, 'dynamic_agent_client', 'https://attacker.invalid'):
            _, query = self.start()
            callback = {'state': query['state'], 'code': 'code'}
            if client:
                callback['client_id'] = client
            self.expect('invalid_client_binding', sub.complete, self.root, callback)
        self.assertEqual([], self.calls)

    def test_wrong_first_client_fails_audience_keeps_only_unconnected_registration(self):
        _, query = self.start()
        self.next_response = self.response(client='oaiapp_legitimate', nonce=query['nonce'])
        self.expect('invalid_token', sub.complete, self.root,
                    {'state': query['state'], 'code': 'code', 'client_id': 'oaiapp_wrong'})
        result = sub.status(self.root)
        self.assertIsNone(result['account_id'])
        self.assertEqual(len(result['accounts']), 1)
        self.assertFalse(result['accounts'][0]['connected'])
        self.assertNotIn('access_token', sub._read(self.root)['accounts'][result['accounts'][0]['account_id']])

    def test_returning_callback_client_mismatch_no_exchange(self):
        aid = self.login()
        _, query = self.start(aid)
        before = len(self.calls)
        self.expect('invalid_client_binding', sub.complete, self.root,
                    {'state': query['state'], 'code': 'code', 'client_id': 'oaiapp_other'})
        self.assertEqual(len(self.calls), before)
        self.assertEqual(sub.status(self.root)['account_id'], aid)

    def test_invalid_grant_retains_issued_registration_for_reauthentication(self):
        _, query = self.start()
        self.next_response = sub._ProviderError(400, 'invalid_grant')
        self.expect('login_required', sub.complete, self.root,
                    {'state': query['state'], 'code': 'code', 'client_id': 'oaiapp_alpha'})
        account = sub.status(self.root)['accounts'][0]
        self.assertTrue(account['requires_login'])
        _, query2 = self.start(account['account_id'])
        self.assertEqual(query2['client_id'], 'oaiapp_alpha')
        self.expect('invalid_state', sub.complete, self.root, {'state': query['state'], 'code': 'code'})

    def test_authorization_failure_diagnostics_consume_state_without_credentials(self):
        cases = [
            (sub._ProviderError(403, endpoint_kind='token'), 'authorization_token_http_403'),
            (sub._ProviderError(503, endpoint_kind='token'), 'authorization_token_http_503'),
            (sub._ProviderError(category='timeout', endpoint_kind='token'), 'authorization_token_timeout'),
            (sub._ProviderError(category='tls', endpoint_kind='token'), 'authorization_token_tls'),
            (sub._ProviderError(category='transport', endpoint_kind='token'), 'authorization_token_transport'),
            (sub._ProviderError(200, category='invalid_response', endpoint_kind='token'), 'authorization_token_invalid_response'),
            (sub._ProviderError(400, 'invalid_client', endpoint_kind='token'), 'invalid_client'),
            (sub._ProviderError(400, 'invalid_grant', endpoint_kind='token'), 'login_required'),
        ]
        for error, expected in cases:
            with self.subTest(expected=expected):
                _, query = self.start()
                self.next_response = error
                callback = {'state': query['state'], 'code': 'secret-code', 'client_id': 'oaiapp_alpha'}
                before = len(self.calls)
                self.expect(expected, sub.complete, self.root, callback)
                self.assertEqual(len(self.calls), before + 1)
                self.assertEqual({}, sub._read(self.root)['pending'])
                self.assertFalse(sub.status(self.root)['connected'])
                self.assertNotIn('access_token', sub._read(self.root)['accounts'][sub._account_id('oaiapp_alpha')])
                self.expect('invalid_state', sub.complete, self.root, callback)
                self.assertEqual(len(self.calls), before + 1)

    def test_jwks_failure_distinct_from_token_exchange_and_does_not_save_tokens(self):
        _, query = self.start()
        self.next_response = self.response(nonce=query['nonce'])
        def request(method, url, **kwargs):
            if url == sub.JWKS:
                raise sub._ProviderError(403, endpoint_kind='jwks')
            return self.request(method, url, **kwargs)
        self.network.side_effect = request
        self.expect('authorization_jwks_http_403', sub.complete, self.root,
                    {'state': query['state'], 'code': 'secret-code', 'client_id': 'oaiapp_alpha'})
        value = sub._read(self.root)
        self.assertEqual({}, value['pending'])
        self.assertIsNone(value['selected'])
        for token in ('access_token', 'refresh_token', 'id_token'):
            self.assertNotIn(token, value['accounts'][sub._account_id('oaiapp_alpha')])

    def test_id_claim_validation_table(self):
        cases = [({'iss': 'https://attacker.invalid'}, {}), ({'aud': 'wrong'}, {}),
                 ({'exp': self.now}, {}), ({'sub': ''}, {}), ({'nonce': 'wrong'}, {}),
                 ({'nbf': self.now + 31}, {}), ({'iat': self.now + 31}, {}),
                 ({'aud': ['oaiapp_alpha', 'other']}, {}), ({'azp': 'other'}, {}),
                 ({}, {'alg': 'none', 'kid': 'test-key'}),
                 ({}, {'alg': 'HS256', 'kid': 'test-key'}),
                 ({}, {'alg': 'RS256', 'kid': 'test-key', 'jku': 'https://attacker.invalid/keys'})]
        base = {'iss': sub.ISSUER, 'aud': 'oaiapp_alpha', 'exp': self.now + 300, 'sub': 'one', 'nonce': 'expected'}
        for change, header in cases:
            with self.subTest(change=change, header=header):
                claims = dict(base, **change)
                self.expect('invalid_token', sub._verify_id, self.jwt(claims, header or None), 'oaiapp_alpha', nonce='expected')

    def test_bad_signature_unknown_kid_duplicate_jwk_rejected(self):
        claims = {'iss': sub.ISSUER, 'aud': 'oaiapp_alpha', 'exp': self.now + 300, 'sub': 'one'}
        alien = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.expect('invalid_token', sub._verify_id, self.jwt(claims, key=alien), 'oaiapp_alpha')
        self.expect('invalid_token', sub._verify_id,
                    self.jwt(claims, {'alg': 'RS256', 'kid': 'unknown'}), 'oaiapp_alpha')
        self.assertGreaterEqual(len([c for c in self.calls if c[1] == sub.JWKS]), 2)
        sub._JWKS_CACHE = (self.now + 300, [self.jwk, self.jwk])
        self.expect('invalid_token', sub._verify_id, self.jwt(claims), 'oaiapp_alpha')

    def test_returning_subject_mismatch_preserves_previous_tokens_and_selection(self):
        aid = self.login()
        before = copy.deepcopy(sub._read(self.root)['accounts'][aid])
        _, query = self.start(aid)
        self.next_response = self.response(nonce=query['nonce'], subject='different-subject')
        self.expect('account_mismatch', sub.complete, self.root, {'state': query['state'], 'code': 'code'})
        self.assertEqual(sub._read(self.root)['accounts'][aid], before)
        self.assertEqual(sub.status(self.root)['account_id'], aid)

    def test_separate_same_email_registrations_and_expected_account_pin(self):
        aid = self.login()
        other = self.login('oaiapp_other', 'subject-other')
        self.assertNotEqual(aid, other)
        self.assertEqual(len(sub.status(self.root)['accounts']), 2)
        self.expect('account_mismatch', sub.access_token, self.root, aid)
        sub.select_account(self.root, aid)
        self.assertEqual(sub.access_token(self.root, aid), 'synthetic-access-token')

    def test_stale_callback_cannot_override_new_selection_or_signout(self):
        aid = self.login()
        _, pending = self.start(aid)
        sub.select_account(self.root, aid)
        before = len(self.calls)
        self.expect('stale_login', sub.complete, self.root, {'state': pending['state'], 'code': 'code'})
        self.assertEqual(before, len(self.calls))
        _, pending = self.start(aid)
        sub.disconnect(self.root, aid)
        before = len(self.calls)
        self.expect('invalid_state', sub.complete, self.root, {'state': pending['state'], 'code': 'code'})
        self.assertEqual(before, len(self.calls))
        self.assertIsNone(sub.status(self.root)['account_id'])

    def test_scope_missing_retains_identity_but_blocks_plan_access(self):
        aid = self.login(scope='openid profile email offline_access')
        result = sub.status(self.root)
        self.assertTrue(result['connected'])
        self.assertFalse(result['plan_usage'])
        self.expect('access_denied', sub.access_token, self.root, aid)
        self.expect('access_denied', sub.models, self.root, aid)

    def test_invalid_token_response_table(self):
        response = self.response(nonce='expected')
        changes = [{'token_type': []}, {'expires_in': True}, {'expires_in': 0},
                   {'access_token': 'line\nsecret'}, {'refresh_token': None}, {'scope': 'profile'},
                   {'earliest_refresh_at': self.now + 4000}, {'earliest_refresh_at': '2026-01-01T01:00:00'}]
        for change in changes:
            self.expect('invalid_token_response', sub._tokens, dict(response, **change), 'oaiapp_alpha', nonce='expected')

    def test_serial_refresh_one_request_rotates_atomic_and_omits_scope(self):
        aid = self.login()
        self.now += 3550
        self.next_response = lambda _: (time.sleep(0.025) or self.response(access_token='new-access', refresh_token='new-refresh'))
        before = len([c for c in self.calls if c[1] == sub.TOKEN])
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: sub.access_token(self.root, aid), range(6)))
        self.assertEqual(results, ['new-access'] * 6)
        token_calls = [c for c in self.calls if c[1] == sub.TOKEN]
        self.assertEqual(len(token_calls) - before, 1)
        form = token_calls[-1][2]['form']
        self.assertEqual(form['refresh_token'], 'synthetic-refresh-token')
        self.assertNotIn('scope', form)
        self.assertEqual(sub._read(self.root)['accounts'][aid]['refresh_token'], 'new-refresh')
        self.assertEqual(stat.S_IMODE((self.root / sub.STORE).stat().st_mode), 0o600)

    def test_switch_waits_for_refresh_then_old_pin_is_rejected(self):
        aid = self.login()
        other = self.login('oaiapp_other', 'subject-other')
        sub.select_account(self.root, aid)
        self.now += 3550
        entered, release = threading.Event(), threading.Event()
        def refresh(_):
            entered.set()
            self.assertTrue(release.wait(3))
            return self.response(access_token='fresh-alpha')
        self.next_response = refresh
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(sub.access_token, self.root, aid)
            self.assertTrue(entered.wait(3))
            switching = pool.submit(sub.select_account, self.root, other)
            time.sleep(0.02)
            self.assertFalse(switching.done())
            release.set()
            self.assertEqual(first.result(), 'fresh-alpha')
            self.assertEqual(switching.result()['account_id'], other)
        self.expect('account_mismatch', sub.access_token, self.root, aid)

    def test_process_lock_prevents_duplicate_rotating_refresh(self):
        aid = self.login()
        self.now += 3550
        context = multiprocessing.get_context('fork')
        count, results = context.Value('i', 0), context.Queue()
        base_request = self.request
        def request(method, url, **kwargs):
            if url == sub.TOKEN:
                with count.get_lock():
                    count.value += 1
                time.sleep(0.05)
                return self.response(access_token='process-access', refresh_token='process-refresh')
            return base_request(method, url, **kwargs)
        self.network.side_effect = request
        def worker():
            try:
                results.put(('ok', sub.access_token(self.root, aid)))
            except Exception as exc:
                results.put(('error', type(exc).__name__))
        children = [context.Process(target=worker) for _ in range(3)]
        try:
            for child in children:
                child.start()
            received = [results.get(timeout=5) for _ in children]
            for child in children:
                child.join(timeout=5)
                self.assertEqual(child.exitcode, 0)
            self.assertEqual(received, [('ok', 'process-access')] * 3)
            self.assertEqual(count.value, 1)
            self.assertEqual(sub._read(self.root)['accounts'][aid]['refresh_token'], 'process-refresh')
        finally:
            for child in children:
                if child.is_alive():
                    child.terminate()
                    child.join(timeout=2)
            results.close()

    def test_earliest_refresh_and_no_refresh_token_validity(self):
        aid = self.login(earliest_refresh_at=self.now + 3590)
        self.now += 3550
        before = len(self.calls)
        self.assertEqual(sub.access_token(self.root, aid), 'synthetic-access-token')
        self.assertEqual(len(self.calls), before)
        aid = self.login(aid=aid, scope='openid resource.invoke chatgpt.tokens.use.direct', refresh_token=None, expires_in=10)
        self.assertEqual(sub.access_token(self.root, aid), 'synthetic-access-token')
        self.now += 11
        self.expect('login_required', sub.access_token, self.root, aid)
        self.assertTrue(sub.status(self.root)['requires_login'])

    def test_terminal_refresh_clears_credentials_but_retains_registration(self):
        aid = self.login()
        self.now += 3600
        self.next_response = sub._ProviderError(400, 'refresh_token_reused')
        self.expect('login_required', sub.access_token, self.root, aid)
        account = sub._read(self.root)['accounts'][aid]
        self.assertEqual(account['client_id'], 'oaiapp_alpha')
        self.assertEqual(account['subject'], 'subject-alpha')
        self.assertNotIn('refresh_token', account)
        self.assertNotIn('access_token', account)
        before = len(self.calls)
        self.expect('login_required', sub.access_token, self.root, aid)
        self.assertEqual(len(self.calls), before)

    def test_transient_refresh_retains_credentials_and_never_retries_inside_call(self):
        aid = self.login()
        self.now += 3600
        self.next_response = sub._ProviderError(503)
        before = len(self.calls)
        self.expect('refresh_unavailable', sub.access_token, self.root, aid)
        self.assertEqual(len(self.calls), before + 1)
        self.assertEqual(sub._read(self.root)['accounts'][aid]['refresh_token'], 'synthetic-refresh-token')

    def test_invalid_rotated_id_never_saves_new_tokens(self):
        aid = self.login()
        self.now += 3600
        self.next_response = self.response(subject='other-subject', access_token='bad-new-access')
        self.expect('account_mismatch', sub.access_token, self.root, aid)
        self.assertNotIn('access_token', sub._read(self.root)['accounts'][aid])

    def test_models_safe_projection_and_pin(self):
        aid = self.login()
        result = sub.models(self.root, aid)
        self.assertEqual(result['models'], [{'slug': 'gpt-test', 'display_name': 'Test'}])
        self.assertEqual(result['account_id'], aid)
        self.assertNotIn('secret', json.dumps(result))
        self.assertNotIn('synthetic-access-token', json.dumps(result))
        before = len(self.calls)
        self.expect('account_mismatch', sub.models, self.root, 'acct_other')
        self.assertEqual(before, len(self.calls))

    def test_disconnect_revokes_then_clears_preserves_mapping(self):
        aid = self.login()
        result = sub.disconnect(self.root, aid)
        self.assertTrue(result['remote_revocation_confirmed'])
        self.assertEqual(result['revocation_status'], 'revoked')
        self.assertIsNone(result['account_id'])
        self.assertEqual(len(result['accounts']), 1)
        account = sub._read(self.root)['accounts'][aid]
        self.assertEqual(account['subject'], 'subject-alpha')
        self.assertNotIn('refresh_token', account)
        call = self.calls[-1]
        self.assertEqual(call[2]['form'], {'token': 'synthetic-refresh-token', 'token_type_hint': 'refresh_token', 'client_id': 'oaiapp_alpha'})

    def test_failed_revocation_local_disconnect_reports_unconfirmed(self):
        aid = self.login()
        self.revocation_error = True
        result = sub.disconnect(self.root, aid)
        self.assertFalse(result['remote_revocation_confirmed'])
        self.assertEqual(result['revocation_status'], 'unconfirmed')
        self.assertFalse(result['connected'])
        self.assertNotIn('refresh_token', sub._read(self.root)['accounts'][aid])

    def test_untrusted_discovery_never_posts_token(self):
        aid = self.login()
        base = self.request
        def request(method, url, **kw):
            if url == sub.DISCOVERY:
                return {'issuer': sub.ISSUER, 'jwks_uri': 'https://attacker.invalid/jwks',
                        'revocation_endpoint': 'https://attacker.invalid/revoke'}
            return base(method, url, **kw)
        self.network.side_effect = request
        before = len(self.calls)
        result = sub.disconnect(self.root, aid)
        self.assertFalse(result['remote_revocation_confirmed'])
        self.assertEqual(before, len(self.calls))

    def test_usage_hold_persists_across_status_and_expires_without_refresh(self):
        aid = self.login()
        result = sub.record_inference_failure(self.root, aid, 'usage_limit_exceeded', 120)
        self.assertEqual(result['availability_code'], 'usage_limit_exceeded')
        self.expect('usage_limit_exceeded', sub.access_token, self.root, aid)
        self.assertEqual(sub.status(self.root)['retry_at'], sub._iso(self.now + 120))
        self.now += 121
        self.assertIsNone(sub.status(self.root)['availability_code'])
        self.assertEqual(sub.access_token(self.root, aid), 'synthetic-access-token')

    def test_auth_hold_not_cleared_by_selection_or_late_usage_failure(self):
        aid = self.login()
        sub.record_inference_failure(self.root, aid, 'access_denied')
        sub.select_account(self.root, aid)
        sub.record_inference_failure(self.root, aid, 'usage_unavailable', 1)
        self.now += 2
        self.expect('access_denied', sub.access_token, self.root, aid)
        self.assertTrue(sub.status(self.root)['requires_login'])
        self.login(aid=aid)
        self.assertIsNone(sub.status(self.root)['availability_code'])

    def test_late_old_account_failure_never_blocks_other_account(self):
        aid = self.login()
        other = self.login('oaiapp_other', 'subject-other')
        sub.record_inference_failure(self.root, aid, 'login_required')
        self.assertEqual(sub.status(self.root)['account_id'], other)
        self.assertIsNone(sub.status(self.root)['availability_code'])
        self.assertEqual(sub.access_token(self.root, other), 'synthetic-access-token')

    def test_hold_blocks_mutations_but_not_read_only_status(self):
        aid = self.login()
        (self.root / 'state/recovery-hold.json').write_text('{"hold":true}')
        from task_service import ControlError
        for method, args in ((sub.begin, ()), (sub.access_token, (aid,)), (sub.models, (aid,)),
                             (sub.select_account, (aid,)), (sub.disconnect, (aid,)),
                             (sub.record_inference_failure, (aid, 'login_required'))):
            with self.assertRaises(ControlError):
                method(self.root, *args)
        self.assertTrue(sub.status(self.root)['connected'])
        (self.root / 'state/recovery-hold.json').write_text('{"hold":false}')
        self.assertEqual(sub.access_token(self.root, aid), 'synthetic-access-token')

    def test_store_symlink_hardlink_and_permissions_rejected(self):
        self.login()
        path = self.root / sub.STORE
        original = path.read_bytes()
        path.unlink()
        outside = self.root / 'outside.json'
        outside.write_bytes(original)
        path.symlink_to(outside)
        self.expect('unsafe_storage', sub.status, self.root)
        path.unlink()
        os.link(outside, path)
        self.expect('unsafe_storage', sub.status, self.root)
        path.unlink()
        path.write_bytes(original)
        path.chmod(0o644)
        self.expect('insecure_storage_permissions', sub.status, self.root)

    def test_duplicate_json_and_invalid_storage_rejected(self):
        self.login()
        path = self.root / sub.STORE
        path.write_text('{"schema":1,"schema":1}')
        self.expect('invalid_storage', sub.status, self.root)

    def test_no_codex_credentials_dependency(self):
        fake = self.root / 'unread-codex-home'
        fake.mkdir()
        (fake / 'auth.json').write_text('THIS IS INVALID JSON AND MUST NOT BE READ')
        with patch.dict(os.environ, {'CODEX_HOME': str(fake), 'OPENAI_API_KEY': 'not-this-credential'}):
            aid = self.login()
            self.assertEqual(sub.access_token(self.root, aid), 'synthetic-access-token')


class TransportTests(unittest.TestCase):
    def test_url_allowlist_and_redirect_handler(self):
        for url in ('http://auth.openai.com/x', 'https://auth.openai.com.attacker.invalid/x',
                    'https://user@auth.openai.com/x', 'https://auth.openai.com:443/x',
                    'https://auth.openai.com/../x', 'https://auth.openai.com/x?secret=y'):
            with self.assertRaises(sub.SubscriptionError):
                sub._official_url(url, revocation=True)
        self.assertIsNone(sub._NoRedirect().redirect_request(None, None, 302, '', {}, 'https://attacker.invalid'))
        with self.assertRaises(sub.SubscriptionError):
            sub._request('GET', 'https://attacker.invalid')

    def test_provider_body_not_exposed_and_no_retry(self):
        error = urllib.error.HTTPError(sub.TOKEN, 400, 'SECRET description', {}, io.BytesIO(b'{"error":"invalid_grant","error_description":"SECRET body"}'))
        with patch.object(urllib.request, 'build_opener') as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(sub._ProviderError) as caught:
                sub._request('POST', sub.TOKEN, form={'refresh_token': 'private-token'})
            self.assertEqual(caught.exception.code, 'invalid_grant')
            self.assertEqual(caught.exception.status, 400)
            self.assertEqual(caught.exception.category, 'http')
            self.assertEqual(caught.exception.endpoint_kind, 'token')
            self.assertNotIn('SECRET', str(caught.exception))
            self.assertEqual(opener.return_value.open.call_count, 1)

    def test_safe_http_diagnostics_never_echo_body_headers_or_url(self):
        for url, kind in ((sub.TOKEN, 'token'), (sub.JWKS, 'jwks')):
            with self.subTest(kind=kind), patch.object(urllib.request, 'build_opener') as opener:
                opener.return_value.open.side_effect = urllib.error.HTTPError(
                    'https://SECRET.invalid/secret-code', 403, 'SECRET reason', {'SECRET': 'SECRET header'},
                    io.BytesIO(b'{"error":{"code":"SECRET provider code"},"detail":"SECRET body"}'))
                with self.assertRaises(sub._ProviderError) as caught:
                    sub._request('GET', url, bearer='SECRET bearer')
                error = caught.exception
                self.assertEqual((error.status, error.category, error.endpoint_kind, error.code),
                                 (403, 'http', kind, None))
                self.assertNotIn('SECRET', repr(vars(error)))
                self.assertNotIn('SECRET', ''.join(traceback.format_exception(error)))
                self.assertEqual(opener.return_value.open.call_count, 1)

    def test_transport_classes_from_types_not_exception_messages(self):
        cases = [(ssl.SSLError('SECRET tls'), 'tls'), (TimeoutError('SECRET timeout'), 'timeout'),
                 (OSError('SECRET transport'), 'transport'),
                 (urllib.error.URLError(ssl.SSLError('SECRET tls')), 'tls'),
                 (urllib.error.URLError(TimeoutError('SECRET timeout')), 'timeout'),
                 (urllib.error.URLError('SECRET tls timeout'), 'transport')]
        for source_error, expected in cases:
            with self.subTest(expected=expected), patch.object(urllib.request, 'build_opener') as opener:
                opener.return_value.open.side_effect = source_error
                with self.assertRaises(sub._ProviderError) as caught:
                    sub._request('POST', sub.TOKEN, form={'code': 'SECRET code'})
                error = caught.exception
                self.assertEqual((error.status, error.category, error.endpoint_kind), (0, expected, 'token'))
                self.assertNotIn('SECRET', repr(vars(error)))
                self.assertNotIn('SECRET', ''.join(traceback.format_exception(error)))
                self.assertEqual(opener.return_value.open.call_count, 1)

    def test_diagnostics_fields_are_bounded_and_allowlisted(self):
        for status in ('SECRET', True, -1, 600, {'SECRET': 'body'}):
            error = sub._ProviderError(status, {'SECRET': 'body'},
                                       category={'SECRET': 'body'}, endpoint_kind='SECRET endpoint')
            self.assertEqual((error.status, error.code, error.category, error.endpoint_kind),
                             (0, None, 'transport', 'provider'))
            self.assertNotIn('SECRET', repr(vars(error)))

    def test_invalid_json_or_success_shape_is_invalid_response(self):
        class Response:
            status = 200
            def __init__(self, data): self.data = data
            def read(self, size): return self.data[:size]
            def __enter__(self): return self
            def __exit__(self, *args): pass
        for data in (b'SECRET invalid json', b'[]', b'"SECRET string"', b'\xff', b'{"x":1,"x":2}'):
            with self.subTest(data=data), patch.object(urllib.request, 'build_opener') as opener:
                opener.return_value.open.return_value = Response(data)
                with self.assertRaises(sub._ProviderError) as caught:
                    sub._request('GET', sub.JWKS)
                error = caught.exception
                self.assertEqual((error.status, error.category, error.endpoint_kind), (200, 'invalid_response', 'jwks'))
                self.assertNotIn('SECRET', repr(vars(error)))
                self.assertNotIn('SECRET', ''.join(traceback.format_exception(error)))

    def test_empty_revocation_200_and_bounded_body(self):
        class Response:
            status = 200
            def __init__(self, data): self.data = data
            def read(self, size): return self.data[:size]
            def __enter__(self): return self
            def __exit__(self, *args): pass
        with patch.object(urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value = Response(b'')
            self.assertEqual(sub._request('POST', sub.ISSUER + '/revoke', form={}, empty=True, revocation=True), {})
            opener.return_value.open.return_value = Response(b'x' * (sub.MAX_BYTES + 1))
            with self.assertRaises(sub._ProviderError) as caught:
                sub._request('GET', sub.JWKS)
            self.assertEqual((caught.exception.status, caught.exception.category, caught.exception.endpoint_kind),
                             (200, 'invalid_response', 'jwks'))


if __name__ == '__main__':
    unittest.main()
