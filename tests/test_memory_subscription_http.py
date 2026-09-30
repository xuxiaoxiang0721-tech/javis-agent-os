"""Subscription routes use local memory sessions; the callback uses OAuth state."""
import http.client
import json
import types
import sys
import unittest
from http.cookies import SimpleCookie
from unittest.mock import patch
import test_control_http as support


class SubscriptionHTTPTests(unittest.TestCase):
    def setUp(self):
        support.HTTPTests.setUp(self)
        self.cookie = ''; self.csrf = ''; self.calls = []
        self.module = types.ModuleType('chatgpt_subscription')
        self.module.status = lambda root: {'connected': False, 'accounts': []}
        def begin(root, **body):
            self.calls.append(('begin', body))
            return {'authorization_url': 'https://auth.openai.com/api/accounts/authorize?state=fixture'}
        def complete(root, query):
            self.calls.append(('complete', query))
            if query.get('state') != ['valid-state']: raise ValueError('subscription_state_invalid')
            return {'connected': True}
        self.module.begin = begin; self.module.complete = complete
        self.module.models = lambda root: {'account_id': 'acct_fixture', 'models': [{'slug': 'gpt-test', 'display_name': 'Test'}]}
        self.module.select_account = lambda root, account_id: {'account_id': account_id}
        self.module.disconnect = lambda root, account_id: {'account_id': account_id, 'connected': False, 'remote_revocation_confirmed': True}
        self.mock = patch.dict(sys.modules, {'chatgpt_subscription': self.module})
        self.mock.start(); self.addCleanup(self.mock.stop)

    def request(self, path, body=None, headers=None):
        h = {'Host': 'localhost:8766', 'Origin': support.panel.ORIGIN,
             'Cookie': self.cookie, 'X-Javis-Memory-CSRF': self.csrf}
        if body is not None: h['Content-Type'] = 'application/json'
        h.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        connection.request('POST' if body is not None else 'GET', path,
                           json.dumps(body) if body is not None else None, h)
        response = connection.getresponse(); raw = response.read()
        result = (response.status, json.loads(raw) if raw else None, dict(response.getheaders()))
        connection.close(); return result

    def open(self):
        code, value, headers = self.request('/api/memory/session', {})
        self.assertEqual(code, 200); jar = SimpleCookie(); jar.load(headers['Set-Cookie'])
        self.cookie = 'javis_memory=' + jar['javis_memory'].value; self.csrf = value['csrf']

    def test_begin_requires_local_memory_session_and_csrf(self):
        self.assertEqual(self.request('/api/memory/subscription/begin', {})[0], 403)
        self.open()
        self.assertEqual(self.request('/api/memory/subscription/begin', {}, {'X-Javis-Memory-CSRF': ''})[0], 403)
        self.assertEqual(self.request('/api/memory/subscription/begin', {}, {'Origin': 'https://evil.example'})[0], 403)
        self.assertEqual(self.request('/api/memory/subscription/begin', {'redirect_uri': 'https://evil.example'})[0], 400)
        code, value, _ = self.request('/api/memory/subscription/begin', {})
        self.assertEqual(code, 200); self.assertTrue(value['authorization_url'].startswith('https://auth.openai.com/'))
        self.assertEqual(self.calls, [('begin', {'account_id': None})])
        self.assertFalse((self.root / 'state/memory-controls/control.json').exists())

    def test_callback_exact_loopback_host_only_no_owner_session(self):
        path = '/auth/chatgpt/callback?state=valid-state&code=fixture-code&client_id=oaiapp_fixture'
        self.assertEqual(self.request(path)[0], 403)
        self.assertEqual(self.request(path, {}, {'Host': '127.0.0.1:8766'})[0], 403)
        code, _, headers = self.request(path, headers={'Host': '127.0.0.1:8766', 'Origin': ''})
        self.assertEqual(code, 303); self.assertEqual(headers['Location'], 'http://localhost:8766/?memory_login=chatgpt#memory')
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer'); self.assertNotIn('Set-Cookie', headers)
        self.assertEqual(len(self.app.auth.sessions), 1)
        self.assertEqual(self.app.memory_sessions, {})
        self.assertEqual(self.request('/api/tasks')[0], 403)
        self.assertEqual(self.request('/api/memory/subscription', headers={'Host': '127.0.0.1:8766'})[0], 403)

    def test_callback_invalid_state_has_no_redirect_or_secrets(self):
        code, value, headers = self.request('/auth/chatgpt/callback?state=bad&code=SECRET_CODE', headers={'Host': '127.0.0.1:8766'})
        self.assertEqual(code, 400); self.assertNotIn('Location', headers)
        self.assertNotIn('SECRET_CODE', json.dumps(value))

    def test_catalog_is_explicit_authenticated_post(self):
        self.open()
        self.assertEqual(self.request('/api/memory/subscription/models')[0], 404)
        self.assertEqual(self.request('/api/memory/subscription/models', {'base_url': 'https://evil.example'})[0], 400)
        code, value, _ = self.request('/api/memory/subscription/models', {})
        self.assertEqual(code, 200); self.assertEqual(value['models'][0]['slug'], 'gpt-test')


if __name__ == '__main__': unittest.main()
