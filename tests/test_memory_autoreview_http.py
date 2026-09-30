"""Memory-only browser capability boundaries; temporary roots and stub backend only."""
import copy
import http.client
import json
import sys
import types
import unittest
from http.cookies import SimpleCookie
from unittest.mock import patch

import test_control_http as support


class MemoryCapabilityHTTPTests(unittest.TestCase):
    def setUp(self):
        support.HTTPTests.setUp(self)
        self.calls = []
        calls = self.calls
        module = types.ModuleType('memory_autoreview')

        class Backend:
            def __init__(self, root):
                self.root = root

            def status(self):
                calls.append(('status',))
                return {'mode': 'automatic', 'enabled': True, 'revision': 7, 'counts': {}, 'recent': []}

            def control(self, *args):
                calls.append(('control', *args))
                return {'enabled': args[0] == 'resume', 'revision': 8}

            def withdraw(self, *args):
                calls.append(('withdraw', *args))
                return {'action': 'revoke'}

        module.MemoryAutoreview = Backend
        mocked = patch.dict(sys.modules, {'memory_autoreview': module})
        mocked.start(); self.addCleanup(mocked.stop)
        self.cookie = ''; self.csrf = ''

    def request(self, path, body=None, *, headers=None, memory=True):
        h = {'Host': 'localhost:8766', 'Origin': support.panel.ORIGIN}
        if body is not None:
            h['Content-Type'] = 'application/json'
        if memory:
            h.update(Cookie=self.cookie, **{'X-Javis-Memory-CSRF': self.csrf})
        h.update(headers or {})
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        conn.request('POST' if body is not None else 'GET', path, json.dumps(body) if body is not None else None, h)
        response = conn.getresponse(); data = json.loads(response.read()); cookie = response.getheader('Set-Cookie')
        conn.close()
        return response.status, data, cookie

    def open_memory(self):
        code, value, raw = self.request('/api/memory/session', {})
        self.assertEqual(code, 200)
        jar = SimpleCookie(); jar.load(raw)
        self.cookie = 'javis_memory=' + jar['javis_memory'].value
        self.csrf = value['csrf']
        return value, raw

    def test_bootstrap_requires_no_owner_or_webauthn_and_creates_only_memory_capability(self):
        before = copy.deepcopy(self.app.auth.sessions)
        value, raw = self.open_memory()
        self.assertEqual(self.app.auth.sessions, before)
        self.assertEqual(value['kind'], 'local_memory')
        self.assertGreaterEqual(len(value['csrf']), 40)
        self.assertNotIn('auth_ref', value)
        for fragment in ('HttpOnly', 'SameSite=Strict', 'Path=/api/memory'):
            self.assertIn(fragment, raw)
        self.assertEqual(self.request('/api/memory/autoreview')[0], 200)

    def test_no_capability_cannot_read_or_mutate(self):
        for path, body in (('/api/memory/autoreview', None), ('/api/memory/autoreview/control', {'action': 'pause'})):
            self.assertEqual(self.request(path, body)[0], 403)
        self.assertEqual(self.calls, [])

    def test_memory_capability_has_no_task_owner_mirror_or_feedback_authority(self):
        self.open_memory()
        for path, body in (('/api/tasks', None), ('/api/roles', None), ('/api/auth/session', None),
                           ('/api/memory/mirror', None), ('/api/memory/pending', None),
                           ('/api/memory/challenge', {'action': 'confirm'}),
                           ('/api/memory/feedback', {'label': 'keep'}),
                           ('/api/fixed-work', {'action': 'run_once'})):
            self.assertEqual(self.request(path, body)[0], 403, path)
        self.assertEqual(self.calls, [])

    def test_control_and_withdraw_send_only_exact_memory_arguments(self):
        self.open_memory()
        self.assertEqual(self.request('/api/memory/autoreview/control',
            {'action': 'pause', 'expected_revision': 7, 'command_id': 'memory-pause'})[0], 200)
        self.assertEqual(self.request('/api/memory/autoreview/withdraw',
            {'decision_id': 'ai-review-1', 'expected_version': 'digest-1', 'command_id': 'memory-revoke', 'reason': '改正'})[0], 200)
        self.assertEqual(self.calls, [('control', 'pause', 7, 'memory-pause'),
            ('withdraw', 'ai-review-1', 'digest-1', 'memory-revoke', '改正')])

    def test_csrf_is_separate_and_required_even_with_cookie(self):
        self.open_memory()
        for headers in ({'X-Javis-Memory-CSRF': ''}, {'X-Javis-Memory-CSRF': 'test-only-csrf'},
                        {'X-Javis-Memory-CSRF': 'wrong', 'X-Javis-CSRF': self.csrf}):
            self.assertEqual(self.request('/api/memory/autoreview/control',
                {'action': 'pause', 'expected_revision': 7, 'command_id': 'bad'}, headers=headers)[0], 403)
        self.assertEqual(self.calls, [])

    def test_expired_capability_denied_then_bootstrap_renews_without_owner(self):
        self.open_memory(); old_cookie = self.cookie
        self.app.memory_sessions[old_cookie.split('=', 1)[1]]['expires'] = 1
        self.assertEqual(self.request('/api/memory/autoreview')[0], 403)
        self.open_memory(); self.assertNotEqual(self.cookie, old_cookie)
        self.assertEqual(self.request('/api/memory/autoreview')[0], 200)

    def test_exact_host_origin_and_nonempty_bootstrap_rejected(self):
        for headers in ({'Host': 'evil.example'}, {'Host': '127.0.0.1:8766'}, {'Origin': 'https://evil.example'}, {'Origin': ''}):
            self.assertEqual(self.request('/api/memory/session', {}, headers=headers)[0], 403)
        self.assertEqual(self.request('/api/memory/session', {'actor_id': 'owner:local'})[0], 400)
        self.assertEqual(self.app.memory_sessions, {})

    def test_non_loopback_peer_cannot_bootstrap_or_use_capability(self):
        with patch.object(support.panel.ipaddress, 'ip_address') as address:
            address.return_value.is_loopback = False
            self.assertEqual(self.request('/api/memory/session', {})[0], 403)
        self.open_memory()
        with patch.object(support.panel.ipaddress, 'ip_address') as address:
            address.return_value.is_loopback = False
            self.assertEqual(self.request('/api/memory/autoreview')[0], 403)
        self.assertEqual(self.calls, [])

    def test_fixed_work_unix_route_cannot_create_or_use_memory_capability(self):
        with patch.object(support.panel.Handler, 'boundary', return_value=True):
            self.assertEqual(self.request('/api/memory/session', {})[0], 403)
            self.assertEqual(self.request('/api/memory/autoreview')[0], 403)
        self.assertEqual(self.app.memory_sessions, {})
        self.assertEqual(self.calls, [])

    def test_body_cannot_inject_identity_proof_or_extra_permissions(self):
        self.open_memory()
        for field in ('actor_id', 'owner_proof', 'assertion', 'permissions'):
            request = {'action': 'pause', 'expected_revision': 7, 'command_id': 'bad', field: 'forged'}
            self.assertEqual(self.request('/api/memory/autoreview/control', request)[0], 400)
        self.assertEqual(self.calls, [])

    def test_memory_read_projections_stay_read_only(self):
        self.open_memory()
        with patch.object(self.app, 'memory_triage', return_value={'ok': True, 'items': []}) as triage:
            self.assertEqual(self.request('/api/memory/triage')[0], 200)
            self.assertEqual(self.request('/api/memory/triage', {'action': 'delete'})[0], 403)
            self.assertEqual(triage.call_count, 1)
        with patch.object(self.app, 'memory_usage', return_value={'ok': True, 'summary': {}}):
            self.assertEqual(self.request('/api/memory/usage')[0], 200)


if __name__ == '__main__':
    unittest.main()
