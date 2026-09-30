#!/usr/bin/env python3
"""Local monitor adapter for the existing Javis control, RAW and memory stores."""
import argparse
import hashlib
import json
import ipaddress
import os
import re
import secrets
import socket
import socketserver
import struct
import threading
import time
import sys
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
sys.path.insert(0, str(Path(__file__).parent / 'orchestration'))
from task_service import Principal, ControlService, ControlError, load_control, ensure_not_held
from owner_auth import OwnerAuth, ORIGIN, ACTOR
from role_registry import ROLE_IDS, ROLE_REGISTRY
from raw_policy import sanitize
from runtime_io import lock

def owner_principal(session):
    return Principal(ACTOR, 'owner', ROLE_IDS,
        frozenset({'task:create', 'task:read:any', 'task:control:any'}), session['auth_ref'])

def service_principal():
    return Principal('service:flowise:invest-fixed-review-v1', 'service', frozenset({'invest'}),
                     frozenset({'task:create', 'task:read'}), 'os-peer-uid')

class App:
    def __init__(self, root, enrollment_seconds=0):
        self.root = Path(root).resolve(); self.control = ControlService(self.root)
        self.auth = OwnerAuth(self.root, enrollment_seconds)
        # Local memory capabilities are deliberately separate from owner sessions.
        # They never create a Principal or authorize tasks, mirror sync or feedback.
        self.memory_sessions = {}
        self.memory_session_lock = threading.Lock()

    def open_memory_session(self, token=''):
        now = time.time()
        with self.memory_session_lock:
            self.memory_sessions = {k: v for k, v in self.memory_sessions.items() if v['expires'] > now}
            session = self.memory_sessions.get(token)
            if session is None:
                token = secrets.token_urlsafe(32)
                session = {'csrf': secrets.token_urlsafe(32), 'expires': now + 28800, 'kind': 'local_memory'}
                self.memory_sessions[token] = session
            return token, dict(session)

    def lookup(self, principal, command_id):
        receipt = self.control.lookup_command(principal, command_id)
        c = load_control(self.root, receipt['task_id'])
        return {**receipt, 'role_id': c['role_id'], 'source_line': c['source_line'],
                'permission': c['permission'],
                'workflow_id': c['entry'][8:] if c['entry'].startswith('flowise:') else None,
                'original_text_sha256': c['goals'][0]['input_sha256']}

    def service_submit(self, body):
        from fixed_work import validate_submission
        # The fixed-work adapter validates its exact template and stable run identity.
        req = validate_submission(self.root, body)
        return self.control.submit(service_principal(), req)

    def review_memory(self, principal, request, assertion):
        from memory_review import MemoryReview
        # Confirmation is durable before projection. A graph outage never
        # turns a committed owner decision into a fabricated failure/approval.
        with lock(self.root / 'state/maintenance.lock', shared=True):
            from task_service import ensure_not_held
            ensure_not_held(self.root)
            decision = MemoryReview(self.root).review(principal, request, assertion)
            if decision.get('status') == 'confirmed':
                from task_memory import _graph
                decision['graph_projection'] = _graph(self.root, [decision['scope']])
                decision['graph_retry'] = 'Revalidated on next task context; no model rerun is required'
            else:
                decision['graph_projection'] = {'status': 'not_applicable', 'reason': 'not_confirmed'}
        return decision

    def raw(self, principal, tid):
        self.control.status(principal, tid)
        rows = []
        for path in sorted((self.root / 'raw/events').rglob('*.jsonl')):
            for line in path.read_text(encoding='utf-8', errors='replace').split('\n'):
                try: row = json.loads(line)
                except ValueError: continue
                if row.get('task_id') == tid:
                    rows.append(row)
        return {'ok': True, 'task_id': tid, 'events': sanitize(rows[-600:]),
                'total': len(rows), 'limited': len(rows) > 600, 'read_only': True}

    def detail(self, principal, tid):
        status = self.control.status(principal, tid)
        c = load_control(self.root, tid)
        return {**status, 'goals': c['goals'], 'context_budget_bytes': c['context_budget_bytes'],
                'entry': c['entry'], 'dispatch': c.get('dispatch')}

    def memory_usage(self):
        # Read-only public projections, loaded lazily so the monitor can still
        # start while an optional memory-adapter deployment is unavailable.
        adapter = str(Path(__file__).resolve().parents[1] / 'tools/memory-adapter')
        if adapter not in sys.path: sys.path.insert(0, adapter)
        from javis_memory_adapter.usage_meter import summary, recent
        def pick(row, fields):
            return {key: row[key] for key in fields if key in row} if isinstance(row, dict) else {}
        def usage(row, window=False):
            fields = ('calls', 'completed', 'pending', 'unknown_usage', 'unknown_price', 'unpriced_requests', 'subscription_requests',
                      'stage', 'model', 'provider_host') if window else (
                      'started_at', 'finished_at', 'stage', 'model', 'actual_model', 'status',
                      'usage_known', 'pricing_status', 'duration_ms', 'http_status', 'error_type', 'billing_mode')
            out = pick(row, fields)
            out['tokens'] = pick(row.get('tokens'), ('input', 'output', 'total', 'cached', 'reasoning'))
            out['estimated_cost'] = pick(row.get('estimated_cost'), ('currency', 'kind', 'known_amount', 'amount', 'reason'))
            if window:
                out['estimated_cost_by_currency'] = {
                    currency: {**pick(cost, ('kind', 'known_amount', 'amount', 'requests', 'priced_requests')), 'currency': currency}
                    for currency, cost in (row.get('estimated_cost_by_currency') or {}).items()
                    if currency in {'CNY', 'USD'} and isinstance(cost, dict)}
                out.update(pick(row, ('unknown_currency_requests',)))
                out['pricing_coverage'] = pick(row.get('pricing_coverage'), ('priced_requests', 'completed_requests', 'fraction'))
                out['usage_coverage'] = pick(row.get('usage_coverage'), ('complete_requests', 'partial_requests', 'missing_requests'))
                if 'breakdown' in row: out['breakdown'] = [usage(item, True) for item in row['breakdown']]
            return out
        value = summary(self.root)
        public = pick(value, ('schema_version', 'timezone', 'as_of', 'meter_started_at'))
        public.update({key: usage(value.get(key, {}), True) for key in ('today', 'month', 'all')})
        public['integrity'] = pick(value.get('integrity'), ('invalid_rows', 'conflicting_rows'))
        return {'ok': True, 'read_only': True, 'summary': public,
                'recent': [usage(row) for row in recent(self.root, limit=20)]}

    def memory_triage(self):
        from memory_triage import list_pending
        result = list_pending(self.root, limit=100)
        fields = {'triage_id', 'status', 'reason_code', 'policy_reason', 'stage', 'source_event_id',
                  'raw_refs', 'scope', 'run_id', 'graph_edge_id', 'policy_version',
                  'created_at', 'source_integrity', 'version_digest'}
        return {'ok': True, 'read_only': True,
                'items': [{k: v for k, v in row.items() if k in fields}
                          for row in result['items']],
                'total': result['total'], 'invalid_records': result['invalid_records']}

    def system(self):
        services = {}
        for name, port in [('neo4j_http', 7474), ('neo4j_bolt', 7687)]:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.3):
                    services[name] = 'reachable'
            except OSError: services[name] = 'unreachable'
        statuses = []
        for path in sorted((self.root / 'state/backup').glob('last-*.json')):
            try: statuses.append({'source': str(path.relative_to(self.root)), 'state': json.loads(path.read_text())})
            except (OSError, ValueError): pass
        try:
            import subprocess
            proc = subprocess.run(['systemctl', '--user', 'show', 'javis-control-panel.service',
                'javis-task-dispatch.service', 'javis-invest-fixed-review.timer', 'javis-memory-pipeline.timer',
                '--property=Id,ActiveState,SubState', '--no-pager'], capture_output=True, text=True, timeout=3)
            services['units'] = [dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
                                 for block in proc.stdout.strip().split('\n\n') if block]
        except (OSError, subprocess.SubprocessError): services['units'] = 'unavailable'
        health = self.root / 'state/drop-bridge/health.json'
        if health.exists():
            watcher = json.loads(health.read_text()); watcher['stale'] = time.time() - watcher.get('updated_at', 0) > 30
            services['drop_bridge'] = watcher
        from memory_pipeline import status as memory_pipeline_status
        from memory_sync import status as memory_sync_status
        try: memory_health = {'pipeline': memory_pipeline_status(self.root), 'sync': memory_sync_status(self.root)}
        except (OSError, ValueError): memory_health = {'status': 'unavailable'}
        return {'ok': True, 'last_updated': time.time(), 'services': services, 'backup_status': sanitize(statuses),
                'memory_health': memory_health,
                'known_gaps': ['独立盘/异机备份缺失', 'Windows整机重启尚未实测',
                               'Grok未提供完整气泡事件API；转发原文与模型转述必须分别标注'],
                'vault': {'contents_exposed': False, 'strict_l4_cloud_execution': 'blocked'},
                'authentication': self.auth.info()}

    def download(self, principal, tid, attempt, index):
        receipt = self.control.result(principal, tid, attempt)
        artifacts = receipt['result'].get('artifacts', [])
        if index < 0 or index >= len(artifacts):
            raise ControlError('not_found', 'Artifact not found', 404)
        artifact = artifacts[index]; digest = artifact.get('sha256', '')
        if not re.fullmatch(r'[a-f0-9]{64}', digest):
            raise ControlError('invalid_artifact', 'Missing artifact hash')
        # Never serve mutable output, arbitrary paths, vault or configured credentials.
        path = self.root / 'raw/objects' / digest
        if path.is_symlink() or path.resolve().parent != (self.root / 'raw/objects').resolve():
            raise ControlError('invalid_artifact', 'Invalid immutable artifact path')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ControlError('artifact_corrupt', 'Artifact does not match receipt hash')
        return data, 'artifact-' + str(index) + '.bin'

class Handler(BaseHTTPRequestHandler):
    server_version = 'JavisControl/1'
    def log_message(self, *args):
        pass  # No query bodies, cookies, credentials or filenames in access logs.

    @property
    def app(self): return self.server.app

    def send(self, code, value, *, cookie=None, content_type='application/json; charset=utf-8', filename=None):
        data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; connect-src 'self'; base-uri 'none'")
        if cookie: self.send_header('Set-Cookie', cookie)
        if filename: self.send_header('Content-Disposition', 'attachment; filename="' + filename + '"')
        self.end_headers(); self.wfile.write(data)

    def body(self):
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise ControlError('content_type', 'JSON is required', 415)
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length <= 1048576: raise ControlError('body_size', 'Invalid request size', 413)
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict): raise ValueError('JSON object required')
        return value

    def boundary(self):
        if getattr(self.server, 'unix', False):
            _, uid, _ = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.getuid(): raise PermissionError('Wrong operating system peer')
            return True
        if self.headers.get('Host') != 'localhost:8766':
            raise PermissionError('Use http://localhost:8766; untrusted Host rejected')
        origin = self.headers.get('Origin')
        if origin and origin != ORIGIN: raise PermissionError('Cross-origin access is not allowed')
        if self.command != 'GET' and origin != ORIGIN: raise PermissionError('Same-origin browser request required')
        return False

    def browser_session(self, mutation=False):
        cookie = SimpleCookie(); cookie.load(self.headers.get('Cookie', ''))
        token = cookie.get('javis_owner')
        session = self.app.auth.session(token.value if token else '')
        if mutation and self.headers.get('X-Javis-CSRF') != session['csrf']:
            raise PermissionError('CSRF verification failed')
        return session

    def memory_cookie(self):
        cookie = SimpleCookie(); cookie.load(self.headers.get('Cookie', ''))
        value = cookie.get('javis_memory')
        return value.value if value else ''

    def memory_boundary(self):
        if not ipaddress.ip_address(self.client_address[0]).is_loopback:
            raise ControlError('local_memory_required', 'Memory management is available only on this computer', 403)

    def browser_memory_session(self, mutation=False):
        self.memory_boundary()
        with self.app.memory_session_lock:
            session = self.app.memory_sessions.get(self.memory_cookie())
            if not session or session['expires'] <= time.time():
                raise ControlError('memory_session_required', 'Open local memory management again', 403)
            if mutation and not secrets.compare_digest(self.headers.get('X-Javis-Memory-CSRF', ''), session['csrf']):
                raise ControlError('memory_csrf_failed', 'Memory CSRF verification failed', 403)
            return dict(session)

    def memory_autoreview_route(self, path, body):
        self.browser_memory_session(self.command == 'POST')
        from memory_autoreview import MemoryAutoreview
        memory = MemoryAutoreview(self.app.root)
        if path == '/api/memory/autoreview' and self.command == 'GET':
            return self.send(200, {'ok': True, **memory.status()})
        if self.command != 'POST':
            raise ControlError('not_found', 'Endpoint not found', 404)
        allowed = ({'action', 'expected_revision', 'command_id'} if path.endswith('/control') else
                   {'decision_id', 'expected_version', 'command_id', 'reason'})
        if set(body) - allowed:
            raise ValueError('Unexpected memory management field')
        with lock(self.app.root / 'state/maintenance.lock', shared=True):
            from task_service import ensure_not_held
            ensure_not_held(self.app.root)
            if path == '/api/memory/autoreview/control':
                result = memory.control(body['action'], body['expected_revision'], body['command_id'])
            elif path == '/api/memory/autoreview/withdraw':
                result = memory.withdraw(body['decision_id'], body['expected_version'], body['command_id'], body.get('reason', ''))
            else:
                raise ControlError('not_found', 'Endpoint not found', 404)
        return self.send(200, {'ok': True, **result})

    def memory_v3_route(self, path, body, query):
        session = self.browser_memory_session(self.command == 'POST')
        root = self.app.root
        if path == '/api/memory/controls':
            import memory_controls
            if self.command == 'POST':
                allowed = {'expected_revision', 'global_enabled', 'roles', 'daily_call_limit', 'command_id'}
                if set(body) - allowed: raise ValueError('Unexpected control field')
                result = memory_controls.update(root, **body)
            else: result = memory_controls.status(root)
            return self.send(200, {'ok': True, **result,
                'role_labels': {k: v['label'] for k, v in ROLE_REGISTRY.items()}})
        if path == '/api/memory/model':
            import memory_model_config
            if self.command == 'POST':
                allowed = {'model', 'api_key', 'expected_revision', 'embedding_model',
                           'auth_mode', 'account_id', 'embedding_provider', 'embedding_api_key',
                           'use_legacy_embedding'}
                if set(body) - allowed: raise ValueError('Unexpected model field')
                with lock(root / 'state/maintenance.lock', shared=True):
                    ensure_not_held(root)
                    result = memory_model_config.configure(root, **body)
            else: result = memory_model_config.status(root)
            return self.send(200, {'ok': True, **result})
        if path.startswith('/api/memory/subscription'):
            import chatgpt_subscription
            if path == '/api/memory/subscription' and self.command == 'GET':
                return self.send(200, {'ok': True, **chatgpt_subscription.status(root)})
            if self.command != 'POST':
                raise ControlError('not_found', 'Endpoint not found', 404)
            if path == '/api/memory/subscription/begin':
                if set(body) - {'account_id'}: raise ValueError('Unexpected subscription field')
                result = chatgpt_subscription.begin(root, account_id=body.get('account_id'))
            elif path == '/api/memory/subscription/models':
                if body: raise ValueError('Model catalog request must be empty')
                result = chatgpt_subscription.models(root)
            elif path in {'/api/memory/subscription/select', '/api/memory/subscription/disconnect'}:
                if set(body) != {'account_id'}: raise ValueError('Account selection required')
                fn = chatgpt_subscription.select_account if path.endswith('/select') else chatgpt_subscription.disconnect
                result = fn(root, body['account_id'])
            else:
                raise ControlError('not_found', 'Endpoint not found', 404)
            return self.send(200, {'ok': True, **result})
        if path == '/api/memory/sources/context' and self.command == 'GET':
            from memory_sources import source_context
            return self.send(200, {'ok': True, **source_context(root, query['event_id'][0], query['scope'][0])})
        if path == '/api/memory/sources/original' and self.command == 'GET':
            from memory_sources import resolve_original
            original = resolve_original(root, query['event_id'][0], query['scope'][0], query['snapshot_id'][0])
            filename = re.sub(r'[^A-Za-z0-9._-]', '_', original.get('filename', 'source.bin'))[:120] or 'source.bin'
            return self.send(200, original['bytes'], content_type='application/octet-stream', filename=filename)
        if path == '/api/memory/coverage' and self.command == 'GET':
            from memory_sources import coverage_reconcile
            return self.send(200, {'ok': True, **coverage_reconcile(root)})
        if path == '/api/memory/local-learning' and self.command == 'GET':
            from memory_learning import MemoryLearning
            return self.send(200, {'ok': True, **MemoryLearning(root).status()})
        if path.startswith('/api/memory/local-feedback'):
            from memory_feedback import LocalMemoryFeedback
            feedback = LocalMemoryFeedback(root)
            if path == '/api/memory/local-feedback/context' and self.command == 'GET':
                selector = json.loads(query['text_path'][0]) if 'text_path' in query else None
                return self.send(200, {'ok': True, **feedback.context(session,
                    query['event_id'][0], query['scope'][0], text_path=selector,
                    run_id=query.get('run_id', [None])[0], triage_id=query.get('triage_id', [None])[0])})
            if path == '/api/memory/local-feedback/sources' and self.command == 'GET':
                return self.send(200, {'ok': True, **feedback.sources(session,
                    limit=30, cursor=query.get('cursor', [None])[0])})
            if path == '/api/memory/local-feedback' and self.command == 'POST':
                return self.send(200, {'ok': True, **feedback.record(session, body)})
        if path == '/api/memory/supplements' and self.command == 'POST':
            from memory_interactions import supplement
            return self.send(200, {'ok': True, **supplement(root, body)})
        if path == '/api/memory/supplements' and self.command == 'GET':
            from memory_interactions import status
            return self.send(200, {'ok': True, **status(root)})
        if path == '/api/memory/retry' and self.command == 'POST':
            from memory_pipeline import retry_pending
            if set(body) != {'triage_id', 'expected_digest', 'command_id'}:
                raise ValueError('Invalid retry request')
            return self.send(200, {'ok': True, **retry_pending(root, **body)})
        raise ControlError('not_found', 'Endpoint not found', 404)

    def do_GET(self): self.run_route()
    def do_POST(self): self.run_route()

    def subscription_callback(self, url):
        # This one OAuth callback uses the exact registered 127.0.0.1 URI.
        # It grants no owner or memory session; one-time state/PKCE/nonce and
        # verified identity bind completion to a local user-started attempt.
        if (getattr(self.server, 'unix', False) or self.command != 'GET'
                or url.scheme or url.netloc or self.headers.get('Host') != '127.0.0.1:8766'):
            raise PermissionError('Invalid subscription callback destination')
        self.memory_boundary()
        if len(url.query) > 16384:
            raise ValueError('Subscription callback too large')
        import chatgpt_subscription
        query = parse_qs(url.query, keep_blank_values=True, max_num_fields=12)
        chatgpt_subscription.complete(self.app.root, query)
        # Clear the authorization code from the visible callback URL promptly.
        self.send_response(303)
        self.send_header('Location', 'http://localhost:8766/?memory_login=chatgpt#memory')
        self.send_header('Content-Length', '0')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()

    def run_route(self):
        try:
            url = urlparse(self.path); path = url.path
            if path == '/auth/chatgpt/callback':
                return self.subscription_callback(url)
            unix = self.boundary()
            body = self.body() if self.command == 'POST' else None
            if not unix:
                if self.command == 'GET' and path in {'/', '/app.js', '/memory-v3.js', '/style.css'}:
                    name = {'/': 'index.html', '/app.js': 'app.js', '/memory-v3.js': 'memory-v3.js', '/style.css': 'style.css'}[path]
                    data = (Path(__file__).parent.parent / 'tools/control-panel/web' / name).read_bytes()
                    return self.send(200, data, content_type={'/': 'text/html; charset=utf-8', '/app.js': 'text/javascript; charset=utf-8', '/memory-v3.js': 'text/javascript; charset=utf-8', '/style.css': 'text/css'}[path])
                if self.command == 'GET' and path == '/api/auth/info': return self.send(200, self.app.auth.info())
                if self.command == 'POST' and path in {'/api/auth/enroll/begin', '/api/auth/login/begin'}:
                    return self.send(200, self.app.auth.begin(path.split('/')[3]))
                if self.command == 'POST' and path in {'/api/auth/enroll/complete', '/api/auth/login/complete'}:
                    token, session = self.app.auth.complete(path.split('/')[3], body['request_id'], body['response'])
                    return self.send(200, {'ok': True, 'csrf': session['csrf'], 'expires': session['expires']},
                                     cookie='javis_owner=' + token + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=900')
                if self.command == 'POST' and path == '/api/memory/session':
                    self.memory_boundary()
                    if body: raise ValueError('Memory session request must be empty')
                    token, local = self.app.open_memory_session(self.memory_cookie())
                    return self.send(200, {'ok': True, **local},
                                     cookie='javis_memory=' + token + '; HttpOnly; SameSite=Strict; Path=/api/memory; Max-Age=28800')
                if path in {'/api/memory/autoreview', '/api/memory/autoreview/control', '/api/memory/autoreview/withdraw'}:
                    return self.memory_autoreview_route(path, body)
                if path in {'/api/memory/controls', '/api/memory/model', '/api/memory/sources/context',
                            '/api/memory/sources/original', '/api/memory/coverage', '/api/memory/local-learning',
                            '/api/memory/local-feedback/context', '/api/memory/local-feedback/sources',
                            '/api/memory/local-feedback', '/api/memory/supplements', '/api/memory/retry',
                            '/api/memory/subscription', '/api/memory/subscription/begin',
                            '/api/memory/subscription/models', '/api/memory/subscription/select',
                            '/api/memory/subscription/disconnect'}:
                    return self.memory_v3_route(path, body, parse_qs(url.query))
                if self.command == 'GET' and self.memory_cookie() and path in {'/api/memory/triage', '/api/memory/usage'}:
                    self.browser_memory_session()
                    return self.send(200, self.app.memory_triage() if path.endswith('/triage') else self.app.memory_usage())
                session = self.browser_session(self.command == 'POST'); principal = owner_principal(session)
                if path == '/api/auth/session' and self.command == 'GET':
                    return self.send(200, {'ok': True, 'csrf': session['csrf'], 'expires': session['expires']})
            else: principal = service_principal()
            if path == '/api/roles' and self.command == 'GET':
                if unix: raise ControlError('forbidden', 'Fixed-work socket cannot list or expand roles', 403)
                return self.send(200, {'ok': True, 'roles': [{'role_id': key, 'label': row['label']} for key, row in ROLE_REGISTRY.items() if key in principal.role_ids]})
            if path == '/api/tasks':
                value = self.app.control.list_tasks(principal) if self.command == 'GET' else (
                    self.app.service_submit(body) if unix else self.app.control.submit(principal, body))
                return self.send(200 if self.command == 'GET' else 202, value)
            match = re.fullmatch(r'/api/commands/([A-Za-z0-9_.:-]+)', path)
            if match and self.command == 'GET': return self.send(200, self.app.lookup(principal, match[1]))
            match = re.fullmatch(r'/api/tasks/([A-Za-z0-9_.:-]+)(?:/(result|commands|raw|artifact))?', path)
            if match:
                tid, action = match.groups()
                if self.command == 'GET' and not action: return self.send(200, self.app.detail(principal, tid))
                if self.command == 'GET' and action == 'result':
                    attempt = parse_qs(url.query).get('attempt', [None])[0]
                    return self.send(200, self.app.control.result(principal, tid, int(attempt) if attempt else None))
                if not unix and self.command == 'POST' and action == 'commands':
                    return self.send(202, self.app.control.command(principal, tid, body))
                if not unix and self.command == 'GET' and action == 'raw': return self.send(200, self.app.raw(principal, tid))
                if not unix and self.command == 'GET' and action == 'artifact':
                    qs = parse_qs(url.query); data, filename = self.app.download(principal, tid, int(qs['attempt'][0]), int(qs['index'][0]))
                    return self.send(200, data, content_type='application/octet-stream', filename=filename)
            if unix: raise ControlError('forbidden', 'Fixed-work socket only supports task submission and retrieval', 403)
            if path == '/api/system' and self.command == 'GET': return self.send(200, self.app.system())
            if path == '/api/memory/usage' and self.command == 'GET':
                return self.send(200, self.app.memory_usage())
            if path == '/api/memory/triage' and self.command == 'GET':
                return self.send(200, self.app.memory_triage())
            if path == '/api/memory/attention' and self.command == 'GET':
                from memory_attention import snapshot
                return self.send(200, {'ok': True, **snapshot(self.app.root)})
            if path.startswith('/api/memory/feedback'):
                from memory_feedback import MemoryFeedback
                feedback = MemoryFeedback(self.app.root)
                query = parse_qs(url.query)
                if path == '/api/memory/feedback/context' and self.command == 'GET':
                    selector = json.loads(query['text_path'][0]) if 'text_path' in query else None
                    return self.send(200, {'ok': True, **feedback.context(principal,
                        query['event_id'][0], query['scope'][0], text_path=selector,
                        run_id=query.get('run_id', [None])[0], triage_id=query.get('triage_id', [None])[0])})
                if path == '/api/memory/feedback/sources' and self.command == 'GET':
                    return self.send(200, {'ok': True, **feedback.sources(principal,
                        limit=50, cursor=query.get('cursor', [None])[0])})
                if path == '/api/memory/feedback' and self.command == 'GET':
                    return self.send(200, {'ok': True, **feedback.list_feedback(principal)})
                if path == '/api/memory/feedback' and self.command == 'POST':
                    return self.send(200, {'ok': True, **feedback.record(principal, body)})
            if path == '/api/memory/learning' and self.command == 'GET':
                from memory_learning import MemoryLearning
                return self.send(200, {'ok': True, **MemoryLearning(self.app.root).status()})
            if path == '/api/grok-captures' and self.command == 'GET':
                rows = []
                for p in sorted((self.app.root / 'raw/events/grok-sync').glob('*.jsonl')):
                    rows.extend(json.loads(line) for line in p.read_text().split('\n') if line.strip())
                return self.send(200, {'ok': True, 'captures': sanitize(rows[-50:]), 'total': len(rows)})
            if path == '/api/memory/mirror' or path.startswith('/api/memory/mirror/'):
                # Grok<->Javis mirror batches/policy: every confirm or reject is a
                # fresh passkey decision bound to the exact manifest digest.
                import mirror_batch_review as mirror
                import memory_cleanup_batch as cleanup  # Javis260928 追加三: one-signature cleanup batches
                if path == '/api/memory/mirror' and self.command == 'GET':
                    return self.send(200, {'ok': True, 'batches': mirror.list_batches(self.app.root, principal),
                                           'policies': mirror.list_policies(self.app.root, principal),
                                           'cleanups': cleanup.list_batches(self.app.root, principal)})
                if path == '/api/memory/mirror/challenge' and self.command == 'POST':
                    make = (cleanup.binding_for if 'cleanup_batch_id' in body else
                            mirror.policy_binding_for if 'policy_id' in body else mirror.binding_for)
                    return self.send(200, self.app.auth.begin('decision', session, make(self.app.root, principal, body)))
                if path == '/api/memory/mirror/review' and self.command == 'POST':
                    request = body['request']
                    decide = (cleanup.review if isinstance(request, dict) and 'cleanup_batch_id' in request else
                              mirror.review_mirror_policy if isinstance(request, dict) and 'policy_id' in request else mirror.review)
                    with lock(self.app.root / 'state/maintenance.lock', shared=True):
                        from task_service import ensure_not_held
                        ensure_not_held(self.app.root)
                        return self.send(200, {'ok': True, **decide(self.app.root, principal, request, body['assertion'])})
            if path.startswith('/api/memory/'):
                from memory_review import MemoryReview
                memory = MemoryReview(self.app.root)
                if path == '/api/memory/pending' and self.command == 'GET':
                    return self.send(200, {'ok': True, 'candidates': memory.list_pending(principal)})
                if path == '/api/memory/challenge' and self.command == 'POST':
                    binding = memory.binding_for(principal, body)
                    return self.send(200, self.app.auth.begin('decision', session, binding))
                if path == '/api/memory/review' and self.command == 'POST':
                    return self.send(200, self.app.review_memory(principal, body['request'], body['assertion']))
            if path == '/api/fixed-work':
                from fixed_work import FixedWorkManager
                work = FixedWorkManager(self.app.root); job = 'invest-fixed-review-v1'
                if self.command == 'GET': value = work.status(job)
                elif body.get('action') in {'enable','disable'}:
                    value = work.set_enabled(job, body['action'] == 'enable', body['expected_version'], body['command_id'], actor=principal.actor_id)
                elif body.get('action') == 'run_once':
                    value = work.run_once(job, body['command_id'], actor=principal.actor_id, expected_version=body['expected_version'])
                else: raise ValueError('Unknown fixed-work action')
                return self.send(200, value)
            raise ControlError('not_found', 'Endpoint not found', 404)
        except ControlError as exc:
            self.send(exc.status_code, {'ok': False, 'error': exc.code, 'message': str(exc), **sanitize(exc.details)})
        except PermissionError as exc:
            self.send(403, {'ok': False, 'error': 'owner_verification_required', 'message': str(exc)})
        except (ValueError, KeyError, TypeError) as exc:
            self.send(400, {'ok': False, 'error': 'invalid_request', 'message': str(sanitize(str(exc)))[:300]})
        except Exception as exc:
            # No paths, submitted content or secrets in error output.
            self.send(503, {'ok': False, 'error': 'backend_unavailable', 'type': type(exc).__name__})

class UnixHTTP(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    unix = True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default=str(Path.home() / 'javis'))
    parser.add_argument('--enroll-owner', action='store_true', help='Open 10-minute window only after owner approves new passkey enrollment')
    args = parser.parse_args(); root = Path(args.root).resolve()
    with lock(root / 'state/locks/control-panel.lock', blocking=False):
        app = App(root, 600 if args.enroll_owner else 0)
        import signal
        def open_enrollment(signum, frame):
            # Sent only by the local operator after owner approval. No HTTP route
            # can enable enrollment; an existing owner can never be replaced.
            if not app.auth.info()['configured']: app.auth.enrollment_until = time.time() + 600
        signal.signal(signal.SIGUSR1, open_enrollment)
        path = root / 'state/control/flowise.sock'; path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if not path.is_socket(): raise RuntimeError('Refusing to replace a non-socket path')
            path.unlink()
        unix = UnixHTTP(str(path), Handler); os.chmod(path, 0o600); unix.app = app
        http = ThreadingHTTPServer(('127.0.0.1', 8766), Handler); http.app = app
        threading.Thread(target=unix.serve_forever, daemon=True).start()
        try: http.serve_forever()
        finally:
            unix.shutdown(); unix.server_close(); http.server_close()
            if path.is_socket(): path.unlink()

if __name__ == '__main__': main()
