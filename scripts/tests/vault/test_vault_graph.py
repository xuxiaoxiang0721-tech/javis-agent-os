"""Consumer tests use synthetic credentials and mocks; never load .env."""
import asyncio
from contextlib import contextmanager
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch

SCRIPT = next((root / 'scripts/vault-graph.py'
               for root in Path(__file__).resolve().parents
               if (root / 'scripts/vault-graph.py').is_file()), None)
if SCRIPT is None:
    raise RuntimeError('Cannot locate the sibling vault-graph.py consumer')
spec = importlib.util.spec_from_file_location('vault_graph', SCRIPT)
vg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vg)
SECRET = 'synthetic-password-DO-NOT-PRINT-123'


def payload(**updates):
    obj = {'schema_version': 1, 'username': 'synthetic-user', 'password': SECRET}
    obj.update(updates)
    return json.dumps(obj).encode('utf-8')


class ConsumerTests(unittest.TestCase):
    def call(self, data=None, args=None):
        out = io.StringIO()
        code = vg.run(args or ['graph-check'], io.BytesIO(payload() if data is None else data), out)
        self.assertNotIn(SECRET, out.getvalue())
        return code, json.loads(out.getvalue())

    def test_valid_unicode_and_spaces_preserved(self):
        self.assertEqual(vg.read_credentials(io.BytesIO(payload(username='用户', password='  合成密码  '))),
                         ('用户', '  合成密码  '))

    def test_rejects_ambiguous_or_extra_authority(self):
        bad = [b'', b'[]', b'null', b'{"schema_version":1,"schema_version":1}',
               payload(schema_version=True), payload(schema_version=2),
               payload(uri='bolt://evil.invalid:7687'), payload(scope='invest'),
               payload(username=''), payload(username='a\nb'), payload(password=''),
               payload(password=None), payload(password='a\0b'),
               b'{"schema_version":1,"username":"x"}', b'\xff',
               b'x' * (vg.MAX_INPUT_BYTES + 1)]
        with patch.object(vg, 'execute', new_callable=AsyncMock) as execute:
            for data in bad:
                with self.subTest(data=data[:30]):
                    code, result = self.call(data=data)
                    self.assertEqual(code, 2)
                    self.assertEqual(result['reason'], 'invalid_input')
            execute.assert_not_called()

    def test_arbitrary_commands_and_paths_are_rejected(self):
        for args in [[], ['graph-sync', '--root', '/tmp'], ['shell'], ['graph-check', SECRET]]:
            with self.subTest(args=args):
                out = io.StringIO()
                code = vg.run(args, io.BytesIO(payload()), out)
                self.assertEqual(code, 2)
                self.assertNotIn(SECRET, out.getvalue())

    def test_graph_check_safe_receipt(self):
        with patch.object(vg, '_check', new_callable=AsyncMock) as check, \
                patch.object(vg, '_sync', new_callable=AsyncMock) as sync:
            code, result = self.call()
            self.assertEqual(code, 0)
            self.assertEqual(result['reason'], 'graph_verified')
            check.assert_awaited_once_with('synthetic-user', SECRET)
            sync.assert_not_called()

    def test_failed_auth_cannot_sync_or_leak_exception(self):
        with patch.object(vg, '_check', new=AsyncMock(side_effect=RuntimeError(SECRET))), \
                patch.object(vg, '_sync', new_callable=AsyncMock) as sync:
            code, result = self.call(args=['graph-sync'])
            self.assertEqual(code, 1)
            self.assertEqual(result['reason'], 'graph_unavailable')
            self.assertIsNone(result['facts_written'])
            sync.assert_not_called()

    def test_dependency_prints_are_discarded(self):
        async def noisy(*args):
            print(SECRET)
            print(SECRET, file=sys.stderr)
        with patch.object(vg, '_check', new=noisy):
            code, result = self.call()
            self.assertEqual(code, 0)

    def test_staged_sync_refuses_production_ledger(self):
        with patch.object(vg, 'CODE_ROOT', Path('/synthetic-not-deployed-javis')):
            with self.assertRaises(RuntimeError):
                asyncio.run(vg._sync('synthetic-user', SECRET))

    def test_driver_always_local_read_check_and_closed(self):
        result = types.SimpleNamespace(single=AsyncMock(return_value={'ok': 1}))
        session = types.SimpleNamespace(run=AsyncMock(return_value=result))
        context = types.SimpleNamespace()
        class SessionContext:
            async def __aenter__(self): return session
            async def __aexit__(self, *args): pass
        driver = types.SimpleNamespace(session=Mock(return_value=SessionContext()), close=AsyncMock())
        factory = Mock(return_value=driver)
        module = types.SimpleNamespace(AsyncGraphDatabase=types.SimpleNamespace(driver=factory))
        with patch.dict(sys.modules, {'neo4j': module}):
            asyncio.run(vg._check('synthetic-user', SECRET))
        self.assertEqual(factory.call_args.args, ('bolt://127.0.0.1:7687',))
        self.assertEqual(factory.call_args.kwargs['auth'], ('synthetic-user', SECRET))
        driver.session.assert_called_once_with(default_access_mode='READ', database='neo4j')
        session.run.assert_awaited_once_with('RETURN 1 AS ok')
        driver.close.assert_awaited_once()

    def test_sync_uses_only_existing_fixed_groups_without_model_or_dotenv(self):
        stores, calls = {}, []
        class Store:
            def __init__(self, scope): self.scope = scope
            def load_facts(self): return [object()]
            @contextmanager
            def rebuild_lock(self): yield
        def store(root, scope):
            self.assertEqual(root, vg.DEPLOY_ROOT)
            stores[scope] = Store(scope)
            return stores[scope]
        def group(root, scope): return 'fixture-' + scope
        async def rebuild(**kwargs):
            calls.append(kwargs)
            return {'written': ['synthetic-fact'], 'errors': [SECRET] if kwargs['store'].scope == 'invest' else []}
        task_memory = types.SimpleNamespace(_store=store, _group=group)
        type_b = types.SimpleNamespace(rebuild_group_from_store=rebuild)
        with patch.object(vg, 'CODE_ROOT', vg.DEPLOY_ROOT), \
                patch.dict(sys.modules, {'task_memory': task_memory, 'javis_memory_adapter.type_b': type_b}):
            result = asyncio.run(vg._sync('synthetic-user', SECRET))
        self.assertEqual(tuple(stores), vg.SCOPES)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['facts_written'], 4)
        self.assertEqual(result['errors'], 1)
        self.assertNotIn(SECRET, json.dumps(result))
        for call in calls:
            self.assertEqual(call['neo4j_uri'], vg.NEO4J_URI)
            self.assertFalse(call['embed'])
            self.assertEqual(call['neo4j_password'], SECRET)


if __name__ == '__main__':
    unittest.main(verbosity=2)
