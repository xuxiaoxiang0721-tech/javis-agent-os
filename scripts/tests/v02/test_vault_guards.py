"""Synthetic vault exclusion checks; never opens an existing password database."""
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, call

CODE = Path(os.environ.get('JAVIS_TEST_CODE_ROOT', Path(__file__).resolve().parents[3]))
GUARDS = Path(os.environ.get('JAVIS_VAULT_GUARD_ROOT', CODE))
sys.path.insert(0, str(CODE / 'scripts'))
sys.path.insert(0, str(GUARDS / 'scripts'))
from raw_policy import CredentialFileBlocked, safe_file_bytes
from raw_storage import snapshot_file
spec = importlib.util.spec_from_file_location('vault_guard_backup', GUARDS / 'scripts/javis-backup.py')
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)

# Fixed public format headers followed by a synthetic, non-secret marker.
HEADERS = [bytes.fromhex(h) for h in ('03d9a29a67fb4bb5', '03d9a29a65fb4bb5', '03d9a29a66fb4bb5')]
MARKER = b'SYNTHETIC_VAULT_BYTES_Q7'
NAMES = ['personal.kdbx', 'program.KDBX.bak', 'archive.kdb-old', 'unlock.keyx',
         'unlock.KEYX~', 'program.kdbx_20260918', 'personal.kdbx copy', 'personal.kdbx:stream']
FAKE = r'''#!/usr/bin/env python3
import json, sys
from pathlib import Path
prompt = sys.stdin.read()
out = Path(prompt.split('Write deliverables under: ', 1)[1].split('\n', 1)[0])
out.mkdir(parents=True, exist_ok=True)
(out/'renamed.bin').write_bytes(bytes.fromhex('03d9a29a67fb4bb5') + b'SYNTHETIC_VAULT_BYTES_Q7')
print(json.dumps({'type':'thread.started','thread_id':'synthetic-vault-guard-session'}))
print(json.dumps({'type':'item.completed','item':{'id':'reply','type':'agent_message','text':'SUMMARY: synthetic file produced'}}))
print(json.dumps({'type':'turn.completed','usage':{'input_tokens':1,'output_tokens':1}}))
'''


class VaultGuards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='javis-vault-guard-test-')
        self.base = Path(self.tmp.name)
        self.root = self.base / 'javis'
        (self.root / 'config').mkdir(parents=True)
        (self.root / 'state').mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_known_paths_rejected_before_opening_content(self):
        paths = [self.root / 'config' / name for name in NAMES]
        paths += [self.root / 'workspace/Javis-Vault/arbitrary.bin',
                  self.root / 'workspace/jAVIS-vAULT/recovery.txt']
        with patch.object(Path, 'open', side_effect=AssertionError('must not open vault content')):
            for path in paths:
                with self.subTest(path=path.name), self.assertRaises(CredentialFileBlocked):
                    safe_file_bytes(path)

    def test_renamed_database_reads_only_public_signature(self):
        for header in HEADERS:
            handle = io.BytesIO(header + MARKER)
            with patch.object(handle, 'read', wraps=handle.read) as read:
                with patch.object(Path, 'open', return_value=handle):
                    with self.assertRaises(CredentialFileBlocked):
                        safe_file_bytes(self.root / 'config/renamed.bin')
                self.assertEqual(read.call_args_list, [call(8)])

    def test_ordinary_documents_and_binary_are_unchanged(self):
        for name, data in [('vault-guide.md', b'How to use a local vault'),
                           ('Javis-Vault.md', b'Public setup notes'),
                           ('image.bin', b'\x00\x81ordinary-binary'),
                           ('short.bin', b'\x03\xd9\xa2')]:
            with self.subTest(name=name):
                source = self.put('docs/' + name, data)
                safe, changes, _ = safe_file_bytes(source)
                self.assertEqual(safe, data)
                self.assertEqual(changes, [])

    def test_file_and_parent_symlink_cannot_hide_vault_location(self):
        source = self.put('workspace/Javis-Vault/plain-recovery.txt', MARKER)
        alias = self.root / 'config/link.txt'
        parent_alias = self.root / 'config/alias'
        alias.symlink_to(source)
        parent_alias.symlink_to(source.parent, target_is_directory=True)
        for path in [alias, parent_alias / source.name]:
            with self.subTest(path=path), self.assertRaises(CredentialFileBlocked):
                safe_file_bytes(path)
        self.assertEqual(list(backup.files(self.root)), [])

    def test_raw_snapshot_refuses_vault_without_object_or_manifest(self):
        for name, data in [('personal.kdbx.bak', MARKER), ('renamed.bin', HEADERS[0] + MARKER)]:
            source = self.put('workspace/out/' + name, data)
            with self.assertRaises(CredentialFileBlocked):
                snapshot_file(self.root, source, 'synthetic-vault-test', relation='output')
        self.assertFalse((self.root / 'raw/objects').exists())
        self.assertFalse((self.root / 'raw/manifests').exists())

    def test_hardlink_with_new_name_is_refused_by_signature(self):
        source = self.put('workspace/Javis-Vault/personal.kdbx', HEADERS[0] + MARKER)
        renamed = self.root / 'config/innocent.bin'
        os.link(source, renamed)
        with self.assertRaises(CredentialFileBlocked):
            safe_file_bytes(renamed)
        self.assertEqual(list(backup.files(self.root)), [])

    def test_backup_excludes_named_renamed_vaults_and_keeps_regular_data(self):
        for name in NAMES:
            self.put('config/' + name, MARKER)
        self.put('workspace/Javis-Vault/recovery.txt', MARKER)
        for n, header in enumerate(HEADERS):
            self.put(f'config/renamed-{n}.bin', header + MARKER)
        expected = {'config/rules.json': b'{"synthetic":true}',
                    'docs/vault-guide.md': b'Public vault instructions',
                    'docs/Javis-Vault.md': b'Public setup notes'}
        for name, data in expected.items():
            self.put(name, data)
        self.assertEqual({rel for _, rel in backup.files(self.root)}, set(expected))
        result = backup.create_backup(self.root, self.base / 'destination', restore_check=True)
        self.assertEqual(result['status'], 'success', result)
        restored = self.base / 'restore'
        manifest = backup.verify(result['archive'], restored)
        self.assertEqual({r['path'] for r in manifest['files']}, set(expected))
        for name, data in expected.items():
            self.assertEqual((restored / name).read_bytes(), data)

    def test_backup_refuses_vault_swapped_in_after_inventory(self):
        source = self.put('config/ordinary.bin', b'ordinary')
        original = Path.read_bytes
        def swapped(path):
            return HEADERS[0] + MARKER if path == source else original(path)
        with patch.object(Path, 'read_bytes', new=swapped):
            result = backup.create_backup(self.root, self.base / 'destination')
        self.assertEqual(result['status'], 'failed')
        self.assertIn('vault or linked source appeared', result['failure_reason'])
        self.assertFalse(list((self.base / 'destination').glob('*.tar.gz*')))

    def test_gitignore_covers_compound_names_and_vault_directory(self):
        repo = self.base / 'git-fixture'
        repo.mkdir()
        shutil.copy2(GUARDS / '.gitignore', repo / '.gitignore')
        subprocess.run(['git', 'init', '-q', str(repo)], check=True, capture_output=True)
        excluded = ['config/' + name for name in NAMES]
        excluded += ['nested/Javis-Vault/recovery.txt', 'nested/javis-vault/anything.bin']
        ordinary = ['docs/vault-guide.md', 'scripts/vault-policy.py', 'docs/Javis-Vault.md']
        result = subprocess.run(['git', '-c', 'core.ignoreCase=false', 'check-ignore', '--stdin'],
                                cwd=repo, input='\n'.join(excluded + ordinary) + '\n',
                                capture_output=True, text=True, check=True)
        self.assertEqual(set(result.stdout.splitlines()), set(excluded))

    def test_runner_does_not_deliver_renamed_vault_or_add_raw_object(self):
        # Source-only isolated fixture; no real model, database or credential reads.
        shutil.copytree(CODE / 'scripts', self.root / 'scripts')
        shutil.copy2(GUARDS / 'scripts/raw_policy.py', self.root / 'scripts/raw_policy.py')
        for tool in ('memory-adapter', 'raw-index'):
            base = CODE / 'tools' / tool
            for path in base.rglob('*.py'):
                rel = path.relative_to(base)
                if any(p in {'.venv', 'venv', '__pycache__'} for p in rel.parts):
                    continue
                target = self.root / 'tools' / tool / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
        (self.root / 'workspace/roles/gpt-star').mkdir(parents=True)
        fake = self.base / 'fake-codex'
        fake.write_text(FAKE, encoding='utf-8')
        fake.chmod(0o755)
        packet = self.base / 'packet.json'
        packet.write_text(json.dumps({'task_id':'vault-synthetic', 'role_id':'gpt-star',
                                     'goal':'Produce a synthetic test artifact', 'from_agent_id':'synthetic'}))
        exchange = self.base / 'exchange'
        env = {**os.environ, 'JAVIS_ROOT':str(self.root), 'JAVIS_CODEX_BIN':str(fake),
               'JAVIS_EXCHANGE_ROOT':str(exchange), 'JAVIS_MEMORY_GRAPH_DISABLED':'1',
               'PYTHONDONTWRITEBYTECODE':'1', 'JAVIS_TASK_TIMEOUT':'20'}
        run = subprocess.run(['bash', str(self.root / 'scripts/gpt-star-run.sh'), '--packet', str(packet)],
                             env=env, capture_output=True, text=True, timeout=35)
        task = self.root / 'workspace/tasks/vault-synthetic'
        result = json.loads((task / 'result.json').read_text())
        self.assertEqual(run.returncode, 74)
        self.assertEqual(result['status'], 'recording_error')
        self.assertEqual(result['artifacts'], [])
        self.assertFalse(any(p.is_file() for p in exchange.rglob('*')))
        digest = hashlib.sha256(HEADERS[0] + MARKER).hexdigest()
        self.assertFalse((self.root / 'raw/objects' / digest).exists())
        combined = '\n'.join(p.read_text() for p in (self.root / 'raw/events').glob('*.jsonl'))
        self.assertNotIn(MARKER.decode(), combined)
        self.assertIn('vault_signature_excluded', json.dumps(result))


if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout, verbosity=2))
