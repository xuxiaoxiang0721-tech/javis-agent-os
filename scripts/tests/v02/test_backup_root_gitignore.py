"""Small synthetic fixtures for the explicit root .gitignore backup allowlist."""
import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

CODE = Path(os.environ.get('JAVIS_TEST_CODE_ROOT', Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(CODE / 'scripts'))
spec = importlib.util.spec_from_file_location('backup_root_gitignore', CODE / 'scripts/javis-backup.py')
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class RootGitignoreBackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='javis-root-ignore-test-')
        self.base = Path(self.tmp.name)
        self.root = self.base / 'javis'
        self.root.mkdir()
        self.dest = self.base / 'backup'

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, relative, data=b'SYNTHETIC_ONLY'):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_backup(self):
        result = backup.create_backup(self.root, self.dest, restore_check=True)
        self.assertEqual(result['status'], 'success', result)
        restored = self.base / 'restored'
        manifest = backup.verify(result['archive'], restored)
        return manifest, restored

    def test_root_gitignore_is_restored_byte_for_byte_and_declared(self):
        original = b'# Synthetic rules\r\n*.kdbx\r\nJavis-Vault/\r\n'
        self.put('.gitignore', original)
        self.put('config/rules.json', b'{"synthetic":true}')
        manifest, restored = self.run_backup()
        rows = [row for row in manifest['files'] if row['path'] == '.gitignore']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['sha256'], hashlib.sha256(original).hexdigest())
        self.assertIn('.gitignore', manifest['includes'])
        self.assertEqual((restored / '.gitignore').read_bytes(), original)
        self.assertTrue((restored / 'config/rules.json').is_file())

    def test_absent_gitignore_remains_compatible(self):
        self.put('config/rules.json', b'{}')
        manifest, restored = self.run_backup()
        self.assertNotIn('.gitignore', {row['path'] for row in manifest['files']})
        self.assertFalse((restored / '.gitignore').exists())
        self.assertEqual((restored / 'config/rules.json').read_bytes(), b'{}')

    def test_gitignore_directory_is_not_traversed(self):
        self.put('.gitignore/ordinary.txt')
        self.put('.gitignore/nested/another.txt')
        manifest, restored = self.run_backup()
        self.assertFalse(any(row['path'].startswith('.gitignore') for row in manifest['files']))
        self.assertFalse((restored / '.gitignore').exists())

    def test_allowlist_does_not_expand_to_other_root_hidden_files(self):
        self.put('.gitignore', b'*.kdbx\n')
        for name in ['.env', '.env.production', '.auth/session.json', '.ssh/id_rsa',
                     '.codex/auth.json', '.unlisted', '.gitignore.bak',
                     'auth.json', 'credentials.json', 'Javis-Vault/personal.kdbx']:
            self.put(name)
        # Existing selected directories must retain their credential exclusions.
        for name in ['.env', 'auth.json', 'credentials.json', 'private.key', 'personal.kdbx']:
            self.put('config/' + name)
        manifest, restored = self.run_backup()
        self.assertEqual({row['path'] for row in manifest['files']}, {'.gitignore'})
        self.assertEqual({str(p.relative_to(restored)) for p in restored.rglob('*')}, {'.gitignore'})

    def test_root_gitignore_symlink_is_not_opened(self):
        target = self.base / 'synthetic-private.txt'
        target.write_bytes(b'SYNTHETIC_PRIVATE_ONLY')
        (self.root / '.gitignore').symlink_to(target)
        with patch.object(Path, 'open', side_effect=AssertionError('must not open linked content')):
            self.assertEqual(list(backup.files(self.root)), [])

    def test_root_gitignore_vault_signature_and_hardlink_are_excluded(self):
        target = self.put('Javis-Vault/personal.kdbx', bytes.fromhex('03d9a29a67fb4bb5') + b'SYNTHETIC')
        ignore = self.root / '.gitignore'
        for hardlink in (False, True):
            with self.subTest(hardlink=hardlink):
                if hardlink:
                    os.link(target, ignore)
                else:
                    ignore.write_bytes(target.read_bytes())
                self.assertEqual(list(backup.files(self.root)), [])
                ignore.unlink()

    def test_destination_cannot_occupy_explicit_root_file(self):
        for relative in ('.gitignore', '.gitignore/nested-backup'):
            with self.subTest(relative=relative):
                result = backup.create_backup(self.root, self.root / relative)
                self.assertEqual(result['status'], 'failed', result)
                self.assertIn('outside included source', result['failure_reason'])
                self.assertFalse((self.root / '.gitignore').exists())

    def test_concurrent_gitignore_write_fails_without_published_archive(self):
        source = self.put('.gitignore', b'*.kdbx\n')
        original = tarfile.TarFile.addfile
        def add_then_change(archive, info, *args, **kwargs):
            result = original(archive, info, *args, **kwargs)
            if info.name == '.gitignore':
                source.write_bytes(b'changed synthetic rules\n')
            return result
        with patch.object(tarfile.TarFile, 'addfile', new=add_then_change):
            result = backup.create_backup(self.root, self.dest)
        self.assertEqual(result['status'], 'failed', result)
        self.assertIn('concurrent source write', result['failure_reason'])
        self.assertFalse(list(self.dest.glob('*.tar.gz*')))

    def test_restore_rejects_gitignore_link_members(self):
        archive_path = self.base / 'untrusted.tar.gz'
        for member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(member_type=member_type):
                manifest = {'files': [{'path': '.gitignore', 'sha256': hashlib.sha256(b'').hexdigest(), 'bytes': 0}]}
                with tarfile.open(archive_path, 'w:gz') as archive:
                    info = tarfile.TarInfo('.gitignore')
                    info.type = member_type
                    info.linkname = '../outside'
                    archive.addfile(info)
                    data = json.dumps(manifest).encode()
                    info = tarfile.TarInfo('MANIFEST.json')
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
                with self.assertRaisesRegex(ValueError, 'must be a regular file'):
                    backup.verify(archive_path, self.base / 'restore-untrusted')
        self.assertFalse((self.base / 'outside').exists())


if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout, verbosity=2))
