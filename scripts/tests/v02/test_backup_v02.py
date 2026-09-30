"""Synthetic backup/schedule regression tests. Never targets the live Javis root."""
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

SCRIPTS=Path(os.environ.get('JAVIS_TEST_CODE_ROOT',Path(__file__).resolve().parent))/'scripts'
sys.path.insert(0,str(SCRIPTS))
spec=importlib.util.spec_from_file_location('backup',SCRIPTS/'javis-backup.py')
backup=importlib.util.module_from_spec(spec); spec.loader.exec_module(backup)


def moment(value): return datetime.fromisoformat(value).replace(tzinfo=backup.TZ)


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='javis-backup-v02-test-')
        self.base=Path(self.temp.name); self.root=self.base/'javis'; self.dest=self.base/'destination'
        (self.root/'raw/events').mkdir(parents=True)
        (self.root/'state').mkdir()
        (self.root/'raw/events/synthetic.jsonl').write_text('{"synthetic":true}\n')
        self.clock=patch.object(backup,'now',return_value=moment('2026-09-18T04:00:00'))
        self.clock.start()

    def tearDown(self): self.clock.stop(); self.temp.cleanup()

    def run_backup(self,**kwargs): return backup.create_backup(self.root,self.dest,**kwargs)

    def test_schedule_boundaries_and_timezone(self):
        for current,expected in [
            ('2026-09-18T03:14:59','2026-09-17T15:15:00'),
            ('2026-09-18T03:15:00','2026-09-18T03:15:00'),
            ('2026-09-18T15:14:59','2026-09-18T03:15:00'),
            ('2026-09-18T15:15:00','2026-09-18T15:15:00')]:
            with self.subTest(current=current): self.assertEqual(backup.scheduled_slot(moment(current)),moment(expected))
        self.assertEqual(backup.scheduled_slot(datetime.fromisoformat('2026-09-18T07:15:00+00:00')),moment('2026-09-18T15:15:00'))

    def test_two_backups_and_login_dedup(self):
        self.assertEqual(self.run_backup(if_due=True)['status'],'success')
        self.assertEqual(self.run_backup(if_due=True)['status'],'skipped')
        with patch.object(backup,'now',return_value=moment('2026-09-18T15:16:00')):
            self.assertEqual(self.run_backup(if_due=True)['status'],'success')
            self.assertEqual(self.run_backup(if_due=True)['status'],'skipped')
        self.assertEqual(len(list(self.dest.glob('*.tar.gz'))),2)

    def test_missed_days_catch_up_only_once(self):
        self.run_backup()
        with patch.object(backup,'now',return_value=moment('2026-09-23T19:00:00')):
            self.assertEqual(self.run_backup(if_due=True)['status'],'success')
            self.assertEqual(self.run_backup(if_due=True)['status'],'skipped')
        self.assertEqual(len(list(self.dest.glob('*.tar.gz'))),2)

    def test_crossed_slot_uses_snapshot_start_not_finish(self):
        self.run_backup()
        latest=json.loads((self.dest/'latest.json').read_text())
        latest.update(created_at='2026-09-18T15:14:00+08:00',success_at='2026-09-18T15:16:00+08:00')
        (self.dest/'latest.json').write_text(json.dumps(latest))
        self.assertTrue(backup.is_due(self.dest,moment('2026-09-18T15:17:00')))

    def test_missing_or_damaged_latest_is_due(self):
        self.run_backup()
        latest=json.loads((self.dest/'latest.json').read_text())
        Path(latest['archive']).unlink()
        self.assertTrue(backup.is_due(self.dest,moment('2026-09-18T04:00:00')))
        (self.dest/'latest.json').write_text('{invalid')
        self.assertTrue(backup.is_due(self.dest,moment('2026-09-18T04:00:00')))

    def test_success_and_failure_audit(self):
        result=self.run_backup(restore_check=True)
        self.assertEqual(result['status'],'success'); self.assertTrue(result['verified'])
        self.assertFalse(result['off_machine_backup_verified']); self.assertGreater(result['bytes'],0)
        self.assertEqual(result['timezone'],'Asia/Shanghai'); self.assertEqual(result['schedule'],['03:15','15:15'])
        with patch.object(backup.shutil,'disk_usage',return_value=type('Disk',(),{'free':0})()):
            failure=self.run_backup()
        self.assertEqual(failure['status'],'failed'); self.assertIn('insufficient',failure['failure_reason'])
        self.assertEqual(json.loads((self.root/'state/backup/last-success.json').read_text())['run_id'],result['run_id'])
        rows=[json.loads(line) for line in (self.root/'state/backup/runs.jsonl').read_text().splitlines()]
        self.assertEqual([r['status'] for r in rows],['success','failed'])
        self.assertFalse(list(self.dest.glob('*.partial')))

    def test_missing_independent_destination_never_created(self):
        result=self.run_backup(destination_kind='independent_unverified')
        self.assertEqual(result['status'],'failed'); self.assertFalse(self.dest.exists())
        self.assertTrue((self.root/'state/backup/last-run.json').exists())

    def test_credentials_excluded_cursors_and_rules_retained(self):
        config=self.root/'config'; config.mkdir()
        for name in ['.env','.env.production','auth.json','credentials.json','private.key','private.pem']:
            (config/name).write_text('SYNTHETIC_SECRET_ONLY')
        (config/'rules.json').write_text('{"synthetic":true}')
        (self.root/'state/cursor.json').write_text('{"offset":4}')
        result=self.run_backup(restore_check=True); self.assertEqual(result['status'],'success')
        with tarfile.open(result['archive'],'r:gz') as archive:
            names=archive.getnames()
            self.assertIn('config/rules.json',names); self.assertIn('state/cursor.json',names)
            self.assertFalse(any(name.endswith('.lock') for name in names))
            self.assertFalse(any(b'SYNTHETIC_SECRET_ONLY' in archive.extractfile(name).read() for name in names))

    def test_sqlite_wal_restore_has_commits_not_uncommitted_rows(self):
        path=self.root/'state/tasks.sqlite'
        with sqlite3.connect(path) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('CREATE TABLE tasks(id INTEGER, goal TEXT)'); writer.commit()
            writer.execute("INSERT INTO tasks VALUES(1,'committed')"); writer.commit()
            writer.execute("INSERT INTO tasks VALUES(2,'uncommitted')")
            result=self.run_backup(restore_check=True)
            self.assertEqual(result['status'],'success',result)
            writer.rollback()
        restore=self.base/'restored'; manifest=backup.verify(result['archive'],restore)
        row=next(row for row in manifest['files'] if row['path']=='state/tasks.sqlite')
        self.assertEqual(row['snapshot_method'],'sqlite_online_backup')
        with sqlite3.connect(restore/'state/tasks.sqlite') as db:
            self.assertEqual(db.execute('SELECT * FROM tasks').fetchall(),[(1,'committed')])
        self.assertFalse(any(row['path'].endswith(('-wal','-shm')) for row in manifest['files']))

    def test_static_wal_database_read_only_open_is_not_reported_as_write(self):
        path=self.root/'state/imported.sqlite'
        with sqlite3.connect(path) as connection:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('CREATE TABLE sample(id INTEGER)')
            connection.execute('INSERT INTO sample VALUES(1)'); connection.commit()
        # sqlite3 connection context managers commit but do not close.
        connection.close()
        self.assertFalse(Path(str(path)+'-wal').exists())
        original=path.read_bytes(); stat=path.stat()
        result=self.run_backup(restore_check=True)
        self.assertEqual(path.read_bytes(),original)
        self.assertEqual(path.stat().st_mtime_ns,stat.st_mtime_ns)
        # A mode=ro connection may itself create an empty WAL/SHM on a DB
        # persisted in WAL mode. It does not create a committed transaction.
        wal=Path(str(path)+'-wal')
        self.assertTrue(not wal.exists() or wal.stat().st_size==0)
        self.assertEqual(result['status'],'success',result)

    def test_only_empty_wal_is_equivalent_to_missing(self):
        path=self.root/'state/synthetic.sqlite'
        wal=Path(str(path)+'-wal')
        before=backup.sqlite_sidecars(path)
        wal.write_bytes(b'')
        self.assertEqual(backup.sqlite_sidecars(path),before)
        wal.write_bytes(b'SYNTHETIC_NONEMPTY_WAL')
        self.assertNotEqual(backup.sqlite_sidecars(path),before)
        self.assertEqual(backup.sqlite_sidecars(path)['-wal'][0],len(b'SYNTHETIC_NONEMPTY_WAL'))

    def test_concurrent_sqlite_commit_fails_snapshot(self):
        path=self.root/'state/tasks.sqlite'
        with sqlite3.connect(path) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('CREATE TABLE tasks(id INTEGER)'); writer.commit()
            original=backup.sqlite_snapshot
            def snapshot_then_write(*args):
                data=original(*args); writer.execute('INSERT INTO tasks VALUES(3)'); writer.commit(); return data
            with patch.object(backup,'sqlite_snapshot',side_effect=snapshot_then_write): result=self.run_backup()
        self.assertEqual(result['status'],'failed'); self.assertIn('concurrent SQLite write',result['failure_reason'])
        self.assertFalse(list(self.dest.glob('*.tar.gz')))

    def test_previous_audit_records_are_backed_up(self):
        first=self.run_backup()
        with patch.object(backup,'now',return_value=moment('2026-09-18T15:16:00')):
            second=self.run_backup()
        restored=self.base/'audit-restore'; backup.verify(second['archive'],restored)
        self.assertEqual(json.loads((restored/'state/backup/last-success.json').read_text())['run_id'],first['run_id'])

    def test_destination_inside_source_is_rejected(self):
        result=backup.create_backup(self.root,self.root/'workspace/backups')
        self.assertEqual(result['status'],'failed'); self.assertIn('outside',result['failure_reason'])

    def test_concurrent_regular_write_fails_snapshot(self):
        original=tarfile.TarFile.addfile
        def add_then_write(archive,info,*args,**kwargs):
            result=original(archive,info,*args,**kwargs)
            if info.name=='raw/events/synthetic.jsonl': (self.root/info.name).write_text('{"changed":true}\n')
            return result
        with patch.object(tarfile.TarFile,'addfile',new=add_then_write): result=self.run_backup()
        self.assertEqual(result['status'],'failed'); self.assertIn('concurrent source write',result['failure_reason'])
        self.assertFalse(list(self.dest.glob('*.tar.gz')))

    def test_archive_corruption_and_unsafe_paths_rejected(self):
        path=self.base/'bad.tar.gz'
        for filename,expected_hash in [('../escape.txt',hashlib.sha256(b'hello').hexdigest()),('memory/value.txt','wrong-hash')]:
            with self.subTest(filename=filename):
                manifest={'files':[{'path':filename,'sha256':expected_hash,'bytes':5}]}
                with tarfile.open(path,'w:gz') as archive:
                    for name,data in [(filename,b'hello'),('MANIFEST.json',json.dumps(manifest).encode())]:
                        info=tarfile.TarInfo(name); info.size=len(data); archive.addfile(info,io.BytesIO(data))
                with self.assertRaises(ValueError): backup.verify(path,self.base/'restore-bad')
        self.assertFalse((self.base/'escape.txt').exists())


if __name__=='__main__': unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout,verbosity=2))
