#!/usr/bin/env python3
"""Isolated migration tests: no writes under real /etc, no service starts."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("migration", SCRIPT_DIR / "lifecycle-systemd.py")
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)
UNITS = SCRIPT_DIR.parent / "systemd"


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="javis-lifecycle-test-")
        self.etc = Path(self.temp.name) / "etc"
        self.etc.mkdir()
        self.original = b"# Preserve operator config\n[user]\ndefault=user\n[boot]\nsystemd=false\ncommand=/usr/local/bin/javis-neo4j-boot\n[automount]\nroot=/mnt/\n"
        (self.etc / "wsl.conf").write_bytes(self.original)
        self.backup = Path(self.temp.name) / "backup"

    def tearDown(self):
        self.temp.cleanup()

    def test_prepare_does_not_write_and_preserves_unrelated_settings(self):
        plan = migration.build_plan(self.etc, UNITS)
        self.assertEqual((self.etc / "wsl.conf").read_bytes(), self.original)
        self.assertIn("# Preserve operator config", plan["new_wsl_conf"])
        self.assertIn("[automount]\nroot=/mnt/", plan["new_wsl_conf"])
        self.assertIn("default=user", plan["new_wsl_conf"])
        self.assertFalse(plan["applied"])

    def test_foreign_boot_command_is_not_overwritten(self):
        (self.etc / "wsl.conf").write_text("[boot]\ncommand=/opt/operator-start.sh\n")
        with self.assertRaisesRegex(ValueError, "Unrecognized"):
            migration.build_plan(self.etc, UNITS)

    def test_file_changed_after_plan_rejects_apply(self):
        plan = migration.build_plan(self.etc, UNITS)
        (self.etc / "wsl.conf").write_bytes(self.original + b"# Concurrent change\n")
        with self.assertRaisesRegex(ValueError, "changed"):
            migration.apply_plan(self.etc, UNITS, plan, self.backup)
        self.assertFalse(self.backup.exists())

    def test_apply_and_rollback_restore_exact_previous_config(self):
        plan = migration.build_plan(self.etc, UNITS)
        installed = migration.apply_plan(self.etc, UNITS, plan, self.backup)
        self.assertTrue(installed["applied"])
        self.assertFalse(installed["restart_performed"])
        self.assertEqual((self.etc / "wsl.conf").stat().st_mode & 0o777, 0o644)
        for name in migration.UNITS:
            self.assertEqual((self.etc / "systemd/system/multi-user.target.wants" / name).resolve(), self.etc / "systemd/system" / name)
        migration.rollback(self.etc, self.backup)
        self.assertEqual((self.etc / "wsl.conf").read_bytes(), self.original)
        for name in migration.UNITS:
            self.assertFalse((self.etc / "systemd/system" / name).exists())

    def test_rollback_refuses_to_destroy_operator_edits(self):
        migration.apply_plan(self.etc, UNITS, migration.build_plan(self.etc, UNITS), self.backup)
        (self.etc / "wsl.conf").write_text("[boot]\nsystemd=true\n# operator edit\n")
        with self.assertRaisesRegex(ValueError, "changed"):
            migration.rollback(self.etc, self.backup)

    def test_foreign_unit_is_not_overwritten(self):
        directory = self.etc / "systemd/system"
        directory.mkdir(parents=True)
        (directory / migration.UNITS[0]).write_text("[Service]\nExecStart=/opt/operator-db\n")
        with self.assertRaisesRegex(ValueError, "Existing unit differs"):
            migration.build_plan(self.etc, UNITS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
