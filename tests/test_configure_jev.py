"""Temporary-file tests for the interactive helper; never use production keys."""
from contextlib import redirect_stdout, redirect_stderr
import importlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / "scripts"))
import configure_jev as cfg
from jev_client import _read_key_file, credentials_status

KEY = "synthetic-typesafe-key-only-for-test"


class ConfigureJevTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.tmp.cleanup()

    def invoke(self, args, key=KEY, tty=True, resume=0):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), \
                patch.object(cfg.sys.stdin, "isatty", return_value=tty), \
                patch.object(errors, "isatty", return_value=tty), \
                patch.object(cfg.getpass, "getpass", return_value=key) as prompt, \
                patch.object(cfg, "_resume_rejected", **({"side_effect": resume} if isinstance(resume, Exception)
                                                        else {"return_value": resume})):
            code = cfg.main(["--root", str(self.root), *args])
        self.assertNotIn(KEY, output.getvalue() + errors.getvalue())
        return code, json.loads(output.getvalue()), prompt

    def key_path(self):
        return self.root / "tools/typesafe/.env"

    def existing(self, text="TYPESAFE_API_KEY='synthetic-old-key'\n"):
        path = self.key_path()
        path.parent.mkdir(parents=True, mode=0o700)
        path.write_text(text)
        path.chmod(0o600)
        return path

    def test_status_and_import_have_no_write_side_effects(self):
        with patch.object(cfg.os, "open") as opening, patch.object(cfg.getpass, "getpass") as prompt:
            importlib.reload(cfg)
            opening.assert_not_called()
            prompt.assert_not_called()
        code, result, prompt = self.invoke(["--status"])
        self.assertEqual(code, 0)
        self.assertEqual(result, {"configured": False, "status": "not_configured"})
        self.assertEqual(list(self.root.iterdir()), [])
        prompt.assert_not_called()

    def test_hidden_key_creates_private_file_and_directory_without_backup(self):
        code, result, prompt = self.invoke(["--set-key"])
        self.assertEqual(code, 0)
        self.assertEqual(result, {"configured": True, "status": "configured", "key_saved": True,
                                  "resumed": 0, "resume_status": "resumed"})
        prompt.assert_called_once()
        path = self.key_path()
        self.assertEqual(_read_key_file(path), KEY)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual([p.name for p in path.parent.iterdir()], [".env"])
        self.assertNotIn("TYPESAFE_API_KEY", os.environ)

    def test_existing_key_replaced_atomically_and_fsynced_without_backup(self):
        path = self.existing()
        inode = path.stat().st_ino
        with patch.object(cfg.os, "fsync", wraps=os.fsync) as fsync, patch.object(cfg.os, "replace", wraps=os.replace) as replace:
            code, result, _ = self.invoke(["--set-key"])
        self.assertEqual(code, 0)
        self.assertTrue(result["configured"])
        self.assertNotEqual(path.stat().st_ino, inode)
        self.assertGreaterEqual(fsync.call_count, 3)
        replace.assert_called_once()
        self.assertTrue(replace.call_args.args[0].startswith(".env.jev-key-"))
        self.assertEqual(sorted(p.name for p in path.parent.iterdir()), [".env"])
        self.assertNotIn("synthetic-old-key", path.read_text())

    def test_non_tty_refuses_before_input_or_filesystem_write(self):
        code, result, prompt = self.invoke(["--set-key"], tty=False)
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "jev_key_input_requires_tty")
        prompt.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_placeholder_and_control_characters_never_write(self):
        for key in ("", "YOUR_API_KEY", "<your-key>", "abc\n", "abc\r", "abc\t", "a\0b", "a\x7fb"):
            code, result, _ = self.invoke(["--set-key"], key=key)
            self.assertEqual((code, result["status"]), (1, "jev_invalid_api_key"))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cancel_and_getpass_echo_fallback_are_safe(self):
        for side_effect, expected in ((KeyboardInterrupt, "jev_key_input_cancelled"),
                                      (EOFError, "jev_key_input_cancelled")):
            output = io.StringIO()
            with redirect_stdout(output), patch.object(cfg.sys.stdin, "isatty", return_value=True), \
                    patch.object(cfg.sys.stderr, "isatty", return_value=True), \
                    patch.object(cfg.getpass, "getpass", side_effect=side_effect):
                code = cfg.main(["--root", str(self.root), "--set-key"])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue())["status"], expected)

        def echoed_input(*args):
            warnings.warn("echo fallback " + KEY, cfg.getpass.GetPassWarning)
            self.fail("echo fallback must be stopped by warning filter")

        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), patch.object(cfg.sys.stdin, "isatty", return_value=True), \
                patch.object(errors, "isatty", return_value=True), patch.object(cfg.getpass, "getpass", side_effect=echoed_input):
            code = cfg.main(["--root", str(self.root), "--set-key"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "jev_hidden_input_unavailable")
        self.assertNotIn(KEY, output.getvalue() + errors.getvalue())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_command_line_key_argument_is_rejected_without_echo(self):
        for args in (["--set-key", "--key", KEY], ["--set-key", KEY], ["--set-key=" + KEY]):
            errors = io.StringIO()
            with redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
                cfg.main(args)
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(errors.getvalue(), "jev_invalid_arguments\n")
            self.assertNotIn(KEY, errors.getvalue())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_symlink_target_and_hardlink_are_refused_without_changing_original(self):
        path = self.existing()
        original = path.read_bytes()
        other = self.root / "other-secret"
        os.link(path, other)
        code, result, _ = self.invoke(["--set-key"])
        self.assertEqual((code, result["status"]), (1, "jev_unsafe_credentials_path"))
        self.assertEqual(other.read_bytes(), original)
        path.unlink()
        path.symlink_to(other)
        code, _, _ = self.invoke(["--set-key"])
        self.assertEqual(code, 1)
        self.assertEqual(other.read_bytes(), original)

    def test_symlink_directory_is_refused(self):
        target = self.root / "target"
        target.mkdir()
        (self.root / "tools").symlink_to(target, target_is_directory=True)
        code, result, _ = self.invoke(["--set-key"])
        self.assertEqual((code, result["status"]), (1, "jev_credentials_write_failed"))
        self.assertEqual(list(target.iterdir()), [])

    def test_foreign_owner_or_readable_key_is_refused(self):
        path = self.existing()
        original = path.read_bytes()
        with patch.object(cfg.os, "geteuid", return_value=os.geteuid() + 1):
            code, result, _ = self.invoke(["--set-key"])
        self.assertEqual((code, result["status"]), (1, "jev_unsafe_credentials_path"))
        path.chmod(0o644)
        code, result, _ = self.invoke(["--set-key"])
        self.assertEqual((code, result["status"]), (1, "jev_unsafe_credentials_path"))
        self.assertEqual(path.read_bytes(), original)

    def test_failed_replace_keeps_old_file_removes_temporary_and_sanitizes_error(self):
        path = self.existing()
        original = path.read_bytes()
        with patch.object(cfg.os, "replace", side_effect=OSError(KEY)):
            code, result, _ = self.invoke(["--set-key"])
        self.assertEqual((code, result["status"]), (1, "jev_credentials_write_failed"))
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual([p.name for p in path.parent.iterdir()], [".env"])

    def test_environment_override_not_mutated_or_misreported(self):
        os.environ["TYPESAFE_API_KEY"] = ""
        code, result, _ = self.invoke(["--set-key"])
        self.assertEqual(code, 0)
        self.assertFalse(result["configured"])
        self.assertEqual(result["status"], "not_configured")
        self.assertTrue(result["key_saved"])
        self.assertEqual(os.environ["TYPESAFE_API_KEY"], "")
        self.assertEqual(_read_key_file(self.key_path()), KEY)

    def test_successful_write_reports_resumed_count(self):
        code, result, _ = self.invoke(["--set-key"], resume=3)
        self.assertEqual(code, 0)
        self.assertEqual(result["resumed"], 3)
        self.assertTrue(result["key_saved"])

    def test_resume_failure_does_not_claim_saved_key_was_lost(self):
        code, result, _ = self.invoke(["--set-key"], resume=RuntimeError(KEY))
        self.assertEqual(code, 1)
        self.assertEqual(result, {"configured": True, "status": "configured", "key_saved": True,
                                  "resumed": None, "resume_status": "resumed_error"})
        self.assertEqual(_read_key_file(self.key_path()), KEY)

    def test_real_queue_resume_is_local_and_preserves_attempt_audit(self):
        folder = self.root / "state/memory-pipeline/queue"
        folder.mkdir(parents=True)
        original = {"queue_id": "synthetic_rejected", "status": "credentials_rejected", "event_id":"synthetic-event",
                    "attempts": 7, "provider_attempts": 2, "scope": "cards-master",
                    "next_attempt_at": 123, "last_result": {"status": "credentials_rejected"}}
        path = folder / "synthetic_rejected.json"
        path.write_text(json.dumps(original))
        untouched = folder / "synthetic_review.json"
        untouched.write_text(json.dumps({**original, "queue_id": "synthetic_review", "status": "needs_review"}))
        import jev_client
        with patch.object(jev_client, "build_opener", side_effect=AssertionError("No network allowed")):
            self.assertEqual(cfg._resume_rejected(self.root), 1)
        result = json.loads(path.read_text())
        self.assertEqual(result["status"], "queued")
        self.assertEqual(result["attempts"], 7)
        self.assertEqual(result["provider_attempts"], 0)
        self.assertEqual(result["next_attempt_at"], 0)
        self.assertEqual(result["last_result"], original["last_result"])
        self.assertEqual(json.loads(untouched.read_text())["status"], "needs_review")


if __name__ == "__main__":
    unittest.main()
