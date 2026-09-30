"""Offline transport/credential tests: no provider API is contacted."""
import asyncio
from email.message import Message
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, build_opener as real_build_opener
from urllib.response import addinfourl

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / "scripts"))
sys.path.insert(0, str(CODE / "tools/memory-adapter"))
import jev_client as jc
from javis_memory_adapter import usage_meter as um

KEY = "synthetic-test-secret-never-a-real-key"
MODEL = "jev-1.13.0"
QUESTIONS = {"supported": {"type": "noul", "instructions": "Is the candidate supported?"}}
RESULT = {"model": MODEL, "answers": {"supported": {"type": "noul", "noul": 0.98}},
          "usage": {"input_tokens": 27, "output_tokens": 0}}


class FakeResponse(io.BytesIO):
    def __init__(self, result=RESULT, status=200, headers=None):
        data = result if isinstance(result, bytes) else json.dumps(result).encode()
        super().__init__(data)
        self.status = status
        self.headers = headers or {"x-typesafe-request-id": "synthetic-request-id"}


class JevClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        from memory_controls import update
        update(self.root, 0, global_enabled=True, command_id='synthetic-enable')
        self.environment = patch.dict(os.environ, {"TYPESAFE_API_KEY": KEY}, clear=True)
        self.environment.start()
        self.client = jc.JevClient(self.root, run_id="synthetic_run", scope="cards-master")

    def tearDown(self):
        self.environment.stop()
        self.tmp.cleanup()

    def evaluate(self, client=None, **overrides):
        args = dict(state={"source": "Synthetic source"}, questions=QUESTIONS, model=MODEL, stage="screening")
        args.update(overrides)
        return asyncio.run((client or self.client).evaluate(**args))

    def request(self, result=RESULT, **overrides):
        opener = Mock()
        opener.open.return_value = FakeResponse(result)
        with patch.object(jc, "build_opener", return_value=opener):
            response = self.evaluate(**overrides)
        return response, opener

    def rows(self):
        path = self.root / "memory/usage/requests.jsonl"
        return [] if not path.exists() else [json.loads(line) for line in path.read_text().splitlines()]

    def key_file(self, contents=None):
        path = self.root / "tools/typesafe/.env"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents if contents is not None else "TYPESAFE_API_KEY='" + KEY + "'\n")
        path.chmod(0o600)
        os.environ.pop("TYPESAFE_API_KEY", None)
        return path

    def test_real_wire_shape_fixed_endpoint_and_usage(self):
        result, opener = self.request()
        req = opener.open.call_args.args[0]
        self.assertEqual(req.full_url, "https://api.typesafe.ai/v1/systemone")
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.get_header("Authorization"), "Bearer " + KEY)
        self.assertEqual(json.loads(req.data), {"model": MODEL, "state": {"source": "Synthetic source"}, "questions": QUESTIONS})
        self.assertEqual(result, RESULT)
        self.assertEqual(len(self.rows()), 2)
        row = um.recent(self.root)[0]
        self.assertEqual(row["provider_host"], "api.typesafe.ai")
        self.assertEqual(row["tokens"]["input"], 27)
        self.assertEqual(row["tokens"]["output"], 0)
        self.assertEqual(row["actual_model"], MODEL)
        self.assertEqual(row["provider_request_id"], "synthetic-request-id")
        self.assertNotIn(KEY, json.dumps(self.rows()))
        self.assertNotIn("Synthetic source", json.dumps(self.rows()))

    def test_no_key_no_network_or_meter_start_and_no_qwen_fallback(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        os.environ.pop("TYPESAFE_API_KEY")
        os.environ.update(OPENAI_API_KEY=KEY, LLM_API_KEY=KEY, JEV_API_KEY=KEY,
                          OPENAI_BASE_URL="https://other.invalid", JEV_BASE_URL="https://other.invalid")
        with patch.object(jc, "build_opener") as opener, patch.object(self.client.meter, "start") as start:
            with self.assertRaisesRegex(jc.JevNotConfigured, "^jev_credentials_unconfigured$"):
                self.evaluate()
            opener.assert_not_called()
            start.assert_not_called()
        self.assertEqual({str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}, before)

    def test_empty_or_placeholder_environment_disables_file_fallback(self):
        self.key_file()
        for value in ("", "   ", "YOUR_API_KEY", "your-typesafe-api-key", "<your-key>", "${TYPESAFE_API_KEY}", "..."):
            os.environ["TYPESAFE_API_KEY"] = value
            self.assertEqual(jc.credentials_status(self.root), {"configured": False, "status": "not_configured"})
            with patch.object(self.client.meter, "start") as start:
                with self.assertRaises(jc.JevNotConfigured):
                    self.evaluate()
                start.assert_not_called()

    def test_private_dotenv_parse_without_environment_mutation(self):
        self.key_file("# private config\nexport TYPESAFE_API_KEY=\"" + KEY + "\" # local comment\n")
        before = dict(os.environ)
        self.assertEqual(jc.credentials_status(self.root), {"configured": True, "status": "configured"})
        self.request()
        self.assertEqual(dict(os.environ), before)

    def test_dotenv_rejects_duplicate_other_fields_shell_and_bad_quotes(self):
        for text in ("TYPESAFE_API_KEY=x\nTYPESAFE_API_KEY=y", "OPENAI_API_KEY=x", "TYPESAFE_API_KEY='abc", "eval $(bad)"):
            self.key_file(text)
            self.assertEqual(jc.credentials_status(self.root), {"configured": False, "status": "invalid_credentials_file"})
        self.key_file("TYPESAFE_API_KEY=${SECRET}")
        self.assertFalse(jc.credentials_status(self.root)["configured"])

    def test_dotenv_links_readable_modes_and_foreign_owner_are_rejected(self):
        path = self.key_file()
        path.chmod(0o644)
        self.assertEqual(jc.credentials_status(self.root)["status"], "unsafe_credentials_file")
        path.chmod(0o600)
        with patch.object(jc.os, "geteuid", return_value=os.geteuid() + 1):
            self.assertEqual(jc.credentials_status(self.root)["status"], "unsafe_credentials_file")
        other = self.root / "linked"
        os.link(path, other)
        self.assertEqual(jc.credentials_status(self.root)["status"], "unsafe_credentials_file")
        other.unlink()
        path.rename(other)
        path.symlink_to(other)
        self.assertEqual(jc.credentials_status(self.root)["status"], "unsafe_credentials_file")
        with patch.object(self.client.meter, "start") as start:
            with self.assertRaises(jc.JevNotConfigured):
                self.evaluate()
            start.assert_not_called()

    def test_symlink_parent_rejected_and_status_never_initializes_meter(self):
        path = self.key_file()
        actual = self.root / "actual"
        path.parent.rename(actual)
        path.parent.symlink_to(actual, target_is_directory=True)
        self.assertEqual(jc.credentials_status(self.root), {"configured": False, "status": "unsafe_credentials_file"})
        self.assertFalse((self.root / "memory").exists())

    def test_env_path_cannot_read_a_different_provider_file(self):
        os.environ.pop("TYPESAFE_API_KEY")
        other = self.root / "tools/graphiti/.env"
        client = jc.JevClient(self.root, env_path=other)
        with patch.object(jc, "_read_key_file") as read, patch.object(client.meter, "start") as start:
            with self.assertRaises(jc.JevNotConfigured):
                self.evaluate(client=client)
            read.assert_not_called()
            start.assert_not_called()

    def test_start_failure_prevents_network(self):
        with patch.object(self.client.meter, "start", side_effect=OSError("journal unavailable")), patch.object(jc, "build_opener") as opener:
            with self.assertRaises(OSError):
                self.evaluate()
            opener.assert_not_called()

    def test_finish_failure_returns_paid_response_and_retains_pending(self):
        with patch.object(self.client.meter, "finish", side_effect=OSError(KEY)), self.assertLogs(jc.__name__, level="WARNING") as logs:
            result, opener = self.request()
        self.assertEqual(result, RESULT)
        opener.open.assert_called_once()
        self.assertNotIn(KEY, str(logs.output))
        self.assertEqual(um.recent(self.root)[0]["status"], "pending")

    def test_http_auth_transient_and_permanent_errors_are_sanitized_not_retried(self):
        for code, error in ((401, jc.JevAuthenticationError), (403, jc.JevAuthenticationError),
                            (429, jc.JevTransientError), (529, jc.JevTransientError), (500, jc.JevTransientError),
                            (400, jc.JevHTTPError)):
            headers = Message()
            headers["x-typesafe-request-id"] = "error-request-id"
            exc = HTTPError(jc.ENDPOINT, code, KEY, headers,
                            io.BytesIO(json.dumps({**RESULT, "error": KEY}).encode()))
            opener = Mock()
            opener.open.side_effect = exc
            with patch.object(jc, "build_opener", return_value=opener):
                with self.assertRaises(error) as raised:
                    self.evaluate()
            self.assertEqual(str(raised.exception), error.code)
            opener.open.assert_called_once()
        self.assertEqual(um.summary(self.root)["all"]["calls"], 6)
        self.assertEqual(um.summary(self.root)["all"]["tokens"]["input"], 27 * 6)
        self.assertNotIn(KEY, json.dumps(self.rows()))

    def test_redirect_does_not_forward_auth_to_another_host(self):
        visited = []

        class FakeHTTPS(HTTPSHandler):
            def https_open(self, req):
                visited.append(req.full_url)
                headers = Message()
                headers["Location"] = "https://untrusted.invalid/steal"
                response = addinfourl(io.BytesIO(b"redirect " + KEY.encode()), headers, req.full_url, 302)
                response.msg = "Found"
                return response

        def opener(*handlers):
            return real_build_opener(*handlers, FakeHTTPS())

        with patch.object(jc, "build_opener", side_effect=opener):
            with self.assertRaisesRegex(jc.JevHTTPError, "^jev_http_error$"):
                self.evaluate()
        self.assertEqual(visited, [jc.ENDPOINT])
        self.assertEqual(um.recent(self.root)[0]["http_status"], 302)
        self.assertNotIn(KEY, json.dumps(self.rows()))

    def test_transport_timeout_is_unknown_usage_not_zero(self):
        for error in (TimeoutError(KEY), URLError(KEY)):
            opener = Mock()
            opener.open.side_effect = error
            with patch.object(jc, "build_opener", return_value=opener):
                with self.assertRaisesRegex(jc.JevTransientError, "^jev_transient_error$"):
                    self.evaluate()
            opener.open.assert_called_once()
        row = um.recent(self.root)[0]
        self.assertEqual(row["status"], "transport_error")
        self.assertIsNone(row["tokens"]["total"])
        self.assertFalse(row["usage_known"])

    def test_missing_usage_is_success_with_unknown_accounting(self):
        result, _ = self.request({"model": MODEL, "answers": RESULT["answers"]})
        self.assertNotIn("usage", result)
        row = um.recent(self.root)[0]
        self.assertEqual(row["status"], "success")
        self.assertIsNone(row["tokens"]["total"])

    def test_invalid_or_oversized_response_is_recorded_once(self):
        for response in (b"not json " + KEY.encode(), b"x" * (jc.MAX_RESPONSE_BYTES + 1),
                         {"model": MODEL, "answers": [], "usage": RESULT["usage"]}):
            with self.assertRaisesRegex(jc.JevInvalidResponse, "^jev_invalid_response$"):
                self.request(response)
        self.assertEqual(len(self.rows()), 6)
        self.assertNotIn(KEY, json.dumps(self.rows()))
        self.assertTrue(all(row["status"] == "invalid_response" for row in um.recent(self.root)))

    def test_metadata_is_whitelisted_not_provider_body(self):
        result = {**RESULT, "secret": KEY, "usage": {**RESULT["usage"], "prompt": KEY}, "id": KEY}
        self.request(result)
        self.assertNotIn(KEY, json.dumps(self.rows()))

    def test_byte_limits_and_invalid_json_prevent_accounting_and_network(self):
        cases = [({"state": "\u4e2d" * 10000}, jc.JevRequestTooLarge),
                 ({"questions": {str(i): {"type": "noul", "instructions": "x" * 1000} for i in range(60)}}, jc.JevRequestTooLarge),
                 ({"state": {"bad": float("nan")}}, jc.JevInvalidRequest),
                 ({"questions": {}}, jc.JevInvalidRequest),
                 ({"model": "invalid model " + KEY}, jc.JevInvalidRequest)]
        with patch.object(self.client.meter, "start") as start, patch.object(jc, "build_opener") as opener:
            for kwargs, expected in cases:
                with self.assertRaises(expected):
                    self.evaluate(**kwargs)
            start.assert_not_called()
            opener.assert_not_called()

    def test_cancellation_still_records_actual_thread_response(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        original_finish = self.client.meter.finish

        def finish(*args, **kwargs):
            result = original_finish(*args, **kwargs)
            finished.set()
            return result

        def open_request(*args, **kwargs):
            entered.set()
            if not release.wait(3):
                raise TimeoutError("test wait expired")
            return FakeResponse()

        async def scenario():
            task = asyncio.create_task(self.client.evaluate("synthetic", QUESTIONS, model=MODEL, stage="screening"))
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            release.set()
            self.assertTrue(await asyncio.to_thread(finished.wait, 2))

        opener = Mock()
        opener.open.side_effect = open_request
        try:
            with patch.object(jc, "build_opener", return_value=opener), patch.object(self.client.meter, "finish", side_effect=finish):
                asyncio.run(scenario())
        finally:
            release.set()
        self.assertEqual(um.recent(self.root)[0]["tokens"]["input"], 27)
        self.assertEqual(len(self.rows()), 2)


if __name__ == "__main__":
    unittest.main()
