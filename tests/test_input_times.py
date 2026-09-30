"""Offline entry-time contract tests, using disposable RAW and no model calls."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / "scripts"))
from raw_time import source_timestamp, utc_timestamp, received_fields, native_time, normalize_time_fields
from raw_storage import append_event, normalize_event
from raw_cursor import ingest_jsonl
from task_service import ControlService, Principal, ControlError


def script(name, filename):
    spec = importlib.util.spec_from_file_location(name, CODE / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


grok = script("grok_time_test", "grok-sync.py")
replay = script("codex_time_test", "codex-log-to-raw.py")
NOW = "2026-09-25T03:04:05.123Z"
LATER = "2026-09-26T03:04:05.123Z"
PAST = "2024-02-29T10:11:12.123456789+08:00"


class InputTimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="javis-input-time-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def events(self):
        return [json.loads(line) for path in (self.root / "raw/events").rglob("*.jsonl")
                for line in path.read_text().splitlines() if line.strip()]

    def request(self):
        return {"capture_id": "synthetic-capture", "role_id": "invest", "messages": [
            {"speaker": "user", "text": "Synthetic supplied historical source", "fidelity": "forwarded_original_unverified"}]}

    def principal(self):
        return Principal("synthetic-owner", "owner", frozenset({"invest"}),
            frozenset({"task:create", "task:control", "task:read"}), "synthetic-proof")

    def test_complete_zoned_source_is_preserved_including_offset_and_nanoseconds(self):
        self.assertEqual(source_timestamp(PAST), PAST)
        self.assertEqual(utc_timestamp(PAST), "2024-02-29T02:11:12.123456789Z")
        self.assertEqual(source_timestamp("2026-09-25T00:00:00Z"), "2026-09-25T00:00:00Z")

    def test_invalid_naive_partial_nonfinite_or_unknown_offset_source_is_not_a_time(self):
        for value in (None, True, 123, "today", "2026-09-25", "2026-09-25T10:00:00", "2026-02-30T00:00:00Z",
                      "2026-09-25T24:00:00Z", "2026-09-25T00:00:00+01:60", "2026-09-25T00:00:00-00:00",
                      "2026-09-25T00:00:00Z\n", "9999-12-31T23:00:00-23:00"):
            with self.subTest(value=value):
                self.assertIsNone(source_timestamp(value))

    def test_default_raw_observation_is_utc_without_inventing_occurrence(self):
        with patch("raw_storage.now_iso", return_value=NOW):
            row = normalize_event({"event_type": "user_input", "payload": {"text": "synthetic"}})
        self.assertIsNone(row["occurred_at"])
        self.assertEqual((row["received_at"], row["captured_at"], row["time_basis"]), (NOW, NOW, "capture_only"))
        self.assertIn("original_event_timestamp_unavailable", row["missing_reason"])

    def test_invalid_source_clock_is_explicit_and_never_replaced_by_now(self):
        with patch("raw_storage.now_iso", return_value=NOW):
            row = normalize_event({"event_type": "user_input", "occurred_at": "2020-01-01T00:00:00",
                                   "captured_at": "bad", "received_at": "bad"})
        self.assertIsNone(row["occurred_at"])
        self.assertEqual(row["time_basis"], "source_time_invalid")
        self.assertEqual((row["received_at"], row["captured_at"]), (NOW, NOW))
        self.assertIn("original_event_timestamp_invalid", row["missing_reason"])
        self.assertEqual({item['field']: item['value'] for item in row['time_normalization_originals']},
            {'occurred_at':'2020-01-01T00:00:00','captured_at':'bad','received_at':'bad'})

    def test_invalid_time_evidence_preserves_existing_entries_and_is_idempotent(self):
        prior = {'field':'occurred_at','value':'older invalid clock','reason':'invalid_source_timestamp'}
        event = {'occurred_at':'2026-09-25', 'received_at':123, 'captured_at':{'unexpected':'clock'},
                 'time_normalization_originals':[copy.deepcopy(prior)]}
        normalize_time_fields(event, observed_at=NOW)
        evidence = copy.deepcopy(event['time_normalization_originals'])
        self.assertEqual(evidence[0], prior)
        self.assertEqual(len(evidence), 4)
        self.assertIn({'field':'received_at','value':123,'reason':'invalid_observation_timestamp'}, evidence)
        self.assertIn({'field':'captured_at','value':{'unexpected':'clock'},'reason':'invalid_observation_timestamp'}, evidence)
        normalize_time_fields(event, observed_at=LATER)
        self.assertEqual(event['time_normalization_originals'], evidence)
        self.assertEqual(event['time_basis'], 'source_time_invalid')

    def test_conflicting_evidence_field_is_not_overwritten(self):
        event = {'occurred_at':'date only', 'time_normalization_originals':{'old':'evidence'}}
        original = copy.deepcopy(event)
        with self.assertRaisesRegex(ValueError,'invalid_time_originals_evidence'):
            normalize_time_fields(event, observed_at=NOW)
        self.assertEqual(event, original)

    def test_empty_source_timestamp_is_preserved_as_invalid_not_unknown(self):
        event = {'occurred_at':''}
        normalize_time_fields(event, observed_at=NOW)
        self.assertIsNone(event['occurred_at'])
        self.assertEqual(event['time_basis'],'source_time_invalid')
        self.assertEqual(event['time_normalization_originals'][0]['value'],'')

    def test_received_clock_is_not_accepted_as_source_evidence(self):
        fields = received_fields(received_at="2026-09-25T11:04:05.123+08:00")
        self.assertEqual(fields, {"occurred_at": None, "received_at": NOW, "captured_at": NOW, "time_basis": "local_received"})
        self.assertEqual(native_time({"created_at": PAST, "mtime": PAST, "text": "At " + PAST}), (None, "capture_only", None))

    def test_control_submission_and_append_have_receipt_time_but_no_remote_occurrence_claim(self):
        service, principal = ControlService(self.root), self.principal()
        request = {"command_id": "submit-one", "role_id": "invest", "original_text": "Synthetic local input",
                   "source_event_id": "remote-message-without-verified-time"}
        with patch("task_service._now", return_value=NOW):
            first = service.submit(principal, request)
        inputs = [row for row in self.events() if row["event_type"] == "user_input"]
        self.assertEqual(len(inputs), 1)
        self.assertIsNone(inputs[0]["occurred_at"])
        self.assertEqual(inputs[0]["time_basis"], "local_received")
        self.assertEqual(inputs[0]["received_at"], first["received_at"])
        before = copy.deepcopy(inputs[0])
        with patch("task_service._now", return_value=LATER):
            duplicate = service.submit(principal, request)
            service.command(principal, first["task_id"], {"command_id": "append-one", "action": "append",
                "expected_goal_revision": 1, "expected_attempt": 0, "original_text": "Synthetic next input"})
        self.assertTrue(duplicate["replayed"])
        inputs = [row for row in self.events() if row["event_type"] == "user_input"]
        self.assertEqual(inputs[0], before)
        self.assertEqual(inputs[1]["received_at"], LATER)
        self.assertEqual(inputs[1]["captured_at"], LATER)
        self.assertIsNone(inputs[1]["occurred_at"])

    def test_public_request_cannot_forge_source_or_local_timestamp(self):
        service = ControlService(self.root)
        for key in ("occurred_at", "received_at", "time_basis", "source_timestamp"):
            with self.assertRaises(ControlError):
                service.submit(self.principal(), {"command_id": "fake-time", "role_id": "invest",
                    "original_text": "synthetic", key: PAST})
        self.assertEqual(self.events(), [])

    def test_native_jsonl_keeps_historical_source_time_and_new_capture_separate(self):
        source = self.root / "native.jsonl"
        native = {"type": "item.completed", "event_id": "native-one", "timestamp": PAST,
                  "item": {"id": "item-one", "type": "agent_message", "text": "Synthetic native reply"}}
        source.write_text(json.dumps(native) + "\n")
        with patch("raw_cursor.now_iso", return_value=NOW):
            ingest_jsonl(self.root, source, task_id="synthetic-task", agent="invest")
        row = self.events()[0]
        self.assertEqual(row["occurred_at"], PAST)
        self.assertEqual((row["received_at"], row["captured_at"]), (NOW, NOW))
        self.assertEqual(row["time_basis"], "source_timestamp")
        self.assertEqual(row["source_time_field"], "payload.native_event.timestamp")
        self.assertEqual(row["payload"]["native_event"], native)
        self.assertEqual(row["evidence_refs"][0]["byte_start"], 0)
        before = copy.deepcopy(self.events())
        with patch("raw_cursor.now_iso", return_value=LATER):
            result = ingest_jsonl(self.root, source, task_id="synthetic-task", agent="invest")
        self.assertEqual(result["written_event_ids"], [])
        self.assertEqual(self.events(), before)

    def test_native_jsonl_invalid_timestamp_is_preserved_as_raw_but_not_occurrence(self):
        source = self.root / "native.jsonl"
        native = {"type": "turn.completed", "timestamp": "2020-01-01T00:00:00"}
        source.write_text(json.dumps(native) + "\n")
        with patch("raw_cursor.now_iso", return_value=NOW):
            ingest_jsonl(self.root, source, task_id="synthetic-task", agent="invest")
        row = self.events()[0]
        self.assertIsNone(row["occurred_at"])
        self.assertEqual(row["time_basis"], "source_time_invalid")
        self.assertEqual(row["payload"]["native_event"]["timestamp"], native["timestamp"])
        self.assertEqual(row["received_at"], NOW)

    def test_live_native_json_timestamp_retained_but_unknown_stays_local_received(self):
        for native in ({"type": "turn.completed", "timestamp": PAST}, {"type": "turn.completed"}):
            row = normalize_event({"event_type": "codex_stream_event", "received_at": NOW, "captured_at": NOW,
                "time_basis": "local_received", "payload": {"record_source": "codex_json_stream", "event": native}})
            self.assertEqual(row["occurred_at"], native.get("timestamp"))
            self.assertEqual(row["time_basis"], "source_timestamp" if "timestamp" in native else "local_received")
            self.assertEqual(row["received_at"], NOW)

    def test_legacy_replay_discards_wrapper_now_but_native_evidence_preserves_source(self):
        with patch("raw_storage.now_iso", return_value=NOW):
            replay.append_event(self.root, {"_replay": True, "event_id": "legacy", "event_type": "user_input",
                "occurred_at": NOW, "payload": {"record_source": "javis_packet", "text": "Synthetic historical prompt"}}, set())
            replay.append_event(self.root, {"_replay": True, "event_id": "native-replay", "event_type": "other",
                "occurred_at": NOW, "payload": {"record_source": "codex_native_jsonl", "native_event": {"timestamp": PAST}}}, set())
        rows = {row["event_id"]: row for row in self.events()}
        self.assertIsNone(rows["legacy"]["occurred_at"])
        self.assertEqual(rows["legacy"]["time_basis"], "capture_only")
        self.assertEqual(rows["native-replay"]["occurred_at"], PAST)
        self.assertEqual(rows["native-replay"]["time_basis"], "source_timestamp")

    def test_grok_message_times_are_local_receipt_without_remote_authorship_upgrade(self):
        request = self.request()
        request["messages"].append({"speaker": "grok", "text": "Synthetic remote message", "fidelity": "relay",
                                     "source_event_id": "remote-source-id", "occurred_at": PAST})
        with patch.object(grok, "utc_now", return_value=NOW):
            first = grok.ingest(self.root, request)
        row = self.events()[0]
        messages = row["payload"]["messages"]
        self.assertEqual(row["received_at"], NOW)
        self.assertIsNone(row["occurred_at"])
        self.assertEqual((messages[0]["occurred_at"], messages[0]["time_basis"]), (None, "local_received"))
        self.assertEqual((messages[1]["occurred_at"], messages[1]["time_basis"]), (PAST, "source_timestamp"))
        self.assertTrue(all(message["received_at"] == NOW and message["captured_at"] == NOW for message in messages))
        self.assertEqual(messages[0]["fidelity"], "forwarded_original_unverified")
        self.assertFalse(first["memory_confirmed"])
        with patch.object(grok, "utc_now", return_value=LATER):
            second = grok.ingest(self.root, request)
        self.assertTrue(second["replayed"])
        self.assertEqual(self.events(), [row])
        self.assertNotIn("received_at", request["messages"][0])

    def test_grok_rejects_invalid_source_timestamp_before_persistence(self):
        for value in ("2026-09-25", "2026-09-25T12:00:00", "bad", True):
            request = self.request()
            request["messages"][0]["occurred_at"] = value
            with self.assertRaises(ValueError):
                grok.ingest(self.root, request)
        self.assertEqual(self.events(), [])

    def test_existing_event_is_not_rewritten_by_new_timestamp_defaults(self):
        old = {"event_id": "existing-event", "event_type": "user_input", "occurred_at": None,
               "captured_at": "2020-01-01T00:00:00Z", "payload": {"text": "Historical source"}}
        path = self.root / "raw/events/old.jsonl"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(old) + "\n")
        before = path.read_bytes()
        with patch("raw_storage.now_iso", return_value=NOW):
            self.assertIsNone(append_event(self.root, old))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.events(), [old])


if __name__ == "__main__":
    unittest.main(verbosity=2)
