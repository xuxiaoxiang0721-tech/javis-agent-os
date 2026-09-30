"""Separate source occurrence from clocks observed by the local recorder.

Valid source timestamps are preserved verbatim, including sub-microsecond
precision. A receiving/capture clock never supplies a missing source timestamp.
"""
from __future__ import annotations
import copy
from datetime import datetime, timezone
import re

_STAMP = re.compile(r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T"
    r"(?P<clock>[0-9]{2}:[0-9]{2}:[0-9]{2})(?P<fraction>\.[0-9]{1,9})?"
    r"(?P<zone>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z")
TIME_BASES = frozenset({"source_timestamp", "local_received", "capture_only", "source_time_invalid"})
_LEGACY_RECORDER_CLOCKS = frozenset({"wrapper_prompt", "grok_forwarded_summary", "codex_log_parse", "agent_summary"})


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parts(value):
    if not isinstance(value, str):
        return None
    match = _STAMP.fullmatch(value)
    # RFC 3339 -00:00 explicitly means that the local offset is unknown.
    if match is None or match["zone"] == "-00:00":
        return None
    try:
        parsed = datetime.fromisoformat(match["date"] + "T" + match["clock"] + match["zone"].replace("Z", "+00:00"))
        parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None
    return match, parsed


def source_timestamp(value):
    """Return the exact complete, zoned timestamp, or None for invalid/unknown."""
    return value if _parts(value) is not None else None


def semantic_source_time(record):
    """Read an occurrence clock without treating a known recorder clock as evidence.

    This compatibility view never edits RAW. Explicit default/capture provenance
    takes precedence over a syntactically valid timestamp. Legacy original
    messages without a basis remain readable unless their own provenance proves
    a recorder/derived clock; callers must pass the selected message itself.
    """
    if not isinstance(record, dict):
        return None
    missing = record.get("missing_reason")
    if isinstance(missing, str) and "occurred_at_defaulted_to_captured_at" in missing:
        return None
    basis = record.get("time_basis")
    if basis not in (None, "", "source_timestamp"):
        return None
    if basis != "source_timestamp":
        payload = record.get("payload")
        contexts = (record, payload) if isinstance(payload, dict) else (record,)
        if any(context.get(key) in _LEGACY_RECORDER_CLOCKS
               for context in contexts for key in ("record_source", "input_kind")
               if isinstance(context.get(key), str)):
            return None
    return source_timestamp(record.get("occurred_at"))


def utc_timestamp(value):
    """Canonicalize an observed timestamp to UTC without losing its fraction."""
    parts = _parts(value)
    if parts is None:
        return None
    match, parsed = parts
    converted = parsed.astimezone(timezone.utc)
    return f"{converted.year:04d}" + converted.strftime("-%m-%dT%H:%M:%S") + (match["fraction"] or "") + "Z"


def native_time(record):
    """Read only timestamp fields carried by the original native event.

    Returns (source time, basis, field name). Callers retain the native event or
    a byte-range reference as evidence. Text content and file mtimes are not used.
    """
    if isinstance(record, dict):
        for field in ("timestamp", "occurred_at"):
            value = record.get(field)
            if value is not None and value != "":
                stamp = source_timestamp(value)
                return stamp, "source_timestamp" if stamp else "source_time_invalid", field
    return None, "capture_only", None


def received_fields(*, occurred_at=None, received_at=None, basis="local_received"):
    """Time metadata for a newly received body, without invented occurrence."""
    stamp = utc_timestamp(received_at) if received_at is not None else utc_now()
    if stamp is None:
        raise ValueError("invalid_received_timestamp")
    occurrence = source_timestamp(occurred_at)
    return {"occurred_at": occurrence, "received_at": stamp, "captured_at": stamp,
            "time_basis": "source_timestamp" if occurrence is not None else
                "source_time_invalid" if occurred_at is not None else basis}


def normalize_time_fields(event, *, observed_at=None):
    """Normalize only the new record; never edit previously stored RAW rows."""
    observed = utc_timestamp(observed_at) if observed_at is not None else utc_now()
    if observed is None:
        raise ValueError("invalid_observation_timestamp")
    occurrence = event.get("occurred_at")
    value = source_timestamp(occurrence)
    invalid_source = occurrence is not None and value is None
    received = utc_timestamp(event.get("received_at"))
    captured = utc_timestamp(event.get("captured_at"))
    problems = []
    originals = event.get('time_normalization_originals', [])
    if not isinstance(originals, list):
        raise ValueError('invalid_time_originals_evidence')
    originals = copy.deepcopy(originals)
    def preserve(field, reason):
        original = {'field': field, 'value': copy.deepcopy(event[field]), 'reason': reason}
        if original not in originals:
            originals.append(original)
    if invalid_source:
        preserve('occurred_at', 'invalid_source_timestamp')
    for key, valid in (("received_at", received), ("captured_at", captured)):
        if event.get(key) is not None and valid is None:
            problems.append("invalid_" + key + "_replaced_by_local_observation")
            preserve(key, 'invalid_observation_timestamp')
    if originals:
        event['time_normalization_originals'] = originals
    event.update(occurred_at=value, received_at=received or observed, captured_at=captured or observed)
    if invalid_source:
        event["time_basis"] = "source_time_invalid"
        problems.append("original_event_timestamp_invalid")
    elif value is not None:
        event["time_basis"] = "source_timestamp"
    elif event.get("time_basis") not in {"local_received", "capture_only", "source_time_invalid"}:
        event["time_basis"] = "capture_only"
    return problems
