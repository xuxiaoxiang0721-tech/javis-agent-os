"""Validity-interval helpers for Graphiti RELATES_TO edges.

Semantics (documented, exclusive end):
  A fact is effective at instant T iff:
    - valid_at is known AND valid_at <= T
    - AND (invalid_at is None OR T < invalid_at)

Unknown valid_at:
  - Does NOT auto-include in current/as_of answers.
  - Surfaced as PENDING with note — caller must not let NL model guess.

Future-effective (valid_at > T): excluded.

expired_at (Graphiti system time when edge was invalidated in the store)
is NOT used as the event-time end; invalid_at is the event-time end.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Optional


def parse_ts(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        if not s or s.lower() in {"none", "null"}:
            return None
        # Normalize UTC before trimming fractional seconds. Otherwise .123Z
        # becomes .123Z00 and a normal RAW millisecond timestamp is rejected.
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        # Neo4j may emit nanoseconds; trim to microseconds for fromisoformat
        if "." in s:
            head, frac = s.split(".", 1)
            # frac may be 123456000+00:00
            sign = "+"
            if "+" in frac:
                frac, tz = frac.split("+", 1)
                tz = "+" + tz
            elif "-" in frac[1:] and frac.count("-") >= 1:
                # e.g. 123-05:00 unlikely; prefer last -
                idx = frac.rfind("-")
                if idx > 0 and ":" in frac[idx:]:
                    tz = frac[idx:]
                    frac = frac[:idx]
                else:
                    tz = ""
            else:
                tz = ""
            frac = (frac + "000000")[:6]
            s = f"{head}.{frac}{tz}"
        s = s.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_effective_at(valid_at: Any, invalid_at: Any, as_of: datetime) -> tuple[bool, str]:
    """Return (effective?, reason_code)."""
    v = parse_ts(valid_at)
    inv = parse_ts(invalid_at)
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=timezone.utc)

    if v is None:
        return False, "unknown_valid_at"
    if v > as_of:
        return False, "future_effective"
    # inclusive start, exclusive end
    if inv is not None and not (as_of < inv):
        return False, "ended"
    return True, "in_interval"


def boundary_note() -> str:
    return "interval=[valid_at, invalid_at) inclusive start, exclusive end; unknown valid_at => PENDING not auto-selected"
