#!/usr/bin/env python3
"""Index ~/javis/raw/events/**/*.jsonl into SQLite. Does NOT modify RAW files."""
from __future__ import annotations
import argparse, json, sqlite3
from pathlib import Path
from datetime import datetime, timezone

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path.home() / "javis"))
    ap.add_argument("--db", default=None, help="default: <root>/raw/index/events.sqlite")
    args = ap.parse_args()
    root = Path(args.root)
    events_dir = root / "raw" / "events"
    db_path = Path(args.db) if args.db else root / "raw" / "index" / "events.sqlite"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          source_file TEXT NOT NULL,
          line_no INTEGER NOT NULL,
          event_id TEXT,
          event_type TEXT,
          occurred_at TEXT,
          captured_at TEXT,
          task_id TEXT,
          dispatch_id TEXT,
          agent TEXT,
          completeness TEXT,
          timezone TEXT,
          sensitivity TEXT,
          subject TEXT,
          message_id TEXT,
          payload_json TEXT,
          raw_json TEXT NOT NULL,
          indexed_at TEXT NOT NULL,
          UNIQUE(source_file, line_no)
        );
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_task ON events(task_id);
        CREATE INDEX IF NOT EXISTS idx_events_dispatch ON events(dispatch_id);
        CREATE INDEX IF NOT EXISTS idx_events_occurred ON events(occurred_at);
        CREATE INDEX IF NOT EXISTS idx_events_message ON events(message_id);
        """
    )

    indexed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    n_files = n_lines = n_ok = n_bad = 0
    for path in sorted(events_dir.rglob("*.jsonl")):
        n_files += 1
        rel = str(path.relative_to(root))
        with path.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                n_lines += 1
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    n_bad += 1
                    continue
                # invest-mail stream is a mail ledger (not javis-raw-event-1 envelope)
                is_mail_ledger = (
                    "message_id" in o and "subject" in o and "event_type" not in o and "schema_version" not in o
                )
                if is_mail_ledger:
                    frm = o.get("from")
                    if isinstance(frm, dict):
                        frm_s = frm.get("address") or frm.get("name")
                    else:
                        frm_s = frm
                    event_type = "mail_captured"
                    event_id = o.get("raw_hash") or o.get("provider_id") or o.get("message_id")
                    occurred_at = o.get("receivedDateTime") or o.get("ts")
                    captured_at = o.get("ts") or occurred_at
                    agent = o.get("agent") or o.get("pipeline")
                    subject = o.get("subject")
                    message_id = o.get("message_id")
                    payload = {k: o.get(k) for k in (
                        "provider_id","mailbox","folder","conversation_id","from","to",
                        "validity","priority","has_attachments","attachments","notes",
                        "verbatim","images_uncompressed","raw_hash","sent_reply_found"
                    ) if k in o}
                    # never put full body into payload_json index row? keep pointer only for size
                    if "body_full" in o:
                        payload["body_full_chars"] = len(o.get("body_full") or "")
                        payload["has_body_full"] = True
                    payload_json = json.dumps(payload, ensure_ascii=False)
                    task_id = None
                    dispatch_id = None
                    completeness = "complete" if o.get("verbatim") else "partial"
                    tz_name = None
                    sensitivity = "sensitive" if (o.get("priority") == "priority" or "medical" in (subject or "").lower()) else "normal"
                else:
                    payload = o.get("payload") if isinstance(o.get("payload"), dict) else {}
                    mail = payload.get("mail") if isinstance(payload.get("mail"), dict) else {}
                    event_type = o.get("event_type") or o.get("type")
                    event_id = o.get("event_id")
                    occurred_at = o.get("occurred_at")
                    captured_at = o.get("captured_at") or o.get("recorded_at")
                    task_id = o.get("task_id")
                    dispatch_id = o.get("dispatch_id") or payload.get("dispatch_id")
                    actor = o.get("actor") if isinstance(o.get("actor"), dict) else {}
                    agent = o.get("agent") or actor.get("role_id")
                    completeness = o.get("completeness")
                    tz_name = o.get("timezone")
                    sensitivity = o.get("sensitivity")
                    subject = mail.get("subject") or payload.get("subject")
                    message_id = mail.get("message_id") or payload.get("message_id")
                    payload_json = json.dumps(payload, ensure_ascii=False) if payload else None
                conn.execute(
                    """
                    INSERT INTO events (
                      source_file, line_no, event_id, event_type, occurred_at, captured_at,
                      task_id, dispatch_id, agent, completeness, timezone, sensitivity,
                      subject, message_id, payload_json, raw_json, indexed_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(source_file, line_no) DO UPDATE SET
                      event_id=excluded.event_id,
                      event_type=excluded.event_type,
                      occurred_at=excluded.occurred_at,
                      captured_at=excluded.captured_at,
                      task_id=excluded.task_id,
                      dispatch_id=excluded.dispatch_id,
                      agent=excluded.agent,
                      completeness=excluded.completeness,
                      timezone=excluded.timezone,
                      sensitivity=excluded.sensitivity,
                      subject=excluded.subject,
                      message_id=excluded.message_id,
                      payload_json=excluded.payload_json,
                      raw_json=excluded.raw_json,
                      indexed_at=excluded.indexed_at
                    """,
                    (
                        rel, i, event_id, event_type, occurred_at, captured_at,
                        task_id, dispatch_id, agent, completeness, tz_name, sensitivity,
                        subject, message_id, payload_json, line, indexed_at,
                    ),
                )
                n_ok += 1
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    print(f"OK files={n_files} lines={n_lines} upserted={n_ok} bad={n_bad} db_rows={total}")
    print(f"DB {db_path}")

if __name__ == "__main__":
    main()
