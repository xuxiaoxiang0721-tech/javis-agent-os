#!/usr/bin/env python3
"""Append one invest-mail RAW event (JSON line). Prefer body_full (verbatim)."""
import json, sys, hashlib
from pathlib import Path
from datetime import datetime

def main():
    if len(sys.argv) < 2:
        print("usage: invest-mail-raw-append.py '<json-object>'", file=sys.stderr)
        sys.exit(2)
    obj = json.loads(sys.argv[1])
    root = Path.home() / "javis" / "raw"
    evdir = root / "events" / "invest-mail"
    objdir = root / "objects"
    evdir.mkdir(parents=True, exist_ok=True)
    objdir.mkdir(parents=True, exist_ok=True)
    day = datetime.now().strftime("%Y%m%d")
    path = evdir / f"{day}.jsonl"
    obj.setdefault("ts", datetime.now().astimezone().isoformat())
    obj.setdefault("agent", "invest")
    obj.setdefault("pipeline", "invest-mail-v021")
    obj.setdefault("verbatim", True)
    obj.setdefault("images_uncompressed", True)
    # normalize: keep body_full; do not drop in favor of excerpt-only
    if "body" in obj and "body_full" not in obj:
        obj["body_full"] = obj["body"]
    # optional attachments: [{filename, sha256, bytes_b64?}] — prefer pre-written object files
    for att in obj.get("attachments") or []:
        if att.get("sha256") and att.get("path"):
            continue
        raw = att.get("bytes")
        if isinstance(raw, str) and raw.startswith("base64:"):
            import base64
            data = base64.b64decode(raw[len("base64:"):])
            h = hashlib.sha256(data).hexdigest()
            out = objdir / h
            if not out.exists():
                out.write_bytes(data)  # original bytes, no recompress
            att["sha256"] = h
            att["path"] = str(out)
            att.pop("bytes", None)
    mid = obj.get("message_id") or obj.get("id") or json.dumps(obj, sort_keys=True)[:200]
    obj["raw_hash"] = hashlib.sha256(str(mid).encode()).hexdigest()[:16]
    if path.exists() and obj.get("message_id"):
        for line in path.read_text(encoding="utf-8").split('\n'):
            try:
                if json.loads(line).get("message_id") == obj["message_id"]:
                    print("DUP", obj["message_id"])
                    return
            except Exception:
                pass
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    idx = root / "manifests" / "invest-mail-class.jsonl"
    idx.parent.mkdir(parents=True, exist_ok=True)
    with idx.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "ts": obj["ts"],
            "message_id": obj.get("message_id"),
            "subject": obj.get("subject"),
            "validity": obj.get("validity"),
            "priority": obj.get("priority"),
            "memory_written": obj.get("memory_written", False),
            "verbatim": True,
        }, ensure_ascii=False) + "\n")
    print(path)

if __name__ == "__main__":
    main()
