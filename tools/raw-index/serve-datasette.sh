#!/usr/bin/env bash
set -euo pipefail
J="${JAVIS_HOME:-$HOME/javis}"
RAW_TOOL="$J/tools/raw-index"
DB="$J/raw/index/events.sqlite"
# shellcheck disable=SC1091
source "$RAW_TOOL/.venv/bin/activate"
pkill -f "datasette serve .*events.sqlite" 2>/dev/null || true
sleep 1
nohup datasette serve "$DB" --host 127.0.0.1 --port 8001 \
  >"$RAW_TOOL/datasette.log" 2>&1 &
echo $! >"$RAW_TOOL/datasette.pid"
sleep 2
echo "Datasette: http://127.0.0.1:8001/"
echo "Table JSON: http://127.0.0.1:8001/events/events"
echo "pid=$(cat "$RAW_TOOL/datasette.pid")"
# correct smoke: table path, not database root with _shape=array
code=$(curl -sS -o /tmp/ds-smoke.json -w "%{http_code}" \
  "http://127.0.0.1:8001/events/events.json?_shape=array&_size=1")
echo "smoke_http=$code"
python3 - <<'PY'
import json
from pathlib import Path
p=Path("/tmp/ds-smoke.json")
data=json.loads(p.read_text())
assert isinstance(data, list) and len(data)>=1, data
print("smoke_ok rows_sample", data[0].get("event_type"), data[0].get("event_id"))
PY
curl -sS "http://127.0.0.1:8001/events.json?sql=select+count(*)+as+n+from+events" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("sql_ok", d.get("rows") or d)'
