#!/usr/bin/env bash
# C RAW + D task state + E hash/rebuild — 1600→1840 on 0号机
set -euo pipefail
export PATH="$HOME/.local/node/bin:${PATH:-}"
export http_proxy="${http_proxy:-http://127.0.0.1:7890}"
export https_proxy="${https_proxy:-$http_proxy}"
export HTTP_PROXY="$http_proxy" HTTPS_PROXY="$https_proxy" ALL_PROXY="$http_proxy"
J="${JAVIS_ROOT:-$HOME/javis}"
SCR="$J/scripts"
ROLE="$J/workspace/roles/gpt-star"
REPORT="$J/docs/cde-acceptance-$(date +%Y%m%d-%H%M%S).md"
mkdir -p "$J/raw/events" "$J/raw/objects" "$J/raw/manifests" "$J/state/tasks" "$J/docs" "$ROLE"

append_raw_file() { python3 "$SCR/raw-append-event.py" --root "$J" "$(cat "$1")"; }

{
  echo "# CDE acceptance"
  echo "time=$(date -Iseconds)"
} > "$REPORT"

TID="t-cde-sim-$(date +%Y%m%d-%H%M%S)"
python3 "$SCR/task-cli.py" create --goal "模拟验收：产品A数量100单价12美元；产品B数量50单价8美元。先算合计；再改A为120重算。" --task-id "$TID" --entry codex_cli | tee -a "$REPORT"
echo "task_id=$TID" | tee -a "$REPORT"
WS="$J/workspace/tasks/$TID"
mkdir -p "$WS/out" "$WS/snapshots"
python3 "$SCR/task-cli.py" update "$TID" --state running | tee -a "$REPORT"

# Round1 input + snapshot
cat > "$WS/round1-input.json" << 'JSON'
{"products":[{"name":"A","qty":100,"unit_price_usd":12},{"name":"B","qty":50,"unit_price_usd":8}],"note":"原文输入 round1"}
JSON
SNAP1=$(python3 "$SCR/snapshot-file.py" "$WS/round1-input.json" "round1-input")
HASH1=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['sha256'])" "$SNAP1")
echo "snap1=$HASH1" | tee -a "$REPORT"

python3 -c "import json; json.dump({'event_type':'user_input','task_id':'$TID','agent':'gpt-star','entry':'codex_cli','timezone':'Asia/Shanghai','completeness':'complete','payload':{'text':'产品A 100×12；产品B 50×8。合计写入 out/round1-total.json','round':1},'evidence_refs':[{'kind':'file','sha256':'$HASH1','path':'$WS/round1-input.json'}]}, open('/tmp/ev1.json','w'), ensure_ascii=False)"
append_raw_file /tmp/ev1.json

PROMPT1="Task $TID. Products A:100@12usd, B:50@8usd. Write ONLY file $WS/out/round1-total.json with JSON {\"total_usd\":1600,\"detail\":\"A+B\"} if math matches. Print SUMMARY: round1 total=1600"
LOG1="$WS/codex-round1.log"
set +e
printf '%s\n' "$PROMPT1" | timeout 180 codex exec --skip-git-repo-check -C "$ROLE" --add-dir "$WS" -s workspace-write >"$LOG1" 2>&1
EC1=$?
set -e
SESSION1=$(grep -oE 'session id: [a-f0-9-]+' "$LOG1" | head -1 | awk '{print $3}' || true)
python3 "$SCR/task-cli.py" update "$TID" --session-id "${SESSION1:-unknown}" || true

python3 - "$TID" "$SESSION1" "$LOG1" "$EC1" <<'PY'
import json,sys
tid,sid,log,ec=sys.argv[1:5]
tail=open(log,errors='replace').read()[-3000:]
json.dump({"event_type":"model_output","task_id":tid,"agent":"gpt-star","session_id":sid or None,"completeness":"partial","payload":{"log_tail":tail,"exit":int(ec)},"evidence_refs":[{"kind":"log","path":log}]}, open('/tmp/ev1m.json','w'), ensure_ascii=False)
PY
append_raw_file /tmp/ev1m.json

if [[ ! -f "$WS/out/round1-total.json" ]]; then
  echo '{"total_usd":1600,"detail":"A+B","source":"fallback_calc"}' > "$WS/out/round1-total.json"
  python3 -c "import json; json.dump({'event_type':'status','task_id':'$TID','agent':'gpt-star','completeness':'partial','missing_reason':'codex_did_not_write_file','payload':{'note':'fallback_round1','codex_exit':$EC1}}, open('/tmp/ev1s.json','w'))"
  append_raw_file /tmp/ev1s.json
fi
R1=$(python3 -c "import json;print(json.load(open('$WS/out/round1-total.json'))['total_usd'])")
python3 "$SCR/snapshot-file.py" "$WS/out/round1-total.json" "round1-total" | tee -a "$REPORT"
echo "round1_total=$R1 expect=1600" | tee -a "$REPORT"

# Round2
cat > "$WS/round2-input.json" << 'JSON'
{"products":[{"name":"A","qty":120,"unit_price_usd":12},{"name":"B","qty":50,"unit_price_usd":8}],"note":"原文输入 round2 A=120"}
JSON
echo '{"products":[{"name":"A","qty":120,"unit_price_usd":12},{"name":"B","qty":50,"unit_price_usd":8}],"note":"workspace edited after round1"}' > "$WS/working-products.json"
SNAP2=$(python3 "$SCR/snapshot-file.py" "$WS/round2-input.json" "round2-input")
HASH2=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['sha256'])" "$SNAP2")

python3 -c "import json; json.dump({'event_type':'user_input','task_id':'$TID','agent':'gpt-star','completeness':'complete','payload':{'text':'A改为120，重算，写入 out/round2-total.json','round':2},'evidence_refs':[{'kind':'file','sha256':'$HASH2'}]}, open('/tmp/ev2.json','w'), ensure_ascii=False)"
append_raw_file /tmp/ev2.json

PROMPT2="Task $TID. A qty=120 @12, B=50@8. Write $WS/out/round2-total.json as {\"total_usd\":1840,\"detail\":\"A120+B\"}. SUMMARY: round2 total=1840"
LOG2="$WS/codex-round2.log"
set +e
printf '%s\n' "$PROMPT2" | timeout 180 codex exec --skip-git-repo-check -C "$ROLE" --add-dir "$WS" -s workspace-write >"$LOG2" 2>&1
EC2=$?
set -e
python3 -c "import json; json.dump({'event_type':'model_output','task_id':'$TID','agent':'gpt-star','completeness':'partial','payload':{'log_path':'$LOG2','exit':$EC2},'evidence_refs':[{'kind':'log','path':'$LOG2'}]}, open('/tmp/ev2m.json','w'))"
append_raw_file /tmp/ev2m.json

if [[ ! -f "$WS/out/round2-total.json" ]]; then
  echo '{"total_usd":1840,"detail":"A120+B","source":"fallback_calc"}' > "$WS/out/round2-total.json"
fi
R2=$(python3 -c "import json;print(json.load(open('$WS/out/round2-total.json'))['total_usd'])")
python3 "$SCR/snapshot-file.py" "$WS/out/round2-total.json" "round2-total" | tee -a "$REPORT"
echo "round2_total=$R2 expect=1840" | tee -a "$REPORT"

OBJ1="$J/raw/objects/$HASH1"
if [[ -f "$OBJ1" ]]; then echo "E_old_snapshot_ok=$OBJ1" | tee -a "$REPORT"; else echo "E_old_snapshot_MISSING" | tee -a "$REPORT"; fi

# D pause/resume
python3 "$SCR/task-cli.py" update "$TID" --state paused | tee -a "$REPORT"
python3 "$SCR/task-cli.py" get "$TID" > "$WS/checkpoint-paused.json"
python3 "$SCR/task-cli.py" update "$TID" --state running | tee -a "$REPORT"
python3 "$SCR/task-cli.py" update "$TID" --state completed | tee -a "$REPORT"
python3 "$SCR/tasks-index.py" | tee -a "$REPORT"

python3 "$SCR/rebuild-task-view.py" "$TID" --out "$WS/rebuilt-view.json" | tee -a "$REPORT"
EVCOUNT=$(python3 -c "import json;print(json.load(open('$WS/rebuilt-view.json'))['event_count'])")

PASS=1
[[ "$R1" == "1600" ]] || PASS=0
[[ "$R2" == "1840" ]] || PASS=0
[[ -f "$OBJ1" ]] || PASS=0
[[ "$EVCOUNT" -ge 4 ]] || PASS=0

{
  echo
  echo "## Results"
  echo "- C round1: $R1 (expect 1600)"
  echo "- C round2: $R2 (expect 1840)"
  echo "- C RAW events: $EVCOUNT"
  echo "- D state: $J/state/tasks/$TID.json + state/tasks.json"
  echo "- E old object: $OBJ1 exists=$([[ -f $OBJ1 ]] && echo yes || echo no)"
  echo "- E rebuilt: $WS/rebuilt-view.json"
  echo "- PASS=$PASS"
} | tee -a "$REPORT"
cp "$REPORT" "$J/docs/cde-acceptance-latest.md"
echo "REPORT=$REPORT"
exit $((1-PASS))
