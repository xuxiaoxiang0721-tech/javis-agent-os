#!/usr/bin/env bash
set -euo pipefail
export JAVA_HOME="${JAVA_HOME:-$HOME/javis/tools/jdk-21}"
export PATH="$JAVA_HOME/bin:$PATH"
export http_proxy="${http_proxy:-http://127.0.0.1:7890}"
export https_proxy="${https_proxy:-http://127.0.0.1:7890}"
ROOT="${JAVIS_MEMORY_ADAPTER_ROOT:-$HOME/javis/tools/memory-adapter}"
bash "$ROOT/scripts/neo4j-managed.sh" start
source "$HOME/javis/tools/graphiti/.venv/bin/activate"
set -a; source "$HOME/javis/tools/graphiti/.env"; set +a
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"
echo "== adapter trial suite =="
python3 "$ROOT/tests/run_trial_suite.py" || true
echo "== type B recovery suite =="
python3 "$ROOT/tests/run_typeb_recovery.py"
echo "== regression done =="
echo "trial: ~/javis/lab/memory-adapter/trial/trial-suite-latest.json"
echo "typeb: ~/javis/lab/memory-adapter/typeb/typeb-recovery-latest.json"
