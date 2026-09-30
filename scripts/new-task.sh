#!/usr/bin/env bash
set -euo pipefail
ROLE="${1:?role_id}"
FROM="${2:?from_agent_id}"
GOAL="${3:?goal}"
TS=$(date +%Y%m%d-%H%M%S)
TID="t-${ROLE}-${TS}"
DIR="$HOME/javis/workspace/tasks/$TID"
mkdir -p "$DIR"
cat > "$DIR/packet.json" <<EOJ
{
  "task_id": "$TID",
  "from_agent_id": "$FROM",
  "role_id": "$ROLE",
  "goal": "$GOAL",
  "inputs": {},
  "cwd_hint": "$HOME/javis/workspace/roles/$ROLE",
  "permission": "R1"
}
EOJ
echo "created $DIR/packet.json"
echo "$TID"
