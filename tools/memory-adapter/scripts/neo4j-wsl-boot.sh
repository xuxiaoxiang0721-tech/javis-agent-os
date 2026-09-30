#!/usr/bin/env bash
# Must return immediately — WSL [boot] command blocks distro start if slow.
export JAVA_HOME="/home/user/javis/tools/jdk-21"
export PATH="$JAVA_HOME/bin:/usr/bin:/bin"
LOG="/home/user/javis/lab/memory-adapter/neo4j-reboot/boot.log"
mkdir -p "$(dirname "$LOG")"
nohup bash -c '
  echo "=== boot $(date -Iseconds) uid=$(id -u) user=$(whoami) ===" >>"'"$LOG"'"
  bash /home/user/javis/tools/memory-adapter/scripts/neo4j-managed.sh start >>"'"$LOG"'" 2>&1
  sleep 3
  bash /home/user/javis/tools/memory-adapter/scripts/neo4j-managed.sh status >>"'"$LOG"'" 2>&1
' >/dev/null 2>&1 &
exit 0