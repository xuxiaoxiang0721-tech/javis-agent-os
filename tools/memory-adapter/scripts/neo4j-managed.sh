#!/usr/bin/env bash
# Managed Neo4j wrapper for WSL (systemd offline). Uses flock to prevent double-start.
# Logs: ~/javis/lab/memory-adapter/logs/neo4j-{start,stop,console}.log
set -euo pipefail
export JAVA_HOME="${JAVA_HOME:-$HOME/javis/tools/jdk-21}"
export PATH="$JAVA_HOME/bin:$PATH"
NEO="${NEO4J_HOME:-$HOME/javis/tools/neo4j}"
LOGDIR="${JAVIS_NEO4J_LOGDIR:-$HOME/javis/lab/memory-adapter/logs}"
LOCKDIR="${JAVIS_NEO4J_LOCKDIR:-$HOME/javis/lab/memory-adapter/locks}"
mkdir -p "$LOGDIR" "$LOCKDIR"
LOCK="$LOCKDIR/neo4j.lock"
PIDFILE="$LOCKDIR/neo4j-console.pid"
CMD="${1:-status}"

ts() { date '+%Y-%m-%dT%H:%M:%S%z'; }

is_http_up() {
  curl -s --connect-timeout 1 --max-time 2 -o /dev/null -w "%{http_code}" http://127.0.0.1:7474 2>/dev/null | grep -qE '200|302'
}

status() {
  if is_http_up; then
    echo "STATUS up http=200"
    "$NEO/bin/neo4j" status || true
    return 0
  fi
  echo "STATUS down"
  "$NEO/bin/neo4j" status || true
  return 1
}

start() {
  exec 9>"$LOCK"
  if ! flock -n 9; then
    echo "LOCK_HELD another start/stop in progress" | tee -a "$LOGDIR/neo4j-start.log"
    exit 2
  fi
  echo "$(ts) START_REQUEST" | tee -a "$LOGDIR/neo4j-start.log"
  if is_http_up; then
    echo "$(ts) ALREADY_UP" | tee -a "$LOGDIR/neo4j-start.log"
    status
    return 0
  fi
  # Prefer official daemon if it stays up; also keep console under nohup as backup path
  if "$NEO/bin/neo4j" start >>"$LOGDIR/neo4j-start.log" 2>&1; then
    for i in $(seq 1 40); do
      if is_http_up; then
        echo "$(ts) STARTED_DAEMON after ${i}s" | tee -a "$LOGDIR/neo4j-start.log"
        status
        return 0
      fi
      sleep 1
    done
  fi
  echo "$(ts) FALLBACK_CONSOLE" | tee -a "$LOGDIR/neo4j-start.log"
  nohup "$NEO/bin/neo4j" console >>"$LOGDIR/neo4j-console.log" 2>&1 &
  echo $! >"$PIDFILE"
  for i in $(seq 1 40); do
    if is_http_up; then
      echo "$(ts) STARTED_CONSOLE pid=$(cat "$PIDFILE") after ${i}s" | tee -a "$LOGDIR/neo4j-start.log"
      status
      return 0
    fi
    sleep 1
  done
  echo "$(ts) START_FAIL" | tee -a "$LOGDIR/neo4j-start.log"
  exit 1
}

stop() {
  exec 9>"$LOCK"
  if ! flock -n 9; then
    echo "LOCK_HELD" | tee -a "$LOGDIR/neo4j-stop.log"
    exit 2
  fi
  echo "$(ts) STOP_REQUEST (source=neo4j-managed.sh explicit)" | tee -a "$LOGDIR/neo4j-stop.log"
  "$NEO/bin/neo4j" stop >>"$LOGDIR/neo4j-stop.log" 2>&1 || true
  if [ -f "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE" || true)
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" >>"$LOGDIR/neo4j-stop.log" 2>&1 || true
    fi
    rm -f "$PIDFILE"
  fi
  sleep 2
  status || true
  echo "$(ts) STOP_DONE" | tee -a "$LOGDIR/neo4j-stop.log"
}

case "$CMD" in
  start) start ;;
  stop) stop ;;
  restart) stop || true; start ;;
  status) status ;;
  *) echo "usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
