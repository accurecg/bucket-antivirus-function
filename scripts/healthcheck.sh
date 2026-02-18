#!/bin/sh
LOG="/proc/1/fd/1"
STATE_FILE="/tmp/healthcheck_state"

# 1. ClamAV check
if [ "$(echo "PING" | nc -w 2 localhost 3310 2>/dev/null)" != "PONG" ]; then
  echo "[HealthCheck] ClamAV daemon is not responding." >"$LOG" 2>&1
  echo "failed" >"$STATE_FILE"
  exit 1
fi

# 2. Worker check
if ! pgrep -f "worker.py" >/dev/null 2>&1; then
  echo "[HealthCheck] Main application process (worker.py) is down." >"$LOG" 2>&1
  echo "failed" >"$STATE_FILE"
  exit 1
fi

# Success: log only on first run or after recovery
prev=$(cat "$STATE_FILE" 2>/dev/null || true)
if [ -z "$prev" ] || [ "$prev" = "failed" ]; then
  if [ "$prev" = "failed" ]; then
    echo "[HealthCheck] Recovered. System healthy." >"$LOG" 2>&1
  else
    echo "[HealthCheck] System healthy." >"$LOG" 2>&1
  fi
fi
echo "ok" >"$STATE_FILE"
exit 0