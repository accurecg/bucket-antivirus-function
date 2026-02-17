#!/bin/sh
# Dual-liveness health check for ECS: ClamAV daemon + main application.
# Output is written to PID 1's stdout so successes/failures appear in CloudWatch.

LOG="/proc/1/fd/1"

# 1. Ping the ClamAV daemon via TCP (same as official clamav/clamav image; more reliable than socket)
if [ "$(echo "PING" | nc -w 2 localhost 3310 2>/dev/null)" != "PONG" ]; then
  echo "[HealthCheck] ClamAV daemon is not responding." >"$LOG" 2>&1
  exit 1
fi

# 2. Check the main application process (Python worker)
if ! pgrep -f "worker.py" >/dev/null 2>&1; then
  echo "[HealthCheck] Main application process (worker.py) is down." >"$LOG" 2>&1
  exit 1
fi

echo "[HealthCheck] System healthy." >"$LOG" 2>&1
exit 0
