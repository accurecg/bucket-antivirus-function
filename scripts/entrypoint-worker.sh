#!/bin/sh
# Start clamd in the background, wait until it is ready, then run the Python worker.
# Used by the ECS worker container so scans use clamdscan (daemon) instead of clamscan.

set -e

CLAMD_SOCKET="${CLAMD_SOCKET:-/tmp/clamd.sock}"

# Start clamd with worker config (ConcurrentDatabaseReload no, SelfCheck 600, LogTime yes)
# Redirect stderr to log for debugging (OOM, etc.)
if command -v clamd >/dev/null 2>&1; then
  clamd -c /app/clamd.conf >>/tmp/clamd.log 2>&1 &
elif [ -x /usr/sbin/clamd ]; then
  /usr/sbin/clamd -c /app/clamd.conf >>/tmp/clamd.log 2>&1 &
else
  echo "clamd not found" >&2
  exit 1
fi

# Wait for the socket to appear
echo "Waiting for clamd socket at $CLAMD_SOCKET..."
while [ ! -S "$CLAMD_SOCKET" ]; do
  sleep 1
done
# ClamAV loads ~1.2 GiB of signatures; can take 1-6 min. Poll until clamd responds (TCP, like official image).
echo "Waiting for clamd to load databases and respond to PING..."
for i in $(seq 1 90); do
  if [ "$(echo "PING" | nc -w 2 localhost 3310 2>/dev/null)" = "PONG" ]; then
    echo "clamd is ready (responded to PING)."
    break
  fi
  [ "$i" -eq 90 ] && { echo "clamd failed to respond within 7.5 minutes" >&2; [ -f /tmp/clamd.log ] && cat /tmp/clamd.log >&2; exit 1; }
  echo "  Attempt $i/90: clamd still loading..."
  sleep 5
done

exec /venv/bin/python worker.py
