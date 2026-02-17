#!/bin/sh
# Start clamd in the background, wait until it is ready, then run the Python worker.
# Used by the ECS worker container so scans use clamdscan (daemon) instead of clamscan.

set -e

CLAMD_SOCKET="${CLAMD_SOCKET:-/tmp/clamd.sock}"

# Start clamd with worker config (ConcurrentDatabaseReload no, SelfCheck 600, LogTime yes)
if command -v clamd >/dev/null 2>&1; then
  clamd -c /app/clamd.conf &
elif [ -x /usr/sbin/clamd ]; then
  /usr/sbin/clamd -c /app/clamd.conf &
else
  echo "clamd not found" >&2
  exit 1
fi

# Wait for the socket to appear
echo "Waiting for clamd socket at $CLAMD_SOCKET..."
while [ ! -S "$CLAMD_SOCKET" ]; do
  sleep 1
done
# ClamAV loads ~1.2 GiB of signatures into memory; can take 1-3 minutes. Poll until clamd responds.
echo "Waiting for clamd to load databases and respond to ping..."
CLAMD_CONF="${CLAMD_CONF:-/app/clamd.conf}"
for i in $(seq 1 60); do
  if clamdscan --config-file="$CLAMD_CONF" --ping 2>/dev/null; then
    echo "clamd is ready (responded to ping)."
    break
  fi
  [ "$i" -eq 60 ] && { echo "clamd failed to respond within 5 minutes" >&2; exit 1; }
  echo "  Attempt $i/60: clamd still loading..."
  sleep 5
done

exec /venv/bin/python worker.py
