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

# Wait for the socket to appear and daemon to be ready
echo "Waiting for clamd socket at $CLAMD_SOCKET..."
while [ ! -S "$CLAMD_SOCKET" ]; do
  sleep 1
done
# Give clamd a moment to finish loading databases
sleep 2
echo "clamd is ready."

exec /venv/bin/python worker.py
