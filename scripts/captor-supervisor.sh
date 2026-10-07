#!/bin/bash
set -u

PYTHON="/usr/bin/python3"
CAPTOR="/opt/.infra/captor.py"

LOG="/var/log/honeypot-captor.log"
PIDFILE="/run/honeypot-captor-supervisor.pid"

echo $$ > "$PIDFILE"

echo "[captor-supervisor] Starting" >> "$LOG"
echo "[captor-supervisor] Consumer: $CAPTOR" >> "$LOG"

while true; do
    echo "[captor-supervisor] Starting Captor consumer" >> "$LOG"

    "$PYTHON" "$CAPTOR" >> "$LOG" 2>&1

    EXIT_CODE=$?

    echo \
        "[captor-supervisor] Captor exited with code $EXIT_CODE; restarting in 5 seconds" \
        >> "$LOG"

    sleep 5
done