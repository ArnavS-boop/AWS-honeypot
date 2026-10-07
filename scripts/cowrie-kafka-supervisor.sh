#!/bin/bash
set -u

PYTHON="/opt/app/.svc/SVCWEB-env/bin/python"
PRODUCER="/opt/.infra/cowrie-kafka-producer.py"

LOG="/var/log/cowrie-kafka-producer.log"
PIDFILE="/run/cowrie-kafka-supervisor.pid"

echo $$ > "$PIDFILE"

echo "[telemetry-supervisor] Starting" >> "$LOG"
echo "[telemetry-supervisor] Producer: $PRODUCER" >> "$LOG"

while true; do
    echo "[telemetry-supervisor] Starting producer" >> "$LOG"

    "$PYTHON" "$PRODUCER" >> "$LOG" 2>&1

    EXIT_CODE=$?

    echo \
        "[telemetry-supervisor] Producer exited with code $EXIT_CODE; restarting in 5 seconds" \
        >> "$LOG"

    sleep 5
done