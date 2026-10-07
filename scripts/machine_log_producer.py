#!/usr/bin/env python3
"""Additive system-log producer. Does not replace the Cowrie producer."""
import json, os, socket, time
from pathlib import Path
from kafka import KafkaProducer

BOOTSTRAP = os.environ["KAFKA_BOOTSTRAP_SERVERS"].split(",")
TOPIC = os.environ.get("KAFKA_TELEMETRY_TOPIC", "honeypot-telemetry")
HOST = socket.gethostname()

LOGS = [
    ("/var/log/cloud-init-output.log", "cloud-init"),
    ("/var/log/decoy-controller.log", "decoy-controller"),
    ("/opt/app/.svc/var/log/cowrie/cowrie.log", "cowrie-diagnostic"),
]

producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP,
    value_serializer=lambda v: json.dumps(v, separators=(",",":")).encode(),
    acks="all",
    retries=5,
)

handles = {}
while True:
    progressed = False
    for filename, source in LOGS:
        path = Path(filename)
        if not path.exists():
            continue
        if filename not in handles:
            f = path.open("r", encoding="utf-8", errors="replace")
            f.seek(0, 2)
            handles[filename] = f
        f = handles[filename]
        line = f.readline()
        if line:
            producer.send(TOPIC, {
                "telemetry_type":"system_log",
                "source":"system",
                "log_source":source,
                "log_file":filename,
                "host":HOST,
                "timestamp":None,
                "message":line.rstrip("\r\n")
            })
            progressed = True
    if progressed:
        producer.flush()
    else:
        time.sleep(0.5)
