#!/opt/app/.svc/SVCWEB-env/bin/python

import json
import os
import ssl
import time
from kafka import KafkaProducer

LOG_FILE = "/opt/app/.svc/var/log/cowrie/cowrie.json"
TOPIC = "honeypot-telemetry"

BOOTSTRAP_SERVERS = os.environ["KAFKA_BOOTSTRAP_SERVERS"].split(",")

KAFKA_CONFIG = {}
if os.environ.get("KAFKA_SECURITY_PROTOCOL") == "SSL":
    KAFKA_CONFIG["security_protocol"] = "SSL"
    KAFKA_CONFIG["ssl_context"] = ssl.create_default_context()


def serialize(event):
    return json.dumps(
        event,
        separators=(",", ":")
    ).encode("utf-8")


def main():
    print("[telemetry] Starting Cowrie → Kafka adapter", flush=True)
    print(f"[telemetry] Log: {LOG_FILE}", flush=True)
    print(f"[telemetry] Topic: {TOPIC}", flush=True)
    print(
        f"[telemetry] Kafka brokers: {len(BOOTSTRAP_SERVERS)}",
        flush=True,
    )

    producer = KafkaProducer(
        bootstrap_servers=BOOTSTRAP_SERVERS,
        value_serializer=serialize,
        acks="all",
        retries=5,
        **KAFKA_CONFIG,
    )

    print("[telemetry] Kafka producer connected", flush=True)

    # Start at the end so old Cowrie events are not replayed.
    with open(LOG_FILE, "r", encoding="utf-8") as logfile:
        logfile.seek(0, os.SEEK_END)

        while True:
            line = logfile.readline()

            if not line:
                time.sleep(0.25)
                continue

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(
                    "[telemetry] Ignoring malformed JSON line",
                    flush=True,
                )
                continue

            normalized = {
                "source": "cowrie",
                "event_type": event.get("eventid"),
                "timestamp": event.get("timestamp"),
                "session_id": event.get("session"),
                "source_ip": event.get("src_ip"),
                "source_port": event.get("src_port"),
                "destination_ip": event.get("dst_ip"),
                "destination_port": event.get("dst_port"),
                "severity": None,
                "data": event,
            }

            producer.send(TOPIC, normalized)

            print(
                f"[telemetry] Published "
                f"{normalized['event_type']} "
                f"session={normalized['session_id']}",
                flush=True,
            )


if __name__ == "__main__":
    main()