import json
import importlib.util
import os
import ssl
import sys
from datetime import datetime, timezone
from kafka import KafkaConsumer

sys.path.insert(0, os.path.dirname(__file__))
try:
    from captor_persistence import S3TelemetrySink, kafka_event_id  # type: ignore[import-not-found]
except ImportError:
    persistence_path = os.path.join(os.path.dirname(__file__), "captor-persistence.py")
    persistence_spec = importlib.util.spec_from_file_location(
        "captor_persistence", persistence_path
    )
    if persistence_spec is None or persistence_spec.loader is None:
        raise
    persistence_module = importlib.util.module_from_spec(persistence_spec)
    persistence_spec.loader.exec_module(persistence_module)
    S3TelemetrySink = persistence_module.S3TelemetrySink
    kafka_event_id = persistence_module.kafka_event_id

BOOTSTRAP = os.environ["KAFKA_BOOTSTRAP_SERVERS"]

TOPIC = "honeypot-telemetry"

KAFKA_CONFIG = {}
if os.environ.get("KAFKA_SECURITY_PROTOCOL") == "SSL":
    KAFKA_CONFIG["security_protocol"] = "SSL"
    KAFKA_CONFIG["ssl_context"] = ssl.create_default_context()

consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=BOOTSTRAP.split(","),
    auto_offset_reset="earliest",
    enable_auto_commit=False,
    group_id="honeypot-captor",
    value_deserializer=lambda value: json.loads(value.decode("utf-8")),
    **KAFKA_CONFIG,
)
sink = S3TelemetrySink()

print("[captor] Started", flush=True)
print(f"[captor] Topic: {TOPIC}", flush=True)

for message in consumer:
    event = message.value
    kafka_meta = {
        "topic": message.topic,
        "partition": message.partition,
        "offset": message.offset,
    }

    source = str(event.get("source", "unknown"))
    event_id = kafka_event_id(source, message.partition, message.offset, event)
    persisted = sink.persist(event, event_id, datetime.now(timezone.utc))

    print(
        f"[captor] "
        f"partition={message.partition} "
        f"offset={message.offset} "
        f"event_id={event_id} "
        f"raw_key={persisted['raw_key']} "
        f"normalized_key={persisted['normalized_key']} "
        f"event={json.dumps(event)}",
        flush=True,
    )
    consumer.commit()