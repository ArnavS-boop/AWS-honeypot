#!/usr/bin/env python3

import datetime as dt
import hashlib
import json
import os
import re
from typing import Any

import boto3
from normalization_schema import normalize_event as schema_normalize_event

SCHEMA_VERSION = "1.0"
SAFE_SOURCE = re.compile(r"[^a-zA-Z0-9_.-]+")


def _first(event: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = event.get(key)
        if value is not None:
            return value
    return None


def _event_timestamp(event: dict[str, Any], received_at: dt.datetime) -> tuple[str, str]:
    value = _first(event, "timestamp", "time", "@timestamp")
    if isinstance(value, str):
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            parsed = parsed.astimezone(dt.timezone.utc)
            return parsed.isoformat().replace("+00:00", "Z"), parsed.date().isoformat()
        except ValueError:
            pass
    parsed = received_at.astimezone(dt.timezone.utc)
    return parsed.isoformat().replace("+00:00", "Z"), parsed.date().isoformat()


def _cowrie_event(event: dict[str, Any]) -> dict[str, Any]:
    data = event.get("data")
    return data if isinstance(data, dict) else event


def _source(event: dict[str, Any]) -> str:
    source = _first(event, "source", "sensor", "sensor_name")
    if source is None and str(event.get("eventid", "")).startswith("cowrie."):
        source = "cowrie"
    return str(source or "unknown")


def legacy_normalize_event(
    event: dict[str, Any], event_id: str, received_at: dt.datetime
) -> dict[str, Any]:
    source = _source(event)
    cowrie = _cowrie_event(event)
    timestamp, _ = _event_timestamp(event if event.get("timestamp") else cowrie, received_at)

    source_ip = _first(event, "source_ip", "src_ip", "remote_ip")
    source_port = _first(event, "source_port", "src_port", "remote_port")
    destination_ip = _first(event, "destination_ip", "dst_ip", "local_ip")
    destination_port = _first(event, "destination_port", "dst_port", "local_port")
    session_id = _first(event, "session_id", "session", "sessionid")
    event_type = _first(event, "event_type", "eventid", "event_type_name")

    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "timestamp": timestamp,
        "sensor": {"source": source},
        "network": {
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
        },
        "session": {"session_id": session_id},
        "activity": {
            "event_type": event_type,
            "command": _first(cowrie, "input", "command", "command_input", "cowrie.command.input"),
            "username": _first(cowrie, "username", "user", "cowrie.login.username"),
            "password": _first(cowrie, "password", "cowrie.login.password"),
            "client_version": _first(cowrie, "client_version", "version", "cowrie.client.version"),
            "key_exchange": _first(cowrie, "kex", "key_exchange", "cowrie.client.kex"),
            "parameters": _first(cowrie, "params", "parameters", "cowrie.session.params"),
        },
        "raw_event_id": event_id,
    }


class S3TelemetrySink:
    def __init__(self) -> None:
        self.bucket = os.environ["CAPTOR_S3_BUCKET"]
        self.endpoint_url = os.environ.get("CAPTOR_S3_ENDPOINT") or None
        self.region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.client = boto3.client(
            "s3", region_name=self.region, endpoint_url=self.endpoint_url
        )

    def persist(self, event: dict[str, Any], event_id: str, received_at: dt.datetime) -> dict[str, Any]:
        source = _source(event)
        source = SAFE_SOURCE.sub("-", source).strip("-") or "unknown"
        _, date = _event_timestamp(event, received_at)
        raw_key = f"raw/source={source}/date={date}/{event_id}.json"
        normalized = schema_normalize_event(
    event,
    kafka={
        "topic": "honeypot-telemetry",
    },
)
        normalized_key = f"normalized/source={source}/date={date}/{event_id}.json"

        self.client.put_object(
            Bucket=self.bucket,
            Key=raw_key,
            Body=json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            ContentType="application/json",
        )
        self.client.put_object(
            Bucket=self.bucket,
            Key=normalized_key,
            Body=json.dumps(normalized, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            ContentType="application/json",
        )
        return {"raw_key": raw_key, "normalized_key": normalized_key, "normalized": normalized}


def kafka_event_id(source: str, partition: int, offset: int, event: dict[str, Any]) -> str:
    source_part = SAFE_SOURCE.sub("-", source).strip("-") or "unknown"
    candidate = f"{source_part}-{partition}-{offset}"
    if partition >= 0 and offset >= 0:
        return candidate
    digest = hashlib.sha256(json.dumps(event, sort_keys=True).encode("utf-8")).hexdigest()[:20]
    return f"{source_part}-{digest}"
