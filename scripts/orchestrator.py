#!/usr/bin/env python3

import hashlib
import json
import os
import re
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any

import boto3


BUCKET = os.environ["HONEYPOT_BUCKET"]
S3_ENDPOINT = os.environ.get("S3_ENDPOINT") or None
STATE_FILE = os.environ.get(
    "ORCHESTRATOR_STATE_FILE",
    "/var/lib/honeypot-orchestrator/processed.json",
)

s3 = boto3.client(
    "s3",
    region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    endpoint_url=S3_ENDPOINT,
)

NORMALIZED_PREFIX = "normalized/"
COMMAND_PREFIX = "orchestrator/commands/"
ORDERED_ACTIONS = (
    "credential_attack",
    "reconnaissance",
    "download_execution",
)

RECON_COMMANDS = {
    "uname",
    "whoami",
    "id",
    "pwd",
    "ls",
    "ll",
    "ps",
    "hostname",
    "env",
    "ifconfig",
    "ip",
    "netstat",
    "ss",
}

DOWNLOAD_COMMANDS = {
    "wget",
    "curl",
    "nc",
    "netcat",
    "ftp",
    "tftp",
}

EXECUTION_PATTERNS = [
    r"\bbash\s+-c\b",
    r"\bsh\s+-c\b",
    r"\bpython(?:3)?\b",
    r"\bperl\b",
    r"\bchmod\b",
    r"\bchown\b",
]


def list_normalized_keys() -> Iterator[str]:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BUCKET, Prefix=NORMALIZED_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".json"):
                yield key


def get_command(event: dict[str, Any]) -> str:
    command = event.get("process", {}).get("command_line")

    if command:
        return command.strip()

    original = event.get("original", {})
    data = original.get("data", {})

    return str(data.get("input", "")).strip()


def classify_event(event: dict[str, Any]) -> str | None:
    event_data = event.get("event", {})
    event_type = event_data.get("type", "")
    event_action = event_data.get("action", "")
    command = get_command(event).lower()

    if (event_type == "authentication" and event_action == "login") or event_type in {
        "login.failed",
        "login.success",
        "cowrie.login.failed",
        "cowrie.login.success",
    }:
        return "credential_attack"

    first_word = command.split()[0] if command else ""

    if first_word in DOWNLOAD_COMMANDS:
        return "download_execution"

    for pattern in EXECUTION_PATTERNS:
        if re.search(pattern, command):
            return "download_execution"

    if first_word in RECON_COMMANDS:
        return "reconnaissance"

    return None


def get_session_id(event: dict[str, Any]) -> str | None:
    session = event.get("session", {})
    if not isinstance(session, dict):
        return None
    value = session.get("id") or session.get("session_id")
    return str(value) if value is not None else None


def get_event_time(event: dict[str, Any]) -> datetime | None:
    time_data = event.get("time", {})
    if not isinstance(time_data, dict):
        return None

    return parse_timestamp(time_data.get("event")) or parse_timestamp(
        time_data.get("ingested")
    )


def get_ingested_time(event: dict[str, Any]) -> datetime | None:
    time_data = event.get("time", {})
    if not isinstance(time_data, dict):
        return None
    return parse_timestamp(time_data.get("ingested"))


def parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def get_kafka_order(event: dict[str, Any]) -> tuple[int, int]:
    provenance = event.get("provenance", {})
    kafka = provenance.get("kafka", {}) if isinstance(provenance, dict) else {}
    if not isinstance(kafka, dict):
        return -1, -1

    partition = kafka.get("partition")
    offset = kafka.get("offset")
    return (
        partition if isinstance(partition, int) else -1,
        offset if isinstance(offset, int) else -1,
    )


def load_action_events() -> list[dict[str, Any]]:
    records = []

    for key in list_normalized_keys():
        response = s3.get_object(Bucket=BUCKET, Key=key)
        event = json.loads(response["Body"].read())
        attack_type = classify_event(event)
        session_id = get_session_id(event)
        event_time = get_event_time(event)
        ingested_time = get_ingested_time(event) or event_time
        partition, offset = get_kafka_order(event)

        if attack_type and session_id and event_time:
            records.append({
                "key": key,
                "event": event,
                "attack_type": attack_type,
                "session_id": session_id,
                "event_time": event_time,
                "ingested_time": ingested_time,
                "partition": partition,
                "offset": offset,
            })

    return records


def find_ordered_sequences(
    records: list[dict[str, Any]],
) -> list[list[dict[str, Any]]]:
    sessions: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        sessions.setdefault(record["session_id"], []).append(record)

    sequences = []
    for session_records in sessions.values():
        session_records.sort(
            key=lambda record: (
                record["event_time"],
                record["ingested_time"],
                record["partition"],
                record["offset"],
                record["key"],
            )
        )
        current_sequence = []

        for record in session_records:
            attack_type = record["attack_type"]
            if attack_type == ORDERED_ACTIONS[0]:
                current_sequence = [record]
            elif (
                current_sequence
                and len(current_sequence) < len(ORDERED_ACTIONS)
                and attack_type == ORDERED_ACTIONS[len(current_sequence)]
            ):
                current_sequence.append(record)

            if len(current_sequence) == len(ORDERED_ACTIONS):
                sequences.append(current_sequence)
                current_sequence = []

    return sequences


def command_key_for_sequence(sequence: list[dict[str, Any]]) -> str:
    event_ids = [
        record["event"].get("event", {}).get("id") or record["key"]
        for record in sequence
    ]
    identity = json.dumps(
        [sequence[0]["session_id"], event_ids],
        separators=(",", ":"),
    )
    command_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    return f"{COMMAND_PREFIX}sequence-{command_id}.json"


def write_profile_command(sequence: list[dict[str, Any]]) -> str:
    output_key = command_key_for_sequence(sequence)
    action = {
        "action": "switch_profile",
        "profile": "investigation",
        "filesystem": "investigation",
        "reason": "ordered_attack_sequence_detected",
        "session_id": sequence[0]["session_id"],
        "sequence": list(ORDERED_ACTIONS),
        "sequence_event_ids": [
            record["event"].get("event", {}).get("id") or record["key"]
            for record in sequence
        ],
        "command_id": output_key.rsplit("/", 1)[-1][:-5],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    s3.put_object(
        Bucket=BUCKET,
        Key=output_key,
        Body=json.dumps(action, indent=2).encode("utf-8"),
        ContentType="application/json",
    )
    print(
        f"[orchestrator] Ordered sequence detected for "
        f"session={action['session_id']} -> investigation",
        flush=True,
    )
    return output_key


def load_processed() -> set[str]:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as state:
            value = json.load(state)
    except FileNotFoundError:
        return set()

    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError(f"invalid orchestrator state file: {STATE_FILE}")
    return set(value)


def save_processed(processed: set[str]) -> None:
    directory = os.path.dirname(STATE_FILE)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary = f"{STATE_FILE}.tmp"
    with open(temporary, "w", encoding="utf-8") as state:
        json.dump(sorted(processed), state)
    os.replace(temporary, STATE_FILE)


def main() -> None:
    processed = load_processed()
    sequences = find_ordered_sequences(load_action_events())

    for sequence in sequences:
        command_key = command_key_for_sequence(sequence)
        if command_key in processed:
            continue
        write_profile_command(sequence)
        processed.add(command_key)
        save_processed(processed)


if __name__ == "__main__":
    main()
