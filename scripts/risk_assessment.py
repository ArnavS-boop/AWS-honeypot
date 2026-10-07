#!/usr/bin/env python3

import hashlib
import json
import os
import re
from collections import Counter
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any

import boto3


BUCKET = os.environ["HONEYPOT_BUCKET"]
S3_ENDPOINT = os.environ.get("S3_ENDPOINT") or None
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
REPORT_STATE_FILE = os.environ.get(
    "RISK_REPORT_STATE_FILE",
    "/var/lib/honeypot-risk-assessment/last-report.json",
)

s3 = boto3.client(
    "s3",
    region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    endpoint_url=S3_ENDPOINT,
)

sns = boto3.client(
    "sns",
    region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    endpoint_url=S3_ENDPOINT,
)

RULES = {
    "reconnaissance": 20,
    "credential_attack": 30,
    "download_execution": 50,
}


def list_normalized_keys() -> Iterator[str]:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BUCKET, Prefix="normalized/"):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".json"):
                yield key


def get_command(event: dict[str, Any]) -> str:
    command = event.get("process", {}).get("command_line")

    if command:
        return command.strip().lower()

    original = event.get("original", {})
    data = original.get("data", {})

    return str(data.get("input", "")).strip().lower()


def classify_event(event: dict[str, Any]) -> str | None:
    event_data = event.get("event", {})
    event_type = event_data.get("type", "")
    event_action = event_data.get("action", "")
    command = get_command(event)

    recon = {
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

    download = {
        "wget",
        "curl",
        "nc",
        "netcat",
        "ftp",
        "tftp",
    }

    if (event_type == "authentication" and event_action == "login") or event_type in {
        "login.failed",
        "login.success",
        "cowrie.login.failed",
        "cowrie.login.success",
    }:
        return "credential_attack"

    first_word = command.split()[0] if command else ""

    if first_word in download:
        return "download_execution"

    if any(re.search(pattern, command) for pattern in (
        r"\bbash\s+-c\b",
        r"\bsh\s+-c\b",
        r"\bpython(?:3)?\b",
        r"\bperl\b",
        r"\bchmod\b",
        r"\bchown\b",
    )):
        return "download_execution"

    if first_word in recon:
        return "reconnaissance"

    return None


def build_alert(
    event: dict[str, Any], attack_type: str, score: int
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_type": attack_type,
        "risk_score": score,
        "session_id": event.get("session", {}).get("id"),
        "source_ip": event.get("source", {}).get("ip"),
        "source_port": event.get("source", {}).get("port"),
        "command": get_command(event),
        "message": f"{attack_type} detected. Risk score: {score}",
    }


def load_risk_events() -> tuple[list[dict[str, Any]], int]:
    events = []
    analyzed_count = 0

    for key in list_normalized_keys():
        response = s3.get_object(Bucket=BUCKET, Key=key)
        event = json.loads(response["Body"].read())
        analyzed_count += 1
        attack_type = classify_event(event)
        if attack_type:
            events.append({
                "key": key,
                "attack_type": attack_type,
                "event": event,
            })

    return events, analyzed_count


def build_report(
    events: list[dict[str, Any]], analyzed_count: int
) -> dict[str, Any]:
    attack_counts = Counter(
        record["attack_type"] for record in events
    )
    source_counts = Counter()
    sessions = set()

    for record in events:
        event = record["event"]
        source = event.get("source", {}).get("ip")
        if source:
            source_counts[str(source)] += 1
        session_id = event.get("session", {}).get("id")
        if session_id:
            sessions.add(str(session_id))

    score = min(
        100,
        sum(RULES[record["attack_type"]] for record in events),
    )
    if score >= 80:
        risk_level = "critical"
    elif score >= 50:
        risk_level = "high"
    elif score >= 20:
        risk_level = "moderate"
    else:
        risk_level = "low"

    identity = [
        (record["key"], record["attack_type"])
        for record in sorted(events, key=lambda item: item["key"])
    ]
    report_id = hashlib.sha256(
        json.dumps(identity, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    return {
        "report_id": report_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events_analyzed": analyzed_count,
        "detected_events": len(events),
        "attack_counts": {
            attack_type: attack_counts.get(attack_type, 0)
            for attack_type in RULES
        },
        "unique_sessions": len(sessions),
        "top_source_ips": [
            {"ip": ip, "events": count}
            for ip, count in source_counts.most_common(10)
        ],
        "risk_score": score,
        "risk_level": risk_level,
        "message": (
            f"Analyzed {analyzed_count} honeypot events; "
            f"{len(events)} matched risk rules. "
            f"Aggregate risk: {risk_level} ({score}/100)."
        ),
    }


def load_last_report_id() -> str | None:
    try:
        with open(REPORT_STATE_FILE, "r", encoding="utf-8") as state:
            value = json.load(state)
    except FileNotFoundError:
        return None

    if not isinstance(value, dict) or not isinstance(value.get("report_id"), str):
        raise ValueError(f"invalid risk report state file: {REPORT_STATE_FILE}")
    return value["report_id"]


def save_last_report_id(report_id: str) -> None:
    directory = os.path.dirname(REPORT_STATE_FILE)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary = f"{REPORT_STATE_FILE}.tmp"
    with open(temporary, "w", encoding="utf-8") as state:
        json.dump({"report_id": report_id}, state)
    os.replace(temporary, REPORT_STATE_FILE)


def run_once() -> dict[str, Any] | None:
    events, analyzed_count = load_risk_events()
    if not events:
        print(
            f"[risk] Analyzed {analyzed_count} events; no risk rules matched",
            flush=True,
        )
        return None

    report = build_report(events, analyzed_count)
    if report["report_id"] == load_last_report_id():
        print(f"[risk] Report {report['report_id']} already sent", flush=True)
        return report

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"Honeypot Risk Report: {report['risk_level'].upper()}",
        Message=json.dumps(report, indent=2),
    )
    save_last_report_id(report["report_id"])
    print(
        f"[risk] Published report {report['report_id']} "
        f"score={report['risk_score']} level={report['risk_level']}",
        flush=True,
    )
    return report


def main() -> None:
    run_once()


if __name__ == "__main__":
    main()
