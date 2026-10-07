#!/usr/bin/env python3

import json
import os
import time
from urllib import request

import boto3


BUCKET = os.environ["HONEYPOT_BUCKET"]
S3_ENDPOINT = os.environ.get("S3_ENDPOINT") or None
COMMAND_PREFIX = os.environ.get("COMMAND_PREFIX", "orchestrator/commands/")
CONTROLLER_URL = os.environ.get(
    "DECOY_CONTROLLER_URL", "http://127.0.0.1:9000/profile"
)
ALLOWED_PROFILES = {"baseline", "investigation"}
POLL_SECONDS = int(os.environ.get("COMMAND_POLL_SECONDS", "10"))
STATE_FILE = os.environ.get(
    "COMMAND_STATE_FILE", "/var/lib/decoy-command-dispatcher/processed.json"
)

s3 = boto3.client(
    "s3",
    region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    endpoint_url=S3_ENDPOINT,
)


def load_processed():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as state:
            value = json.load(state)
    except FileNotFoundError:
        return set()
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError(f"invalid dispatcher state file: {STATE_FILE}")
    return set(value)


def save_processed(processed):
    directory = os.path.dirname(STATE_FILE)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary = f"{STATE_FILE}.tmp"
    with open(temporary, "w", encoding="utf-8") as state:
        json.dump(sorted(processed), state)
    os.replace(temporary, STATE_FILE)


def list_command_keys():
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BUCKET, Prefix=COMMAND_PREFIX):
        for item in page.get("Contents", []):
            key = item["Key"]
            if key.endswith(".json"):
                yield key


def dispatch(key):
    response = s3.get_object(Bucket=BUCKET, Key=key)
    command = json.loads(response["Body"].read())
    if command.get("action") != "switch_profile":
        raise ValueError(f"unsupported action in {key}")

    profile = command.get("profile")
    if profile not in ALLOWED_PROFILES:
        raise ValueError(f"unsupported profile in {key}: {profile}")

    body = json.dumps({"profile": profile}).encode("utf-8")
    request_data = request.Request(
        CONTROLLER_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(request_data, timeout=30) as result:
        if result.status != 200:
            raise RuntimeError(f"controller returned HTTP {result.status}")
        acknowledgement = json.loads(result.read().decode("utf-8"))
        if (
            acknowledgement.get("status") != "applied"
            or acknowledgement.get("profile") != profile
        ):
            raise RuntimeError(f"controller did not apply profile from {key}")
    print(f"[dispatcher] Applied profile={profile} from {key}", flush=True)


def run_once(processed=None):
    processed = load_processed() if processed is None else processed
    for key in list_command_keys():
        if key in processed:
            continue
        dispatch(key)
        processed.add(key)
        save_processed(processed)
    return processed


def main():
    print("[dispatcher] Started", flush=True)
    while True:
        try:
            run_once()
        except Exception as exc:
            print(f"[dispatcher] ERROR: {exc}", flush=True)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()