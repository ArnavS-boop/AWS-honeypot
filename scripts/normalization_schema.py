from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"

def _first(d, *keys, default=None):
    for k in keys:
        if d.get(k) is not None:
            return d[k]
    return default

def normalize_event(raw, kafka=None):
    kafka = kafka or {}
    source = raw.get("source") or ("cowrie" if str(raw.get("event_type","")).startswith("cowrie.") else "unknown")

    if raw.get("telemetry_type") == "system_log":
        return normalize_machine_log(raw, kafka)

    data = raw.get("data") if isinstance(raw.get("data"), dict) else raw
    eventid = data.get("eventid") or raw.get("event_type") or "unknown"
    event_id = raw.get("event_id") or raw.get("id") or f"{eventid}-{kafka.get('partition','x')}-{kafka.get('offset','x')}"

    out = {
        "schema_version": SCHEMA_VERSION,
        "event": {"id": str(event_id), "type": None, "action": None, "outcome": None},
        "time": {
            "event": data.get("timestamp") or raw.get("timestamp"),
            "ingested": datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
        },
        "observer": {
            "type": "honeypot" if source in ("cowrie","dionaea") else "unknown",
            "host": data.get("sensor") or raw.get("sensor"),
            "product": source,
            "version": data.get("version"),
            "sensor": data.get("sensor") or raw.get("sensor")
        },
        "session": {"id": _first(raw, "session_id", "session", default=data.get("session"))},
        "source": {
            "ip": _first(raw, "source_ip", "src_ip", default=data.get("src_ip")),
            "port": _first(raw, "source_port", "src_port", default=data.get("src_port"))
        },
        "destination": {
            "ip": _first(raw, "destination_ip", "dst_ip", default=data.get("dst_ip")),
            "port": _first(raw, "destination_port", "dst_port", default=data.get("dst_port"))
        },
        "network": {"protocol": data.get("protocol") or raw.get("protocol")},
        "user": {"name": data.get("username")},
        "process": {"command_line": None},
        "file": {"name": None, "path": None, "sha256": None},
        "http": {"method": None, "url": None},
        "log": {"source": None, "file": None, "message": None},
        "activity": {"type": None},
        "original": deepcopy(raw),
        "vendor": {source: deepcopy(data)},
        "provenance": {"source": source, "raw_event_id": str(event_id), "kafka": kafka}
    }

    if eventid == "cowrie.command.input":
        out["event"].update(type="command", action="input")
        out["activity"]["type"] = "shell_command"
        out["process"]["command_line"] = data.get("input")
    elif eventid == "cowrie.command.success":
        out["event"].update(type="command", action="execute", outcome="success")
        out["activity"]["type"] = "shell_command"
        out["process"]["command_line"] = data.get("input")
    elif eventid == "cowrie.command.failed":
        out["event"].update(type="command", action="execute", outcome="failure")
        out["activity"]["type"] = "shell_command"
        out["process"]["command_line"] = data.get("input")
    elif eventid == "cowrie.session.input":
        out["event"].update(type="interactive_input", action="input")
        out["activity"]["type"] = "stdin"
        out["process"]["command_line"] = data.get("input")
    elif eventid == "cowrie.login.success":
        out["event"].update(type="authentication", action="login", outcome="success")
        out["activity"]["type"] = "authentication"
        out["user"]["name"] = data.get("username")
    elif eventid == "cowrie.login.failed":
        out["event"].update(type="authentication", action="login", outcome="failure")
        out["activity"]["type"] = "authentication"
        out["user"]["name"] = data.get("username")
    elif eventid == "cowrie.session.connect":
        out["event"].update(type="connection", action="connect")
        out["activity"]["type"] = "session"
    elif eventid == "cowrie.session.closed":
        out["event"].update(type="session", action="close")
        out["activity"]["type"] = "session"
        if "duration_ms" in data:
            out["session"]["duration_ms"] = data["duration_ms"]
    elif eventid == "cowrie.session.file_download":
        out["event"].update(type="file", action="download", outcome="success")
        out["activity"]["type"] = "file_transfer"
        out["file"].update(name=data.get("outfile"), path=data.get("destfile") or data.get("outfile"), sha256=data.get("shasum"))
        out["http"]["url"] = data.get("url")
    elif eventid == "cowrie.session.file_download.failed":
        out["event"].update(type="file", action="download", outcome="failure")
        out["activity"]["type"] = "file_transfer"
        out["http"]["url"] = data.get("url")
    elif eventid == "cowrie.session.file_upload":
        out["event"].update(type="file", action="upload", outcome="success")
        out["activity"]["type"] = "file_transfer"
        out["file"].update(name=data.get("filename"), path=data.get("destfile") or data.get("outfile"), sha256=data.get("shasum"))
    elif eventid == "cowrie.client.version":
        out["event"].update(type="client", action="identify")
        out["activity"]["type"] = "client_identification"
        out["client"] = {"version": data.get("version")}
    elif eventid == "cowrie.client.kex":
        out["event"].update(type="client", action="key_exchange")
        out["activity"]["type"] = "ssh_kex"
        out["client"] = {"kex": data.get("kex")}
    elif eventid == "cowrie.client.size":
        out["event"].update(type="client", action="terminal_size")
        out["activity"]["type"] = "terminal"
        out["session"]["terminal"] = {"width": data.get("width"), "height": data.get("height")}
    elif eventid == "cowrie.session.params":
        out["event"].update(type="session", action="parameters")
        out["activity"]["type"] = "session_parameters"
        if isinstance(data.get("params"), dict):
            out["session"]["parameters"] = deepcopy(data["params"])
    else:
        out["event"]["type"] = eventid
        out["activity"]["type"] = "cowrie_event"

    return out

def normalize_machine_log(raw, kafka=None):
    kafka = kafka or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "event": {
            "id": f"system-log-{kafka.get('partition','x')}-{kafka.get('offset','x')}",
            "type": "log", "action": "emit", "outcome": None
        },
        "time": {
            "event": raw.get("timestamp"),
            "ingested": datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
        },
        "observer": {
            "type": "machine", "host": raw.get("host"),
            "product": "system", "version": None, "sensor": raw.get("host")
        },
        "session": {"id": None},
        "source": {"ip": None, "port": None},
        "destination": {"ip": None, "port": None},
        "network": {"protocol": None},
        "user": {"name": None},
        "process": {"command_line": None},
        "file": {"name": None, "path": None, "sha256": None},
        "http": {"method": None, "url": None},
        "log": {
            "source": raw.get("log_source"),
            "file": raw.get("log_file"),
            "message": raw.get("message")
        },
        "activity": {"type": "system_log"},
        "original": deepcopy(raw),
        "provenance": {
            "source": "system",
            "raw_event_id": f"system-log-{kafka.get('partition','x')}-{kafka.get('offset','x')}",
            "kafka": kafka
        }
    }
