from normalization_schema import normalize_event

event = {
    "source":"cowrie",
    "event_type":"cowrie.command.input",
    "timestamp":"2026-09-19T12:34:56Z",
    "session_id":"s3-verification-001",
    "source_ip":"198.51.100.20",
    "source_port":4242,
    "destination_ip":"10.0.0.20",
    "destination_port":22,
    "data":{
        "eventid":"cowrie.command.input",
        "timestamp":"2026-09-19T12:34:56Z",
        "session":"s3-verification-001",
        "src_ip":"198.51.100.20",
        "src_port":4242,
        "dst_ip":"10.0.0.20",
        "dst_port":22,
        "input":"uname -a",
        "version":"Cowrie-3.0.14",
        "params":{"username":"root","success":True}
    }
}
out = normalize_event(event, {"topic":"honeypot-telemetry","partition":0,"offset":11})
assert out["process"]["command_line"] == "uname -a"
assert out["user"]["name"] is None  # current wrapper stores username inside params
assert out["session"]["id"] == "s3-verification-001"
assert out["source"]["ip"] == "198.51.100.20"
assert out["destination"]["port"] == 22
print("NORMALIZATION TEST PASSED")
print(out)
