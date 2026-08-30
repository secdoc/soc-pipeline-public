#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "collector" / "run_pipeline.py"


def load_module():
    spec = importlib.util.spec_from_file_location("greenbone_pipeline", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GreenbonePipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_named_graylog_endpoint_supports_https(self):
        endpoint = self.module.parse_graylog_endpoint(
            "target=graylog.example.local:12213:https"
        )
        self.assertEqual(
            {
                "name": "target",
                "host": "graylog.example.local",
                "port": 12213,
                "transport": "https",
            },
            endpoint,
        )

    def test_named_wazuh_endpoint_supports_tcp(self):
        endpoint = self.module.parse_wazuh_endpoint(
            "target=198.51.100.39:5514:tcp"
        )
        self.assertEqual(
            {
                "name": "target",
                "host": "198.51.100.39",
                "port": 5514,
                "transport": "tcp",
            },
            endpoint,
        )

    def test_stable_event_hash_uses_complete_source_identity(self):
        event = {
            "report_id": "report-1",
            "nvt_oid": "1.3.6.1.4.1",
            "host": "192.0.2.10",
            "vuln_port": "443/tcp",
            "severity": 8.1,
            "scan_end": "2026-08-30T10:00:00Z",
        }
        expected = hashlib.sha256(
            b"report-1\n1.3.6.1.4.1\n192.0.2.10\n443/tcp\n8.1\n2026-08-30T10:00:00Z"
        ).hexdigest()
        self.assertEqual(expected, self.module.stable_event_hash(event))
        gelf = self.module.to_gelf(event, "greenbone-scanner")
        self.assertEqual(expected, gelf["_event_hash"])
        self.assertEqual("greenbone", gelf["_feed_source"])
        self.assertEqual(expected, self.module.wazuh_event(event)["event_hash"])

    def test_existing_sha1_state_prevents_replay_during_hash_transition(self):
        event = {"report_id": "report-1", "nvt_oid": "oid-1", "host": "192.0.2.10"}
        delivered = {self.module.legacy_finding_key(event)}
        self.assertTrue(self.module.was_delivered(event, delivered))

    def test_delivery_failure_does_not_advance_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps({"keys": ["existing"]}))
            event = {"report_id": "report-2", "nvt_oid": "oid-2", "host": "192.0.2.20"}

            def success(events):
                return len(events)

            def failure(events):
                raise ConnectionError("Wazuh unavailable")

            with self.assertRaises(ConnectionError):
                self.module.deliver_then_commit(
                    state,
                    {"existing"},
                    [event],
                    [("graylog:target", success), ("wazuh", failure)],
                )
            self.assertEqual({"keys": ["existing"]}, json.loads(state.read_text()))

    def test_https_graylog_requires_success_for_each_event(self):
        connection = mock.Mock()
        accepted = mock.Mock(status=202)
        connection.getresponse.side_effect = [accepted, accepted]
        with mock.patch.object(
            self.module.http.client, "HTTPSConnection", return_value=connection
        ):
            delivered = self.module.send_graylog_http(
                [{"report_id": "one"}, {"report_id": "two"}],
                "graylog.example.local",
                12213,
                "greenbone-scanner",
                mock.Mock(),
            )
        self.assertEqual(2, delivered)
        self.assertEqual(2, connection.request.call_count)
        self.assertEqual(2, accepted.read.call_count)
        connection.close.assert_called_once()

    def test_wazuh_nonzero_exit_is_a_required_delivery_failure(self):
        result = mock.Mock(returncode=1, stderr="append denied")
        with mock.patch.object(self.module.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError):
                self.module.append_wazuh(
                    [{"report_id": "one"}],
                    {
                        "WAZUH_SSH_KEY": "/missing",
                        "WAZUH_SSH_USER": "collector",
                        "WAZUH_SSH_HOST": "manager",
                    },
                    "/var/ossec/logs/greenbone/findings.jsonl",
                )

    def test_wazuh_tcp_is_newline_delimited(self):
        connection = mock.Mock()
        event = {"report_id": "report-1", "event_hash": "a" * 64}
        with mock.patch.object(
            self.module.socket, "create_connection", return_value=connection
        ):
            delivered = self.module.send_wazuh_tcp(
                [event], "198.51.100.39", 5514
            )
        self.assertEqual(delivered, 1)
        payload = connection.sendall.call_args.args[0]
        self.assertTrue(payload.endswith(b"\n"))
        expected = dict(event)
        expected["event_hash"] = self.module.stable_event_hash(event)
        self.assertEqual(expected, json.loads(payload))


if __name__ == "__main__":
    unittest.main()
