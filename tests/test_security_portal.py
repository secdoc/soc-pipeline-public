from __future__ import annotations

import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from security_portal.config import ConfigError, load_config
from security_portal.connectors import collect_integration
from security_portal.model import aggregate_overview, classify_snapshot


NOW = datetime(2026, 9, 4, 22, 54, 39, tzinfo=timezone.utc)


class SnapshotClassificationTests(unittest.TestCase):
    def test_fresh_healthy_snapshot_is_healthy(self) -> None:
        snapshot = classify_snapshot(
            integration_id="wazuh",
            name="Wazuh",
            collected_at="2026-09-04T22:53:39Z",
            max_age_seconds=120,
            source_state="healthy",
            summary={"critical_alerts": 0},
            deep_link="https://wazuh.example.com/",
            now=NOW,
        )

        self.assertEqual(snapshot["state"], "healthy")
        self.assertEqual(snapshot["freshness"], "fresh")
        self.assertEqual(snapshot["age_seconds"], 60)

    def test_old_healthy_snapshot_is_stale_not_healthy(self) -> None:
        snapshot = classify_snapshot(
            integration_id="graylog",
            name="Graylog",
            collected_at="2026-09-04T22:40:00Z",
            max_age_seconds=300,
            source_state="healthy",
            summary={},
            deep_link="https://graylog.example.com/",
            now=NOW,
        )

        self.assertEqual(snapshot["state"], "stale")
        self.assertEqual(snapshot["freshness"], "stale")

    def test_missing_timestamp_is_unknown_not_healthy(self) -> None:
        snapshot = classify_snapshot(
            integration_id="pbs",
            name="Backup",
            collected_at=None,
            max_age_seconds=300,
            source_state="healthy",
            summary={},
            deep_link=None,
            now=NOW,
        )

        self.assertEqual(snapshot["state"], "unknown")
        self.assertEqual(snapshot["freshness"], "unknown")

    def test_unauthorized_state_is_preserved(self) -> None:
        snapshot = classify_snapshot(
            integration_id="proxmox",
            name="Proxmox",
            collected_at="2026-09-04T22:54:00Z",
            max_age_seconds=300,
            source_state="unauthorized",
            summary={},
            deep_link=None,
            now=NOW,
        )

        self.assertEqual(snapshot["state"], "unauthorized")


class ConfigTests(unittest.TestCase):
    def write_config(self, value: dict) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "portal.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_load_config_accepts_read_only_file_connector(self) -> None:
        path = self.write_config(
            {
                "portal": {"title": "SOC", "refresh_seconds": 30},
                "integrations": [
                    {
                        "id": "siem-health",
                        "name": "SIEM health",
                        "category": "platform",
                        "connector": "json_file",
                        "path": "/run/soc/health.json",
                        "collected_at_path": "collected_at",
                        "state_path": "state",
                        "summary_paths": {"findings": "finding_count"},
                        "max_age_seconds": 600,
                        "deep_link": "https://siem.example.com/",
                    }
                ],
            }
        )

        config = load_config(path)

        self.assertEqual(config["integrations"][0]["connector"], "json_file")

    def test_load_config_rejects_mutating_http_method(self) -> None:
        path = self.write_config(
            {
                "portal": {"title": "SOC", "refresh_seconds": 30},
                "integrations": [
                    {
                        "id": "unsafe",
                        "name": "Unsafe",
                        "category": "response",
                        "connector": "http_json",
                        "url": "https://soar.example.com/api/run",
                        "method": "POST",
                        "max_age_seconds": 60,
                    }
                ],
            }
        )

        with self.assertRaisesRegex(ConfigError, "GET"):
            load_config(path)

    def test_load_config_rejects_javascript_deep_link(self) -> None:
        path = self.write_config(
            {
                "portal": {"title": "SOC", "refresh_seconds": 30},
                "integrations": [
                    {
                        "id": "bad-link",
                        "name": "Bad link",
                        "category": "platform",
                        "connector": "static",
                        "state": "unknown",
                        "deep_link": "javascript:alert(1)",
                        "max_age_seconds": 60,
                    }
                ],
            }
        )

        with self.assertRaisesRegex(ConfigError, "deep_link"):
            load_config(path)

    def test_load_config_requires_exact_http_origin_allowlist(self) -> None:
        path = self.write_config(
            {
                "portal": {"title": "SOC", "refresh_seconds": 30},
                "integrations": [
                    {
                        "id": "api",
                        "name": "API",
                        "category": "platform",
                        "connector": "http_json",
                        "url": "https://api.example.com:8443/health",
                        "allowed_origins": ["https://other.example.com:8443"],
                        "max_age_seconds": 60,
                    }
                ],
            }
        )

        with self.assertRaisesRegex(ConfigError, "allowed_origins"):
            load_config(path)

    def test_load_config_accepts_exact_http_origin_allowlist(self) -> None:
        path = self.write_config(
            {
                "portal": {"title": "SOC", "refresh_seconds": 30},
                "integrations": [
                    {
                        "id": "api",
                        "name": "API",
                        "category": "platform",
                        "connector": "http_json",
                        "url": "https://api.example.com:8443/health",
                        "allowed_origins": ["https://api.example.com:8443"],
                        "max_age_seconds": 60,
                    }
                ],
            }
        )

        config = load_config(path)

        self.assertEqual(config["integrations"][0]["id"], "api")


class ConnectorTests(unittest.TestCase):
    def test_json_file_connector_maps_summary_and_classifies_freshness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "latest.json"
            evidence.write_text(
                json.dumps(
                    {
                        "collected_at": "2026-09-04T22:53:39Z",
                        "healthy": False,
                        "findings": ["queue backlog", "certificate expiry"],
                        "wazuh": {"contract_alerts_30m": 18},
                    }
                ),
                encoding="utf-8",
            )
            spec = {
                "id": "enterprise-siem",
                "name": "Enterprise SIEM",
                "category": "soc",
                "connector": "json_file",
                "path": str(evidence),
                "collected_at_path": "collected_at",
                "healthy_path": "healthy",
                "summary_paths": {
                    "active_findings": "findings",
                    "alerts_30m": "wazuh.contract_alerts_30m",
                },
                "max_age_seconds": 300,
                "deep_link": "https://wazuh.example.com/",
            }

            result = collect_integration(spec, now=NOW)

        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["summary"]["active_findings"], 2)
        self.assertEqual(result["summary"]["alerts_30m"], 18)

    def test_missing_file_is_unavailable_with_safe_reason(self) -> None:
        spec = {
            "id": "missing",
            "name": "Missing source",
            "category": "platform",
            "connector": "json_file",
            "path": "/definitely/not/present.json",
            "max_age_seconds": 60,
        }

        result = collect_integration(spec, now=NOW)

        self.assertEqual(result["state"], "unavailable")
        self.assertEqual(result["reason_code"], "source_unavailable")
        self.assertNotIn("/definitely/not/present.json", result.get("detail", ""))

    def test_http_connector_does_not_follow_redirects(self) -> None:
        class RedirectHandler(BaseHTTPRequestHandler):
            target_hits = 0

            def log_message(self, format: str, *args: object) -> None:
                pass

            def do_GET(self) -> None:
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/target")
                    self.end_headers()
                    return
                type(self).target_hits += 1
                body = json.dumps({"state": "healthy", "collected_at": "2026-09-04T22:54:00Z"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("localhost", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop_server() -> None:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.addCleanup(stop_server)
        spec = {
            "id": "redirect",
            "name": "Redirecting source",
            "category": "platform",
            "connector": "http_json",
            "url": f"http://localhost:{server.server_port}/redirect",
            "allowed_origins": [f"http://localhost:{server.server_port}"],
            "state_path": "state",
            "collected_at_path": "collected_at",
            "max_age_seconds": 60,
        }

        result = collect_integration(spec, now=NOW)

        self.assertEqual(result["state"], "unavailable")
        self.assertEqual(result["reason_code"], "source_redirect_refused")
        self.assertEqual(RedirectHandler.target_hits, 0)


class OverviewTests(unittest.TestCase):
    def test_overview_counts_nonhealthy_states_and_critical_alerts(self) -> None:
        integrations = [
            {"id": "a", "state": "healthy", "summary": {"critical_alerts": 2}},
            {"id": "b", "state": "stale", "summary": {"critical_alerts": 3}},
            {"id": "c", "state": "unauthorized", "summary": {}},
        ]

        overview = aggregate_overview(integrations, generated_at=NOW)

        self.assertEqual(overview["state"], "degraded")
        self.assertEqual(overview["counts"]["stale"], 1)
        self.assertEqual(overview["counts"]["unauthorized"], 1)
        self.assertEqual(overview["critical_alerts"], 5)


if __name__ == "__main__":
    unittest.main()
