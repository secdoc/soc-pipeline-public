from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from security_portal.server import PortalServer, build_payload


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 4, 22, 54, 39, tzinfo=timezone.utc)


class PayloadTests(unittest.TestCase):
    def test_payload_contains_portal_overview_and_integrations(self) -> None:
        config = {
            "portal": {"title": "Security Visibility", "refresh_seconds": 30},
            "integrations": [
                {
                    "id": "wazuh",
                    "name": "Wazuh",
                    "category": "soc",
                    "connector": "static",
                    "state": "healthy",
                    "collected_at": "2026-09-04T22:54:00Z",
                    "summary": {"critical_alerts": 2},
                    "max_age_seconds": 300,
                    "deep_link": "https://wazuh.example.com/",
                }
            ],
        }

        payload = build_payload(config, now=NOW)

        self.assertEqual(payload["portal"]["title"], "Security Visibility")
        self.assertEqual(payload["overview"]["critical_alerts"], 2)
        self.assertEqual(payload["integrations"][0]["state"], "healthy")
        self.assertNotIn("connector", payload["integrations"][0])


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        config = {
            "portal": {"title": "Security Visibility", "refresh_seconds": 30},
            "integrations": [
                {
                    "id": "catalog",
                    "name": "Tool catalog",
                    "category": "platform",
                    "connector": "static",
                    "state": "planned",
                    "collected_at": None,
                    "summary": {"native_access": "preserved"},
                    "max_age_seconds": 300,
                    "deep_link": "https://tools.example.com/",
                }
            ],
        }
        cls.server = PortalServer(("localhost", 0), config=config, static_root=ROOT / "security_portal" / "static")
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://localhost:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_health_endpoint_and_security_headers(self) -> None:
        with urllib.request.urlopen(self.base + "/healthz", timeout=2) as response:
            body = json.load(response)
            headers = response.headers

        self.assertEqual(body, {"status": "ok"})
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_overview_api_returns_normalized_data(self) -> None:
        with urllib.request.urlopen(self.base + "/api/v1/overview", timeout=2) as response:
            body = json.load(response)

        self.assertEqual(body["portal"]["title"], "Security Visibility")
        self.assertEqual(body["integrations"][0]["id"], "catalog")

    def test_index_and_assets_are_served_without_external_dependencies(self) -> None:
        with urllib.request.urlopen(self.base + "/", timeout=2) as response:
            html = response.read().decode()
        with urllib.request.urlopen(self.base + "/app.js", timeout=2) as response:
            script = response.read().decode()

        self.assertIn("Security Visibility Portal", html)
        self.assertIn("/api/v1/overview", script)
        self.assertNotIn("https://", html)
        self.assertNotIn("http://", html)

    def test_post_is_rejected(self) -> None:
        request = urllib.request.Request(self.base + "/api/v1/overview", data=b"{}", method="POST")

        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=2)

        self.assertEqual(caught.exception.code, 405)

    def test_unknown_path_returns_not_found(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(self.base + "/does-not-exist", timeout=2)

        self.assertEqual(caught.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
