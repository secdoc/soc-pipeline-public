#!/usr/bin/env python3
import importlib.util
import sys
import unittest
from pathlib import Path

MODULE = Path(__file__).parents[1] / "scripts/wazuh_agent_migration.py"


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("wazuh_agent_migration", MODULE)
        if spec is None or spec.loader is None:
            raise RuntimeError("unable to load migration helper")
        cls.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.module
        spec.loader.exec_module(cls.module)

    def test_activation_uses_explicit_process_boundary(self):
        script = self.module.render_activation_script(
            "/root/target-ossec.conf",
            "/root/target-client.keys",
            "wazuh-agent.example.local",
        )
        self.assertIn("systemctl stop wazuh-agent", script)
        self.assertIn("pgrep -x wazuh-agentd", script)
        self.assertIn("wazuh-agentd did not exit", script)
        self.assertIn("wazuh-agentd -t", script)
        self.assertIn("systemctl start wazuh-agent", script)
        self.assertIn("wazuh-agent.example.local:1514", script)
        self.assertNotIn("systemctl restart wazuh-agent", script)

    def test_rollback_uses_same_process_boundary_and_hash_gates(self):
        script = self.module.render_rollback_script(
            "/root/source-ossec.conf",
            "/root/source-client.keys",
            "a" * 64,
            "b" * 64,
            "198.51.100.243",
        )
        self.assertIn("systemctl stop wazuh-agent", script)
        self.assertIn("pgrep -x wazuh-agentd", script)
        self.assertIn("sha256sum", script)
        self.assertIn("a" * 64, script)
        self.assertIn("b" * 64, script)
        self.assertIn("systemctl start wazuh-agent", script)
        self.assertNotIn("systemctl restart wazuh-agent", script)

    def test_acceptance_reports_every_failed_field(self):
        expected = {
            "target_status": "active",
            "groups_exact": True,
            "group_synced": True,
            "target_connection": True,
            "source_disconnected": True,
            "service_active": True,
            "samba_active": True,
            "drs_all_good": True,
            "failed_shards": 0,
        }
        observed: dict[str, object] = {key: False for key in expected}
        observed["target_status"] = "disconnected"
        observed["failed_shards"] = 2
        failures = self.module.acceptance_failures(observed, expected)
        self.assertEqual(len(failures), len(expected))
        self.assertIn("target_status", failures)
        self.assertIn("failed_shards", failures)


if __name__ == "__main__":
    unittest.main()
