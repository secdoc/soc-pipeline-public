#!/usr/bin/env python3
import importlib.util
import sys
import unittest
from pathlib import Path

MODULE = Path(__file__).parents[1] / "scripts/wazuh_manager_vendor_config.py"


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("wazuh_manager_vendor_config", MODULE)
        if spec is None or spec.loader is None:
            raise RuntimeError("unable to load manager config helper")
        cls.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.module
        spec.loader.exec_module(cls.module)

    def test_patch_adds_lists_and_replaces_exactly_one_hook(self):
        original = """<ossec_config><ruleset></ruleset><integration><hook_url>http://x/webhook_old</hook_url></integration></ossec_config>"""
        patched = self.module.patch_config(original, "old", "new")
        for name in ("bash_profile", "common-ports", "malicious-powershell"):
            self.assertEqual(patched.count(f"<list>etc/lists/{name}</list>"), 1)
        self.assertNotIn("old", patched)
        self.assertEqual(patched.count("new"), 1)

    def test_patch_refuses_missing_or_duplicate_hook(self):
        with self.assertRaises(ValueError):
            self.module.patch_config("<ossec_config><ruleset/></ossec_config>", "old", "new")
        duplicate = "<ossec_config><ruleset></ruleset><x>old</x><y>old</y></ossec_config>"
        with self.assertRaises(ValueError):
            self.module.patch_config(duplicate, "old", "new")

    def test_list_only_patch_preserves_existing_hook(self):
        original = "<ossec_config><ruleset></ruleset><hook_url>webhook_old</hook_url></ossec_config>"
        patched = self.module.add_list_entries(original)
        self.assertIn("webhook_old", patched)
        for name in ("bash_profile", "common-ports", "malicious-powershell"):
            self.assertEqual(patched.count(f"<list>etc/lists/{name}</list>"), 1)


if __name__ == "__main__":
    unittest.main()
