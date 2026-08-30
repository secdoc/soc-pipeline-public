#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).parents[1] / "scripts/prepare_socfortress_rules.py"


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("prepare_socfortress_rules", MODULE)
        if spec is None or spec.loader is None:
            raise RuntimeError("unable to load rules bundle builder")
        cls.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.module
        spec.loader.exec_module(cls.module)

    def fixture(self, root):
        (root / "Feature").mkdir()
        (root / "Feature" / "rules.xml").write_text(
            '<group name="test,"><rule id="100" level="3" overwrite="yes"><decoded_as>json</decoded_as>'
            '<description>base</description></rule><rule id="101" level="5">'
            '<if_sid>100</if_sid><list>etc/lists/example-list</list>'
            '<description>child</description></rule></group>'
        )
        (root / "Feature" / "decoder.xml").write_text(
            '<decoder name="example"><prematch>example</prematch></decoder>'
        )
        (root / "Feature" / "example-list").write_text("key:value\n")

    def test_missing_license_requires_explicit_acknowledgment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            root.mkdir()
            self.fixture(root)
            with self.assertRaises(ValueError):
                self.module.build_bundle(root, Path(directory) / "out", {100})

    def test_collision_is_remapped_with_parent_reference_and_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            out = Path(directory) / "out"
            root.mkdir()
            self.fixture(root)
            manifest = self.module.build_bundle(
                root,
                out,
                {100},
                allow_unlicensed=True,
                commit="abc123",
            )
            rule_path = next((out / "rules").glob("*.xml"))
            rule = rule_path.read_text()
            self.assertTrue(rule_path.name.startswith("000100_"))
            self.assertIn('id="910000"', rule)
            self.assertIn("<if_sid>910000</if_sid>", rule)
            self.assertNotIn("overwrite=", rule)
            self.assertIn("socfortress_vendor", rule)
            self.assertTrue(any((out / "decoders").glob("*.xml")))
            self.assertEqual((out / "lists" / "example-list").read_text(), "key:value\n")
            self.assertEqual(manifest["remapped_rule_ids"], {"100": 910000})
            self.assertEqual(manifest["source_commit"], "abc123")
            self.assertTrue((out / "manifest.json").exists())

    def test_internal_duplicate_rule_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            root.mkdir()
            self.fixture(root)
            (root / "Feature" / "duplicate.xml").write_text(
                '<group name="test,"><rule id="100" level="3">'
                '<description>duplicate</description></rule></group>'
            )
            with self.assertRaises(ValueError):
                self.module.build_bundle(
                    root,
                    Path(directory) / "out",
                    set(),
                    allow_unlicensed=True,
                )

    def test_multiple_wazuh_top_level_elements_are_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            out = Path(directory) / "out"
            root.mkdir()
            (root / "multi.xml").write_text(
                '<group name="one,"><rule id="200" level="3">'
                '<description>one</description></rule></group>\n'
                '<group name="two,"><rule id="201" level="3">'
                '<description>two</description></rule></group>\n'
            )
            manifest = self.module.build_bundle(
                root, out, set(), allow_unlicensed=True
            )
            self.assertEqual(manifest["rule_ids"], 2)

    def test_rule_with_unresolved_parent_is_excluded_and_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            out = Path(directory) / "out"
            root.mkdir()
            (root / "broken.xml").write_text(
                '<group name="test,"><rule id="300" level="3">'
                '<if_sid>299</if_sid><description>broken</description>'
                '</rule><rule id="301" level="3">'
                '<description>valid</description></rule></group>'
            )
            manifest = self.module.build_bundle(
                root, out, set(), allow_unlicensed=True
            )
            self.assertEqual(manifest["excluded_unresolved_rules"], {"300": [299]})
            self.assertNotIn('id="300"', next((out / "rules").glob("*.xml")).read_text())

    def test_known_sysmon_group_alias_is_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            out = Path(directory) / "out"
            root.mkdir()
            (root / "group.xml").write_text(
                '<group name="test,"><rule id="400" level="1">'
                '<if_group>sysmon_event_7</if_group>'
                '<description>exclude</description></rule></group>'
            )
            self.module.build_bundle(root, out, set(), allow_unlicensed=True)
            text = next((out / "rules").glob("*.xml")).read_text()
            self.assertIn("<if_group>sysmon_event7</if_group>", text)
            self.assertNotIn("sysmon_event_7", text)


if __name__ == "__main__":
    unittest.main()
