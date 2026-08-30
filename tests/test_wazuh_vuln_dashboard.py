#!/usr/bin/env python3
import importlib.util
import json
import sys
import unittest
from pathlib import Path

MODULE = Path(__file__).parents[1] / "scripts/wazuh_dashboard_gen.py"


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("wazuh_vuln_dashboard", MODULE)
        if spec is None or spec.loader is None:
            raise RuntimeError("unable to load vulnerability dashboard generator")
        cls.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.module
        spec.loader.exec_module(cls.module)

    def test_dashboard_tracks_distinct_stable_findings(self):
        objects = cls_objects = self.module.build_objects()
        unique = next(item for item in cls_objects if item["id"] == "vuln_kpi_unique")
        state = json.loads(unique["attributes"]["visState"])
        metric = next(agg for agg in state["aggs"] if agg["type"] == "cardinality")
        self.assertEqual(metric["params"]["field"], "data.event_hash")
        self.assertTrue(objects)

    def test_dashboard_identifies_portable_target_and_fills_rows(self):
        objects = self.module.build_objects()
        dashboard = self.module.build_dashboard(
            "soc-pipeline-vuln-greenbone",
            "SOC Pipeline - Vulnerability (Greenbone)",
            [item["id"] for item in objects],
        )
        self.assertIn("portable", dashboard["attributes"]["description"])
        panels = json.loads(dashboard["attributes"]["panelsJSON"])
        widths = {}
        for panel in panels:
            widths.setdefault(panel["gridData"]["y"], 0)
            widths[panel["gridData"]["y"]] += panel["gridData"]["w"]
        self.assertTrue(widths)
        self.assertTrue(all(width == 48 for width in widths.values()))


if __name__ == "__main__":
    unittest.main()
