import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from security_portal.config import ConfigError, load_config
from security_portal.model import ENTITY_TYPES, RELATIONSHIP_TYPES, SCHEMA_VERSION, data_contract
from security_portal.server import build_payload


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)


class CerebroContractTests(unittest.TestCase):
    def test_schema_and_runtime_vocabulary_are_synchronized(self) -> None:
        schema = json.loads((ROOT / "contracts/cerebro-integration-v1.schema.json").read_text())

        self.assertEqual(schema["properties"]["schema_version"]["const"], SCHEMA_VERSION)
        self.assertEqual(schema["$defs"]["entity"]["properties"]["type"]["enum"], list(ENTITY_TYPES))
        self.assertEqual(
            schema["$defs"]["relationship"]["properties"]["type"]["enum"],
            list(RELATIONSHIP_TYPES),
        )
        self.assertEqual(
            schema["$defs"]["data_contract"]["properties"]["entity_required_fields"]["const"],
            data_contract()["entity_required_fields"],
        )
        self.assertEqual(
            schema["$defs"]["data_contract"]["properties"]["relationship_required_fields"]["const"],
            data_contract()["relationship_required_fields"],
        )

    def test_overview_exposes_contract_metadata_for_every_connector(self) -> None:
        config = load_config(ROOT / "config/cerebro.example.json")
        payload = build_payload(config, now=NOW)

        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
        self.assertEqual(payload["data_contract"], data_contract())
        self.assertEqual(len(payload["integrations"]), len(config["integrations"]))
        for integration in payload["integrations"]:
            self.assertEqual(
                set(integration["provenance"]),
                {"source_system", "source_kind", "source_owner", "collection_cadence_seconds"},
            )
            self.assertEqual(
                set(integration["connector_health"]),
                {
                    "state", "freshness", "last_success_at", "collection_duration_ms",
                    "record_count", "reason_code",
                },
            )
            self.assertEqual(integration["entities"], [])
            self.assertEqual(integration["relationships"], [])

    def test_config_rejects_invalid_provider_metadata(self) -> None:
        base = {
            "portal": {"title": "Cerebro"},
            "integrations": [{
                "id": "provider", "name": "Provider", "category": "SOC",
                "connector": "static", "state": "planned", "max_age_seconds": 60,
                "source_owner": "Security Operations", "collection_cadence_seconds": True,
            }],
        }
        path = ROOT / "tests/.invalid-cerebro-provider.json"
        try:
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
