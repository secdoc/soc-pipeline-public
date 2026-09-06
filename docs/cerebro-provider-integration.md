# Cerebro Provider Integration Guide

Status: normative for `cerebro.integration.v1`  
Audience: maintainers adding security products, data providers, and internal tools

## Integration boundary

Cerebro is a read-only visibility and navigation layer. A provider integration may publish bounded health, posture, aggregate analytics, entities, relationships, provenance, and a deep link to the authoritative product. It must not execute workflows, change source configuration, return raw telemetry, or expose credentials.

The normative response schema is [`contracts/cerebro-integration-v1.schema.json`](../contracts/cerebro-integration-v1.schema.json). Both `GET /api/v1/overview` and `GET /api/v1/integrations` return that payload. Consumers must check `schema_version` before processing it.

## Choose the integration pattern

Use the simplest safe pattern:

| Pattern | Use when | Trust boundary |
|---|---|---|
| `static` | The product is a navigation entry only | No source collection and no health claim |
| `json_file` | A scheduled producer can authenticate, aggregate, sanitize, and atomically publish a snapshot | Cerebro receives no source credential |
| `http_json` | The product offers a bounded GET endpoint with non-mutating authentication | Cerebro holds a read-only credential server-side |
| Custom adapter | Native response validation or protocol handling cannot be expressed by path mappings | New code, tests, and security review required |

Prefer `json_file` when authentication requires a POST, when source responses contain sensitive records, when collection is slow, or when the provider has tight quotas. Keep token acquisition and raw response handling outside the web request path.

## Minimum configuration

Every integration requires:

| Field | Requirement |
|---|---|
| `id` | Stable, unique, lower-case identifier. Do not rename it after clients depend on it. |
| `name` | Human-readable product or capability name. |
| `category` | Stable grouping such as `SOC`, `Identity`, or `Vulnerability`. |
| `connector` | `static`, `json_file`, or `http_json`. |
| `max_age_seconds` | Positive freshness threshold based on the real collection schedule and SLO. |
| `source_owner` | Team or role accountable for source-field meaning and availability. |
| `collection_cadence_seconds` | Expected successful collection interval for active connectors. |
| `deep_link` | Optional HTTP or HTTPS URL to the authoritative native console. |

Example snapshot connector:

```json
{
  "id": "example-edr",
  "name": "Example EDR",
  "category": "Endpoint",
  "connector": "json_file",
  "path": "/var/lib/cerebro/snapshots/example-edr.json",
  "collected_at_path": "collected_at",
  "healthy_path": "healthy",
  "summary_paths": {
    "active_agents": "agents.active",
    "high_alerts_24h": "alerts.high_24h"
  },
  "record_count_path": "agents.total",
  "collection_duration_ms_path": "collection.duration_ms",
  "source_owner": "Security Operations",
  "collection_cadence_seconds": 300,
  "max_age_seconds": 900,
  "deep_link": "https://edr.example.com/"
}
```

The producer should atomically replace the snapshot only after successful collection and validation. A failed collection should preserve the last-known-good snapshot so Cerebro reports stale data instead of false health.

Example GET connector:

```json
{
  "id": "example-api",
  "name": "Example Security API",
  "category": "Security",
  "connector": "http_json",
  "url": "https://api.example.com/v1/health",
  "allowed_origins": ["https://api.example.com"],
  "header_env": {"Authorization": "EXAMPLE_API_AUTHORIZATION"},
  "collected_at_path": "generated_at",
  "state_path": "status",
  "state_map": {"ok": "healthy", "warning": "degraded", "error": "degraded"},
  "summary_paths": {"open_findings": "counts.open_findings"},
  "source_owner": "Security Operations",
  "collection_cadence_seconds": 60,
  "max_age_seconds": 180,
  "deep_link": "https://console.example.com/"
}
```

The URL must match an allowlisted origin by exact scheme, host, and effective port. Redirects are refused. TLS verification is enabled. Put secret values in the process environment or an external secret-injection mechanism, never in the JSON configuration.

## Normalized integration object

Each integration returned by the API includes:

| Field | Contract |
|---|---|
| `state` | `healthy`, `degraded`, `stale`, `unavailable`, `unauthorized`, `unknown`, or `planned` |
| `freshness` | `fresh`, `stale`, or `unknown` |
| `collected_at` | UTC RFC 3339 timestamp or `null` |
| `age_seconds` | Nonnegative age or `null` |
| `summary` | Explicitly allowlisted values only |
| `analytics` | Optional bounded aggregate structures, limited to 256 KiB per configured field |
| `reason_code` | Stable machine-readable failure code when applicable |
| `detail` | Safe operator guidance without source bodies, paths, headers, or credentials |
| `provenance` | Source identity, kind, owner, and collection cadence |
| `connector_health` | State, freshness, last success, duration, record count, and reason code |
| `entities` | Validated correlation records. Empty until a reviewed adapter publishes them. |
| `relationships` | Validated links between entity IDs. Empty until a reviewed adapter publishes them. |

A successful request alone does not produce `healthy`. Healthy data requires an explicit healthy source signal and a valid fresh timestamp. Missing time becomes `unknown`. Old healthy data becomes `stale`. HTTP 401 and 403 become `unauthorized`. Redirects and other retrieval failures become `unavailable` with a bounded reason code.

## Entity and relationship contract

The v1 entity types are:

```text
ip_address, asset, alert, finding, cve, threat_model,
attack_technique, atlas_technique, source_system
```

Every entity requires `id`, `type`, `label`, and `provenance`. Optional `attributes` must contain only bounded, reviewed fields. IDs must be deterministic within the provider namespace. Do not use display labels as foreign keys.

The v1 relationship types are:

```text
affects, associated_with, detected_by, maps_to, observed_by, supports
```

Every relationship requires `id`, `type`, `source_ref`, `target_ref`, and `provenance`. Both references must identify entities present in the same payload or in a documented stable external namespace. Reject dangling references during adapter validation.

Adding configuration does not authorize entity publication. A custom adapter must validate record count, types, lengths, identifiers, references, timestamps, and allowed attributes before returning a non-empty array. Any invalid batch fails closed to empty entity and relationship arrays. Do not partially publish a malformed correlation graph.

## Versioning policy

`cerebro.integration.v1` permits backward-compatible additions only:

1. New optional fields may be added.
2. New enum values require a documented compatibility review because older clients may reject them.
3. Required-field removal, field renaming, type changes, or semantic changes require a new major schema identifier.
4. Clients must ignore unknown optional fields but reject an unsupported major schema.
5. The JSON Schema, `data_contract`, implementation constants, tests, examples, and release notes must change together.

## Provider acceptance checklist

A provider is not accepted until all applicable checks pass:

1. Identify the source owner, metric owner, authoritative source fields, cadence, freshness threshold, and data classification.
2. Create a least-privilege read-only identity. Record ownership, consumers, rotation interval, and revocation procedure outside the public repository.
3. Restrict egress to exact destinations. Verify TLS identity and private CA handling where applicable.
4. Prove that no POST, PUT, PATCH, DELETE, workflow execution, scan trigger, or response action is reachable through Cerebro.
5. Allowlist only required summaries and aggregates. Add negative fixtures for tokens, credentials, personal data, raw events, internal paths, and unbounded arrays.
6. Test healthy, degraded, stale, unavailable, unauthorized, malformed, oversized, redirect, timeout, and certificate-failure behavior.
7. For entities and relationships, test vocabulary, deterministic IDs, bounds, provenance, duplicate rejection, and dangling-reference rejection.
8. Validate the complete API response against the v1 JSON Schema.
9. Confirm the native deep link still enforces the provider's own authorization.
10. Document deployment, operations, monitoring, backup, rebuild, rollback, known gaps, and the native-console fallback.

## Required repository checks

Run from the repository root:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/cerebro_validate.py --config config/cerebro.example.json --collect
python3 -m json.tool contracts/cerebro-integration-v1.schema.json >/dev/null
git diff --check
```

For a custom adapter, add unit fixtures for every acceptance state and at least one HTTP-level test proving the response contract. Never use production samples in the public repository. Use RFC 5737 addresses, example domains, synthetic identifiers, and non-secret headers.

## Rollback

Remove the provider entry or restore the prior configuration and code release, restart only Cerebro, and verify that the native product remains unchanged and reachable. Revoke connector-only credentials and remove connector-only egress permits if they have no other consumer. A Cerebro rollback must never require changing or restarting the source product.
