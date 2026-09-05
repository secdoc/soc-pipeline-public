# 2026-09-05 Cerebro Provider Integration Contract

Status: Verified public reference implementation
Change type: Backward-compatible read-only API extension and documentation

## Purpose

Give adopters one repeatable, testable way to integrate additional security providers and tools with Cerebro without widening its read-only visibility boundary.

## Delivered contract

The API now declares `cerebro.integration.v1`, publishes its stable vocabulary in `data_contract`, and returns provenance, connector health, and fail-closed entity and relationship arrays for every integration. The repository includes:

* `contracts/cerebro-integration-v1.schema.json`, the normative Draft 2020-12 response schema.
* `docs/cerebro-provider-integration.md`, the provider patterns, field contracts, versioning rules, security requirements, acceptance checklist, and rollback process.
* Sanitized owner, cadence, and record-count mappings in `config/cerebro.example.json`.
* Contract synchronization, runtime payload, and invalid-configuration tests.

The supported provider patterns remain static catalog, sanitized JSON snapshot, and exact-origin GET-only JSON API. Custom adapters require bounded validators and negative security fixtures before they may publish entities or relationships.

## Compatibility and security

Existing routes and normalized fields remain available. POST, PUT, PATCH, and DELETE remain rejected. Redirect refusal, TLS verification, source-value allowlists, bounded analytics, server-side secret handling, native-console authorization, and no source mutation remain unchanged.

## Verification

The repository passed 85 unit and contract tests, full-history scrub checking, Python compilation, JavaScript syntax validation, configuration collection validation, JSON parsing, and Git whitespace validation. An isolated `jsonschema` Draft 2020-12 validator accepted the generated three-integration example payload.

## Deployment boundary

This public change does not deploy or reconfigure a Cerebro instance. Adopters must run their own authenticated proxy, source-access, schema-validation, negative-fixture, and rollback acceptance before activation.

## Rollback

Revert this commit. Existing providers and native consoles remain unchanged because the extension is read-only and backward compatible.
