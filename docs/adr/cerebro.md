# ADR: Cerebro as the Read-Only Security Visibility Layer

Status: Accepted  
Date: 2026-09-04

## Decision

Provide centralized security visibility through Cerebro, a stateless read-only portal. Keep every native tool and console authoritative. Normalize only allowlisted summaries, explicit data freshness, failure reason codes, and native-console links.

The first implementation is a standard-library Python modular monolith. It binds to loopback and requires an authenticated TLS reverse proxy before network exposure. Source connectors are JSON snapshots, exact-origin HTTPS GET requests, or explicit static catalog entries. The portal has no mutating endpoint.

## Why

A new SIEM or database would duplicate security data and create retention, recovery, and authority conflicts. Embedded native consoles would mix authentication boundaries and weaken clickjacking controls. Mutating actions would turn a visibility layer into a privileged response plane. Microservices would add operational cost without a measured scaling need.

## Tradeoffs

The portal depends on correct source timestamps and field ownership. Native authorization is still required. A standard-library threaded server is intentionally limited to low internal concurrency and must sit behind a trusted proxy. Source-specific connectors and metric definitions remain adopter work.

## Revisit

Revisit when measured latency blocks page refreshes, several teams need independent connector releases, or one connector requires independent scaling. Prefer scheduled snapshot producers before splitting the portal into services.
