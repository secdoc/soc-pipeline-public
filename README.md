# soc-pipeline (public)

Build an **end-to-end Security Operations pipeline** that correlates **every security feed** — network, DNS, endpoint, identity, and vulnerability — into one central pane, enriches with AI, and drives decision and response through SOAR and DFIR. A simple, pipeline-based approach so each feed is a first-class source in one correlated flow, not a scattered set of consoles nobody watches.

**Stack:** UniFi / OPNsense+Suricata / DNS / endpoints / vuln scanner → **Graylog** (transport & retention) → **Wazuh** (central pane: correlate & detect) → **AI enrichment** → **Shuffle** (SOAR) + **Velociraptor** (DFIR) → incident. Provisioned and configured with **Terraform + Ansible**. All read-only and human-in-the-loop through triage; response actions are staged by risk with human approval on containment.

> This is the **sanitized, adaptable** reference build. It uses placeholders (`<SCANNER_HOST>`, `<WAZUH_HOST>`, `<GMP_USER>`, RFC5737 example networks) so you can drop in your own environment. It carries no real environment data.

## Why

Standing each security tool up as its own silo means another console, another login, and context that never reaches the analyst making the decision. This build treats every tool as **one source in one pipeline**: the same `log → event → alert → incident` path for all of them. The central pane stays the SIEM you already run. No new orchestration UI you have to babysit, no new failure domain.

Read the reasoning in [`docs/DESIGN.md`](docs/DESIGN.md).

## Feeds in scope

| Domain | Source | Scope note |
|--------|--------|-----------|
| Network | firewall (ZBF) + IDS (Suricata) | denies alert; bulk allows → archive tier |
| DNS | resolver query logs | C2 domains, tunneling, NRD contact |
| Endpoint | SIEM agents + DFIR client | execution, persistence, FIM, SCA |
| Identity | directory auth + 802.1X/RADIUS | rank-1 source; RADIUS = universal, incl. mobile |
| Vulnerability | network scanner + agent-native VD | scanner for un-agentable; native VD for agent'd hosts |

## What you get

- Every feed correlated in one central pane (Wazuh), transported and retained by Graylog.
- **Alert discipline built in:** only Critical / High / KEV and high-signal detections page you; everything else is retained, queryable enrichment.
- **Cross-correlation:** an alert on a host that also has a known critical vuln (or a suspicious identity event) is a higher-priority incident than the same alert on a hardened host.
- **AI enrichment:** dense signal turned into ranked, plain-language triage and remediation.
- **Response:** SOAR workflows (enrich → notify → contain-with-approval) and DFIR (hunt, collect, isolate host).
- **Reproducible:** Terraform provisions, Ansible configures — `terraform apply` + `ansible-playbook`, not a pile of manual steps.

## Architecture

![SOC pipeline architecture](docs/architecture.svg)

Full reasoning and stage-by-stage mapping: [`docs/DESIGN.md`](docs/DESIGN.md).

### Vulnerability dashboard (sample)

Point-in-time vulnerability posture rendered from a Greenbone findings feed. This sample uses pseudonymized hosts (`host-NN`) and RFC5737 example addresses; it carries no real environment data. Regenerate from any collector output with `scripts/vuln_dashboard_gen.py`.

![Vulnerability dashboard](docs/vuln-dashboard.svg)

See [`docs/vuln-dashboard.md`](docs/vuln-dashboard.md) for the tabular breakdown.

## Build order (efficient + non-disruptive)

Build one feed end-to-end first (the **vulnerability slice**), proving the whole source → Graylog → Wazuh → enrich → respond pattern, then repeat the slice per feed. Every live change is preceded by offline validation (`wazuh-logtest`), a config backup, and read-back verification. IaC is built alongside each phase. Phases:

- **P0** Foundations & access · **P1** Vuln slice (offline build/validate) · **P2** First live change (verified) · **P3** Add source lanes (DNS, firewall/IDS, endpoints, identity) · **P4** Enrich, orchestrate, respond · **P5** Reproducibility & publish

Tracked on the project board and in `docs/` (design + lab as built).

## Safety model

- **Read-only through triage.** Collectors and AI agents only read. They never re-run scans or touch hosts.
- **Response is staged.** SOAR/DFIR actions are ordered by risk-if-wrong; enrichment (no downside) first, containment only with human approval.
- **Offline-validate before any live change.** Dedicated SIEM rule-ID ranges per source (no collisions); logtest both ways before load.
- **Secrets never leave; telemetry is treated as hostile.** Credentials stripped before ingest and before any LLM call; service banners are attacker-influenceable (prompt-injection aware).

## Reliability controls

The vulnerability collector advances delivered state only after every configured consumer succeeds. A Graylog or Wazuh failure leaves the batch retryable instead of silently losing it.

Supported delivery modes:

```text
Graylog GELF/TCP
Graylog GELF/TCP with TLS
Graylog GELF/HTTP over verified HTTPS
Wazuh localfile append over SSH
Wazuh newline-delimited JSON over TCP
```

Example target-only invocation:

```bash
python3 collector/run_pipeline.py \
  --socket /tmp/gvmd.sock \
  --graylog-endpoint retention=graylog.example.local:12213:https \
  --graylog-ca /path/to/ca-chain.pem \
  --no-default-graylog \
  --wazuh-endpoint detection=wazuh.example.local:5514:tcp \
  --no-default-wazuh
```

Each finding carries a stable SHA-256 event hash across Graylog, Wazuh, dedupe state, and dashboard cardinality.

## Operational tooling

- `scripts/wazuh_agent_migration.py`: generates activation and rollback scripts that stop the agent, require process exit, validate configuration, start, and verify the intended manager connection.
- `scripts/prepare_socfortress_rules.py`: builds a temporary collision-safe rules bundle from a pinned third-party source. It remaps conflicts, preserves parent references, validates dependencies, and emits a hash manifest.
- `scripts/wazuh_manager_vendor_config.py`: adds required CDB list declarations and supports exact-count hook replacement.
- `scripts/wazuh_dashboard_gen.py`: generates a full-width dashboard with total and distinct stable-finding KPIs.

The SOCFortress source repository did not contain a license file at the reviewed revision. Do not redistribute its rule content without a valid license. The builder itself is Apache-2.0 and does not embed vendor rules.

Validation gates:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/scrub_check.py .
```

## Adapting to a different stack

The pipeline is the transferable part. Swap tools per stage — any source with an API, any log platform for transport/retention, any SIEM for correlation, any SOAR/DFIR for response. The stage roles stay the same. See `docs/DESIGN.md`.

## Related projects

- **[socfortress-waf-siem](https://github.com/secdoc/socfortress-waf-siem)** — standalone sanitized build of the WAF lane: wire a SOCFortress WAF (Caddy+Coraza / OWASP CRS) into Wazuh+Graylog (collector, dual delivery, detection rules, dashboard).
- **[greenbone-wazuh-graylog](https://github.com/secdoc/greenbone-wazuh-graylog)** — standalone sanitized build of the vulnerability lane: wire a Greenbone/OpenVAS scanner into Wazuh+Graylog (GMP collector, dual delivery, rules, dashboard, how-tos).
- **[technitium-wazuh-graylog](https://github.com/secdoc/technitium-wazuh-graylog)** — standalone sanitized build of the DNS lane: wire a Technitium DNS server/cluster into Wazuh+Graylog (Query Logs collector, dual delivery, detection enrichments, rules for blocking/NXDOMAIN/DGA/tunneling).

## License

Dual-licensed, **attribution required** under both:

- **Code & configuration** (`collector/`, `wazuh/`, `graylog/`, `ansible/`, `terraform/`, `scripts/`): [Apache License 2.0](LICENSE)
- **Docs, labs & diagrams** (`docs/`, `lab/`, `README`): [CC BY 4.0](LICENSE-docs)

See [`LICENSING.md`](LICENSING.md) and [`NOTICE`](NOTICE). Credit: Lester E. Nichols III, secdoc.tech. Contributions welcome.
