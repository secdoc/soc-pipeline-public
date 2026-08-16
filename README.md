# vuln-siem-pipeline (public)

Feed **vulnerability scan findings into your SIEM's central pane** using a simple, pipeline-based integration, so vulnerabilities become a first-class source alongside your logs and alerts, not a siloed scanner dashboard nobody checks.

**Stack:** Greenbone / OpenVAS (Community Edition, Docker) → Graylog → Wazuh, with an optional AI enrichment path (LLM-generated remediation briefs). All read-only, human-in-the-loop.

> This is the **sanitized, adaptable** reference build. It uses placeholders (`<SCANNER_HOST>`, `<GMP_USER>`, RFC5737 example networks) so you can drop in your own environment. It carries no real environment data.

## Why

Bolting a vulnerability scanner on as its own silo means another console, another login, and vuln context that never reaches the analyst triaging an alert. This build treats the scanner as **one more source in one pipeline**: the same source → collect → normalize → correlate → alert → incident path every other log source follows. The central pane stays the SIEM you already run. No new orchestration UI, no new failure domain.

Read the reasoning in [`docs/DESIGN.md`](docs/DESIGN.md).

## What you get

- Vulnerability findings flowing into Wazuh (your central pane) through Graylog.
- **Alert discipline built in:** only Critical / High / KEV findings page you; everything else is retained and queryable as triage enrichment.
- **Cross-correlation:** a SIEM alert on a host that also has a known critical vuln is a higher-priority incident than the same alert on a hardened host.
- An optional **AI enrichment** agent that turns a dense scan report into a ranked, plain-language remediation plan per host.

## Architecture (short)

```
Greenbone gvmd (GMP socket, in Docker)
   │ one read-only pull (gvm-tools container)
   ▼
Collector → GELF → Graylog `vuln` stream → forward → Wazuh
                        │                              rules: Crit/High/KEV = alert,
                        └─ (optional) AI agent          rest = event-only
                           → remediation brief
   ▼
Central pane: Wazuh
```

## Quick start

1. Read [`docs/DESIGN.md`](docs/DESIGN.md) and [`lab/`](lab/) (the step-by-step build).
2. Copy `.env.example` to `.env`, fill in your hosts/creds.
3. Deploy the collector (`collector/`), Graylog config (`graylog/`), and Wazuh decoder+rules (`wazuh/`).
4. Validate end-to-end with a real scan.

Full walkthrough in [`lab/README.md`](lab/README.md).

## Safety model

- **Read-only.** The collector and AI agent only read from the scanner. They never re-run scans or touch hosts.
- **Secrets never leave.** Credentials are stripped before data enters the pipeline, and before anything reaches an LLM.
- **Scan output is treated as hostile.** Service banners are attacker-influenceable; they are sanitized before ingest and before any model call (prompt-injection aware).

## Adapting to a different stack

The pipeline is the transferable part. Swap tools per stage: any scanner with an API at the source, any log platform for transport/retention, any SIEM for correlation. The stage roles stay the same. See `docs/DESIGN.md` → "pipeline-stage mapping."

## License

MIT. Contributions welcome.
