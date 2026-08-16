# Design: Vulnerability findings into the SIEM central pane

A KISS, pipeline-based integration that feeds vulnerability scan findings from **Greenbone / OpenVAS (Community Edition, Docker)** into a **Graylog → Wazuh** SIEM pipeline, with an optional **AI enrichment** path. The goal: make vulnerability data a first-class source in the same central pane analysts already use, without adding another console.

## Why this design

Most guides bolt a vulnerability scanner on as its own silo with its own dashboard. That violates two principles:

1. **The pipeline is what transfers, not the tool.** Every source should flow through the same stages: source → collect → parse/normalize → correlate/detect → alert/triage → incident. Vulnerability data is just another source.
2. **A single pane is only a virtue if it doesn't add a failure domain.** So the central pane stays the SIEM you already run (Wazuh here). We do not introduce a new orchestration UI.

## Architecture

![Vulnerability pipeline architecture](architecture.svg)

*One read-only GMP pull feeds two consumers: the forwarding path (into the SIEM central pane) and the optional enrichment path (AI remediation brief). Rendered diagram: [`architecture.svg`](architecture.svg).*

## Design principles (the transferable part)

- **One pull, two consumers.** A single GMP pull feeds both the forwarding path (into the pane) and the enrichment path (the AI brief). No duplicate scanner access.
- **Read-only, human-in-the-loop.** The collector and the AI agent only read. They never re-run scans, never touch a host, never write to the scanner. A human reads the output and decides.
- **Alert discipline.** Only Critical/High/KEV findings become alerts. A raw scan returns thousands of results; if each were an alert you would recreate the noise problem the SIEM exists to solve. Everything else is retained and queryable as enrichment.
- **Treat scan output as hostile.** A scan banner or service description is attacker-influenceable text. Sanitize before it enters the pipeline, and (for the AI path) before it reaches a model — prompt injection is a real risk when the input is telemetry.
- **Divide vuln scope to avoid double-counting.** Agent-based vulnerability detection (e.g. Wazuh's native VD) covers hosts that run an agent. The scanner covers the **un-agentable**: network gear, appliances, IoT, printers, firewalls. Keep them in separate rule-ID ranges and tag the source.

## GMP access (Greenbone Community Docker build)

In the official Greenbone Community Docker Compose stack, `gvmd` exposes GMP on a **local unix socket inside the container**, not on a network port. The clean, no-exposure access method is the `gvm-tools` container, which already has the socket mounted:

```bash
docker compose exec -T gvm-tools \
  gvm-cli --gmp-username <GMP_USER> --gmp-password "$GMP_PASS" \
  socket --xml "<get_version/>"
```

This keeps GMP off the network entirely (no 9390 exposure). The collector runs the same exec to pull reports.

## Components

| Component | Role | Path |
|-----------|------|------|
| Collector | pull GMP report, normalize, emit GELF + JSON | `collector/` |
| Graylog config | `vuln` stream, index set, pipeline, Wazuh forward output | `graylog/` |
| Wazuh decoder | parse the normalized vuln event | `wazuh/decoders/` |
| Wazuh rules | alert on Critical/High/KEV; suppress the rest | `wazuh/rules/` |
| AI enrichment (optional) | LLM remediation plan per host | `collector/` (agent) |
| Lab | step-by-step build guide | `lab/` |

## Pipeline-stage mapping (for the article)

| Stage | This build |
|-------|-----------|
| Source | Greenbone gvmd (GMP) |
| Collect/transport | collector → GELF → Graylog |
| Parse/normalize | collector normalizes; Graylog pipeline tags `event_type=vulnerability` |
| Correlate/detect | Wazuh rules (severity-gated) |
| Alert/triage | Wazuh central pane; AI agent ranks + explains |
| Incident | cross-correlation of SIEM alert × vuln on same host |
