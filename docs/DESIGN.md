# SOC Pipeline — End to End

> Implementation note, 2026-09-04: this document describes the target architecture. The published reference now includes a sanitized Terraform scaffold and eleven non-mutating Ansible role skeletons. Complete idempotent deployment roles, live Terraform adoption, endpoint and identity expansion, DFIR automation, the final firewall/IDS sensor design, and default-deny egress remain controlled follow-on work. See the status table in the repository README and public Project #3.

A KISS, pipeline-based Security Operations design for network, DNS, endpoint, identity, vulnerability, and audit feeds. It normalizes and correlates them in one central pane (**Wazuh**), retains and transports through **Graylog**, enriches local observations, and drives **decision and response** through **Shuffle (SOAR)** and **Velociraptor (DFIR)**. The published implementation includes portable collectors, generators, tests, safety controls, and adaptable Terraform and Ansible scaffolds. Live adoption and a turnkey installer remain separate controlled work.

This is the practical, buildable form of the "log → event → alert → incident" pipeline: every stage discards volume to add meaning, and every narrowing is a filter someone designed.

## Architecture

![SOC pipeline architecture](architecture.svg)

*Rendered diagram: [`architecture.svg`](architecture.svg). One correlated pipeline; the central pane stays the SIEM you already run.*

## Sources (all feeds)

| Domain | Source | Ingest | Scope note |
|--------|--------|--------|-----------|
| Network | UniFi EFG firewall (ZBF) | syslog → Graylog/Wazuh | denies alert; bulk allows → archive tier |
| Network | OPNsense + Suricata IDS | syslog | lab/segment isolation; signature detection |
| DNS | Technitium ×4 | API / query logs | C2 domains, tunneling, NRD contact (high value) |
| Endpoint | Wazuh agents (Linux/macOS/Windows) | agent channel | execution, persistence, FIM, SCA |
| Endpoint | Velociraptor client | DFIR (on-demand) | hunt, collect, isolate |
| Identity | Zentyal AD + 802.1X/RADIUS **(planned)** | AD security log + RADIUS | rank-1 source; RADIUS = universal, incl. iOS/Android |
| Vulnerability | Greenbone/OpenVAS | read-only GMP pull | un-agentable assets (firewalls, appliances, IoT) |
| Vulnerability | Wazuh native VD | built-in | agent'd hosts |

## Pipeline stages

| Stage | Component |
|-------|-----------|
| Collect / transport | Graylog (inputs, pipelines, streams, retention tiers; fan-out point) |
| Parse / normalize | Wazuh decoders + Graylog pipelines |
| Correlate / detect | Wazuh (central pane; dedicated rule-ID ranges per source; MITRE tagging) |
| Enrich / triage | AI agents (rank + explain, remediation briefs); cross-correlation of alert × vuln × identity on the same host |
| Orchestrate / respond | Shuffle SOAR (enrich → notify → contain with approval) + Velociraptor (DFIR, host isolation) |
| Incident | contain / escalate / close — the decision layer |

## Infrastructure as Code (cross-cutting)

- **Terraform — provision:** VMs, containers, Proxmox guests, network/firewall objects.
- **Ansible — configure/deploy:** collectors, Wazuh rules/decoders, Graylog pipelines, agent rollout, Shuffle workflows.

IaC is built alongside each phase so the whole pipeline is reproducible (`terraform apply` + `ansible-playbook`), version-controlled, and adoptable by anyone — not a pile of manual steps.

## Design principles (the transferable part)

- **One detection plane plus one operational overview.** Wazuh remains the authoritative detection and correlation pane. Cerebro adds read-only cross-tool posture, freshness, health, and navigation without duplicating SIEM data or replacing native consoles.
- **Read-only, human-in-the-loop.** Collectors and AI agents only read. Response actions (Shuffle/Velociraptor) are staged by risk-if-wrong, with human approval on containment.
- **Offline-validate before any live change.** `wazuh-logtest`, config backup, read-back verification. No production surprise.
- **Dedicated rule-ID ranges per source.** No collisions between feeds (e.g. vuln rules never touch the UniFi 110xxx range).
- **Alert discipline.** Only Critical/High/KEV and high-signal detections page; everything else is retained, queryable enrichment.
- **Scope split for vulnerability + identity.** Wazuh native VD for agent'd hosts, Greenbone for the un-agentable; identity via host logs (domain-join) plus RADIUS (universal, the only auth signal from mobile).

## Component reachability (2026-08-16)

Set your own component hosts (UniFi, OPNsense, Technitium, Wazuh, Graylog, Greenbone, Shuffle, Velociraptor). Identity/AD: build to close the rank-1 gap.
