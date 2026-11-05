# Adapt the SOC pipeline: three source lanes

This is an adopter-facing **guide**, not a turnkey installer or a claim that every published collector is safe to run unchanged. It explains how to build a small, isolated SOC lab using the public Greenbone/OpenVAS, Technitium DNS, and SOCFortress WAF examples, then how to substitute tools without losing the security and evidence contracts. Optional commands illustrate the published stack. Use your own approved packages, inventory, PKI, credentials, addresses, storage, and change process.[2][3]

**Evidence boundary:** This guide was reconciled against the public repository commits in the [Sources](#sources) section. Public Python unit tests and synthetic generators were run offline; no clean-environment product installation, credentialed source collection, Wazuh logtest, Graylog search, index receipt, or disaster restore was executed for this guide. The umbrella README's implementation checkpoints are dated through September 17, 2026, not a current private GitLab acceptance readback. Greenbone is the strongest published runnable example. DNS and WAF have source-level safety gaps described below. Do not confuse a source example, a mocked test, an adopter's later acceptance, and a planned integration.[1][2][3]

## 1. Choose roles and trust boundaries before products

| Role | Public example | Required contract when substituting |
|---|---|---|
| Vulnerability source | Greenbone GMP | Read-only access to authorized reports, known task/asset ownership, stable finding identity, scan time distinct from collection time. |
| DNS source | Technitium Query Logs | Per-resolver client/query/answer/response/block metadata, bounded complete source windows or an explicit best-effort gap policy, protected API credentials. |
| WAF source | SOCFortress management logs | Read-only request/action/rule data, stable transaction ID, management identity distinct from site traffic key, verified proxy-header provenance. |
| Retention | Graylog | Searchable full-volume structured data, dedicated routing and retention policy, queue/journal bounds, snapshots and isolated restore. |
| Detection | Wazuh | Independently delivered normalized events, schema-safe field names, low-noise rule tiers and a verified indexed alert for rule-eligible events. |
| Response | Out of this three-lane exercise | No containment based only on a log; separately authorize and verify any effect-bearing action. |

The source collector normalizes once and delivers **independently** to retention and detection. These three public lanes do not send normalized data serially through Graylog into Wazuh. A GELF/TCP send or SSH append is not an indexed receipt; a Wazuh level-zero rule is not a searchable alert in `wazuh-alerts-*`. A replacement product should preserve those semantics even if its API and dashboard look different.[5][25][26]

Use an isolated collector/management zone, an owned scanner target, an owned DNS test client/resolver, and an isolated WAF test site. Restrict source management APIs and SIEM inputs to named peers. Bind TLS/SSH identities before credentials, separate per-source read-only identities from Wazuh write/append identities, prohibit the collector from scanning or containing targets, and keep real secrets and logs out of public repositories. For Cloudflare-fronted WAF traffic, distinguish trusted `cf-connecting-ip` from the CDN edge and reject spoofed headers from direct clients before treating `waf_true_ip` as attribution.[8][14]

**Capacity and recovery:** measure per-source daily volume, index growth and replica cost, queue peak, and acceptable loss window before setting rotation and retention. Graylog's journal maximum age/size is not its searchable index-retention policy; configure both explicitly and test snapshot restoration in isolation. Set Wazuh alert-index retention separately. Keep the source cursor, collector config, rule files, Graylog index snapshots, Wazuh index snapshots, and dashboard objects in the recovery inventory. An index, VM snapshot, or healthy UI alone is not a complete restore.[3]

The umbrella OpenTofu example has synthetic Proxmox guests, empty managed inventory and `prevent_destroy`. Its Ansible roles are gated, but only the common baseline has published clean-container two-run convergence evidence. Treat these as examples for teams already operating those platforms, **not** as required or proven clean-environment product installers. Alternative hypervisors, containers, cloud VMs, or manual test systems are valid when the same isolation and recovery contracts hold.[3][15][19]

## 2. Start with a vulnerability finding

**Published path:** Greenbone read-only GMP pull over an SSH-forwarded UNIX socket, normalized findings, Graylog GELF retention and Wazuh JSON rules in the 115xxx range. Choose the umbrella repository's newer `collector/run_pipeline.py` with its matching collector, rules and stable SHA-256 event identity. Do not substitute the older standalone runner: it uses a different SHA-1 dedupe key and can advance its state after a failed Wazuh append. The standalone documentation and samples remain useful for orientation.[4][8][22]

For an **offline, synthetic example**, from the respective cloned repositories:

```bash
cd soc-pipeline-public
python3 -m unittest discover -s tests -v
python3 scripts/scrub_check.py .
python3 scripts/wazuh_dashboard_gen.py --index-pattern-id 'wazuh-alerts-*' --out /path/to/private-preview/greenbone.ndjson
cd ../greenbone-wazuh-graylog
python3 collector/gelf_emitter.py --in samples/greenbone-findings-sample.jsonl --graylog-host example.invalid --dry-run
```

The old standalone fixture has a scalar `port` field. The current umbrella collector emits `vuln_port` because `data.port` can be an object in the Wazuh index template. Do not ingest that fixture unchanged. Its free-text `summary` can contain credential-shaped synthetic material; omit it from shared transcripts and screenshots.[16][23]

**Adopter acceptance:** before a live run, confirm the GMP account sees only the intended task/reports, the forwarded socket has the expected peer, Graylog's owned GELF input is running, and Wazuh has exactly one JSON localfile plus collision-free 115xxx rules. Back up manager config, run `wazuh-analysisd -t` and `wazuh-logtest` with High, Critical and wrong-source lines, then obtain a separately approved activation. Expect 115030/level 10 for High and 115040/level 12 for Critical, subject to actual installed rule readback. The standalone rule how-to also documents the native JSON decoder and severity ladder.[9] Find the same stable event hash in a Graylog indexed document and a Wazuh indexed alert. A second unchanged pull should report no new findings. An intentionally failed second consumer must leave delivered state unchanged; reconcile possible first-consumer duplicates by hash, not by resetting state.[4][20][24]

**Rollback:** stop only the owned collector schedule and socket forward, restore the saved manager config/rules after validation and approval, remove an input only after confirming no other producer uses it, and retain source state and indexed evidence for reconciliation. Remove dashboard saved objects only by inspected type/ID. Never delete alert indices or replay findings just to make a panel nonempty.[27]

## 3. Add DNS query telemetry

**Published components:** Technitium query-log normalizer, per-server timestamp state, synthetic blocked/NXDOMAIN/upstream-blocked JSONL, Graylog GELF and Wazuh 116xxx rules. Use the fixtures to learn schema and rule behavior, not as proof of a live feed. An ordinary query belongs in full-volume retention; single blocked or anomalous queries remain low-level while justified same-client frequency rules escalate.[6][17][25]

```bash
cd technitium-wazuh-graylog
python3 -c 'import json; [json.loads(s) for s in open("samples/dns-events-sample.jsonl") if s.strip()]; print("DNS JSONL valid")'
python3 scripts/scrub_check.py .
```

**Do not use the published DNS runner for a credentialed or recurring adopter exercise without a reviewed replacement.** Its collector builds a plaintext HTTP URL carrying the token, can stop after a page failure and still write state, and its runner advances state before independent delivery and reports downstream errors as warnings. A token-bearing `--dry-run` still makes a network request. An unpublished local safety candidate requires verified HTTPS and rejects incomplete pages, but deliberately disables non-dry-run delivery. It is not part of this published example or an accepted production fix. The pinned DNS repository's scrub check fails on an internal registry reference in its tracked CI file; do not copy that reference or claim the standalone repository passes public sanitation.[10][11][21]

**Adopter substitution/acceptance:** select a CA-verified, no-redirect API route and source enumeration that either proves complete windows or explicitly labels possible source loss. Persist a bounded batch before moving a source checkpoint, track Graylog and Wazuh receipts separately, and reconcile ambiguous sends rather than assuming exactly-once. Offline `wazuh-logtest` should show 116013/level 3 for the blocked synthetic event, a high-entropy child for the NXDOMAIN example, and no 116xxx rule for a wrong source. Same-session repeated events test rate rules. On an owned lab, query full-volume DNS in retention and a rule-eligible indexed Wazuh event with matching server, client and event identity. Negative checks: partial page, equal timestamps, one consumer unavailable, and successful low-level retention with no page. **These live checks are adopter-specific and were not run here.**[10][11][25]

**Rollback:** stop the owned schedule, preserve checkpoint/outbox and failure evidence, restore only owned rule/localfile changes after validation and approved restart, and remove only the dedicated retention input/stream when unused. Never silently reset a cursor to a recent lookback, because doing so can hide a historical gap.

## 4. Add WAF request and block telemetry

**Published components:** SOCFortress management API collection, normalized `waf_*` fields, independent Graylog/Wazuh delivery, Wazuh 117xxx rules, synthetic blocked-event JSONL and dashboard generator. The fixture provides example blocked requests and distinct true-client and edge fields.[18] The management login/JWT is not a WAF site access key. `waf_true_ip` is meaningful only behind a trusted CDN/proxy boundary; `waf_edge_ip` is the edge, not the attacker. Single blocked requests are low-level; same-client bursts are candidate pages.[7][14][26]

```bash
cd socfortress-waf-siem
python3 -m unittest discover -s tests -v
python3 scripts/wazuh_waf_dashboard_gen.py --index-pattern-id 'wazuh-alerts-*' --out /path/to/private-preview/waf.ndjson
python3 scripts/scrub_check.py .
```

**Do not transmit a management password using the pinned public collector unchanged.** It disables certificate and hostname verification. An unpublished local candidate adds verified HTTPS, cross-origin redirect refusal and fail-closed state/pagination tests, but its offset pagination still cannot prove a snapshot while logs change. The public runner's zero first-run seed also needs an explicit positive seed decision. No live management TLS or indexed receipt was verified for this guide.[12][13]

**Adopter substitution/acceptance:** require a dedicated least-privilege management identity, trusted peer certificate, no credential-forwarding redirect, explicit bounded historical seed, and a documented completeness limit. Offline logtest a CRITICAL block (117010/level 5), other block, detected-only and wrong-source negative; exercise 117100/117101 with same-client events in one session. In an isolated lab, check `waf_event_id` in independently indexed Graylog and Wazuh records and inspect dashboard panels by true-client and matched CRS rules. Reject spoofed forwarded IPs and test failed consumer/cursor non-advancement. These are **expected checks**, not observed results here.[12][13][26]

**Rollback:** stop the owned schedule, retain source cursor and duplicate evidence, restore only owned Wazuh rules/localfile changes after validation and approval, and remove owned input/dashboard objects only after confirming their IDs and consumers. Do not change WAF blocking policy as an ingest rollback.

## 5. Decide what is complete

For each lane, the adopter records: source-native ID and event time; collector/batch identity; Graylog stream/index/receipt time; Wazuh decoded rule and indexed alert time for eligible events; expected non-alert for an ordinary event; one unavailable-consumer result; credential/peer boundary; retention/snapshot evidence; duplicate/gap decision; and rollback owner. A successful command, UI health response, synthetic preview, scheduler `ok`, or TCP write alone is not end-to-end evidence.

This **guide** is complete when its portable roles, example implementation, substitution criteria, positive/negative acceptance, failure interpretation, and rollback can be understood without internal lab facts. It does **not** require every adopter to install this exact stack or require production acceptance of 802.1X/RADIUS, final IDS placement, DFIR automation, or autonomous containment. Those remain separate planned capabilities. The public guide does not repair any current private production feed.[1][2][3]

Documentation and diagrams are CC BY 4.0. Credit: Lester E. Nichols III, secdoc.tech. The linked repositories' code/configuration use their respective license and attribution files.[2]

## Sources

[1] https://github.com/secdoc/soc-pipeline-public/issues/8
[2] https://github.com/secdoc/soc-pipeline-public/blob/069d1b1854cbfc4cdfc1273c18b302778f0b7759/README.md
[3] https://github.com/secdoc/soc-pipeline-public/blob/069d1b1854cbfc4cdfc1273c18b302778f0b7759/ansible/DEPLOYMENT.md
[4] https://github.com/secdoc/soc-pipeline-public/blob/069d1b1854cbfc4cdfc1273c18b302778f0b7759/collector/run_pipeline.py
[5] https://github.com/secdoc/greenbone-wazuh-graylog/blob/a565a1ee2a6e25830f9b02ffd2a91dc2466af2f2/README.md
[6] https://github.com/secdoc/technitium-wazuh-graylog/blob/c04387bbfdd5621b136133f27a613c261fb5915c/README.md
[7] https://github.com/secdoc/socfortress-waf-siem/blob/4db0ef19e4df7fb746e8eeb1034a11b95fca9e25/README.md
[8] https://github.com/secdoc/greenbone-wazuh-graylog/blob/a565a1ee2a6e25830f9b02ffd2a91dc2466af2f2/docs/how-to-greenbone-access.md
[9] https://github.com/secdoc/greenbone-wazuh-graylog/blob/a565a1ee2a6e25830f9b02ffd2a91dc2466af2f2/docs/how-to-wazuh-vuln-rules.md
[10] https://github.com/secdoc/technitium-wazuh-graylog/blob/c04387bbfdd5621b136133f27a613c261fb5915/collector/dns_pipeline.py
[11] https://github.com/secdoc/technitium-wazuh-graylog/blob/c04387bbfdd5621b136133f27a613c261fb5915/collector/dns_collector.py
[12] https://github.com/secdoc/socfortress-waf-siem/blob/4db0ef19e4df7fb746e8eeb1034a11b95fca9e25/collector/waf_pipeline.py
[13] https://github.com/secdoc/socfortress-waf-siem/blob/4db0ef19e4df7fb746e8eeb1034a11b95fca9e25/collector/waf_collector.py
[14] https://github.com/secdoc/socfortress-waf-siem/blob/4db0ef19e4df7fb746e8eeb1034a11b95fca9e25/docs/how-to-waf-feed.md
[15] https://github.com/secdoc/soc-pipeline-public/blob/069d1b1854cbfc4cdfc1273c18b302778f0b7759/terraform/README.md
[16] https://github.com/secdoc/greenbone-wazuh-graylog/blob/a565a1ee2a6e25830f9b02ffd2a91dc2466af2f2/samples/greenbone-findings-sample.jsonl
[17] https://github.com/secdoc/technitium-wazuh-graylog/blob/c04387bbfdd5621b136133f27a613c261fb5915/samples/dns-events-sample.jsonl
[18] https://github.com/secdoc/socfortress-waf-siem/blob/4db0ef19e4df7fb746e8eeb1034a11b95fca9e25/samples/waf-events-sample.jsonl
[19] https://github.com/secdoc/soc-pipeline-public/blob/069d1b1854cbfc4cdfc1273c18b302778f0b7759/ansible/README.md
[20] https://github.com/secdoc/soc-pipeline-public/blob/069d1b1854cbfc4cdfc1273c18b302778f0b7759/tests/test_greenbone_pipeline.py
[21] https://github.com/secdoc/technitium-wazuh-graylog/blob/c04387bbfdd5621b136133f27a613c261fb5915/.gitlab-ci.yml
[22] https://github.com/secdoc/greenbone-wazuh-graylog/blob/a565a1ee2a6e25830f9b02ffd2a91dc2466af2f2/collector/run_pipeline.py
[23] https://github.com/secdoc/greenbone-wazuh-graylog/blob/a565a1ee2a6e25830f9b02ffd2a91dc2466af2f2/collector/gelf_emitter.py
[24] https://github.com/secdoc/greenbone-wazuh-graylog/blob/a565a1ee2a6e25830f9b02ffd2a91dc2466af2f2/wazuh/rules/greenbone_rules.xml
[25] https://github.com/secdoc/technitium-wazuh-graylog/blob/c04387bbfdd5621b136133f27a613c261fb5915/wazuh/rules/dns_rules.xml
[26] https://github.com/secdoc/socfortress-waf-siem/blob/4db0ef19e4df7fb746e8eeb1034a11b95fca9e25/wazuh/rules/waf_rules.xml
[27] https://github.com/secdoc/greenbone-wazuh-graylog/blob/a565a1ee2a6e25830f9b02ffd2a91dc2466af2f2/docs/how-to-wazuh-dashboard.md
