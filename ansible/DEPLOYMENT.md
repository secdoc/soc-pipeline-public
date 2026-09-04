# Adopter deployment guide

Status: functional role implementation under convergence acceptance. The roles have approved mutation paths, but issue 18 remains open until every component passes clean-environment installation and two-run idempotence tests.

## Prerequisites

Use Debian-family targets with Python 3, systemd for service roles, and passwordless or interactive sudo. Configure each vendor's signed APT repository before enabling package installation. Supply DNS, addresses, storage, PKI, package versions, and service credentials for your environment. The example inventory is documentation data and must not be deployed unchanged.

Run with `soc_iac_apply_confirmed: false` first to prove refusal. Set it to `true` only for an adopter-owned target after reviewing the resolved inventory. Service roles also require `soc_iac_restart_confirmed: true`. Edge, collector, and Shuffle activation have additional role-local gates.

## Secrets

Keep Graylog password secrets, MongoDB credentials, Wazuh API passwords, Wazuh agent keys, and Shuffle API keys in Ansible Vault or an external secret manager. Do not commit rendered inventories, vault files, package signing keys, private keys, or Terraform state. Tasks handling secrets use `no_log`, but controller and target access still require normal least-privilege controls.

## `common_baseline`

Installs the configured baseline package list and creates protected backup and candidate directories. `common_baseline_update_cache` is off by default so repository changes remain a separate operation.

## `storage_mount`

Accepts only `/dev/disk/by-id/` sources, verifies the block device, filesystem, and required option tokens, rejects ambiguous state, and backs up `/etc/fstab`. If this run activates a mount and later verification fails, `fstab is restored only after the rollback unmount succeeds`. If unmount fails, the role stops with the active mount and matching `fstab` entry retained; resolve the consumer or busy mount, unmount it explicitly, then restore the recorded backup. It never creates or formats a filesystem.

## `graylog_core`

Installs an exact adopter-selected `graylog-server` package version from a preconfigured signed repository. Validates protected password and MongoDB inputs, renders a protected candidate, and requires an adopter-supplied `graylog_core_validation_command` before copying the candidate to the active path. Restarts require the separate restart gate. Domain, bind address, TLS paths, journal path, retention, and size are variables.

## `graylog_datanode`

Installs an exact adopter-selected `graylog-datanode` package version, validates its protected inputs, and requires an adopter-supplied `graylog_datanode_validation_command` for the protected candidate. Cluster name, heap, bind address, HTTP port, and snapshot repository path are variables.

## `wazuh_manager`

Installs the adopter-selected Wazuh manager package, accepts a complete adopter-supplied `ossec.conf`, optionally installs adopter-supplied rules and decoders, and runs `wazuh-analysisd -t` before restart. The prior manager configuration is restored when validation fails and a backup exists. Public defaults include no private rules or decoders.

## `wazuh_indexer`

Installs an exact adopter-selected indexer package and validates a protected candidate with `wazuh_indexer_validation_command` before activation. Cluster size, name, repository path, certificate, key, and CA paths are variables. The adopter must provision PKI material before activation.

## `wazuh_dashboard`

Installs an exact adopter-selected dashboard package and validates protected OpenSearch and Wazuh API candidates with `wazuh_dashboard_validation_command` before activation. The Wazuh API password is mandatory and protected by `no_log`. The adopter must provision dashboard and CA certificates first.

## `wazuh_agent`

Installs an exact agent version and requires an API-approved four-field client key whose name matches the inventory identity. It refuses to overwrite a different existing agent identity, updates exactly one manager address, validates with `wazuh-agentd -t`, and restores the pre-install identity and configuration state after failure. A package explicitly installed during the run may remain staged and stopped; package removal or downgrade is a separate operator-approved rollback.

## `siem_edge`

Installs exact adopter-selected HAProxy and Keepalived versions with maintainer service starts suppressed, renders both configurations into the protected candidate directory, and runs each product's native configuration check. Copying candidates into active paths requires `siem_edge_activation_confirmed: true` plus restart approval. VIPs, prefix, interface, peer, DNS suffix, certificate paths, and CA paths are variables.

## `soc_collector`

Validates collector names, executable paths, argument lists, users, write paths, schedules, and randomized delays before installing hardened systemd service and timer units. Each executable is canonicalized beneath `soc_collector_root`; the executable and every canonical parent must be root-owned and not group/world writable. Write paths are canonicalized under `soc_collector_allowed_write_roots`. Starting and enabling timers requires `soc_collector_activation_confirmed: true` plus restart approval.

## `shuffle_workflow`

Reconciles adopter-supplied workflow definitions through HTTPS. It requires global apply approval, `shuffle_workflow_activation_confirmed: true`, an API key, mandatory certificate validation, literal non-traversing `/api/` paths, and an explicit POST, PUT, or PATCH method. Automatic containment workflows are outside this role.

## Verification

Run:

```text
python3 -m unittest discover -s tests -v
python3 scripts/scrub_check.py .
ansible-lint ansible
ansible-playbook -i ansible/inventories/example/hosts.yml ansible/playbooks/site.yml --syntax-check
ansible-playbook -i ansible/inventories/example/hosts.yml ansible/playbooks/validate.yml --syntax-check
ansible-playbook -i ansible/inventories/example/hosts.yml ansible/playbooks/wazuh_agents.yml --syntax-check
bash ansible/tests/run_common_baseline_convergence.sh
```

The convergence harness first proves `soc_iac_apply_confirmed=false` is rejected, then applies twice inside one disposable Debian 13 container and requires the second run to report `changed=0`.

Before production use, run each selected role twice against a disposable environment containing the actual vendor packages and certificates. Validate product configuration, service health, cluster membership, API behavior, and isolation before introducing traffic.

## Rollback

Stop after the first failed target. Do not continue through the inventory. Restore module-created backup files, validate the restored product configuration, and restart only with explicit approval. `storage_mount`, `wazuh_manager`, and `wazuh_agent` contain automatic restoration paths for their bounded transactions. For other roles, restore the captured Ansible backup file or the pre-change system snapshot. Never remove data volumes as a configuration rollback.

## Known gaps

- Only `common_baseline` currently has clean-container two-run convergence evidence.
- Vendor package repositories are adopter prerequisites and are not configured by these roles yet.
- Product candidate validators are adopter-supplied because vendor packaging exposes different validation commands across supported versions.
- File rollback is implemented for the configuration transactions, but clean-environment service-failure recovery is not yet proven. Package installation rollback is intentionally separate because automatic package removal or downgrade can be more destructive than leaving a stopped staged package.
- Full product clusters have not been created in public CI.
- Storage tests do not create or format a loop device.
- Shuffle API convergence depends on the adopter's endpoint semantics.
- Issue 18 remains open until every role has clean-environment installation, validation, rollback, check-mode, and second-run `changed=0` evidence.
