# Public Ansible SOC scaffold

This sanitized reference publishes gated, adopter-configurable roles for Graylog, Wazuh, HA edge candidates, collectors, endpoint agents, storage, and explicitly approved SOAR workflows. The example inventory uses RFC 5737 addresses and contains no credentials.

Mutation is disabled by default. Every role requires `soc_iac_apply_confirmed=true`; service restart, edge activation, collector activation, and Shuffle activation have additional gates. Package installation assumes the adopter has already configured the applicable signed vendor repository.

The edge role validates HAProxy and Keepalived candidates before installation. It does not activate routing, VIPs, or listeners unless `siem_edge_activation_confirmed=true` and restart approval are both present.

Issue 18 remains open while clean-environment product convergence is completed for every role. The current implementation provides package, configuration, identity, candidate, validation, rollback, and restart gates where documented. See `DEPLOYMENT.md` for exact prerequisites, variables, verification, rollback, and known gaps.

```text
ansible-lint .
ansible-playbook -i inventories/example/hosts.yml playbooks/site.yml --syntax-check
ansible-playbook -i inventories/example/hosts.yml playbooks/validate.yml --syntax-check
ansible-playbook -i inventories/example/hosts.yml playbooks/wazuh_agents.yml --syntax-check
ansible-inventory -i inventories/example/hosts.yml --graph
```

Before adapting a role, replace generic package, path, TLS, peer, and API values with reviewed environment-specific values. Validate product configuration before any restart. Automatic containment is outside this scaffold.
