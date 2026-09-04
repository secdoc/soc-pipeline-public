# Public Ansible SOC scaffold

This sanitized reference publishes non-mutating role skeletons for Graylog, Wazuh, HA edge candidates, collectors, endpoint agents, storage, and planning-only SOAR workflows. The example inventory uses RFC 5737 addresses and contains no credentials.

No live deployment is authorized by this reference. Every role refuses `soc_iac_apply_confirmed=true` and contains no package, file, mount, service, or restart mutation. Defaults and templates are published for adaptation and review only.

The edge templates illustrate candidate HAProxy and Keepalived configuration only. They do not activate live routing, VIP, rsyslog, queue, or listener configuration.

Issue 18 remains open. These skeletons do not claim to install complete products or pass clean-environment idempotence. Before enabling a role, add package and repository management, prerequisite users and directories, certificate provisioning, protected candidate rendering, product validation, rollback, independently gated handlers, and two-run integration tests.

```text
ansible-lint .
ansible-playbook -i inventories/example/hosts.yml playbooks/site.yml --syntax-check
ansible-playbook -i inventories/example/hosts.yml playbooks/validate.yml --syntax-check
ansible-playbook -i inventories/example/hosts.yml playbooks/wazuh_agents.yml --syntax-check
ansible-inventory -i inventories/example/hosts.yml --graph
```

Before adapting a role, replace generic package, path, TLS, peer, and API values with reviewed environment-specific values. Validate product configuration before any restart. Automatic containment is outside this scaffold.
