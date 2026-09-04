# Public OpenTofu/Terraform SOC scaffold

This sanitized reference models four synthetic Proxmox SOC guests with RFC 5737 addresses, generic nodes, and a generic shared datastore. Replace every example value through your own reviewed inventory.

Safety defaults:

- management disabled
- empty managed inventory
- empty adoption target set
- at most one adoption target
- protected, powered-off, non-booting, disconnected new guests
- `prevent_destroy = true`
- runtime power and NIC-link drift ignored after import

No apply is authorized by this reference. Existing resources require import-first reconciliation, remote state with locking, refresh-only and normal plans, and rejection of create, destroy, replacement, migration, storage movement, power, boot, or link changes.

For an adoption-only operation, save the plan, render its JSON, and run the included policy before review:

```text
tofu plan -out=adoption.tfplan
tofu show -json adoption.tfplan > adoption.tfplan.json
python3 ../scripts/validate_terraform_plan.py adoption.tfplan.json
```

The policy rejects every `create`, `delete`, and delete-plus-create replacement action. It does not authorize apply or prove that an imported object matches live state; continue reviewing updates, storage, power, boot, network, and provider-default drift.

Validate with OpenTofu 1.12.6:

```text
tofu fmt -check -recursive
tofu init -backend=false
tofu validate
tofu test -no-color
```

Credentials, backend configuration, state, plan files, generated imports, certificates, and live inventory must remain untracked.
