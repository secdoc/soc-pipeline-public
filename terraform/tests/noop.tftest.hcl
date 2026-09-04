mock_provider "proxmox" {}

variables {
  proxmox_endpoint  = "https://example.invalid:8006/"
  proxmox_api_token = join("", ["validation@pve!noop=", "00000000-0000-0000-0000-000000000000"])
}

run "management_is_disabled_by_default" {
  command = plan

  assert {
    condition     = length(output.managed_vm_inventory) == 0
    error_message = "Default configuration must not manage any VM resources."
  }
}

run "multiple_adoption_targets_are_rejected" {
  command = plan

  variables {
    enable_vm_management = true
    managed_vms = jsondecode(
      file("environments/example/soc.auto.tfvars.json")
    ).managed_vms
    adoption_targets = ["graylog-core-01", "wazuh-manager-01"]
  }

  expect_failures = [var.adoption_targets]
}
