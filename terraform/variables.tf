variable "proxmox_endpoint" {
  description = "Proxmox API endpoint with a CA-valid HTTPS identity."
  type        = string
}

variable "proxmox_api_token" {
  description = "Least-privilege Proxmox API token. Supply with TF_VAR_proxmox_api_token."
  type        = string
  sensitive   = true
}

variable "proxmox_ssh_username" {
  description = "Scoped SSH identity used only by provider operations that require SSH."
  type        = string
  default     = "automation"
}

variable "enable_vm_management" {
  description = "Fail-closed gate. False produces no managed VM resources."
  type        = bool
  default     = false
}

variable "adoption_targets" {
  description = "Exact managed_vms keys enabled for one-at-a-time import and planning."
  type        = set(string)
  default     = []

  validation {
    condition     = length(var.adoption_targets) <= 1
    error_message = "At most one VM may be in the Terraform adoption scope."
  }

  validation {
    condition     = alltrue([for key in var.adoption_targets : contains(keys(var.managed_vms), key)])
    error_message = "Every adoption target must exist in managed_vms."
  }
}

variable "managed_vms" {
  description = "Enterprise SIEM VM inventory keyed by stable role name."
  type = map(object({
    vm_id                     = number
    name                      = string
    role                      = string
    node_name                 = string
    vlan_id                   = number
    reservation_ipv4_address  = string
    cores                     = number
    memory_mib                = number
    os_disk_gib               = number
    data_disk_gib             = optional(number)
    datastore_id              = string
    data_datastore_id         = optional(string, "shared-vm-storage")
    allow_nonstandard_storage = optional(bool, false)
    cpu_type                  = optional(string, "x86-64-v2-AES")
    tags                      = optional(list(string), ["soc", "example", "isolated"])
  }))
  default = {}

  validation {
    condition = alltrue([
      for vm in values(var.managed_vms) :
      (vm.datastore_id == "shared-vm-storage" && vm.data_datastore_id == "shared-vm-storage") || vm.allow_nonstandard_storage
    ])
    error_message = "A datastore other than shared-vm-storage requires allow_nonstandard_storage=true and documented approval."
  }

  validation {
    condition     = length(distinct([for vm in values(var.managed_vms) : vm.vm_id])) == length(var.managed_vms)
    error_message = "VM IDs must be unique."
  }

  validation {
    condition     = length(distinct([for vm in values(var.managed_vms) : vm.name])) == length(var.managed_vms)
    error_message = "VM names must be unique."
  }

  validation {
    condition     = length(distinct([for vm in values(var.managed_vms) : vm.reservation_ipv4_address])) == length(var.managed_vms)
    error_message = "Declared reservation addresses must be unique."
  }
}
