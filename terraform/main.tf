module "enterprise_siem_vm" {
  source = "./modules/proxmox_vm"
  for_each = var.enable_vm_management ? {
    for key, vm in var.managed_vms : key => vm if contains(var.adoption_targets, key)
  } : {}

  vm_id                     = each.value.vm_id
  name                      = each.value.name
  role                      = each.value.role
  node_name                 = each.value.node_name
  vlan_id                   = each.value.vlan_id
  reservation_ipv4_address  = each.value.reservation_ipv4_address
  cores                     = each.value.cores
  memory_mib                = each.value.memory_mib
  os_disk_gib               = each.value.os_disk_gib
  data_disk_gib             = try(each.value.data_disk_gib, null)
  datastore_id              = each.value.datastore_id
  data_datastore_id         = each.value.data_datastore_id
  allow_nonstandard_storage = each.value.allow_nonstandard_storage
  cpu_type                  = each.value.cpu_type
  tags                      = each.value.tags
}
