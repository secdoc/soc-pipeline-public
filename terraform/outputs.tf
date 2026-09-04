output "managed_vm_inventory" {
  description = "Non-secret VM identities governed by this composition."
  value = {
    for key, vm in module.enterprise_siem_vm : key => {
      vm_id                             = vm.vm_id
      name                              = vm.name
      node_name                         = vm.node_name
      declared_reservation_ipv4_address = vm.declared_reservation_ipv4_address
    }
  }
}
