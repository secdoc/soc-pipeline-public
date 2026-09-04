output "vm_id" { value = proxmox_virtual_environment_vm.this.vm_id }
output "name" { value = proxmox_virtual_environment_vm.this.name }
output "node_name" { value = proxmox_virtual_environment_vm.this.node_name }
output "declared_reservation_ipv4_address" { value = var.reservation_ipv4_address }
