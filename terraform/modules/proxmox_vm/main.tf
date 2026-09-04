resource "proxmox_virtual_environment_vm" "this" {
  vm_id       = var.vm_id
  name        = var.name
  description = "Enterprise SIEM Phase 1 isolated build; role=${var.role}"
  node_name   = var.node_name
  tags        = var.tags

  protection          = true
  started             = false
  on_boot             = false
  stop_on_destroy     = false
  reboot_after_update = false
  scsi_hardware       = "virtio-scsi-single"
  boot_order          = ["scsi0", "ide2", "net0"]

  agent {
    enabled = true
    trim    = true
  }

  cpu {
    cores = var.cores
    type  = var.cpu_type
  }

  memory {
    dedicated = var.memory_mib
    floating  = 0
  }

  disk {
    datastore_id = var.datastore_id
    interface    = "scsi0"
    size         = var.os_disk_gib
    discard      = "on"
    iothread     = true
    ssd          = true
  }

  dynamic "disk" {
    for_each = var.data_disk_gib == null ? [] : [var.data_disk_gib]
    content {
      datastore_id = var.data_datastore_id
      interface    = "scsi1"
      size         = disk.value
      discard      = "on"
      iothread     = true
      ssd          = true
    }
  }

  initialization {
    datastore_id = var.datastore_id
    dns {
      domain  = "example.internal"
      servers = ["192.0.2.53"]
    }
    ip_config {
      ipv4 {
        address = "dhcp"
      }
    }
    user_account {
      username = "automation"
    }
  }

  network_device {
    bridge       = "vmbr0"
    disconnected = true
    firewall     = true
    model        = "virtio"
    vlan_id      = var.vlan_id
  }

  operating_system {
    type = "l26"
  }

  lifecycle {
    prevent_destroy = true
    ignore_changes = [
      started,
      on_boot,
      network_device[0].disconnected,
      cpu[0].type,
    ]
    precondition {
      condition     = (var.datastore_id == "shared-vm-storage" && var.data_datastore_id == "shared-vm-storage") || var.allow_nonstandard_storage
      error_message = "Refusing nonstandard storage without an explicit approved override."
    }
  }
}
