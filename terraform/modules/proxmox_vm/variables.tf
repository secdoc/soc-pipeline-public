variable "vm_id" { type = number }
variable "name" { type = string }
variable "role" { type = string }
variable "node_name" { type = string }
variable "vlan_id" { type = number }
variable "reservation_ipv4_address" { type = string }
variable "cores" { type = number }
variable "memory_mib" { type = number }
variable "os_disk_gib" { type = number }
variable "data_disk_gib" {
  type    = number
  default = null
}
variable "datastore_id" {
  type    = string
  default = "shared-vm-storage"
  validation {
    condition     = var.datastore_id == "shared-vm-storage" || var.allow_nonstandard_storage
    error_message = "Nonstandard storage requires an explicit approved override."
  }
}
variable "data_datastore_id" {
  type    = string
  default = "shared-vm-storage"
}
variable "allow_nonstandard_storage" {
  type    = bool
  default = false
}
variable "cpu_type" {
  type    = string
  default = "x86-64-v2-AES"
}
variable "tags" {
  type    = list(string)
  default = ["soc", "example", "isolated"]
}
