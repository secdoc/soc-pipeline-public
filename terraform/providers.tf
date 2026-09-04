provider "proxmox" {
  endpoint  = var.proxmox_endpoint
  api_token = var.proxmox_api_token

  ssh {
    agent    = true
    username = var.proxmox_ssh_username
  }
}
