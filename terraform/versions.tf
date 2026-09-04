terraform {
  required_version = ">= 1.8.0"

  backend "http" {}

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.111.0"
    }
  }
}
