#!/usr/bin/env python3
"""Fail a public release when environment-specific facts are present."""

import ipaddress
import json
import os
import re
import sys

SKIP_DIRS = {".git", ".terraform", ".venv", "__pycache__", "node_modules", "venv"}
SKIP_FILES = {".git", "scrub_check.py"}
ALLOWED_PRIVATE_CIDRS = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"
))
IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?![0-9])")
INTERNAL_DNS = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:home|internal)\b")
LOCAL_PATH = re.compile(r"(?i)(?:(?:/opt|/srv)/(?!example(?:/|\b))[^\s'\"]*|/home/(?!runner\b|user\b|example\b)[a-z0-9._-]+)")
SECRET_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?(?!\$|<|CHANGE_ME|None|\"\"|'')[A-Za-z0-9!@#$%^&*_\-]{8,}")
SYNTHETIC_NODE = re.compile(r"^pve-[a-z]$")
SYNTHETIC_DATASTORES = {"shared-vm-storage"}
SYNTHETIC_VMID_RANGE = range(9000, 10000)


def private_address_is_allowed(token):
    if token in ALLOWED_PRIVATE_CIDRS:
        return True
    try:
        address = ipaddress.ip_interface(token).ip
        if any(address in network for network in DOCUMENTATION_NETWORKS):
            return True
        return not address.is_private
    except ValueError:
        return True


def validate_synthetic_inventory(data):
    findings = []
    for key, vm in (data.get("managed_vms") or {}).items():
        if SYNTHETIC_NODE.fullmatch(str(vm.get("node_name", ""))) is None:
            findings.append(f"{key}: node_name is not synthetic")
        datastores = {
            str(vm.get("datastore_id", "")),
            str(vm.get("data_datastore_id", "shared-vm-storage")),
        }
        if not datastores.issubset(SYNTHETIC_DATASTORES):
            findings.append(f"{key}: datastore is not synthetic")
        if vm.get("vm_id") not in SYNTHETIC_VMID_RANGE:
            findings.append(f"{key}: VMID is outside the synthetic range")
    return findings


def validate_synthetic_accounts(ansible_text, terraform_text):
    findings = []
    if re.search(r"(?m)^\s*ansible_user:\s*automation\s*$", ansible_text) is None:
        findings.append("Ansible example account is not synthetic")
    provider_account = re.search(
        r'variable\s+"proxmox_ssh_username"\s*\{.*?default\s*=\s*"automation"',
        terraform_text,
        re.DOTALL,
    )
    if provider_account is None:
        findings.append("Terraform example account is not synthetic")
    return findings


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    hits = []
    for directory, directories, files in os.walk(root):
        directories[:] = [name for name in directories if name not in SKIP_DIRS]
        for name in files:
            if name in SKIP_FILES:
                continue
            path = os.path.join(directory, name)
            try:
                lines = open(path, encoding="utf-8", errors="ignore")
            except OSError:
                continue
            with lines:
                for number, line in enumerate(lines, 1):
                    for match in INTERNAL_DNS.finditer(line):
                        if not match.group(0).lower().endswith("example.internal"):
                            hits.append((path, number, "internal DNS name"))
                    if LOCAL_PATH.search(line):
                        hits.append((path, number, "operator-local filesystem path"))
                    if SECRET_ASSIGNMENT.search(line):
                        hits.append((path, number, "possible hardcoded secret"))
                    for match in IPV4.finditer(line):
                        token = match.group(0)
                        if not private_address_is_allowed(token):
                            hits.append((path, number, "specific private IPv4 address"))
    inventory_path = os.path.join(root, "terraform", "environments", "example", "soc.auto.tfvars.json")
    if os.path.isfile(inventory_path):
        with open(inventory_path, encoding="utf-8") as handle:
            for finding in validate_synthetic_inventory(json.load(handle)):
                hits.append((inventory_path, 0, finding))
    ansible_path = os.path.join(root, "ansible", "inventories", "example", "hosts.yml")
    terraform_path = os.path.join(root, "terraform", "variables.tf")
    if os.path.isfile(ansible_path) and os.path.isfile(terraform_path):
        with open(ansible_path, encoding="utf-8") as ansible_file:
            ansible_text = ansible_file.read()
        with open(terraform_path, encoding="utf-8") as terraform_file:
            terraform_text = terraform_file.read()
        for finding in validate_synthetic_accounts(ansible_text, terraform_text):
            hits.append((ansible_path, 0, finding))
    if hits:
        print(f"SCRUB-CHECK FAILED: {len(hits)} possible environment leak(s)")
        for path, number, description in hits:
            print(f"  {path}:{number} [{description}]")
        return 1
    print("SCRUB-CHECK PASSED: no environment-specific facts found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
