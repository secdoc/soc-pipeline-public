#!/usr/bin/env python3
import json
import importlib.util
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


def load_scrubber():
    path = ROOT / "scripts" / "scrub_check.py"
    spec = importlib.util.spec_from_file_location("scrub_check", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_plan_validator():
    path = ROOT / "scripts" / "validate_terraform_plan.py"
    spec = importlib.util.spec_from_file_location("validate_terraform_plan", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PublicIaCContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        path = ROOT / relative
        self.assertTrue(path.is_file(), f"missing public IaC artifact: {relative}")
        return path.read_text(encoding="utf-8")

    def test_terraform_is_noop_by_default_and_single_target(self):
        variables = self.read("terraform/variables.tf")
        main = self.read("terraform/main.tf")
        module = self.read("terraform/modules/proxmox_vm/main.tf")
        self.assertIn("enable_vm_management", variables)
        self.assertIn("default     = false", variables)
        self.assertIn("length(var.adoption_targets) <= 1", variables)
        self.assertIn("var.enable_vm_management", main)
        self.assertIn("prevent_destroy = true", module)
        self.assertIn("reboot_after_update = false", module)

    def test_adoption_plan_policy_rejects_create_replace_and_destroy(self):
        validator = load_plan_validator()
        safe = {"resource_changes": [{"address": "module.vm", "change": {"actions": ["no-op"]}}]}
        create = {"resource_changes": [{"address": "module.vm", "change": {"actions": ["create"]}}]}
        replace = {"resource_changes": [{"address": "module.vm", "change": {"actions": ["delete", "create"]}}]}
        destroy = {"resource_changes": [{"address": "module.vm", "change": {"actions": ["delete"]}}]}
        self.assertEqual([], validator.forbidden_changes(safe))
        self.assertEqual(1, len(validator.forbidden_changes(create)))
        self.assertEqual(1, len(validator.forbidden_changes(replace)))
        self.assertEqual(1, len(validator.forbidden_changes(destroy)))

    def test_public_inventory_is_synthetic(self):
        inventory = json.loads(self.read("terraform/environments/example/soc.auto.tfvars.json"))
        self.assertEqual(4, len(inventory["managed_vms"]))
        serialized = json.dumps(inventory)
        for vm in inventory["managed_vms"].values():
            self.assertRegex(vm["node_name"], r"^pve-[a-z]$")
            self.assertEqual("shared-vm-storage", vm["datastore_id"])
            self.assertGreaterEqual(vm["vm_id"], 9000)
            self.assertLess(vm["vm_id"], 10000)
        addresses = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", serialized)
        self.assertTrue(addresses)
        for address in addresses:
            self.assertTrue(address.startswith(("192.0.2.", "198.51.100.", "203.0.113.")))

    def test_structural_scrubber_rejects_non_synthetic_inventory(self):
        scrubber = load_scrubber()
        valid = json.loads(self.read("terraform/environments/example/soc.auto.tfvars.json"))
        self.assertEqual([], scrubber.validate_synthetic_inventory(valid))
        invalid = json.loads(json.dumps(valid))
        first = next(iter(invalid["managed_vms"].values()))
        first.update(node_name="cluster-node-9", datastore_id="fast-storage", vm_id=8123)
        findings = scrubber.validate_synthetic_inventory(invalid)
        self.assertEqual(3, len(findings))

    def test_structural_scrubber_rejects_non_synthetic_accounts(self):
        scrubber = load_scrubber()
        ansible_text = self.read("ansible/inventories/example/hosts.yml")
        terraform_text = self.read("terraform/variables.tf")
        self.assertEqual([], scrubber.validate_synthetic_accounts(ansible_text, terraform_text))
        findings = scrubber.validate_synthetic_accounts(
            ansible_text.replace("ansible_user: automation", "ansible_user: build-operator"),
            terraform_text.replace('default     = "automation"', 'default     = "build-operator"'),
        )
        self.assertEqual(2, len(findings))

    def test_import_example_uses_synthetic_node_and_vmid(self):
        imports = self.read("terraform/imports.tf.example")
        self.assertIn('id = "pve-a/9001"', imports)
        self.assertNotRegex(imports, r'\bid = "[^\"]+/[1-8][0-9]{2}"')

    def test_all_component_roles_are_published(self):
        expected = {
            "common_baseline", "storage_mount", "graylog_core", "graylog_datanode",
            "wazuh_manager", "wazuh_indexer", "wazuh_dashboard", "siem_edge",
            "soc_collector", "wazuh_agent", "shuffle_workflow",
        }
        observed = {path.name for path in (ROOT / "ansible" / "roles").iterdir() if path.is_dir()}
        self.assertEqual(expected, observed)

    def test_ansible_defaults_fail_closed(self):
        group_vars = self.read("ansible/inventories/example/group_vars/all/main.yml")
        self.assertIn("soc_iac_apply_confirmed: false", group_vars)
        self.assertIn("soc_iac_restart_confirmed: false", group_vars)
        cfg = self.read("ansible/ansible.cfg")
        self.assertIn("host_key_checking = True", cfg)
        for tasks in (ROOT / "ansible" / "roles").glob("*/tasks/main.yml"):
            content = tasks.read_text(encoding="utf-8")
            self.assertIn("not (soc_iac_apply_confirmed | bool)", content, tasks)
            for mutation in ("ansible.builtin.apt:", "ansible.builtin.copy:", "ansible.builtin.template:",
                             "ansible.builtin.systemd_service:", "ansible.posix.mount:"):
                self.assertNotIn(mutation, content, tasks)
        for handlers in (ROOT / "ansible" / "roles").glob("*/handlers/main.yml"):
            self.assertEqual("---\n[]", handlers.read_text(encoding="utf-8").strip(), handlers)

    def test_edge_role_is_candidate_only(self):
        tasks = self.read("ansible/roles/siem_edge/tasks/main.yml")
        handlers = self.read("ansible/roles/siem_edge/handlers/main.yml")
        self.assertNotIn("/etc/haproxy", tasks)
        self.assertNotIn("/etc/keepalived", tasks)
        self.assertTrue((ROOT / "ansible/roles/siem_edge/templates/haproxy.cfg.j2").is_file())
        self.assertTrue((ROOT / "ansible/roles/siem_edge/templates/keepalived.conf.j2").is_file())
        self.assertEqual("---\n[]", handlers.strip())

    def test_public_docs_state_no_live_apply(self):
        terraform = self.read("terraform/README.md")
        ansible = self.read("ansible/README.md")
        self.assertIn("No apply is authorized", terraform)
        self.assertIn("example", terraform.lower())
        self.assertIn("No live deployment is authorized", ansible)
        self.assertIn("Issue 18 remains open", ansible)

    def test_ci_runs_iac_and_scrub_contracts(self):
        pipeline = self.read(".gitlab-ci.yml")
        self.assertIn("tests.test_iac_public_contract", pipeline)
        self.assertIn("scripts/scrub_check.py", pipeline)
        scrubber = self.read("scripts/scrub_check.py")
        self.assertNotIn("name.endswith(TEXT_SUFFIXES", scrubber)
        self.assertIn("if name in SKIP_FILES", scrubber)
        self.assertIn('".terraform"', scrubber)
        self.assertIn('SKIP_FILES = {".git", "scrub_check.py"}', scrubber)

    def test_scrubber_rejects_private_values_in_jinja_templates(self):
        with tempfile.TemporaryDirectory() as directory:
            private_ip = ".".join(("10", "23", "45", "67"))
            private_path = "/" + "/".join(("opt", "private", "operator"))
            for name in ("config.conf.j2", "backend.hcl.example", "imports.tf.example", "Dockerfile", "NOTICE"):
                artifact = Path(directory) / name
                artifact.write_text(f"host={private_ip}\npath={private_path}\n", encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts" / "scrub_check.py"), directory],
                    text=True,
                    capture_output=True,
                )
                self.assertNotEqual(0, result.returncode, name)
                self.assertIn("specific private IPv4 address", result.stdout)
                self.assertIn("operator-local filesystem path", result.stdout)
                artifact.unlink()


if __name__ == "__main__":
    unittest.main()
