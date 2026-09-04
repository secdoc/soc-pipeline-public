#!/usr/bin/env python3
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
ROLE = ROOT / "ansible" / "roles" / "common_baseline"


class CommonBaselineDeploymentTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        path = ROOT / relative
        self.assertTrue(path.is_file(), f"missing artifact: {relative}")
        return path.read_text(encoding="utf-8")

    def test_common_baseline_is_gated_and_deployable(self):
        tasks = self.read("ansible/roles/common_baseline/tasks/main.yml")
        defaults = self.read("ansible/roles/common_baseline/defaults/main.yml")
        self.assertIn("soc_iac_apply_confirmed | bool", tasks)
        self.assertIn("ansible.builtin.apt:", tasks)
        self.assertIn("common_baseline_packages", defaults)
        self.assertNotIn("configuration skeleton only", tasks)

    def test_common_baseline_convergence_harness_exists(self):
        converge = self.read("ansible/tests/common_baseline/converge.yml")
        runner = self.read("ansible/tests/run_common_baseline_convergence.sh")
        self.assertIn("common_baseline", converge)
        self.assertIn("soc_iac_apply_confirmed: true", converge)
        self.assertIn("changed=0", runner)
        self.assertIn("soc_iac_apply_confirmed=false", runner)
        self.assertIn("ANSIBLE_TEST_APT_MAIN", runner)
        self.assertIn("ANSIBLE_TEST_CA_FILE", runner)
        self.assertIn("/workspace/ansible/tests/common_baseline/converge.yml", runner)


class ComponentDeploymentContractTests(unittest.TestCase):
    roles = {
        "common_baseline", "storage_mount", "graylog_core", "graylog_datanode",
        "wazuh_manager", "wazuh_indexer", "wazuh_dashboard", "siem_edge",
        "soc_collector", "wazuh_agent", "shuffle_workflow",
    }

    def read(self, relative: str) -> str:
        path = ROOT / relative
        self.assertTrue(path.is_file(), f"missing artifact: {relative}")
        return path.read_text(encoding="utf-8")

    def test_every_role_has_an_explicit_approved_mutation_path(self):
        mutation_tokens = (
            "ansible.builtin.apt:", "ansible.builtin.copy:", "ansible.builtin.template:",
            "ansible.builtin.file:", "ansible.builtin.command:", "ansible.builtin.uri:",
            "ansible.builtin.lineinfile:", "ansible.builtin.replace:",
        )
        for role in self.roles:
            tasks = self.read(f"ansible/roles/{role}/tasks/main.yml")
            self.assertIn("soc_iac_apply_confirmed | bool", tasks, role)
            self.assertTrue(any(token in tasks for token in mutation_tokens), role)
            self.assertNotIn("configuration skeleton only", tasks, role)

    def test_service_restart_handlers_are_separately_gated(self):
        service_roles = {
            "graylog_core", "graylog_datanode", "wazuh_manager", "wazuh_indexer",
            "wazuh_dashboard", "wazuh_agent", "soc_collector",
        }
        for role in service_roles:
            handlers = self.read(f"ansible/roles/{role}/handlers/main.yml")
            self.assertIn("ansible.builtin.systemd_service:", handlers, role)
            self.assertIn("soc_iac_restart_confirmed | bool", handlers, role)

    def test_ci_executes_native_ansible_and_convergence_gates(self):
        pipeline = self.read(".gitlab-ci.yml")
        validation = self.read("ansible/tests/run_ansible_validation.sh")
        convergence = self.read("ansible/tests/run_common_baseline_convergence.sh")
        self.assertIn("ansible-lint", pipeline)
        self.assertIn("ansible-playbook", pipeline)
        self.assertIn("run_common_baseline_convergence.sh", pipeline)
        self.assertIn('--workdir /workspace/ansible "$name" ansible-lint .', validation)
        self.assertGreaterEqual(convergence.count("--workdir /workspace/ansible"), 3)

    def test_templates_use_adopter_variables_not_fixed_topology(self):
        templates = {
            "ansible/roles/graylog_core/templates/server.conf.j2": ("graylog_core_domain",),
            "ansible/roles/graylog_datanode/templates/datanode.conf.j2": (
                "graylog_datanode_cluster_name", "graylog_datanode_repository_path",
            ),
            "ansible/roles/wazuh_indexer/templates/opensearch.yml.j2": (
                "wazuh_indexer_cluster_name", "wazuh_indexer_repository_path",
            ),
            "ansible/roles/siem_edge/templates/haproxy.cfg.j2": (
                "siem_edge_graylog_vip", "siem_edge_wazuh_vip", "siem_edge_dashboard_vip",
            ),
            "ansible/roles/siem_edge/templates/keepalived.conf.j2": (
                "siem_edge_graylog_vip", "siem_edge_wazuh_vip", "siem_edge_dashboard_vip",
            ),
        }
        for path, variables in templates.items():
            content = self.read(path)
            for variable in variables:
                self.assertIn(variable, content, path)
            self.assertNotIn("192.0.2.", content, path)

    def test_adopter_deployment_guide_covers_every_role_and_boundary(self):
        guide = self.read("ansible/DEPLOYMENT.md")
        for role in self.roles:
            self.assertIn(f"## `{role}`", guide)
        for section in ("Prerequisites", "Secrets", "Verification", "Rollback", "Known gaps"):
            self.assertIn(f"## {section}", guide)
        self.assertIn("soc_iac_apply_confirmed", guide)
        self.assertIn("soc_iac_restart_confirmed", guide)
        self.assertIn("systemd", guide)
        self.assertIn("fstab is restored only after the rollback unmount succeeds", guide)

    def test_security_sensitive_templates_reject_unsafe_defaults_and_values(self):
        indexer = self.read("ansible/roles/wazuh_indexer/templates/opensearch.yml.j2")
        collector = self.read("ansible/roles/soc_collector/tasks/main.yml")
        collector_template = self.read("ansible/roles/soc_collector/templates/collector.service.j2")
        shuffle = self.read("ansible/roles/shuffle_workflow/tasks/main.yml")
        self.assertNotIn("enforce_hostname_verification: false", indexer)
        self.assertNotIn("item.command", collector)
        self.assertIn("item.schedule is match", collector)
        self.assertIn("item.user | default('root') is match", collector)
        self.assertIn("item.executable is match", collector)
        self.assertNotIn("item.command", collector_template)
        self.assertIn("soc_collector_executable_checks.results", collector_template)
        self.assertIn("^/api/[A-Za-z0-9_./-]+$", shuffle)
        self.assertNotIn("?=&%", shuffle)
        self.assertIn("randomized_delay | default('30s') is match", collector)
        self.assertIn("resolve(strict=True)", collector)
        self.assertIn("st_uid != 0", collector)
        self.assertIn("0o022", collector)

    def test_ci_supply_chain_and_auth_cleanup_are_fail_closed(self):
        pipeline = self.read(".gitlab-ci.yml")
        validation = self.read("ansible/tests/run_ansible_validation.sh")
        convergence = self.read("ansible/tests/run_common_baseline_convergence.sh")
        self.assertIn("trap 'rm -f \"$REGISTRY_AUTH_FILE\"' EXIT", pipeline)
        for script in (validation, convergence):
            self.assertRegex(script, r"debian:13-slim@sha256:[0-9a-f]{64}")
            self.assertIn("ANSIBLE_TEST_ANSIBLE_CORE_VERSION", script)
        self.assertIn("ANSIBLE_TEST_ANSIBLE_LINT_VERSION", validation)

    def test_service_package_installation_suppresses_maintainer_starts(self):
        package_roles = {
            "common_baseline", "graylog_core", "graylog_datanode", "wazuh_manager", "wazuh_indexer",
            "wazuh_dashboard", "wazuh_agent", "siem_edge",
        }
        for role in package_roles:
            tasks = self.read(f"ansible/roles/{role}/tasks/main.yml")
            self.assertIn("policy_rc_d: 101", tasks, role)

    def test_wazuh_identity_is_checked_before_package_mutation_and_fails_closed(self):
        tasks = self.read("ansible/roles/wazuh_agent/tasks/main.yml")
        self.assertLess(tasks.index("Read any existing Wazuh agent identity"), tasks.index("Install the adopter-selected"))
        self.assertNotIn("wazuh_agent_existing_key.failed | default(false) or", tasks)
        self.assertIn("wazuh_agent_key_stat.stat.exists", tasks)
        self.assertIn("Require exactly one manager address", tasks)
        self.assertIn("when: not ansible_check_mode", tasks)
        self.assertIn("Restore the pre-install Wazuh identity", tasks)
        self.assertIn("Remove package-created Wazuh identity", tasks)
        self.assertNotIn("wazuh_agent_key_copy.backup_file", tasks)

    def test_storage_rejects_wrong_active_mount_and_reads_back_activation(self):
        tasks = self.read("ansible/roles/storage_mount/tasks/main.yml")
        defaults = self.read("ansible/roles/storage_mount/defaults/main.yml")
        self.assertIn("Reject an unexpected active mount", tasks)
        self.assertIn("Read back the activated mount", tasks)
        self.assertIn("storage_mount_post_state", tasks)
        self.assertIn("storage_mount_required_options", tasks)
        self.assertIn("Unmount a filesystem activated by this failed transaction", tasks)
        self.assertIn("storage_mount_options | join(',')", tasks)
        self.assertIn("storage_mount_options:", defaults)
        self.assertNotIn("failed_when: false\n      when:\n        - storage_mount_activation", tasks)

    def test_wazuh_artifacts_are_confined_to_rules_and_decoders(self):
        tasks = self.read("ansible/roles/wazuh_manager/tasks/main.yml")
        self.assertIn("Validate adopter artifact paths", tasks)
        self.assertIn("^/var/ossec/etc/(rules|decoders)/", tasks)
        self.assertIn("wazuh_manager_artifact_root", tasks)
        self.assertIn("resolve(strict=True)", tasks)
        self.assertIn("relative_to(root)", tasks)
        self.assertIn("wazuh_manager_artifact_source_checks.results", tasks)
        self.assertIn("Verify installed Wazuh artifact checksums", tasks)
        self.assertIn("wazuh_manager_installed_artifact_checks", tasks)

    def test_shuffle_requires_normalized_https_origin(self):
        tasks = self.read("ansible/roles/shuffle_workflow/tasks/main.yml")
        self.assertIn("^https://", tasks)
        self.assertIn("'..' not in item.endpoint", tasks)
        self.assertIn("validate_certs: true", tasks)
        self.assertNotIn("shuffle_workflow_validate_certs", tasks)
        validation = tasks[tasks.index("Validate adopter-supplied workflow contracts"):tasks.index("Reconcile approved Shuffle workflows")]
        self.assertIn("no_log: true", validation)
        self.assertIn("label: \"{{ item.name }}\"", validation)

    def test_product_configurations_are_candidate_validated_before_activation(self):
        for role in ("graylog_core", "graylog_datanode", "wazuh_indexer", "wazuh_dashboard"):
            tasks = self.read(f"ansible/roles/{role}/tasks/main.yml")
            self.assertIn("soc_iac_candidate_root", tasks, role)
            self.assertIn(f"{role}_validation_command", tasks, role)
            self.assertIn("Validate the candidate", tasks, role)
            self.assertIn("rescue:", tasks, role)
            self.assertIn("when: not ansible_check_mode", tasks, role)

    def test_wazuh_manager_uses_xml_candidate_before_active_validation(self):
        tasks = self.read("ansible/roles/wazuh_manager/tasks/main.yml")
        self.assertIn("soc_iac_candidate_root", tasks)
        self.assertIn("wazuh_manager_validation_command", tasks)
        self.assertIn("Validate the candidate Wazuh manager XML", tasks)
        self.assertLess(tasks.index("Validate the candidate Wazuh manager XML"), tasks.index("Install rendered manager configuration"))

    def test_edge_activation_is_atomic_and_restores_both_configs(self):
        tasks = self.read("ansible/roles/siem_edge/tasks/main.yml")
        self.assertIn("rescue:", tasks)
        self.assertIn("siem_edge_haproxy_active_copy", tasks)
        self.assertIn("siem_edge_keepalived_active_copy", tasks)
        self.assertIn("Restore prior HAProxy configuration", tasks)
        self.assertIn("Restore prior Keepalived configuration", tasks)
        keepalived = self.read("ansible/roles/siem_edge/templates/keepalived.conf.j2")
        self.assertEqual(3, keepalived.count("siem_edge_health_check_path"))

    def test_edge_packages_require_exact_versions(self):
        defaults = self.read("ansible/roles/siem_edge/defaults/main.yml")
        tasks = self.read("ansible/roles/siem_edge/tasks/main.yml")
        self.assertIn("siem_edge_haproxy_version", defaults)
        self.assertIn("siem_edge_keepalived_version", defaults)
        self.assertIn("haproxy={{ siem_edge_haproxy_version }}", tasks)
        self.assertIn("keepalived={{ siem_edge_keepalived_version }}", tasks)

    def test_convergence_outputs_are_job_private(self):
        runner = self.read("ansible/tests/run_common_baseline_convergence.sh")
        self.assertIn("mktemp -d", runner)
        self.assertNotIn("/tmp/soc-iac-", runner)

    def test_ci_discovers_deployment_contract_suite(self):
        pipeline = self.read(".gitlab-ci.yml")
        self.assertIn("unittest discover -s tests -v", pipeline)

    def test_collector_write_paths_are_canonical_and_root_confined(self):
        tasks = self.read("ansible/roles/soc_collector/tasks/main.yml")
        template = self.read("ansible/roles/soc_collector/templates/collector.service.j2")
        self.assertIn("soc_collector_allowed_write_roots", tasks)
        self.assertIn("relative_to(root)", tasks)
        self.assertIn("soc_collector_write_path_checks.results", template)


if __name__ == "__main__":
    unittest.main()
