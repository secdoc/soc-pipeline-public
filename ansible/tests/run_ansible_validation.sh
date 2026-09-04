#!/usr/bin/env bash
set -euo pipefail

engine="${CONTAINER_ENGINE:-podman}"
image="${ANSIBLE_TEST_IMAGE:-docker.io/library/debian:13-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132}"
apt_main="${ANSIBLE_TEST_APT_MAIN:-}"
apt_security="${ANSIBLE_TEST_APT_SECURITY:-}"
ca_file="${ANSIBLE_TEST_CA_FILE:-}"
ansible_core_version="${ANSIBLE_TEST_ANSIBLE_CORE_VERSION:-2.19.4-0+deb13u1}"
ansible_lint_version="${ANSIBLE_TEST_ANSIBLE_LINT_VERSION:-25.6.1+really25.2.1-1}"
name="soc-iac-ansible-validation-$RANDOM-$$"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cleanup() {
  "$engine" rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

run_args=(--detach --name "$name" --volume "$root:/workspace:ro")
if [[ -n "$ca_file" ]]; then
  run_args+=(--volume "$ca_file:/usr/local/share/ca-certificates/ansible-test-root.crt:ro")
fi
"$engine" run "${run_args[@]}" "$image" sleep infinity >/dev/null

if [[ -n "$apt_main" ]]; then
  [[ -n "$apt_security" && -n "$ca_file" ]] || {
    echo "ANSIBLE_TEST_APT_SECURITY and ANSIBLE_TEST_CA_FILE are required with ANSIBLE_TEST_APT_MAIN" >&2
    exit 1
  }
  "$engine" exec --env APT_MAIN="$apt_main" --env APT_SECURITY="$apt_security" \
    --env ANSIBLE_CORE_VERSION="$ansible_core_version" --env ANSIBLE_LINT_VERSION="$ansible_lint_version" "$name" sh -ec '
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources
    printf "deb %s trixie main\ndeb %s trixie-security main\n" "$APT_MAIN" "$APT_SECURITY" >/etc/apt/sources.list
    apt-get -o Acquire::https::CaInfo=/usr/local/share/ca-certificates/ansible-test-root.crt update >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::CaInfo=/usr/local/share/ca-certificates/ansible-test-root.crt install -y "ansible-core=$ANSIBLE_CORE_VERSION" "ansible-lint=$ANSIBLE_LINT_VERSION" ca-certificates >/dev/null
    update-ca-certificates >/dev/null
  '
else
  "$engine" exec --env ANSIBLE_CORE_VERSION="$ansible_core_version" --env ANSIBLE_LINT_VERSION="$ansible_lint_version" "$name" sh -ec 'apt-get update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y "ansible-core=$ANSIBLE_CORE_VERSION" "ansible-lint=$ANSIBLE_LINT_VERSION" ca-certificates >/dev/null'
fi

"$engine" exec --workdir /workspace "$name" ansible-lint ansible
for playbook in site.yml validate.yml wazuh_agents.yml; do
  "$engine" exec --workdir /workspace/ansible "$name" \
    ansible-playbook -i inventories/example/hosts.yml "playbooks/$playbook" --syntax-check
done
"$engine" exec --workdir /workspace/ansible "$name" \
  ansible-playbook -i localhost, tests/common_baseline/converge.yml --syntax-check
printf 'native ansible-lint and ansible-playbook validation passed\n'
