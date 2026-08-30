#!/usr/bin/env python3
"""Safe Wazuh agent manager transition and rollback script generator."""

import argparse
import json
import re
import shlex

SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
SAFE_HOST = re.compile(r"^[A-Za-z0-9.-]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _path(value):
    if not SAFE_PATH.fullmatch(value) or ".." in value.split("/"):
        raise ValueError(f"unsafe path: {value!r}")
    return shlex.quote(value)


def _host(value):
    if not SAFE_HOST.fullmatch(value):
        raise ValueError(f"unsafe manager identity: {value!r}")
    return shlex.quote(value)


def _stop_boundary():
    return """systemctl stop wazuh-agent
for _ in $(seq 1 30); do
  if ! pgrep -x wazuh-agentd >/dev/null; then break; fi
  sleep 1
done
if pgrep -x wazuh-agentd >/dev/null; then
  echo 'wazuh-agentd did not exit after service stop' >&2
  exit 1
fi
"""


def _start_and_verify(manager):
    host = _host(manager)
    return f"""/var/ossec/bin/wazuh-agentd -t
systemctl start wazuh-agent
for _ in $(seq 1 30); do
  if systemctl is-active --quiet wazuh-agent && pgrep -x wazuh-agentd >/dev/null; then break; fi
  sleep 1
done
systemctl is-active --quiet wazuh-agent
pgrep -x wazuh-agentd >/dev/null
MANAGER={host}
MANAGER_IP=$(getent ahostsv4 "$MANAGER" | awk 'NR==1{{print $1}}')
test -n "$MANAGER_IP"
for _ in $(seq 1 30); do
  if ss -Htnp | grep -F "$MANAGER_IP:1514" >/dev/null; then break; fi
  sleep 1
done
ss -Htnp | grep -F "$MANAGER_IP:1514" >/dev/null
# Expected manager: {manager}:1514
"""


def render_activation_script(target_ossec, target_keys, manager):
    ossec = _path(target_ossec)
    keys = _path(target_keys)
    return "#!/bin/bash\nset -euo pipefail\n" + f"""test -s {ossec}
test -s {keys}
""" + _stop_boundary() + f"""install -o root -g wazuh -m 0660 {ossec} /var/ossec/etc/ossec.conf
install -o wazuh -g wazuh -m 0640 {keys} /var/ossec/etc/client.keys
""" + _start_and_verify(manager)


def render_rollback_script(source_ossec, source_keys, ossec_sha256, keys_sha256, manager):
    if not SHA256.fullmatch(ossec_sha256) or not SHA256.fullmatch(keys_sha256):
        raise ValueError("rollback SHA-256 value is invalid")
    ossec = _path(source_ossec)
    keys = _path(source_keys)
    return "#!/bin/bash\nset -euo pipefail\n" + f"""test -s {ossec}
test -s {keys}
""" + _stop_boundary() + f"""install -o root -g wazuh -m 0660 {ossec} /var/ossec/etc/ossec.conf
install -o wazuh -g wazuh -m 0640 {keys} /var/ossec/etc/client.keys
test "$(sha256sum /var/ossec/etc/ossec.conf | cut -d' ' -f1)" = {ossec_sha256}
test "$(sha256sum /var/ossec/etc/client.keys | cut -d' ' -f1)" = {keys_sha256}
""" + _start_and_verify(manager)


def acceptance_failures(observed, expected):
    failures = {}
    for field, expected_value in expected.items():
        actual = observed.get(field)
        if actual != expected_value:
            failures[field] = {"expected": expected_value, "actual": actual}
    return failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("activate", "rollback"))
    parser.add_argument("--ossec", required=True)
    parser.add_argument("--keys", required=True)
    parser.add_argument("--manager", required=True)
    parser.add_argument("--ossec-sha256")
    parser.add_argument("--keys-sha256")
    args = parser.parse_args()
    if args.mode == "activate":
        script = render_activation_script(args.ossec, args.keys, args.manager)
    else:
        if not args.ossec_sha256 or not args.keys_sha256:
            parser.error("rollback requires both SHA-256 values")
        script = render_rollback_script(
            args.ossec,
            args.keys,
            args.ossec_sha256,
            args.keys_sha256,
            args.manager,
        )
    print(script, end="")


if __name__ == "__main__":
    main()
