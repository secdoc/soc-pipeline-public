#!/usr/bin/env python3
"""
SOC Pipeline — Greenbone pipeline runner (Phase 1 end-to-end).

Orchestrates one full cycle:
  1. (assumes an SSH socket-forward to gvmd is already up)
  2. collector: read-only GMP pull -> normalized findings
  3. dedupe against a local state file (only NEW findings since last run)
  4. deliver: GELF/TCP -> Graylog (retention/search)  AND
     append NEW findings to the Wazuh manager's json localfile (detection)

Dedupe key = report_id + nvt_oid + vuln_host, so re-running (or a weekly scan
that re-reports the same open vuln) does NOT re-alert. Only genuinely new
findings reach Wazuh, so you don't get 366 alerts every cycle.

Read-only against Greenbone. Idempotent. Safe to cron.

Env (from /opt/soc/.env): GVM_USER, GVM_PASS, GRAYLOG_HOST,
  WAZUH_SSH_USER, WAZUH_SSH_HOST, WAZUH_SSH_KEY
"""
import argparse
import hashlib
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_DEFAULT = os.path.join(HERE, "..", "collector", ".delivered_state.json")

def load_env(path="/opt/soc/.env"):
    e = {}
    if os.path.exists(path):
        for l in open(path):
            if "=" in l and not l.strip().startswith("#"):
                k, v = l.strip().split("=", 1); e[k] = v
    return e

def legacy_finding_key(ev):
    raw = f"{ev.get('report_id','')}|{ev.get('nvt_oid','')}|{ev.get('host','')}"
    return hashlib.sha1(raw.encode()).hexdigest()


def stable_event_hash(ev):
    return hashlib.sha256(
        "\n".join(
            str(value)
            for value in (
                ev.get("report_id", ""),
                ev.get("nvt_oid", ""),
                ev.get("host", ""),
                ev.get("vuln_port", ev.get("port", "")),
                ev.get("severity", ""),
                ev.get("scan_end", ""),
            )
        ).encode()
    ).hexdigest()


def finding_key(ev):
    return stable_event_hash(ev)


def was_delivered(ev, delivered):
    return stable_event_hash(ev) in delivered or legacy_finding_key(ev) in delivered


def parse_graylog_endpoint(value):
    name, separator, address = value.partition("=")
    if not separator or not name or not address:
        raise ValueError("Graylog endpoint must be NAME=HOST:PORT[:tls|https]")
    parts = address.rsplit(":", 2)
    transport = parts[-1].lower() if len(parts) == 3 else "tcp"
    if len(parts) == 3 and transport in ("tls", "https"):
        host, port_text, _transport = parts
    elif len(parts) == 2:
        host, port_text = parts
        transport = "tcp"
    else:
        raise ValueError("Graylog endpoint must include host and port")
    return {
        "name": name,
        "host": host,
        "port": int(port_text),
        "transport": transport,
    }


def resolve_graylog_endpoints(values, default_host, default_port, include_default=True):
    endpoints = [parse_graylog_endpoint(value) for value in values]
    if include_default and not any(item["name"] == "production" for item in endpoints):
        endpoints.insert(
            0,
            {
                "name": "production",
                "host": default_host,
                "port": default_port,
                "transport": "tcp",
            },
        )
    return endpoints


def parse_wazuh_endpoint(value):
    name, separator, address = value.partition("=")
    if not separator or not name or not address:
        raise ValueError("Wazuh endpoint must be NAME=HOST:PORT[:tcp]")
    parts = address.rsplit(":", 2)
    transport = parts[-1].lower() if len(parts) == 3 else "tcp"
    if len(parts) == 3 and transport == "tcp":
        host, port_text, _transport = parts
    elif len(parts) == 2:
        host, port_text = parts
        transport = "tcp"
    else:
        raise ValueError("Wazuh endpoint must include host and port")
    return {"name": name, "host": host, "port": int(port_text), "transport": transport}


def severity_level(value):
    try:
        severity = float(value)
    except (TypeError, ValueError):
        severity = 0.0
    if severity >= 9:
        return 2
    if severity >= 7:
        return 3
    if severity >= 4:
        return 4
    return 6


def to_gelf(ev, source_host):
    short = (
        f"[{ev.get('threat','?')}/{ev.get('severity','?')}] "
        f"{ev.get('name','vuln')} on {ev.get('host','?')}"
    )
    epoch = time.time()
    scan_end = ev.get("scan_end") or ""
    if scan_end:
        try:
            epoch = time.mktime(time.strptime(scan_end, "%Y-%m-%dT%H:%M:%SZ"))
        except ValueError:
            pass
    return {
        "version": "1.1",
        "host": source_host,
        "short_message": short[:250],
        "timestamp": round(epoch, 3),
        "level": severity_level(ev.get("severity")),
        "_event_type": ev.get("event_type", "vulnerability"),
        "_source": ev.get("source", "greenbone"),
        "_feed_source": ev.get("source", "greenbone"),
        "_scan_task": ev.get("task", ""),
        "_report_id": ev.get("report_id", ""),
        "_vuln_host": ev.get("host", ""),
        "_vuln_port": ev.get("vuln_port", ev.get("port", "")),
        "_nvt_name": ev.get("name", ""),
        "_nvt_oid": ev.get("nvt_oid", ""),
        "_family": ev.get("family", ""),
        "_severity": ev.get("severity", 0.0),
        "_threat": ev.get("threat", ""),
        "_qod": ev.get("qod", 0),
        "_cvss_base": ev.get("cvss_base", ""),
        "_cvss_vector": ev.get("cvss_vector", ""),
        "_cve": ",".join(ev.get("cves", [])) if ev.get("cves") else "",
        "_cve_count": len(ev.get("cves", [])),
        "_solution_type": ev.get("solution_type", ""),
        "_summary": (ev.get("summary", "") or "")[:1000],
        "_event_hash": stable_event_hash(ev),
    }


def send_graylog_tcp(events, host, port, source_host, ssl_context=None):
    raw = socket.create_connection((host, port), timeout=30)
    connection = (
        ssl_context.wrap_socket(raw, server_hostname=host)
        if ssl_context is not None
        else raw
    )
    try:
        for event in events:
            connection.sendall(
                json.dumps(to_gelf(event, source_host)).encode() + b"\x00"
            )
    finally:
        connection.close()
    return len(events)


def send_graylog_http(events, host, port, source_host, ssl_context):
    connection = http.client.HTTPSConnection(
        host, port, context=ssl_context, timeout=30
    )
    delivered = 0
    try:
        for event in events:
            connection.request(
                "POST",
                "/gelf",
                json.dumps(to_gelf(event, source_host)).encode(),
                {"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            response.read()
            if not 200 <= response.status < 300:
                raise RuntimeError(
                    f"Graylog HTTP delivery returned {response.status}"
                )
            delivered += 1
    finally:
        connection.close()
    return delivered


def append_wazuh(events, env, wazuh_path):
    if (
        not wazuh_path.startswith("/var/ossec/logs/")
        or ".." in Path(wazuh_path).parts
    ):
        raise ValueError("Wazuh path must be below /var/ossec/logs")
    key = os.path.expanduser(env["WAZUH_SSH_KEY"])
    if not os.path.exists(key):
        key = os.path.expanduser("~/.ssh/wazuh_hermes")
    data = "".join(
        json.dumps(wazuh_event(event), ensure_ascii=False) + "\n"
        for event in events
    )
    result = subprocess.run(
        [
            "ssh",
            "-i",
            key,
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            f"{env['WAZUH_SSH_USER']}@{env['WAZUH_SSH_HOST']}",
            f"cat >> {wazuh_path}",
        ],
        input=data,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("Wazuh delivery failed: " + result.stderr[:200])
    return len(events)


def wazuh_event(event):
    payload = dict(event)
    payload["event_hash"] = stable_event_hash(event)
    return payload


def send_wazuh_tcp(events, host, port):
    connection = socket.create_connection((host, port), timeout=30)
    delivered = 0
    try:
        for event in events:
            connection.sendall(
                json.dumps(wazuh_event(event), ensure_ascii=False).encode() + b"\n"
            )
            delivered += 1
    finally:
        connection.close()
    return delivered


def save_state(path, delivered):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps({"keys": sorted(delivered)}) + "\n")
    os.replace(temporary, target)


def deliver_then_commit(state_path, delivered, events, deliveries):
    results = {name: deliver(events) for name, deliver in deliveries}
    updated = set(delivered)
    updated.update(stable_event_hash(event) for event in events)
    save_state(state_path, updated)
    return results, updated

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True, help="forwarded gvmd.sock path")
    ap.add_argument("--state", default=STATE_DEFAULT)
    ap.add_argument("--min-qod", type=int, default=70)
    ap.add_argument("--wazuh-path", default="/var/ossec/logs/greenbone/findings.jsonl")
    ap.add_argument("--wazuh-endpoint", action="append", default=[])
    ap.add_argument("--no-default-wazuh", action="store_true")
    ap.add_argument("--graylog-port", type=int, default=12201)
    ap.add_argument("--graylog-endpoint", action="append", default=[])
    ap.add_argument("--graylog-ca")
    ap.add_argument("--no-default-graylog", action="store_true")
    ap.add_argument("--source-host", default="greenbone-scanner")
    ap.add_argument("--no-graylog", action="store_true")
    ap.add_argument("--no-wazuh", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    env = load_env()
    workdir = tempfile.mkdtemp(prefix="socpipe_")

    # 1. collect
    subprocess.run([sys.executable, os.path.join(HERE, "greenbone_collector.py"),
                    "--socket", args.socket, "--out", workdir,
                    "--min-qod", str(args.min_qod)], check=True)
    jl = sorted([f for f in os.listdir(workdir) if f.endswith(".jsonl")])
    if not jl:
        print("no findings file produced"); return
    findings = [json.loads(l) for l in open(os.path.join(workdir, jl[-1])) if l.strip()]

    # 2. dedupe against delivered state
    delivered = set()
    if os.path.exists(args.state):
        delivered = set(json.load(open(args.state)).get("keys", []))
    new = [finding for finding in findings if not was_delivered(finding, delivered)]
    print(f"pulled {len(findings)} findings; {len(new)} NEW since last run")

    if args.dry_run:
        print("dry-run: would deliver", len(new), "new findings")
        return
    if not new:
        print("nothing new to deliver"); return

    endpoints = resolve_graylog_endpoints(
        args.graylog_endpoint,
        env.get("GRAYLOG_HOST", ""),
        args.graylog_port,
        include_default=not args.no_graylog and not args.no_default_graylog,
    )
    tls_context = None
    if any(endpoint["transport"] in ("tls", "https") for endpoint in endpoints):
        if not args.graylog_ca:
            raise SystemExit("--graylog-ca is required for TLS endpoints")
        tls_context = ssl.create_default_context(cafile=args.graylog_ca)

    deliveries = []
    if not args.no_graylog:
        for endpoint in endpoints:
            def deliver_graylog(events, endpoint=endpoint):
                if endpoint["transport"] == "https":
                    return send_graylog_http(
                        events,
                        endpoint["host"],
                        endpoint["port"],
                        args.source_host,
                        tls_context,
                    )
                context = tls_context if endpoint["transport"] == "tls" else None
                return send_graylog_tcp(
                    events,
                    endpoint["host"],
                    endpoint["port"],
                    args.source_host,
                    context,
                )
            deliveries.append(("graylog:" + endpoint["name"], deliver_graylog))
    if not args.no_wazuh:
        if not args.no_default_wazuh:
            deliveries.append(
                (
                    "wazuh:production",
                    lambda events: append_wazuh(events, env, args.wazuh_path),
                )
            )
        for value in args.wazuh_endpoint:
            endpoint = parse_wazuh_endpoint(value)
            deliveries.append(
                (
                    "wazuh:" + endpoint["name"],
                    lambda events, endpoint=endpoint: send_wazuh_tcp(
                        events, endpoint["host"], endpoint["port"]
                    ),
                )
            )

    try:
        results, delivered = deliver_then_commit(
            args.state, delivered, new, deliveries
        )
    except Exception as error:
        print("pipeline failed; delivered state unchanged:", str(error)[:300])
        raise SystemExit(1)
    print(
        f"delivered {len(new)} new findings; state now tracks {len(delivered)} keys:",
        json.dumps(results, sort_keys=True),
    )

if __name__ == "__main__":
    main()
