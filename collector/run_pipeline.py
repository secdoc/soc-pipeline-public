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
import argparse, json, os, subprocess, sys, hashlib, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_DEFAULT = os.path.join(HERE, "..", "collector", ".delivered_state.json")

def load_env(path="/opt/soc/.env"):
    e = {}
    if os.path.exists(path):
        for l in open(path):
            if "=" in l and not l.strip().startswith("#"):
                k, v = l.strip().split("=", 1); e[k] = v
    return e

def finding_key(ev):
    raw = f"{ev.get('report_id','')}|{ev.get('nvt_oid','')}|{ev.get('host','')}"
    return hashlib.sha1(raw.encode()).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True, help="forwarded gvmd.sock path")
    ap.add_argument("--state", default=STATE_DEFAULT)
    ap.add_argument("--min-qod", type=int, default=70)
    ap.add_argument("--wazuh-path", default="/var/ossec/logs/greenbone/findings.jsonl")
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
    new = [f for f in findings if finding_key(f) not in delivered]
    print(f"pulled {len(findings)} findings; {len(new)} NEW since last run")

    if args.dry_run:
        print("dry-run: would deliver", len(new), "new findings")
        return
    if not new:
        print("nothing new to deliver"); return

    newfile = os.path.join(workdir, "new_findings.jsonl")
    with open(newfile, "w") as f:
        for ev in new:
            f.write(json.dumps(ev) + "\n")

    # 3a. Graylog (all NEW findings, retention/search)
    if not args.no_graylog:
        subprocess.run([sys.executable, os.path.join(HERE, "gelf_emitter.py"),
                        "--in", newfile, "--graylog-host", env["GRAYLOG_HOST"],
                        "--port", "12201", "--tcp",
                        "--source-host", "greenbone-scanner"], check=True)

    # 3b. Wazuh manager localfile (append NEW findings for detection)
    if not args.no_wazuh:
        key = env["WAZUH_SSH_KEY"].replace("~/.ssh", os.path.expanduser("~/.ssh"))
        if not os.path.exists(key):
            key = os.path.expanduser("~/.ssh/wazuh_hermes")
        # append via ssh: cat >> the manager file
        with open(newfile) as f:
            data = f.read()
        r = subprocess.run(["ssh", "-i", key, "-o", "StrictHostKeyChecking=accept-new",
                            "-o", "BatchMode=yes", f"{env['WAZUH_SSH_USER']}@{env['WAZUH_SSH_HOST']}",
                            f"cat >> {args.wazuh_path}"],
                           input=data, capture_output=True, text=True)
        if r.returncode != 0:
            print("WARN: wazuh delivery failed:", r.stderr[:200])
        else:
            print(f"appended {len(new)} findings to Wazuh {args.wazuh_path}")

    # 4. update delivered state
    delivered |= {finding_key(f) for f in new}
    os.makedirs(os.path.dirname(args.state), exist_ok=True)
    json.dump({"keys": sorted(delivered)}, open(args.state, "w"))
    print(f"delivered {len(new)} new findings; state now tracks {len(delivered)} keys")

if __name__ == "__main__":
    main()
