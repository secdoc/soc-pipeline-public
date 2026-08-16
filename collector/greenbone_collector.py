#!/usr/bin/env python3
"""
SOC Pipeline — Greenbone collector (Phase 1).

Read-only pull of the latest report per task from Greenbone via GMP, over an
SSH-forwarded gvmd unix socket. Normalizes each finding to a flat JSON event,
filters by Quality-of-Detection, strips nothing sensitive (findings carry no
secrets, but we defensively drop any credential-looking fields), and writes:
  - one JSON-lines file of normalized events (for the GELF emitter / Wazuh)
  - a run summary

This does NOT write to the scanner, never launches scans, never modifies
anything. GMP get_* only.

Usage:
  # first start the socket forward (separate process):
  ssh -i <key> -N -L <local.sock>:/tmp/gvm/gvmd/gvmd.sock <user>@<scanner>
  # then:
  python3 collector/greenbone_collector.py --socket <local.sock> --out <dir>

Env (from /opt/data/.env or environment): GVM_USER, GVM_PASS
"""
import argparse, json, os, sys, re, datetime
import xml.etree.ElementTree as ET

# ---- config ----
DEFAULT_MIN_QOD = 70          # drop low quality-of-detection noise (<70%)
SENSITIVE_KEYS = re.compile(r"(password|passwd|secret|api[_-]?key|token|private[_-]?key)", re.I)

def load_env(path="/opt/data/.env"):
    env = {}
    if os.path.exists(path):
        for line in open(path):
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k] = v
    return env

def gmp_connect(socket_path, timeout=120):
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    conn = UnixSocketConnection(path=socket_path, timeout=timeout)
    return Gmp(connection=conn)

def text(el, path, default=""):
    if el is None:
        return default
    v = el.findtext(path)
    return v.strip() if v else default

def extract_cves(nvt_el):
    """Pull CVE ids from the nvt/refs block."""
    cves = []
    if nvt_el is None:
        return cves
    refs = nvt_el.find("refs")
    if refs is not None:
        for ref in refs.findall("ref"):
            if (ref.get("type") or "").lower() == "cve":
                cves.append(ref.get("id"))
    # also scan tags for CVE mentions as a fallback
    return sorted(set(c for c in cves if c))

def cvss_vector(nvt_el):
    tags = text(nvt_el, "tags")
    m = re.search(r"cvss_base_vector=([^|]+)", tags)
    return m.group(1).strip() if m else ""

def normalize_result(res, task_name, report_id, scan_end):
    """One GMP <result> -> flat normalized finding dict."""
    nvt = res.find("nvt")
    sev = text(res, "severity", "0.0")
    try:
        sev_f = float(sev)
    except ValueError:
        sev_f = 0.0
    finding = {
        "event_type": "vulnerability",
        "source": "greenbone",
        "task": task_name,
        "report_id": report_id,
        "scan_end": scan_end,
        "host": text(res, "host", "unknown"),
        "port": text(res, "port"),
        "name": text(res, "name"),
        "severity": sev_f,
        "threat": text(res, "threat"),            # High/Medium/Low/Log
        "qod": _to_int(text(res, "qod/value") or text(res, "qod")),
        "nvt_oid": (nvt.get("oid") if nvt is not None else ""),
        "family": text(nvt, "family"),
        "cvss_base": text(nvt, "cvss_base"),
        "cvss_vector": cvss_vector(nvt),
        "cves": extract_cves(nvt),
        "solution_type": (nvt.find("solution").get("type") if nvt is not None and nvt.find("solution") is not None else ""),
        # keep description short to bound token/log size; scanner banners are attacker-influenceable
        "summary": (text(res, "description")[:600]),
    }
    # defensive: drop any accidental credential-looking value
    for k in list(finding.keys()):
        if SENSITIVE_KEYS.search(k):
            finding[k] = "<REDACTED>"
    return finding

def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0

def collect(gmp, guser, gpass, min_qod):
    ET.fromstring(gmp.authenticate(guser, gpass))
    # latest report per task: pull all tasks, then their last report id
    tasks_xml = ET.fromstring(gmp.get_tasks(filter_string="rows=-1"))
    findings = []
    summary = []
    for task in tasks_xml.findall("task"):
        tname = text(task, "name")
        last = task.find("last_report/report")
        if last is None:
            summary.append({"task": tname, "reports": 0, "findings": 0})
            continue
        rid = last.get("id")
        # fetch full report, only h/m/l threat levels (skip Log/debug), QoD-filtered server-side too
        report = ET.fromstring(gmp.get_report(
            rid, details=True,
            filter_string=f"rows=-1 levels=hml min_qod={min_qod} sort-reverse=severity"))
        scan_end = report.findtext(".//report/scan_end") or ""
        rfindings = []
        for res in report.findall(".//result"):
            if not res.findtext("nvt/name"):
                continue
            qod = _to_int(text(res, "qod/value") or text(res, "qod"))
            if qod and qod < min_qod:
                continue
            rfindings.append(normalize_result(res, tname, rid, scan_end))
        findings.extend(rfindings)
        summary.append({"task": tname, "report_id": rid, "findings": len(rfindings)})
    return findings, summary

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True, help="path to SSH-forwarded gvmd.sock")
    ap.add_argument("--out", default="./out", help="output dir")
    ap.add_argument("--min-qod", type=int, default=DEFAULT_MIN_QOD)
    args = ap.parse_args()

    env = load_env()
    guser = os.environ.get("GVM_USER") or env.get("GVM_USER")
    gpass = os.environ.get("GVM_PASS") or env.get("GVM_PASS")
    if not (guser and gpass):
        sys.exit("GVM_USER/GVM_PASS not found in env or /opt/data/.env")

    os.makedirs(args.out, exist_ok=True)
    gmp = gmp_connect(args.socket)
    with gmp as g:
        findings, summary = collect(g, guser, gpass, args.min_qod)

    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    events_path = os.path.join(args.out, f"greenbone-findings-{ts}.jsonl")
    with open(events_path, "w") as f:
        for ev in findings:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    # severity histogram for the run summary
    hist = {"critical(>=9)": 0, "high(7-8.9)": 0, "medium(4-6.9)": 0, "low(<4)": 0}
    for ev in findings:
        s = ev["severity"]
        if s >= 9: hist["critical(>=9)"] += 1
        elif s >= 7: hist["high(7-8.9)"] += 1
        elif s >= 4: hist["medium(4-6.9)"] += 1
        else: hist["low(<4)"] += 1

    print(f"collected {len(findings)} findings from {len(summary)} tasks -> {events_path}")
    print("severity:", json.dumps(hist))
    for s in summary:
        print(f"  {s['task']}: {s['findings']} findings")

if __name__ == "__main__":
    main()
