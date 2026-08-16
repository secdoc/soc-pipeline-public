#!/usr/bin/env python3
"""Generate a SANITIZED public sample from a real collector output.
Scrubs ALL private IPs (10/172.16-31/192.168) from EVERY field, including the
free-text `summary` (scanner banners embed IPs/URLs). Replaces with RFC5737
example ranges and generic task names. The public scrub-check must still pass
after this runs — this is belt, the scrub-check is braces.

Usage: sanitize_sample.py <real.jsonl> <out.jsonl> [count]
"""
import json, re, sys

PRIV_IP = re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                     r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
                     r'|192\.168\.\d{1,3}\.\d{1,3})\b')
TASK_MAP = {
    "Gateway Scan": "Firewall Scan", "Hypervisor Scan": "Server Scan",
    "Infrastructure Scan": "Infra Scan", "IPMI Scan": "BMC Scan",
    "User Scan": "Workstation Scan", "Wifi Scan": "WiFi Scan",
    "IOT Scan": "IoT Scan",
}

def scrub(obj):
    if isinstance(obj, str):
        return PRIV_IP.sub("192.0.2.10", obj)
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()}
    return obj

def main():
    if len(sys.argv) < 3:
        sys.exit("usage: sanitize_sample.py <real.jsonl> <out.jsonl> [count]")
    src, out = sys.argv[1], sys.argv[2]
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    events = [json.loads(l) for l in open(src)]
    # representative mix across severities
    hi = [e for e in events if e.get("severity", 0) >= 7][:5]
    md = [e for e in events if 4 <= e.get("severity", 0) < 7][:5]
    lo = [e for e in events if e.get("severity", 0) < 4][:max(0, count - 10)]
    picked = (hi + md + lo)[:count]
    with open(out, "w") as f:
        for e in picked:
            e = dict(e)
            e["report_id"] = "00000000-0000-0000-0000-000000000000"
            e["task"] = TASK_MAP.get(e.get("task", ""), e.get("task", "Example Scan"))
            e = scrub(e)
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    # self-verify no private IP survived
    leaked = sum(len(PRIV_IP.findall(l)) for l in open(out))
    print(f"wrote {len(picked)} sanitized events -> {out}")
    print("private IPs remaining:", leaked, "(must be 0)")
    sys.exit(1 if leaked else 0)

if __name__ == "__main__":
    main()
