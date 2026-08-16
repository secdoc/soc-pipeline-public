#!/usr/bin/env python3
"""
SOC Pipeline — GELF emitter (Phase 1).

Reads normalized findings (JSON-lines from greenbone_collector.py) and ships
each as a GELF message to Graylog over UDP (chunked) or TCP (null-delimited).

GELF spec fields:
  version="1.1", host, short_message, timestamp (epoch sec), level (syslog 0-7)
  everything else prefixed with "_" becomes a searchable custom field.

We map vulnerability severity -> GELF/syslog level so alert-tier routing and
Wazuh forwarding can key on it:
  CVSS >= 9  -> level 2 (Critical)
  CVSS >= 7  -> level 3 (Error/High)
  CVSS >= 4  -> level 4 (Warning/Medium)
  else       -> level 6 (Info/Low)

No secrets are added; the collector already stripped credential-like fields.
Transport is fire-and-forget UDP by default (matches syslog feed style);
use --tcp for delivery guarantees.

Usage:
  python3 collector/gelf_emitter.py --in findings.jsonl \
      --graylog-host <HOST> --port 12201 [--tcp] [--dry-run]
"""
import argparse, json, socket, sys, time, zlib, struct, uuid

def sev_to_level(cvss):
    try:
        s = float(cvss)
    except (TypeError, ValueError):
        s = 0.0
    if s >= 9: return 2
    if s >= 7: return 3
    if s >= 4: return 4
    return 6

def to_gelf(ev, source_host):
    """Normalized finding dict -> GELF 1.1 message dict."""
    # short_message is the human headline; full detail in custom fields
    short = f"[{ev.get('threat','?')}/{ev.get('severity','?')}] {ev.get('name','vuln')} on {ev.get('host','?')}"
    ts = ev.get("scan_end") or ""
    epoch = time.time()
    if ts:
        try:
            epoch = time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
        except ValueError:
            pass
    gelf = {
        "version": "1.1",
        "host": source_host,                 # the scanner/pipeline as the emitting host
        "short_message": short[:250],
        "timestamp": round(epoch, 3),
        "level": sev_to_level(ev.get("severity")),
        # custom fields (underscore-prefixed, searchable in Graylog)
        "_event_type": ev.get("event_type", "vulnerability"),
        "_source": ev.get("source", "greenbone"),
        "_scan_task": ev.get("task", ""),
        "_report_id": ev.get("report_id", ""),
        "_vuln_host": ev.get("host", ""),      # the SCANNED host (distinct from GELF host)
        "_port": ev.get("port", ""),
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
    }
    return gelf

def send_udp(sock, host, port, payload, chunk=True):
    data = zlib.compress(payload)
    MAX = 8192
    if not chunk or len(data) <= MAX:
        sock.sendto(data, (host, port))
        return
    # GELF chunked UDP: magic 0x1e0f, 8-byte msg id, seq, total
    msg_id = uuid.uuid4().bytes[:8]
    parts = [data[i:i+MAX] for i in range(0, len(data), MAX)]
    total = len(parts)
    for i, part in enumerate(parts):
        header = b"\x1e\x0f" + msg_id + struct.pack("BB", i, total)
        sock.sendto(header + part, (host, port))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--graylog-host", required=True)
    ap.add_argument("--port", type=int, default=12201)
    ap.add_argument("--source-host", default="greenbone-scanner",
                    help="value for the GELF 'host' field (the emitter/source)")
    ap.add_argument("--tcp", action="store_true", help="use GELF TCP (null-delimited) instead of UDP")
    ap.add_argument("--dry-run", action="store_true", help="print GELF messages, do not send")
    args = ap.parse_args()

    events = [json.loads(l) for l in open(args.infile) if l.strip()]
    sent = 0
    hist = {2: 0, 3: 0, 4: 0, 6: 0}

    if args.dry_run:
        for ev in events[:3]:
            print(json.dumps(to_gelf(ev, args.source_host), indent=2))
        print(f"... dry-run: {len(events)} messages would be sent")
        return

    if args.tcp:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((args.graylog_host, args.port))
        for ev in events:
            g = to_gelf(ev, args.source_host)
            hist[g["level"]] += 1
            s.sendall(json.dumps(g).encode() + b"\x00")   # GELF TCP: null-terminated, no compression
            sent += 1
        s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for ev in events:
            g = to_gelf(ev, args.source_host)
            hist[g["level"]] += 1
            send_udp(s, args.graylog_host, args.port, json.dumps(g).encode())
            sent += 1
        s.close()

    print(f"sent {sent} GELF messages to {args.graylog_host}:{args.port} ({'TCP' if args.tcp else 'UDP'})")
    print(f"levels: critical={hist[2]} high={hist[3]} medium={hist[4]} low={hist[6]}")

if __name__ == "__main__":
    main()
