#!/usr/bin/env python3
"""
SOC Pipeline — Vulnerability dashboard generator.

Reads a Greenbone findings JSONL (the collector's normalized output) and emits,
idempotently, a point-in-time dashboard:

  - <out>/vuln-dashboard.svg   dark-themed rendered charts (severity mix, top
                               hosts, threat/solution breakdown). Rendered SVG,
                               never ASCII — matches docs/architecture.svg style.
  - <out>/vuln-dashboard.md    markdown page (KPIs + tables) for the repo and
                               for Wiki.js (embeds the SVG by URL).

Read-only over its input file. Deterministic: same input -> same output (stable
sort orders, no timestamps in the body except the explicit generated-at line and
an optional --as-of you pass in), so it is safe to regenerate on every pull and
diff cleanly in git.

Public/sanitized mode (--sanitize): pseudonymizes each distinct host to
host-NN (preserving distinctness so the per-host charts still mean something),
scrubs RFC1918 addresses from all free text, maps internal task names to generic
ones, and zeroes report ids. The public scrub-check remains the gate after this.

Usage:
  vuln_dashboard_gen.py --in findings.jsonl --out docs/ [--title "..."] \
      [--as-of 2026-08-15] [--source-commit <sha>] [--sanitize]
"""
import argparse, json, html, re, sys, os, datetime, collections

# ---- palette (matches docs/architecture.svg) ----
BG      = "#020617"
PANEL   = "#0f172a"
GRID    = "#1e293b"
FG      = "#e6edf3"
MUTED   = "#94a3b8"
CRIT    = "#f43f5e"   # rose
HIGH    = "#fb923c"   # orange
MED     = "#facc15"   # amber
LOW     = "#38bdf8"   # sky
ACCENT  = "#a78bfa"   # violet

PRIV_IP = re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                     r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
                     r'|192\.168\.\d{1,3}\.\d{1,3})\b')
TASK_MAP = {
    "Gateway Scan": "Firewall Scan", "Hypervisor Scan": "Server Scan",
    "Infrastructure Scan": "Infra Scan", "IPMI Scan": "BMC Scan",
    "User Scan": "Workstation Scan", "Wifi Scan": "WiFi Scan",
    "IOT Scan": "IoT Scan", "Camera Scan": "Camera Scan",
    "Network Scan": "Network Scan",
}


def sev_bucket(s):
    if s >= 9.0:  return "Critical"
    if s >= 7.0:  return "High"
    if s >= 4.0:  return "Medium"
    return "Low"


SEV_COLOR = {"Critical": CRIT, "High": HIGH, "Medium": MED, "Low": LOW}
SEV_ORDER = ["Critical", "High", "Medium", "Low"]


def load(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def sanitize(events):
    """Pseudonymize hosts (stable host-NN), scrub free text, map task names."""
    def scrub(v):
        if isinstance(v, str):
            return PRIV_IP.sub("192.0.2.10", v)
        if isinstance(v, list):
            return [scrub(x) for x in v]
        if isinstance(v, dict):
            return {k: scrub(x) for k, x in v.items()}
        return v

    # stable host order = first-seen, so host-01 is deterministic per input
    host_ids, n = {}, 0
    out = []
    for e in events:
        e = dict(e)
        h = e.get("host", "unknown")
        if h not in host_ids:
            n += 1
            host_ids[h] = f"host-{n:02d}"
        e["host"] = host_ids[h]
        e["task"] = TASK_MAP.get(e.get("task", ""), e.get("task", "Example Scan"))
        e["report_id"] = "00000000-0000-0000-0000-000000000000"
        # scrub every OTHER field's free text (summary banners embed IPs/URLs)
        for k in list(e.keys()):
            if k not in ("host",):
                e[k] = scrub(e[k])
        out.append(e)
    return out


def aggregate(events):
    a = {}
    a["total"] = len(events)
    a["sev"] = collections.Counter(sev_bucket(e.get("severity", 0.0)) for e in events)
    a["threat"] = collections.Counter(e.get("threat", "") or "Unknown" for e in events)
    a["soln"] = collections.Counter(e.get("solution_type", "") or "Unspecified" for e in events)
    a["family"] = collections.Counter(e.get("family", "") or "Unknown" for e in events)
    a["hosts"] = len({e.get("host") for e in events})
    a["with_cve"] = sum(1 for e in events if e.get("cves"))
    a["unique_cves"] = len({c for e in events for c in (e.get("cves") or [])})

    # per-host: count + max severity
    hc = collections.Counter()
    hmax = collections.defaultdict(float)
    for e in events:
        h = e.get("host", "unknown")
        hc[h] += 1
        hmax[h] = max(hmax[h], float(e.get("severity", 0.0)))
    a["host_count"] = hc
    a["host_max"] = hmax

    # per-task
    tc = collections.Counter(e.get("task", "") for e in events)
    thi = collections.Counter()
    for e in events:
        if float(e.get("severity", 0.0)) >= 7.0:
            thi[e.get("task", "")] += 1
    a["task_count"] = tc
    a["task_high"] = thi

    # top findings by name (with a representative severity)
    fc = collections.Counter(e.get("name", "") for e in events)
    fsev = {}
    for e in events:
        nm = e.get("name", "")
        fsev[nm] = max(fsev.get(nm, 0.0), float(e.get("severity", 0.0)))
    a["find_count"] = fc
    a["find_sev"] = fsev
    return a


def esc(s):
    return html.escape(str(s), quote=True)


def bar_row(x, y, w, label, value, vmax, color, label_w=190, bar_h=18, unit=""):
    """One horizontal bar with a right-aligned label and value."""
    frac = (value / vmax) if vmax else 0
    bw = max(1, int((w - label_w - 60) * frac))
    parts = []
    parts.append(f'<text x="{x + label_w - 6}" y="{y + bar_h - 5}" fill="{MUTED}" '
                 f'font-size="10" text-anchor="end">{esc(label)}</text>')
    parts.append(f'<rect x="{x + label_w}" y="{y}" width="{bw}" height="{bar_h}" '
                 f'rx="2" fill="{color}"/>')
    parts.append(f'<text x="{x + label_w + bw + 6}" y="{y + bar_h - 5}" fill="{FG}" '
                 f'font-size="10">{esc(value)}{esc(unit)}</text>')
    return "".join(parts)


def render_svg(a, title, as_of):
    W = 1200
    # dynamic height: top hosts (max 12) + tasks block
    top_hosts = a["host_count"].most_common(12)
    tasks = sorted(a["task_count"].items(), key=lambda kv: (-kv[1], kv[0]))
    H = 300 + max(len(top_hosts), len(tasks)) * 24 + 60
    s = []
    s.append(f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" '
             f'font-family="\'Segoe UI\',Helvetica,Arial,sans-serif">')
    s.append('<defs><pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">'
             f'<path d="M 40 0 L 0 0 0 40" fill="none" stroke="{GRID}" stroke-width="0.5"/>'
             '</pattern></defs>')
    s.append(f'<rect width="{W}" height="{H}" fill="{BG}"/>')
    s.append(f'<rect width="{W}" height="{H}" fill="url(#grid)"/>')

    # header
    s.append(f'<text x="{W//2}" y="34" fill="{FG}" font-size="20" font-weight="700" '
             f'text-anchor="middle">{esc(title)}</text>')
    sub = f"Point-in-time vulnerability posture from Greenbone. As of {esc(as_of)}."
    s.append(f'<text x="{W//2}" y="55" fill="{MUTED}" font-size="11" '
             f'text-anchor="middle">{sub}</text>')

    # KPI cards
    kpis = [
        ("FINDINGS", a["total"], ACCENT),
        ("HOSTS AFFECTED", a["hosts"], LOW),
        ("HIGH+", a["sev"]["Critical"] + a["sev"]["High"], HIGH),
        ("CRITICAL", a["sev"]["Critical"], CRIT),
        ("WITH CVE", a["with_cve"], MED),
        ("UNIQUE CVEs", a["unique_cves"], ACCENT),
    ]
    cw, gap, x0, ky = 180, 12, 30, 74
    for i, (lab, val, col) in enumerate(kpis):
        x = x0 + i * (cw + gap)
        s.append(f'<rect x="{x}" y="{ky}" width="{cw}" height="66" rx="8" '
                 f'fill="{PANEL}" stroke="{col}" stroke-width="1.3"/>')
        s.append(f'<text x="{x + cw//2}" y="{ky + 30}" fill="{col}" font-size="26" '
                 f'font-weight="700" text-anchor="middle">{esc(val)}</text>')
        s.append(f'<text x="{x + cw//2}" y="{ky + 52}" fill="{MUTED}" font-size="10" '
                 f'text-anchor="middle">{esc(lab)}</text>')

    # severity mix — stacked bar
    sy = 170
    s.append(f'<text x="30" y="{sy}" fill="{FG}" font-size="13" font-weight="700">'
             f'Severity mix</text>')
    total = a["total"] or 1
    bx, bw, bh = 30, W - 60, 30
    cur = bx
    for k in SEV_ORDER:
        v = a["sev"].get(k, 0)
        seg = int(bw * v / total)
        if seg <= 0:
            continue
        s.append(f'<rect x="{cur}" y="{sy + 12}" width="{seg}" height="{bh}" '
                 f'fill="{SEV_COLOR[k]}"/>')
        if seg > 44:
            s.append(f'<text x="{cur + seg//2}" y="{sy + 32}" fill="#0b1120" '
                     f'font-size="11" font-weight="700" text-anchor="middle">'
                     f'{esc(k)} {esc(v)}</text>')
        cur += seg
    # legend
    ly = sy + 58
    lx = 30
    for k in SEV_ORDER:
        v = a["sev"].get(k, 0)
        s.append(f'<rect x="{lx}" y="{ly - 9}" width="11" height="11" fill="{SEV_COLOR[k]}"/>')
        s.append(f'<text x="{lx + 16}" y="{ly}" fill="{MUTED}" font-size="10">'
                 f'{esc(k)}: {esc(v)}</text>')
        lx += 130

    # two columns: top hosts | scans
    col_y = sy + 90
    s.append(f'<text x="30" y="{col_y}" fill="{FG}" font-size="13" font-weight="700">'
             f'Top affected hosts (by finding count)</text>')
    s.append(f'<text x="{W//2 + 20}" y="{col_y}" fill="{FG}" font-size="13" '
             f'font-weight="700">Findings by scan</text>')
    hmax = max([c for _, c in top_hosts], default=1)
    ry = col_y + 14
    for host, cnt in top_hosts:
        mx = a["host_max"].get(host, 0.0)
        col = SEV_COLOR[sev_bucket(mx)]
        s.append(bar_row(30, ry, W // 2 - 40, host, cnt, hmax, col, label_w=150))
        ry += 24
    tmax = max([c for _, c in tasks], default=1)
    ry2 = col_y + 14
    for tname, cnt in tasks:
        hi = a["task_high"].get(tname, 0)
        col = HIGH if hi else LOW
        lbl = f"{tname}"
        s.append(bar_row(W // 2 + 20, ry2, W // 2 - 50, lbl, cnt, tmax, col, label_w=150,
                         unit=(f"  ({hi} high+)" if hi else "")))
        ry2 += 24

    s.append(f'<text x="{W//2}" y="{H - 14}" fill="{MUTED}" font-size="9" '
             f'text-anchor="middle">SOC Pipeline — generated by scripts/vuln_dashboard_gen.py. '
             f'Rendered SVG. Source of truth: secdoc/soc-pipeline.</text>')
    s.append('</svg>')
    return "\n".join(s)


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def render_md(a, events, title, as_of, svg_name, source_commit, sanitized):
    generated = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC")
    hi = a["sev"]["Critical"] + a["sev"]["High"]
    lines = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"> **Point-in-time vulnerability posture** from Greenbone, "
                 f"{a['total']} findings across {a['hosts']} hosts. "
                 f"**{hi}** are High or Critical. As of **{as_of}**.")
    lines.append("")
    tag = "SANITIZED / SYNTHETIC-SAFE" if sanitized else "REAL environment data"
    lines.append(f"*Data class: {tag}. Generated {generated} by "
                 f"`scripts/vuln_dashboard_gen.py`.*")
    lines.append("")
    lines.append(f"![Vulnerability dashboard]({svg_name})")
    lines.append("")
    # KPIs
    lines.append("## Key numbers")
    lines.append("")
    lines.append(md_table(
        ["Metric", "Value"],
        [["Total findings", a["total"]],
         ["Hosts affected", a["hosts"]],
         ["Critical (>=9.0)", a["sev"]["Critical"]],
         ["High (7.0-8.9)", a["sev"]["High"]],
         ["Medium (4.0-6.9)", a["sev"]["Medium"]],
         ["Low (<4.0)", a["sev"]["Low"]],
         ["Findings with a CVE", a["with_cve"]],
         ["Unique CVEs", a["unique_cves"]]]))
    lines.append("")
    # per-scan
    lines.append("## By scan")
    lines.append("")
    trows = []
    for t, c in sorted(a["task_count"].items(), key=lambda kv: (-kv[1], kv[0])):
        trows.append([t, c, a["task_high"].get(t, 0)])
    lines.append(md_table(["Scan", "Findings", "High+"], trows))
    lines.append("")
    # top hosts
    lines.append("## Top affected hosts")
    lines.append("")
    hrows = []
    for h, c in a["host_count"].most_common(15):
        hrows.append([h, c, f'{a["host_max"].get(h, 0.0):.1f}',
                      sev_bucket(a["host_max"].get(h, 0.0))])
    lines.append(md_table(["Host", "Findings", "Max CVSS", "Worst"], hrows))
    lines.append("")
    # top findings
    lines.append("## Most frequent findings")
    lines.append("")
    frows = []
    for nm, c in a["find_count"].most_common(15):
        sv = a["find_sev"].get(nm, 0.0)
        frows.append([nm[:70], c, f"{sv:.1f}", sev_bucket(sv)])
    lines.append(md_table(["Finding", "Count", "Max CVSS", "Severity"], frows))
    lines.append("")
    # solution types
    lines.append("## Remediation posture (by solution type)")
    lines.append("")
    srows = [[k or "Unspecified", v] for k, v in
             sorted(a["soln"].items(), key=lambda kv: -kv[1])]
    lines.append(md_table(["Solution type", "Findings"], srows))
    lines.append("")
    if source_commit:
        lines.append(f"*Source commit: `{source_commit}`. Source of truth: "
                     f"`secdoc/soc-pipeline`.*")
    else:
        lines.append("*Source of truth: `secdoc/soc-pipeline`.*")
    lines.append(f"*Last generated: {generated}.*")
    lines.append("")
    return "\n".join(lines)


def _html_table(headers, rows):
    th = "".join(f'<th style="text-align:left;padding:6px 12px;border-bottom:1px solid '
                 f'{GRID};color:{MUTED};font-weight:600">{esc(h)}</th>' for h in headers)
    trs = []
    for r in rows:
        tds = "".join(f'<td style="padding:5px 12px;border-bottom:1px solid {GRID};'
                      f'color:{FG}">{esc(c)}</td>' for c in r)
        trs.append(f"<tr>{tds}</tr>")
    return (f'<table style="border-collapse:collapse;width:100%;font-size:13px;'
            f'margin:8px 0 18px">{th and "<tr>"+th+"</tr>"}{"".join(trs)}</table>')


def render_html(a, svg, title, as_of, source_commit, sanitized):
    """Self-contained dark-theme HTML page (inline SVG + tables) for Wiki.js HTML editor."""
    generated = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC")
    hi = a["sev"]["Critical"] + a["sev"]["High"]
    tag = "SANITIZED / SYNTHETIC-SAFE" if sanitized else "REAL environment data"
    p = []
    p.append(f'<div style="background:{BG};color:{FG};padding:16px;border-radius:10px;'
             f'font-family:\'Segoe UI\',Helvetica,Arial,sans-serif">')
    p.append(f'<p style="color:{MUTED};font-size:12px;margin:0 0 4px">'
             f'Point-in-time vulnerability posture from Greenbone. {a["total"]} findings '
             f'across {a["hosts"]} hosts; <b style="color:{HIGH}">{hi}</b> High or Critical. '
             f'As of <b>{esc(as_of)}</b>. Data class: {esc(tag)}. Generated {generated}.</p>')
    p.append(f'<div style="background:{BG};padding:12px;border-radius:10px;overflow:auto">{svg}</div>')
    # tables
    p.append(f'<h2 style="color:{FG};font-size:16px;margin:18px 0 4px">By scan</h2>')
    p.append(_html_table(["Scan", "Findings", "High+"],
             [[t, c, a["task_high"].get(t, 0)] for t, c in
              sorted(a["task_count"].items(), key=lambda kv: (-kv[1], kv[0]))]))
    p.append(f'<h2 style="color:{FG};font-size:16px;margin:18px 0 4px">Top affected hosts</h2>')
    p.append(_html_table(["Host", "Findings", "Max CVSS", "Worst"],
             [[h, c, f'{a["host_max"].get(h,0.0):.1f}', sev_bucket(a["host_max"].get(h,0.0))]
              for h, c in a["host_count"].most_common(15)]))
    p.append(f'<h2 style="color:{FG};font-size:16px;margin:18px 0 4px">Most frequent findings</h2>')
    p.append(_html_table(["Finding", "Count", "Max CVSS", "Severity"],
             [[nm[:70], c, f'{a["find_sev"].get(nm,0.0):.1f}', sev_bucket(a["find_sev"].get(nm,0.0))]
              for nm, c in a["find_count"].most_common(15)]))
    p.append(f'<h2 style="color:{FG};font-size:16px;margin:18px 0 4px">Remediation posture (by solution type)</h2>')
    p.append(_html_table(["Solution type", "Findings"],
             [[k or "Unspecified", v] for k, v in sorted(a["soln"].items(), key=lambda kv: -kv[1])]))
    src = f'Source commit: <code>{esc(source_commit)}</code>. ' if source_commit else ''
    p.append(f'<p style="color:{MUTED};font-size:11px;margin-top:14px">{src}'
             f'Source of truth: <code>secdoc/soc-pipeline</code>. Rendered SVG, regenerated by '
             f'<code>scripts/vuln_dashboard_gen.py</code>. Last generated {generated}.</p>')
    p.append('</div>')
    return "\n".join(p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="findings JSONL")
    ap.add_argument("--out", required=True, help="output dir")
    ap.add_argument("--title", default="Vulnerability Dashboard")
    ap.add_argument("--as-of", default=None, help="scan date to display (default: max scan_end)")
    ap.add_argument("--source-commit", default=None)
    ap.add_argument("--sanitize", action="store_true", help="pseudonymize hosts + scrub for public")
    ap.add_argument("--html", action="store_true", help="also emit vuln-dashboard.html (Wiki.js HTML editor)")
    ap.add_argument("--svg-name", default="vuln-dashboard.svg")
    args = ap.parse_args()

    events = load(args.inp)
    if not events:
        sys.exit("no findings in input")
    if args.sanitize:
        events = sanitize(events)

    as_of = args.as_of
    if not as_of:
        ends = sorted(e.get("scan_end", "") for e in events if e.get("scan_end"))
        as_of = (ends[-1][:10] if ends else datetime.date.today().isoformat())

    a = aggregate(events)
    svg = render_svg(a, args.title, as_of)
    md = render_md(a, events, args.title, as_of, args.svg_name,
                   args.source_commit, args.sanitize)

    os.makedirs(args.out, exist_ok=True)
    svg_path = os.path.join(args.out, args.svg_name)
    md_path = os.path.join(args.out, "vuln-dashboard.md")
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(svg)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)
    outputs = [svg_path, md_path]
    if args.html:
        html_page = render_html(a, svg, args.title, as_of, args.source_commit, args.sanitize)
        html_path = os.path.join(args.out, "vuln-dashboard.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_page)
        outputs.append(html_path)
    for pth in outputs:
        print(f"wrote {pth}")
    print(f"findings={a['total']} hosts={a['hosts']} "
          f"crit={a['sev']['Critical']} high={a['sev']['High']} "
          f"med={a['sev']['Medium']} low={a['sev']['Low']} "
          f"cves={a['unique_cves']} sanitized={args.sanitize}")


if __name__ == "__main__":
    main()
