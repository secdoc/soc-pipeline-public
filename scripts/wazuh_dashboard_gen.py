#!/usr/bin/env python3
"""
SOC Pipeline — Wazuh (OpenSearch Dashboards) vulnerability dashboard builder.

Emits an OpenSearch Dashboards saved-objects NDJSON that can be imported into the
Wazuh dashboard (Stack Management -> Saved Objects -> Import, or POST
/api/saved_objects/_import). It builds a "SOC Pipeline - Vulnerability (Greenbone)"
dashboard over the existing `wazuh-alerts-*` index pattern, filtered to
`rule.groups: greenbone`.

Panels (aggregation-based, no scripted fields):
  - KPI metric: total Greenbone alerts
  - Severity tier: donut on rule.level (2=Low,5=Med,10=High,12=Crit)
  - Threat band: bar on data.threat
  - Top vulnerable hosts: bar on data.host
  - Top findings: bar on data.name
  - Top CVEs: bar on data.cves
  - By scan: bar on data.task
  - Remediation posture: bar on data.solution_type
  - Alert timeline: date histogram split by rule.level

The dimension fields (data.host/name/task/family/solution_type) populate the
mapping only once real findings are indexed; panels show "No results" until then.

This writes NOTHING to the cluster. It only produces the NDJSON file. Import is a
separate, explicit step (see the runbook / --print-import-cmd).

Usage:
  wazuh_dashboard_gen.py --index-pattern-id 'wazuh-alerts-*' --out docs/wazuh-vuln-dashboard.ndjson
"""
import argparse, json, os, sys

IDX_REF = "kibanaSavedObjectMeta.searchSourceJSON"


def _search_source(index_ref_name, extra_filters=None, query=None):
    ss = {
        "query": query or {"query": "rule.groups: greenbone", "language": "kuery"},
        "filter": extra_filters or [],
        "indexRefName": index_ref_name,
    }
    return json.dumps(ss)


def _vis(vid, title, vis_state, index_ref_name="kibanaSavedObjectMeta.searchSourceJSON.index"):
    return {
        "id": vid,
        "type": "visualization",
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(index_ref_name)},
        },
        "references": [
            {"name": index_ref_name, "type": "index-pattern", "id": "__IPID__"}
        ],
    }


def _metric(vid, title, label):
    vs = {
        "title": title, "type": "metric",
        "params": {"metric": {"percentageMode": False, "useRanges": False,
                              "colorSchema": "Green to Red", "metricColorMode": "None",
                              "labels": {"show": True}, "style": {"fontSize": 48}}},
        "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric",
                  "params": {"customLabel": label}}],
    }
    return _vis(vid, title, vs)


def _terms_bar(vid, title, field, size=15, custom_label=None, order_by="1"):
    vs = {
        "title": title, "type": "histogram",
        "params": {"type": "histogram", "grid": {"categoryLines": False},
                   "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                                     "position": "left", "show": True, "style": {},
                                     "scale": {"type": "linear"},
                                     "labels": {"show": True, "truncate": 100},
                                     "title": {}}],
                   "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1",
                                  "type": "value", "position": "bottom", "show": True,
                                  "style": {}, "scale": {"type": "linear", "mode": "normal"},
                                  "labels": {"show": True, "rotate": 0, "filter": True,
                                             "truncate": 100}, "title": {"text": "Count"}}],
                   "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                     "data": {"label": "Count", "id": "1"},
                                     "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                     "showCircles": True}],
                   "addTooltip": True, "addLegend": True, "legendPosition": "right",
                   "times": [], "addTimeMarker": False},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": field, "orderBy": order_by, "order": "desc",
                        "size": size, "otherBucket": False, "missingBucket": False,
                        "customLabel": custom_label or field}},
        ],
    }
    return _vis(vid, title, vs)


def _pie(vid, title, field, custom_label=None, size=10):
    vs = {
        "title": title, "type": "pie",
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "right", "isDonut": True,
                   "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                        "customLabel": custom_label or field}},
        ],
    }
    return _vis(vid, title, vs)


def _timeline(vid, title, split_field):
    vs = {
        "title": title, "type": "histogram",
        "params": {"type": "histogram", "grid": {"categoryLines": False},
                   "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                                     "position": "bottom", "show": True, "style": {},
                                     "scale": {"type": "linear"},
                                     "labels": {"show": True, "truncate": 100}, "title": {}}],
                   "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                                  "position": "left", "show": True, "style": {},
                                  "scale": {"type": "linear", "mode": "normal"},
                                  "labels": {"show": True, "rotate": 0, "filter": False,
                                             "truncate": 100}, "title": {"text": "Count"}}],
                   "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                     "data": {"label": "Count", "id": "1"},
                                     "valueAxis": "ValueAxis-1"}],
                   "addTooltip": True, "addLegend": True, "legendPosition": "right",
                   "times": [], "addTimeMarker": False},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": "timestamp", "useNormalizedEsInterval": True,
                        "interval": "auto", "drop_partials": False, "min_doc_count": 1}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "group",
             "params": {"field": split_field, "orderBy": "1", "order": "desc", "size": 5,
                        "customLabel": "severity tier (rule.level)"}},
        ],
    }
    return _vis(vid, title, vs)


PANELS = [
    ("vuln_kpi_total",   _metric,  ("SOC Vuln - Total Greenbone alerts", "Greenbone alerts")),
    ("vuln_sev_tier",    _pie,     ("SOC Vuln - Severity tier (rule.level)", "rule.level", "tier")),
    ("vuln_threat",      _terms_bar, ("SOC Vuln - Threat band", "data.threat", 6, "threat")),
    ("vuln_top_hosts",   _terms_bar, ("SOC Vuln - Top vulnerable hosts", "data.host", 15, "host")),
    ("vuln_top_findings",_terms_bar, ("SOC Vuln - Top findings", "data.name", 15, "finding")),
    ("vuln_top_cves",    _terms_bar, ("SOC Vuln - Top CVEs", "data.cves", 15, "CVE")),
    ("vuln_by_scan",     _terms_bar, ("SOC Vuln - By scan", "data.task", 12, "scan")),
    ("vuln_solution",    _terms_bar, ("SOC Vuln - Remediation posture", "data.solution_type", 10, "solution type")),
    ("vuln_timeline",    _timeline, ("SOC Vuln - Alert timeline by tier", "rule.level")),
]


def build_objects():
    objs = []
    for spec in PANELS:
        vid, fn, args = spec
        objs.append(fn(vid, *args))
    return objs


def build_dashboard(dash_id, title, panel_ids):
    # grid: 2 columns of 24 units; KPI small, others larger
    layout = []
    x, y, i = 0, 0, 0
    sizes = {
        "vuln_kpi_total": (12, 8),
        "vuln_sev_tier": (12, 8),
        "vuln_threat": (24, 8),
        "vuln_top_hosts": (24, 12),
        "vuln_top_findings": (24, 12),
        "vuln_top_cves": (24, 12),
        "vuln_by_scan": (24, 10),
        "vuln_solution": (24, 10),
        "vuln_timeline": (48, 10),
    }
    # OpenSearch Dashboards uses a 48-column responsive grid. Every row MUST sum to
    # 48 columns or the remaining width renders as empty space (looks like the panels
    # don't fit the window). Each row is (pid, width) pairs whose widths total 48.
    GRID_W = 48
    rows = [
        [("vuln_kpi_total", 12), ("vuln_sev_tier", 12), ("vuln_threat", 24)],  # -> 48
        [("vuln_top_hosts", 24), ("vuln_top_findings", 24)],                   # -> 48
        [("vuln_top_cves", 24), ("vuln_by_scan", 24)],                         # -> 48
        [("vuln_solution", 48)],                                               # -> 48
        [("vuln_timeline", 48)],                                               # -> 48
    ]
    panels_json, refs = [], []
    cur_y = 0
    n = 0
    for group in rows:
        assert sum(w for _, w in group) == GRID_W, f"row does not fill 48 cols: {group}"
        cur_x = 0
        max_h = 0
        for pid, w in group:
            h = sizes[pid][1]
            pref = f"panel_{n}"
            panels_json.append({
                "version": "2.13.0",
                "gridData": {"x": cur_x, "y": cur_y, "w": w, "h": h, "i": str(n)},
                "panelIndex": str(n),
                "embeddableConfig": {},
                "panelRefName": pref,
            })
            refs.append({"name": pref, "type": "visualization", "id": pid})
            cur_x += w
            max_h = max(max_h, h)
            n += 1
        cur_y += max_h
    dash = {
        "id": dash_id,
        "type": "dashboard",
        "attributes": {
            "title": title,
            "hits": 0,
            "description": "Greenbone vulnerability posture over wazuh-alerts-* (rule.groups: greenbone). "
                           "Built by scripts/wazuh_dashboard_gen.py.",
            "panelsJSON": json.dumps(panels_json),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-90d",
            "refreshInterval": {"pause": True, "value": 0},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "rule.groups: greenbone", "language": "kuery"},
                    "filter": []})
            },
        },
        "references": refs,
    }
    return dash


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index-pattern-id", required=True,
                    help="saved-object id of the wazuh-alerts-* index pattern")
    ap.add_argument("--out", required=True)
    ap.add_argument("--dashboard-id", default="soc-pipeline-vuln-greenbone")
    ap.add_argument("--title", default="SOC Pipeline - Vulnerability (Greenbone)")
    args = ap.parse_args()

    objs = build_objects()
    # inject the real index-pattern id
    for o in objs:
        for r in o["references"]:
            if r["type"] == "index-pattern":
                r["id"] = args.index_pattern_id
    dash = build_dashboard(args.dashboard_id, args.title, [o["id"] for o in objs])

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for o in objs + [dash]:
            f.write(json.dumps(o) + "\n")
    print(f"wrote {args.out} ({len(objs)} visualizations + 1 dashboard)")
    print("import with: POST /api/saved_objects/_import?overwrite=true "
          "(multipart file=@<ndjson>, header osd-xsrf: true)")


if __name__ == "__main__":
    main()
