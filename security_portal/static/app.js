const stateOrder = ["degraded", "unavailable", "unauthorized", "stale", "unknown", "healthy", "planned"];
let latest = null;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = String(text);
  if (className) element.className = className;
  return element;
}

function metric(label, value, state) {
  const item = node("article", undefined, "kpi");
  if (state) item.dataset.state = state;
  item.append(node("span", label), node("strong", value));
  return item;
}

function liveIntegration(integrations) {
  return integrations.find(item => (item.analytics || {}).security_activity) ||
    integrations.find(item => Number.isFinite((item.summary || {}).active_hosts)) || {};
}

function renderOverview(data, integrations) {
  const siem = liveIntegration(integrations);
  const activeHosts = (siem.summary || {}).active_hosts;
  const root = document.getElementById("overview");
  root.replaceChildren(
    metric("Overall state", data.state, data.state),
    metric("Active hosts", Number.isFinite(activeHosts) ? activeHosts : "Unavailable", Number.isFinite(activeHosts) ? "healthy" : "unknown"),
    metric("Needs attention", data.nonhealthy_count, data.nonhealthy_count ? "degraded" : "healthy"),
    metric("Critical alerts", data.critical_alerts, data.critical_alerts ? "degraded" : "healthy")
  );
}

const SVG_NS = "http://www.w3.org/2000/svg";

function svgNode(tag, attributes = {}) {
  const element = document.createElementNS(SVG_NS, tag);
  Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
  return element;
}

function project(lat, lon, width = 960, height = 480) {
  return [((lon + 180) / 360) * width, ((90 - lat) / 180) * height];
}

function renderThreatMap(points) {
  const root = document.getElementById("threat-map");
  root.replaceChildren();
  root.append(svgNode("rect", {x: 0, y: 0, width: 960, height: 480, class: "map-ocean"}));
  for (let lon = -120; lon <= 120; lon += 60) {
    const [x] = project(0, lon);
    root.append(svgNode("line", {x1: x, y1: 0, x2: x, y2: 480, class: "map-grid"}));
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const [, y] = project(lat, 0);
    root.append(svgNode("line", {x1: 0, y1: y, x2: 960, y2: y, class: "map-grid"}));
  }
  const continents = [
    [[-168,72],[-52,72],[-58,48],[-82,25],[-100,8],[-130,24],[-168,55]],
    [[-82,13],[-35,10],[-50,-55],[-72,-52],[-80,-8]],
    [[-12,72],[45,72],[38,36],[15,33],[-10,36]],
    [[-18,35],[52,35],[43,-35],[15,-35],[-15,5]],
    [[38,72],[180,68],[145,8],[100,5],[72,24],[42,35]],
    [[112,-10],[154,-12],[150,-44],[115,-38]],
    [[-180,-64],[180,-64],[180,-85],[-180,-85]],
  ];
  continents.forEach(shape => {
    const coordinates = shape.map(([lon, lat]) => project(lat, lon).join(",")).join(" ");
    root.append(svgNode("polygon", {points: coordinates, class: "continent"}));
  });
  const max = Math.max(1, ...points.map(item => Number(item.count) || 0));
  points.forEach(item => {
    const lat = Number(item.lat);
    const lon = Number(item.lon);
    const count = Number(item.count) || 0;
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return;
    const [cx, cy] = project(Math.max(-90, Math.min(90, lat)), Math.max(-180, Math.min(180, lon)));
    const circle = svgNode("circle", {cx, cy, r: 3 + 16 * Math.sqrt(count / max), class: "threat-point"});
    const title = svgNode("title");
    title.textContent = `${count.toLocaleString()} events near ${lat.toFixed(1)}, ${lon.toFixed(1)}`;
    circle.append(title);
    root.append(circle);
  });
  if (!points.length) {
    const empty = svgNode("text", {x: 480, y: 245, class: "empty-label", "text-anchor": "middle"});
    empty.textContent = "No geo-located threat activity in this window";
    root.append(empty);
  }
}

function renderEventChart(timeline) {
  const root = document.getElementById("event-chart");
  root.replaceChildren();
  const left = 54, top = 24, width = 638, height = 238;
  const counts = timeline.map(item => Number(item.count) || 0);
  const max = Math.max(1, ...counts);
  for (let step = 0; step <= 4; step += 1) {
    const y = top + height * step / 4;
    root.append(svgNode("line", {x1: left, y1: y, x2: left + width, y2: y, class: "chart-grid"}));
    const label = svgNode("text", {x: left - 10, y: y + 4, class: "chart-label", "text-anchor": "end"});
    label.textContent = Math.round(max * (1 - step / 4)).toLocaleString();
    root.append(label);
  }
  if (!timeline.length) {
    const empty = svgNode("text", {x: 360, y: 160, class: "empty-label", "text-anchor": "middle"});
    empty.textContent = "Timeline unavailable";
    root.append(empty);
    return;
  }
  const coordinates = timeline.map((item, index) => {
    const x = left + width * index / Math.max(1, timeline.length - 1);
    const y = top + height * (1 - (Number(item.count) || 0) / max);
    return [x, y];
  });
  const area = `${left},${top + height} ${coordinates.map(point => point.join(",")).join(" ")} ${left + width},${top + height}`;
  root.append(svgNode("polygon", {points: area, class: "chart-area"}));
  root.append(svgNode("polyline", {points: coordinates.map(point => point.join(",")).join(" "), class: "chart-line"}));
  [0, Math.floor((timeline.length - 1) / 2), timeline.length - 1].forEach(index => {
    const label = svgNode("text", {x: coordinates[index][0], y: 292, class: "chart-label", "text-anchor": index === 0 ? "start" : index === timeline.length - 1 ? "end" : "middle"});
    label.textContent = new Date(timeline[index].at).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
    root.append(label);
  });
}

function renderRankList(id, items) {
  const root = document.getElementById(id);
  const max = Math.max(1, ...items.map(item => Number(item.count) || 0));
  root.replaceChildren(...items.slice(0, 8).map(item => {
    const row = node("div", undefined, "rank-row");
    const label = node("span", item.key);
    const bar = node("i", undefined, "rank-bar");
    bar.style.setProperty("--width", `${Math.max(2, (Number(item.count) || 0) / max * 100)}%`);
    row.append(label, bar, node("strong", Number(item.count || 0).toLocaleString()));
    return row;
  }));
  if (!items.length) root.append(node("p", "No activity", "empty-text"));
}

function renderSecurityActivity(integrations) {
  const siem = liveIntegration(integrations);
  const activity = ((siem.analytics || {}).security_activity) || null;
  const status = document.getElementById("activity-status");
  if (!activity) {
    status.textContent = "Telemetry unavailable";
    status.dataset.state = "unknown";
    document.getElementById("activity-kpis").replaceChildren(metric("Telemetry", "Unavailable", "unknown"));
    renderThreatMap([]);
    renderEventChart([]);
    ["top-countries", "top-sources", "detection-lanes"].forEach(id => renderRankList(id, []));
    return;
  }
  status.textContent = siem.freshness === "fresh" ? "Live aggregate feed" : `${siem.freshness} aggregate feed`;
  status.dataset.state = siem.freshness === "fresh" ? "healthy" : "degraded";
  document.getElementById("activity-kpis").replaceChildren(
    metric("Threat events", Number(activity.event_count || 0).toLocaleString()),
    metric("Distinct sources", Number(activity.distinct_sources || 0).toLocaleString()),
    metric("Source countries", Number(activity.country_count || 0).toLocaleString()),
    metric("Map clusters", (activity.map_points || []).length)
  );
  renderThreatMap(activity.map_points || []);
  renderEventChart(activity.timeline || []);
  renderRankList("top-countries", activity.top_countries || []);
  renderRankList("top-sources", activity.top_sources || []);
  renderRankList("detection-lanes", activity.lanes || []);
}

function renderIntegrations(items) {
  const selected = document.getElementById("category").value;
  const root = document.getElementById("integrations");
  const filtered = items.filter(item => selected === "all" || item.category === selected);
  filtered.sort((a, b) => stateOrder.indexOf(a.state) - stateOrder.indexOf(b.state) || a.name.localeCompare(b.name));
  root.replaceChildren(...filtered.map(item => {
    const card = node("article", undefined, "card");
    card.dataset.state = item.state;
    const top = node("div", undefined, "card-top");
    const names = node("div");
    names.append(node("p", item.category, "eyebrow"), node("h3", item.name));
    top.append(names, node("span", item.state, "badge"));
    card.append(top);
    const facts = node("dl");
    facts.append(node("dt", "Freshness"), node("dd", item.freshness));
    facts.append(node("dt", "Age"), node("dd", item.age_seconds === null ? "Unknown" : `${item.age_seconds}s`));
    Object.entries(item.summary || {}).forEach(([key, value]) => {
      facts.append(node("dt", key.replaceAll("_", " ")), node("dd", typeof value === "object" ? JSON.stringify(value) : value));
    });
    card.append(facts);
    if (item.reason_code) card.append(node("p", `Reason: ${item.reason_code}`, "reason"));
    if (item.deep_link) {
      const link = node("a", "Open native console");
      link.href = item.deep_link;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      card.append(link);
    }
    return card;
  }));
}

function configureCategories(items) {
  const select = document.getElementById("category");
  if (select.options.length > 1) return;
  [...new Set(items.map(item => item.category))].sort().forEach(category => {
    const option = node("option", category);
    option.value = category;
    select.append(option);
  });
}

async function refresh() {
  try {
    const response = await fetch("/api/v1/overview", {headers: {"Accept": "application/json"}, cache: "no-store"});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    latest = await response.json();
    document.getElementById("title").textContent = latest.portal.title;
    document.getElementById("classification").textContent = latest.portal.classification;
    document.getElementById("updated").textContent = new Date(latest.overview.generated_at).toLocaleString();
    configureCategories(latest.integrations);
    renderOverview(latest.overview, latest.integrations);
    renderSecurityActivity(latest.integrations);
    renderIntegrations(latest.integrations);
    window.setTimeout(refresh, latest.portal.refresh_seconds * 1000);
  } catch (error) {
    document.getElementById("updated").textContent = "Refresh failed";
    window.setTimeout(refresh, 30000);
  }
}

document.getElementById("category").addEventListener("change", () => latest && renderIntegrations(latest.integrations));
refresh();
