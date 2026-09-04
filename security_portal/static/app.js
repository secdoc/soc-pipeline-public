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

function renderOverview(data) {
  const root = document.getElementById("overview");
  root.replaceChildren(
    metric("Overall state", data.state, data.state),
    metric("Integrations", data.integration_count),
    metric("Needs attention", data.nonhealthy_count, data.nonhealthy_count ? "degraded" : "healthy"),
    metric("Critical alerts", data.critical_alerts, data.critical_alerts ? "degraded" : "healthy")
  );
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
    renderOverview(latest.overview);
    renderIntegrations(latest.integrations);
    window.setTimeout(refresh, latest.portal.refresh_seconds * 1000);
  } catch (error) {
    document.getElementById("updated").textContent = "Refresh failed";
    window.setTimeout(refresh, 30000);
  }
}

document.getElementById("category").addEventListener("change", () => latest && renderIntegrations(latest.integrations));
refresh();
