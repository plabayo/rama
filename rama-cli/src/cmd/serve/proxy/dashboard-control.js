// Shared traffic policy lives in the proxy. Local drafts never apply themselves.
const $ = (id) => document.getElementById(id);
const session = document.body.dataset.inspectorSession;
let current, editing, ruleIndex = -1, ruleResponse, responseTarget;
let loading = false, reload = false, scopeDirty = false, limitsDirty = false;
let revision = 0;
const presets = [
  ["Block access", { status: 403, headers: [["content-type", "text/plain; charset=utf-8"], ["cache-control", "no-store"]], body: "Blocked by Rama proxy.\n" }],
  ["Redirect (preserve method)", { status: 307, headers: [["location", ""], ["cache-control", "no-store"]], body: "" }],
  ["Redirect to a retrieval request", { status: 303, headers: [["location", ""], ["cache-control", "no-store"]], body: "" }],
  ["Cached content unchanged", { status: 304, headers: [], body: "" }],
  ["Success without content", { status: 204, headers: [], body: "" }],
  ["Resource missing", { status: 404, headers: [["cache-control", "no-store"]], body: "Not found.\n" }],
  ["Rate limited", { status: 429, headers: [["retry-after", "60"], ["cache-control", "no-store"]], body: "Too many requests.\n" }],
  ["Temporary outage", { status: 503, headers: [["retry-after", "60"], ["cache-control", "no-store"]], body: "Temporarily unavailable.\n" }],
  ["Mock JSON", { status: 200, headers: [["content-type", "application/json"], ["cache-control", "no-store"]], body: "{}" }],
  ["Start from scratch", { status: 200, headers: [], body: "" }],
];

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}
function button(text, action) {
  const element = node("button", text, "ghost compact");
  element.type = "button";
  element.addEventListener("click", () => run(action));
  return element;
}
function connectionLabel(message) { return message.connection_display_id ? `Connection #${message.connection_display_id}` : `Unrecorded connection (ID ${message.connection})`; }
function errorText(error) { return error?.message || String(error); }
async function run(action, target = "control-status") {
  try { $(target).textContent = ""; await action(); }
  catch (error) { $(target).textContent = errorText(error); }
}
async function api(path, body) {
  const response = await fetch(path + (body === undefined ? `${path.includes("?") ? "&" : "?"}session=${encodeURIComponent(session)}` : ""), {
    method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store",
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify({ session, ...body }),
  });
  if (!response.ok) throw new Error((await response.text()).trim() || `HTTP ${response.status}`);
  return response.status === 204 ? null : response.json();
}
function formatHeaders(headers) { return headers.map(([name, value]) => `${name}: ${value}`).join("\n"); }
function readHeaders(text) {
  return text.split(/\r?\n/u).filter((line) => line.trim()).map((line) => {
    const colon = line.indexOf(":");
    if (colon <= 0) throw new Error("Each header needs a name followed by a colon.");
    return [line.slice(0, colon).trim(), line.slice(colon + 1).trim()];
  });
}
async function refresh() {
  if (loading) { reload = true; return; }
  loading = true;
  try {
    current = await api("/api/control");
    const c = current.control;
    $("intercept-enabled").checked = c.config.enabled;
    $("pending-count").textContent = c.pending.length;
    if (!limitsDirty) {
      $("queue-limit").value = c.config.queue_limit;
      $("approval-timeout").value = c.config.timeout_seconds;
    }
    if (!scopeDirty) {
      $("mitm-mode").value = current.scope.mode;
      $("mitm-allow").value = current.scope.allow.join("\n");
      $("mitm-deny").value = current.scope.deny.join("\n");
    }
    renderPending(); renderRules(); renderHosts();
    const connections = $("automatic-connections"); connections.replaceChildren();
    for (const connection of c.automatic_connections) connections.append(button(`${connectionLabel(connection)} · Resume interception`, async () => { await api(`/api/control/resume/${connection.connection}`, {}); await refresh(); }));
    if (editing && !c.pending.some((m) => m.id === editing.id)) {
      $("intercept-error").textContent = "This message has been resolved or its connection ended.";
      for (const id of ["forward-message", "forward-connection", "block-message", "respond-message", "close-websocket"]) $(id).disabled = true;
    }
  } finally { loading = false; if (reload) { reload = false; scheduleRefresh(); } }
}
let refreshTimer;
function scheduleRefresh() {
  if (refreshTimer) return;
  refreshTimer = setTimeout(() => { refreshTimer = null; void run(refresh); }, 300);
}
async function configure(config, applyRule) {
  await api("/api/control/config", { revision: current.control.revision, config, apply_rule: applyRule });
  await refresh();
}
async function decide(ids, decision) {
  const results = await api("/api/control/decision", { ids, decision });
  await refresh();
  const errors = results.filter((r) => r.error);
  if (errors.length) throw new Error(errors.map((r) => `#${r.id}: ${r.error}`).join("; "));
}
function selectedIds() { return [...document.querySelectorAll("[data-pending-select]:checked")].map((e) => Number(e.value)); }
function renderPending() {
  const selected = new Set(selectedIds());
  const list = $("pending-list"); list.replaceChildren();
  if (!current.control.pending.length) list.append(node("p", "No messages awaiting approval."));
  for (const m of current.control.pending) {
    const row = node("div", undefined, "control-row");
    const check = node("input"); check.type = "checkbox"; check.value = m.id; check.dataset.pendingSelect = ""; check.checked = selected.has(m.id); check.setAttribute("aria-label", `Select message ${m.id}`);
    const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(m.queued_at)) / 1000));
    const detail = node("div"), open = button(`#${m.id} · ${m.protocol} · ${m.direction} · ${m.method} ${m.url}`, () => editMessage(m.id));
    open.className = "control-primary";
    detail.append(open, node("span", `Awaiting approval · ${seconds}s · ${connectionLabel(m)}`, "control-meta"));
    row.append(check, detail);
    list.append(row);
  }
  document.querySelectorAll(".approval-badge").forEach((n) => n.remove());
  for (const m of current.control.pending) {
    if (!m.exchange) continue;
    const row = document.querySelector(`.exchange[data-focus-id="${m.exchange}"]`);
    if (row) row.append(node("span", `Awaiting ${m.direction} approval`, "approval-badge"));
  }
}
async function editMessage(id) {
  editing = await api(`/api/control/pending/${id}`);
  const m = editing, http = ["request", "response"].includes(m.direction);
  $("intercept-title").textContent = `#${id} · ${m.protocol} · ${m.direction}`;
  $("intercept-description").textContent = `${m.method} ${m.url} · ${connectionLabel(m)}${m.binary ? " · Binary payload uses base64" : ""}`;
  $("http-edit-fields").hidden = !http; $("ws-edit-fields").hidden = http;
  $("intercept-headers").value = formatHeaders(m.headers);
  $("intercept-status").value = m.status || ""; $("intercept-status").disabled = m.direction !== "response";
  $("intercept-payload").value = m.payload || "";
  $("block-message").textContent = http ? "Block" : "Drop message";
  $("respond-message").hidden = !http; $("close-websocket").hidden = http;
  $("intercept-error").textContent = "";
  for (const id of ["forward-message", "forward-connection", "block-message", "respond-message", "close-websocket"]) $(id).disabled = false;
  $("intercept-editor").showModal();
}
function readResponse() { return { status: Number($("response-status").value), headers: readHeaders($("response-headers").value), body: $("response-body").value }; }
function fillResponse(response) { $("response-status").value = response.status; $("response-headers").value = formatHeaders(response.headers); $("response-body").value = response.body; }
function responseEditor(response, target) {
  responseTarget = target;
  const select = $("response-preset"); select.replaceChildren(node("option", "Current response"));
  [...presets, ...current.control.config.presets.map((p) => [p.name, p.response])].forEach(([name], i) => { const option = node("option", name); option.value = String(i); select.append(option); });
  select.firstChild.value = "";
  fillResponse(response); $("response-error").textContent = ""; $("response-editor").showModal();
}
function editRule(index = -1, message) {
  ruleIndex = index; revision = current.control.revision;
  const rule = index >= 0 ? current.control.config.rules[index] : { name: message ? `Rule for ${message.host}` : "", matcher: message ? { host: message.host, path: message.path } : {}, action: "intercept" };
  $("rule-name").value = rule.name;
  for (const key of ["host", "path", "protocol", "direction", "method", "status", "port", "kind"]) $(`rule-${key}`).value = rule.matcher[key] || "";
  $("rule-headers").value = formatHeaders(rule.matcher.headers || []); $("rule-action").value = rule.action;
  ruleResponse = rule.response || current.control.config.default_response;
  $("apply-rule-pending").checked = false; $("rule-error").textContent = "";
  $("rule-editor").showModal();
}
function renderRules() {
  const list = $("rule-list"); list.replaceChildren();
  current.control.config.rules.forEach((rule, index) => {
    const row = node("div", undefined, "control-row");
    const enabled = node("input"); enabled.type = "checkbox"; enabled.checked = rule.enabled; enabled.setAttribute("aria-label", `Enable ${rule.name}`);
    enabled.addEventListener("change", () => run(async () => { const config = structuredClone(current.control.config); config.rules[index].enabled = enabled.checked; await configure(config); }));
    const summary = Object.entries(rule.matcher).filter(([,v]) => Array.isArray(v) ? v.length : v).map(([k,v]) => `${k}: ${Array.isArray(v) ? formatHeaders(v) : v}`).join(" · ") || "All traffic";
    row.classList.add("rule-row");
    const detail = node("div"), actions = node("div", undefined, "control-actions"), open = button(`${rule.name} · ${rule.action}`, () => editRule(index));
    open.className = "control-primary"; detail.append(open, node("span", summary, "control-meta"));
    row.append(enabled, detail, actions);
    for (const [label, offset] of [["↑", -1], ["↓", 1]]) {
      const move = button(label, async () => { const config = structuredClone(current.control.config); [config.rules[index], config.rules[index + offset]] = [config.rules[index + offset], config.rules[index]]; await configure(config); });
      move.disabled = index + offset < 0 || index + offset >= current.control.config.rules.length; actions.append(move);
    }
    actions.append(button("Remove", async () => { const config = structuredClone(current.control.config); config.rules.splice(index, 1); await configure(config); }));
    list.append(row);
  });
}
function renderHosts() {
  if (!current) return;
  const query = $("host-search").value.toLowerCase();
  const hosts = current.control.hosts.filter((h) => h.host.includes(query) && (!$("host-bypass").checked || h.bypassed));
  hosts.sort($("host-sort").value === "count" ? (a,b) => b.connections-a.connections || (Date.parse(b.last_seen) - Date.parse(a.last_seen)) : (a,b) => (Date.parse(b.last_seen) - Date.parse(a.last_seen)));
  $("host-recording").textContent = current.control.recording ? "Recording hosts and connection statistics." : "Recording paused · host counts and last-seen times are frozen.";
  const list = $("host-list"); list.replaceChildren();
  for (const h of hosts.slice(0, 100)) {
    const row = node("div", undefined, "control-row");
    const time = node("time", new Date(h.last_seen).toLocaleString()); time.dateTime = h.last_seen; time.title = h.last_seen;
    row.classList.add("host-row");
    const identity = node("div"), stats = node("div"), actions = node("div", undefined, "control-actions");
    identity.append(node("strong", h.host), node("span", h.eligible ? "MITM eligible" : "Outside MITM scope"), node("span", `${h.source} · ${h.reason}`, "control-meta"));
    stats.append(node("span", `${h.connections} connections · ${h.bypassed} uninspected`), time);
    row.append(identity, stats, actions);
    actions.append(button("Add to MITM scope", async () => {
      const scope = current.scope;
      await api("/api/mitm-policy", { mode: "selected", allow: [...new Set([...scope.allow, `=${h.host}`])], deny: scope.deny });
      scopeDirty = false; await refresh();
      $("control-status").textContent = "Host selected for new connections. CLI restrictions and exclusions still apply.";
    }));
    list.append(row);
  }
}
function on(id, action, target) { $(id).addEventListener("click", () => run(action, target)); }
on("intercept-enabled", async () => { const config = structuredClone(current.control.config); config.enabled = $("intercept-enabled").checked; await configure(config); });
on("forward-all", async () => { await api("/api/control/forward-all", {}); await refresh(); });
function editedDecision(action = "forward") {
  const decision = { action };
  if (["request", "response"].includes(editing.direction)) {
    if ($("intercept-headers").value !== formatHeaders(editing.headers)) decision.headers = readHeaders($("intercept-headers").value);
    if (editing.direction === "response" && Number($("intercept-status").value) !== editing.status) decision.status = Number($("intercept-status").value);
  } else decision.payload = $("intercept-payload").value;
  return decision;
}
on("forward-message", async () => { await decide([editing.id], editedDecision()); $("intercept-editor").close(); }, "intercept-error");
on("forward-connection", async () => { await decide([editing.id], editedDecision("connection")); $("intercept-editor").close(); }, "intercept-error");
on("block-message", async () => { await decide([editing.id], { action: ["request", "response"].includes(editing.direction) ? "block" : "drop" }); $("intercept-editor").close(); }, "intercept-error");
on("close-websocket", async () => {
  const reason = window.prompt("Close reason", "Closed by Rama proxy"); if (reason === null) return;
  const code = window.prompt("WebSocket close code", "1008"); if (code === null) return;
  await decide([editing.id], { action: "close", code: Number(code), reason }); $("intercept-editor").close();
}, "intercept-error");
on("respond-message", () => responseEditor(current.control.config.default_response, async (response) => { await decide([editing.id], { action: "respond", response }); $("intercept-editor").close(); }));
on("default-response", () => responseEditor(current.control.config.default_response, async (response) => { const config = structuredClone(current.control.config); config.default_response = response; await configure(config); }));
on("send-response", async () => { await responseTarget(readResponse()); $("response-editor").close(); }, "response-error");
on("save-response-preset", async () => { const name = window.prompt("Preset name"); if (!name?.trim()) return; const config = structuredClone(current.control.config); config.presets.push({ name: name.trim(), response: readResponse() }); await configure(config); }, "response-error");
$("response-preset").addEventListener("change", () => { const i = $("response-preset").value; if (i !== "") fillResponse([...presets.map(([,r]) => r), ...current.control.config.presets.map((p) => p.response)][Number(i)]); });
on("new-rule", () => editRule());
on("rule-from-message", () => editRule(-1, editing));
on("rule-response", () => responseEditor(ruleResponse, async (response) => { ruleResponse = response; }));
on("save-rule", async () => {
  if (revision !== current.control.revision) throw new Error("Settings changed while editing. Reopen the rule before saving.");
  const matcher = {}; for (const key of ["host", "path", "protocol", "direction", "method", "kind"]) matcher[key] = $(`rule-${key}`).value.trim();
  matcher.port = $("rule-port").value ? Number($("rule-port").value) : null;
  matcher.status = $("rule-status").value ? Number($("rule-status").value) : null; matcher.headers = readHeaders($("rule-headers").value);
  const previous = ruleIndex < 0 ? null : current.control.config.rules[ruleIndex];
  const rule = { name: $("rule-name").value.trim() || "Traffic rule", enabled: previous?.enabled ?? true, matcher, action: $("rule-action").value };
  if (rule.action === "respond") rule.response = ruleResponse;
  if (rule.action === "close") { rule.code = previous?.code ?? 1008; rule.reason = previous?.reason ?? "Closed by Rama proxy rule"; }
  const config = structuredClone(current.control.config), index = ruleIndex < 0 ? config.rules.length : ruleIndex;
  config.rules[index] = rule;
  await configure(config, $("apply-rule-pending").checked ? index : undefined); $("rule-editor").close();
}, "rule-error");
on("apply-control-limits", async () => { const config = structuredClone(current.control.config); config.queue_limit = Number($("queue-limit").value); config.timeout_seconds = Number($("approval-timeout").value); await configure(config); limitsDirty = false; });
on("clear-hosts", async () => { await api("/api/control/hosts/clear", {}); await refresh(); });
on("export-control", () => {
  const blob = new Blob([JSON.stringify({ config: current.control.config, scope: current.scope }, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob), link = node("a"); link.href = url; link.download = "rama-proxy-settings.json"; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$("import-control").addEventListener("change", () => run(async () => {
  const file = $("import-control").files[0]; if (!file) return;
  if (file.size > 1024 * 1024) throw new Error("Settings file exceeds 1 MiB.");
  const data = JSON.parse(await file.text());
  await configure(data.config);
  if (data.scope) await api("/api/mitm-policy", { mode: data.scope.mode, allow: data.scope.allow, deny: data.scope.deny });
  scopeDirty = false; await refresh();
}));
for (const id of ["host-search", "host-sort", "host-bypass"]) $(id).addEventListener("input", renderHosts);
for (const id of ["mitm-mode", "mitm-allow", "mitm-deny"]) $(id).addEventListener("input", () => { scopeDirty = true; });
for (const id of ["queue-limit", "approval-timeout"]) $(id).addEventListener("input", () => { limitsDirty = true; });
document.addEventListener("rama-control-refresh", () => { scopeDirty = false; scheduleRefresh(); });
document.addEventListener("click", (event) => {
  const tab = event.target.closest("[data-control-tab]");
  if (tab) {
    for (const name of ["pending", "rules", "hosts"]) $(`control-${name}`).hidden = name !== tab.dataset.controlTab;
    document.querySelectorAll("[data-control-tab]").forEach((button) => button.setAttribute("aria-pressed", String(button === tab)));
  }
  const bulk = event.target.closest("[data-bulk]"); if (bulk) void run(() => decide(selectedIds(), { action: bulk.dataset.bulk }));
  const create = event.target.closest("[data-create-traffic-rule]");
  if (create) void run(async () => { const message = await api(`/api/control/from/${create.dataset.createTrafficRule}`); editRule(-1, message); });
});
let lastHeartbeat;
new MutationObserver(() => {
  const heartbeat = $("live-heartbeat");
  const sequence = heartbeat?.dataset.sequence;
  if (sequence !== lastHeartbeat) { lastHeartbeat = sequence; scheduleRefresh(); }
}).observe(document.documentElement, { childList: true, subtree: true });
void run(refresh);
