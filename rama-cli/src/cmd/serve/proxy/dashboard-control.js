// Shared traffic policy lives in the proxy. Local drafts never apply themselves.
const inlineEditor = document.getElementById("intercept-editor");
const $ = (id) => document.getElementById(id) || inlineEditor.querySelector(`#${id}`);
const session = document.body.dataset.inspectorSession;
let current, editing, ruleIndex = -1, ruleResponse, responseTarget;
let loading = false, reload = false, scopeDirty = false, limitsDirty = false;
let revision = 0, controlTab = null, approvalOnly = false, editSequence = 0;
const actions = new Map();
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
const binaryHeaderPrefix = "rama-capture-base64:";
function formatHeaders(headers, patterns = false) {
  return headers.map(([name, value]) => {
    if (Array.isArray(value)) value = binaryHeaderPrefix + btoa(value.map((byte) => String.fromCharCode(byte)).join(""));
    else if (!patterns && value.startsWith(binaryHeaderPrefix)) value = binaryHeaderPrefix + btoa(Array.from(new TextEncoder().encode(value), (byte) => String.fromCharCode(byte)).join(""));
    return `${name}: ${value}`;
  }).join("\n");
}
function readHeaders(text, patterns = false) {
  return text.split(/\r?\n/u).filter((line) => line.trim()).map((line) => {
    const colon = line.indexOf(":");
    if (colon <= 0) throw new Error("Each header needs a name followed by a colon.");
    let value = line.slice(colon + 1).trim();
    if (!patterns && value.startsWith(binaryHeaderPrefix)) value = Array.from(atob(value.slice(binaryHeaderPrefix.length)), (character) => character.charCodeAt(0));
    return [line.slice(0, colon).trim(), value];
  });
}
async function refresh() {
  if (loading) { reload = true; return; }
  loading = true;
  try {
    current = await api("/api/control");
    const c = current.control;
    $("intercept-enabled").checked = c.config.enabled;
    $("intercept-enabled").disabled = !c.recording;
    $("intercept-enabled").title = c.recording ? "" : "Resume the inspector to enable interception";
    if (!limitsDirty) {
      $("queue-limit").value = c.config.queue_limit;
      $("approval-timeout").value = c.config.timeout_seconds;
    }
    if (!scopeDirty) {
      $("mitm-mode").value = current.scope.mode;
      $("mitm-allow").value = current.scope.allow.join("\n");
      $("mitm-deny").value = current.scope.deny.join("\n");
    }
    renderControlPanes(); renderApprovals(); renderRules(); renderHosts();
    if (editing && !c.pending.some((m) => m.id === editing.id)) closeEditor();
    mountEditor();
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
function renderControlPanes() {
  for (const name of ["rules", "hosts"]) $(`control-${name}`).hidden = name !== controlTab;
}
function selectedIds() {
  const ids = new Set([...document.querySelectorAll("[data-pending-select]:checked")].map((e) => Number(e.value)));
  for (const row of document.querySelectorAll(".exchange[data-approval-id]")) {
    if (row.querySelector(".select.selected")) {
      row.querySelectorAll("[data-pending-id]").forEach((item) => ids.add(Number(item.dataset.pendingId)));
    }
  }
  return [...ids].filter((id) => current?.control.pending.some((message) => message.id === id));
}
function renderApprovalView() {
  const live = $("live");
  if (!live) return;
  live.classList.toggle("approvals-only", approvalOnly);
  const filter = $("approval-filter");
  if (filter) filter.setAttribute("aria-pressed", String(approvalOnly));
  if ($("approval-view-note")) $("approval-view-note").hidden = !approvalOnly;
  const ranks = new Map((current?.control.pending || []).map((message, index) => [message.id, index]));
  live.querySelectorAll(".exchange[data-approval-id]").forEach((row) => {
    row.style.setProperty("--approval-order", ranks.get(Number(row.dataset.approvalId)) ?? 0);
  });
  live.querySelectorAll("[data-request-empty]").forEach((empty) => {
    const list = empty.previousElementSibling;
    empty.hidden = !!list?.querySelector(approvalOnly ? ".exchange[data-approval-id]" : ".exchange");
    empty.textContent = approvalOnly ? "No messages awaiting approval." : "Waiting for matching traffic.";
  });
}
function renderApprovals() {
  const toolbar = $("approval-toolbar");
  if (!toolbar || !current) return;
  const c = current.control, active = c.config.enabled || c.pending.length > 0;
  toolbar.hidden = !active && !approvalOnly && !c.automatic_connections.length;
  $("approval-filter").textContent = `Awaiting approval (${c.pending.length})`;
  $("approval-actions").hidden = !active;
  $("forward-all").textContent = c.config.enabled ? "Forward all and turn off" : "Forward all";
  const selected = selectedIds().length;
  for (const button of toolbar.querySelectorAll("[data-bulk]")) {
    button.disabled = !selected;
    button.textContent = `${button.dataset.bulk === "forward" ? "Forward" : "Block"} selected (${selected})`;
  }
  const connections = $("automatic-connections"); connections.replaceChildren();
  for (const connection of c.automatic_connections) connections.append(button(`${connectionLabel(connection)} · Resume interception`, async () => { await api(`/api/control/resume/${connection.connection}`, {}); await refresh(); }));
  renderApprovalView();
}
function closeEditor() {
  editSequence += 1;
  editing = undefined;
  inlineEditor.hidden = true;
  $("intercept-editor-home").append(inlineEditor);
}
function mountEditor() {
  if (!editing) return;
  const slot = $(`approval-slot-${editing.id}`);
  const parent = slot || $("intercept-editor-home");
  if (inlineEditor.parentElement !== parent) parent.append(inlineEditor);
}
async function editMessage(id) {
  const sequence = ++editSequence;
  const message = await api(`/api/control/pending/${id}`);
  if (sequence !== editSequence) return;
  // Reopening the current message must preserve the user's draft.
  if (editing?.id === id) { mountEditor(); return; }
  editing = message;
  const m = editing, http = m.kind == null;
  $("intercept-title").textContent = `Edit ${m.direction} · approval #${id}`;
  $("intercept-description").textContent = `${m.method} ${m.url} · ${connectionLabel(m)}${m.binary ? " · Binary payload uses base64" : ""}`;
  $("http-edit-fields").hidden = !http; $("ws-edit-fields").hidden = http;
  $("intercept-headers").value = formatHeaders(m.headers);
  $("intercept-status").value = m.status || "";
  $("intercept-status").closest("label").hidden = m.kind != null || m.direction !== "egress";
  $("intercept-payload").value = m.payload || "";
  $("block-message").textContent = http ? "Block" : "Drop message";
  $("respond-message").hidden = !http; $("close-websocket").hidden = http;
  $("intercept-error").textContent = "";
  for (const id of ["forward-message", "forward-connection", "block-message", "respond-message", "close-websocket"]) $(id).disabled = false;
  inlineEditor.hidden = false;
  mountEditor();
  inlineEditor.scrollIntoView({ block: "nearest" });
  (http ? $("intercept-headers") : $("intercept-payload")).focus({ preventScroll: true });
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
  $("rule-headers").value = formatHeaders(rule.matcher.headers || [], true); $("rule-action").value = rule.action;
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
    const summary = Object.entries(rule.matcher).filter(([,v]) => Array.isArray(v) ? v.length : v).map(([k,v]) => `${k}: ${Array.isArray(v) ? formatHeaders(v, true) : v}`).join(" · ") || "All traffic";
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
function on(id, action, target) { actions.set(id, () => run(action, target)); }
on("intercept-enabled", async () => { const config = structuredClone(current.control.config); config.enabled = $("intercept-enabled").checked; await configure(config); });
on("close-intercept", closeEditor);
on("approval-filter", () => { approvalOnly = $("live")?.classList.contains("focused") ? true : !approvalOnly; renderApprovals(); });
on("forward-all", async () => { await api("/api/control/forward-all", {}); await refresh(); });
function editedDecision(action = "forward") {
  const decision = { action };
  if (editing.kind == null) {
    if ($("intercept-headers").value !== formatHeaders(editing.headers)) decision.headers = readHeaders($("intercept-headers").value);
    if (editing.kind == null && editing.direction === "egress" && Number($("intercept-status").value) !== editing.status) decision.status = Number($("intercept-status").value);
  } else decision.payload = $("intercept-payload").value;
  return decision;
}
async function decideEditing(decision) {
  const id = editing.id;
  await decide([id], decision);
  if (editing?.id === id) closeEditor();
}
on("forward-message", () => decideEditing(editedDecision()), "intercept-error");
on("forward-connection", () => decideEditing(editedDecision("connection")), "intercept-error");
on("block-message", () => decideEditing({ action: editing.kind == null ? "block" : "drop" }), "intercept-error");
on("close-websocket", async () => {
  const reason = window.prompt("Close reason", "Closed by Rama proxy"); if (reason === null) return;
  const code = window.prompt("WebSocket close code", "1008"); if (code === null) return;
  await decideEditing({ action: "close", code: Number(code), reason });
}, "intercept-error");
on("respond-message", () => { const id = editing.id; responseEditor(current.control.config.default_response, async (response) => { await decide([id], { action: "respond", response }); if (editing?.id === id) closeEditor(); }); });
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
  matcher.status = $("rule-status").value ? Number($("rule-status").value) : null; matcher.headers = readHeaders($("rule-headers").value, true);
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
  const action = actions.get(event.target.closest("button[id], input[id]")?.id);
  if (action) { action(); return; }
  const edit = event.target.closest("[data-edit-approval]");
  if (edit) { void run(() => editMessage(Number(edit.dataset.editApproval))); return; }
  const tab = event.target.closest("[data-control-tab]");
  if (tab) {
    controlTab = controlTab === tab.dataset.controlTab ? null : tab.dataset.controlTab;
    renderControlPanes();
    document.querySelectorAll("[data-control-tab]").forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.controlTab === controlTab)));
  }
  const bulk = event.target.closest("[data-bulk]"); if (bulk) void run(() => decide(selectedIds(), { action: bulk.dataset.bulk }));
  const create = event.target.closest("[data-create-traffic-rule]");
  if (create) void run(async () => { const message = await api(`/api/control/from/${create.dataset.createTrafficRule}`); editRule(-1, message); });
});
document.addEventListener("rama-edit-approval", (event) => { void run(() => editMessage(event.detail.id)); });
document.addEventListener("change", (event) => {
  if (event.target.matches("[data-pending-select]")) renderApprovals();
});
let lastHeartbeat;
new MutationObserver(() => {
  const heartbeat = $("live-heartbeat");
  const sequence = heartbeat?.dataset.sequence;
  if (sequence !== lastHeartbeat) { lastHeartbeat = sequence; renderApprovalView(); mountEditor(); scheduleRefresh(); }
}).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["data-sequence"] });
void run(refresh);
