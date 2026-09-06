const HEARTBEAT_STALE_AFTER_MS = 12000;
const HISTORY_STATE_KEY = "ramaInspectorFocus";

const status = document.getElementById("connection-status");
const label = status?.querySelector("[data-live-label]");
let lastSequence;
let lastHeartbeatNode;
let staleTimer;
let pendingScroll;
let connectionWindowPage;
let connectionWindowDirection;
let connectionPaging = false;
let connectionLastScrollTop = 0;
let connectionListNode;
let connectionRestoringScroll = false;
const connectionScrollByPage = new Map();

function focusFromLocation() {
  const query = new URLSearchParams(window.location.search);
  const request = query.get("request");
  if (request && /^\d+$/.test(request)) return { kind: "request", id: request };
  const connection = query.get("connection");
  if (connection && /^\d+$/.test(connection)) {
    return { kind: "connection", id: connection };
  }
  return { kind: "overview" };
}

function focusUrl(focus) {
  const url = new URL(window.location.href);
  url.searchParams.delete("request");
  url.searchParams.delete("connection");
  if (focus.kind === "request") url.searchParams.set("request", focus.id);
  if (focus.kind === "connection") url.searchParams.set("connection", focus.id);
  return `${url.pathname}${url.search}${url.hash}`;
}

async function applyFocus(focus) {
  const session = document.body.dataset.inspectorSession;
  if (!session) return;
  const path = focus.kind === "overview"
    ? "/api/focus/clear"
    : `/api/focus/${focus.kind}/${focus.id}`;
  const response = await fetch(path, {
    method: "POST",
    cache: "no-store",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ session }),
  });
  if (!response.ok) throw new Error(`focus returned HTTP ${response.status}`);
}

function syncFocus(focus) {
  void applyFocus(focus).catch(() => setStatus("offline", "disconnected"));
}

function rememberScroll() {
  history.replaceState(
    { ...history.state, inspectorScroll: { x: window.scrollX, y: window.scrollY } },
    "",
  );
}

function queueScroll(point = { x: 0, y: 0 }) {
  pendingScroll = point;
  window.scrollTo(point.x, point.y);
}

function restorePendingScroll() {
  if (!pendingScroll) return;
  const point = pendingScroll;
  pendingScroll = undefined;
  requestAnimationFrame(() => window.scrollTo(point.x, point.y));
}

function navigateToFocus(focus) {
  const current = history.state?.[HISTORY_STATE_KEY];
  if (current?.kind === focus.kind && current?.id === focus.id) return;
  rememberScroll();
  history.pushState(
    {
      [HISTORY_STATE_KEY]: focus,
      inspectorNavigation: true,
      inspectorScroll: { x: 0, y: 0 },
    },
    "",
    focusUrl(focus),
  );
  queueScroll();
  syncFocus(focus);
}

function activateFocusControl(control) {
  if (control.dataset.approvalId) {
    document.dispatchEvent(new CustomEvent("rama-edit-approval", { detail: { id: Number(control.dataset.approvalId) } }));
    return;
  }
  const kind = control.dataset.inspectorFocus;
  const id = control.dataset.focusId;
  if (kind === "overview") {
    navigateToFocus({ kind: "overview" });
    return;
  }
  if (!id || !["connection", "request"].includes(kind)) return;
  navigateToFocus({ kind, id });
}

function setStatus(state, text) {
  if (!status || !label) return;
  status.classList.remove("is-connecting", "is-live", "is-offline");
  status.classList.add(`is-${state}`);
  label.textContent = text;
}

function armStaleTimer() {
  clearTimeout(staleTimer);
  if (document.visibilityState === "hidden") return;
  staleTimer = setTimeout(() => {
    setStatus("offline", "disconnected");
  }, HEARTBEAT_STALE_AFTER_MS);
}

function readHeartbeat() {
  const heartbeat = document.getElementById("live-heartbeat");
  const sequence = heartbeat?.dataset.sequence;
  if (sequence === undefined || sequence === "") return;
  if (heartbeat === lastHeartbeatNode && sequence === lastSequence) return;
  lastHeartbeatNode = heartbeat;
  lastSequence = sequence;
  setStatus("live", "live");
  armStaleTimer();
  restorePendingScroll();
  syncConnectionWindow();
}

function syncConnectionWindow() {
  const connections = document.querySelector(".connections[data-connection-page]");
  if (!connections) return;
  const page = Number(connections.dataset.connectionPage);
  if (!Number.isFinite(page)) return;
  const nodeChanged = connections !== connectionListNode;
  const pageChanged = connectionWindowPage !== undefined && page !== connectionWindowPage;
  const restoreDirection = connectionWindowDirection;
  if (nodeChanged) {
    connections.addEventListener("scroll", handleConnectionScroll, { passive: true });
    requestAnimationFrame(() => {
      connectionRestoringScroll = true;
      if (pageChanged && restoreDirection === "newer") {
        connections.scrollTop = Math.max(0, connections.scrollHeight - connections.clientHeight - 24);
      } else if (pageChanged) {
        connections.scrollTop = Math.min(24, connections.scrollHeight);
      } else {
        connections.scrollTop = connectionScrollByPage.get(page) ?? 0;
      }
      connectionLastScrollTop = connections.scrollTop;
      requestAnimationFrame(() => {
        connectionRestoringScroll = false;
      });
    });
  }
  connectionListNode = connections;
  connectionWindowPage = page;
  if (pageChanged) {
    connectionWindowDirection = undefined;
    connectionPaging = false;
  }
}

function handleConnectionScroll(event) {
  const connections = event.target;
  if (!(connections instanceof Element) || !connections.matches(".connections")) return;
  const current = connections.scrollTop;
  const page = Number(connections.dataset.connectionPage);
  if (Number.isFinite(page)) connectionScrollByPage.set(page, current);
  if (connectionRestoringScroll) {
    connectionLastScrollTop = current;
    return;
  }
  const scrollingDown = current >= connectionLastScrollTop;
  connectionLastScrollTop = current;
  maybePageConnections(connections, scrollingDown);
}

function maybePageConnections(connections, scrollingDown) {
  if (connectionPaging) return;
  const nearBottom = connections.scrollTop + connections.clientHeight >= connections.scrollHeight - 48;
  const nearTop = connections.scrollTop <= 8;
  const direction = scrollingDown && nearBottom && connections.dataset.hasOlder === "true"
    ? "older"
    : !scrollingDown && nearTop && connections.dataset.hasNewer === "true"
      ? "newer"
      : undefined;
  if (!direction) return;
  const button = connections.querySelector(`[data-connection-page-action="${direction}"]`);
  if (!button || button.disabled) return;
  connectionPaging = true;
  connectionWindowDirection = direction;
  button.click();
  setTimeout(() => {
    connectionPaging = false;
  }, 5000);
}

document.addEventListener("wheel", (event) => {
  const connections = event.target.closest?.(".connections");
  if (!connections || event.deltaY === 0) return;
  requestAnimationFrame(() => maybePageConnections(connections, event.deltaY > 0));
}, { passive: true });

new MutationObserver(readHeartbeat).observe(document.documentElement, {
  attributes: true,
  attributeFilter: ["data-sequence"],
  childList: true,
  subtree: true,
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") {
    clearTimeout(staleTimer);
  } else {
    setStatus("connecting", "reconnecting…");
    armStaleTimer();
  }
});

window.addEventListener("offline", () => setStatus("offline", "disconnected"));
window.addEventListener("online", () => {
  setStatus("connecting", "reconnecting…");
  armStaleTimer();
});

document.addEventListener("click", (event) => {
  const pageButton = event.target.closest("[data-connection-page-action]");
  if (pageButton) {
    connectionPaging = true;
    connectionWindowDirection = pageButton.dataset.connectionPageAction;
  }

  if (event.target.closest("[data-confirm-clear]")) {
    const focus = { kind: "overview" };
    history.replaceState({ [HISTORY_STATE_KEY]: focus }, "", focusUrl(focus));
    queueScroll();
    return;
  }

  const back = event.target.closest("[data-inspector-back]");
  if (back) {
    event.preventDefault();
    if (history.state?.inspectorNavigation) {
      history.back();
    } else {
      const focus = { kind: "overview" };
      history.replaceState({ [HISTORY_STATE_KEY]: focus }, "", focusUrl(focus));
      syncFocus(focus);
    }
    return;
  }

  const control = event.target.closest("[data-inspector-focus]");
  if (!control) return;
  const interactive = event.target.closest("button, a, input, select, textarea");
  if (interactive && interactive !== control) return;
  event.preventDefault();
  activateFocusControl(control);
});

document.addEventListener("keydown", (event) => {
  if (!["Enter", " "].includes(event.key)) return;
  const control = event.target.closest("[data-inspector-focus]");
  if (!control || control.matches("button, a")) return;
  const interactive = event.target.closest("button, a, input, select, textarea");
  if (interactive && interactive !== control) return;
  event.preventDefault();
  activateFocusControl(control);
});

window.addEventListener("popstate", (event) => {
  queueScroll(event.state?.inspectorScroll);
  syncFocus(focusFromLocation());
});

const initialFocus = focusFromLocation();
history.scrollRestoration = "manual";
history.replaceState(
  {
    [HISTORY_STATE_KEY]: initialFocus,
    inspectorScroll: { x: window.scrollX, y: window.scrollY },
  },
  "",
  focusUrl(initialFocus),
);

// A page restored from cache, or one loaded immediately before shutdown,
// must not claim to be connected forever without receiving a heartbeat.
armStaleTimer();
readHeartbeat();
