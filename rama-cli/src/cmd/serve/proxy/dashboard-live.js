const HEARTBEAT_STALE_AFTER_MS = 12000;

const status = document.getElementById("connection-status");
const label = status?.querySelector("[data-live-label]");
let lastSequence;
let lastHeartbeatNode;
let staleTimer;

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
}

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

// A page restored from cache, or one loaded immediately before shutdown,
// must not claim to be connected forever without receiving a heartbeat.
armStaleTimer();
readHeartbeat();
