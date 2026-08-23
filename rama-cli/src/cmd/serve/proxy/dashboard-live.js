const HEARTBEAT_STALE_AFTER_MS = 6000;

const status = document.getElementById("connection-status");
const label = status?.querySelector("[data-live-label]");
let lastSequence;
let staleTimer;

function setStatus(state, text) {
  if (!status || !label) return;
  status.classList.remove("is-connecting", "is-live", "is-offline");
  status.classList.add(`is-${state}`);
  label.textContent = text;
}

function armStaleTimer() {
  clearTimeout(staleTimer);
  staleTimer = setTimeout(() => {
    setStatus("offline", "disconnected");
  }, HEARTBEAT_STALE_AFTER_MS);
}

function readHeartbeat() {
  const sequence = document.getElementById("live-heartbeat")?.dataset.sequence;
  if (sequence === undefined || sequence === "" || sequence === lastSequence) return;
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

// A page restored from cache, or one loaded immediately before shutdown,
// must not claim to be connected forever without receiving a heartbeat.
armStaleTimer();
readHeartbeat();
