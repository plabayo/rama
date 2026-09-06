const FILTER_KEY = "ramaProxyInspector.filters.v1";


function storageGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function storageSet(key, value) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

function storedObject(key) {
  const encoded = storageGet(key);
  if (!encoded) return null;
  try {
    const value = JSON.parse(encoded);
    return value && typeof value === "object" ? value : null;
  } catch {
    return null;
  }
}

function filterControls() {
  return [...document.querySelectorAll("[data-persist-filter]")];
}

function saveFilters() {
  const filters = {};
  for (const control of filterControls()) {
    filters[control.dataset.persistFilter] = control.value;
  }
  storageSet(FILTER_KEY, filters);
}

function restoreFilters() {
  const filters = storedObject(FILTER_KEY);
  if (!filters) return;
  for (const control of filterControls()) {
    const value = filters[control.dataset.persistFilter];
    if (typeof value !== "string") continue;
    control.value = value;
    control.dispatchEvent(new Event(control.matches("select") ? "change" : "input", {
      bubbles: true,
    }));
  }
}

function parseRules(value) {
  return [...new Set(value.split(/[\s,]+/u).map((rule) => rule.trim()).filter(Boolean))];
}

function policyControls() {
  return {
    allow: document.querySelector('[data-mitm-policy="allow"]'),
    deny: document.querySelector('[data-mitm-policy="deny"]'),
    apply: document.querySelector("[data-apply-mitm-policy]"),
    status: document.getElementById("mitm-policy-status"),
  };
}

function showPolicyStatus(message, kind = "") {
  const { status } = policyControls();
  if (!status) return;
  status.textContent = message;
  status.classList.toggle("error", kind === "error");
  status.classList.toggle("success", kind === "success");
}

async function applyPolicy() {
  const { allow, deny, apply } = policyControls();
  const session = document.body.dataset.inspectorSession;
  if (!allow || !deny || !apply || !session) return;
  const policy = { mode: document.getElementById("mitm-mode").value, allow: parseRules(allow.value), deny: parseRules(deny.value) };
  apply.disabled = true;
  showPolicyStatus("Applying…");
  try {
    const response = await fetch("/api/mitm-policy", {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ session, ...policy }),
    });
    if (!response.ok) {
      const detail = (await response.text()).trim();
      throw new Error(detail || `HTTP ${response.status}`);
    }
    showPolicyStatus("Applied globally", "success");
    document.dispatchEvent(new Event("rama-control-refresh"));
  } catch (error) {
    showPolicyStatus(`Could not apply: ${error.message}`, "error");
  } finally {
    apply.disabled = false;
  }
}


document.addEventListener("input", (event) => {
  if (event.target.closest("[data-persist-filter]")) saveFilters();
});

document.addEventListener("change", (event) => {
  if (event.target.closest("[data-persist-filter]")) saveFilters();
});

document.addEventListener("click", (event) => {
  if (event.target.closest("[data-reset-preferences]")) {
    storageSet(FILTER_KEY, {});
    return;
  }
  if (event.target.closest("[data-apply-mitm-policy]")) {
    void applyPolicy();
  }
});


if (document.readyState === "complete") {
  setTimeout(restoreFilters, 0);
} else {
  window.addEventListener("load", () => setTimeout(restoreFilters, 0), { once: true });
}
