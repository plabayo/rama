// Dependency-free unit regressions for the inspector's browser-side state.
// Run from the workspace root with `just test-proxy-dashboard-browser`.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const liveScript = fs.readFileSync(path.join(__dirname, "dashboard-live.js"), "utf8");
const detailsScript = fs.readFileSync(path.join(__dirname, "dashboard-details.js"), "utf8");

function liveContext(document, requestAnimationFrame = () => 0) {
  const handlers = {};
  document.addEventListener = (type, handler) => {
    handlers[type] = handler;
  };
  const context = vm.createContext({
    CustomEvent: class { constructor(type, init) { this.type = type; this.detail = init.detail; } },
    URL,
    URLSearchParams,
    clearTimeout() {},
    console,
    document,
    fetch: async () => ({ ok: true }),
    history: {
      pushState() {},
      replaceState() {},
      scrollRestoration: "auto",
      state: null,
    },
    MutationObserver: class {
      observe() {}
    },
    requestAnimationFrame,
    setTimeout: () => 0,
    window: {
      addEventListener() {},
      location: { href: "http://127.0.0.1/", search: "" },
      scrollTo() {},
      scrollX: 0,
      scrollY: 0,
    },
  });
  vm.runInContext(liveScript, context);
  return { context, handlers };
}

test("nested row controls keep their native keyboard action", () => {
  const { handlers } = liveContext({
    documentElement: {},
    getElementById: () => null,
    querySelector: () => null,
    visibilityState: "visible",
  });
  let prevented = false;
  const row = {
    dataset: { focusId: "1", inspectorFocus: "request" },
    matches: () => false,
  };
  const nestedButton = {
    closest: (selector) => selector === "[data-inspector-focus]" ? row : nestedButton,
  };

  handlers.keydown({
    key: " ",
    preventDefault: () => {
      prevented = true;
    },
    target: nestedButton,
  });

  assert.equal(prevented, false);
});

test("newer page restoration uses the direction captured before animation", () => {
  const frames = [];
  let heartbeat = { dataset: { sequence: "1" } };
  let connections = connectionFixture(0);
  const { context } = liveContext({
    documentElement: {},
    getElementById: (id) => id === "live-heartbeat" ? heartbeat : null,
    querySelector: (selector) => selector.startsWith(".connections") ? connections : null,
    visibilityState: "visible",
  }, (callback) => {
    frames.push(callback);
    return frames.length;
  });
  drainFrames(frames);

  vm.runInContext('connectionWindowDirection = "newer"', context);
  connections = connectionFixture(1);
  heartbeat = { dataset: { sequence: "2" } };
  vm.runInContext("readHeartbeat()", context);
  drainFrames(frames);

  assert.equal(connections.scrollTop, 776);
});

test("an in-flight preview survives a Datastar element morph", async () => {
  const handlers = {};
  let mutationObserver;
  let current = previewFixture();
  let resolveChunk;
  let reads = 0;
  const reader = {
    read() {
      reads += 1;
      if (reads === 1) {
        return new Promise((resolve) => {
          resolveChunk = resolve;
        });
      }
      return Promise.resolve({ done: true });
    },
  };
  const context = vm.createContext({
    AbortController,
    console,
    document: {
      addEventListener: (type, handler) => {
        handlers[type] = handler;
      },
      body: { append() {} },
      documentElement: {},
      getElementById: () => null,
      querySelectorAll: () => [current.button],
    },
    fetch: async () => ({ body: { getReader: () => reader }, ok: true }),
    MutationObserver: class {
      constructor(callback) {
        mutationObserver = callback;
      }

      observe() {}
    },
    queueMicrotask,
    setImmediate,
    setTimeout: () => 0,
    TextDecoder,
  });
  vm.runInContext(detailsScript, context);

  handlers.click({ target: current.button });
  await new Promise((resolve) => setImmediate(resolve));
  current = previewFixture();
  mutationObserver();
  assert.equal(current.label.textContent, "Loading preview…");
  assert.equal(current.output.hidden, false);

  resolveChunk({ done: false, value: Buffer.from("abc") });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(current.label.textContent, "Hide preview");
  assert.equal(current.output.hidden, false);
  assert.equal(current.output.textContent, "abc");
});

function connectionFixture(page) {
  return {
    addEventListener() {},
    clientHeight: 200,
    dataset: {
      connectionPage: String(page),
      hasNewer: String(page > 0),
      hasOlder: "true",
    },
    scrollHeight: 1000,
    scrollTop: 0,
  };
}

function drainFrames(frames) {
  while (frames.length > 0) frames.shift()();
}

function previewFixture() {
  const label = { textContent: "Preview first 64 KiB" };
  const output = {
    hidden: true,
    textContent: "",
    replaceChildren() {
      this.textContent = "";
    },
  };
  const container = { querySelector: () => output };
  const button = {
    dataset: {
      label: "Preview first 64 KiB",
      payloadFormat: "text",
      url: "/api/body",
    },
    closest(selector) {
      if (selector === "[data-capture-preview]") return this;
      if (selector === "[data-capture-container]") return container;
      return null;
    },
    querySelector: () => label,
    setAttribute(name, value) {
      this[name] = value;
    },
    toggleAttribute(name, present) {
      this[name] = present;
    },
  };
  return { button, label, output };
}

test("activating a pending request opens its inline editor instead of navigating", () => {
  const events = [];
  const { context } = liveContext({
    documentElement: {}, getElementById: () => null, querySelector: () => null,
    visibilityState: "visible", dispatchEvent: (event) => events.push(event),
  });
  vm.runInContext('activateFocusControl({ dataset: { approvalId: "17", inspectorFocus: "request", focusId: "3" } })', context);
  assert.equal(events.length, 1);
  assert.equal(events[0].type, "rama-edit-approval");
  assert.equal(events[0].detail.id, 17);
});
