// Dependency-free unit regressions for the inspector's browser-side state.
// Run from the workspace root with `just test-proxy-dashboard-browser`.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const liveScript = fs.readFileSync(path.join(__dirname, "dashboard-live.js"), "utf8");
const detailsScript = fs.readFileSync(path.join(__dirname, "dashboard-details.js"), "utf8");
const controlScript = fs.readFileSync(path.join(__dirname, "dashboard-control.js"), "utf8");

test("approval editor uses message kind independently of traffic direction", async () => {
  const editor = controlScript.slice(controlScript.indexOf("async function editMessage("), controlScript.indexOf("function readResponse("));
  for (const direction of ["ingress", "egress"]) {
    for (const kind of [null, "text", "binary"]) {
      const elements = new Map();
      const element = (id) => {
        if (!elements.has(id)) elements.set(id, { label: {}, closest() { return this.label; }, focus() {} });
        return elements.get(id);
      };
      const context = vm.createContext({
        $: element,
        api: async () => ({ id: 1, direction, kind, method: "GET", url: "/", headers: [], status: 200 }),
        editSequence: 0,
        editing: undefined,
        formatHeaders: () => "",
        connectionLabel: () => "connection #1",
        mountEditor() {},
        inlineEditor: { scrollIntoView() {} },
      });
      vm.runInContext(editor, context);
      await context.editMessage(1);
      const http = kind === null;
      assert.equal(element("http-edit-fields").hidden, !http);
      assert.equal(element("ws-edit-fields").hidden, http);
      assert.equal(element("intercept-status").label.hidden, !http || direction !== "egress");
      assert.equal(element("block-message").textContent, http ? "Block" : "Drop message");
      assert.equal(element("respond-message").hidden, !http);
    }
  }
});

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
      createTextNode: (data) => ({ data }),
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
    requestAnimationFrame: () => 1,
    cancelAnimationFrame() {},
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
    childNodes: [],
    get lastChild() { return this.childNodes.at(-1) ?? null; },
    get textContent() { return this.childNodes.map((node) => node.data).join(""); },
    replacements: 0,
    replaceChildren() { this.childNodes = []; this.replacements += 1; },
    append(node) { this.childNodes.push(node); },
  };
  const container = { querySelector: () => output };
  const button = {
    dataset: {
      label: "Preview first 64 KiB",
      payloadFormat: "text",
      byteLimit: "65536",
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

test("header editing preserves ordered duplicates, opaque bytes and literal prefixes", () => {
  const source = fs.readFileSync(path.join(__dirname, "dashboard-control.js"), "utf8");
  const context = vm.createContext({ btoa, atob, TextEncoder });
  vm.runInContext(source.slice(source.indexOf("const binaryHeaderPrefix"), source.indexOf("async function refresh()")), context);
  const headers = [["x-test", "first"], ["x-test", [0x80, 0xff]], ["x-literal", "rama-capture-base64:ordinary text"], ["x-latin", "rama-capture-base64:é"], ["x-unicode", "rama-capture-base64:€💖"]];
  const result = JSON.parse(JSON.stringify(context.readHeaders(context.formatHeaders(headers))));
  assert.deepEqual(result.slice(0, 2), headers.slice(0, 2));
  for (let index = 2; index < headers.length; index++) {
    assert.deepEqual(result[index][1], [...Buffer.from(headers[index][1])]);
  }
  const patterns = [["x-test", "rama-capture-base64:é*"]];
  assert.deepEqual(JSON.parse(JSON.stringify(context.readHeaders(context.formatHeaders(patterns, true), true))), patterns);
});

test("binary previews append deltas, survive morphs and stop at the byte limit", async () => {
  let current = previewFixture();
  current.button.dataset.payloadFormat = "binary";
  const frames = [];
  let mutations;
  let reads = 0;
  let cancelled = false;
  const priorNodes = [];
  const context = vm.createContext({
    AbortController, TextDecoder, console,
    document: {
      addEventListener() {}, documentElement: {},
      createTextNode: (data) => ({ data }),
      querySelectorAll: () => [current.button],
    },
    MutationObserver: class { constructor(callback) { mutations = callback; } observe() {} },
    requestAnimationFrame: (callback) => { frames.push(callback); return frames.length; },
    cancelAnimationFrame() {},
    fetch: async () => ({ ok: true, body: { getReader: () => ({
      async read() {
        drainFrames(frames);
        if (reads > 0) {
          assert.equal(current.output.childNodes.length, reads);
          if (reads > 1) assert.equal(current.output.childNodes[0], priorNodes[0]);
          else priorNodes.push(current.output.childNodes[0]);
          mutations();
          assert.equal(current.output.replacements, 1);
        }
        reads += 1;
        // More data exists than the preview budget: reading it all would be a bug.
        assert.ok(reads <= 64);
        return { done: false, value: new Uint8Array(1024).fill(reads % 256) };
      },
      cancel: async () => { cancelled = true; },
    }) } }),
  });
  vm.runInContext(detailsScript, context);
  await context.streamPreview(current.button);
  assert.equal(reads, 64);
  assert.equal(cancelled, true);
  assert.equal(current.output.textContent.length, 65536 * 3);
  const fullText = current.output.textContent;
  assert.ok(fullText.startsWith("01 01 "));
  assert.ok(fullText.endsWith("40 40 "));
  assert.equal(current.output.replacements, 1);
  current = previewFixture();
  current.button.dataset.payloadFormat = "binary";
  mutations();
  assert.equal(current.output.textContent, fullText);
  assert.equal(current.output.replacements, 1);
});


test("text preview caps an oversized chunk without a partial UTF-8 character", async () => {
  const current = previewFixture();
  current.button.dataset.byteLimit = "7";
  let cancelled = false;
  let reads = 0;
  const context = vm.createContext({
    AbortController, TextDecoder,
    document: {
      addEventListener() {}, documentElement: {},
      createTextNode: (data) => ({ data }),
      querySelectorAll: () => [current.button],
    },
    MutationObserver: class { observe() {} },
    requestAnimationFrame: () => 1,
    cancelAnimationFrame() {},
    fetch: async () => ({ ok: true, body: { getReader: () => ({
      async read() {
        assert.equal(++reads, 1);
        return { done: false, value: Buffer.from("hello 💖 tail") };
      },
      cancel: async () => { cancelled = true; },
    }) } }),
  });
  vm.runInContext(detailsScript, context);
  await context.streamPreview(current.button);
  assert.equal(cancelled, true);
  assert.equal(current.output.textContent, "hello ");
  assert.equal(current.label.textContent, "Hide preview");
});
