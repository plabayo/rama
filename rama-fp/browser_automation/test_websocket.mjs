// Exercise the actual fp page function without a second browser implementation.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import test from "node:test";

const source = fs.readFileSync(new URL("../../rama-cli/assets/script.js", import.meta.url), "utf8");
const probe = "rama-fp echo: " + "🐢".repeat(32);

function fixture(probe) {
  let socket;
  let timer;
  const reports = [];
  const context = vm.createContext({
    window: { addEventListener() {} },
    location: { protocol: "https:", host: "fixture.invalid" },
    setTimeout(callback) { timer = callback; return 1; },
    clearTimeout() { timer = null; },
    WebSocket: class {
      constructor(url, protocols) {
        socket = this;
        assert.equal(url, "wss://fixture.invalid/api/ws");
        assert.deepEqual([...protocols], ["a", "b"]);
        this.sent = [];
        this.closed = false;
      }
      send(value) { this.sent.push(value); }
      close() { this.closed = true; }
    },
  });
  vm.runInContext(source, context);
  context.showProtocol = (...args) => reports.push(args);
  const pending = context.connectWebSocket(probe);
  // Attach rejection handling before simulating events; keep the original
  // promise available so each test still checks whether it actually rejected.
  pending.catch(() => {});
  return {
    socket, pending, reports,
    message(value) { socket.onmessage({ data: value }); },
    greeting(version = "HTTP/3.0") {
      socket.onmessage({ data: JSON.stringify({ initiator: "ws", version, h3: "negotiated" }) });
    },
    close(changes = {}) { socket.onclose({ wasClean: true, code: 1000, ...changes }); },
    expire() { assert.ok(timer); timer(); },
    get timer() { return timer; },
  };
}

test("every HTTP version needs its UTF-8 echo and clean close before reporting", async () => {
  for (const version of ["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]) {
    const f = fixture();
    f.greeting(version);
    assert.deepEqual(f.socket.sent, [probe]);
    assert.deepEqual(f.reports, []);
    f.message(probe);
    assert.deepEqual(f.reports, []);
    f.close();
    await f.pending;
    assert.deepEqual(f.reports, [["WebSocket", version]]);
    assert.equal(f.timer, null);
  }
});

test("a greeting or echo cannot hide an early or unclean close", async () => {
  for (const phase of ["empty", "greeting", "echo"]) {
    for (const changes of [{}, { wasClean: false }, { code: 1006 }]) {
      if (phase === "echo" && Object.keys(changes).length === 0) continue;
      const f = fixture();
      if (phase !== "empty") f.greeting();
      if (phase === "echo") f.message(probe);
      f.close(changes);
      await assert.rejects(f.pending);
      assert.deepEqual(f.reports, []);
      assert.equal(f.timer, null);
    }
  }
});

test("malformed greetings, wrong echoes and extra messages fail", async () => {
  for (const messages of [
    ["not JSON"], ["null"], ["{}"],
    [JSON.stringify({ initiator: "other", version: "h3" })],
    [JSON.stringify({ initiator: "ws", version: 3 })],
  ]) {
    const f = fixture();
    for (const message of messages) f.message(message);
    await assert.rejects(f.pending);
    assert.equal(f.socket.closed, true);
    assert.deepEqual(f.reports, []);
  }
  for (const messages of [["wrong"], [probe, probe]]) {
    const f = fixture();
    f.greeting();
    for (const message of messages) f.message(message);
    f.close();
    await assert.rejects(f.pending);
    assert.deepEqual(f.reports, []);
  }
});

test("connection errors and silent peers release the pending workflow", async () => {
  for (const phase of ["empty", "greeting", "echo"]) {
    for (const event of ["error", "deadline"]) {
      const f = fixture();
      if (phase !== "empty") f.greeting();
      if (phase === "echo") f.message(probe);
      if (event === "error") f.socket.onerror(); else f.expire();
      await assert.rejects(f.pending);
      assert.equal(f.socket.closed, true);
      assert.equal(f.timer, null);
      assert.deepEqual(f.reports, []);
    }
  }
});

// The page returns already-consumed responses, so a collector never reruns requests.
test("a custom echo probe is returned only after its exact round trip", async () => {
  const probe = "owned page #" + "ab".repeat(16);
  const f = fixture(probe);
  f.greeting("HTTP/2.0");
  assert.deepEqual(f.socket.sent, [probe]);
  f.message(probe);
  f.close();
  const result = await f.pending;
  assert.ok(result);
  assert.equal(result.probe, probe);
  assert.equal(result.greeting.version, "HTTP/2.0");
  assert.deepEqual(f.reports, [["WebSocket", "HTTP/2.0"]]);
});

test("the load-owned Promise exposes one completed journey without duplicate work", async () => {
  const listeners = new Map();
  const input = {};
  const context = vm.createContext({
    window: { addEventListener(name, callback) { listeners.set(name, callback); } },
    location: { protocol: "https:", host: "fixture.invalid", href: "https://fixture.invalid/report" },
    document: { querySelector() { return null; }, getElementById() { return input; } },
    performance: { getEntriesByType() { return [{ nextHopProtocol: "h3" }]; } },
    crypto: { getRandomValues(bytes) { return bytes.fill(7); } },
    URL, Uint8Array, console: { log() {}, warn() {}, error() {} },
  });
  vm.runInContext(source, context);
  context.showProtocol = () => {};
  // These exact wire integers exceed Number's range; display parsing may round them.
  const fetch = '{"number":12,"fp":{"request_info":{"version":"HTTP/3.0"},"quic":{"parameters":[{"id":44049833617918945}]}}}';
  const xhr = '{"number":34,"fp":{"request_info":{"version":"HTTP/3.0"},"quic":{"parameters":[{"id":4611686018427387903}]}}}';
  const calls = [];
  context.makePostRequest = async () => { calls.push("fetch"); return { text: async () => fetch }; };
  context.makeRequestWithXHR = async () => { calls.push("xhr"); return xhr; };
  context.connectWebSocket = async (probe) => {
    calls.push("ws");
    return { greeting: { initiator: "ws", version: "HTTP/2.0" }, probe };
  };
  listeners.get("load")();
  const promise = context.window.ramaFpFlow;
  assert.equal(typeof promise?.then, "function");
  const first = await promise;
  assert.ok(first && typeof first === "object");
  const second = await context.window.ramaFpFlow;
  assert.equal(first, second);
  assert.equal(first.fetch, fetch);
  assert.equal(first.xhr, xhr);
  assert.equal(first.websocket.probe, probe + " #" + "07".repeat(16));
  assert.equal(first.websocket.greeting.version, "HTTP/2.0");
  assert.deepEqual(calls, ["fetch", "xhr", "ws"]);
  assert.match(input.innerHTML, /<form method="POST"/);
});


test("Alt-Svc discovery reloads only a non-H3 secure navigation once", async () => {
  for (const protocol of ["h3", "h2", "http/1.1", ""]) {
    for (const scheme of ["https:", "http:"]) {
      for (const probed of [false, true]) {
        const redirects = [];
        const calls = [];
        const href = `${scheme}//fixture.invalid/report${probed ? "?h3_probe=1" : ""}`;
        const context = vm.createContext({
          window: { addEventListener() {} },
          location: { protocol: scheme, host: "fixture.invalid", href, replace(url) { redirects.push(url); } },
          document: {
            querySelector(selector) {
              return selector === 'meta[name="rama-h3-probe"]' ? { content: "enabled" } : null;
            },
            getElementById() { return {}; },
          },
          performance: { getEntriesByType() { return [{ nextHopProtocol: protocol }]; } },
          crypto: { getRandomValues(bytes) { return bytes.fill(7); } },
          URL, Uint8Array, console: { log() {}, warn() {}, error() {} },
        });
        vm.runInContext(source, context);
        context.showProtocol = () => {};
        context.makePostRequest = async () => { calls.push("fetch"); return { text: async () => '{"fp":{"request_info":{"version":"HTTP/3.0"}}}' }; };
        context.makeRequestWithXHR = async () => { calls.push("xhr"); return JSON.stringify({ fp: { request_info: { version: "HTTP/3.0" } } }); };
        context.connectWebSocket = async (probe) => { calls.push("ws"); return { probe, greeting: {} }; };
        await context.main();
        const shouldDiscover = scheme === "https:" && protocol !== "h3" && !probed;
        assert.deepEqual(redirects, shouldDiscover ? ["https://fixture.invalid/report?h3_probe=1"] : []);
        assert.deepEqual(calls, shouldDiscover ? [] : ["fetch", "xhr", "ws"]);
      }
    }
  }
});

test("site probes follow the page's own flows and report each site flow", async () => {
  const sites = [
    { site: "same-site", origin: "https://ss.fixture.invalid", token: "tok-ss" },
    { site: "cross-site", origin: "https://xss.fixture.example", token: "tok-xss" },
  ];
  const calls = [];
  const reports = [];
  const input = { hidden: true, innerHTML: "" };
  const context = vm.createContext({
    window: { addEventListener() {} },
    location: { protocol: "https:", host: "fixture.invalid", href: "https://fixture.invalid/report" },
    document: {
      querySelector(selector) {
        if (selector === 'meta[name="rama-fp-sites"]') return { content: JSON.stringify(sites) };
        return null;
      },
      getElementById() { return input; },
      createElement() { return {}; },
      head: { append() {} },
      body: { append() {} },
    },
    performance: { getEntriesByType() { return [{ nextHopProtocol: "h2" }]; } },
    crypto: { getRandomValues(bytes) { return bytes.fill(7); } },
    Image: class {},
    URL, Uint8Array, console: { log() {}, warn() {}, error() {} },
  });
  vm.runInContext(source, context);
  context.showProtocol = (...args) => reports.push(args);
  const version = (url) => JSON.stringify({ fp: { request_info: { version: "HTTP/2.0" } } });
  context.makePostRequest = async (url) => { calls.push(["fetch", url]); return { text: async () => version(url) }; };
  context.makeRequestWithXHR = async (url) => { calls.push(["xhr", url]); return version(url); };
  context.connectWebSocket = async (probe, url) => {
    calls.push(["ws", url]);
    if (url && url.includes("xss")) throw new Error("refused");
    return { probe, greeting: { initiator: "ws", version: "HTTP/2.0" } };
  };
  context.loadSubresource = async (_element, _attribute, url) => {
    calls.push(["load", url]);
    return "h2";
  };
  // Objects from the page's realm have their own prototypes.
  const result = JSON.parse(JSON.stringify(await context.main()));
  assert.match(input.innerHTML, /<form method="POST"/);
  assert.deepEqual(Object.keys(result.sites), ["same-site", "cross-site"]);
  for (const [site, { origin, token }] of [["same-site", sites[0]], ["cross-site", sites[1]]]) {
    const flows = result.sites[site];
    assert.deepEqual(
      Object.keys(flows), ["image", "style", "script", "frame", "fetch", "xhr", "ws"],
    );
    const urls = calls.map(([, url]) => url).filter((url) => url && url.includes(new URL(origin).host));
    assert.equal(urls.length, 7, site);
    for (const url of urls) {
      assert.equal(new URL(url).searchParams.get("rama-fp-site"), token);
    }
    assert.ok(urls.some((url) => url.startsWith("wss://")), site);
  }
  assert.deepEqual(result.sites["same-site"].ws, { protocol: "HTTP/2.0" });
  assert.deepEqual(result.sites["cross-site"].ws, { error: "refused" });
  assert.deepEqual(result.sites["cross-site"].image, { protocol: "h2" });
  assert.ok(reports.some(([flow, protocol]) => flow === "WebSocket (cross-site)" && protocol === "unavailable"));
});

test("an invalid site configuration never breaks the page's own journey", async () => {
  const reports = [];
  const input = { hidden: true, innerHTML: "" };
  const context = vm.createContext({
    window: { addEventListener() {} },
    location: { protocol: "https:", host: "fixture.invalid", href: "https://fixture.invalid/report" },
    document: {
      querySelector(selector) {
        return selector === 'meta[name="rama-fp-sites"]' ? { content: "{not json" } : null;
      },
      getElementById() { return input; },
    },
    performance: { getEntriesByType() { return [{ nextHopProtocol: "h2" }]; } },
    crypto: { getRandomValues(bytes) { return bytes.fill(7); } },
    URL, Uint8Array, console: { log() {}, warn() {}, error() {} },
  });
  vm.runInContext(source, context);
  context.showProtocol = (...args) => reports.push(args);
  context.makePostRequest = async () => ({ text: async () => '{"fp":{"request_info":{"version":"HTTP/2.0"}}}' });
  context.makeRequestWithXHR = async () => '{"fp":{"request_info":{"version":"HTTP/2.0"}}}';
  context.connectWebSocket = async (probe) => ({ probe, greeting: {} });
  // Objects from the page's realm have their own prototypes.
  const result = JSON.parse(JSON.stringify(await context.main()));
  assert.deepEqual(result.sites, {});
  assert.match(input.innerHTML, /<form method="POST"/);
  assert.ok(reports.some(([flow, protocol]) => flow === "Sites" && protocol === "unavailable"));
});
