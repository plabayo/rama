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
  const fetch = { number: 12, fp: { request_info: { version: "HTTP/3.0" } } };
  const xhr = { number: 34, fp: { request_info: { version: "HTTP/3.0" } } };
  const calls = [];
  context.makePostRequest = async () => { calls.push("fetch"); return { json: async () => fetch }; };
  context.makeRequestWithXHR = async () => { calls.push("xhr"); return JSON.stringify(xhr); };
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
  assert.equal(first.xhr.number, xhr.number);
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
          document: { querySelector() { return { content: "enabled" }; }, getElementById() { return {}; } },
          performance: { getEntriesByType() { return [{ nextHopProtocol: protocol }]; } },
          crypto: { getRandomValues(bytes) { return bytes.fill(7); } },
          URL, Uint8Array, console: { log() {}, warn() {}, error() {} },
        });
        vm.runInContext(source, context);
        context.showProtocol = () => {};
        context.makePostRequest = async () => { calls.push("fetch"); return { json: async () => ({ fp: { request_info: { version: "HTTP/3.0" } } }) }; };
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
