// Exercise the actual fp page function without a second browser implementation.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import test from "node:test";

const source = fs.readFileSync(new URL("../../rama-cli/assets/script.js", import.meta.url), "utf8");
const probe = "rama-fp echo: " + "🐢".repeat(32);

function fixture() {
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
  const pending = context.connectWebSocket();
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
    assert.deepEqual(f.reports, [["WebSocket", version, "negotiated"]]);
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
