# Embedded JavaScript

Some network configuration is written in JavaScript. The best known case is a
[Proxy Auto-Configuration (PAC)](./proxies/operate/pac.md) file, but any proxy or
gateway that lets operators supply small scripts runs into the same need: run code
you did not write, from async Rust, without letting it take down the process.

`rama::js` is Rama's embedded JavaScript runtime for that job. It is available with
the `js` feature.

> 📚 Rust Docs: <https://ramaproxy.org/docs/rama/js/index.html>

## Runtimes and workers

There are two ways to run a script:

- `JsRuntime` runs scripts on the current thread. It is `!Send`, which makes it a
  fit for one-off evaluations and synchronous code.
- `JsWorker` owns a runtime on a dedicated OS thread. You compile a script once and
  then `call` its functions per request from async code. Handles are cheap to clone,
  jobs run in order, and the job queue is bounded so a stalled worker applies
  backpressure instead of growing without limit.

Both are built from a `JsRuntimeBuilder`. The builder is a cloneable blueprint:
one blueprint can create many runtimes or workers, for example a fresh worker per
script when one script must not observe state from another.

## Host functions

Scripts can only reach what you give them. Register host functions on the builder
with `with_fn`. Arguments are extracted into typed Rust values, much like a web
handler extracts a request, and return values are converted back. Values cross the
boundary as `JsValue`; wrap a type in `Serde` to pass any `serde` type, or expose a
Rust-owned resource as a `JsHostObject` with typed methods and properties.
`JsNamespace` groups functions and values under one global name. `console` is
present by default and drops its output; `Console::trace` routes it to `tracing`.

A typical flow: register host functions on
[`JsRuntime::builder`](https://ramaproxy.org/docs/rama/js/struct.JsRuntime.html), hand the blueprint to
[`JsWorker::spawn`](https://ramaproxy.org/docs/rama/js/struct.JsWorker.html), load the script once with `exec`, and
then `call` one of its functions by name with arguments, getting a `JsValue` back.

## Isolation and limits

The engine runs inside a private WebAssembly sandbox without filesystem, network,
clock or randomness access. `Date.now()` and `Math.random()` return fixed values
unless you register host functions for them. The builder bounds each runtime:

- **Memory**: `with_memory_limit`, 64 MiB by default.
- **Work**: `with_loop_iteration_limit`, an instruction budget for each evaluation
  or call.
- **Wall-clock time**: `with_execution_time_limit`, off by default.
- **Values copied out**: `JsSnapshotLimits` bound depth, size and length of results,
  thrown values and host function arguments.

A script that exceeds a limit fails with an error. When the engine had to be
aborted mid-execution the runtime is marked as poisoned and later calls fail; the
rest of the process keeps running. On a worker, `JsWorkerBuilder::with_timeout`
releases callers whose job takes too long.

These limits apply to JavaScript. Your own host functions run as normal Rust code
outside the sandbox, so keep them short and non-blocking.

Two related features exist: `js-interpreter` adds a bytecode interpreter backend
for platforms that do not allow executable memory (select it with
`JsBackend::Interpreter`; iOS always uses it), and `js-disk-cache` reuses compiled
code across process starts. Call `JsRuntime::warm_up` at startup to move the
one-time engine compilation out of the first request.

## Users

PAC evaluation (`rama::js::pac`, `pac` feature) is built on `JsWorker`. See the
[PAC chapter](./proxies/operate/pac.md) for what it adds on top.

## Examples

- [/examples/src/http_pac_client.rs](https://github.com/plabayo/rama/blob/main/examples/src/http_pac_client.rs):
  an HTTP client that routes requests through the proxies a PAC script selects.

API docs:

- <https://ramaproxy.org/docs/rama/js/index.html>
- <https://ramaproxy.org/docs/rama/js/pac/index.html>
