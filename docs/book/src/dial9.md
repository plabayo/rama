# 🐕 dial9

[dial9] is a Tokio runtime telemetry crate by Russell Cohen and Jess
Izen at AWS. It records what your async program is doing — poll timing,
wake events, scheduling delays, custom application events — into a
self-describing binary trace that you can analyse offline.

If you have ever stared at "P99 went up" in a metrics dashboard and
wished you could just see what the runtime was doing at that moment,
dial9 is for you.

## What it captures

- **Tokio runtime events** — every poll start / stop, wake, worker park
  / unpark.
- **Scheduling delay** — how long a task sat ready-to-run before the
  runtime actually polled it. Surfaces wedges that look like "the task
  was slow" but were really "the runtime was busy elsewhere."
- **Kernel events** (Linux) — context switches, off-CPU samples, and
  CPU profiling stacks.
- **Custom events** — application-defined structs you derive
  `TraceEvent` on. Recorded with the same low-overhead encoder as the
  built-in events.

The output is a binary trace file. Browse it with the dashboard, dig
through it with the CLI, or hand it to an LLM agent to summarise.

## A small example

```rust,ignore
use dial9_trace_format::TraceEvent;

#[derive(TraceEvent)]
struct RequestCompleted {
    #[traceevent(timestamp)]
    ts_ns: u64,
    request_id: u64,
    elapsed_ms: u64,
}
```

Build the program with `--cfg tokio_unstable` (dial9 hooks into
Tokio's unstable runtime APIs), and `dial9-tokio-telemetry` writes the
trace to disk while your program runs.

## How rama exposes dial9

rama integrates dial9 as an opt-in feature so the pre-defined event
sets shipped by sub-crates are available without forcing the
dependency on everyone.

- **`rama-net-apple-networkextension`** — `dial9` feature. Ships
  pre-defined events (`TproxyFlowOpened`, `TproxyFlowClosed`,
  `TproxyHandlerDeadline`) for the transparent proxy engine's flow
  lifecycle.
- **`rama`** — bundled `dial9` feature that activates the sub-crate
  features above. More rama crates may grow their own pre-defined
  event sets over time; `rama-net`, `rama-http`, `rama-tcp`, and the
  TLS crates are good candidates.

The expectation is that whatever rama crate you pull in, if it has
something interesting to tell you about a flow / connection /
handshake, you can opt into the matching event types by enabling the
feature — without writing them yourself. Library code that needs to
define its own events can depend on `dial9-trace-format` directly.

## Why dial9 fits long-lived L4 proxies particularly well

The most reliable place where the runtime view matters more than the
metrics view is a long-lived L4 proxy: lots of concurrent flows,
each one a multi-poll task, with the failure modes that hurt being
"this one flow hung for 30 seconds" or "wake-up latency drifted up
under load." Those are exactly the things conventional metrics
aggregate away. The runtime trace puts them back into focus.

The transparent-proxy hardening series in `rama-net-apple-networkextension`
adds a `flow_id` to every flow's structured `tracing` close event.
That same `flow_id` shows up in the dial9 events emitted from the
engine, so cross-correlating the two — "here is the flow id from the
production log; show me its full poll history in dial9-viewer" —
becomes the natural debugging workflow.

## Playing with it

The transparent-proxy FFI example under
[`ffi/apple/examples/transparent_proxy/`](https://github.com/plabayo/rama/tree/main/ffi/apple/examples/transparent_proxy)
is built with dial9 always on. It pulls the pre-defined events from
`rama_net_apple_networkextension::tproxy::dial9` and provides a
working integration of dial9-tokio-telemetry's `TracedRuntime` with
the transparent-proxy engine. If you want to see what a dial9 trace
of a real, long-lived L4 proxy looks like, that is the place to
start.

## Caveats

- **`tokio_unstable`.** Required for any program that actually records
  events (i.e. uses `dial9-tokio-telemetry::TracedRuntime`). Enabling
  the rama `dial9` feature on its own — for the trace-format building
  blocks — does not require it.
- **Memory.** dial9 allocates a roughly 1 MiB trace buffer per OS
  thread.
- **OS support.** Linux gets the full picture (kernel scheduling, CPU
  profiling). macOS gets the runtime-level view; the kernel-side
  capture is more limited.
- **Maturity.** dial9 is young. Treat it as instrumental for
  diagnostics, evaluate carefully before enabling it permanently in
  long-running production.

## Going further

For the design and motivation behind dial9, listen to
[netstack.fm episode 37](https://netstack.fm/#episode-37) — interview
with the dial9 authors. Their guest blog post on the Tokio blog and
the dial9 README cover the integration patterns in more depth.

[dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry
