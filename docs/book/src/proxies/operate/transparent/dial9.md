# 🐕 dial9 — Tokio runtime telemetry for L4 proxies

[`dial9`](https://github.com/dial9-rs/dial9-tokio-telemetry) is a low-overhead
runtime telemetry crate for Tokio. It records poll timing, wake events, kernel
scheduling delays (Linux), CPU profiling samples (Linux), and arbitrary custom
events into a self-describing binary trace format that can be analysed offline
with `dial9-viewer` or programmatically.

For long-lived L4 proxies — and transparent proxies in particular — dial9 is
unusually well-suited as a diagnostic tool. The failure modes that are hardest
to reproduce in a development environment (post-wake stale flows, runtime
starvation under load, occasional handler hangs) leave clear fingerprints in
a dial9 trace that conventional metrics aggregators will smooth out.

## Why dial9 specifically for transparent proxies

Transparent proxies on macOS / Linux mediate every TCP and UDP flow on the
host. A wedge — even a transient one — is system-wide and immediately
visible to the user. Conventional metrics tell you "P99 latency went up";
dial9 lets you go from "this flow took 30 seconds" in the rama close log to
"here is the exact poll history of that flow's task" in the trace, including
what was on the CPU when it stalled.

The flow ID added to
[`TransparentProxyFlowMeta`](https://docs.rs/rama-net-apple-networkextension/latest/rama_net_apple_networkextension/tproxy/struct.TransparentProxyFlowMeta.html)
in this series is the bridge: rama's structured close events log
`flow_id=…`; dial9 custom events emitted from the same hot path also carry
`flow_id=…`. Cross-referencing the two surfaces the runtime view of any flow
that misbehaves.

## How it composes with rama

dial9 hooks into Tokio at the runtime level. The recommended integration
pattern is to construct the runtime via `dial9_tokio_telemetry::TracedRuntime`
and pass its underlying `tokio::runtime::Handle` (and the runtime itself) into
the rama engine. For the apple transparent-proxy engine, this means
implementing a custom
[`TransparentProxyAsyncRuntimeFactory`](https://docs.rs/rama-net-apple-networkextension/latest/rama_net_apple_networkextension/tproxy/trait.TransparentProxyAsyncRuntimeFactory.html)
that returns the dial9-traced runtime instead of the default factory's
plain runtime.

In addition to the runtime-level events that dial9 records automatically,
the rama tproxy example defines a small set of custom events for
flow lifecycle correlation:

| Event                  | Emitted from                                          |
| ---------------------- | ----------------------------------------------------- |
| `TproxyFlowOpened`     | engine, after a flow is assigned a flow_id            |
| `TproxyFlowClosed`     | bridge close path                                     |
| `TproxyHandlerDeadline`| engine, when `match_*_flow` exceeds the deadline      |

These mirror the structured `tracing` events emitted by the engine but go
directly into the dial9 trace as native events for fast offline analysis,
without paying the tracing-layer overhead.

## Caveats

- **Requires `tokio_unstable`.** Set
  `RUSTFLAGS="--cfg tokio_unstable"` (or in `.cargo/config.toml`) when
  building with the `dial9` feature.
- **Memory.** dial9 allocates a roughly 1 MiB trace buffer per OS thread.
  For an L4 proxy with bounded thread counts this is fine; document if
  copying the integration pattern into a high-thread-count workload.
- **macOS vs Linux capability gap.** The deepest data — kernel scheduling
  delay, perf-event flame graphs — is Linux-only. On macOS dial9 still
  records the Tokio runtime events and any custom events your code emits;
  this is the bulk of what is useful for diagnosing L4-proxy wedges.
- **Production-readiness.** dial9 is young and evolving. Treat it as
  instrumental for diagnostics and short-window production probes; evaluate
  carefully before enabling it permanently in a long-running production
  deployment.

## Reference implementation

The transparent-proxy FFI example in `ffi/apple/examples/transparent_proxy/`
gates dial9 behind a `dial9` cargo feature; the rust-side custom events
defined for tproxy (see above) live in
`ffi/apple/examples/transparent_proxy/tproxy_rs/src/dial9.rs`. The example's
README documents how to enable the feature and view the resulting trace.

## Going further

dial9 is a young crate and the relationship between rama and dial9 is
expected to evolve as we learn more about real-world traces from the
transparent-proxy example running on developer machines. If you have
useful traces or feedback, [open an issue on rama](https://github.com/plabayo/rama/issues)
or [on dial9](https://github.com/dial9-rs/dial9-tokio-telemetry/issues)
directly.

For more context on the design and motivation behind dial9, see
[netstack.fm episode 37](https://netstack.fm/) where we spoke with the
authors.
