# 🐕 dial9

[dial9] is a Tokio runtime telemetry crate by Russell Cohen and Jess
Izen at AWS. It records poll / wake / scheduling-delay events plus
application-defined events into a binary trace you can analyse offline.

## How rama exposes dial9

Each rama crate that emits events has an opt-in `dial9` cargo feature.
With it enabled, the crate emits its predefined events at the matching
lifecycle hooks; recording becomes a no-op when no
[`dial9-tokio-telemetry`] `TracedRuntime` is wired into the
application. The `rama` mono-crate has a bundled `dial9` feature that
activates the same on every enabled sub-crate.

Library code that wants its own events alongside rama's predefined
sets can depend on `dial9-trace-format` directly and derive
`TraceEvent` on its types.

### tokio_unstable

Enabling `dial9` on any rama crate requires `--cfg tokio_unstable`
(the standard requirement for [`dial9-tokio-telemetry`]). The rama
workspace sets this in `.cargo/config.toml`. Users who do not enable
`dial9` do not need it.

## Caveats

- macOS only captures runtime-level + application events; Linux gets
  kernel scheduling delays and CPU profiling samples too.
- ~1 MiB trace buffer per OS thread.
- dial9 is young — treat it as a diagnostics tool, not a production
  metrics replacement.

## Going further

For the design and motivation, see [netstack.fm episode 37], the
[Tokio blog post], and the [dial9 README]. A working integration in
the rama tree:
[`ffi/apple/examples/transparent_proxy/`](https://github.com/plabayo/rama/tree/main/ffi/apple/examples/transparent_proxy).

[dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry
[`dial9-tokio-telemetry`]: https://github.com/dial9-rs/dial9-tokio-telemetry
[netstack.fm episode 37]: https://netstack.fm/#episode-37
[Tokio blog post]: https://tokio.rs/blog/2026-03-18-dial9
[dial9 README]: https://github.com/dial9-rs/dial9-tokio-telemetry
