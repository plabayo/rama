# 🐕 dial9

[dial9] is a Tokio runtime telemetry crate by Russell Cohen and Jess
Izen at AWS. It records poll / wake / scheduling-delay events plus
application-defined events into a binary trace you can analyse offline.

## How rama exposes dial9

Rama crates that emit events or expose runtime boundaries have an opt-in
`dial9` cargo feature. Event-producing crates emit their predefined events at
the matching lifecycle hooks; recording becomes a no-op when no [`dial9`]
recorder is wirted into the application. 
The `rama` mono-crate has a bundled `dial9` feature that activates the same on every enabled sub-crate.

Library code that wants its own events alongside rama's predefined
sets can depend on `dial9-trace-format` directly and derive
`TraceEvent` on its types.

The `rama` crate's `dial9` feature also exposes it through
`rama::telemetry::dial9`.
Runtime-owning integrations can use `rama::rt::OwnedRuntime`. Blocking
runtimes resolve the `DIAL9_*` environment when built if the feature is enabled;
call `with_dial9_recorder(...)` to supply your own `dial9::Recorder` or
`without_dial9_recorder()` to opt out explicitly. Tasks crossing those
boundaries remain associated with that runtime's trace.

### tokio_unstable

`--cfg tokio_unstable` can be used to widen dial9's task coverage. 
Without it, poll events come from dial9's own spawn helpers, so the task timeline covers what rama routes through `rama_core::rt::Executor`, task spawn/terminate events and per-worker queue depth are unavailable. 
Set it to get the full timeline:

```toml
# .cargo/config.toml
[build]
rustflags = ["--cfg", "tokio_unstable"]
```

## Caveats

- macOS only captures runtime-level + application events; Linux gets
  kernel scheduling delays and CPU profiling samples too.
- ~1 MiB trace buffer per OS thread.
- dial9 is young — treat it as a diagnostics tool, not a production
  metrics replacement.

## Going further

For the design and motivation, see [ Netstack.FM episode 37], the
[Tokio blog post], and the [dial9 README]. A working integration in
the rama tree:
[`ffi/apple/examples/transparent_proxy/`](https://github.com/plabayo/rama/tree/main/ffi/apple/examples/transparent_proxy).

[dial9]: https://github.com/dial9-rs/dial9
[`dial9`]: https://github.com/dial9-rs/dial9
[Netstack.FM episode 37]: https://netstack.fm/#episode-37
[Tokio blog post]: https://tokio.rs/blog/2026-03-18-dial9
[dial9 README]: https://github.com/dial9-rs/dial9
