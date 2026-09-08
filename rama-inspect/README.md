# rama-inspect

Protocol-independent building blocks for inspection interfaces: shared lifecycle,
typed interception, subscriptions, and streaming storage. Use them with a web UI,
native GUI, TUI, or custom protocol.

Memory and filesystem storage are included. Protocol adapters live in their owning
crates; encryption is provided by `rama-crypto` with `inspect` and `boring` enabled.
Through the `rama` facade, combine `inspect` with the protocol and crypto features
your application needs.

See the [API documentation](https://docs.rs/rama-inspect),
[core modules](src/lib.rs), [storage contracts](src/storage/mod.rs), and
[MITM guide](../docs/book/src/proxies/mitm.md).
