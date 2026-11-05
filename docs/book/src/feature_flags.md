# Feature flags

The `rama` crate is one crate with many optional parts. Each protocol, transport and
backend is behind a cargo feature, so you only compile what you use.

By default only the `std` feature is enabled, which gives you the service and layer
abstractions but no network stack. Enable the features for the parts you need.
A minimal HTTP server over TCP:

```
cargo add rama --features http-backend,tcp
cargo add tokio --features macros,rt-multi-thread
```

A minimal HTTP client (`EasyHttpWebClient`), with Rustls on `aws-lc` for `https`:

```
cargo add rama --features http-backend,tcp,dns,rustls,aws-lc
cargo add tokio --features macros,rt-multi-thread
```

Use `boring` instead of `rustls,aws-lc` for the BoringSSL backend. Add `quic` (with a TLS backend)
for HTTP/3. `http-full` enables the full HTTP stack, including HTTP/3, WebSocket and compression.
See the `[features]` table in
[`Cargo.toml`](https://github.com/plabayo/rama/blob/main/Cargo.toml) for all features.

## Feature groups

| Area | Features |
|---|---|
| Transports | `tcp`, `udp`, `unix`, `quic` (needs a TLS backend) |
| TLS | `tls`, with a backend: `rustls` (plus `aws-lc` or `ring`) or `boring`; `acme` |
| DNS | `dns`, `dns-hickory` |
| HTTP | `http`, `http-backend`, `http-full`, `ws`, `multipart`, `html`, `rss`, `http-hyperium` |
| RPC and gateways | `grpc`, `grpc-full`, `ttrpc`, `fastcgi`, `icap` |
| Proxies | `proxy`, `socks5`, `haproxy`, `masque`, `pac`, `proxy-memory-db`, `proxy-csv`, `proxy-live-update`, `proxy-full` |
| Scripting | `js`, `js-interpreter`, `js-disk-cache` |
| Inspection and emulation | `inspect`, `ua`, `ua-embed-profiles` |
| Platform | `net-apple-networkextension`, `net-apple-xpc` |
| Observability | `opentelemetry`, `dial9` |
| Interop | `tower` |

Features pull in what they need: `pac` enables `js`, `dns` and `http`, and
`masque` enables `http`, `udp` and `dns`. The API docs on
[docs.rs](https://docs.rs/rama) are built with all features and mark each item
with the features it needs.
