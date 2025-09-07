# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

# 0.3.0-alpha.3

> Release date: `2025-08-29`

### Windows Tier 1 Support

Windows is now a tier 1 platform.
Bug tickets specific to windows can now be reported, windows 10 and above.

### Added

- Windows promoted to tier-1 target, with pre-built binaries, signed releases, and `winget` package publication (`Plabayo.Rama.Preview`) (#683, #689, #690).
- HTTP-to-HTTPS upgrade redirect service (#678).
- Support for custom X.509 certificate stores in `rama-tls-boring`, with system store defaults (via `schannel`) on Windows (#677).
- Support for WebSocket extensions, including per-message deflate, plus new typed WebSocket headers (#663, #672).
- Header byte size tracking for HTTP/1 and HTTP/2 requests and responses (#672, #688).
- `include_dir` integration into `rama-utils`, with cross-platform support and embedded directory serving example (#665).
- OTLP HTTP metrics improvements (#383).
- Router support for defining routes without a leading slash (#664).
- New unified HTTP and SOCKS5(h) proxy connector for `EasyWebClient`, with default HTTP proxy connector fallback (#659, #668).
- `tokio-turmoil` based HTTP/1 client–server test for simulation environments (#642).
- Hot-reload (dev-only) support for the `http_sse_datastar_hello` example.
- Added support for HTTP status code 301 in `Redirect` server utilities.

### Changed

- Windows support validated across all CLI targets and CI (#674).
- Internal layering simplified with `MaybeProxiedConnection` and `MaybeLayeredService` wrappers (#670, #673, #671).
- Consistent naming change from `Websocket` to `WebSocket`.
- Improved test coverage for `http-mitm-proxy-boring`.

### Fixed

- Broken tracing when multiple layers were active (#660).
- Rust 1.89 lint errors (#661).

# 0.3.0-alpha.2

> Release date: `2025-08-05`

### Added

- ACME client support with `rama-acme` crate, including HTTP and TLS challenge examples (#603).
- Initial `rama-crypto` crate with JOSE/JWK/JWA/JWS support (#611).
- New connection pool implementation with metrics support and round-robin reuse (#636, #641).
- TCP (client) connector pool (#637).
- Support for WebSockets in fingerprinting service and `rama-ua` (#632).
- Target HTTP version enforcement (incl ext data such as `TargetHttpVersion`) (#617).
- Datastar SSE server: 100% test suite compliance (v1.0.0-RC.4)
- First anti-bot HTTP examples: infinite resource and zip bomb
- Save CONNECT (HTTP response) headers in `HttpProxyConnectResponseHeaders` (#652).

### Changed

- `HttpVersionAdapater` renamed to `HttpVersionAdapter` (#653).
- `Header` trait split into `TypedHeader`, `HeaderEncode`, and `HeaderDecode` for better usability.
- Socks example updated to correctly negotiate ALPN (#655).
- User agent parsing improvements for Safari (fixes #633).
- `HttpRequestParts` split into immutable and mutable parts (#635).

### Fixed

- Proper cleanup of idle connections before reusing in connection pool.

### Removed

- 32-bit Linux build (open for contributions).

### Addendum

- `rama-0.3.0-alpha.1` introduced a breaking change in HTTP version negotiation. If you're using a client that upgrades or downgrades HTTP versions automatically (such as when using TLS with ALPN), you must now explicitly use both `HttpsAlpnModifier` and `HttpVersionAdapter`. Refer to the examples for proper usage.

# 0.3.0-alpha.1

> Release date: `2025-07-07`

Highlights:

- WebSocket (WS) Support:
  Introduced the new `rama-ws` crate with full WebSocket support.
  Includes both client and server implementations, a CLI tool (with TUI),
  Autobahn test suite integration, and HTTP/2 support.
  Examples and documentation are included.

- SOCKS5 Support:
  Added full client and server support via the new `rama-socks5` crate.
  Includes support for framed UDP relays and integrated proxy examples.

- Observability Improvements:
  - OpenTelemetry (OTEL) tracing support via a new `opentelemetry` feature.
  - Span/trace IDs are now injected into all spans.
  - OTLP HTTP client support integrated with rama's http-client trait.
  - Centralized and improved span creation and root span macros.

- Datastar Integration:
  Datastar support is now built-in, replacing the need for an external SDK crate.
  Full SSE compatibility with integration tests and examples.

- TLS and Fingerprinting Enhancements:
  - Added support for TLS ALPS and draft GOST suites.
  - Integrated PeetPrint fingerprinting with frontend and feature flag support.

Protocol Peek Support:
  - Added HAProxy protocol detection and peek routing.
  - Socks5, TLS and HTTP also have peek support,
    allowing you to detect such traffic patterns for custom routing and handling.

- Unix Domain Socket Support:
  Added initial `rama-unix` implementation with examples and documentation.

- Expanded Example Set:
  - Multi-protocol proxy: HTTP, HTTPS, SOCKS5, and SOCKS5H with TLS and authentication.
  - HTTP MITM proxy with WebSocket and boring TLS support.
  - Proxy connectivity checking with peek routing.

Additional Changes:

- Numerous dependency updates and embedded User-Agent profile enhancements.
- Improved EasyHttpWebClientBuilder for connection pooling, DNS resolution,
  and pluggable connector layers.
- MSRV bumped to 1.88 with support for new Rust idioms like `if let` chaining.
- Cleanup of old lints and removal of unused dependencies.
- Improved common server authentication logic and CORS preflight customization.

This marks the first pre-release in the 0.3.0 series.

# 0.2.0

> Release date: `2025-05-10`

🎉 **Rama 0.2.0 is out!** After 3+ years of R\&D, countless iterations, and production-grade usage, Rama is now a solid choice for building modular, high-performance clients, servers, and proxies — all in Rust. Rama strikes a balance between flexibility and structure, with full customizability, batteries included, and a growing ecosystem of real-world adopters.

Rama is still evolving, but already powers terabytes of traffic daily across production deployments. Read the full announcement: [🎉 Rama 0.2 — 3+ Years in the Making](https://github.com/plabayo/rama/discussions/544)

In the meantime, we’ve already begun work on [0.3](https://github.com/plabayo/rama/milestone/2) — with `0.3.0-alpha.1` expected early next week. Rama is moving fast — stay in sync with the alpha train, or hop on whenever you're ready.

# 0.1.0

> Release date: `2022-09-01`

Reserve the name `rama` on crates.io and
start the R&D and design work in Rust of this project.
