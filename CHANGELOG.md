# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

# 0.3.0-alpha.4

> Release date: `2025-12-27`

This will be the last alpha release of rama 0.3.0. Besides some minor stuff there are still
two big features that we want to have done before shipping 0.3.0:

- rama-grpc: Grpc support for rama (#488; funded by one of our commercial partners);
- impl a new Uri implementation in rama-net (#724) and make use of that:
  - as the uri for Request, improving that further;
  - replace RequestContext and TransportContext with scoped traits to get
    get info such as path and Uri from input in a stateless simplified way (#724)

These changes will also unlock some other minor improvements that we still plan to do.
You can check https://github.com/plabayo/rama/milestone/2 for the full 0.3 milestone,
Note that not everything in that list will be done prior to 0.3. Some of it we will probably
drop or move to another milestone.

Once the Uri, Grpc and some other minor improvements and feature work (e.g. multi-part support)
is done we will start with release candidates (`rc`) for rama.
We plan to do 1 or 2 of these with a final `0.3` release at the end of January (2026).

Once we released rama `0.3` we plan to start doing a regular release train of six weeks.
The idea is to release whatever is in main, which will be a patch- or major release depending if we have
breaking changes or not.

### Community

Thank you to the contributors of this release: Glen De Cauwsemaecker [glen@plabayo.tech], Abdelkader Boudih [terminale@gmail.com], Nicolas Trippar [ntrippar@gmail.com], M-Kusumgar [98405247+M-Kusumgar@users.noreply.github.com], Brecht Stamper [stamper.brecht@gmail.com], Ali Tariq [raja.ali945@gmail.com], Camille Louédoc-Eyriès [clouedoc@icloud.com], sim-hash [84858164+sim-hash@users.noreply.github.com], Irfan - ئىرفان [irfanabliz914@gmail.com], Yukun Wang [airycanon@airycanon.me], hafihaf123 [misobuchta@gmail.com], Aydan Pirani [aydanpirani@gmail.com], Kenny Lau [72945813+lauk20@users.noreply.github.com], and MeerKatDev [lcampobasso@gmail.com]. We also want to extend our thanks to all the individuals in the wider ecosystem and the maintainers of the third-party crates that make this work possible.

Huge shoutout to Brecht Stamper [stamper.brecht@gmail.com] for stepping up to help maintain rama and driving major changes this release. His work was instrumental in the service and state API redesign, ACME support, TLS improvements, and Pooled Connections, among many other contributions.

### Major Architectural Refactor

#### Removal of Context

In a fundamental shift for the 0.3 milestone, the centralized `Context` type has been removed in favor of a decentralized, extension-based architecture. This aligns Rama more closely with standard Rust middleware patterns and improves flexibility for complex service stacks.

* **Context Type Removal**: The `Context` object is no longer passed through services. Data, state, and executors are now managed via **Extensions** attached directly to the `Request`, `Response`, or `Connection` (#711, #714).
* **Forked HTTP Modules**: Integrated and forked parts of the `http` crate's request/response modules into Rama to provide native support for our specific `Extension` requirements and performance optimizations (#696).
* **Extensions-First Design**: Extensions are now supported throughout `rama-http-core` for both HTTP/1.1 and HTTP/2 (#706, #727).
* **State Migration**: State management has moved from `Context` to `Extensions`. New utilities like `AddInputExtensionLayer`, `AddOutputExtensionLayer` and `IntoEndpointServiceWithState`
have been introduced to handle state injection (#685, #720).

During this process we played at some point with the concept of **Parent Extensions** (#715).
We have however simplified, the concept even further and at this point it is
a list of extensions which can be forked.

We are not yet 100% finished with this design and there will probably be some more minor changes
prior to the actual release of rama 0.3. The biggest design changes around these concepts
are however behind our back.

#### Input/Output

the `Service` trait now uses the type parameters:

- `Input`, instead of `Request`;
- `Output`, instead of `Response`;

This aligns much better with `Rama`'s future but even for its present.
For example service and layers also operate on the transport and tls layers,
where the parameter types `Request` and `Response` make no sense.

### Added

* **CLI & Tooling**:
    * **Major Refactor**: The `rama-cli` now features a restructured command hierarchy with `send` (unified HTTP/WS client), `serve`, and `probe` subcommands (#732).
    * **Stunnel Support**: Added a stunnel-like feature to `rama-cli` to support TLS tunneling use cases (#453, #629).
    * **Export to curl**: Support for exporting HTTP requests to `curl` commands directly from the CLI or via service layers (#509, #699).
    * **HAR Support**: Introduced an HTTP Archive (HAR) recorder layer to capture and export traffic for debugging (#357, #646, #694).
    * **Windows Signing**: CLI releases for Windows are now officially signed via **SignPath.io**.
    * **New CLI Features**: Added `probe tcp` command and support for the `--resolve` flag in the `send` command to override DNS for specific domains.
* **Networking & Protocols**:
    * **Discard Protocol**: Implemented **RFC 863 Discard service** for both TCP and UDP (#718).
    * **Fingerprinting**: Added **Akamai HTTP/2 passive fingerprinting** support, integrated into the fingerprinting and echo services (#517, #719).
    * **Post-Quantum Crypto**: Re-integrated **PQ encryption** support in `boring` (e.g., `X25519MLKEM768`) (#721, #722).
    * **OTLP Integration**: Added OTLP and subscriber support directly into the core `rama` crate to reduce external dependency overhead.
    * Built-in overwrite of span and trace logic to make it compatible with OTLP;
* **HTTP Features**:
    * **New Typed Headers**: Support for `X-Robots-Tag` (#382, #707), `X-Clacks-Overhead` (#620, #734), `DNT` (Do Not Track), and `Sec-GPC`.
    * **Data Streaming**: Added support for **NDJSON** (Newline Delimited JSON) and improved JSON body streaming (#703, #704).
    * **Octet-stream**: Implemented octet-stream response support (#718).
    * **HSTS**: Added an **HSTS** (HTTP Strict Transport Security) example and e2e tests (#00fff66).
    * **Redirects**: Added redirect/rewrite/forward HTTP services and layers (#717).
* **TLS & ACME**:
    * **DNS Challenges**: Support for **DNS-01 challenges** in `rama-acme` and TXT record lookups in `rama-dns`.
    * **Wildcard Support**: Added support for wildcard domains in `rama-net` and better wildcard handling in the `DynamicIssuer`.
    * **ACME Certs**: Support for downloading ACME certificates as raw PEM bytes.

### Changed

* **API Naming Conventions**:
    * Applied consistent prefixes where it helps in meaning (no need to apply these everywhere, but where it otherwise is not clear it probably is advised: `try_` (fallible), `maybe_` (optional), `set_` (`&mut self`) and `with_` (`self`). These can also be combined for example for a fallible setter: `try_set`. For Setters we also have a macro to easily define these which we also started to use and apply more (`generate_set_and_with`);
    * Renamed `AddExtension` to `AddInputExtension` and introduced `AddOutputExtension` for clearer lifecycle management (#759, #761).
* **Internal Improvements**:
    * **Performance**: Replaced standard `HashMap`/`HashSet` with faster `ahash` versions (#709).
    * **Stream Libs**: Replaced `async-stream` with `asynk-strim` for better performance and DX.
    * **Memory Management**: Updated internal usage of `SmallVec` and `SmolStr` to reduce allocations across the workspace.
      * These dependencies are also re-exported under `rama-utils`
    * **Upstream Sync**: Massive sync with upstream forks including `hyper`, `h2` (1xx informational responses support), `tungstenite`, and `tower-http`.
* **MSRV**: Bumped Rust Minimum Supported Rust Version to **1.91**.
* **EasyWebClient**: Refactored to be more explicit with `connector_builder` and support for `jit_layers`.

### Fixed

* **HTTP/2**: Fixed a critical bug in H2 emulation regarding window update replay and early frame replay (#772).
* **Compression**:
  * Fixed gzip decompression issues with empty bodies combined with trailers (synced with `tower-http` patch).
  * Also provide a **StreamCompression** version which is recommended to use for compression of streaming
    endpoints such as SSE or chunked encoding;
* **Cookies**: Implemented RFC 6265 compliance when downgrading requests from HTTP/2+ to HTTP/1.x by merging multiple Cookie headers (#768, #770).

### Removed

* **Request Inspectors**: Removed the `RequestInspector` concept; all inspection is now handled via standard services/layers (#750).
* **UDP Wrapper**: Removed the custom `UdpSocket` wrapper in favor of re-exporting `tokio::net::UdpSocket`.
* **Extension Removal**: Extensions no longer support `remove()`, ensuring a predictable "breadcrumb" trace of information (#715).
* **ErrorWithExitCode**: Removed as it was deemed unreliable for complex error propagation.

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
