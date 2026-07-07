# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

# 0.3.0

> Planned release date: `2026-07-07`

Rama 0.3.0 is here. This is a big release: the 0.3 series started with the
first alpha on `2025-07-07` and carried a long line of protocol work, API
redesign, platform hardening, and real-world proxy features all the way to this
final release.

For people coming from 0.2: expect breaking changes. The central `Context`
model is gone, service inputs and outputs have been generalized, extensions are
now the main way to carry request, response, connection and transport metadata,
and Rama owns more of its HTTP and URI surface directly. The migration cost is
real, but it buys a cleaner service model, stronger protocol fidelity, better
proxy ergonomics, and much more room for the next release trains.

This also closes the long alpha era. From here on we aim to ship regular Rama
releases on a 2 to 8 week cadence. Versioning will continue to follow SemVer
semantics.

### Community

Thank you to everyone who contributed code, reviews, documentation, testing,
bug reports, ideas, and production feedback during the 0.3 cycle. This release
includes work from Glen De Cauwsemaecker, Brecht Stamper, Abdelkader Boudih,
Nicolas Trippar, M-Kusumgar, Ali Tariq, Camille Louédoc-Eyriès, sim-hash,
Irfan - ئىرفان, Yukun Wang, hafihaf123, Aydan Pirani, Kenny Lau, MeerKatDev,
Maarten Deprez, Dominic Lindsay, Xavier Lambein, Stijn De Clercq,
Shabbir Hasan, Antoine Bernardeau, Darshil Patel, Gautham Venkataraman, FS,
Elias, Azzam S.A, Nikita, Ian Wagner, bitterpanda, Elizabeth Gonzales Belsuzarri,
0x676e67, KoHcoJlb, and everyone else who helped shape the release.

Thank you also to our GitHub Sponsors for directly funding Rama development,
and to our commercial partners for funding a significant part of the
work in this cycle. If you want to support Rama, you can become a
[GitHub Sponsor](https://github.com/sponsors/plabayo). If your organisation is
looking for a long-term partner around proxies, protocol work, support,
training, or custom integrations, see [ramaproxy.com](https://ramaproxy.com).

### Alpha Train Recap

* `0.3.0-alpha.1` (`2025-07-07`) opened the cycle with the first versions of
  `rama-ws`, `rama-socks5`, `rama-unix`, built-in Datastar support, SSE work,
  richer observability, PeetPrint and TLS fingerprinting improvements, protocol
  peek routing, and a much larger proxy example set.
* `0.3.0-alpha.2` (`2025-08-05`) added ACME support, the first `rama-crypto`
  crate with JOSE/JWK/JWA/JWS support, connection pooling, TCP connector pools,
  WebSocket fingerprinting support, target HTTP version enforcement, and the
  first anti-bot examples.
* `0.3.0-alpha.3` (`2025-08-29`) promoted Windows to tier-1, added signed
  Windows CLI releases and `winget` packaging, custom X.509 stores,
  WebSocket extensions, HTTP-to-HTTPS upgrade redirects, include-dir serving,
  router quality-of-life improvements, and the unified HTTP/SOCKS proxy
  connector path for `EasyWebClient`.
* `0.3.0-alpha.4` (`2025-12-27`) carried the main architectural refactor:
  removal of `Context`, the extensions-first design, native forked HTTP
  request/response types, service `Input`/`Output` naming, CLI restructuring,
  HAR support, stunnel support, typed headers, NDJSON, redirects, compression
  improvements, and more TLS/ACME work.

And while that was a lot already... even more happened in the 6 months after
that... While we will do our best to cover it all in this changelog, please do
always consider the code diff as the authoritative source of truth.

### Highlights

* **Extensions-first architecture**: removed the centralized `Context` type and
  moved request, response, connection, transport, state and executor metadata
  into extensions (#685, #706, #711, #714, #715, #720, #727, #856, #869,
  #873, #884, #914, #956, #1001).
* **Generalized service model**: the core `Service` APIs now speak in terms of
  `Input` and `Output` instead of HTTP-specific request/response language,
  making the same stack model fit HTTP, TCP, TLS, proxy and transport layers
  better (#747, #755, #878).
* **Native HTTP and URI foundation**: Rama now owns more of its HTTP types,
  header behavior and URI model directly, including first-class `rama-net` URI
  support, Host/Authority overhaul, path segment enrichment, query lookup and
  mutation helpers, integrated original header order/casing preservation,
  improved HTTP version conversions, and the removal of the external `http`
  crate from the core path (#696, #921, #934, #1006, #1027, #1030, #1039,
  #1045, #1046, #1048, #1059).
* **New protocol crates and gateways**: added WebSocket, gRPC, FastCGI, Unix
  sockets, SOCKS5, ACME, crypto, and Apple Network Extension (NE) support
  (Transparent Proxy only for now, more providers to follow in later versions),
  with examples and docs around real server, client, gateway and proxy use
  cases (#491, #582, #603, #611, #615, #790, #836, #875, #899).
* **Proxy and TLS depth**: expanded transparent proxy support across macOS,
  Linux and Windows, improved MITM relay behavior, certificate mirroring,
  CRL/OCSP handling, native trust-store defaults, SNI routing, protocol peeking,
  ALPS, zstd certificate compression, and Boring/Rustls configuration APIs
  (#551, #555, #567, #573, #594, #677, #834, #845, #865, #900, #903, #960,
  #966, #968, #970, #974, #1015, #1017).
* **CLI and operational tooling**: `rama-cli` now has a clearer `send`, `serve`
  and `probe` hierarchy, signed Windows releases, `winget` publication, stunnel
  use cases, curl export, HAR recording/replay, JSON selection, feed reader
  support, richer echo and fingerprinting services, and Linux/Windows/macOS
  release target improvements (#629, #683, #689, #699, #732, #798, #810,
  #955, #1043).
* **Protocol correctness and security hardening**: many fixes landed across
  HTTP/1, HTTP/2, WebSocket, SOCKS5, HAProxy, file serving, URI parsing, TLS,
  DNS, Apple NE FFI, log injection, path traversal, mTLS client authentication,
  and release supply-chain surfaces (#770, #895, #896, #913, #916, #917, #945,
  #972, #1003, #1005, #1021, #1022, #1023, #1031, #1032, #1034, #1042, #1054).

### Added

* **HTTP and Web APIs**:
  * WebSocket support in `rama-ws`, including client and server handshakes,
    per-message deflate, HTTP/2 WebSocket support, 100% Autobahn compliance,
    examples, CLI support and fingerprinting integration (#615, #632, #663,
    #672, #729, #758, #895).
  * gRPC support through `rama-grpc`, including build support, examples,
    compression tests, health checks, gRPC-Web coverage and an OTLP exporter
    path (#790, #799, #808, #815, #991, #992).
  * Streaming RSS 2.0 and Atom 1.0 support, RSS podcast helpers, strong typed
    feed URIs, six extension namespaces, lossless parse/serialize round-trips,
    and an interactive `rama-cli` feed reader (#882, #955, #962, #988).
  * `rama-json` with streaming JSON tokenization, RFC 9535 JSONPath selection,
    HTTP body capture/rewrite integration, typed JSONPath builders, CLI JSON
    selection, fuzz-style tests, and vendor/RFC coverage (#1043).
  * Multipart support, octet-stream extraction, NDJSON and streaming JSON
    processing, SSE response helpers, Datastar integration, declarative partial
    updates and HTML rewriting/tokenizing support (#576, #599, #625, #703,
    #704, #718, #888, #927, #937, #963, #1043).
  * FastCGI gateway support through `rama-fastcgi`, including HTTP adapters,
    streaming bodies, configurable caps/timeouts, CGI constants, and PHP-FPM
    TCP/Unix-socket examples that run in CI (#899).
  * More typed headers and header helpers, including `X-Robots-Tag`,
    `X-Clacks-Overhead`, WebSocket headers, HSTS preload, COEP/COOP/CORP,
    Permissions-Policy, Referrer-Policy, Content-Type, Cache-Control,
    Accept-CH and Critical-CH (#663, #707, #734, #907, #948, #953, #977).
  * HTTP QUERY method support, HTTP-to-HTTPS upgrade redirects, advanced
    redirect/rewrite/forward services, flexible upgrades, response-to-error
    helpers, bounded body collection errors, and more H2 builder settings
    (#678, #717, #806, #1025, #1009, #1051, #1056).
* **Networking and proxying**:
  * SOCKS5 client/server support, UDP associate support, HTTP/SOCKS auto
    acceptors and connectors, SNI proxy routing, HAProxy protocol peeking,
    client-side HAProxy TLV/CRC32C support, HTTP peek routing, proxy connectivity
    examples, and UDP-over-TCP examples (#491, #559, #562, #567, #592, #594,
    #659, #904, #916).
  * Connection pooling improvements, including TCP connector pools, round-robin
    reuse, metrics, health checks, connection identifiers, body-bound connection
    release, `MaxConcurrency` tracking, multiplexing connections by default for
    `EasyHttpWebClient`, and safer broken/idle connection handling (#571, #580,
    #584, #636, #637, #641, #780, #868, #892, #909, #1044).
  * Transparent proxy support for Apple Network Extension, Linux and Windows,
    plus XPC support, system keychain integration, Swift/C FFI support, flow
    metadata propagation, wake-from-sleep handling, memory improvements and
    extensive hardening (#836, #865, #875, #881, #887, #905, #924, #950, #954,
    #965, #971, #973, #1026).
  * DNS improvements including custom/system/native resolvers, TXT lookups,
    DNS load balancing, resolver cache/picker hooks, Apple native DNS,
    `res_nsearch` (Linux), Windows native DNS, FQDN fixes and resolver hardening
    (#568, #702, #788, #833, #854, #912, #922, #923).
  * IP geolocation support, and also integrated in the IP, echo and
    fingerprinting services (#994).
* **TLS, crypto and fingerprinting**:
  * ACME HTTP/TLS challenges, DNS-01 challenge support and dynamic issuer
    improvements (#603, #702).
  * `rama-crypto` with JOSE/JWK/JWA/JWS support and optional `aws-lc-rs`
    integration (#611, #650, #847).
  * TLS ALPS support, draft GOST suites, new ALPS codepoint support, zstd
    certificate compression, native trust-store defaults, improved Windows
    certificate loading, and Boring/Rustls config refactors (#554, #555, #573,
    #805, #812, #834, #961, #966, #970).
  * PeetPrint, Akamai HTTP/2 passive fingerprinting, JA4 refactors, fingerprint
    service improvements, and redaction of fingerprint storage secrets (#585,
    #607, #719, #919, #981, #1028).
  * TLS close-notify error handling, MITM certificate mirroring, AKI/SKI
    handling, OCSP stapling, proxy-hosted CRL/OCSP revocation and better Boring
    relay issue classification (#900, #903, #920, #968, #974, #1017, #1018).
  * Shared TLS foundations moved into `rama-tls`, including client hello parsing,
    SNI helpers, TLS fingerprinting, keylog support and common client/server
    configuration building blocks (#1006, #1010, #1015).
* **Core utilities and platform support**:
  * `rama-unix`, Unix FD helpers, FD limit utilities, `include_dir`
    integration, safe filesystem helpers, append-only collections (used also
    for the new and improved `Extensions` type), non-empty collection utilities,
    octet and duration helpers, byte/string search helpers,
    `BoxErrorExt`, `CountInput`, `BytesRWTracker`, reactive values, owned IO
    buffer traits for completion-based IO and no-std-compatible subsets of
    `rama`, `rama-error`, `rama-macros` `rama-core` and `rama-net`
    (#582, #665, #776, #809, #823, #824, #827, #842, #872, #967, #997, #1037, #1047).
  * Apple XPC support and Secure Enclave integration for the Network Extension
    system-extension path, including Rust XPC primitives and Swift packages used
    by the transparent proxy example (#875).
  * Linux ARM64/AMD64 MUSL first-tier release targets, Windows tier-1 support,
    Windows ARM CI/release support, signed Windows binaries, `winget`
    publication, vendored `protoc`, nextest-based testing and improved CI
    hardening (#674, #683, #689, #765, #797, #798, #799, #800, #925, #976,
    #1000, #1031).
  * New benchmarking and simulation coverage, including end-to-end HTTP
    client/server benchmarks, TLS/proxy benchmark dimensions and a
    `tokio-turmoil` HTTP/1 client/server test (#642, #766, #816, #818, #832).
  * New docs, book chapters and examples for protocol inspection, proxies,
    SNI/TLS, SOCKS5, WebSocket, gRPC, HAR, RSS, FastCGI, multipart, SSE,
    Datastar, transparent proxy operation, XPC and platform setup (#552, #810,
    #875, #888, #899, #952).
    * This also includes a first attempt on chapters to help proxy operators
      of more "advanced" proxy use cases. Feedback welcome.

### Changed

* **State, extensions and services**:
  * Removed `Context` from the service flow and moved state/executor metadata
    into extensions; `AddExtension`/`GetExtension` became
    `AddInputExtension`/`GetInputExtension`, with output equivalents for output
    lifecycles (#685, #711, #714, #720, #759, #761, #794).
  * Extensions are append-only breadcrumbs with trait tags, custom `Debug`,
    ranked extraction, multi-extraction in a single pass, and better support
    around WebSocket upgrades and connection data (#715, #758, #811, #856,
    #869, #873, #884, #914, #956, #1001).
  * HTTP services became generic over output and error types, and service
    terminology moved from request/response to input/output (#747, #755, #878).
* **HTTP internals**:
  * Forked and integrated key `http`, `headers`, `http-body`, `hyper`, `h2`,
    `tungstenite` and `tower-http` pieces to support Rama's extension,
    protocol and fingerprinting needs while continuing to sync upstream fixes
    (#696, #897, #938, #939, #940, #941, #975, #1053).
  * Header maps preserve original HTTP order/casing better and fixed ordered
    multi-value removal (#1045, #1055).
  * Router APIs were improved, including slashless routes, 405 + `Allow`
    handling, infallible path pattern matching and route rebuilds (#664, #741,
    #844, #1027).
* **Client, TLS and proxy APIs**:
  * `EasyHttpWebClientBuilder` and `HttpClientExt` were made more granular and
    flexible, with better custom DNS, connector, proxy and JIT layer support
    (#571, #591, #659, #668, #820).
  * Boring and Rustls client/server TLS config types were refactored into
    clearer extension/config pieces; server TLS now uses `TlsServerConfig`
    similar to clients, and certificate generation moved into `rama-crypto`
    with rcgen/aws-lc/boring feature paths (#961, #970, #1015).
  * TCP client request types moved into `rama-net`, and DNS became optional
    in `rama-socks5` and was completely removed from `rama-tcp` and `rama-udp`
    (#1013, #1041).
  * Runtime time handling moved toward `jiff`, and several utility helpers were
    moved or promoted into `rama-utils` (#825, #853, #990).
* **Versioning and support**:
  * MSRV is now Rust `1.96.0` and the workspace uses Rust 2024 edition (#1050).
  * 32-bit Linux binary releases were dropped during the alpha cycle, while
    Windows, Windows ARM and Linux MUSL release coverage were expanded (#626,
    #765, #798).

### Fixed

* Fixed HTTP/2 correctness bugs including early frame replay, early connection
  `WINDOW_UPDATE` replay, H2 trailer/settings conformance, H2 settings mirroring
  in MITM relay, H2 `SETTINGS`-driven concurrency updates, and H2 WebSocket edge
  cases (#607, #770, #946, #1044, #1054).
* Fixed RFC 6265 cookie merging when adapting HTTP/2/3 requests to HTTP/1.x
  (#770).
* Fixed WebSocket and SOCKS5 security/correctness gaps and deflaked MITM relay
  timing tests (#895, #896, #999).
* Fixed file serving XSS in directory listings and hardened include-dir
  extraction, symlink handling, `file://` and octet-stream path handling, plus
  client/file-serving edge cases (#945, #1003, #1023, #1032).
* Fixed URI, authority, domain, user-info, IPv4-mapped IPv6 and path component
  safety issues (#902, #921, #972, #1011, #1030).
* Fixed Boring TLS MITM SNI handling, certificate mirroring, trust-store parsing
  on acceptors, mTLS client-auth enforcement, revocation behavior for
  schannel/libcurl clients and close-notify behavior (#968, #969, #974, #1002,
  #1017, #1018, #1034).
* Fixed Apple Network Extension lifecycle, FFI, wake-from-sleep, promoted-flow,
  memory, unsafe metadata and XPC listener edge cases (#887, #893, #924, #947,
  #950, #954, #965, #971, #973, #1005, #1042, #1059).
* Fixed tracing with multiple layers, span/event scoping, HTTP span attributes,
  OTLP exporter runtime/log support, and log-injection hardening (#597, #604,
  #660, #802, #804, #837, #838, #898, #901, #917).
* Fixed DNS resolver behavior, including FQDN handling and resolver
  implementation details (#788, #912, #922).
* Fixed CLI, release, CI and docs issues across Windows signing, Windows runner
  stability, cargo fetching, pinned GitHub Actions/cross releases, non-root
  Docker images, mdbook, lychee, docs.rs builds and contributor onboarding
  (#689, #797, #889, #925, #935, #976, #1000, #1021, #1022, #1031, #1053,
  #1058).

### Removed

* Removed the central `Context` type from public service flow in favor of
  extensions (#711, #714).
* Removed request inspectors and moved inspection/customization into regular
  services, layers and connector configuration (#730, #750).
* Removed extension `remove()` semantics so extensions behave as append-only
  breadcrumbs (#715).
* Removed the legacy Boring `ClientConfig` in favor of the clearer
  `TlsClientConfig` API (#970), a similar change happened for server as well.
* Removed the `http` crate from Rama's core URI/HTTP type path and migrated URI
  imports into `rama-net` (#1006, #1048).

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
* **MSRV**: Bumped Rust Minimum Supported Rust Version to **1.96**.
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
