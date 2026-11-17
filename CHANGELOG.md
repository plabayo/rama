# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

# 0.5.0

> Release date: `2026-11-17`

In the 0.5.0 release, Rama adds support for QUIC, h3 (HTTP/3) and MASQUE
proxies. It was tracked as issue #14 since December 2023, and we now support it
for clients, servers and proxies (incl. peek and relay support). The existing
HTTP types `Request`, `Response` and `Body` are used for h3, just like they work
for HTTP/1 and h2. You can connect to h3 servers by use of prior knowledge (e.g.
setting the `TargetHttpVersion`) or by making use of the Alt-Svc and DNS HTTPS
discovery support that is now also available for your own network stacks as
well as built into the `EasyHttpWebClient`.

On top of that foundation comes MASQUE, with the new `rama-masque` crate: proxying
UDP (CONNECT-UDP) and IP (CONNECT-IP) over HTTP/1.1, HTTP/2 and HTTP/3, a
CONNECT-UDP proxy hardened for untrusted networks, a MITM relay for MASQUE
sessions, and CLI support to serve and use CONNECT-UDP proxies. Encrypted Client
Hello (ECH) is supported on BoringSSL clients and servers, over TCP and QUIC.

User-agent emulation was redesigned around a new profile system. Profiles are
captured from real browsers and retain counted observations and bounded samples
of the variants a browser sends (header orders, TLS extension orders, SETTINGS).
They cover QUIC (incl. TLS), ECH and HTTP/3 next to TLS-over-TCP, HTTP/1.1 and
HTTP/2, and ship as a precompiled embedded set. The public fingerprinting
services expose the matching QUIC and HTTP/3 data.

Graceful shutdown was rebuilt as well. Rama's own scopes replace the `Executor`
and the `tokio-graceful` guards: a scope is cancelled to drain and aborted to
stop, and every server, client and relay takes one. This is the breaking change
most existing (rama user) code will have to adapt to.

The `rama` CLI proxy grew into an interception tool with a live web inspector,
interception rules and a scriptable API, backed by the new `rama-inspect` crate.
This cycle also adds ICAP (`rama-icap`), the `rama inspect` TUI for HAR and qlog
files, platform TLS verification, staged client authentication for the TLS MITM
relay, a rebuilt HTTP client connection pool, and a stabilised Apple Network
Extension transparent proxy.

Please read **Breaking API Changes** before upgrading, and
**Migrating from User-Agent Emulation to Profiles** if you use `rama::ua`. As
always, this changelog calls out the user-visible work; the code diff is the
authoritative source of truth.

### Community

Thank you to everyone who contributed code, reviews, documentation, testing,
bug reports, ideas, and production feedback during the 0.5 cycle. This release
includes work from Glen De Cauwsemaecker, Brecht Stamper, Abdelkader Boudih,
Maarten Deprez, Julián Montes de Oca, Attila Nagy, Ivan Porto Carrero, and Yann
(yfe404). Thank you also to Tudor Timcu for the field report and proposed fix
behind the Apple Network Extension sleep/wake recovery work (#1308, #1309),
Attila Nagy for reporting the DNS burst overflow (#1218), Ivan Porto Carrero
for the mTLS use cases behind staged client authentication (#1200), Yann for
reporting the missing `trust_anchors` extension (#1195), and Maarten Deprez for
reporting the missing `ExtensionsRef` forwarding (#1306).

Rama also builds on the work of the upstream projects it maintains forks or
ports of. Four sync rounds this cycle (#1139, #1241, #1298, #1318, and the h2
sync in #1239) brought in fixes from hyper, h2, h3, http, http-body,
http-body-util, hyper-util, headers, tower-http, axum, tonic, tungstenite,
lol-html, quinn, quinn-udp, and rustls-native-certs, credited in those commits
to: 0x676e67,
Aaron Todd, Aashish Thapa, aiqubits, Alex (ragen1337), Alex Butler, Alexander
(AlexanderHD27), Alexander Kjäll, Almaz, Andrea Bozzo, Andrei Gheorghe, André
Cruz, Ariel Ben-Yehuda, Benjamin Saunders, Bill Fraser, Breeze, brentechols,
Brian Schroeder, Bugen Zhao, Chen Hongzhi, Choudhry Shehryar, ChrisJr404,
Christoph Sens, cui (cuiweixie), cui fliter, CyberneticX-Tech, Dahale Aditya
Dnyaneshwar, Dan Bondarenko, darkuss, David Mládek, David Pedersen, David
Tolnay, Denis Cornehl, Dihan Nahdi, Diogo Sousa, Dirkjan Ochtman, Dmitry
Adamushka, Dmitry B., Dmitry Marakasov, Dominic Rubas, dox4, dswij, Endale
Dinh, Erick Tryzelaar, Evgenii Shutov, f3ath, Falk Woldmann Lu, Feldt, Florian
Uekermann, Frank Taylor, Gavin D., Ignacio Goldchluk, Jacob Thrane Lund,
jaeminbird, Jaideep Pyne, James (jg-rp), Jan (Threated), Jayakumar Thanakodi,
Jeremy Schoemaker, jeremyjpj0916, Jess Izen, Jindřich Bär, Joey de Waal, Jonas
Platte, Joseph Dye, K-tecchan, karanabe, katelyn martin, kaze, Lars Eggert,
Laurence Rowe, Leo Camus, Lethe Lee, LoadingALIAS, Lorenz Leutgeb, Lucio
Franco, Luke Curley, Luke Parker, Martin Trigaux, Mathieu (4Mathleu), Mathieu
Tricoire, Max Inden, Minh Vu, Mira Sato, Muhamad Awad, Muhammed Çiçekel,
Nakaryo, Nanasi, Nathan Jaremko, Nathaniel Ford, Nor.na, Paolo Barbolini,
Patrick Hintermayer, Patrik Wenger, PeterUlb, Phoenix K, Reiner Pope, Robert
Kiel, ruben (Ruben2424), Rémi Berson, Sabnock, Sai Asish Y, Sam Hitz, Sean
Lynch, Sean McArthur, Seungtaek Oh, Shai (Shaisolaris), shodoco, Shuvro Roy,
subotac, syszery, t0ms, tangaac, Temporary Fix, Thomas Eizinger, Tim Vilgot
Mikael Fredenberg, Tobias Bieniek, Toshit Chawda, tottoto, Toyeshh Medikonda,
Trivikram Kamat, ump45nose, Vaibhav Srivastava, Vaiz, vcarus, vishal-770, vk
(kv-cache), vvvviiv, WaterWhisperer, xd009642, Yann Simon, Yusuke Tanaka,
zerox80, Árni Dagur, Örjan Fors, and 赤坂理子.

Thank you also to our GitHub Sponsors for directly funding Rama development,
and to our commercial partners for funding a significant part of the work in
this cycle. If you want to support Rama, you can become a
[GitHub Sponsor](https://github.com/sponsors/plabayo). If your organisation is
looking for a long-term partner around proxies, protocol work, support,
training, or custom integrations, see [ramaproxy.com](https://ramaproxy.com).

### Highlights

* **Native QUIC transport**: `rama-quic` is a Rama-owned QUIC v1 and v2 stack
  on BoringSSL or Rustls with 0-RTT, connection migration and qlog, checked
  against the QUIC interop runner as client and server; `rama-quic-proto` holds
  the engine-free wire layer (#1172, #1182, #1191, #1281, #1337, #1345).
* **HTTP/3**: a Rama-native HTTP/3 and QPACK engine behind the usual Rama
  types, with Alt-Svc and DNS HTTPS discovery in the default client, Extended
  CONNECT, WebSockets and HTTP datagrams over HTTP/2 and HTTP/3, early data with
  `425` recovery, and HTTP/3 in `rama serve` and the public services (#1192,
  #1198, #1228, #1232, #1304, #1350).
* **MASQUE**: `rama-masque` proxies UDP (CONNECT-UDP) and IP (CONNECT-IP) over
  HTTP/1.1, HTTP/2 and HTTP/3, with a CONNECT-UDP proxy that denies private
  destinations by default and enforces per-principal limits, and CLI support on
  both ends (#1274, #1277, #1287, #1295).
* **Encrypted Client Hello**: BoringSSL clients offer real ECH from DNS HTTPS
  records or preknowledge, over TCP and QUIC, with one authenticated retry;
  servers accept it with reloadable keys, and profiles capture and replay it
  (#1350, #1354).
* **Graceful scopes**: `Scope` and `WeakScope` replace `Executor` and the
  `tokio-graceful` guards with a cancellation tree that drains first and aborts
  second, used by every server, client, pool and relay (#1317, #1330, #1335).
* **Browser profiles**: emulation moved to `ProfileEmulateLayer` and counted,
  multi-variant profiles that cover QUIC, ECH and HTTP/3, ship as a compiled
  embedded set, and are managed with `rama ua` (#1234, #1258, #1282, #1286,
  #1313, #1320, #1354).
* **Interactive MITM proxy**: `rama serve proxy --mitm` serves a live inspector
  with capture, export, interception rules and a scriptable API, built on the
  new `rama-inspect` crate; `rama inspect` views HAR and qlog files (#1135,
  #1160, #1163, #1175).
* **ICAP**: `rama-icap` adds an ICAP client, server and HTTP adaptation layer,
  `rama serve icap` and `--icap` in the proxy (#1136, #1142, #1143).
* **Trust and TLS fidelity**: platform certificate verification, SPKI deny
  lists, staged client authentication in the TLS MITM relay, closer BoringSSL
  ClientHello replay, and reassembly of fragmented ClientHellos (#1209, #1234,
  #1276, #1303, #1313).
* **Protocol hardening**: one header limit and strict field validation across
  HTTP/1.1, HTTP/2 and HTTP/3, adaptive server deadlines, panic-free header
  decoding, bounded decompression and multipart, and a safety proof for every
  `unsafe` block (#1217, #1241, #1291, #1321, #1340, #1355).
* **Foundations**: a rebuilt client connection pool, constant-time `Extensions`
  forks with connection-scoped values for tunnels, richer errors, and peeking
  that judges both sides of a connection without timers (#1239, #1305, #1331,
  #1351).
* **Apple Network Extension**: bounded memory, fail-open refusals, explicit
  egress proxy policy, intact large uploads, and flow recovery across sleep/wake
  (#1153, #1159, #1243, #1272, #1309).

### Getting Started with QUIC, HTTP/3 and MASQUE

* **Cargo features**: enable `quic` on the `rama` crate together with a QUIC
  capable TLS backend: `boring`, or `rustls` with `ring` or `aws-lc`. The
  `http-full` feature now includes `quic` and `masque`, so `http-full` plus
  `boring` (or `rustls` and `ring`) is enough for HTTP/3 and MASQUE. The engine
  lives at `rama::quic` (wire types at `rama::quic::proto`), the HTTP/3 engine
  at `rama::http::core::h3` and MASQUE at `rama::proxy::masque`.
* **Client**: with those features, `EasyHttpWebClient::default()` discovers
  HTTP/3 from DNS HTTPS records and `Alt-Svc`, and falls back to the origin
  connection when an alternative fails. Set `.version(Version::HTTP_3)` on a
  request to require HTTP/3 without fallback. Custom stacks add HTTP/3 with
  `Http3Connector::builder(scope)` and
  `EasyHttpConnectorBuilder::with_http3_support(connector)`, and opt out of
  discovery with `.without_https_discovery()` and `.without_alt_svc()`.
* **Server**: `HttpServer::new_http3(scope)` serves a normal Rama HTTP service
  on a `rama::quic::Endpoint` (`ServerConfig::try_from_rama_tls` builds the QUIC
  server config from a Rama TLS server config with the `h3` ALPN). Serve
  HTTP/1.1 and HTTP/2 on TCP as before and advertise HTTP/3 with an `Alt-Svc`
  response header (`AltSvc`, `AlternativeService`).
* **Examples** (`cargo run -p rama-examples --bin <name> --features ...`):
  `quic_client_server` and `quic_terminating_relay` (`quic` plus a backend),
  `http3_client_server`, `ws_over_h3`, `http_datagram_echo` and
  `http_early_data` (`http-full` plus a backend), `http_version_proxy`,
  `quic_h3_mitm_proxy`, `masque_connect_udp_proxy` and `http_ech_preknowledge`
  (`http-full,boring`), and `http_https_discovery_custom_resolver`
  (`http-full,boring,dns-hickory`).
* **CLI**: `rama send --http3 https://echo.ramaproxy.org` requires HTTP/3, and
  `rama send --http3 wss://...` runs a WebSocket over HTTP/3. Without `--http3`,
  `rama send` may still select HTTP/3 through discovery; `--no-alt-svc` turns
  Alt-Svc off. `rama serve echo|fp|http-test|ip` serve HTTP/3 next to HTTP/1.1
  and HTTP/2 whenever TLS is enabled (`--http-version`, `--h3-bind`). The public
  `echo`, `ipv4`, `http-test` and `fp` services at `ramaproxy.org` speak HTTP/3.
* **MASQUE**: `rama serve proxy --bind 127.0.0.1:8443 --protocol masque` serves
  a CONNECT-UDP proxy, and
  `rama send --http3 -x masque://127.0.0.1:8443 --proxy-insecure <URL>` sends an
  HTTP/3 request through it. `--proxy-insecure` is only needed because that
  local proxy generates its own certificate; use `--proxy-cacert FILE` or a
  trusted certificate otherwise. In Rust, start from
  `rama::proxy::masque::connect_udp` (`ConnectUdpService` to serve,
  `ConnectUdpConnector` to open tunnels as UDP sockets) or
  `DefaultHttpWebClient::default_masque_with_scope` for web requests through a
  `masque://` proxy.
* **ECH**: the default client with BoringSSL offers real ECH when the HTTPS
  record of an origin carries a configuration, and reports the outcome as
  `TlsEchAccepted`. Use `EchRequirement::Required` to fail instead of connecting
  without it, and `TlsClientConfig::with_encrypted_client_hello(false)` to turn
  it off. Servers install keys with `with_ech_keys`; `rama serve echo|fp` read
  them from `RAMA_TLS_ECH_KEYS_FILE`.
* **Docs**: the book has chapters on [QUIC](https://ramaproxy.org/book/quic.html),
  [HTTP/3](https://ramaproxy.org/book/http/http3.html),
  [HTTP clients](https://ramaproxy.org/book/http/http_clients.html) (Alt-Svc,
  HTTPS discovery and ECH),
  [early data](https://ramaproxy.org/book/http/early_data.html),
  [MASQUE](https://ramaproxy.org/book/proxies/masque.html) and
  [QUIC MITM across changing flows](https://ramaproxy.org/book/proxies/quic_migration.html).
  `rama-quic/README.md` documents backends, handshake budgets and benchmarks.
* **Current limits**: WebTransport is not supported yet. Server push exists only
  in the low-level HTTP/3 engine (off by default) and relays refuse it. Alt-Svc
  entries are kept in memory only, and named-proxy routes skip HTTPS discovery
  unless asked. Real (inner) ECH needs BoringSSL. The CLI serves CONNECT-UDP
  only; CONNECT-IP is a library API without a platform TUN integration (planned
  for the next release). A Rustls QUIC client offers a single QUIC version
  (BoringSSL clients can negotiate up to QUIC v2 mid-handshake). Early data is
  sent and accepted natively over QUIC and HTTP/3 only.

### Recommendations

* **Plan the move to graceful scopes first**: every constructor that took an
  `Executor` now takes a scope, so this touches most applications. Create one
  root `Scope`, pass `WeakScope`s to servers and clients, bound a connection's
  lifetime with `ScopeLayer` (instead of `TimeoutLayer`), and finish with
  `scope.join()`. The
  [graceful shutdown](https://ramaproxy.org/book/intro/graceful.html) chapter
  walks through it (#1317).
* **Pick your features deliberately**: `http-full` now builds QUIC, HTTP/3
  and MASQUE, and no longer includes user-agent support. Add `ua` (or
  `ua-embed-profiles` for the embedded profile set) when you use `rama::ua`. If
  you want an HTTP stack without QUIC, start from `http-backend` plus `tcp`,
  `dns` and a TLS backend instead of `http-full` (#1258, #1293).
* **Decide what a client may reveal and link**: like a browser,
  `DefaultHttpWebClient` looks up DNS HTTPS records, learns alternative
  services and resumes TLS sessions (with BoringSSL also over TCP), which lets
  servers link connections made by one client. Use
  `.without_https_discovery()`, `.without_alt_svc()` or a client without a
  session store where that matters (#1198, #1234, #1350).
* **Add the response headers you rely on**: servers no longer add `Date` on
  their own. Wrap services that should send `Date` and `Server` in
  `AddRequiredResponseHeadersLayer` (#1355).
* **Configure `Forwarded` for your deployment**: client information is now read
  from the nearest (rightmost) hop by default, the safe choice when the
  leftmost values are client-supplied. Behind a known chain of proxies, install
  a `ForwardedSelectionPolicy` with `with_hops` or `with_trusted_proxies`; with
  trusted proxies, forwarding headers only count when the connection's peer is
  one of them (#1228, #1340).
* **Make strict SNI routing strict**: for routing that must not be bypassed,
  combine `MalformedTlsPolicy::Reject` with `PeekPolicy::FAIL_CLOSED` on
  `PeekTlsClientHelloService` / `SniRouter`, and bound how long a silent client
  may hold the connection through its scope, since peeking no longer has a
  timeout of its own. QUIC ClientHello peeking defaults to best-effort
  passthrough; select `QuicPeekFallbackPolicy::NOT_QUIC` when unparseable QUIC
  must not reach the fallback (#1303, #1331).
* **Keep MASQUE destinations scoped**: the default `DestinationScopePolicy`
  refuses loopback, private, link-local and other special-purpose ranges, and
  the proxy's own address. Only open them (`--masque-allow-private`, or explicit
  `ConnectUdpRules`) for the networks you intend to expose, and set
  `TunnelLimits` per principal on shared proxies (#1287).
* **Only send early data you can replay**: HTTP early data stays off unless
  enabled, and clients only send safe, bodyless requests early. On servers, use
  `require_confirmed` for routes that are not replay-safe: it waits for the
  current hop's handshake to confirm and answers `425 Too Early` when exposure
  was inherited from an earlier hop. Gateways use `forward_to` with the selected
  origin's early-data capability (#1304).
* **Bound the platform verifier**: OS verification can block on network
  fetches (revocation, intermediate fetching) and cannot be cancelled. Size the
  blocking pool and bound concurrent handshakes accordingly (#1276).
* **Load profile databases once**: the embedded profile set takes a noticeable
  amount of memory when decoded. Build one `UserAgentDatabase` and share it as
  an `Arc` across layers and clients (#1282).

### Breaking API Changes

Rama remains below 1.0, so a `0.x` minor release may change public APIs. The
items below are the main migration points, ordered roughly by how many users
they affect. They are not an exhaustive symbol-by-symbol inventory; users with
a broad public-API footprint should also inspect the `rama-0.4.0..rama-0.5.0`
diff once the release tag is published. The minimum supported Rust version
stays at 1.96 and the edition at 2024.

* **Graceful scopes replace `Executor`**: `rama::rt::Executor` and the
  `tokio-graceful` re-exports in `rama::graceful` (`Shutdown`, `ShutdownGuard`)
  are gone. `rama::graceful::Scope` is a cancellation tree with a graceful
  phase (cancelled: stop taking work and drain) and a hard phase (aborted: drop
  what still runs); a `WeakScope` observes a scope without keeping its drain
  open. Every API that took an `Executor` now takes `impl Into<WeakScope>`:
  `HttpServer::auto`, `TcpListener::bind_address`,
  `with_default_http_connector`, `IoForwardService::new`, the upgrade and MITM
  relay layers, the SOCKS5 acceptor, and the Apple Network Extension handler
  hooks. `*_with_executor`
  and `default_with_exec` constructors became `*_with_scope`. To migrate,
  replace `Shutdown::default()` and `Executor::graceful(guard)` with
  `Scope::new().with_default_signal().with_grace(..)`, hand `scope.clone_weak()`
  to servers and clients, spawn with `scope.spawn_task(..)`, and end with
  `scope.join().await`. Use `WeakScope::detached()` where `Executor::default()`
  was used, `ScopeLayer` (`with_max_age`, `with_grace`) to bound a connection,
  `spawn_task_to_completion` for work that must finish, and `rama::rt::spawn`
  for detached tasks; `spawn_task` now yields `None` when the hard phase drops
  the task. `GracefulIo` and `CancelIo` became `AbortableIo` (#1317, #1330,
  #1335).
* **Cargo features**: `http` no longer enables `ua`, and `http-full` no longer
  enables `ua-embed-profiles`; add those features explicitly when you use
  `rama::ua` or the embedded profiles. `http-full` now enables `quic` and
  `masque`. The `rama-net` crate lost its `http` feature (its HTTP helpers only
  need `std`) and its `venndb` feature, `rama_net::test_utils` needs the new
  `test-utils` feature, and `multipart` no longer enables `hyperium`.
  `rama::http::server` and the backend parts of `rama::http::proxy` only need
  `http-backend` (#1146, #1188, #1258, #1293, #1328, #1348).
* **User-agent emulation**: `UserAgentEmulate*` became `ProfileEmulate*` on a
  new profile model; see **Migrating from User-Agent Emulation to Profiles**
  below (#1258, #1282).
* **HTTP client pool**: `EasyHttpConnectorBuilder::try_with_connection_pool`
  became the infallible `with_connection_pool`. `HttpPooledConnectorConfig`
  replaced `max_total` and `max_concurrent_streams` with optional
  `NonZeroUsize` limits (`max_connections_total`, `max_streams_per_connection`,
  `max_connections_per_id`, `max_idle_per_id`, `max_idle_total`,
  `max_connecting_per_id`) plus `saturation_policy`, `max_wait_before_dial` and
  `http1_body_drain`, and `build_default_connector`/`try_build_connector` became
  `build_connector`, `build_connector_with_identifier` and `build_pool`.
  `MultiplexPool::new()` takes no arguments (use its builder methods), custom
  `Pool` implementations gain `abandon` plus `input`/`deadline` arguments, and
  `ConnID` now requires `Eq + Hash`. `BasicHttpConnIdentifier`/`BasicHttpConId`
  became `HttpConnIdentifier`/`HttpConnId`, with a protocol-agnostic
  `rama_net::client::pool::{BasicConnIdentifier, BasicConnId}` beside them.
  Defaults changed too: no total cap (0.4 capped the pool at 50 connections
  across all origins), streams per connection decided by the peer, a 90 s idle
  timeout (was 300 s), and abandoned HTTP/1 bodies are drained for reuse (#1142,
  #1146, #1176, #1239, #1254).
* **Default web client behaviour**: clients built through
  `EasyHttpConnectorBuilder` learn `Alt-Svc` advertisements and, with `quic`,
  look up DNS HTTPS records, and may use an alternative service for HTTPS
  requests; opt out with `.without_alt_svc()` and `.without_https_discovery()`.
  `DefaultHttpWebClient` also configures HTTP/3 when `quic` and a QUIC-capable
  TLS backend are enabled (now the case for `http-full` plus `boring`, or
  `rustls` with `ring` or `aws-lc`), resumes TLS sessions, and with BoringSSL
  offers ECH when a record carries a configuration. Custom builders install
  HTTP/3 with `with_http3_support` or `with_http3_connector`. The
  `DefaultHttpWebClient` type alias changed accordingly (#1198, #1234, #1350).
* **No automatic `Date` header**: HTTP/1.1, HTTP/2 and HTTP/3 servers relay
  responses as written and no longer add `Date`; `auto_date_header` was removed.
  Add `AddRequiredResponseHeadersLayer` (it adds `Date` and `Server` when
  missing) or your own layer (#1355).
* **HTTP limits and validation**: received headers share one default limit of
  1 MiB and 4096 fields on HTTP/1.1, HTTP/2 and HTTP/3, answered with `431`
  when exceeded (0.4 allowed 100 fields on HTTP/1.1 and a 16 KiB list on
  HTTP/2). Invalid field names and values make a message malformed on every
  version, and on HTTP/2 and HTTP/3 a field value with leading or trailing
  whitespace is answered `400` and reset. `max_local_error_reset_streams` became
  `refused_stream_budget(Option<RateBudget>)`, by default a burst of 1000
  regained at 33 per second; `RateBudget::lifetime(1024)` approximates the old
  count. SSE and NDJSON decoders cap a line at 16 MiB by default
  (`without_max_line_len`, `without_max_event_len`, `without_max_line_bytes` to
  lift it) (#1340, #1355).
* **HTTP server deadlines**: HTTP/1.1 and HTTP/2 servers now apply an adaptive
  header-read deadline (`HeaderReadTimeout`: 10 s grace, then a 256 B/s floor up
  to a 60 s ceiling) and an idle deadline (`IdleTimeout`: 10 s before the first
  request, 90 s between requests) by default. `header_read_timeout` takes
  `Option<HeaderReadTimeout>` instead of a `Duration`; pass `None` to disable,
  and use `idle_timeout(..)` to change how long an unused connection may stay
  open between requests. Open requests, streamed responses, WebSockets and
  tunnels pause the idle clock (#1241, #1297).
* **Peeking without timeouts**: `PeekTimeoutPolicy`, `with_peek_timeout` and
  `with_peek_timeout_policy` were removed from `PeekRouter`, `TlsPeekRouter`,
  `PeekTlsClientHelloService`, `SniRouter`, `Socks5PeekRouter` and
  `HttpPeekRouter`, together with the `HttpPeekConfig` timeout fields and the
  `peek_input_until*` helpers. A waiting peek now ends when the input's scope
  is cancelled or aborted, or when the other side of a bridge cuts it, and a
  `PeekPolicy` (`FAIL_OPEN` by default, `FAIL_CLOSED` where 0.4 used
  `PeekTimeoutPolicy::FailClosed`) decides between fallback and failure. Drop
  the timeout and bound the connection's scope instead. `SniRouter` is built on
  `PeekTlsClientHelloService` and hands handlers the peeked input, and custom
  `PeekIoProvider` implementations expose both sides (`peek_ios_mut`) (#1324,
  #1331, #1355).
* **Connection-scoped extensions**: a CONNECT, SOCKS5 or CONNECT-UDP tunnel is
  a nested connection, on clients and servers. Values scoped to a connection,
  such as `SecureTransport`, `NegotiatedTlsParameters`, `TargetHttpVersion`,
  `MaxConcurrency` and `EstablishedProxyRoute`, no longer resolve from inside
  the tunnel, so facts about the proxy hop stop answering for the tunnelled
  connection. Read the hop with `Extensions::outer_connection()`, or carry a
  value across with `with_nested_connection_transfer(..)`. Your own types opt in
  with `#[extension(scope(connection))]` (#1351, by Brecht Stamper; #1355).
* **`Forwarded` client information**: the `Forwarded::client_*` accessors
  became the `ForwardedClientExt` extension trait (`forwarded_client_ip()`,
  `forwarded_client_socket_addr()`, ...) available on anything with extensions,
  and the default now reads the nearest (rightmost) hop instead of the leftmost.
  Use `Forwarded::client(&policy)` or install a `ForwardedSelectionPolicy` to
  pick another side or trust a known number of proxies. `XForwardedHost` and
  `XForwardedProto` now hold every value (`into_protocols()` replaces
  `into_protocol()`) (#1228).
* **Proxy credentials and hop-by-hop headers**: `SetProxyAuthHttpHeaderLayer`
  and its service were removed. The HTTP connector now inserts
  `Proxy-Authorization` only on an established HTTP forward-proxy route and
  strips it elsewhere; `with_forward_proxy_auth(false)` disables the insertion,
  while credentials are still stripped on other routes. Custom proxy connectors
  must publish `EstablishedProxyRoute` in the established connection's
  extensions, and intermediaries should set
  `with_isolate_forward_proxy_auth_error(true)` on their egress client.
  `RemoveRequestHeaderLayer::hop_by_hop()` and its response counterpart no
  longer remove `Proxy-Authorization`/`Proxy-Authenticate` (use the new
  `proxy_auth()` modes) and re-originate `TE: trailers` and valid upgrade
  headers for the next hop; `hop_by_hop_strict()` also removes the upgrade and
  `TE` envelope, and is combined with `proxy_auth()` when proxy authentication
  fields must go too. `ProxyAuthLayer` consumes `Proxy-Authorization` after
  authenticating unless `with_preserve_header(true)` is set. The
  `remove_hop_by_hop_*` helpers moved to `rama::http::header::hop_by_hop`
  (#1150, #1158).
* **Authorizers fail closed**: an empty list of `Authorizer`s now rejects every
  credential, where 0.4 accepted all. Use `Option<A>` with `None` for "open
  when unconfigured" (#1340).
* **Moved and renamed types**: `ApplicationProtocol` and `TlsAlpn` moved from
  `rama::tls` to `rama::net::tls`. URI match-replace moved from
  `rama::net::http::uri` to `rama::net::uri`. The upgrade token `Protocol`
  moved from `proto::h2::ext` to `rama::http::proto::ext`, is shared by
  HTTP/1.1 upgrades and HTTP/2 and HTTP/3 Extended CONNECT, and is built with
  `TryFrom<&str>` (or the `WEBSOCKET`, `CONNECT_UDP` and `CONNECT_IP` constants)
  instead of `From<&str>`. `ServerTrustRoots` became `ServerTrustSource`
  (`Default` is now `Native`, with a new `Platform` variant), with
  `TlsServerTrust::native_roots()`, `source()` and `with_source()` replacing
  `default_roots()`, `roots()` and `with_roots()`. The HTTP layer's
  `TimeoutError` became `rama::error::TimeoutError` (#1146, #1228, #1276,
  #1347).
* **`SocketInfo`** is a shared cell that QUIC updates after connection
  migration, so it is no longer `Clone`. Copy `info.address_pair()` (a
  `SocketAddresses` value) where you cloned it before; `local_addr()` and
  `peer_addr()` are unchanged (#1260).
* **TLS clients and the MITM relay**: the ECH switch moved from
  `BoringClientConfigExt` to `TlsClientConfig::with_encrypted_client_hello`
  (`TlsEncryptedClientHello`); left unset, a capable client now offers real ECH
  when a configuration is known, and `false` keeps the 0.4 default of no ECH.
  `Ja3`/`Ja4::compute_from_client_hello` and `TlsProfile::compute_ja3`/
  `compute_ja4` no longer take a negotiated version; values now follow the JA3
  and JA4 specifications and can differ from 0.4 for the same hello.
  `TlsMitmRelay` now fails the egress handshake when the upstream asks for a
  client certificate and no client-auth policy is set, applies a 30 s handshake
  deadline (`without_handshake_timeout()` to opt out), and
  `TlsMitmRelayErrorKind` gained `ClientAuth` and `Timeout`.
  `parse_client_hello_handshake` rejects trailing bytes (#1209, #1234, #1303,
  #1313).
* **DNS and connector targets**: `DnsResolver` now also requires
  `DnsCnameResolver` and `DnsServiceBindingResolver`; custom resolvers
  implement both (an empty stream is fine when unsupported). TXT lookups yield
  one `rama_dns::wire::Txt` per record instead of raw `Bytes`.
  `ConnectorTargetStream::new` also takes the target it belongs to (#1146,
  #1350).
* **Upgrades and prefixed IO**: HTTP/2 upgraded streams no longer carry the
  handshake message's extensions, and `HttpUpgradeMitmRelay` only transfers
  values placed in `HttpUpgradeMitmRelayExtensions`. Upgrade `Parts` gained a
  `read_err` field that callers of `Upgraded::downcast` should check, and
  `Rewind`/`PrefixedIo` may return replayed and inner bytes in one read. The
  `IoBufMut::as_uninit` method was replaced by `as_mut_slice` and `spare_mut`
  (#1169, #1216, #1291).
* **Strict and case-sensitive values**: closed-set enums built with
  `enum_builder!` can now be strict. `CrossOriginEmbedderPolicyValue`,
  `CrossOriginOpenerPolicyValue`, `CrossOriginResourcePolicy`,
  `PerMessageDeflateIdentifier` and the SOCKS5 `ProtocolVersion`,
  `UsernamePasswordSubnegotiationVersion` and `AddressType` lost their
  `Unknown` variant and convert with `TryFrom`/`FromStr`; the COEP, COOP and
  CORP tokens match case-sensitively. WebSocket subprotocols must be RFC 6455
  tokens and match case-sensitively (#1143, #1290).
* **Files and forms**: `ServeDir` no longer serves dot-prefixed or hidden
  entries, except `.well-known`; restore them with `with_allowed_hidden_kinds`.
  Multipart forms are limited to 1000 parts by default (`with_max_parts`),
  `Field::headers()` returns `&HeaderMap`, and `Multipart::from_body` takes the
  boundary as bytes. `HeaderFromStrConfigLayer` selects its repeat mode with a
  type parameter (`Single` or `Repeated<C>`) instead of `with_repeat` (#1314,
  #1321, #1328).
* **HTTP service details**: a tuple response such as `(StatusCode, X)` now keeps
  the error status when `X` fails to convert (use `ForceStatusCode` to force the
  outer status); body extractors answer `413` when a body limit is hit and `408`
  when reading the body times out; `ReadSignals` reads the `datastar` query
  parameter for `DELETE` and treats a missing parameter as `null`; `localhost`
  and `*.localhost` resolve to loopback without consulting a custom resolver
  unless a request-level resolver override is set; `RetryBody::into_bytes`
  returns a `Result`; the HTML tokenizer returns `TokenizerError`, and the
  rewriter fails a body when a single construct exceeds 4 MiB
  (`with_max_buffered_bytes`, `MemoryLimitPolicy`); SOCKS5 `write_to_buf` and
  the OpenTelemetry exporter's `HeaderBag::merge` return a `Result` (#1132,
  #1140, #1143, #1301, #1304, #1321, #1355).
* **`TlsTunnel`** gained `application_protocol` and `alpn`, so the TLS spoken
  with an intermediary is configured apart from the final origin's TLS. Add
  `application_protocol: None, alpn: None` to existing literals to keep the
  tunnel connector's base policy, or set the intermediary's protocol and ALPN
  explicitly. Custom tunnel connectors should read `TlsTunnel::from_extensions`,
  so settings chosen by routing (`TlsTunnelRoute`) override request settings
  (#1142, #1158).
* **Struct literals and exhaustive matches**: several public structs gained
  fields, such as `ProxyAddress` (`template`, for MASQUE URI templates),
  `NegotiatedTlsParameters`, the Boring and Rustls connector and acceptor
  configs, `SocketOptions`, `H2ClientContextParams`, `H2ServerContextParams`,
  Datastar `PatchElements` and the RSS feed and item extensions. Enums such as
  `HttpMatcherKind`, `HttpProxyError`, `WebSocketRelayEvent`,
  `ClientHelloExtension`, `Ja4ComputeError` and `XpcError` gained variants. Use
  `..Default::default()` and wildcard arms where possible (#1132, #1133, #1142,
  #1143, #1172, #1228, #1232, #1234, #1258, #1274, #1355).
* **Apple Network Extension**: `NwEgressParameters::allow_system_proxy` (and its
  C field) is now `allow_proxy`; blocking a system or PAC proxy as strongly as
  possible needs the opt-in SwiftPM trait `PrivateNetworkProxyControl`, which
  uses private Apple API and is not suitable for App Store builds. Provider-side
  refusals now default to `FlowRefusalAction::Passthrough` (configure `Block` to
  fail closed), a 500 live-flow cap and writer and UDP memory budgets are on by
  default, the `transparent_proxy_ffi!` `init` callback receives an owned
  `TransparentProxyInitConfig`, handler hooks, `TransparentProxyServiceContext`
  and `TcpFlow` expose a `WeakScope` instead of an `Executor`, the C UDP
  read-demand callback takes a `probe_id`, `BytesOwnedView` fields are private,
  and the Swift package needs Swift tools 6.1. Rebuild the Rust static library
  and the Swift package from the same Rama revision (#1153, #1159, #1166, #1243,
  #1291, #1312, #1317, #1345).
* **Other platform APIs**: `XpcMessage::Fd` owns its descriptor
  (`Arc<OwnedFd>`). `MmdbReader::open_mmap` is now `unsafe` because a mapped
  file modified underneath is undefined behaviour, and `IpGeoDb::from_env` and
  `parse_spec` read the database into memory; use the new positional reader
  (`from_env_positional`) or the explicit `unsafe` mmap constructors.
  `process::pid_path` and `pid_arguments` are no longer `unsafe` (#1291).
* **Dependencies re-exported by Rama**: `rama::graceful` no longer re-exports
  `tokio-graceful`. dial9 moved from `dial9-tokio-telemetry` 0.3 to `dial9`
  0.5; `with_dial9_config` became `with_dial9_recorder` plus
  `with_dial9_attach_options`, and `--cfg tokio_unstable` is optional (#1147, by
  Julián Montes de Oca). The OpenTelemetry re-exports moved to `opentelemetry`
  0.33 and `tracing-opentelemetry` 0.34, and `rama::tls::boring::core`
  re-exports rama-boring 0.7, a breaking release with soundness fixes.
* **Network and CLI defaults**: `TCP_NODELAY` is on for TCP sockets Rama
  creates (set `tcp_no_delay` in `SocketOptions` to change it). The proxy
  started by `rama serve proxy` serves HTTP and SOCKS5 on `--bind` by default
  and no longer limits a connection's lifetime (`--timeout` defaults to `0`,
  was 8 s); pass `--protocol http` and `--timeout 8` for behaviour close to
  0.4. On every `rama serve` command `--timeout` now starts a drain at that age
  and drops the connection `--timeout-grace` later (5 s by default).
  `--http-version auto` on `rama serve echo|fp|http-test|ip` adds HTTP/3 when
  TLS is on. `rama send` uses discovery by default and `--http3` requires
  HTTP/3 with no fallback.
  `rama send` and `rama probe tls` verify with the platform verifier by
  default; use `--cacert`, `--proxy-cacert` or `SSL_CERT_EXTRA_FILE` for private
  CAs. No 0.4 subcommand or flag was removed (#1135, #1143, #1198, #1232, #1276,
  #1317, #1318, #1350).

### Migrating from User-Agent Emulation to Profiles

In 0.4 it was one row per user agent: one HTTP/1.1 header order, one
HTTP/2 configuration and one ClientHello, inserted as `HttpProfile` and
`TlsProfile` request extensions and replayed by separate layers. Real user
agents such as (web) browsers do not behave like that. One browser version sends
two or three header orders for the same kind of request, permutes or varies its
TLS extensions, and speaks QUIC and HTTP/3 with their own transport parameters,
SETTINGS and QPACK behaviour. Some clients never use HTTP/1.1 or HTTP/2 at all.
A fixed row either replays one variant forever, which is itself a fingerprint,
or has to be filled with Rama defaults where the capture had nothing.

0.5 therefore keeps profiles as counted evidence. A captured profile retains
counted observations and bounded samples of the connection and request variants
a browser sent for each transport it used, and selection weighs them by how
often they were seen. Selection is capability-aware: no protocol layer is
mandatory, and a missing layer is never filled with Rama defaults. Variants are
drawn per connection and per request, optionally seeded for reproducibility.
Replay goes through backend compilers for TLS over TCP (BoringSSL), QUIC with
TLS over QUIC, HTTP/2 and HTTP/3. Anything the stack cannot reproduce is lowered
to native behaviour and listed in a `ProfilePreservationReport` instead of
failing the request. The embedded set is analysed when it is exported and ships
as a compiled, compressed binary, so loading it only decodes.

* **Layers** (under `rama::ua::layer::emulate`): `UserAgentEmulateLayer` is now
  `ProfileEmulateLayer`, `UserAgentEmulateService` is `ProfileEmulateService`
  (built by the layer), `UserAgentEmulateHttpConnectModifier[Layer]` is
  `ProfileEmulateHttpConnectModifier[Layer]`, and
  `UserAgentEmulateHttpRequestModifier[Layer]` is
  `ProfileEmulateHttpRequestModifier[Layer]`. `PreserveHeaderUserAgent` moved
  here from `profile`, next to the new `PreserveClientHints`.
* **Sources and fallback**: `UserAgentProvider` is now `ProfileSource`,
  implemented for `UserAgentDatabase`, `Arc`, `Box` and `Either*`.
  `UserAgentSelectFallback::{Abort, Random}` is now
  `ProfileSelectFallback::{Abort, SameClient, Any}`; `Random` maps to `Any`, or
  to `SameClient` to stay on the same browser.
* **Database and profiles**: `profile::UserAgentDatabase` moved to
  `profile::selection::database::UserAgentDatabase` (`try_embedded`,
  `try_from_json_slice`, `select`, `candidates`). `UserAgentProfile` moved to
  `profile::model::ua` and holds captured, analysed data instead of `http` and
  `tls` fields; build rows with `profile::format::input::UserAgentProfileInput`.
  `HttpProfile`, `Http1Profile`, `Http2Profile`, `HttpHeadersProfile` and
  `RequestClientHints` were removed; `Http1Settings` and `Http2Settings` live in
  `profile::model::http`, `RequestInitiator` in `profile::model::runtime_hints`,
  and `try_load_embedded_profiles` in `profile::format::input`.
* **TLS replay**: `EmulateTlsProfileLayer` was removed; the profile layer does
  not insert a `TlsProfile` for it to act on. Register
  `rama::tls::boring::client::profile::compiler::ConnectionProfileCompiler` on
  the connect modifier instead, built from the same base `TlsClientConfig` as
  the TLS connector:
  `ProfileEmulateHttpConnectModifier::new(connector).with_connection_compiler(..)`,
  placed with `map_connector` right after `with_tls_support_using_boringssl`.
  Keep `ProfileEmulateHttpRequestModifierLayer` as a just-in-time layer on the
  client, as before. To send one known ClientHello without a profile, write
  `TlsClientConfig::new_from_client_hello(&hello)` onto the request.
* **HTTP/3 replay**: wrap an `Http3Connector` (built with `BoringTlsProvider`)
  in the same connect modifier, with
  `rama::quic::profile::replay::ConnectionProfileCompiler` as compiler, and
  install it with its DNS layer through `with_http3_connector`;
  `with_http3_support` only accepts the unwrapped built-in connector. The `ua`
  feature enables both compilers.
* **Relays and proxies**: on a relay that forwards requests over connections it
  did not open through the profile connector, use
  `ProfileEmulateRelayRequestModifierLayer`. The `http_mitm_proxy_emulate_boring`
  example shows a MITM proxy that re-sends through an emulating client and
  picks the profile from proxy-auth labels (`ProfileSelectorUsernameParser`).
* **Behaviour to know about**: without a user agent and without a fallback, 0.5
  draws any profile weighted by observations, where 0.4 selected nothing. A
  request whose kind the profile never captured replays the nearest captured
  flow and keeps the caller's `Sec-Fetch-*` headers. An invalid input header
  order is ignored instead of failing the request. `is_optional(true)` also
  covers connection preparation, which then connects natively.
* **CLI and your own profiles**: `rama send --emulate` takes an optional
  profile file (`--emulate=profiles.json`), defaults to the embedded set and
  falls back to the same browser (`SameClient`) instead of a random one.
  0.4-style JSON rows load with `UserAgentDatabase::try_from_json_slice`; use
  `rama ua export` and `rama ua compact` to build your own sets, as described
  in [capturing your own profiles](https://ramaproxy.org/book/intro/user_agent_capture.html).
  `rama send`'s client in `rama-cli` is a complete example of the TCP and
  HTTP/3 wiring.

### Added

* **QUIC** (`rama-quic`, `rama-quic-proto`, feature `quic`):
  * Added a native QUIC transport for clients and servers: QUIC v1 and v2 with
    compatible version negotiation, streams and RFC 9221 datagrams, session
    resumption, 0-RTT, connection migration, path MTU discovery, graceful
    shutdown, qlog, OpenTelemetry metrics and dial9 coverage. `Endpoint::serve`
    serves accepted connections through a Rama `Service` (#1172, #1191, #1249,
    #1287, #1288, #1299, #1337).
  * It runs on BoringSSL or Rustls (`ring` or `aws-lc`), with injectable TLS
    providers for other backends. Every backend runs the QUIC interop-runner
    cases as client and server, and in the benchmark matrix
    (`just rama-quic/bench-matrix`) the BoringSSL backend matches or beats
    quic-go in the measured cases (#1182, #1281).
  * Added the engine-free `rama-quic-proto` crate with the wire codec, version
    and transport parameter types, first-flight capture and typed
    `QuicProfile`s (#1191).
  * Added proxy building blocks in `rama::quic::proxy`: ClientHello peeking,
    admission, transparent relays, and a BoringSSL MITM relay that follows a
    client's connection across UDP and platform flows, with an explicit policy
    for how ingress and egress react to network changes (#1258, #1303, #1345,
    #1355).
  * QUIC connections publish `SocketInfo` (updated after migration),
    `NegotiatedTlsParameters` and `QuicConnectionInfo` in their extensions,
    like the TCP TLS connectors do (#1260, #1265, #1271, #1280, by Brecht
    Stamper).
* **HTTP/3 and HTTP datagrams**:
  * Added an HTTP/3 client and server (RFC 9114) with a stateful QPACK codec
    (RFC 9204), priorities (RFC 9218), two-phase GOAWAY shutdown, trailers and
    connection coalescing: `HttpServer::new_http3`, `Http3Connector` and
    `EasyHttpConnectorBuilder::with_http3_support`, sharing the multiplex pool
    with HTTP/2. The engine is generic over its QUIC transport (#1192, #1198,
    #1258, #1264, #1340; #1283 and #1293 by Brecht Stamper).
  * Added service discovery for HTTP clients: `Alt-Svc` (typed headers, HTTP/2
    `ALTSVC` frames, `AltSvcLayer`, `AltSvcCache`) and DNS HTTPS records
    (`HttpsServiceLayer`), which supply HTTP/3 endpoints, address hints and ECH
    configurations. Both are on in the default web client, with per-attempt
    timeouts, backoff and origin fallback; `Alt-Used` is only sent on request
    (#1146, #1198, #1294, #1350, #1355).
  * Added Extended CONNECT over HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220),
    WebSockets over HTTP/3 through the normal `rama-ws` APIs, and HTTP Datagrams
    with the Capsule Protocol (RFC 9297) on HTTP/1.1, HTTP/2 and HTTP/3
    (`rama::http::datagram`); a relay can move capsules onto the next hop's
    native datagrams (#1228, #1231; #1339 by Brecht Stamper).
  * Added HTTP early data with `425 Too Early` recovery: per-request
    `EarlyDataPermit`/`ForbidEarlyData`, client retry helpers, server and
    gateway gates, a typed `Early-Data` header, and exposure preserved across
    HTTP versions and ICAP. Everything stays handshake-first unless enabled
    (#1304).
  * Added HTTP/1.1, HTTP/2 and HTTP/3 conversion in proxies, with WebSockets
    relayed across versions (#1263).
* **MASQUE** (`rama-masque`, feature `masque`, `rama::proxy::masque`):
  * Added CONNECT-UDP (RFC 9298) over HTTP/1.1, HTTP/2 and HTTP/3, with native
    QUIC datagrams or capsules: `ConnectUdpService`, `ConnectUdpConnector`, URI
    templates, `masque://` proxy addresses, the typed `Proxy-Status` header, and
    `DefaultHttpWebClient::default_masque_with_scope` to run HTTP/3 through a
    tunnel. The proxy denies private and special-purpose destinations by
    default (NAT64-aware) and has tunnel and per-principal limits, traffic
    budgets, audit events that never log identities, and OpenTelemetry metrics
    (#1274, #1287, #1340).
  * Added CONNECT-IP (RFC 9484): scopes, address and route capsules, IP
    datagrams, a deny-by-default `ConnectIpPolicy`, and
    `ConnectIpService`/`ConnectIpConnector`/`ConnectIpSession`, backed by a new
    `rama::net::ip` packet API (#1295).
  * Added a MITM relay for a client's own CONNECT-UDP sessions on every HTTP
    version (`connect_udp::mitm`) (#1277).
  * Added `rama serve proxy --protocol masque` with its `--masque-*` options,
    MASQUE upstream chaining, and `rama send -x masque://...` (#1274).
* **UDP and networking** (`rama-udp`, `rama-net`, `rama-tcp`):
  * Added packet-oriented datagram sockets (`DatagramSocket`,
    `UdpPacketSocket`) with ECN, packet info, batching and segmentation,
    adapted from quinn-udp, plus forwarding, demultiplexing, peeking and bounded
    socket-group building blocks and an in-memory test backend (#1152, #1258,
    #1345).
  * Added network availability tracking (`rama::net::availability`) and opt-in
    recovery of UDP forwarding after a network change (`DatagramRecovery`)
    (#1345, #1355).
  * Added binding a socket to an interface by index
    (`SocketOptions::interface_index`) (#1355).
  * Added `PostedRecv` (`rama_tcp::posted_recv`) to keep data a peer sent right
    before a TCP reset on Windows, and bounded lingering close for HTTP/1
    servers and `IoForwardService` (#1212).
* **TLS, ECH and trust**:
  * Added Encrypted Client Hello on BoringSSL, over TCP and QUIC. Clients take
    configurations from HTTPS discovery, `TargetEchConfigLayer` or
    preknowledge, choose opportunistic or required use with `EchRequirement`,
    report the outcome as `TlsEchAccepted`, and retry once after an
    authenticated rejection. Servers install reloadable keys
    (`ReloadableEchServerKeys`, `with_ech_keys`), and the TLS MITM relay offers
    ECH upstream when it has a configuration (#1350, #1354).
  * Added the operating system's certificate verifier for BoringSSL and Rustls
    clients (`TlsClientConfig::with_platform_verifier`), extra roots through
    `SSL_CERT_EXTRA_FILE` and `SSL_CERT_EXTRA_DIR`, and reject-only chain
    policies such as `DistrustedServerKeys` (SPKI deny lists) (#1276).
  * Added staged client authentication to the BoringSSL `TlsMitmRelay`: a
    per-connection `TlsMitmClientAuthPolicy` verifies the ingress client and then
    selects the upstream credential (#1209, superseding #1202, co-authored by
    Ivan Porto Carrero).
  * Added bounded reassembly of ClientHellos fragmented across TLS records, with
    a `MalformedTlsPolicy` for TCP and QUIC peeking (#1303).
  * Added BoringSSL ClientHello controls for key shares, signature-scheme
    GREASE, per-handshake extension permutation, requested trust anchors and
    TLS 1.2 tickets, and opt-in TLS session resumption for clients and servers
    (#1234, building on #1196 by Yann).
* **Profiles, emulation and fingerprinting** (`rama-ua`, `rama-fp`):
  * Added the profile system: capture, counted evidence, analysis, variant
    selection with seeds and pins, and replay for TLS over TCP and QUIC, QUIC
    transport parameters, ECH, HTTP/1.1, HTTP/2 and HTTP/3. Requests of a kind a
    profile never captured replay the nearest captured flow, and a
    `ProfilePreservationReport` lists what could not be reproduced (#1258,
    #1313, #1320, #1354).
  * Added a compiled embedded profile set and the `rama ua` command (`parse`,
    `export`, `compact`, `view`, `compare`) (#1258, #1282, #1329).
  * Added `rama send --emulate[=FILE]` with initiator, seed and variant
    options, `rama send --next` to send several curl-style requests over one
    client, and `ProfileSelectorUsernameParser` to pick a profile from
    proxy-auth labels (#1135, #1258, #1313).
  * Added profile capture from desktop Safari, iOS simulators and Firefox on
    Android, same-site and cross-site captures in fp, and a guide to capturing
    your own profiles (#1282, #1286, #1320).
  * The echo and fp services report HTTP/3 SETTINGS, QPACK and pseudo-header
    order, the QUIC first flight and transport parameters, TLS over QUIC, ECH
    acceptance, and how JA3, JA4 and PeetPrint compare with the recorded
    profile for that user agent (#1258, #1281, #1286, #1354).
  * Added typed `Sec-Fetch-Dest`, `Sec-Fetch-Mode`, `Sec-Fetch-User`,
    `Sec-Purpose` and `X-Requested-With` headers and a `FetchMetadata`
    extractor (#1289, #1290).
* **Proxying, MITM and inspection**:
  * Added MITM and a live web inspector to `rama serve proxy` (`--mitm`):
    encrypted, bounded captures of HTTP(S) and WebSocket traffic, HAR and
    profile export, curl export, replay over TCP or HTTP/3 as captured,
    interception with approval, edits, local responses and rules
    (`--intercept`), and host discovery without decryption (`--mitm-scope`).
    The proxy is multi-protocol (`--protocol http,https,socks5`) with upstream
    and system proxy support (#1135, #1160).
  * Added the `rama-inspect` crate (`rama::inspect`): inspection sessions,
    typed interception waits, subscriptions, streaming memory and file stores,
    search and timelines, with adapters in the HTTP, WebSocket, TLS, UA and
    crypto crates, and `--inspect-json` plus a bearer-token HTTP API to script
    the CLI inspector (#1163; storage conformance harness #1206 by Abdelkader
    Boudih).
  * Added `rama inspect` to view HAR and qlog files in a terminal (#1175,
    #1177).
  * Added route-aware forward-proxy handling (`EstablishedProxyRoute`,
    `HttpForwardProxyLayer`, plaintext HTTP through CONNECT, isolated upstream
    `407` responses) and context-aware hop-by-hop handling
    (`rama::http::header::hop_by_hop`) (#1150, #1158).
  * Added peeking on both sides of a bridge (`PeekEgressPredicate`), so a
    proxy that dials before classifying no longer stalls on a server-first
    protocol, and `PeekPolicy` to choose between fallback and failure (#1324,
    #1331).
  * Proxy databases return MASQUE proxies for UDP (and TCP) lookups, and the
    in-memory database gained runtime exclude and require columns
    (`ProxyRuntimeColumn`, #1355).
* **ICAP** (`rama-icap`, feature `icap`):
  * Added an ICAP (RFC 3507) codec usable without `std`, a streaming client and
    server, and an HTTP adaptation layer with REQMOD, RESPMOD, OPTIONS caching,
    Preview, `204` and `206`, `icaps://` direct TLS and protocol-separated
    connection pooling (#1136, #1142).
  * Added `rama serve icap` and ICAP adaptation in `rama serve proxy`
    (`--icap` and its options) (#1136, #1143).
* **DNS** (`rama-dns`):
  * Added typed CNAME, SVCB and HTTPS lookups to the Apple, Windows, Linux and
    Hickory resolvers, `rama resolve -t CNAME|SVCB|HTTPS`, and a DNS message
    parser in `rama_dns::wire`. The portable Tokio (`getaddrinfo`) resolver
    supports address lookups only (#1146, #1186, #1350).
  * Added sharing of concurrent identical lookups, bounds on concurrent and
    burst queries per native resolver, and `BoundedDnsResolver` to cap the
    answers per lookup (#1221, #1295).
  * The Windows resolver answers its own computer name locally, like
    `getaddrinfo` does (#1291).
* **HTTP, web and content formats**:
  * Added JSON-LD (`JsonLd`, `JsonLdScript`, extraction from HTML) (#1134),
    typed DCMI relationships for RSS and Atom (#1133), and current Datastar
    protocol support with the typed `Datastar-Request` header and embedded
    client 1.0.4 (#1132, #1199; embedded client updates #1164 and #1214 by
    Abdelkader Boudih).
  * Added a push-driven SSE `EventDecoder` with line and event limits and a
    lenient resync mode, usable by proxies that inspect a stream while
    forwarding it (#1184, #1190).
  * Added a sans-IO `multipart/form-data` codec
    (`rama::http::protocols::multipart`) that replaces `multer` and lets a proxy
    rewrite a form in flight without buffering it (#1328, #1336).
  * Added gRPC services on HTTP web routers (`RouterExt::with_grpc_service`)
    (#1138).
  * Added `HttpClientExt::query` and `WebService::with_query` for the HTTP
    `QUERY` method (#1214), `Option<Authority>` and `Option<Host>` extractors
    (#1245, by Abdelkader Boudih), `ForceStatusCode`, fallible
    `Redirect::try_*` constructors (#1143), and configurable path matching with
    `PathMatchPolicy` (#1144).
  * Added draining of HTTP bodies: reuse of HTTP/1 client connections after a
    response body is dropped early (`Http1BodyDrainConfig`), and
    `DrainRequestBodyLayer` with an opt-in HTTP/1 server `request_body_drain`
    for handlers that ignore an upload (#1254, #1347).
  * Added `max_decoded_size` to the decompression layers,
    `CorsLayer::with_forward_disallowed_preflights`, `ServeDir` options
    (`redirect_to_trailing_slash`, `ignore_multi_range_requests`,
    `with_enforce_not_acceptable`) and a Rama-owned HTTP-date formatter and
    parser (`rama::http::utils::http_date`) (#1139, #1321, #1355).
* **Core, errors and utilities**:
  * Added graceful scopes (`rama::graceful::{Scope, WeakScope}`), `ScopeLayer`
    for per-input scopes with a maximum age and grace, `AbortableIo`, and
    `rama::rt::spawn`. HTTP/1.1, HTTP/2, HTTP/3 and ttRPC drain in the graceful
    phase, relays run until the hard phase, and pooled connections are drained
    rather than reused once their scope is cancelled (#1317).
  * Added connection-scoped extensions and nested connections
    (`#[extension(scope(connection))]`, `Extensions::fork_nested_connection`,
    `outer_connection`, `NestedConnectionTransfer`) (#1351, by Brecht Stamper;
    #1355).
  * Added `CauseExt` (typed cause lookup, root cause, context fields),
    `ErrorList`, `CollectErrors`, caller locations on error context, and a
    runtime-independent `TimeoutError`; address races and DNS chains now keep
    every failure (#1305, #1347).
  * Added `#[derive(ExtensionsRef)]`, applied across Rama's wrapper types, and
    `ExtensionsRef` for `RequestWriterService` and `ResponseWriterService` (#1307,
    by Maarten Deprez).
  * Added a `no_std` hex module (`rama::utils::hex`) replacing the `hex` crate
    (#1171), and strict and case-sensitive `enum_builder!` modes (#1290).
  * Added positional file reads with a sharded block cache
    (`rama::io::{ReadAt, ReadAtFiles, BlockCache}`) and an MMDB reader that
    follows file replacements without loading the database into memory
    (`MmdbFileReader`, `IpGeoDb::from_env_positional`) (#1291).
* **Platforms and diagnostics**:
  * Added Linux GNU cross-builds from macOS and Windows with `cargo-zigbuild`
    (#1149).
  * Added dial9 correlation across tasks, FFI, queues and pools, local trace
    exports and `Dial9Layer` for HTTP/1, HTTP/2 and HTTP/3 (#1249).
  * Added the `js-interpreter` feature to run PAC scripts through Wasmtime's
    Pulley interpreter on hosts without executable memory, selected explicitly
    with `JsBackend::Interpreter` (#1253, #1261).
  * Added an `http.cancellations.total` OpenTelemetry counter and
    `RequestMetricsLayer::custom_with_meter` (#1194, by Brecht Stamper).
  * Apple Network Extension: added network path notifications for handlers,
    the interface an app bound its flow to (`bound_interface_index()`), and a
    configurable TCP payload view size (#1312, #1323, #1345).
  * Restructured the book and added chapters on QUIC, HTTP/3, TLS, graceful
    shutdown, feature flags, JavaScript, JSON, inspection and ttRPC (#1316).

### Changed

* Graceful shutdown runs on Rama's own scopes instead of `tokio-graceful`
  (#1317, #1330, #1335).
* Reworked the HTTP client connection pool: connections are grouped by reuse
  key, waiters are served in order, bursts dial only what they need,
  connections report capacity and health changes to the pool, and idle or
  broken connections are trimmed lazily. The pull request measured up to five
  times faster multi-origin load than the previous pool with far fewer
  connections. `Extensions` clone and fork are now constant time (#1239, folding
  in work from closed PRs by Attila Nagy, Brecht Stamper and Abdelkader Boudih;
  #1349).
* HTTP servers apply shared header-read and idle deadlines on HTTP/1.1, HTTP/2
  and HTTP/3; HTTP/2 answers abuse with `GOAWAY ENHANCE_YOUR_CALM` and HTTP/3
  with `H3_REQUEST_REJECTED` (#1241, #1297).
* A body sent with a `Content-Length` that disagrees with its known length has
  the header corrected; a streamed body that runs longer or shorter than
  declared is never sent past its length nor ended cleanly: HTTP/1 closes the
  connection and HTTP/2 resets the stream (#1355).
* HTTP/1.1, HTTP/2 and HTTP/3 share one trailer policy (`ForbiddenTrailers`).
  By default only fields whose definitions allow trailers are sent;
  `ForbiddenTrailers` can allow more, as the MITM relays do by default, while
  framing, routing and connection fields are never sent (#1232).
* Peeking no longer depends on timers: scopes and the other side of a bridge
  end a waiting peek, and `SniRouter`, the TLS, HTTP and SOCKS5 peek routers and
  the HAProxy layer accept a bridge as input (#1324, #1331, #1355).
* HTTP/1 relays keep EOF-delimited response framing instead of re-chunking, and
  repeated `Content-Length` values must agree (#1170).
* With GREASE enabled, a custom TLS extension order that names no GREASE
  codepoint keeps BoringSSL's native GREASE slots (the first and last of the
  prefix) instead of turning GREASE off; an order that names GREASE codepoints
  places them itself (#1258).
* The embedded user-agent profiles are a compiled, compressed set that is
  analysed at export time, so loading only decodes it. The set was refreshed
  throughout the cycle (#1258, #1282, #1286, #1310, #1329, #1355).
* The BoringSSL acceptor only issues session tickets with
  `with_session_resumption(true)` (#1234).
* Apple Network Extension: provider-side refusals fail open by default, egress
  proxy policy is explicit and logged per flow, and the provider bounds writer
  and UDP ingress memory, admits at most 500 live flows by default and drops
  excess UDP datagrams instead of blocking (#1153, #1155, #1159, #1243).
* Apple Network Extension: one 15 s per-flow path-recovery allowance, restarted
  by wake, replaces the separate post-wake, viability and `.waiting` timers, so
  a path that returns in time keeps its flows and a still-dead path is reset.
  Synthetic teardowns report `ECONNRESET`, `ECONNABORTED` or `ETIMEDOUT` instead
  of `-1`, which apps saw as errno 65535 (#1309, following the report and
  proposal in #1308 by Tudor Timcu).
* Native DNS resolvers on Linux walk search domains themselves, fit retries
  inside the timeout and stop retrying on SERVFAIL and REFUSED. The native
  resolver no longer needs `bindgen` or libclang, and C warnings no longer fail
  downstream builds (#1221, #1257; #1193 by Brecht Stamper).
* dial9 moved to 0.5 and no longer requires `tokio_unstable` (#1147, by Julián
  Montes de Oca).
* Reduced copies and allocations across the stack: large HTTP/1 bodies are no
  longer copied, gRPC messages decode without copying, WebSocket payloads are
  written without a copy, small files are served from one blocking call, SSE
  decoding and encoding were rewritten, the HTML rewriter streams text-mode
  element bodies, MITM certificates are issued off the runtime, and the
  in-memory proxy database filters by transport without scanning every match
  (#1140, #1176, #1184, #1301, #1325, #1328, #1336, #1348; #1240 by Abdelkader
  Boudih; #1268 by Brecht Stamper).
* Endpoint diagnostics explain the `From<Rejection>` requirement, and
  streaming-body plumbing is shared across the rewrite and capture layers
  (#1189, #1244, by Abdelkader Boudih).
* Synced the maintained forks with upstream in four rounds: hyper, h2, http,
  http-body-util, hyper-util, headers, h3, tower-http, axum, tonic,
  tungstenite, lol-html, quinn, quinn-udp and rustls-native-certs (#1139,
  #1239, #1241, #1298, #1318).
* Raised `rama-boring` to 0.7 and OpenTelemetry to 0.33, unpinned `time`
  (#1220, by Abdelkader Boudih), and refreshed all dependencies (#1310 and the
  other update rounds).
* Release workflows separate build and test jobs from privileged signing and
  publishing, with deny-by-default permissions and no persisted checkout
  credentials (#1197).

### Fixed

* Fixed undefined behaviour found by a workspace-wide audit, which also gave
  every `unsafe` block a documented safety proof enforced by lints: a
  use-after-free in the `Debug` output of partially consumed `HeaderMap`
  iterators, unsound ordered iteration after a panicking `HeaderMap::clear`,
  invalid UTF-8 accepted by URI path editing, `IoBufMut::as_uninit` exposing
  initialised bytes, a double free and an out-of-bounds read in Windows DNS, an
  unchecked `nscount` in Linux `res_nsearch`, XPC calls that make libxpc trap,
  and SOCKS5 UDP client panics and buffer overwrites (#1291).
* Fixed panics in typed header decoding, which no longer panics on any input,
  including malformed `If-Match`/`If-None-Match` values reachable through
  `ServeDir` and permessage-deflate parameters that made the WebSocket MITM
  relay panic (#1217).
* Hardened HTTP servers against slow or abusive clients with adaptive
  header-read and idle deadlines, and fixed `Content-Length`/`Transfer-Encoding`
  and CONNECT framing per RFC 9112 (#1241).
* Hardened HTTP parsing and framing: invalid field names and values are
  malformed on every version, bare LF in chunked framing is rejected, an HPACK
  table can no longer desynchronise on a self-dependent stream, `100 Continue`
  no longer stalls a pipelined response, and oversized field counts, gRPC
  metadata, HAR headers and FastCGI records fail instead of panicking (#1321,
  #1355).
* Hardened body handling: decompression caps zstd windows and total decoded
  size, nested body limits keep the strictest one, multipart forms are bounded,
  gRPC streams that end inside a message are rejected, and WebSocket refuses
  interleaved data frames and stray RSV bits (#1321, #1340, #1355).
* `ServeDir` no longer serves dot-prefixed and hidden entries by default, and
  its `HEAD` answers match `GET` (#1321, #1355).
* Fixed TCP and Unix listeners spinning on accept errors such as `EMFILE`:
  they now back off, and binding a Unix socket only replaces stale socket files
  (#1321).
* Fixed forward-proxy credentials reaching an origin after route fallback or
  connection reuse onto a direct or tunnelled connection (#1158).
* Fixed ClientHellos fragmented across TLS records evading inspection: they are
  reassembled, so a client can no longer dodge strict SNI routing that way
  (#1303).
* Fixed unbounded memory in the HTML rewriter: one construct is bounded and the
  rewriter fails closed by default (#1301).
* Fixed HTTP client pool reuse: abandoned HTTP/1 bodies no longer hand out the
  connection again, parked waiters are woken when a slot frees, and upgraded
  tunnels no longer inherit the HTTP connection's health (#1141).
* Fixed an HTTP/2 deadlock where a stream waited on write readiness with no
  early frame to send, and a close-delimited HTTP/1 client response being
  treated as keep-alive (#1254).
* Fixed MITM relays: an ingress connection is closed gracefully when the
  HTTP/2 egress dies, raced requests get `REFUSED_STREAM` instead of `502`, and
  HTTP/2 header lists fall back to a 256 KiB budget when a peer omits its limit
  instead of answering `431` (#1205, #1210, #1284).
* Fixed WebSocket upgrades over HTTP/2 retaining their own upgrade handle
  through the handshake message's extensions (#1169), and bounded a WebSocket
  client's wait for the server to end its transport after the close handshake
  (`close_drain_timeout`, default 2 s).
* Fixed empty frames resetting streaming compression and gRPC-Web responses
  losing trailers (#1165).
* Fixed the SOCKS5 peek router rejecting valid greetings (#1144), and the
  SOCKS5 UDP relay forwarding oversized datagrams truncated (#1355).
* Fixed proxy address formatting for Basic credentials containing reserved
  characters (#1296), and an unbracketed IPv6 authority such as `::1` now
  parses as a host without a port (#1355).
* Fixed Apple Network Extension upload corruption: Network.framework can read
  send buffers after the send completion fires, so payloads now stay alive until
  it releases them. Also fixed close and FIN ordering, stranded UDP read demand,
  IPv6 zone handling, stalled promoted writes, and TCP egress leaving the
  interface an app bound its socket to (#1166, #1272, #1291, #1296, #1312,
  #1323).
* Fixed `localhost` and `*.localhost` lookups depending on the resolver: they
  now resolve to loopback as RFC 6761 asks (#1140).
* Fixed OpenTelemetry HTTP metrics leaking the active-request gauge on cancelled
  requests (#1194, by Brecht Stamper).
* Updated wasmtime for RUSTSEC-2026-0325..0327, and rustls-webpki and
  webpki-roots for RUSTSEC-2026-0381, among other advisory updates; cargo-deny
  advisories now run daily.

### Removed

* Removed `rama::rt::Executor`, the `tokio-graceful` re-exports
  (`Shutdown`, `ShutdownGuard`), `GracefulIo` and `CancelIo` in favour of
  graceful scopes and `AbortableIo` (#1317).
* Removed `PeekTimeoutPolicy`, the `with_peek_timeout*` builders and the
  `peek_input_until*` helpers in favour of `PeekPolicy` and scopes (#1331,
  #1355).
* Removed `UserAgentEmulateLayer` and the rest of the `UserAgentEmulate*`
  family, `UserAgentProvider`, the `HttpProfile` family, `RequestClientHints`,
  and `EmulateTlsProfileLayer` with its service, in favour of the profile
  system (#1258).
* Removed `SetProxyAuthHttpHeaderLayer` and `SetProxyAuthHttpHeaderService` in
  favour of route-aware forward-proxy credentials (#1158).
* Removed `HttpPooledConnectorConfig::{build_default_connector,
  try_build_connector}`, `EasyHttpConnectorBuilder::try_with_connection_pool` and
  the `max_total`/`max_concurrent_streams` pool fields (#1239).
* Removed `auto_date_header` and `max_local_error_reset_streams` from the HTTP
  builders (#1340, #1355).
* Removed `IoBufMut::as_uninit` (#1291), the `rama-net` `http` and `venndb`
  features (#1146, #1348), and the `tokio-graceful`, `multer`, `httpdate` and
  `hex` dependencies (#1171, #1317, #1328, #1355).
* Removed the Python profile generator in `rama-fp` in favour of `rama ua export`
  and `rama ua compact` (#1258).

# 0.4.0

> Release date: `2026-08-19`

Rama 0.4.0 is the first regular release train after 0.3.0. It came with
a bunch of improvements, as well as another correctness and reliability
pass for our Apple Network Extension (NE) foundations. Our Peek
and relay concepts were also improved. A last-minute improvement
also came at our doorsteps in the form of WebSocket support for HAR.
It's a feature that originated from chromium and now is also supported by rama.

This release brings system proxy support for all supported platforms.
In function this we also added `rama-js` support (Javascript runtime
support within a WASM runtime) as well as `rama-pac` to add
Proxy Auto Configuration (PAC) support. With the latter making use
of the possibility to run a javascript (JS) runtime in an isolated manner,
to safely and swiftly run PAC scripts.

Together with improved environment variable, native proxy setting auto-discovery
and refresh hooks, as well as the ability to add bypass rules (e.g. `NO_PROXY`)
we have now for the first time full system proxy support for network clients built with rama.
The rama CLI tool also makes use of it by default.

It is also the first release where we have `ttRPC` support,
a lightweight alternative to `gRPC` running directly on
the transport layer (e.g. `tcp`). And for those use cases where you do still want `gRPC`,
it is now also possible to define your models using macros provided by rama
in case you do not fancy those _proto_ files.

Please read **Breaking API Changes** before upgrading.
As always, this changelog calls out the user-visible work; the code diff is the
authoritative source of truth.

### Community

Thank you to everyone who contributed code, reviews, documentation, testing,
bug reports, ideas, and production feedback during the 0.4 cycle. This release
includes work from Glen De Cauwsemaecker, Brecht Stamper, Abdelkader Boudih,
bitterpanda, Abhinav, Sean McArthur, 0x676e67, Bailey Hayes, Brent Echols,
Catwoman08, Clemens Losbichler, Darius, Dorian Verlaine, Frédéric Soumaré,
Jess Izen, Jihun Kim, John Howard, Langning Zhang, Logan, Martin Taillefer,
Morax, MsfPablo, Murilo Silva, Murph Murphy, Nam2ee, Recoordinate, Sam
Landfried, Sander Saares, SCADA StrangeLove, dswij, tottoto, Árni Dagur, and
the other upstream contributors whose work arrived through the HTTP stack
sync. Thank you also to zeeshan8281 for reporting the CLI default-command
regression (#1089).

Thank you also to our GitHub Sponsors for directly funding Rama development,
and to our commercial partners for funding a significant part of the work in
this cycle. If you want to support Rama, you can become a
[GitHub Sponsor](https://github.com/sponsors/plabayo). If your organisation is
looking for a long-term partner around proxies, protocol work, support,
training, or custom integrations, see [ramaproxy.com](https://ramaproxy.com).

### Highlights

* **Policy-driven client routing**: the client connector now carries a
  protocol-independent `ConnectRequest`, supports ordered direct and proxy
  routes with fallback and failure backoff, and can resolve routes from
  explicit configuration, proxy environment variables, operating-system proxy
  settings, and PAC scripts. Rama CLI applies these sources with a predictable
  precedence while preserving decisions already made by an outer layer
  (#1095, #1098, #1099, #1103, #1124).
* **Sandboxed JavaScript and PAC**: new `rama-js` and `rama-pac` crates provide
  bounded JavaScript execution and classic plus Microsoft IPv6-aware PAC
  helpers. PAC programs are compiled and reused, DNS goes through Rama, and
  resource, time, result, and disclosure budgets are configurable. The CLI can
  evaluate and generate PAC files (#566, #1099, #1103, #1106, #1124).
* **Traffic policy and blocking stacks**: services can now enforce concurrent
  request and keyed rate limits, shape stream or datagram bandwidth, and choose
  between waiting and failing fast. A continuously driven blocking runtime,
  HTTP(S) client, response reader, and WebSocket APIs make the same foundations
  available to synchronous applications (#1100, #1115).
* **Streaming capture and HAR WebSockets**: HTTP body capture no longer needs
  to collect an entire body before handing data to a sink. Traffic recording
  streams frames and messages, HTTP request/response parts gained serde
  support, and HAR exports can include Chromium-compatible WebSocket messages
  in chronological request order (#1102, #1105, #1118, #1123, #1127).
* **Safer TLS and proxy handshakes**: custom trust anchors and certificate
  pinning work across Rustls and BoringSSL, TLS tunnels use an explicit server
  identity, HTTP CONNECT establishes proxy egress before returning success by
  default, and TLS relay egress behavior is configurable (#1072, #1110, #1120,
  #1121).
* **Protocol and platform growth**: this cycle adds lightweight ttrpc,
  protobuf-free gRPC services with custom codecs, Linux systemd-resolved
  Varlink DNS, local interface discovery, modern Apple Network Extension UDP
  callbacks, and native unified logging (#1064, #1069, #1087, #1091, #1093,
  #1094).
* **HTTP correctness and upstream sync**: Rama's maintained HTTP, HTTP/2, URI,
  and middleware forks were synchronized with upstream fixes and performance
  work. The result includes bounded tiny-frame handling, safer trailers and
  header values, correct dropped-stream capacity accounting, pooling fixes,
  and fewer lock-held flushes (#1127).

### Recommendations

* **Fail fast on known non-HTTP traffic**: mixed-protocol listeners using
  `HttpPeekConfig` should consider
  `.with_known_non_http_protocol_methods()`. It rejects request-line prefixes
  commonly belonging to Redis (`PING`), SMTP (`EHLO`/`HELO`), FTP (`USER`),
  IRC (`NICK`), SSH, and HAProxy PROXY v1 instead of waiting for more HTTP
  bytes. The match is deliberately case-sensitive and prefix-based; do not use
  the preset if an HTTP extension method such as `PING` or `PINGX` is valid for
  your application. Use `.with_skipped_http1_methods(...)` for an explicit
  list, and pair a configured peek timeout with `PeekTimeoutPolicy::FailClosed`
  where ambiguous traffic must never reach the fallback service (#1076, #1104,
  #1108, #1119).
* **Recompute routes per attempt**: put DNS, PAC, proxy selection, and other
  target-derived layers inside redirect and retry layers. Extensions are now
  forked for each hop or attempt, so this placement recalculates policy for the
  actual target without leaking decisions from a previous request (#1098,
  #1103). Rama CLI uses `NO_PROXY`, an explicit `--proxy`, proxy environment
  variables, and operating-system settings in that order. System settings are
  routing input for clients that honor them, not an enforcement boundary; use
  transparent interception when all traffic must traverse the proxy (#1124).
* **Choose PAC failure behavior deliberately**: system PAC defaults to failing
  the request when the script cannot be fetched, compiled, or evaluated. Keep
  that fail-closed behavior when PAC is an enforcement boundary. Select the
  browser-like direct fallback only when bypassing the proxy is acceptable;
  PAC selects routes but does not itself provide proxy authentication, TLS, or
  connection reuse (#1099, #1103, #1124).
* **Place admission controls before expensive work**: apply rate limits before
  concurrency limits when rejected or delayed traffic should not occupy a
  scarce service slot. Use keyed limits for tenant/client fairness, and choose
  shared rather than per-connection throttling when the configured bandwidth
  is meant to cap an aggregate. `KeyedRatePolicy` allows inputs with no
  derivable key by default; set `.with_missing_key_allowed(false)` when a
  missing identity must fail closed (#1100).
* **Treat server identity as security input**: pass the actual destination
  identity into TLS tunnels and keep automatic verification enabled. DNS names
  use SNI and DNS-name validation; IP destinations validate the IP SAN without
  sending an IP address as SNI. Add custom roots or pins intentionally instead
  of bypassing verification (#1072, #1110).
* **Keep blocking calls off async workers**: the blocking client and WebSocket
  APIs are intended for synchronous callers. When used from async code, move
  them to an appropriate blocking thread rather than blocking an executor
  worker (#1115).

### Breaking API Changes

Rama remains below 1.0, so a `0.x` minor release may change public APIs. The
items below are the main migration points, not an exhaustive symbol-by-symbol
inventory. Users with a broad public-API footprint should also inspect the
`rama-0.3.0..rama-0.4.0` diff when the release tag is published.

* **Connector inputs and failures**: the connector-side `client::Request` was
  renamed and generalized to `ConnectRequest`. Connector failures now use the
  structured `ConnectionError`, and route intent is represented by
  `ProxyRoute`/`ProxyRoutes` instead of a single bare `ProxyAddress` extension.
  Custom connectors and pool builders need to adopt the new input, error, and
  builder stages (#1095).
* **Proxy layers**: HTTP-specific `HttpProxyAddressLayer` and
  `HttpProxyAddressService` were replaced by protocol-independent networking
  layers. Migrate to `ProxyAddressLayer`, `ProxyEnvLayer`, `NoProxyEnvLayer`,
  and, when desired, `SystemProxyLayer`. Their public types are re-exported
  from `rama_net::client`; the implementation module is private (#1124).
* **Redirect and retry extensions**: every redirect hop and retry attempt now
  receives a fork of the original extensions. The old
  `RedirectExtensionsBehaviour` choice was removed. Mutable state that must be
  shared across attempts should live behind an explicitly shared handle; route
  decisions should generally be inserted inside the redirect/retry stack
  (#1098, #1103).
* **IO forwarding results**: `IoForwardService` no longer returns `()`. It
  returns an `IoForwardOutcome` describing why forwarding stopped, bytes moved,
  connection age, and any fatal error. A genuine non-connection I/O failure is
  returned as `IoForwardError`, which retains the complete outcome. Callers
  matching the old output or error type must be updated (#1080, #1081).
* **TLS identity and certificate generation**: `TlsTunnel::sni` became
  `server_identity: Option<Host>`, and the BoringSSL client handshake requires
  an identity when automatic verification is used. The old `SelfSignedData`,
  `SelfSignedKeyKind`, and `self_signed_server_auth` family was replaced by
  explicit CA, leaf request, subject, validity, key-kind, and generated server
  auth types. Dynamic issuers now receive `CertificateIssuanceContext`
  (#1072, #1110).
* **HTTP CONNECT and upgrades**: the eager connector is now the normal server
  path: it establishes egress before a successful CONNECT reply and maps
  timeout/failure to `504`/`502`. The former default lazy reply service is named
  `LazyHttpProxyConnectReplyService` and remains available for stacks that must
  obtain the upgraded stream before routing. Upgrade layer construction and
  composition changed alongside this work (#1120).
* **gRPC, WebSocket, and curl helpers**: gRPC method registration now accepts a
  `RamaGrpcMethodBuilder`, WebSocket handshake/upgrade wrappers are generic over
  their socket so they can be mapped or wrapped, and payload-aware curl export
  moved to `try_cmd_string_for_request_parts_and_payload` and
  `prepare_cmd_for_request_parts_and_payload`, with `CurlExportOptions`. Code
  that names the old concrete wrappers or helper functions will need adjustment
  (#1093, #1112, #1113, #1115).
* **Apple XPC date interpretation**: the `XpcMessage::Date` documentation now
  correctly defines the native value as nanoseconds since the Unix epoch, not
  the macOS 2001 reference date. Code that followed the old guidance must
  remove that epoch conversion; `XpcDate` provides an explicit serde wrapper
  for the native value (#1124).
* **Examples are an external consumer**: examples moved under `examples/src`
  into a standalone workspace crate. Tooling, documentation links, or scripts
  that used the old example paths must be updated (#1074).

### Added

* **Routing, PAC, and JavaScript**:
  * Added `rama-js`, an engine-agnostic JavaScript API with local and worker
    runtimes, bounded execution, warm-up, and compiled-module caching. The
    default PAC path runs a WebAssembly-contained SpiderMonkey engine without
    ambient WASI capabilities (#1099, #1103, #1106).
  * Added `rama-pac` with classic and Microsoft IPv6-aware PAC helpers,
    Rama-backed DNS, URL sanitization controls, route/result limits, and CLI
    `pac eval`/`pac generate` workflows (#566, #1099, #1103).
  * Added ordered proxy route fallback, route-specific extensions, bounded
    failed-route backoff, ProxyDB integration, and pooling-aware route
    selection (#1095).
  * Added lazy, cached operating-system proxy discovery for Windows current-user
    WinINET settings, Apple CFNetwork, Android, GNOME, and KDE. Native monitors
    refresh macOS, Windows, and Linux snapshots early while a TTL and last-known
    valid snapshot provide resilience (#1124).
* **Networking and protocols**:
  * Added `rama-ttrpc` and `rama-ttrpc-build`, providing unary and streaming
    lightweight RPC over a length-prefixed byte stream with prost-based code
    generation and transport-independent client/server services (#1064).
  * Added custom gRPC codecs, a serde JSON codec, and `define_service!` so
    Rust-native services can be defined without protobuf files or `build.rs`.
    Protobuf remains the interoperability-oriented default (#1093).
  * Added concurrent, global and keyed rate policies; HTTP `429` plus
    `Retry-After` mapping; per-connection/shared stream throttling; and paced
    datagram sinks (#1100).
  * Added blocking HTTP(S), response body, and WebSocket support on a dedicated,
    continuously driven core runtime (#1115).
  * Added local network-interface enumeration and Linux systemd-resolved
    Varlink DNS with per-query fallback to `res_nsearch`/`getaddrinfo`, plus TXT
    `ResolveRecord` support (#1087, #1091).
  * Added the `http-backend` feature for HTTP-capable builds that do not need
    the complete server stack, substantially reducing the dependency graph
    (#1078).
* **Inspection, capture, and export**:
  * Added a generic incremental `PeekRouter` with bounded growing buffers,
    replay, match/reject/need-more verdicts, fixed-prefix convenience, and
    configurable fail-open/fail-closed timeout policy (#1108, #1119).
  * Added streaming HTTP body capture and request/response serde support,
    avoiding mandatory full-body collection and allowing sinks to process
    frames asynchronously (#1102, #1105).
  * Added WebSocket message capture to HAR, including text, base64-encoded
    binary, and relay-error records in Chromium's `_webSocketMessages` format
    (#1118, #1123).
  * Added zero-copy owned request-parts extractors, control-aware WebSocket
    relay, configurable high-fidelity curl export, and per-request send
    timeouts in the high-level client builder (#1109, #1112, #1113).
* **TLS and platform support**:
  * Added backend-agnostic TLS server trust composition, custom trust anchors,
    and certificate pinning for Rustls and BoringSSL (#1072).
  * Added configurable TLS relay egress policy, eager HTTP CONNECT proxy
    establishment, more TCP egress socket options, and first-byte forwarding
    timeouts (#1079, #1080, #1120, #1121).
  * Added Apple unified-log tracing and the modern macOS 15 Network Extension
    UDP callback path with signed end-to-end coverage (#1069, #1094).

### Changed

* Reworked the client connector around `ConnectRequest`, structured connection
  failures, ordered routes, pooled reuse, and target-aware fallback (#1095).
* Redirects and retries now fork extensions on every hop/attempt, keeping newly
  inserted target-specific values isolated while preserving explicitly shared
  handles (#1098, #1103).
* HTTP proxy servers now establish egress before acknowledging CONNECT by
  default, and TLS MITM relays can choose when and how egress is established
  (#1120, #1121).
* System proxy and proxy-environment decisions are lazy and cacheable rather
  than fixed during stack construction. Rama CLI now combines `NO_PROXY`,
  explicit, environment, and system routes without overwriting an existing
  outer decision (#1124).
* HTTP capture and traffic writing became streaming operations, and HAR entry
  publication is ordered chronologically even when asynchronous capture workers
  finish out of order (#1102, #1105, #1127).
* Synchronized the maintained `http`, `hyper`, `h2`, and `tower-http` forks,
  bringing URI/header performance work, smaller HTTP/2 reservations, safer
  trailer and multipart handling, better directory-service error propagation,
  HPACK table/buffer improvements, and extensive flow-control/scheduling fixes.
  HTTP/2 no longer flushes a socket while stream locks are held; the upstream
  multi-worker benchmarks reported an 11.8–33.5% improvement (#1127).
* Moved all examples into a standalone crate so they compile as an external
  user of Rama's public APIs (#1074).
* Homebrew publication now dispatches to the tap repository, and CLI release
  selection correctly distinguishes latest stable releases from prereleases
  (#1065).
* Refreshed the project README with an animated Rama banner (#1126).

### Fixed

* HTTP protocol detection now validates the complete request line within a
  configured bound, releases its replay buffer when possible, rejects known
  non-HTTP prefixes early, preserves partially peeked TLS ClientHello bytes,
  and supports explicit timeout policy (#1076, #1101, #1104, #1108, #1119).
* TLS client verification now consistently uses the real server identity. DNS
  destinations send and validate SNI, while IP destinations validate IP SANs
  without sending invalid IP SNI (#1110).
* Fixed Linux DNS partial-consumption caching that could exhaust the blocking
  worker pool, Windows DNS cancellation deadlocks, and systemd-resolved
  fallback behavior (#1077, #1086, #1087).
* Fixed Apple Network Extension, XPC, Secure Enclave, passthrough, overload,
  socket, reconnect, logging, and shutdown edge cases (#1063, #1066, #1070,
  #1079, #1094).
* Fixed HTTP/2 busy loops after zero-byte writes, missed trailer wakeups,
  dropped-stream flow-control capacity, END_STREAM handling around
  `RST_STREAM(NO_ERROR)`, 1xx push counting, connection-specific trailers, and
  excessive tiny DATA-frame resource use (#1127).
* Fixed pooled HTTP connections surviving `Connection: close`, buffered write
  rechecks, partial line-ending detection, trailer negotiation, empty-path URI
  building, non-ASCII header construction, decompression across empty frames,
  and multipart range validation (#1127).
* Fixed HTTP/1 forwarding when `Content-Length` appears before
  `Transfer-Encoding`: the cancelled length is removed and the connection is
  closed after the message, avoiding propagation of confusing dual-framing
  headers (upstream Hyper sync).
* Fixed proxy, TLS, WebSocket relay, replay-buffer, forwarding-header, curl
  version/export, and HTTP capture/serde edge cases (#1111, #1113, #1114,
  #1116).
* Fixed `rama-cli`'s implicit `send` fallback so the `resolve` subcommand is not
  swallowed when invoking the binary without an explicit command (#1089,
  #1092).

### Removed

* Removed the old connector `client::Request` name and single-value proxy route
  model in favor of `ConnectRequest`, `ConnectionError`, and ordered
  `ProxyRoutes` (#1095).
* Removed HTTP-only proxy-address services in favor of the shared `rama-net`
  proxy layers, including environment and system sources (#1124).
* Removed `RedirectExtensionsBehaviour`; extensions are always forked for each
  redirect or retry boundary (#1098, #1103).
* Removed the old self-signed certificate-generation surface in favor of
  explicit CA, leaf, identity, subject, validity, and key-kind types (#1072,
  #1110).
* Removed the old default-lazy CONNECT reply naming and payload-specific
  infallible curl helpers in favor of explicit lazy/eager services and fallible,
  configurable export (#1113, #1120).
* Removed in-repository Winget publication files now maintained by the external
  package workflow.

# 0.3.0

> Release date: `2026-07-07`

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
