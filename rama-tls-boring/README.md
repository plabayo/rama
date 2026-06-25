[![rama banner](../docs/img/rama_banner.jpeg)](https://ramaproxy.org/)

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT License][license-mit-badge]][license-mit-url]
[![Apache 2.0 License][license-apache-badge]][license-apache-url]
[![rust version][rust-version-badge]][rust-version-url]
[![Build Status][actions-badge]][actions-url]

[![Discord][discord-badge]][discord-url]
[![Buy Me A Coffee][bmac-badge]][bmac-url]
[![GitHub Sponsors][ghs-badge]][ghs-url]
[![Paypal Donation][paypal-badge]][paypal-url]

[crates-badge]: https://img.shields.io/crates/v/rama-tls.svg
[crates-url]: https://crates.io/crates/rama-tls-boring
[docs-badge]: https://img.shields.io/docsrs/rama-tls-boring/latest
[docs-url]: https://docs.rs/rama-tls-boring/latest/rama_tls_boring/index.html
[license-mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[license-mit-url]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[license-apache-badge]: https://img.shields.io/badge/license-APACHE-blue.svg
[license-apache-url]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE
[rust-version-badge]: https://img.shields.io/badge/rustc-1.93+-blue?style=flat-square&logo=rust
[rust-version-url]: https://www.rust-lang.org
[actions-badge]: https://github.com/plabayo/rama/workflows/CI/badge.svg
[actions-url]: https://github.com/plabayo/rama/actions

[discord-badge]: https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white
[discord-url]: https://discord.gg/29EetaSYCD
[bmac-badge]: https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black
[bmac-url]: https://www.buymeacoffee.com/plabayo
[ghs-badge]: https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA
[ghs-url]: https://github.com/sponsors/plabayo
[paypal-badge]: https://img.shields.io/badge/paypal-contribution?style=for-the-badge&color=blue
[paypal-url]: https://www.paypal.com/donate/?hosted_button_id=P3KCGT2ACBVFE

🦙 rama® (ラマ) is a modular service framework for the 🦀 Rust language to move and transform your network packets.
The reasons behind the creation of rama can be read in [the "Why Rama" chapter](https://ramaproxy.org/book/why_rama).

## rama-tls-boring

Tls implementations for `rama` using boring.

Learn more about `rama`:

- Github: <https://github.com/plabayo/rama>
- Book: <https://ramaproxy.org/book/>

## TLS Feature Support

> **Backend scope.** Within the rama ecosystem these extended capabilities — especially full-fidelity TLS **mirroring**, (user-agent) **emulation** and ClientHello mimicry — are for now only available in `rama-tls-boring`, not [`rama-tls-rustls`](../rama-tls-rustls/). The rustls backend can still capture/inspect a smaller `ClientHello` view for fingerprinting. We eventually plan to fork [`rustls`](https://github.com/rustls/rustls) and adapt it to our needs (kept bi-directionally in sync with upstream where possible), so we can step away from the C/C++ of boringssl for the resulting safety and performance gains — most likely prioritised through a paid partner feature request.
>
> **See it live.** Point any web client (user agent) at <https://echo.ramaproxy.org> to inspect the exact TLS versions, cipher suites, extensions and algorithms it actually sends — and to gauge whether rama can reproduce them.
>
> **Source is truth.** When in doubt, consult the linked source code below and treat it — not this summary — as authoritative (line ranges especially can drift over time).

The TLS features below are implemented on top of [`rama-boring`](https://github.com/plabayo/rama-boring), which `rama-tls-boring` re-exports directly as [`rama_tls_boring::core`](src/lib.rs) — so its native types are available to you whenever the rama-level config isn't enough. Most features, though, are configured through rama's own TLS-agnostic type vocabulary in [`rama-tls`](../rama-tls/src/) (protocol versions, cipher suites, signature schemes, groups, ALPN, extensions, …) and mapped onto `rama-boring` in [type_conversion.rs](src/type_conversion.rs). Configuration flows through extension-based pieces on `TlsClientConfig` / `TlsServerConfig`, and per-request extensions layer over an optional base config (newest-wins).

**Boring-specific config.** Knobs beyond the backend-agnostic vocabulary are set through two extension traits that insert `Boring*` extension pieces onto the agnostic config (layered the same way — per-connection over base, newest-wins):

- [`BoringClientConfigExt`](src/client/config.rs) on `TlsClientConfig`: `mimic_client_hello`, plus explicit `cipher_suites`, `supported_groups`, `signature_schemes`, `grease`, `alps`, `extension_order`, `cert_compression`, `delegated_credentials`, `record_size_limit`, `encrypted_client_hello`, `ocsp_stapling`, `signed_cert_timestamps`, a custom server-verify `server_verify_cert_store` (`Arc<X509Store>`), and explicit `min_version` / `max_version`.
- [`BoringServerConfigExt`](src/server/config.rs) on `TlsServerConfig`: `cert_issuer` — issue server certs on the fly (from a CA or a custom `DynamicCertIssuer`) with optional in-memory caching, the boring-only alternative to a static `ServerAuthData`.

Most negotiables (cipher suites, extension order, ALPN, groups, versions, signature schemes, cert compression, delegated credentials, record-size-limit, ECH, ALPS, OCSP/SCT, GREASE) can also be **derived from a captured `ClientHello`** for fingerprint mimicry — see [Proxy](#proxy-mitm--mirroring) and `new_from_client_hello`.

**Important limits:** ClientHello mimicry is best-effort, not byte-for-byte arbitrary TLS message synthesis. Unsupported/unknown values may be ignored by `rama-boring`/BoringSSL. Server-side client-certificate verification (enforced mTLS), client-side OCSP/CRL revocation verification, real ECH, and server-side TLS fingerprint controls are not currently wired at the rama config layer. The MITM relay intentionally disables upstream certificate verification on egress; use it only in flows where that trust model is acceptable.

### Client

The outbound connector ([`TlsConnector`](src/client/connector.rs) / `TlsConnectorLayer`) builds a `rama-boring` `SslConnector` per the resolved [`TlsClientConfig`](src/client/config.rs).

| Feature | Support | Source |
| --- | --- | --- |
| **Protocol versions** | Min/max derived from the offered (non-GREASE) supported-versions list; explicit `BoringMinVersion`/`BoringMaxVersion` overrides win. rama `ProtocolVersion` → `rama-boring` `SslVersion` (TLS 1.0–1.3, SSL3; SSLv2/DTLS unmapped → build error). | [connector_data.rs#L144-L185](src/client/connector_data.rs#L144-L185), [type_conversion.rs#L96-L103](src/type_conversion.rs#L96-L103) |
| **Cipher suites** | Ordered raw u16 list via `set_raw_cipher_list` for Boring-known ciphers. Unknown/unsupported IDs are skipped by the `rama-boring` helper (all-unknown lists error); GREASE is controlled separately by `set_grease_enabled`. `CipherSuite` is an open u16 enum. | [connector_data.rs#L103-L105](src/client/connector_data.rs#L103-L105), [connector_data.rs#L236-L241](src/client/connector_data.rs#L236-L241) |
| **Signature schemes** | `set_verify_algorithm_prefs` from `SignatureScheme` list (unmappable dropped, deduped). | [connector_data.rs#L121-L131](src/client/connector_data.rs#L121-L131), [connector_data.rs#L267-L271](src/client/connector_data.rs#L267-L271) |
| **Supported groups / curves** | Ordered `set_curves`, incl. PQ hybrids (X25519MLKEM768, Kyber draft variants, MLKEM1024); unmappable dropped, consecutive dups removed. | [connector_data.rs#L111-L120](src/client/connector_data.rs#L111-L120), [type_conversion.rs#L63-L75](src/type_conversion.rs#L63-L75) |
| **ALPN** ([RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301)) | Wire-encoded `set_alpn_protos`; negotiated protocol read back into `NegotiatedTlsParameters`. With the `http` feature a pinned `TargetHttpVersion` forces matching ALPN and the negotiated ALPN derives a `TargetHttpVersion`. | [connector_data.rs#L95-L101](src/client/connector_data.rs#L95-L101), [connector.rs#L348-L425](src/client/connector.rs#L348-L425) |
| **ALPS** | Application-Layer Protocol Settings with old/new codepoint selection (`add_application_settings` + `set_alps_use_new_codepoint`). | [connector_data.rs#L359-L366](src/client/connector_data.rs#L359-L366), [config.rs#L244-L252](src/client/config.rs#L244-L252) |
| **SNI** ([RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066)) | Resolved per-request from the target authority; IP literals get no SNI. Explicit `TlsServerName` and (tunnel mode) `TlsTunnel.sni` take precedence. | [connector.rs#L294-L401](src/client/connector.rs#L294-L401) |
| **GREASE** ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701)) | `set_grease_enabled(bool)`, default false; auto-enabled when mimicking a hello that carries GREASE values. | [connector_data.rs#L81](src/client/connector_data.rs#L81), [connector_data.rs#L273](src/client/connector_data.rs#L273) |
| **Extension order** | Explicit `set_extension_order` from `ExtensionId` list. Recognized listed extensions are placed first; unknown/duplicate IDs are skipped, and BoringSSL may still fill the remaining supported extensions in its own order/permutation. | [connector_data.rs#L106-L108](src/client/connector_data.rs#L106-L108), [connector_data.rs#L229-L234](src/client/connector_data.rs#L229-L234) |
| **Certificate compression** ([RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879)) | zlib / brotli / zstd compressors advertised via `add_certificate_compression_algorithm`. Gated behind the `compression` cargo feature. | [connector_data.rs#L283-L315](src/client/connector_data.rs#L283-L315), [compress_certificate.rs](src/client/compress_certificate.rs) |
| **Key logging** | `set_keylog_callback` writing NSS keylog lines to a `KeyLogSink`; default intent `Environment` (`SSLKEYLOGFILE`). | [connector_data.rs#L220-L227](src/client/connector_data.rs#L220-L227) |
| **OCSP stapling request** ([RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066)) | `enable_ocsp_stapling()` (request side only; no client-side response verification). Default off. | [connector_data.rs#L275-L277](src/client/connector_data.rs#L275-L277) |
| **Signed Certificate Timestamps** | `enable_signed_cert_timestamps()`. Default off. | [connector_data.rs#L279-L281](src/client/connector_data.rs#L279-L281) |
| **Delegated credentials** | `set_delegated_credential_schemes` from a `SignatureScheme` list. | [connector_data.rs#L132-L137](src/client/connector_data.rs#L132-L137), [connector_data.rs#L374-L378](src/client/connector_data.rs#L374-L378) |
| **record_size_limit** | `set_record_size_limit(u16)`. | [connector_data.rs#L368-L372](src/client/connector_data.rs#L368-L372) |
| **ECH GREASE** ([ECH draft](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)) | `set_enable_ech_grease(true)` — decoy ECH only; no real ECHConfigList/HPKE key is consumed. Default off. | [connector_data.rs#L380-L383](src/client/connector_data.rs#L380-L383) |
| **Server verification** | `ServerVerifyMode::Auto` (default) verifies against a shared trust store; `Disable` installs a `NONE` verify callback that always accepts. | [connector_data.rs#L317-L325](src/client/connector_data.rs#L317-L325) |
| **Trust store** | Auto mode uses a process-wide, parse-once shared store from native OS roots ([`rama-crypto` native_certs](../rama-crypto/src/native_certs/mod.rs), webpki/CCADB fallback), shared with the rustls backend. A custom `Arc<X509Store>` overrides it. | [connector_data.rs#L196-L216](src/client/connector_data.rs#L196-L216), [connector_data.rs#L404-L468](src/client/connector_data.rs#L404-L468) |
| **mTLS / client auth** | `ClientAuth::SelfSigned` (fresh 4096-bit RSA self-signed) or `Single` (supplied chain+key as DER) via `set_private_key`/`set_certificate`/`add_extra_chain_cert`. | [connector_data.rs#L327-L351](src/client/connector_data.rs#L327-L351), [connector_data.rs#L470-L597](src/client/connector_data.rs#L470-L597) |
| **Capture server cert chain** | Optional post-handshake `peer_cert_chain()` → `NegotiatedTlsParameters.peer_certificate_chain` (DER stack). Default off. | [connector.rs#L572-L578](src/client/connector.rs#L572-L578) |
| **Negotiated params** | Post-handshake `protocol_version`, selected ALPN, optional peer chain. Missing session is a hard error. | [connector.rs#L555-L591](src/client/connector.rs#L555-L591) |
| **Connector kinds** | `auto` (handshake only for secure protocols, default), `secure` (always), `tunnel(sni)` (handshake only with a `TlsTunnel` extension). | [connector.rs#L183-L329](src/client/connector.rs#L183-L329) |
| **Base config layering** | Optional base `TlsClientConfig`; per-request extensions resolve first, base as fallback. | [connector.rs#L375-L404](src/client/connector.rs#L375-L404) |
| **UA emulation** | `EmulateTlsProfileLayer` builds a config from a `TlsProfile`'s ClientHello (+ static and WS-specific overwrites). Gated behind the `ua` feature. | [emulate_ua.rs](src/client/emulate_ua.rs) |
| **ClientHello mimicry** | `new_from_client_hello` / `mimic_client_hello` build a config from a captured `ClientHello` (per-extension mapping at L314-L402). | [config.rs#L118-L123](src/client/config.rs#L118-L123), [config.rs#L314-L402](src/client/config.rs#L314-L402), [type_conversion.rs#L8-L26](src/type_conversion.rs#L8-L26) |
| **Handshake entrypoint** | `tls_connect(stream, Option<TlsConnectorData>)` runs the tokio handshake; error classification (Builder / Handshake IO / SSL-stack) lives in the internal `handshake` fn (+ `dial9` telemetry feature). | [connector.rs#L463-L617](src/client/connector.rs#L463-L617) |

**Not configured (`rama-boring` defaults):** session resumption, session tickets, early-data (0-RTT), and PSK have no rama-side control on the client; they follow `rama-boring`'s `SslConnector`/`ConnectConfiguration` defaults.

### Server

The inbound acceptor ([`TlsAcceptorLayer`](src/server/layer.rs) / [`TlsAcceptorService`](src/server/service.rs)) is configured from a [`TlsServerConfig`](../rama-tls/src/server/config.rs); per connection it resolves a [`TlsAcceptorData`](src/server/acceptor_data.rs) (the base config merged with the stream's extensions) and builds a fresh `SslAcceptor`.

| Feature | Support | Source |
| --- | --- | --- |
| **Base profile** | `SslAcceptor::mozilla_intermediate_v5(tls_server())`, rebuilt per connection. Provides TLS 1.2 floor + a TLS 1.2 cipher list + FFDHE-2048; cipher/sigalg/group/TLS-1.3 specifics are `rama-boring` defaults. | [service.rs#L69-L70](src/server/service.rs#L69-L70) |
| **GREASE** ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701)) | `set_grease_enabled(true)`, always on (hardcoded). | [service.rs#L72](src/server/service.rs#L72) |
| **Protocol versions** | If `TlsServerConfig` protocol versions are set, min and max of the list applied as `set_min/max_proto_version`. Else the v5 profile governs. | [service.rs#L106-L122](src/server/service.rs#L106-L122) |
| **ALPN** ([RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301)) | `set_alpn_select_callback` picks the **first client-offered** protocol contained in the configured list; no overlap → `NOACK`. | [service.rs#L130-L161](src/server/service.rs#L130-L161) |
| **SNI-aware cert selection** | `select_certificate` (InMemoryIssuer) / async `select_certificate` (DynamicIssuer) resolve the domain from client SNI (else context `server_name`) and install the leaf+chain+key at handshake. A static `ServerAuthData` sets a fixed cert up front (not per-SNI). | [acceptor_data.rs](src/server/acceptor_data.rs) |
| **Cert source: static** | `ServerAuthData` — a supplied chain+key (DER), or self-signed material generated once at config build (see below); `check_private_key` validates the pair. | [acceptor_data.rs](src/server/acceptor_data.rs) |
| **Cert source: self-signed gen** | Generated up front via `TlsServerConfig::try_with_self_signed` → [`rama_crypto::cert::self_signed_server_auth`](../rama-crypto/src/cert/) (boring provider): CA (20-year, BasicConstraints CA, keyCertSign+cRLSign) + leaf (90-day end-entity, SAN=CN + extra SANs), 159-bit random serials. Key kinds RSA2048/4096, EC P-256/384/521, Ed25519 (default Ec P-256). The result is stored as concrete DER, so the cert is stable across connections. | [rama-crypto cert::boring](../rama-crypto/src/cert/boring.rs) |
| **Cert source: issuer (on-the-fly)** | The boring-only cert-issuer config mints a per-SNI leaf signed by an in-memory CA (`SelfSigned`/`Single`) or a user `Dynamic` async issuer. | [acceptor_data.rs](src/server/acceptor_data.rs) |
| **Issued-cert caching** | moka `Cache<Domain, IssuedCert>` for issuer sources; `Disabled` or `MemCache { max_size, ttl }` (default TTL ~89 days). | [acceptor_data.rs#L307-L321](src/server/acceptor_data.rs#L307-L321) |
| **Client CA advertisement, no mTLS enforcement** | `ClientVerifyMode::ClientAuth` only **advertises** acceptable client-CA names via `add_client_ca`; `SSL_VERIFY_PEER` is never set, so client certs are not required or verified. The OS trust store is deliberately not loaded. | [service.rs#L73-L128](src/server/service.rs#L73-L128), [acceptor_data.rs#L269-L292](src/server/acceptor_data.rs#L269-L292) |
| **Capture client cert chain** | Optional: post-handshake leaf + `peer_cert_chain()` → `NegotiatedTlsParameters.peer_certificate_chain` (only if a client voluntarily presents one). | [service.rs#L210-L233](src/server/service.rs#L210-L233) |
| **Key logging** | `set_keylog_callback` from the `TlsServerConfig` keylog intent (`Environment`/`Disabled`/`File`/`Custom`); default `Environment`. | [service.rs#L163-L170](src/server/service.rs#L163-L170) |
| **ClientHello capture** | `store_client_hello` parses the incoming ClientHello in the cert-selection callback into `SecureTransport` on the stream extensions. Default off. | [service.rs#L92-L104](src/server/service.rs#L92-L104) |
| **Per-connection override** | The layer's base `TlsServerConfig` is merged with any TLS config pieces present in the inbound stream's extensions (per-connection pieces win), so a connection can override auth / ALPN / versions / keylog for that handshake — e.g. ACME-renewed certs. | [service.rs#L59-L64](src/server/service.rs#L59-L64) |
| **Negotiated params** | After accept: `protocol_version`, selected ALPN, optional peer chain; `SecureTransport` + `StreamTransformed`. Missing session is a hard error. | [service.rs#L195-L259](src/server/service.rs#L195-L259) |

**Utilities (exported, not wired into the acceptor service):** an OCSP "good" staple builder (`build_mitm_leaf_ocsp_response`, [RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066)), an OCSP request answerer (`answer_ocsp_request`, [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960)) and a CA CRL builder (`build_mitm_ca_crl`, [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)) live in [server::utils](src/server/utils/) and are consumed by the MITM proxy below — the acceptor itself staples nothing. The generic ASN.1 assembly is in `rama_crypto::ocsp` / `rama_crypto::crl`. Self-signed CA/leaf generation and the cert-mirroring re-signer (`self_signed_server_auth_mirror_cert[_with_extensions]`) live in [`rama_crypto::cert::boring`](../rama-crypto/src/cert/boring.rs).

**Not configured (`rama-boring` / Mozilla-v5 defaults):** server-side cipher suites, signature algorithms, curves/groups, certificate compression, and session tickets/resumption are not set by rama on the server.

### Proxy (MITM / mirroring)

[`TlsMitmRelay`](src/proxy/mitm/mod.rs) terminates the client TLS (**ingress**) and opens its own TLS to the upstream (**egress**). "Mirroring" here means the relay derives one side's parameters from the other rather than using fixed config: the egress ClientHello is built from the client's hello, and the ingress server parameters + presented certificate are built from the upstream handshake. The flow is A→B→C→D (client hello A → egress hello B → server hello C → ingress hello D); egress connects **first**, then upstream parameters are mirrored back into the ingress acceptor. See [proxy/mod.rs](src/proxy/mod.rs).

**Client-hello mirroring (A → B)** — the egress `TlsClientConfig` is built from the peeked ingress `ClientHello`:

| Mirrored | Detail | Source |
| --- | --- | --- |
| Per-extension set | cipher suites, extension order, ALPN, supported groups, supported versions, signature algorithms, cert compression, delegated credentials, record_size_limit, ALPS, OCSP (status_request / v2), SCT, ECH→GREASE. Unknown extensions ignored. | [config.rs#L314-L402](src/client/config.rs#L314-L402) |
| GREASE | Auto-enabled when any mirrored cipher/group/version/sigalg is a GREASE value. | [config.rs#L317-L392](src/client/config.rs#L317-L392) |
| SNI re-attachment | `new_from_client_hello` strips SNI (connectors normally re-derive it per-request); the relay re-attaches the peeked SNI explicitly so the upstream gets a correct hello. | [service.rs#L24-L49](src/proxy/mitm/service.rs#L24-L49), [service.rs#L140-L147](src/proxy/mitm/service.rs#L140-L147) |
| Max-version clamp | Egress max version is capped to the legacy `ClientHello.protocol_version` when `supported_versions` is absent; TLS 1.3 offers that lack a TLS 1.3 cipher or TLS 1.3-capable sigalg are clamped to TLS 1.2. | [config.rs#L394-L442](src/client/config.rs#L394-L442) |
| Fallback | Mirror → default-with-SNI (no ALPN) → no connector data, logged at each downgrade. The bare `BridgeIo` path (no captured hello) ships `rama-boring` defaults with a warning. | [service.rs#L82-L162](src/proxy/mitm/service.rs#L82-L162) |

**Server-param mirroring (C → D)** — the ingress `SslAcceptor` (mozilla_intermediate_v5 base) is built from the upstream snapshot:

| Mirrored | Detail | Source |
| --- | --- | --- |
| Protocol version | Upstream-negotiated version pinned as ingress **min == max**. The whole negotiated-params/ALPN block runs only when an egress session version exists. | [mod.rs#L684-L757](src/proxy/mitm/mod.rs#L684-L757) |
| ALPN | `set_alpn_select_callback` forces the ingress selection to match the upstream-selected protocol; no-op when upstream selected none. | [mod.rs#L711-L748](src/proxy/mitm/mod.rs#L711-L748) |
| Leaf certificate | The ingress leaf is a **re-signed mirror** of the upstream's real peer certificate (see issuers below). | [mod.rs#L589-L671](src/proxy/mitm/mod.rs#L589-L671) |
| OCSP staple ([RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066)) | Issuer-signed "good" staple wired via `set_status_callback`, gated on whether the upstream advertised revocation; emitted on the wire only if the client sent status_request. | [mod.rs#L677-L682](src/proxy/mitm/mod.rs#L677-L682), [issuer/memory.rs#L52-L104](src/proxy/mitm/issuer/memory.rs#L52-L104) |
| Revocation pointers (opt-in) | With a `BoringMitmRevocation` responder wired, the re-signed leaf carries a CRL distribution point and/or AIA OCSP URL pointing back at a proxy-hosted CA-signed responder, mirroring whichever source the upstream advertised. Lets revocation-strict clients that ignore the staple (notably libcurl + schannel) resolve the leaf. | [revocation.rs](src/proxy/mitm/revocation.rs), [issuer/memory.rs](src/proxy/mitm/issuer/memory.rs) |
| Negotiated params / HTTP | `NegotiatedTlsParameters` (+ `TargetHttpVersion` under the `http` feature) stamped onto the egress stream; both streams tagged `StreamTransformed`. | [mod.rs#L750-L829](src/proxy/mitm/mod.rs#L750-L829) |

**Certificate mirroring / forging** ([`self_signed_server_auth_mirror_cert`](../rama-crypto/src/cert/boring.rs)) — the re-signed leaf copies the upstream subject name, notBefore/notAfter (clamped into the CA's validity window), and most extensions verbatim (preserving criticality), with a **fresh** key matched to the source key type (RSA→RSA max(bits,2048); EC on the source group; Ed25519; else RSA-2048 fallback). SKI/AKI are regenerated (only when the source carried them). Stripped: CRL Distribution Points, Authority Information Access, Freshest CRL, RFC 7633 must-staple, and RFC 6962 embedded SCTs — extensions invalid or unsatisfiable after re-signing. When a `BoringMitmRevocation` responder is wired, the stripped CRL DP / AIA OCSP pointers are **replaced** with proxy-hosted equivalents (`self_signed_server_auth_mirror_cert_with_extensions`).

**Cert issuers** (`BoringMitmCertIssuer` trait, [issuer/mod.rs](src/proxy/mitm/issuer/mod.rs); re-exported as `proxy::cert_issuer`):

| Issuer | Behavior | Source |
| --- | --- | --- |
| `InMemoryBoringMitmCertIssuer` | Mirrors + re-signs each upstream leaf with an in-memory CA; attaches a best-effort OCSP staple. `with_revocation(..)` additionally stamps proxy-hosted CRL/OCSP pointers. | [issuer/memory.rs](src/proxy/mitm/issuer/memory.rs) |
| `StaticBoringMitmCertIssuer` | Returns one fixed chain+key for every request, ignoring the upstream cert; no staple. | [issuer/static_pair.rs](src/proxy/mitm/issuer/static_pair.rs) |
| `DenyBoringMitmCertIssuer` | Rejects every request → relay short-circuits before the ingress handshake (blocks interception). | [issuer/deny.rs](src/proxy/mitm/issuer/deny.rs) |
| `CachedBoringMitmCertIssuer<T>` | Wraps any issuer with a moka cache keyed on the upstream cert signature (default ~89-day TTL, 32 000 entries). | [issuer/cache.rs](src/proxy/mitm/issuer/cache.rs) |
| `Either<…>` | Runtime dispatch between issuer strategies via `rama_core::combinators::Either`. | [issuer/either.rs](src/proxy/mitm/issuer/either.rs) |

**Construction & integration:** `TlsMitmRelay::new(issuer)` plus `try_new_with_self_signed_issuer` / `new_in_memory` / `new_with_cached_issuer[_and_config]` and combined cached variants ([mod.rs#L52-L186](src/proxy/mitm/mod.rs#L52-L186)). The relay is a `Layer` producing `TlsMitmRelayService`, which implements `Service` over both `BridgeIo` (defaults path) and `InputWithClientHello` (mirror path) ([service.rs](src/proxy/mitm/service.rs)).

**GREASE & key logging:** ingress GREASE is on by default (`grease_enabled`); egress GREASE follows the mirrored hello. `keylog_intent` (default `Environment`) applies to **both** sides — the keylog exports session keys for the relay-mirrored client side *and* the upstream side, so treat the file as security-sensitive ([mod.rs#L73-L99](src/proxy/mitm/mod.rs#L73-L99)).

**Trust:** egress verification is forced `Disable` (the relay accepts the upstream's real cert without verifying it); ingress loads no OS trust store and enforces no client-cert verification ([service.rs#L43-L93](src/proxy/mitm/service.rs#L43-L93), [mod.rs#L643-L650](src/proxy/mitm/mod.rs#L643-L650)).

**Error classification:** `TlsMitmRelayError` carries a kind (Config / Handshake{direction, classification} / TlsServe). Handshake errors are classified `CertTrust` (cacheable bypass candidate) vs `TlsProtocol` vs `Transport` vs `Unclassified` from peer alerts and `rama-boring` reason strings, with direction (Ingress/Egress), `ConnectorTarget`, and SNI attached ([mod.rs#L188-L478](src/proxy/mitm/mod.rs#L188-L478)). A plaintext pre-handshake alert primitive exists in [alert.rs](src/proxy/mitm/alert.rs) but is currently **disabled** (`mod alert;` commented out) — failures are conveyed by transport close.

### Shared type vocabulary

Features are expressed through open enums and config types in [`rama-tls`](../rama-tls/src/) and converted to `rama-boring` in [type_conversion.rs](src/type_conversion.rs). Key types in [enums.rs](../rama-tls/src/enums.rs):

- **`ProtocolVersion`** (u16) — SSLv2/SSLv3, TLS 1.0–1.3, DTLS; only TLS 1.0–1.3 + SSL3 map to `rama-boring`.
- **`CipherSuite`** (u16) — full IANA registry incl. the five TLS 1.3 suites + AEGIS; `is_tls13()` / `is_grease()`.
- **`SignatureScheme`** (u16) — RSA-PKCS1/PSS, ECDSA, EdDSA, GOST, brainpool, …; subset maps to `SslSignatureAlgorithm`.
- **`SupportedGroup`** (u16) — SECP/X25519/X448, FFDHE, brainpool, GOST, and PQ hybrids (MLKEM/Kyber).
- **`ApplicationProtocol`** (byte string) — HTTP/0.9–3, and many non-HTTP protocols; used for both ALPN and ALPS.
- **`CertificateCompressionAlgorithm`** (zlib/brotli/zstd) and legacy **`CompressionAlgorithm`** (parse-only).
- **`ExtensionId`**, **`ClientHelloExtension`**, **`ECPointFormat`** (parse/inspection), and **`ECHClientHello`** / HPKE suite enums.
- Backend-agnostic config: **`KeyLogIntent`**, **`ServerVerifyMode`**, **`ClientVerifyMode`** / **`ClientAuth`**, and the **`ServerAuthData`** / **`ClientAuthData`** (concrete DER cert material via `rama_crypto::pki_types`) / **`ServerCertIssuer*`** family. Self-signed generation (**`SelfSignedData`** + `self_signed_server_auth`) lives in [`rama-crypto`](../rama-crypto/src/cert/), backend-pluggable across boring / aws-lc / ring.

Conversions are bidirectional where applicable; unmapped values either error at build time (protocol versions) or are silently filtered out (signature schemes, groups).
