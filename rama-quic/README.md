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

[crates-badge]: https://img.shields.io/crates/v/rama-quic.svg
[crates-url]: https://crates.io/crates/rama-quic
[docs-badge]: https://img.shields.io/docsrs/rama-quic/latest
[docs-url]: https://docs.rs/rama-quic/latest/rama_quic/index.html
[license-mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[license-mit-url]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[license-apache-badge]: https://img.shields.io/badge/license-APACHE-blue.svg
[license-apache-url]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE
[rust-version-badge]: https://img.shields.io/badge/rustc-1.96+-blue?style=flat-square&logo=rust
[rust-version-url]: https://www.rust-lang.org
[actions-badge]: https://github.com/plabayo/rama/actions/workflows/CI.yml/badge.svg?branch=main
[actions-url]: https://github.com/plabayo/rama/actions/workflows/CI.yml

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

## rama-quic

QUIC transport for Rama, version 1 (RFC 9000) and version 2 (RFC 9369): client,
server and combined endpoints, streams, DATAGRAM, resumption and 0-RTT, migration,
loss recovery, congestion control and path MTU discovery, on top of `rama-udp`
sockets and the common `rama-tls` configuration (TLS 1.3 through BoringSSL or
Rustls).

Both versions are on by default and negotiated per RFC 9368 with downgrade protection:
a client starts in v1 and, on BoringSSL, offers v2 as a compatible version the server
may switch to mid-handshake; otherwise the server replies with Version Negotiation and
the client restarts in a shared version. `version::ClientVersionPolicy` and
`version::ServerVersionPolicy` control the offer — Rustls clients cannot switch
mid-handshake, so they offer only their first flight's version. Tickets and address
tokens are scoped to their issuing version, and the QUIC bit is greased per RFC 9287.

The `profile` module describes the wire image a client presents — version offer,
transport parameter order, connection ID lengths, datagram size, packet-number and frame
layout — as a typed, invariant-checked `QuicProfile`.

Choose `boring` for BoringSSL alone, `rustls,ring` for Rustls with ring, or
`rustls,aws-lc` for Rustls with AWS-LC. The `boring` feature does not require
ring, AWS-LC, or the Rustls engine. `rustls-pki-types` remains the shared
certificate/key representation used throughout Rama.

Applications can supply their own TLS 1.3 and packet protection through
`tls::provider::{ClientConfig, ServerConfig, Session}`. Pass the configurations to
`ClientConfig::new` and `ServerConfig::new`; the latter accepts a custom token key.
No built-in TLS or crypto feature is needed for this API. The root `rama` crate's
`quic` feature also enables the shared `tls` types without selecting a backend.
The [external GnuTLS interop project](e2e/gnutls-interop/) exercises this interface
against aioquic in both roles with all built-in Rama backends disabled.

Crate used by the end-user `rama` crate.

Qlog recording targets main schema draft 14 and QUIC events draft 13.
See the [qlog module documentation](src/qlog/mod.rs) for scope, specification links,
and compatibility considerations for older readers.

Learn more about `rama`:

- Github: <https://github.com/plabayo/rama>
- Book: <https://ramaproxy.org/book/>

## Benchmarks

Every pairing of QUIC implementations, measured through the public interop-runner endpoint
images on one host: rows are clients, columns are servers, Rama appears once per TLS
backend. Each chart names the host's OS, CPU count, the UTC time and the Rama commit it was
produced from. `just rama-quic/bench-matrix` regenerates them; see
[e2e/bench](e2e/bench/) for the cases and how the numbers are taken.

![handshake](e2e/bench/graph/handshake.svg)
![bulk](e2e/bench/graph/bulk.svg)
![parallel](e2e/bench/graph/parallel.svg)
![small](e2e/bench/graph/small.svg)
