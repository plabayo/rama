[![rama banner](../docs/img/rama_banner.jpeg)](https://ramaproxy.org/)

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT License][license-mit-badge]][license-mit-url]
[![Apache 2.0 License][license-apache-badge]][license-apache-url]
[![rust version][rust-version-badge]][rust-version-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/rama-net-apple-xpc.svg
[crates-url]: https://crates.io/crates/rama-net-apple-xpc
[docs-badge]: https://img.shields.io/docsrs/rama-net-apple-xpc/latest
[docs-url]: https://docs.rs/rama-net-apple-xpc/latest/rama_net_apple_xpc/index.html
[license-mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[license-mit-url]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[license-apache-badge]: https://img.shields.io/badge/license-APACHE-blue.svg
[license-apache-url]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE
[rust-version-badge]: https://img.shields.io/badge/rustc-1.93+-blue?style=flat-square&logo=rust
[rust-version-url]: https://www.rust-lang.org
[actions-badge]: https://github.com/plabayo/rama/actions/workflows/CI.yml/badge.svg?branch=main
[actions-url]: https://github.com/plabayo/rama/actions/workflows/CI.yml

## rama-net-apple-xpc

Apple XPC support for rama.

> **Scope:** this crate has been developed and tested primarily with **macOS System
> Extensions** in mind. It may also work in other contexts — app extensions, regular
> apps, iOS — but those have not been tested and are not a current maintainer priority.
> If you have such a use case and run into issues, feel free to
> [open a ticket on GitHub](https://github.com/plabayo/rama/issues/new) and we can
> look into it together.

This crate wraps the low-level `libXPC` C API through bindgen-generated bindings in
[`ffi`](./src/lib.rs), then layers a small ergonomic Rust API on top for:

- listening for Mach service connections;
- connecting to XPC services as a client;
- exchanging dictionary/array/scalar XPC messages;
- applying peer identity and entitlement requirements before activation;
- integrating client connection setup into Rama's `Service` model.

Primary Apple references:

- XPC framework overview:
  <https://developer.apple.com/documentation/xpc>
- Creating XPC services:
  <https://developer.apple.com/documentation/xpc/creating_xpc_services>
- XPC connections:
  <https://developer.apple.com/documentation/xpc/xpc-connections?language=objc>
- XPC updates, including peer requirement APIs:
  <https://developer.apple.com/documentation/updates/xpc>

The low-level API shape is inspired in part by:

- <https://github.com/dfrankland/xpc-connection-rs>

The goal here is not to hide `libXPC`, but to expose it in a Rama-friendly form.

## Status

This crate currently focuses on the low-level connection-based API surface:

- `XpcListener`
- `XpcConnection`
- `XpcMessage`
- `PeerSecurityRequirement`
- `XpcConnector`

That makes it suitable as a foundation for secure Apple-process IPC inside Rama-based
applications and companion services.
