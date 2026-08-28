[![rama banner](../docs/img/rama_banner.jpeg)](https://ramaproxy.org/)

# rama-icap

Internet Content Adaptation Protocol (ICAP) support for Rama.

The crate is re-exported as `rama::icap` when the top-level `rama` crate's
`icap` feature is enabled.

## Features

| Features | API |
|---|---|
| none | `no_std` protocol types and allocation-free codecs |
| `std` | streaming ICAP client, server, messages, and I/O |
| `http` | typed HTTP messages and HTTP adaptation; implies `std` |

```toml
rama = { version = "0.5.0", features = ["http-full", "icap"] }
```

The top-level `rama` crate is the recommended dependency for applications and
framework libraries. Enable only the Rama modules your stack uses, then add
your own services and layers where needed. Crate authors that specifically
need the standalone ICAP protocol surface can depend on `rama-icap` directly
with `std` or `http`.

The complete
[`http_icap_proxy`][example] example serves an embedded ICAP service by
default and can target c-icap through a command-line service URI.

[example]: https://github.com/plabayo/rama/blob/main/examples/src/http_icap_proxy.rs

Use [`codec`](https://docs.rs/rama-icap/latest/rama_icap/codec/) for borrowed
wire syntax, the streaming `client` and `server` modules for standalone ICAP,
and `http::layer::AdaptationLayer` to detour HTTP requests or responses.

## Direct TLS

`ServiceEndpoint` accepts both `icap://` and `icaps://` service URIs. The
`icaps` convention selects direct TLS and defaults to port 11344; ICAP request
targets are still encoded with the RFC-defined `icap` scheme. This is direct
TLS from the start of the connection, not an in-band TLS upgrade.

The connector supplied to the ICAP client must include a TLS connector, such
as an auto-mode Rama Rustls or BoringSSL connector around the TCP/DNS
transport. Auto mode leaves `icap` plaintext and negotiates TLS for `icaps`.
Connection pools must include the application protocol as well as the logical
authority in their identity so plaintext and TLS connections cannot mix.

URI userinfo is preserved in the ICAP request target but omitted from the
`Host` header. Because it is sent on every exchange, avoid embedding
credentials in the service URI, especially for plaintext `icap` endpoints.
