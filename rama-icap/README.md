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
