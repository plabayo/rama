![rama banner](./docs/img/banner.png)

llama is the monorepo for [rama (ラマ)](./rama) and [pango](#pango).

## rama (ラマ)

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/rama.svg
[crates-url]: https://crates.io/crates/rama
[docs-badge]: https://img.shields.io/docsrs/rama/latest
[docs-url]: https://docs.rs/rama/latest/rama/index.html
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/plabayo/llama/blob/master/LICENSE
[actions-badge]: https://github.com/plabayo/llama/workflows/CI/badge.svg
[actions-url]: https://github.com/plabayo/llama/actions?query=workflow%3ACI+branch%main

rama is a proxy framework using Tokio written purely in Rust,
it's services all the way down.

The name is Japanese for llama, the mascot and spiritual inspiration of this proxy framework.

Look into [rama's README](./rama/README.md) for more information.

## pango

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/pangotls.svg
[crates-url]: https://crates.io/crates/pangotls
[docs-badge]: https://img.shields.io/docsrs/pangotls/latest
[docs-url]: https://docs.rs/pangotls/latest/pangotls/index.html
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/plabayo/llama/blob/master/LICENSE
[actions-badge]: https://github.com/plabayo/llama/workflows/CI/badge.svg
[actions-url]: https://github.com/plabayo/llama/actions?query=workflow%3ACI+branch%main

pango is a cross platform TLS Reverse Proxy, written purely in Rust, built on top of [rama](./rama).

It can be used either as a standalone binary where it is used as part of your backend infrastructure, or as a library in order to use pango as a [Tower](https://github.com/tower-rs/tower) service which wraps your _Http_ service.

[Axum](https://github.com/tokio-rs/axum) is the recommended http server library of choice
should you wanna go for the latter approach, as it will fit nicely with the rest of the code.

Here is a high level overview of how pango's services are composed:

```
tcp::Server
 ⤷ tcp::middleware::*
     ⤷ tls::Server
         ⤷ tls::middleware::*
             ⤷ tcp::Client ⭢ /target/
```

Look into [pango's README](./pangotls/README.md) for more information.
