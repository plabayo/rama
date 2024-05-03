![rama banner](https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg)

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT License][license-mit-badge]][license-mit-url]
[![Apache 2.0 License][license-apache-badge]][license-apache-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/rama.svg
[crates-url]: https://crates.io/crates/rama
[docs-badge]: https://img.shields.io/docsrs/rama/latest
[docs-url]: https://docs.rs/rama/latest/rama/index.html
[license-mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[license-mit-url]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[license-apache-badge]: https://img.shields.io/badge/license-APACHE-blue.svg
[license-apache-url]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE
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

🦙 Rama (ラマ) is a modular service framework for the 🦀 Rust language to move and transform your network packets.
The reasons behind the creation of rama can be read in [the "Why Rama" chapter](./why_rama.md).

Rama is async-first using [Tokio](https://tokio.rs/) as its _only_ Async Runtime.
Please refer to [the examples found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples)
to get inspired on how you can use it for your purposes.

This opiniated framework comes with 🔋 batteries included:

| category | description |
|-|-|
| [transports](https://ramaproxy.org/docs/rama/stream/index.html) | ✅ [tcp](https://ramaproxy.org/docs/rama/tcp/index.html) ⸱ ❌ udp ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/stream/layer/index.html) |
| [http](https://ramaproxy.org/docs/rama/http/index.html) | ✅ [auto](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.auto) ⸱ ✅ [http/1.1](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.http1) ⸱ ✅ [h2](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.h2) ⸱ ❌ h3 ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/http/layer/index.html) |
| web server | ✅ [fs](https://ramaproxy.org/docs/rama/http/service/fs/index.html) ⸱ ✅ [redirect](https://ramaproxy.org/docs/rama/http/service/redirect/struct.Redirect.html) ⸱ ✅ [dyn router](https://ramaproxy.org/docs/rama/http/service/web/struct.WebService.html) ⸱ ✅ [static router](https://ramaproxy.org/docs/rama/http/service/web/macro.match_service.html) ⸱ ✅ [handler extractors](https://ramaproxy.org/docs/rama/http/service/web/extract/index.html) ⸱ ✅ [k8s healthcheck](https://ramaproxy.org/docs/rama/http/service/web/k8s/index.html) |
| http client | ✅ [client](https://ramaproxy.org/docs/rama/http/client/struct.HttpClient.html) ⸱ ✅ [high level API](https://ramaproxy.org/docs/rama/http/client/trait.HttpClientExt.html) |
| [tls](https://ramaproxy.org/docs/rama/tls/index.html) | ✅ [Rustls](https://ramaproxy.org/docs/rama/tls/rustls/index.html) ⸱ ❌ BoringSSL ⸱ ❌ NSS ⸱ ❌ OpenSSL |
| dns | ✅ [DNS Resolver](https://ramaproxy.org/docs/rama/dns/layer/index.html) |
| proxy protocols | ✅ [PROXY protocol](https://ramaproxy.org/docs/rama/proxy/pp/index.html) ⸱ ❌ http proxy ⸱ ❌ SOCKS5 ⸱ ❌ SOCKS5H |
| async-method trait services | ✅ [Service](https://ramaproxy.org/docs/rama/service/trait.Service.html) ⸱ ✅ [Layer](https://ramaproxy.org/docs/rama/service/layer/trait.Layer.html) ⸱ ✅ [context](https://ramaproxy.org/docs/rama/service/context/index.html) ⸱ ✅ [dyn dispatch](https://ramaproxy.org/docs/rama/service/struct.BoxService.html) ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/service/layer/index.html) |
| telemetry | ✅ [tracing](https://tracing.rs/tracing/) ⸱ ✅ [opentelemetry](https://ramaproxy.org/docs/rama/opentelemetry/index.html) ⸱ ✅ [http metrics](https://ramaproxy.org/docs/rama/http/layer/opentelemetry/index.html) ⸱ ✅ [transport metrics](https://ramaproxy.org/docs/rama/stream/layer/opentelemetry/index.html) ⸱ ✅ [prometheus exportor](https://ramaproxy.org/docs/rama/http/service/web/struct.PrometheusMetricsHandler.html) |
| upstream proxies | ✅ [MemoryProxyDB](https://ramaproxy.org/docs/rama/proxy/struct.MemoryProxyDB.html) ⸱ ✅ [L4 Username Config](https://ramaproxy.org/docs/rama/proxy/username/struct.UsernameConfig.html) ⸱ ✅ [Proxy Filters](https://ramaproxy.org/docs/rama/proxy/struct.ProxyFilter.html) |
| distortion proxies | ❌ UA Profiles ⸱ ❌ UA Emulation ⸱ ❌ UA Parsing |
| utilities | ✅ [error handling](https://ramaproxy.org/docs/rama/error/index.html) ⸱ ✅ [graceful shutdown](https://ramaproxy.org/docs/rama/graceful/index.html) |

The primary focus of Rama is to aid you in your development of proxies:

- 🚦 [Reverse proxies](https://ramaproxy.org/book/proxies/reverse);
- 🔓 [TLS Termination proxies](https://ramaproxy.org/book/proxies/tls);
- 🌐 [HTTP(S) proxies](https://ramaproxy.org/book/proxies/http);
- 🧦 [SOCKS5 proxies](https://ramaproxy.org/book/proxies/socks5) (will be implemented in `v0.3`);
- 🔎 [MITM proxies](https://ramaproxy.org/book/proxies/mitm);
- 🕵️‍♀️ [Distortion proxies](https://ramaproxy.org/book/proxies/distort).

The [Distortion proxies](https://ramaproxy.org/book/proxies/distort) support
comes with User-Agent (UA) emulation capabilities. The emulations are made possible by patterns
and data extracted using [`rama-fp`](https://github.com/plabayo/rama/tree/main/rama-fp/). The service is publicly exposed at
<https://fp.ramaproxy.org>, made possible by our sponsor host <https://fly.io/>.

> 🔁 <https://echo.ramaproxy.org/> is another service publicly exposed.
> In contrast to the Fingerprinting Service it is aimed at developers
> and allows you to send any http request you wish in order to get an insight
> on the Tls Info and Http Request Info the server receives
> from you when making that request.
>
> ```bash
> curl -XPOST 'https://echo.ramaproxy.org/foo?bar=baz' \
>   -H 'x-magic: 42' --data 'whatever forever'
> ```
>
> Feel free to make use of while crafting distorted http requests,
> but please do so with moderation. In case you have ideas on how to improve
> the service, please let us know [by opening an issue](https://github.com/plabayo/rama/issues).

[BrowserStack](https://browserstack.com) sponsors Rama by providing automated cross-platform browser testing
on real devices, which [uses the public fingerprinting service](https://github.com/plabayo/rama/tree/main/rama-fp/browserstack/main.py) to aid in automated fingerprint collection
on both the Http and Tls layers. By design we do not consider Tcp and Udp fingerprinting.

Next to proxies, Rama can also be used to develop [Web Services](./web_servers.md) and [Http Clients](./http_clients.md).

[![Discord][discord-badge]][discord-url]
[![Buy Me A Coffee][bmac-badge]][bmac-url]
[![GitHub Sponsors][ghs-badge]][ghs-url]
[![Paypal Donation][paypal-badge]][paypal-url]

Please consult [the official docs.rs documentation][docs-url] or explore
[the examples found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples)
to know how to use rama for your purposes.

> 💡 You can find the edge docs of the rama framework code at <https://ramaproxy.org/docs/rama/index.html>,
> which contains the documentation for the main branch of the project.

🤝 Enterprise support, software customisations, integrations, professional support, consultancy and training are available upon request by sending an email to [glen@plabayo.tech](mailto:glen@plabayo.tech).

💖 Please consider becoming [a regular sponsor][ghs-url] if you critically depend upon Rama (ラマ) or if you are a fan of the project.