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
[polar-badge]: https://img.shields.io/badge/polar.sh-subscribe?style=for-the-badge&color=blue
[polar-url]: https://polar.sh/plabayo

🦙 Rama (ラマ) is a modular service framework for the 🦀 Rust language to move and transform your network packets.
The reasons behind the creation of rama can be read in [the "Why Rama" chapter](./why_rama.md).

Rama is async-first using [Tokio](https://tokio.rs/) as its _only_ Async Runtime.
Please refer to [the examples found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples)
to get inspired on how you can use it for your purposes.

This framework comes with 🔋 batteries included, giving you the full freedome to build the middleware and services you want, without _having_ to repeat the "common":

| category | support list |
|-|-|
| 🏗️ [transports](https://ramaproxy.org/docs/rama/net/stream/index.html) | ✅ [tcp](https://ramaproxy.org/docs/rama/tcp/index.html) ⸱ 🏗️ udp <sup>(2)</sup> ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/net/stream/layer/index.html) |
| 🏗️ [http](https://ramaproxy.org/docs/rama/http/index.html) | ✅ [auto](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.auto) ⸱ ✅ [http/1.1](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.http1) ⸱ ✅ [h2](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.h2) ⸱ 🏗️ h3 <sup>(2)</sup> ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/http/layer/index.html) |
| ✅ web server | ✅ [fs](https://ramaproxy.org/docs/rama/http/service/fs/index.html) ⸱ ✅ [redirect](https://ramaproxy.org/docs/rama/http/service/redirect/struct.Redirect.html) ⸱ ✅ [dyn router](https://ramaproxy.org/docs/rama/http/service/web/struct.WebService.html) ⸱ ✅ [static router](https://ramaproxy.org/docs/rama/http/service/web/macro.match_service.html) ⸱ ✅ [handler extractors](https://ramaproxy.org/docs/rama/http/service/web/extract/index.html) ⸱ ✅ [k8s healthcheck](https://ramaproxy.org/docs/rama/http/service/web/k8s/index.html) |
| ✅ http [client](https://ramaproxy.org/docs/rama/http/client/index.html) | ✅ [client](https://ramaproxy.org/docs/rama/http/client/struct.HttpClient.html) ⸱ ✅ [high level API](https://ramaproxy.org/docs/rama/http/client/trait.HttpClientExt.html) ⸱ ✅ [Proxy Connect](https://ramaproxy.org/docs/rama/proxy/http/client/struct.HttpProxyConnectorService.html) ⸱ ❌ [Chromium Http](https://github.com/plabayo/rama/issues/189) <sup>(3)</sup> |
| 🏗️ [tls](https://ramaproxy.org/docs/rama/tls/index.html) | ✅ [Rustls](https://ramaproxy.org/docs/rama/tls/rustls/index.html) ⸱ 🏗️ BoringSSL <sup>(1)</sup> ⸱ ❌ NSS <sup>(3)</sup> |
| ✅ [dns](https://ramaproxy.org/docs/rama/dns/index.html) | ✅ [DNS Resolver](https://ramaproxy.org/docs/rama/dns/layer/index.html) |
| ✅ [proxy protocols](https://ramaproxy.org/docs/rama/proxy/index.html) | ✅ [PROXY protocol](https://ramaproxy.org/docs/rama/proxy/pp/index.html) ⸱ ✅ [http proxy](https://github.com/plabayo/rama/blob/main/examples/http_connect_proxy.rs) ⸱ ✅ [https proxy](https://github.com/plabayo/rama/blob/main/examples/https_connect_proxy.rs) ⸱ 🏗️ SOCKS5 <sup>(2)</sup> ⸱ 🏗️ SOCKS5H <sup>(2)</sup> |
| 🏗️ web protocols | 🏗️ Web Sockets (WS) <sup>(2)</sup> ⸱ 🏗️ WSS <sup>(2)</sup> ⸱ ❌ Web Transport <sup>(3)</sup> ⸱ ❌ gRPC <sup>(3)</sup> |
| ✅ [async-method trait](https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html) services | ✅ [Service](https://ramaproxy.org/docs/rama/service/trait.Service.html) ⸱ ✅ [Layer](https://ramaproxy.org/docs/rama/service/layer/trait.Layer.html) ⸱ ✅ [context](https://ramaproxy.org/docs/rama/service/context/index.html) ⸱ ✅ [dyn dispatch](https://ramaproxy.org/docs/rama/service/struct.BoxService.html) ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/service/layer/index.html) |
| ✅ [telemetry](https://ramaproxy.org/docs/rama/telemetry/index.html) | ✅ [tracing](https://tracing.rs/tracing/) ⸱ ✅ [opentelemetry](https://ramaproxy.org/docs/rama/telemetry/opentelemetry/index.html) ⸱ ✅ [http metrics](https://ramaproxy.org/docs/rama/http/layer/opentelemetry/index.html) ⸱ ✅ [transport metrics](https://ramaproxy.org/docs/rama/net/stream/layer/opentelemetry/index.html) ⸱ ✅ [prometheus exportor](https://ramaproxy.org/docs/rama/http/service/web/struct.PrometheusMetricsHandler.html) |
| ✅ upstream [proxies](https://ramaproxy.org/docs/rama/proxy/index.html) | ✅ [MemoryProxyDB](https://ramaproxy.org/docs/rama/proxy/struct.MemoryProxyDB.html) ⸱ ✅ [L4 Username Config](https://ramaproxy.org/docs/rama/utils/username/index.html) ⸱ ✅ [Proxy Filters](https://ramaproxy.org/docs/rama/proxy/struct.ProxyFilter.html) |
| 🏗️ [User Agent (UA)](https://ramaproxy.org/book/intro/user_agent) | 🏗️ Http Emulation <sup>(1)</sup> ⸱ 🏗️ Tls Emulation <sup>(1)</sup> ⸱ ✅ [UA Parsing](https://ramaproxy.org/docs/rama/ua/struct.UserAgent.html) |
| 🏗️ utilities | ✅ [error handling](https://ramaproxy.org/docs/rama/error/index.html) ⸱ ✅ [graceful shutdown](https://ramaproxy.org/docs/rama/utils/graceful/index.html) ⸱ 🏗️ Connection Pool <sup>(1)</sup> ⸱ 🏗️ IP2Loc <sup>(2)</sup> |
| 🏗️ [TUI](https://ratatui.rs/) | 🏗️ traffic logger <sup>(2)</sup> ⸱ 🏗️ curl export <sup>(2)</sup> ⸱ ❌ traffic intercept <sup>(3)</sup> ⸱ ❌ traffic replay <sup>(3)</sup> |
| ✅ binary | ✅ [prebuilt binaries](https://ramaproxy.org/book/binary/rama) ⸱ 🏗️ proxy config <sup>(2)</sup> ⸱ ✅ http client ⸱ ❌ WASM Plugins <sup>(3)</sup> |
| 🏗️ data scraping | 🏗️ Html Processor <sup>(2)</sup> ⸱ ❌ Json Processor <sup>(3)</sup> |
| ❌ browser | ❌ JS Engine <sup>(3)</sup> ⸱ ❌ [Web API](https://developer.mozilla.org/en-US/docs/Web/API) Emulation <sup>(3)</sup> |

> 🗒️ _Footnotes_
>
> * <sup>(1)</sup> Part of [`v0.2.0` milestone (ETA: 2024/05)](https://github.com/plabayo/rama/milestone/1)
> * <sup>(2)</sup> Part of [`v0.3.0` milestone (ETA: 2024/07)](https://github.com/plabayo/rama/milestone/2)
> * <sup>(3)</sup> No immediate plans, but on our radar. Please [open an issue](https://github.com/plabayo/rama/issues) to request this feature if you have an immediate need for it. Please add sufficient motivation/reasoning and consider [becoming a sponsor][ghs-url] to help accelerate its priority.

The primary focus of Rama is to aid you in your development of proxies:

- 🚦 [Reverse proxies](https://ramaproxy.org/book/proxies/reverse);
- 🔓 [TLS Termination proxies](https://ramaproxy.org/book/proxies/tls);
- 🌐 [HTTP(S) proxies](https://ramaproxy.org/book/proxies/http);
- 🧦 [SOCKS5 proxies](https://ramaproxy.org/book/proxies/socks5) (will be implemented in `v0.3`);
- 🔎 [MITM proxies](https://ramaproxy.org/book/proxies/mitm);
- 🕵️‍♀️ [Distortion proxies](https://ramaproxy.org/book/proxies/distort).

The [Distortion proxies](https://ramaproxy.org/book/proxies/distort) support
comes with [User Agent (UA)](./intro/user_agent.md) emulation capabilities. The emulations are made possible by patterns
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

[![Polar Subscribe][polar-badge]][polar-url]
[![GitHub Sponsors][ghs-badge]][ghs-url]
[![Buy Me A Coffee][bmac-badge]][bmac-url]
[![Paypal Donation][paypal-badge]][paypal-url]
[![Discord][discord-badge]][discord-url]

Please consult [the official docs.rs documentation][docs-url] or explore
[the examples found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples)
to know how to use rama for your purposes.

> 💡 You can find the edge docs of the rama framework code at <https://ramaproxy.org/docs/rama/index.html>,
> which contains the documentation for the main branch of the project.

🤝 Enterprise support, software customisations, integrations, professional support, consultancy and training are available upon request by sending an email to [glen@plabayo.tech](mailto:glen@plabayo.tech). Or get an entireprise subscription at [polar.sh/plabayo](https://polar.sh/plabayo).

💖 Please consider becoming [a sponsor][ghs-url] if you critically depend upon Rama (ラマ) or if you are a fan of the project.

## ⌨️ | `rama` binary

The `rama` binary allows you to use a lot of what `rama` has to offer without
having to code yourself. It comes with a working http client for CLI, which emulates
User-Agents and has other utilities. And it also comes with IP/Echo services.

It also allows you to run a `rama` proxy, configured to your needs.

Learn more about the `rama` binary and how to install it at [/binary/rama.md](./binary/rama.md).

## 🧪 | Experimental

🦙 Rama (ラマ) is to be considered experimental software for the foreseeable future. In the meanwhile it is already used
in production by ourselves and others alike. This is great as it gives us new perspectives and data to further improve
and grow the framework. It does mean however that there are still several non-backward compatible releases that will follow `0.2`.

In the meanwhile the async ecosystem of Rust is also maturing, and edition 2024 is also to be expected as a 2024 end of year gift.
It goes also without saying that we do not nilly-willy change designs or break on purpose. The core design is by now also well defined. But truth has to be said,
there is still plenty to be improve and work out. Production use and feedback from you and other users helps a lot with that. As such,
if you use Rama do let us know feedback over [Discord][discord-url], [email](mailto:glen@plabayo.tech) or a [GitHub issue](https://github.com/plabayo/rama/issues).

👉 If you are a company or enterprise that makes use of Rama, or even an individual user that makes use of Rama for commcercial purposes. Please consider becoming [a business/enterprise subscriber](https://polar.sh/plabayo/subscriptions). It helps make the development cycle to remain sustainable, and is beneficial to you as well. As part of your benefits we are also available to assist you with migrations between breaking releases. For enterprise users we can even make time to develop those PR's in your integration codebases ourselves on your behalf. A win for everybody. 💪