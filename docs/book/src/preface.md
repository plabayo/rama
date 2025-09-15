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

🦙 Rama (ラマ) is a modular service framework for the 🦀 Rust language to move and transform your network packets.

> 🎧 **New! Listen to [Netstack.FM Episode 1](https://netstack.fm/#episode-1)**
> — the podcast about rethinking networking with Rust and building with Rama.

This framework is designed for developers who need fine-grained, programmable control over how packets are handled across
the network stack. Whether you're intercepting traffic for security analysis, emulating clients with custom user agents,
hijacking connections for advanced testing, or building high-performance proxies,
Rama provides a clean and composable Rust-native foundation.

With support for modular packet pipelines, deep protocol introspection, and advanced socket manipulation—including features
like transparent proxying and HAProxy protocol support—Rama makes it easy to prototype, deploy,
and scale complex network behavior with safety and speed.

It's not just a toolkit—it's a mindset shift for how
to design and operate dynamic, programmable network services.

> 💡 The motivations behind Rama's creation are detailed in [the "Why Rama" chapter](./why_rama.md).

Rama is async-first using [Tokio](https://tokio.rs/) as its _only_ Async Runtime.
Please refer to [the examples found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples)
to get inspired on how you can use it for your purposes.

> While powerful and flexible, Rama might not be the ideal framework for everyone. If you're building a
> conventional web server or need a simple HTTP client, other crates might better suit your needs. Although
> we at [Plabayo](https://plabayo.tech) use Rama extensively for our web infrastructure (clients, servers,
> and proxies), it has a steeper learning curve and a smaller community compared to more established alternatives.
>
> Consider these alternatives for simpler use cases:
>
> - [Axum](https://github.com/tokio-rs/axum) for building standard HTTP web servers. It offers extensive
>   community support and ecosystem integrations. However, be aware that Axum's higher-level abstractions
>   may limit your control over the web stack when you need to implement non-standard features.
>   - 📚 Or read more about web servers using Rama in [this book's Web Server chapter](./web_servers.md)
>
> - [Reqwest](https://docs.rs/reqwest/latest/reqwest/) for basic HTTP client needs. It's ideal when you
>   don't require fine-grained control over HTTP requests/responses or TLS configuration details.
>   - 📚 Or read more about HTTP clients using Rama in [this book's Http Client chapter](./http_clients.md)
>
> If you're specifically building proxies and find Rama's approach doesn't align with your needs,
> explore the alternatives listed in our [project README](https://github.com/plabayo/rama?tab=readme-ov-file#--alternatives).
>
> Rama's core philosophy centers on empowerment and modularity. It provides a foundation for building
> proxies, servers, and clients without imposing restrictions. Any component in a Rama-based web stack
> can be customized to meet your specific requirements, even if that means implementing custom solutions
> for particular layers.
>
> We gratefully acknowledge that Rama stands on the shoulders of giants. For more details about our
> inspirations and dependencies, see our [acknowledgements](https://github.com/plabayo/rama?tab=readme-ov-file).
>
> In some cases, we've had to fork external crates to accommodate our specific needs or scope requirements.
> While this creates additional maintenance work, we believe it's worthwhile to support our mission of
> empowering Rama users. Details about these forks can be found in our [FORK.md](https://github.com/plabayo/rama/blob/main/docs/thirdparty/fork/README.md).
> We maintain the original code structure in these forks to facilitate upstream synchronization and
> contribute patches back when possible.

> 💡 If your organization relies on Rama (ラマ) for its operations,
> we invite you to consider becoming a sponsor 💖. By supporting our project,
> you'll help ensure its continued development and success.
> To learn more about sponsorship opportunities, please refer to
> [the "Sponsors" chapter in this book](./sponsor.md)
> or contact us directly at [sponsor@ramaproxy.org](mailto:sponsor@ramaproxy.org).

Rama comes with 🔋 batteries included, giving you the full freedom to build the middleware and services you want, without _having_ to repeat the "common":

| category | support list |
|-|-|
| ✅ [transports](https://ramaproxy.org/docs/rama/net/stream/index.html) | ✅ [tcp](https://ramaproxy.org/docs/rama/tcp/index.html) ⸱ ✅ [udp](https://ramaproxy.org/docs/rama/udp/index.html) ⸱ ✅ [Unix (UDS)](https://ramaproxy.org/docs/rama/unix/index.html) ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/net/stream/layer/index.html) |
| ✅ [http](https://ramaproxy.org/docs/rama/http/index.html) | ✅ [auto](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.auto) ⸱ ✅ [http/1.1](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.http1) ⸱ ✅ [h2](https://ramaproxy.org/docs/rama/http/server/service/struct.HttpServer.html#method.h2) ⸱ 🏗️ h3 <sup>(2)</sup> ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/http/layer/index.html) |
| ✅ web server | ✅ [fs](https://ramaproxy.org/docs/rama/http/service/fs/index.html) ⸱ ✅ [redirect](https://ramaproxy.org/docs/rama/http/service/redirect/struct.Redirect.html) ⸱ ✅ [router](https://ramaproxy.org/docs/rama/http/service/web/struct.Router.html) ⸱ ✅ [dyn router](https://ramaproxy.org/docs/rama/http/service/web/struct.WebService.html) ⸱ ✅ [static router](https://docs.rs/rama-http/latest/rama_http/service/web/macro.match_service.html) ⸱ ✅ [handler extractors](https://ramaproxy.org/docs/rama/http/service/web/extract/index.html) ⸱ ✅ [k8s healthcheck](https://ramaproxy.org/docs/rama/http/service/web/k8s/index.html) |
| ✅ http [client](https://ramaproxy.org/docs/rama/http/client/index.html) | ✅ [easy client](https://ramaproxy.org/docs/rama/http/client/struct.EasyHttpWebClient.html) ⸱ ✅ [high level API](https://ramaproxy.org/docs/rama/http/service/client/trait.HttpClientExt.html) ⸱ ✅ [BoringSSL Connect](https://ramaproxy.org/docs/rama/tls/boring/client/struct.TlsConnectorLayer.html) ⸱ ✅ [Rustls Connect](https://ramaproxy.org/docs/rama/tls/rustls/client/struct.TlsConnectorLayer.html) ⸱ ✅ [HTTP Proxy Connect](https://ramaproxy.org/docs/rama/http/client/proxy/layer/struct.HttpProxyConnector.html) ⸱ ✅ [Socks5 Proxy Connect](https://ramaproxy.org/docs/rama/proxy/socks5/struct.Socks5ProxyConnectorLayer.html) ⸱ ❌ [Chromium Http](https://github.com/plabayo/rama/issues/189) <sup>(3)</sup> |
| ✅ [tls](https://ramaproxy.org/docs/rama/tls/index.html) | ✅ [Rustls](https://ramaproxy.org/docs/rama/tls/rustls/index.html) ⸱ ✅ [BoringSSL](https://ramaproxy.org/docs/rama/tls/boring/index.html) ⸱ ❌ NSS <sup>(3)</sup> |
| ✅ [dns](https://ramaproxy.org/docs/rama/dns/index.html) | ✅ [DNS Resolver](https://ramaproxy.org/docs/rama/dns/trait.DnsResolver.html) |
| ✅ [proxy protocols](https://ramaproxy.org/docs/rama/proxy/index.html) | ✅ [PROXY protocol](https://ramaproxy.org/docs/rama/proxy/haproxy/index.html) ⸱ ✅ [http proxy](https://github.com/plabayo/rama/blob/main/examples/http_connect_proxy.rs) ⸱ ✅ [https proxy](https://github.com/plabayo/rama/blob/main/examples/https_connect_proxy.rs) ⸱ ✅ [socks5(h) proxy](https://github.com/plabayo/rama/blob/main/examples/socks5_connect_proxy.rs) |
| ✅ web protocols | ✅ [SSE](https://ramaproxy.org/docs/rama/http/sse/index.html) ⸱ ✅ [WS](https://ramaproxy.org/docs/rama/http/ws/index.html) ⸱ ❌ Web Transport <sup>(3)</sup> ⸱ ❌ gRPC <sup>(2)</sup> |
| ✅ [async-method trait](https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html) services | ✅ [Service](https://ramaproxy.org/docs/rama/service/trait.Service.html) ⸱ ✅ [Layer](https://ramaproxy.org/docs/rama/layer/trait.Layer.html) ⸱ ✅ [context](https://ramaproxy.org/docs/rama/context/index.html) ⸱ ✅ [dyn dispatch](https://ramaproxy.org/docs/rama/service/struct.BoxService.html) ⸱ ✅ [middleware](https://ramaproxy.org/docs/rama/layer/index.html) |
| ✅ [telemetry](https://ramaproxy.org/docs/rama/telemetry/index.html) | ✅ [tracing](https://tracing.rs/tracing/) ⸱ ✅ [opentelemetry](https://ramaproxy.org/docs/rama/telemetry/opentelemetry/index.html) ⸱ ✅ [http metrics](https://ramaproxy.org/docs/rama/http/layer/opentelemetry/index.html) ⸱ ✅ [transport metrics](https://ramaproxy.org/docs/rama/net/stream/layer/opentelemetry/index.html) |
| ✅ Diagnostics | ✅ [curl export](https://ramaproxy.org/docs/rama/http/convert/curl/index.html) ⸱ ✅ [HAR](https://ramaproxy.org/docs/rama/http/layer/har/index.html) |
| ✅ upstream [proxies](https://ramaproxy.org/docs/rama/proxy/index.html) | ✅ [MemoryProxyDB](https://ramaproxy.org/docs/rama/proxy/struct.MemoryProxyDB.html) ⸱ ✅ [Username Config](https://ramaproxy.org/docs/rama/username/index.html) ⸱ ✅ [Proxy Filters](https://ramaproxy.org/docs/rama/proxy/struct.ProxyFilter.html) |
| ✅ [User Agent (UA)](https://ramaproxy.org/book/intro/user_agent) | ✅ [Http Emulation](https://ramaproxy.org/docs/rama/ua/profile/struct.HttpProfile.html) ⸱ ✅ [Tls Emulation](https://ramaproxy.org/docs/rama/ua/profile/struct.TlsProfile.html) ⸱ ✅ [UA Parsing](https://ramaproxy.org/docs/rama/ua/struct.UserAgent.html) |
| ✅ [Fingerprinting](https://ramaproxy.org/docs/rama/net/fingerprint/index.html) | ✅ [Ja3](https://ramaproxy.org/docs/rama/net/fingerprint/struct.Ja3.html) ⸱ ✅ [Ja4](https://ramaproxy.org/docs/rama/net/fingerprint/struct.Ja4.html) ⸱ ✅ [Ja4H](https://ramaproxy.org/docs/rama/net/fingerprint/struct.Ja4H.html) ⸱ 🏗️ [Akamai passive h2](https://github.com/plabayo/rama/issues/517) <sup>(1)</sup> ⸱ ✅ [Peetprint (tls)](https://ramaproxy.org/docs/rama/net/fingerprint/struct.PeetPrint.html) |
| ✅ utilities | ✅ [error handling](https://ramaproxy.org/docs/rama/error/index.html) ⸱ ✅ [graceful shutdown](https://ramaproxy.org/docs/rama/graceful/index.html) ⸱ ✅ [Connection Pooling](https://ramaproxy.org/docs/rama/net/client/pool/index.html)  ⸱ ✅ [Tower Adapter](https://ramaproxy.org/docs/rama/utils/tower/index.html) ⸱ 🏗️ IP2Loc <sup>(1)</sup> |
| 🏗️ Graphical Interface | 🏗️ traffic logger <sup>(2)</sup> ⸱ 🏗️ [TUI implementation](https://ratatui.rs/) <sup>(2)</sup> ⸱ ❌ traffic intercept <sup>(3)</sup> ⸱ ❌ traffic replay <sup>(3)</sup> |
| ✅ binary | ✅ [prebuilt binaries](https://ramaproxy.org/book/deploy/rama-cli) ⸱ 🏗️ proxy config <sup>(2)</sup> ⸱ ✅ http client ⸱ ❌ WASM Plugins <sup>(3)</sup> |
| 🏗️ data scraping | 🏗️ Html Processor <sup>(2)</sup> ⸱ ❌ Json Processor <sup>(3)</sup> |
| ❌ browser | ❌ JS Engine <sup>(3)</sup> ⸱ ❌ [Web API](https://developer.mozilla.org/en-US/docs/Web/API) Emulation <sup>(3)</sup> |

> 🗒️ _Footnotes_
>
> * <sup>(1)</sup> Part of [`v0.3.0` milestone (ETA: 2025 Q4)](https://github.com/plabayo/rama/milestone/2)
> * <sup>(2)</sup> Part of [`v0.4.0` milestone (ETA: 2025 Q4)](https://github.com/plabayo/rama/milestone/3)
> * <sup>(3)</sup> No immediate plans, but on our radar. Please [open an issue](https://github.com/plabayo/rama/issues) to request this feature if you have an immediate need for it. Please add sufficient motivation/reasoning and consider [becoming a sponsor](./sponsor.md) to help accelerate its priority.

The primary focus of Rama is to aid you in your development of proxies:

- 🚦 [Reverse proxies](./proxies/reverse.md);
- 🔓 [TLS Termination proxies](./proxies/tls.md);
- 🌐 [HTTP(S) proxies](./proxies/http.md);
- 🧦 [SOCKS5 proxies](./proxies/socks5.md);
- 🔓 [SNI proxies](./proxies/sni.md);
- 🔎 [MITM proxies](./proxies/mitm.md);
- 🕵️‍♀️ [Distortion proxies](./proxies/distord.md).
- 🧭 [HaProxy (PROXY protocol)](./proxies/haproxy.md).

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

[![GitHub Sponsors][ghs-badge]][ghs-url]
[![Buy Me A Coffee][bmac-badge]][bmac-url]
[![Paypal Donation][paypal-badge]][paypal-url]
[![Discord][discord-badge]][discord-url]

> Rama also has a channel on the official Discord of the Tokio project.
> Feel free to join us there as well: <https://discord.com/channels/500028886025895936/1349098858831024209>

Please consult [the official docs.rs documentation][docs-url] or explore
[the examples found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples)
to know how to use rama for your purposes.

> 💡 You can find the edge docs of the rama framework code at <https://ramaproxy.org/docs/rama/index.html>,
> which contains the documentation for the main branch of the project.

🤝 Enterprise support, software customisations, integrations, professional support, consultancy and training are available upon request by sending an email to [partner@ramaproxy.org](mailto:partner@ramaproxy.org). Or get an entireprise subscription via [Gihub Sponsors](https://github.com/sponsors/plabayo/sponsorships?tier_id=300734).

💖 Please consider becoming [a sponsor][ghs-url] if you critically depend upon Rama (ラマ) or if you are a fan of the project.

## ⌨️ | `rama` binary

The `rama` binary allows you to use a lot of what `rama` has to offer without
having to code yourself. It comes with a working http client for CLI, which emulates
User-Agents and has other utilities. And it also comes with IP/Echo services.

It also allows you to run a `rama` proxy, configured to your needs.

Learn more about the `rama` binary and how to install it at [/deploy/rama-cli.md](./deploy/rama-cli.md).

> Learn more about the rama CLI code signing- and privacy policy at
> <https://ramaproxy.org/book/deploy/rama-cli.html#code-signing>.
> Applicable to MacOS and Windows platforms only.

## 🧪 | Experimental

🦙 Rama (ラマ) is to be considered experimental software for the foreseeable future. In the meanwhile it is already used
in production by ourselves and others alike. This is great as it gives us new perspectives and data to further improve
and grow the framework. It does mean however that there are still several non-backward compatible releases that will follow `0.2`.

In the meanwhile the async ecosystem of Rust is also maturing, and edition 2024 is also to be expected as a 2024 end of year gift.
It goes also without saying that we do not nilly-willy change designs or break on purpose. The core design is by now also well defined. But truth has to be said,
there is still plenty to be improve and work out. Production use and feedback from you and other users helps a lot with that. As such,
if you use Rama do let us know feedback over [Discord][discord-url], [email](mailto:glen@plabayo.tech) or a [GitHub issue](https://github.com/plabayo/rama/issues).

👉 If you are a company or enterprise that makes use of Rama, or even an individual user that makes use of Rama for commcercial purposes. Please consider becoming [a business/enterprise subscriber](https://github.com/sponsors/plabayo/sponsorships?tier_id=300734). It helps make the development cycle to remain sustainable, and is beneficial to you as well. As part of your benefits we are also available to assist you with migrations between breaking releases. For enterprise users we can even make time to develop those PR's in your integration codebases ourselves on your behalf. A win for everybody. 💪
