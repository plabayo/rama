![rama banner](https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg)

🦙 **Rama** (ラマ) is a modular network service and proxy framework for the Rust language.

It gives you fine grained, programmable control over how packets move through your stack.  
With Rama you can build:

- production grade reverse and forward proxies
- HTTP and TLS termination layers
- traffic inspection, distortion and security pipelines
- high volume scraping and data extraction systems
- custom HTTP clients with deep control over the wire

Rama is already used in production by organisations across industries for use cases such as network security, routing, API gateways, scraping infrastructure and traffic analytics.

Rama is async first and built entirely on top of [`tokio`](https://tokio.rs).

---

## 🎯 Who this book is for

This book serves two audiences:

### 1. Developers and teams
You want to understand what Rama is, why it exists, and how to use it to build proxies, servers or clients with full control over networking layers.

### 2. Organisations
You rely on networking infrastructure and want to understand whether Rama is the right long term foundation.  
You may also be looking for maintenance, support, feature development or training.

If you are new to Rama, begin with [the **Why Rama** chapter](./why_rama.md).  
If you already know what you want to build, jump to the relevant proxy or web service chapters.

---

## 🚀 A new model for programmable networking

Rama is more than a toolkit.  
It is a mindset shift for designing dynamic, composable network services.

Traditional frameworks tend to hide or abstract away the networking layers.  
Rama exposes them, while still giving you safe, ergonomic building blocks.

You choose:

- how requests flow  
- where they are transformed  
- which layers apply  
- whether you operate at transport-, application- or some layer in between

This enables use cases that are difficult or impossible in conventional frameworks.

---

## 🧱 Batteries included

Rama ships with a large set of capabilities so you can focus on your unique logic instead of reinventing common networking primitives.

### Highlights

- **Transports:** TCP, UDP, UDS, middleware, instrumentation  
- **HTTP:** 1.1 and 2, automatic protocol detection, routing, middleware  
- **TLS:** Rustls and BoringSSL support  
- **Proxy protocols:** HTTP CONNECT, HTTPS CONNECT, SOCKS5, HAProxy PROXY protocol  
- **Web protocols:** SSE, WebSocket  
- **Telemetry:** tracing and OpenTelemetry  
- **Fingerprinting:** JA3, JA4, JA4H, PeetPrint, Akamai h2
- **User Agent emulation:** HTTP + TLS profiles for distortion proxies  
- **Diagnostics:** HAR and cURL export  
- **Utilities:** error handling, graceful shutdown, connection pooling

The detailed feature matrix in the repository readme or website.

---

## 🧪 Experimental, but already in production

Rama is considered **experimental software**, not because it is unstable, but because:

- the networking and async ecosystem in Rust continues to evolve  
- Rama is still expanding and refining its design  
- we occasionally introduce small breaking changes between releases

Despite this, Rama is already used in production by multiple companies including Plabayo.  
Real world users provide crucial feedback that helps shape priorities and design.

If you use Rama in production, please reach out — your input genuinely matters.

---

## 🕸️ A framework built for proxies

Rama’s core strength is proxy development.  
This book provides dedicated chapters for:

- 🚦 Reverse proxies  
- 🔓 TLS termination proxies  
- 🌐 HTTP(S) proxies  
- 🧦 SOCKS5 proxies  
- 🔓 SNI routing  
- 🔎 MITM proxies  
- 🕵️ Distortion proxies  
- 🧭 HAProxy (PROXY protocol)

Distortion proxies are backed by a public fingerprinting service at <https://fp.ramaproxy.org>.

We also provide a public echo service for debugging TLS and HTTP request signatures:

```bash
curl -XPOST 'https://echo.ramaproxy.org/foo?bar=baz' \
  -H 'x-magic: 42' --data 'whatever forever'
```

You can use this while crafting distorted or experimental HTTP requests, but please do so with moderation.
If you plan to send a lot of traffic, run your own echo service using the `rama` CLI instead of relying on `echo.ramaproxy.org`.

BrowserStack sponsors Rama by providing automated cross platform browser testing on real devices.
Their infrastructure uses the public fingerprinting service to collect HTTP and TLS fingerprints across platforms and browsers.

---

## 🌐 Beyond proxies: web services and clients

While Rama is built with proxies as a primary focus, it is equally suitable for:

* dynamic HTTP APIs
* static file serving
* WebSocket and Server Sent Events (SSE)
* Kubernetes health and readiness endpoints
* metrics and control plane services

The same service and middleware abstractions apply to both **servers** and **clients**.

Rama provides:

* an `EasyHttpWebClient` for low level control over HTTP requests and responses
* an `HttpClientExt` trait for a higher level, fluent client API

You can find more detail in the **Web Services** and **HTTP Clients** chapters of this book.

---

## ⌨️ The `rama` binary

The `rama` CLI lets you use many features without writing Rust code:

* a CLI HTTP client with User Agent emulation and utilities
* IP and echo services for debugging traffic
* proxies configured to your needs

The CLI is documented in the [`rama` binary chapter](./deploy/rama-cli.md), including installation instructions and platform specific notes (such as code signing requirements on macOS and Windows).

---

## 🤝 For organisations

If your organisation relies on Rama or plans to, the maintainers offer:

* **Support and maintenance contracts**
  Help with upgrades, bug fixes and operational questions.
* **Feature development contracts**
  Prioritised or extended features in Rama itself.
* **Consulting and integration**
  Design and implementation of proxies, scraping pipelines, security layers and other network services built on Rama.
* **Training and knowledge transfer**
  Workshops, mentoring and code reviews to help your team become productive with Rama.

To discuss options, reach out at **[hello@plabayo.tech](mailto:hello@plabayo.tech)** or see the sponsor and partner information in the [Sponsors](./sponsor.md) chapter.

---

## 💬 Community and where to get help

You can get help, share ideas and follow development in several places:

* Public `#rama` channel on the community Discord: [invite link][discord-url]
* The Rama channel on the official Tokio Discord:
  [https://discord.com/channels/500028886025895936/1349098858831024209](https://discord.com/channels/500028886025895936/1349098858831024209)
* GitHub issues for bugs, questions and feature requests:
  [https://github.com/plabayo/rama/issues](https://github.com/plabayo/rama/issues)

The latest API documentation is available at:

* Stable docs: [https://docs.rs/rama](https://docs.rs/rama)
* Edge docs (main branch): [https://ramaproxy.org/docs/rama/index.html](https://ramaproxy.org/docs/rama/index.html)
