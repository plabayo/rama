![rama banner](https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg)

🦙 **Rama** (ラマ) is a modular network service and proxy framework for the Rust language.

It gives you fine grained, programmable control over how packets move through your stack.  
With Rama you can build:

- production grade reverse and forward proxies
- traffic inspection, distortion and security pipelines
- high volume data extraction systems
- custom clients, servers and proxies with deep control over the wire

Rama is already used in production by organisations across industries for use cases
such as network security, routing, API gateways, scraping infrastructure and traffic analytics.

Rama is async first and built entirely on top of [`tokio`](https://tokio.rs).

## Who this book is for

This book serves two audiences:

### 1. Developers and teams

You want to understand what Rama is, why it exists, and how to use it to build proxies, servers or clients with full control over networking layers.

### 2. Organisations

You rely on networking infrastructure and want to understand whether Rama is the right long term foundation.  
You may also be looking for maintenance, support, feature development or training.

If you are new to Rama, begin with [the **Why Rama** chapter](./why_rama.md).  
If you already know what you want to build, jump to the relevant proxy or web service chapters.

> **rama is already used in production by companies at scale for use cases such as network security,
> data extraction, API gateways and routing**. We also offer **commercial support**.
>
> Service contracts and partner offerings are available at [ramaproxy.com](https://ramaproxy.com).

## A new model for programmable networking

Rama is more than a toolkit.  
It is a mindset shift for designing dynamic, composable network services.

Traditional frameworks tend to hide or abstract away the networking layers.  
Rama exposes them, while still giving you safe, ergonomic building blocks.

You choose:

- how requests flow  
- where they are transformed  
- which layers apply  
- whether you operate at transport-, application-, some layer in between or all over the place.

This enables use cases that are difficult or impossible in conventional frameworks.

## Batteries included

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

## A framework built for proxies

Rama’s core strength is proxy development.
See [the intro to proxy chapters](./proxies/intro.md) for
learning more about the various kind of proxies.

Once you start to get a feel on the different use cases
of proxies, you probably also want to read [how to operate proxies](./proxies/operate/intro.md).

## Beyond proxies: web services and clients

While Rama is built with proxies as a primary focus, it is equally suitable for:

* dynamic HTTP APIs (web services as most people know it)
* gRPC servers (and clients)
* static file serving
* WebSocket and Server Sent Events (SSE)
* Kubernetes health and readiness endpoints
* metrics and control plane services

The same service and middleware abstractions apply to both **servers** and **clients**.

Rama provides:

* an `EasyHttpWebClient` for low level control over HTTP requests and responses
* an `HttpClientExt` trait for a higher level, fluent client API

You can find more detail in the [**Web Services**](./web_servers.md) and
[**HTTP Clients**](./http/http_clients.md) chapters of this book.


## The `rama` binary

The `rama` CLI lets you use many features without writing Rust code:

* a CLI HTTP client with User Agent emulation and utilities
* IP and echo services for debugging traffic
* proxies configured to your needs

The CLI is documented in the [`rama` binary chapter](./deploy/rama-cli.md), including installation instructions and platform specific notes (such as code signing requirements on macOS and Windows).

## Community and where to get help

You can get help, share ideas and follow development in several places:

* Public `#rama` channel on the community Discord: [invite link](https://discord.gg/29EetaSYCD)
* The Rama channel on [the official Tokio Discord](https://discord.com/channels/500028886025895936/1349098858831024209)
* GitHub issues for bugs, questions and feature requests:
  <https://github.com/plabayo/rama/issues>

The latest API documentation is available at:

* Stable docs: [https://docs.rs/rama](https://docs.rs/rama)
* Edge docs (main branch): [https://ramaproxy.org/docs/rama/index.html](https://ramaproxy.org/docs/rama/index.html)
