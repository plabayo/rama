# Web Servers

Rama is a powerful and flexible service framework that excels at building web services, though it takes a different approach than traditional web frameworks. While Rama is often associated with proxy services, it's equally capable of building robust web applications and APIs.

## Philosophy

Rama's approach to web services is built on the principle of empowerment through control and flexibility. Rather than providing high-level abstractions that make certain patterns easier but limit your options, Rama gives you direct access to the underlying layers while still providing ergonomic tools for common tasks.

This philosophy means:
- Full control over your network stack
- Direct access to transport layers when needed
- No "magic" or hidden behavior
- The ability to build exactly what you need, how you need it
- Seamless integration with proxy services when required

## Use Cases

Rama is particularly well-suited for:

- Building APIs that need fine-grained control over the network stack
- Services that require both web and proxy capabilities
- Applications where performance and control are critical
- Systems that need to integrate with custom protocols or transport layers
- Services that require deep integration with the operating system

Common examples include:
- Kubernetes health services
- Metric exposure endpoints
- Device management APIs
- Control panels and admin interfaces
- Custom protocol servers
- High-performance API gateways

## Comparison with Axum

[Axum](https://docs.rs/axum/latest/axum) is an excellent web framework that shares many similarities with Rama. Both run on Tokio and can be used to build web services. The key differences are:

- **Philosophy**: Axum focuses on providing high-level abstractions for common web patterns, while Rama emphasizes control and flexibility
- **Scope**: Axum is specifically designed for web services, while Rama is a broader service framework that includes web capabilities
- **Control**: Rama gives you more direct access to the network stack and transport layers
- **Integration**: Rama makes it easier to combine web services with proxy functionality

The choice between them often comes down to your priorities:
- Choose Axum if you want a framework optimized for traditional web development with excellent developer experience
- Choose Rama if you need more control, want to integrate with proxy services, or have specific requirements that benefit from direct access to the network stack

## Datastar

> Datastar helps you build reactive web applications with the simplicity of server-side rendering and the power of a full-stack SPA framework.
>
> — <https://data-star.dev/>

Rama has built-in support for [🚀 data-\*](https://data-star.dev).
You can see it in action in [Examples](https://github.com/plabayo/rama/tree/main/examples):

- [/examples/http_sse_datastar_hello.rs](https://github.com/plabayo/rama/tree/main/examples/http_sse_datastar_hello.rs):
  SSE Example, showcasing a very simple datastar example,
  which is supported by rama both on the client as well as the server side.

Rama rust docs:

- SSE support: <https://ramaproxy.org/docs/rama/http/sse/datastar/index.html>
- Extractor support (`ReadSignals`): <https://ramaproxy.org/docs/rama/http/service/web/extract/datastar/index.html>
- Embedded JS Script: <https://ramaproxy.org/docs/rama/http/service/web/response/struct.DatastarScript.html>

<div class="book-article-image-center">
<img style="width: 50%" src="img/rama_datastar.jpg" alt="llama cruising through space empowered by the powerfull rama/datastar combo">
</div>

You can join the discord server of [🚀 data-\*](https://data-star.dev) at <https://discord.gg/sGfFuw9k>,
after which you can join [the #general-rust channel](https://discord.com/channels/1296224603642925098/1315397669954392146)
for any datastar specific help.

Combining [🚀 data-\*](https://data-star.dev) with 🦙 Rama (ラマ) provides a powerful foundation for your web application—one that **empowers you to build and scale without limitations**.

The core concept of datastar is to keep one long lived connection per user (agent) session open,
through which you stream your data(star) events (SSE). While your client interacts with the server
via regular HTTP calls. This paradigm is often referred to as ommand Query Responsibility Segregation (CQRS).
Covering CQRS properly is out of scope of this doc as well as the knowledge of the author.
You can however start your journey in that rabbit hole by reading these resources:

- [Ubiquitous language](https://martinfowler.com/bliki/UbiquitousLanguage.html)
- [The Blue Book](https://www.amazon.com/Domain-Driven-Design-Tackling-Complexity-Software-ebook/dp/B00794TAUG) e original text on DDD by Eric Evans
- [The Red Book](https://www.amazon.com/Implementing-Domain-Driven-Design-Vaughn-Vernon-ebook/dp/B00BCLEBN8) - a book refined from years of experience with DDD

## Examples

Rama provides a rich set of examples demonstrating its web service capabilities. These range from simple services to complex applications:

### Basic Services
- [/examples/http_listener_hello.rs](https://github.com/plabayo/rama/blob/main/examples/http_listener_hello.rs): A minimal web service example
- [/examples/http_health_check.rs](https://github.com/plabayo/rama/blob/main/examples/http_health_check.rs): A health check service
- [/examples/http_service_hello.rs](https://github.com/plabayo/rama/blob/main/examples/http_service_hello.rs): Demonstrates transport layer control

### Production-Ready Examples
- [/examples/http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/http_k8s_health.rs): A production-ready Kubernetes health service
- [/examples/http_key_value_store.rs](https://github.com/plabayo/rama/tree/main/examples/http_key_value_store.rs): A key-value store API
- [/examples/http_web_service_dir_and_api.rs](https://github.com/plabayo/rama/tree/main/examples/http_web_service_dir_and_api.rs): A full web application with API

### More Examples
- [/examples/http_web_router.rs](https://github.com/plabayo/rama/tree/main/examples/http_web_router.rs): Path-based routing, something you are probably already familiar with
- [/examples/http_form.rs](https://github.com/plabayo/rama/tree/main/examples/http_form.rs): Form handling
- [/examples/http_service_fs.rs](https://github.com/plabayo/rama/tree/main/examples/http_service_fs.rs): Static file serving
- [/examples/http_user_agent_classifier.rs](https://github.com/plabayo/rama/tree/main/examples/http_user_agent_classifier.rs): Request classification

For a real-world example, check out the [rama cli `fp` source code](https://github.com/plabayo/rama/tree/main/rama-cli/src/cmd/fp), which implements a production web service for the Rama fingerprinting service.

> This example demonstrates the power of Rama's [`match_service`](https://docs.rs/rama-http/latest/rama_http/service/web/macro.match_service.html) macro for creating efficient, box-free service routers.
