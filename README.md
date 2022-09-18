# llama

llama is a proxy framework written purely in Rust,
it's services all the way down.

> llama is in early development and not ready for production use yet.
> Use this framework at your own risk and your own responsibility.

## Issue backlog

Tracking of active issues/features that require urgent attention:

- do not require TCPService::Future to be Send, most likely we need to implement our own future instead...
- do not require services to be Clone, as services in the ecosystem do not require that by default
- incoming connections:
  - make sure that process is closed only when all tasks are released
  - do add an opt-in feature for a timeout where possible

## Goals

With llama you can should be able to write any typical tls/http proxy,
without having to write all the boilerplate code first,
but by keeping all the power that comes with having a source-code driven proxy.

The following technologies are used under the hood of llama,
and are for the most part exposed to the user:

- [tokio][tokio]: async runtime of choice, and also drives the TCP layer, the foundation for most common proxies;
- [tower][tower]: layer your proxy together using tower, all services provided by llama are tower-compatible;
- [rustls][rustls]: tls server layer (reverse proxy) as well as tls client layer, provided by _rustls_, safe and fun;
- [hyper][hyper]: http1/2/3 client of choice, also used in case you wish to implement an http (MITM) proxy;
- [fast-socks5][socks5]: socks5 client/server, useful in case you want a socks5 proxy;
- [hyper-tungstenite-rs][ws]: serve incoming web socket requests;

[tokio]: https://tokio.rs
[tower]: https://github.com/tower-rs/tower
[rustls]: https://github.com/rustls/rustls
[hyper]: https://hyper.rs
[socks5]: https://github.com/dizda/fast-socks5
[ws]: https://github.com/de-vri-es/hyper-tungstenite-rs

All these technologies are built-in to llama and drive many of its provided services.
Llama is also bundled with some custom middleware layers as well that can be used in combination with
these services. Important to know is that:

- All layers are optional and composable how you want;
- You should be able to use any other Tokio-compatible Tower-driven library out there, for all your middleware and service needs;

As such you should easily be able to implement your own Service for any layer you wish,
while at the same time retaining the ability to seamlessly piggy-back on llama for most of your proxy logic.

## Services

With [Tower][tower] everything is a service. A service takes in a request and outputs either an error or a response.
What the actual types for these request-response pairs are, is up to you and depend mostly on the layer it is used.
In tower it is typical that a service wraps another service, as such all your services and middleware will stack on top of each other,
like a... _tower_.

### Socks5 Proxy Example

A socks5 proxy could be implemented as follows:

```
tcp::Server
     ⤷ socks5::Server ⭢ /target/
```

A typical llama proxy will start with `tcp::Server`.
This gives you [an accepted TcpStream](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html).

> Given "Accept" is a _kernel_ function this is the lowest level you can go painlessly.
> Should you want to be able to act upon incoming tcp clients prior to accepting,
> you'll need to implement it yourself on kernel level, and make your own Rust service
> to make use of that kernel module.
>
> _eBPF_ could help you achieve this, which can be done
> using https://github.com/foniod/redbpf. Note though that this comes
> with a lot of effort on your side while at the same time not giving a lot in return.

## Pango

Pango is a cross platform TLS Reverse Proxy, written purely in Rust.
It can be used either as a standalone binary where it is used as part of your backend infrastructure,
or as a library in order to use Pango as a [Tower][tower] service which wraps your _Http_ service.

[Axum](https://github.com/tokio-rs/axum) is the recommended http server library of choice
should you wanna go for the latter approach, as it will fit nicely with the rest of the code.

Here is a high level overview of how Pango's services are composed:

```
tcp::Server
 ⤷ tcp::middleware::*
     ⤷ tls::Server
         ⤷ tls::middleware::*
             ⤷ tcp::Client ⭢ /target/
```
