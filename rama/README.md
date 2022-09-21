# rama (ラマ)

rama is a proxy framework using Tokio written purely in Rust,
it's services all the way down.

The name is Japanese for rama, the mascot and spiritual inspiration of this proxy framework.

> rama is in early development and not ready for production use yet.
> Use this framework at your own risk and your own responsibility.

Look into [rama's README](./rama/README.md) for more information.

## Issue backlog

Tracking of active issues/features that require urgent attention:

- use Service properly from within TCP Server:
    - call ready first before using it, to make sure service is ready;
    - do not require to clone it, instead we probably want to do something else, but not sure what;
- do not require TCPService::Future to be Send, most likely we need to implement our own future instead...
- do not require services to be Clone, as services in the ecosystem do not require that by default
- incoming connections:
  - make sure that process is closed only when all tasks are released
  - do add an opt-in feature for a timeout where possible
  - see <https://docs.rs/hyper/0.14.20/src/hyper/server/server.rs.html#153-159>
    for inspiration how we might instead allow for opt-in graceful shutdown behavior
- server will need to implement future, will be the way to go to keep things as efficient as possible,
  same for other services

## Goals

With rama you can should be able to write any typical tls/http proxy,
without having to write all the boilerplate code first,
but by keeping all the power that comes with having a source-code driven proxy.

The following technologies are used under the hood of rama,
and are for the most part exposed to the user:

- [tokio][tokio]: async runtime of choice, and also drives the TCP layer, the foundation for most common proxies;
- [tower][tower]: layer your proxy together using tower, all services provided by rama are tower-compatible;
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

All these technologies are built-in to rama and drive many of its provided services.
Llama is also bundled with some custom middleware layers as well that can be used in combination with
these services. Important to know is that:

- All layers are optional and composable how you want;
- You should be able to use any other Tokio-compatible Tower-driven library out there, for all your middleware and service needs;

As such you should easily be able to implement your own Service for any layer you wish,
while at the same time retaining the ability to seamlessly piggy-back on rama for most of your proxy logic.

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

A typical rama proxy will start with `tcp::Server`.
This gives you [an accepted TcpStream](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html).

> Given "Accept" is a _kernel_ function this is the lowest level you can go painlessly.
> Should you want to be able to act upon incoming tcp clients prior to accepting,
> you'll need to implement it yourself on kernel level, and make your own Rust service
> to make use of that kernel module.
>
> _eBPF_ could help you achieve this, which can be done
> using https://github.com/foniod/redbpf. Note though that this comes
> with a lot of effort on your side while at the same time not giving a lot in return.
