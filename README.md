# llama

llama is a proxy framework written purely in Rust,
it's services all the way down.

> llama is in early development and not ready for production use yet.
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

## Pango

Pango is a cross platform TLS Reverse Proxy, written purely in Rust, built on top of [rama](./rama).
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
