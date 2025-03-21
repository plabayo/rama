# 🚦 Reverse proxies

<div class="book-article-intro">
    <img src="../img/proxy_llama_reverse.jpeg" alt="artistical representation of rama reverse proxy as llama directing traffic">
    <div>
        In computer networks, a reverse proxy is an application that sits in front of back-end applications and forwards client (e.g. browser) requests to those applications. The resources returned to the client appear as if they originated from the web server itself.
        <p>— <a href="https://en.wikipedia.org/wiki/Reverse_proxy">Wikipedia</a></p>
    </div>
</div>

[Examples](https://github.com/plabayo/rama/tree/main/examples):

- [/examples/tls_rustls_termination.rs](https://github.com/plabayo/rama/tree/main/examples/tls_rustls_termination.rs):
  Spawns a mini handmade http server, as well as a TLS termination proxy, forwarding the
  plain text stream to the first.
  - See also [the TLS Termination Proxies chapter](./tls.md), as a specific example of a reverse proxy;

## Description

<div class="book-article-image-center">

```dot process
digraph {
    pad=0.2;
    "client" -> "proxy (rama)" [dir=both]
    "proxy (rama)" -> "server A" [dir=both]
    "proxy (rama)" -> "server B" [dir=both]
}
```

</div>

Reverse proxies are very common and chances are big that you've set it up yourself
already, beknowingly or not. For standard proxy cases like this, the default
proxy solutions available are usually good enough. It is however just as simple
to make with rama, which gives you a degree of freedom that might come in handy.

The reasons on why one wants a reverse proxies are usually among the following:

- it improves security by:
  - having only one service exposed to the public intranet;
  - your "backend" applications can stay very simple, e.g. a plain old http server;
  - all your policies, authentication, firewall rules and more can be handled in this one place;
- tls connections are typically terminated here,
  forwarding the requests as plain text over the internal network to the "backend services;
  - see [the TLS Termination proxies chapter](./tls.md) for more info on that.

A trivial example is that it allows your old PHP http/1 web service to be
exposed to the web as a secured h3 server with caching and more provided,
without changing your code from the 90s / early 2000s. If that is what you want.
