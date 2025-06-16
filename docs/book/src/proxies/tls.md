# 🔓 TLS Termination proxies

<div class="book-article-intro">
    <img src="../img/proxy_llama_tls.jpeg" alt="artistical representation of rama TLS Termination proxy as llama unlocking cargo to move it forward unprotected">
    <div>
        A TLS termination proxy is a proxy server that acts as an intermediary point between client and server applications, and is used to terminate and/or establish TLS (or DTLS) tunnels by decrypting and/or encrypting communications. This is different to TLS pass-through proxies that forward encrypted (D)TLS traffic between clients and servers without terminating the tunnel.
        <p> — <a href="https://en.wikipedia.org/wiki/TLS_termination_proxy">Wikipedia</a></p>
    </div>
</div>

[Examples](https://github.com/plabayo/rama/tree/main/examples):

- [/examples/tls_rustls_termination.rs](https://github.com/plabayo/rama/tree/main/examples/tls_rustls_termination.rs):
  Spawns a mini handmade http server, as well as a TLS termination proxy, forwarding the
  plain text stream to the first.
- [/examples/mtls_tunnel_and_service.rs](https://github.com/plabayo/rama/blob/main/examples/mtls_tunnel_and_service.rs):
  Example of how to do mTLS (mutual TLS, where the client also needs a certificate) using rama,
  as well as how one might use this concept to provide a tunnel service build with these concepts;

## Description

<div class="book-article-image-center">

```dot process
digraph {
    pad=0.2;
    "client" -> "proxy (rama)" [dir=both; label="  https"]
    "proxy (rama)" -> "server A" [dir=both; label="  http"]
    "proxy (rama)" -> "server B" [dir=both; label="  http"]
}
```

</div>

[Reverse proxies](./reverse.md) are a superset of proxies that also
include TLS Termination Proxies. It's very common for a reverse proxy
to also terminate the TLS tunnel.
