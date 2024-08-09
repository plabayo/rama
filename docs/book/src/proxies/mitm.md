# 🔎 MITM proxies

<div class="book-article-intro">
    <img src="../img/proxy_llama_mitm.jpeg" alt="artistical representation of rama MITM proxy as llama snooping into cargo packages">
    <div>
        A Man-In-The-Middle proxy (MITM) is a proxy which sits in between the client and the server.
        That by itself is nothing special and is in fact what all proxies do. What defines this kind of
        proxy is that it actively interprets the application layer packets. It might also
        modify the packets as they pass, but more often then not inspecting and tracking
        is all it does.
    </div>
</div>

[Examples](https://github.com/plabayo/rama/tree/main/examples):

- [/examples/http_mitm_proxy.rs](https://github.com/plabayo/rama/tree/main/examples/http_mitm_proxy.rs):
  Spawns a minimal http proxy which accepts http/1.1 and h2 connections alike,
  and proxies them to the target host;
  - Similar to [/examples/http_connect_proxy.rs](https://github.com/plabayo/rama/tree/main/examples/http_connect_proxy.rs)
    but MITM for both http and https requests alike.

## Description

<div class="book-article-image-center">

```dot process
digraph {
    pad=0.2;
    "client" -> "proxy (rama)" [dir=both]
    "proxy (rama)" -> "server A" [dir=both]
    "proxy (rama)" -> "upstream proxy" [dir=both]
    "upstream proxy" -> "server B" [dir=both]
}
```

</div>

A MITM proxy is typically setup as [an HTTP Proxy](./http.md), but in case you
want it can be setup as [a SOCKS5 proxy](./socks5.md) instead.
