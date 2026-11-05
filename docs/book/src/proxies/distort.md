# 🕵️‍♀️ Distortion proxies

<div class="book-article-intro">
    <img src="../img/proxy_llama_distort.jpeg" alt="artistical representation of rama distort proxy as llama desguised as human in badly masked environment">
    <div>
        Distorting proxy refers to a type of proxy server that masks the client's IP address by modifying the HTTP headers and presents a fake IP address to the target server. It is often used to enhance privacy, add a layer of anonymity, and limit the ability to monitor the user's browsing activity.
        <p>— <a href="https://nordvpn.com/cybersecurity/glossary/distorting-proxy">NordVPN</a></p>
    </div>
</div>

[Examples](https://github.com/plabayo/rama/tree/main/examples):

- [/examples/src/http_mitm_relay_proxy_boring.rs](https://github.com/plabayo/rama/tree/main/examples/src/http_mitm_relay_proxy_boring.rs):
  An HTTP(S) MITM relay proxy which mirrors the client's TLS ClientHello towards the target,
  and uses `ProfileEmulateLayer` to auto-detect the client's user-agent profile and
  emulate its outgoing request headers.

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

The Http/Tls content, version, config and flow can be adapted by the distortion proxy,
often in function of a specific web client it wishes to emulate. The IP Address can be changed
by the use of an upstream proxy.

The goal is to ensure your requests are not being fingerprinted
either as a collective or in order to connect you to a technology stack or origin
seen as malicious.
