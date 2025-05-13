# 🧦 SOCKS5 proxies

<div class="book-article-intro">
    <img src="../img/proxy_llama_socks5.jpeg" alt="artistical representation of rama socks5 proxy as llama carying cargo through space while wearing socks">
    <div>
        SOCKS is an Internet protocol that exchanges network packets between a client and server through a proxy server. SOCKS5 optionally provides authentication so only authorized users may access a server. Practically, a SOCKS server proxies TCP connections to an arbitrary IP address, and provides a means for UDP packets to be forwarded.
        <p>— <a href="https://en.wikipedia.org/wiki/SOCKS">Wikipedia</a></p>
    </div>
</div>

[Examples](https://github.com/plabayo/rama/tree/main/examples):

- [/examples/socks5_connect_proxy.rs](https://github.com/plabayo/rama/tree/main/examples/socks5_connect_proxy.rs):
  Spawns a minimal socks5 CONNECT proxy with authentication, snappy and easy;
- [/examples/socks5_connect_proxy_mitm_proxy.rs](https://github.com/plabayo/rama/tree/main/examples/socks5_connect_proxy_mitm_proxy.rs):
  Spawns a socks5 CONNECT proxy with authentication and HTTP MITM capabilities;
- [/examples/socks5_connect_proxy_over_tls.rs](https://github.com/plabayo/rama/tree/main/examples/socks5_connect_proxy_over_tls.rs):
  Spawns a socks5 CONNECT proxy implementation which runs within a TLS tunnel

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

You'll notice that the above graph is the exact same one used in
[the http(s) Proxies chapter](./http.md). This is no coincidence,
as topology wise they are the same.

The key differences are:

- SOCKS5 proxies do not operate on the application layer, and sit directly on the application layer;
  - This means they have no need to touch for example the http packets at all, unless they want to;
  - It is also one of the reasons that they are typically said to be faster, given the SOCKS protocol,
    is fairly trivial and cheaply to interpret;
- These proxies also support UDP traffic, which is not commonly associated with [HTTP proxies](./http.md);

The SOCKS5 protocol is however in plaintext, just
like is the case with [HTTP Proxy authentication](./http.md).
Depending on your client support you can tunnel it through a TLS connection,
which from the Rama proxy perspective you can easily achieve.

Similar to [HTTP proxies](./http.md), a SOCKS5 proxy can only do routing of connections,
but can just as easily sniff the application packets and as such be [a MITM proxy](./mitm.md).
It can even go further and actively mold the packets and therefore be more of
[a Distortion proxy](./distort.md).

## Transport Proxies

Proxies that operate on the TCP/UDP layers are also referred to as "transport proxies".
Socks5 proxies are an example of this. An [http proxy](./http.md) can also be a transport proxy,
and in fact most commcercial proxies out in the wild are just that. The key difference
with socks5 proxies is however that for plain text requests it is still
the (http) proxy that will see the http request to be proxied, while even for plain text
requests (read: not encrypted with TLS) socks5 proxies do not _have_ to see the requests.

That said, regardless if you expose yourself as an [http proxy](./http.md) or socks5 proxy,
you can if you want to still run your proxy as a [Man In The Middle Proxy](./mitm.md),
and at that point you are no longer a transport proxy, but do see the http requests coming by,
regardless if they were initially secured via tls.

## SOCKS5 BIND

In addition to the common `CONNECT`, the SOCKS5 protocol also supports a less frequently used command: `BIND`.

Where `CONNECT` is used for outgoing connections to a remote server, `BIND` enables the proxy to **accept incoming connections** from a third party on behalf of the client. This is useful in protocols where the client needs to listen for a peer (e.g., FTP active mode, SIP, or custom peer-to-peer scenarios).

When a client sends a `BIND` request to a SOCKS5 proxy, it asks the proxy to open a listening socket. The proxy responds with the bound address and port. The client then waits for the proxy to accept an incoming connection from the peer. Once a connection is accepted, the proxy notifies the client and begins relaying data between the peer and the client.

You can try this flow using the following example:

- [/examples/socks5_bind_proxy.rs](https://github.com/plabayo/rama/tree/main/examples/socks5_bind_proxy.rs):
  Spawns a SOCKS5 proxy that supports the `BIND` command and allows you to experiment with incoming peer connections via the proxy.

This makes `BIND` a useful tool for reverse connection setups and client-initiated listeners in NAT'd environments or restricted network conditions.

## SOCKS5 UDP ASSOCIATE

The `UDP ASSOCIATE` command in SOCKS5 allows a client to proxy **UDP datagrams** through the SOCKS5 server. This is essential for supporting protocols that are UDP-based, such as DNS, QUIC, VoIP, gaming traffic, or any custom UDP-based application.

When the client sends a `UDP ASSOCIATE` request, it provides a local IP/port hint (or just `0.0.0.0:0`) and receives from the proxy a `BND.ADDR:BND.PORT` in return. This is the address the client should send UDP packets to. The client then sends UDP datagrams, each wrapped in a lightweight SOCKS5 UDP header, to that address. The proxy receives these datagrams, unpacks them, forwards them to the intended destination, and can relay responses back to the client in the same wrapped format.

The TCP connection used to initiate the UDP ASSOCIATE must remain open for the duration of the UDP session, as it controls the lifetime of the association.

You can test this functionality using the following example:

- [/examples/socks5_udp_associate.rs](https://github.com/plabayo/rama/tree/main/examples/socks5_udp_associate.rs):
  Spawns a SOCKS5 proxy that supports the `UDP ASSOCIATE` command, enabling proxying of UDP traffic over a TCP-controlled SOCKS5 session.

This command enables powerful use cases like full DNS proxying or tunneling UDP through restrictive firewalls via a single TCP-controlled proxy session.
