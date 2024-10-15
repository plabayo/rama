# 🌐 HTTP(S) proxies

<div class="book-article-intro">
    <img src="../img/proxy_llama_http.jpeg" alt="artistical representation of rama http proxy as llamas spread across the globe">
    <div>
        HTTP(S) proxies forward HTTP requests. The request from the client is the same as a regular HTTP request except the full URL is passed, instead of just the path. Some web proxies allow the HTTP CONNECT method to set up forwarding of arbitrary data through the connection; a common policy is to only forward port 443 to allow HTTPS traffic.
        <p>— <a href="https://en.wikipedia.org/wiki/Proxy_server#Web_proxy_servers">Wikipedia</a></p>
    </div>
</div>

[Examples](https://github.com/plabayo/rama/tree/main/examples):

- [/examples/http_connect_proxy.rs](https://github.com/plabayo/rama/tree/main/examples/http_connect_proxy.rs):
  Spawns a minimal http proxy which accepts http/1.1 and h2 connections alike,
  and proxies them to the target host.
- [/examples/https_connect_proxy.rs](https://github.com/plabayo/rama/tree/main/examples/https_connect_proxy.rs):
  Spawns a minimal https connect proxy which accepts http/1.1 and h2 connections alike,
  and proxies them to the target host through a TLS tunnel.

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
[the Reverse Proxies chapter](./reverse.md). In an abstract topology sense
this is expected, however there are typically differences:

- The client, proxy and server are typically in 3 different intranets,
  with communication going typically over the intranet;
- The use cases of a reverse proxy are very wide, while
  those of the http proxy are pretty specific.

The most common use case of an http(s) proxy is to
conceal the MAC (~L3) and IP address (~L4) of the client, and have the request
originate instead from the http(s) proxy.

In case the client request is encrypted (TLS) it will typically make a
plaintext (http/1.1) request with the "CONNECT" method to the proxy,
whom on the behalve of the client will establish an encrypted tunnel
to the target (server), from there it will:

- either just copy the data between the two connections as they are;
- or it might act as [a MITM proxy](./mitm.md) and actually read and
  possibly even modify the incoming (http) request prior to sending
  it to the target client. In this case it might even act
  as [a distortion proxy](./distort.md).

In case we are dealing with TLS-encrypted traffic it does mean that the client
most likely will have to accept/approve the authority of the proxy's TLS certification,
given it will not match the expected target (server) TLS certificate. Depending on the
client's network policies this might be handled automatically due to the use
of a non-public [root certificate](https://en.wikipedia.org/wiki/Root_certificate).

Plain text (http) requests are typically immediately made with the Host/Authorization
headers being equal to the desired target server. Which once again looks a lot more
like logic that a [reverse proxy](./reverse.md) would also do among one of its many tasks.

See the official RFCs for more information regarding HTTP semantics and
protocol specifications.

## SNI Proxies

In case an http proxy Man-In-The-Middle's (MITM) TLS encrypted traffic (e.g. https),
it becomes essentially a SNI proxy, where SNI stands for "Server Name Indication".

It is a proxy which terminates incoming tls connections and makes use of that connection's
Client Hello "Server Name" extension to establish the connection on the other side. In case
that host is a domain it will also have to resolve (using DNS) it into an IPv4/IPv6 address.

Within Rama we usually refers to SNI Proxies as MITM proxies, given we usually
focus on the web. It is however important to note that a SNI Proxy is just a specific
example of a MITM proxy and not 1-to-1 connected.

These DNS Queries can also be cached in the (SNI) proxy as to make sure
"hot" targets are not overly queried.

In case you want to intercept both https and http traffic, you'll want your
http proxy to act as a SNI proxy, which you do by terminating the TLS Connection
right after you processed the http CONNECT request.

### SNI Proxies as invisible proxies

A SNI Proxy can be send tls-encrypted traffic without it first going
via a CONNECT request. This is great for environments that might not
support proxies.

This can work by allowing your firewall, ip table, router or some other "box" in the middle,
to override the DNS resolution for specific domain names
to the IP of the (SNI) proxy. The proxy on its turn will establish a connection
based on the Server Name as discussed previously and onwards it goes.

A proxy without a proxy protocol. That is also what a SNI proxy can be.
