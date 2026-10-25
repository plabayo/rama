# 🎭 MASQUE proxies (CONNECT-UDP)

MASQUE proxies carry traffic other than TCP through HTTP. Rama implements proxying UDP in
HTTP, CONNECT-UDP ([RFC 9298]): a client asks the proxy for a UDP tunnel to a target, and
the UDP payloads travel inside that HTTP request. The main use is HTTP/3, whose QUIC
connections run over UDP and so cannot go through an ordinary `CONNECT` tunnel.

<div class="book-article-image-center">

```dot process
digraph {
    pad=0.2;
    "client" -> "MASQUE proxy (rama)" [dir=both, label=" HTTP/3, HTTP/2 or HTTP/1.1 "]
    "MASQUE proxy (rama)" -> "target (UDP)" [dir=both]
}
```

</div>

## How it works

A tunnel is one HTTP request to the proxy:

- HTTP/3 and HTTP/2 send an Extended CONNECT with `:protocol = connect-udp`; HTTP/1.1
  upgrades a `GET` request.
- The request path names the target, by default
  `/.well-known/masque/udp/{target_host}/{target_port}/`. A proxy can use any URI template
  that has both variables.
- The proxy resolves the target and checks it against its policy before it accepts the
  tunnel: `101 Switching Protocols` on HTTP/1.1, a `2xx` on HTTP/2 and HTTP/3. Rama refuses
  private, loopback and link-local targets unless that is allowed.
- UDP payloads then travel as HTTP Datagrams ([RFC 9297]). On HTTP/3 they use QUIC DATAGRAM
  frames when both peers support them; otherwise they travel as DATAGRAM capsules on the
  request stream.

A MASQUE proxy is also an HTTPS proxy: `CONNECT` still tunnels TCP. A rama client with a
`masque://` proxy therefore tunnels HTTP/3 with CONNECT-UDP and HTTP/1.1 and HTTP/2 with
`CONNECT`.

### Proxy addresses

A MASQUE proxy is addressed with the `masque` scheme. The default port is 443:

```text
masque://proxy.example
masque://user:pass@proxy.example:8443
masque://proxy.example/masque?h={target_host}&p={target_port}
```

The path, when present, is the proxy's URI template. An `https://` proxy address whose path
is a template with both variables is a MASQUE proxy too, such as
`https://proxy.example/masque?h={target_host}&p={target_port}`. Credentials are sent as
`Proxy-Authorization: Basic`.

### Packet sizes

A QUIC packet needs at least 1200 bytes of UDP payload (RFC 9000 §14). A tunneled packet
also has to fit inside a QUIC datagram of the connection to the proxy, so that connection
needs room above 1200 bytes:

- Both ends of a connection that carries tunnels start at an initial MTU of 1350
  (`OUTER_INITIAL_MTU`), and rama's MASQUE client and server set this up for you. Other
  QUIC stacks need the same: a proxy that starts at QUIC's default of 1200 cannot carry an
  HTTP/3 handshake in datagrams.
- Inside the tunnel, rama sizes the inner QUIC connection to what the tunnel can carry. It
  advertises a receive size that fits the return direction. That size is an estimate for
  proxies that start at common packet sizes, not a measurement of the proxy's path.
- A datagram too large for the tunnel is dropped, never split. QUIC's loss recovery and the
  1200-byte minimum handle that during a handshake.

### Idle timeouts

A quiet tunnel stays open for two minutes ([RFC 9298] §3.1); after that it closes. The QUIC
connections that carry tunnels idle out after three minutes (`OUTER_IDLE_TIMEOUT`), so the
tunnel's own timeout is the one that applies.

## Build features

The `masque` feature enables the `rama::proxy::masque` module and MASQUE support in the
HTTP client. `http-full` includes it. HTTP/3 needs a TLS backend for QUIC as well, `boring`
or `rustls`:

```toml
rama = { version = "0.5", features = ["http-full", "boring"] }
```

## Rama as a MASQUE client

`DefaultHttpWebClient::default_masque_with_executors` is the default client with its HTTP/3
going through MASQUE proxies. Give a request a `masque://` proxy route and ask for HTTP/3:

```rust,ignore
use rama::{
    Service,
    extensions::ExtensionsRef as _,
    http::{Body, Request, Version, client::DefaultHttpWebClient, conn::TargetHttpVersion},
    net::{address::ProxyAddress, client::ProxyRoute},
    rt::Executor,
};

// `exec` and `proxy_exec` are graceful executors, see below.
let client = DefaultHttpWebClient::default_masque_with_executors(exec, proxy_exec);
let request = Request::builder()
    .version(Version::HTTP_3)
    .uri("https://cloudflare-quic.com/")
    .body(Body::empty())?;
let proxy: ProxyAddress = "masque://user:pass@proxy.example:443".parse()?;
request.extensions().insert(ProxyRoute::Proxy(proxy));
request.extensions().insert(TargetHttpVersion(Version::HTTP_3));
let response = client.serve(request).await?;
```

Every HTTP/3 connection gets a tunnel of its own, opened by a second client to the proxy
(`DefaultHttpWebClient::masque_proxy_client_with_executor`), which runs on `proxy_exec`. To build the stack yourself,
for example with your own TLS settings, use `EasyHttpConnectorBuilder::with_http3_masque_support`.
To do the same for raw UDP sockets, use `ConnectUdpConnector` (or `ConnectUdpConnectorLayer`):
it hands out a `ConnectUdpSocket` for each tunnel.

Run both executors as graceful executors, each with its own `Shutdown`, and before the
process exits, drain `exec` first and `proxy_exec` second. Draining closes the QUIC
connections, so the origin and the proxy do not wait for them to idle out. The order matters:
a tunneled connection's close travels through the connection to the proxy, so that one closes
last. The [`masque_proxy` example][example] shows this.

## Rama as a MASQUE proxy

`ConnectUdpService` serves CONNECT-UDP requests. It parses the target, applies a
`ConnectUdpPolicy` (`DestinationScopePolicy` by default), connects the target's UDP socket
and spawns a relay between the tunnel and that socket. `with_relay` swaps in your own
service for that relay, for example to inspect the traffic.

Put it behind an `UpgradeLayer` with `HttpProxyConnectMatcher` to serve `CONNECT` next to
it, and serve it on TLS over TCP for HTTP/1.1 and HTTP/2 and on QUIC for HTTP/3.
Configure both servers for it:

- HTTP/2 needs `set_enable_connect_protocol`, and HTTP/3 needs `extended_connect`;
- the HTTP/3 server's QUIC transport starts from `masque_quic_transport()`;
- the HTTP/3 server's QUIC transport also goes through `configure_transport`, which turns
  on QUIC datagrams.

The [`masque_proxy` example][example] has the complete setup: a proxy and a client.

```sh
cargo run -p rama-examples --bin masque_proxy --features http-full,boring -- proxy --listen 127.0.0.1:4433
cargo run -p rama-examples --bin masque_proxy --features http-full,boring -- client \
    --proxy masque://127.0.0.1:4433 --insecure --url https://cloudflare-quic.com/
```

## The rama CLI

### `rama send` through a MASQUE proxy

```sh
rama send --http3 --proxy masque://user:pass@proxy.example:443 https://cloudflare-quic.com/
```

`--http3` runs the request in a CONNECT-UDP tunnel. Without it the request goes through the
same proxy with `CONNECT`, over HTTP/1.1 or HTTP/2. `--proxy-insecure` skips verification of
the proxy's certificate, and `-k`/`--insecure` skips it for the origin.

### `rama serve proxy` as a MASQUE proxy

```sh
rama serve proxy --bind 0.0.0.0:443 --protocol masque --proxy-auth user:pass
```

This serves TLS over TCP (HTTP/1.1 and HTTP/2) and HTTP/3 on the same port. It answers
CONNECT-UDP for UDP targets and `CONNECT` for TCP targets. The proxy presents a generated
self-signed certificate, so clients skip its verification (`--proxy-insecure`).

| Flag | Meaning |
|---|---|
| `--protocol masque` | serve MASQUE on `--bind`; combine with other protocols, comma-separated |
| `--masque-bind ADDR` | an additional MASQUE listener; repeatable |
| `--masque-template T` | the CONNECT-UDP URI template; default `/.well-known/masque/udp/{target_host}/{target_port}/` |
| `--masque-transport tcp,udp` | what to tunnel: `udp` with CONNECT-UDP, `tcp` with `CONNECT`; both by default |
| `--masque-allow-private` | allow private, loopback and link-local UDP targets |
| `--masque-initial-mtu N` | initial QUIC MTU of the HTTP/3 listener; default 1350 |
| `--proxy-auth user:pass` | require this credential on every ingress; it is never forwarded upstream |

### MITM egress through a MASQUE upstream

`rama serve proxy` can terminate the TLS and QUIC it proxies (`--mitm`) and send the
traffic on through a MASQUE upstream proxy:

```sh
rama serve proxy --protocol masque --mitm --mitm-ca-cert ./mitm-ca.pem \
    --upstream-proxy masque://user:pass@vendor.example:443
```

Clients connect to this proxy as a MASQUE proxy, and they trust the MITM CA written to
`mitm-ca.pem`. Intercepted HTTP/3 leaves through a CONNECT-UDP tunnel at the upstream, and
TCP leaves through `CONNECT`. QUIC that is not intercepted, such as a domain excluded with
`--mitm-deny`, is relayed untouched through an upstream tunnel. A client's tunnel is never
sent around a configured upstream.

Without `--mitm`, the same command chains MASQUE proxies: each client tunnel continues as a
tunnel at the upstream. `--upstream-proxy-insecure` skips verification of the upstream's
certificate only. Through an untouched tunnel the end client still verifies the origin. An
intercepted connection's egress to the origin does not verify the origin's certificate, the
same default as rama's TLS MITM relay.

## Interoperability

The MASQUE implementation is tested against [masque-go] in both roles: rama's client
through a masque-go proxy, and the masque-go client through `rama serve proxy`. Each
direction runs ten consecutive HTTP/3 exchanges, each on a new tunnel, followed by a clean
shutdown. Run it with Go installed:

```sh
cargo build -p rama-cli --all-features
just examples/tests/masque-interop /tmp/masque-interop
```

Results go to `results.json` in the output directory, with every process's log next to it.

## Troubleshooting

- **`407 Proxy Authentication Required`**: the proxy needs credentials; put them in the
  proxy address (`masque://user:pass@…`).
- **The tunnel is refused with `502 Bad Gateway`**: the `Proxy-Status` header says why.
  `error=destination_ip_prohibited` is a private, loopback or link-local target, which
  needs `--masque-allow-private` or a `DestinationScopePolicy` that allows it;
  `error=dns_error` is a target that does not resolve.
- **The HTTP/3 handshake through the tunnel times out**: check that the connection to the
  proxy has room for tunneled packets. Both ends need an initial MTU of at least 1350. Some
  stacks also drop datagrams larger than a fixed limit; masque-go drops those over 1500
  bytes.
- **A quiet tunnel closes**: tunnels close after two minutes without traffic, as RFC 9298
  recommends. Send keep-alives, such as QUIC PINGs, more often than that.
- **Shutdown waits for its timeout**: a peer that disappeared without closing its QUIC
  connection keeps that connection until its idle timeout. Clients should drain before they
  exit (see above).
- **Logs**: `RUST_LOG=rama_masque=debug` logs each tunnel's close and reason;
  `RUST_LOG=rama_masque=trace` also logs dropped datagrams.

[RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
[RFC 9297]: https://datatracker.ietf.org/doc/html/rfc9297
[masque-go]: https://github.com/quic-go/masque-go
[example]: https://github.com/plabayo/rama/blob/main/examples/src/masque_proxy.rs
