# 🎭 MASQUE proxies

MASQUE is a set of IETF protocols for proxying traffic other than TCP through HTTP. Rama
implements CONNECT-UDP ([RFC 9298]): a client asks the proxy for a UDP tunnel to a target,
and the UDP payloads travel inside that HTTP request. Its main use is HTTP/3, whose QUIC
connections run over UDP and so cannot go through an ordinary `CONNECT` tunnel.

<div class="book-article-image-center">

```dot process
digraph {
    pad=0.2;
    "client" -> "MASQUE proxy (rama)" [dir=both, label=" HTTP/3, HTTP/2 or HTTP/1.1 "]
    "MASQUE proxy (rama)" -> "target" [dir=both]
}
```

</div>

## CONNECT-UDP

Establishing a tunnel starts with an HTTP request to the proxy. HTTP/3 and HTTP/2 send an
Extended CONNECT with `:protocol = connect-udp`, HTTP/1.1 upgrades a `GET` request. The
request path names the target through the proxy's URI template, by default
`/.well-known/masque/udp/{target_host}/{target_port}/`.

The proxy resolves the target and checks it against its policy before it accepts the tunnel:
`101 Switching Protocols` on HTTP/1.1, a `2xx` on HTTP/2 and HTTP/3. Rama refuses private,
loopback and link-local targets unless they are allowed. After that, UDP payloads travel as
HTTP Datagrams ([RFC 9297]): in QUIC DATAGRAM frames on HTTP/3 when both peers support them,
otherwise as DATAGRAM capsules on the request stream.

A MASQUE proxy is also an HTTPS proxy: `CONNECT` still tunnels TCP. A rama client with a
`masque://` proxy tunnels HTTP/3 with CONNECT-UDP and HTTP/1.1 and HTTP/2 with `CONNECT`.

A MASQUE proxy is addressed with the `masque` scheme, port 443 by default, such as
`masque://user:pass@proxy.example`. A path in the address is the proxy's URI template; an
`https://` address whose path is a template with both variables is a MASQUE proxy as well.
Templates follow RFC 6570, not the route syntax of Rama's router; the
[`uri` module docs](https://ramaproxy.org/docs/rama/net/uri/index.html#patterns-and-templates)
compare the two.

### Packet sizes

A QUIC packet needs at least 1200 bytes of UDP payload (RFC 9000 §14), and a tunneled packet
has to fit in a single QUIC datagram of the connection to the proxy. Both ends of that
connection therefore start with room above that minimum; rama's MASQUE client and server set
this up, other QUIC stacks need the same. Inside the tunnel, rama sizes the inner QUIC
connection to what the tunnel can carry, in both directions. The return direction is an
estimate, since the proxy's own path is not known to the client.

A datagram too large for the tunnel is dropped, never split or resent reliably: a QUIC
DATAGRAM frame cannot be fragmented (RFC 9221 §5), and dropping keeps path MTU discovery
working end to end (RFC 9297 §3.5).

### Idle tunnels

A quiet tunnel closes after a while without traffic; RFC 9298 §3.1 recommends at least two
minutes. The QUIC connections that carry tunnels stay open longer than that, so the tunnel's
own policy decides. The API documentation of `rama::proxy::masque` describes the values in
use.

## Rama as a MASQUE client and proxy

The building blocks live in `rama::proxy::masque` and the HTTP client:

- `DefaultHttpWebClient::default_masque_with_executor` is the default HTTP client with its
  HTTP/3 also going through MASQUE proxies. Variants take TLS configurations of your own.
- `ConnectUdpConnector` opens CONNECT-UDP tunnels as UDP sockets, for any QUIC or UDP client.
- `ConnectUdpService` serves CONNECT-UDP requests: target policy, DNS, and a relay that can be
  swapped for your own, such as one inspecting the traffic.

The [`masque_connect_udp_proxy` example][example] has a complete proxy and client.

## The rama CLI

`rama send` uses a MASQUE proxy with `--proxy masque://…`: `--http3` requests go through a
CONNECT-UDP tunnel, other HTTP versions through `CONNECT`.

`rama serve proxy --protocol masque` serves a MASQUE proxy, TLS over TCP and HTTP/3 over UDP
on the same port:

| Flag | Meaning |
|---|---|
| `--protocol masque` | serve MASQUE on `--bind`, next to other protocols |
| `--masque-bind ADDR` | an additional MASQUE listener; repeatable |
| `--masque-template T` | the CONNECT-UDP URI template |
| `--masque-tunnels connect,connect-udp` | the tunnel methods served; both by default |
| `--masque-allow-private` | allow private, loopback and link-local targets |
| `--proxy-auth user:pass` | require this credential on every ingress; never forwarded |

With `--upstream-proxy masque://…` the proxy sends its own egress through a MASQUE upstream:
TCP through `CONNECT`, UDP and QUIC through CONNECT-UDP. Combined with `--mitm`, intercepted
HTTP/3 leaves through an upstream tunnel and QUIC that is not intercepted is relayed untouched
through one. Without `--mitm` the proxies chain. A tunnel is never sent around a configured
upstream. `--upstream-proxy-insecure` skips verification of the upstream's certificate only;
through an untouched tunnel the end client still verifies the origin, while intercepted egress
does not verify the origin, as rama's TLS MITM relay.

## Transparent interception of a client's MASQUE proxy

The Apple transparent-proxy example and `rama serve proxy --mitm` can intercept a client's
own connection to a MASQUE proxy. HTTP/1.1 and HTTP/2 carry capsules; HTTP/3 supports both
capsules and native QUIC datagrams. The relay preserves the HTTP version and the client's
proxy URI template, credentials and authentication challenges. The outer proxy's own
authentication is consumed on the outer CONNECT, before parsing requests inside the tunnel.
Inner proxy headers are preserved for every protocol. The chosen MASQUE proxy validates
requests and owns their HTTP error responses; the relay validates successful handshakes
before selecting capsule forwarding. An excluded connection passes through untouched.

For a custom MITM, install `ConnectUdpRelayRequestMatcher` in `HttpUpgradeMitmRelayLayer`
for HTTP/1.1 and HTTP/2, and `ConnectUdpMitmLayer` in `Http3MitmRelay` for HTTP/3. Both live
in `rama::proxy::masque::connect_udp::mitm`. Configure **both** QUIC transports with
`masque_quic_transport()` so native datagrams have room for an inner QUIC Initial and
quiet tunnels can use their own idle timeout. Apply the HTTP/3 configuration's
`configure_transport` for finite receive budgets. These connection settings precede
HTTP requests, so they also cover ordinary requests multiplexed on that connection.
The HTTP/3 relay selects datagram semantics only when middleware marks the response itself.
An inherited request marker or the protocol token alone does not enable them.

`mitm::relay(exec)` supplies bounded capsule reads, a two-minute idle timeout and a five-second
half-close drain, observing the executor's graceful shutdown. Pass it to
`ConnectUdpRelayRequestMatcher::new(service)` and `Http3MitmRelay::with_datagram_relay(service)`.
For HTTP/1.1 and HTTP/2, `ConnectUdpRelayRequestMatcher::default_with_exec(exec)` is shorthand.
Both entry points accept an ordinary Rama service decorated with layers. Use `MapOutputLayer`
when composing upgrade services with different output types, as for CONNECT and WebSocket.

Both MASQUE adapters support `with_matcher`, using ordinary Rama matchers to select sessions
by destination, headers, or connection metadata. Selection enables protocol handling; it is
not an access-control decision. Put `HijackLayer`, request validation, or your HTTP firewall
in the stack to refuse prohibited requests before egress. The URI template belongs to the
upstream MASQUE proxy, so extracting its inner UDP destination requires knowing that template;
the transparent adapter does not guess it.

Matcher output is HTTP request metadata. For per-session forwarding policy, HTTP middleware
can copy selected owned values into the request's own `HttpUpgradeMitmRelayExtensions`;
the injected service receives it on the appropriate upgraded transport. The service can use
`HttpDatagramSession` to inspect, modify, or drop individual payloads, for either native
datagrams or DATAGRAM capsules. Services and layers stay in the service stack, not extensions.
The supplied opaque relay preserves unreliable native delivery and reliable capsules, and
streams unknown capsules without buffering their full values. Nested QUIC interception and
carrier HTTP-version translation are outside this adapter's scope.

## Troubleshooting

- **`407 Proxy Authentication Required`**: put the credentials in the proxy address.
- **The tunnel is refused with `502 Bad Gateway`**: the `Proxy-Status` header says why, such
  as `destination_ip_prohibited` for a private target or `dns_error` for one that does not
  resolve.
- **The HTTP/3 handshake through the tunnel times out**: the connection to the proxy may not
  have room for tunneled packets, see [Packet sizes](#packet-sizes).
- **A quiet tunnel closes**: see [Idle tunnels](#idle-tunnels); keep-alives such as QUIC PINGs
  keep it open.
- **Logs**: `RUST_LOG=rama_masque=debug` logs each tunnel's close and why.

[RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
[RFC 9297]: https://datatracker.ietf.org/doc/html/rfc9297
[example]: https://github.com/plabayo/rama/blob/main/examples/src/masque_connect_udp_proxy.rs
