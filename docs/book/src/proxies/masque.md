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

## Quick start

Run a MASQUE proxy on loopback and send an HTTP/3 request through it:

```sh
rama serve proxy --bind 127.0.0.1:8443 --protocol masque
rama send -v --http3 -x masque://127.0.0.1:8443 --proxy-insecure https://cloudflare-quic.com/
```

`-v` prints `using HTTP/3.0` and the response status. `rama serve proxy` generates its own
certificate, hence `--proxy-insecure`; use `--proxy-cacert FILE` for a proxy with a
certificate you can verify. Any RFC 9298 proxy works the same way: put its credentials and
URI template in the address, for example
`-x 'masque://user:pass@proxy.example/.well-known/masque/udp/{target_host}/{target_port}/'`.
In code, `DefaultHttpWebClient::default_masque_with_executor` gives the same client; the
[`masque_connect_udp_proxy` example][example] runs a proxy and a client together, and
[`rama::proxy::masque`](https://ramaproxy.org/docs/rama/proxy/masque/index.html) documents
the API.

## CONNECT-UDP

Establishing a tunnel starts with an HTTP request to the proxy. HTTP/3 and HTTP/2 send an
Extended CONNECT with `:protocol = connect-udp`, HTTP/1.1 upgrades a `GET` request. The
request path names the target through the proxy's URI template, by default
`/.well-known/masque/udp/{target_host}/{target_port}/`.

The proxy resolves the target and checks it against its policy before it accepts the tunnel:
`101 Switching Protocols` on HTTP/1.1, a `2xx` on HTTP/2 and HTTP/3. Rama refuses private,
loopback and link-local targets unless they are allowed, including through IPv6 addresses
that carry such an IPv4 address (NAT64, 6to4, Teredo). The tunnel sends only to the resolved
address the policy approved. After that, UDP payloads travel as
HTTP Datagrams ([RFC 9297]): in QUIC DATAGRAM frames on HTTP/3 when both peers support them,
otherwise as DATAGRAM capsules on the request stream.

### Delivery modes

Which mode a tunnel uses is settled when it opens: native QUIC datagrams when it runs on
HTTP/3 and both peers enabled HTTP/3 datagrams, otherwise DATAGRAM capsules on the request
stream. HTTP/1.1 and HTTP/2 always use capsules. The two modes carry payloads between client
and proxy differently:

| Between client and proxy | Native HTTP/3 datagrams | DATAGRAM capsules |
|---|---|---|
| Loss | a payload in a lost packet is lost, as with UDP | the carrier resends lost packets: a payload on the stream is lost only when the stream fails |
| Order | payloads may arrive out of order | payloads arrive in the order they were put on the stream |
| Head-of-line blocking | no payload waits for a resent one; datagrams still share the connection's congestion control and pacing | a lost carrier packet holds back every later payload of that tunnel, and on HTTP/1.1 and HTTP/2 every tunnel and request of that TCP connection |
| Size | one QUIC DATAGRAM frame, see [Packet sizes](#packet-sizes) | up to a full UDP payload (65 527 bytes) |
| Under pressure | the sender waits for room in its connection's datagram buffer; a receiver that falls behind loses its oldest queued payloads | flow control slows the sender down |

Either way that covers only the carrier. The proxy still drops payloads its budgets refuse
(see `TunnelBudget` below) and ones still queued when a tunnel ends, and between proxy and
target payloads travel as plain UDP, with UDP's loss and reordering.

Capsules are not a better UDP. They turn what UDP would lose into delay, and an inner QUIC
connection already recovers its own losses and runs its own congestion control. Over
capsules that control is stacked on the carrier's TCP or QUIC congestion control. Each layer
reacts to delay the other one introduced, so a lossy path costs more latency through
capsules than through native datagrams. Use native datagrams whenever the path allows HTTP/3
with datagrams. Capsules make a tunnel work where it otherwise could not: UDP blocked on the
path, or a proxy or MITM in between that speaks only HTTP/1.1 or HTTP/2.

Tunnels on one HTTP/2 or HTTP/3 connection share its congestion control, pacing and buffers,
so a tunnel that floods slows the others on that connection down, and with native datagrams
can cost them payloads. Tunnels on separate connections share none of that, but they still
share the proxy's host, its UDP socket and the network: a flood on another connection can
still add latency and, with native datagrams, loss. A proxy's limits bound what a flooding
tenant gets forwarded, not what it sends to the proxy.

A MASQUE proxy is also an HTTPS proxy: `CONNECT` still tunnels TCP. A rama client with a
`masque://` proxy tunnels HTTP/3 with CONNECT-UDP and HTTP/1.1 and HTTP/2 with `CONNECT`.

A MASQUE proxy is addressed with the `masque` scheme, port 443 by default, such as
`masque://user:pass@proxy.example`. A path in the address is the proxy's URI template; an
`https://` address whose path is a template with both variables is a MASQUE proxy as well.
Templates follow RFC 6570, not the route syntax of Rama's router; the
[`uri` module docs](https://ramaproxy.org/docs/rama/net/uri/index.html#patterns-and-templates)
compare the two.

In a [proxy database](https://ramaproxy.org/docs/rama/proxy/trait.ProxyDB.html), a row
whose address is a MASQUE proxy is selected for HTTP/3 and other UDP traffic when its `udp`
flag is set, and for HTTP/1.1 and HTTP/2 when its `tcp` flag is set. Set both for a proxy
that serves every HTTP version, as most MASQUE proxies do.

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

### Closing tunnels

A destination that stops accepting output ends that forwarding direction. The reverse
direction can still deliver input already received by the carrier, including input its
HTTP driver has yet to file. CONNECT-UDP sockets allow at most five seconds for this
drain; local aborts, capacity failures and idle expiration still stop immediately.
`DatagramForwardService::with_close_timeout` controls the UDP forwarder's drain bound.
Once a UDP receive side has delivered its queued input and reports the association
closed, forwarding ends immediately; the reverse direction has no live destination.
Successful traffic cannot extend this deadline. The HTTP datagram relay has the same
directional behavior, with a five-second close timeout and two-minute idle timeout by
default. Applications with another lifetime policy can opt out with `without_idle_timeout`
and `without_close_timeout`. The default datagram service in `Http3MitmRelay` drains
accepted tunnels during graceful shutdown, like byte forwarding. A custom relay can
opt into cancellation with `with_executor`.

After a clean HTTP/3 connection close, the server and MITM dispatcher keep polling the
driver and accepted request futures together. `Config::close_drain_timeout` bounds this
phase to five seconds by default. During a graceful shutdown, once the GOAWAY is queued, each
wait for the peer to acknowledge a response's end is bounded by `Config::goaway_drain_timeout`
(one second by default), so a peer that went away cannot hold the shutdown. It is not an
overall deadline: requests still running keep their own. A protocol error or cancellation
still ends the affected work.

QUIC transmits a tunnel's FIN only after its earlier queued native datagrams have been
transmitted or dropped under the configured queue/MTU policy. This prevents local FIN
overtaking; it does not make datagrams reliable or prevent network reordering. Receive
queues keep their normal byte and packet limits during closure, so a stalled consumer
cannot turn draining into unbounded retention. Unknown capsules and nonzero contexts
retain their protocol-defined handling, with cooperative work budgets under continuous
input.

## Rama as a MASQUE client and proxy

The building blocks live in `rama::proxy::masque` and the HTTP client:

- `DefaultHttpWebClient::default_masque_with_executor` is the default HTTP client with its
  HTTP/3 also going through MASQUE proxies. Variants take TLS configurations of your own.
- `ConnectUdpConnector` opens CONNECT-UDP tunnels as UDP sockets, for any QUIC or UDP client.
- `ConnectUdpService` serves CONNECT-UDP requests: target policy, DNS, and a relay that can be
  swapped for your own, such as one inspecting the traffic.
- `DestinationScopePolicy` and `ConnectUdpRules` decide which targets a tunnel may reach.
  Policies see the request's extensions, such as the user an authentication layer in front
  identified, and combine as tuples: `(DestinationScopePolicy::new(), rules)` needs both.
  Both judge an IPv6 target and every IPv4 address it carries; the proxy's own NAT64
  prefixes are set with `ConnectUdpService::with_translation_prefix`.
- `ConnectUdpLimits` caps the tunnels a proxy runs at once, in total and per principal. Which
  principal a tunnel counts against is up to its keyer (rama's `InputToRateKey`, closures
  included), derived from the whole CONNECT-UDP request: by default `UserOrClientIpKey`, the
  authenticated user, else the client IP (an IPv6 client by its /64); `ClientIpRateKey` keys by IP
  alone, and a keyer of your own can key by tenant, API key or anything else in the request.
  Usernames and tokens never show in logs. A tunnel takes its place before anything is resolved
  and holds it until it ends; a full proxy answers `503` with `Proxy-Status:
  connection_limit_reached`.
- `TunnelBudget` sets what each tunnel may move: packet and byte rates per direction, a quota,
  and how much reaches a target before it answers (64 packets or 64 KiB by default, so a
  tunnel to a target that never replies stops being forwarded; one-way UDP needs a larger
  allowance or none). Every datagram is charged once where it enters the proxy, also when it
  is then dropped; over budget it is dropped, never queued. `ConnectUdpSocket::stats` reports
  what a tunnel forwarded and why it dropped the rest.
- `PrincipalBudget` (on `ConnectUdpLimits`) sets what all the tunnels of one principal move
  together: rates per direction and a quota per window. Every datagram is charged to the
  principal first, then to its tunnel. A principal is only forgotten once its rates would be
  full again and its quota window has ended, so reopening tunnels never restores budget early.

- Every tunnel opened, refused and ended is a DEBUG audit event at the tracing target
  `rama_masque::connect_udp::audit`, such as `RUST_LOG=info,rama_masque::connect_udp::audit=debug`
  for an audit trail. The event carries the target, the resolved address, the client's address,
  the principal's kind (`user`, `token`, `ip`, `anonymous`) but never who it is, and on close the
  reason, duration and byte counts.

The [`masque_connect_udp_proxy` example][example] has a complete proxy and client.

## Telemetry

With the `opentelemetry` feature, three opt-in metric sets cover a MASQUE deployment. Each
records nothing until it is set:

- `ConnectUdpService::with_metrics(ConnectUdpMetrics)`: tunnels active, refused by
  `Proxy-Status` error type, and ended by reason with their duration; datagrams from the
  client by outcome (forwarded or the drop reason) and by delivery mode; datagrams to the
  client by outcome; byte counts. `ConnectUdpMetrics::with_attributes` adds labels taken from
  each request, such as a tenant.
- `EndpointBuilder::with_metrics(QuicMetrics)`: per-connection duration, handshake time,
  bytes, lost packets and gated datagrams; endpoint handshake, admission and receive counters.
- `Config::metrics` with `H3Metrics`, on the HTTP/3 configuration: the HTTP/3 datagrams each
  connection discarded, by reason.

Without the feature, or with it but no metrics set, tunnels still keep their counters in
`ConnectUdpSocket::stats`, and QUIC connections in `Connection::stats`.

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
| `--masque-initial-mtu N` | initial QUIC MTU of MASQUE HTTP/3 connections, see [Packet sizes](#packet-sizes) |
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
