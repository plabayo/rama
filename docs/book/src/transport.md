# Transport Protocols

Transport protocols form the foundation of communication in networked applications.
In Rama, they’re not just a substrate—they’re fully integrated, layered services,
treated with the same flexibility and modularity as higher-level components.
This chapter explores how Rama supports and enhances [TCP][rama-tcp],
[UDP][rama-udp], [QUIC][rama-quic], and [Unix sockets][rama-unix], emwpoering you to build
robust and performant network applications.

Rama's layered architecture starts at the transport layer and goes *all the way up*.
This is a distinguishing trait: in most frameworks, transport is considered a
low-level concern that you configure once and forget. But in Rama, transport
protocols are first-class citizens. They participate in the same service
stack as application protocols, middleware, observability tools, and business logic.

## Streams and Datagrams

Before diving into specific protocols, it's important to understand the two primary
transport abstractions: streams and datagrams.

- **Streams** (like those provided by [TCP][rama-tcp] and [Unix][rama-unix] stream sockets) represent ordered, reliable, connection-oriented communication. They guarantee delivery and preserve the order of bytes.
- **Datagrams** (like those used in [UDP][rama-udp] and [Unix][rama-unix] datagram sockets) represent unordered, unreliable, connectionless communication. Each message stands alone.

Each abstraction has different strengths and trade-offs. Streams are great for
general-purpose applications like HTTP, SSH, and database access.
Datagrams are perfect for high-performance, latency-sensitive applications like DNS,
real-time telemetry, or custom RPC protocols.

> Note that H3 is built upon UDP by
> layering QUIC in between for the same ordered and reliable
> connection-oriented communication traditionally offered by TCP.

[QUIC][rama-quic] sits between the two. It runs over UDP and carries many independent
streams on one connection, each of them ordered and reliable on its own. Ordering is
per-stream, not connection-wide: a stream that loses a packet does not hold up the others,
which is what distinguishes it from carrying several exchanges over one TCP connection. It
also carries unreliable [DATAGRAM][rfc-9221] frames, which are neither ordered nor
retransmitted and are bounded by what one packet can hold.

Rama's QUIC is the transport itself. HTTP/3 is not part of it.

## Remote vs Local

Another dimension in transport protocol design is **remote** vs **local** communication:

- **Remote transports** like TCP, UDP and QUIC operate over the network stack and are ideal for client-server or peer-to-peer communication across machines.
- **Local transports** like Unix domain sockets (UDS) operate within a single host, using the filesystem as an addressing mechanism.

Unix sockets are especially useful for high-performance, secure inter-process communication (IPC).
They avoid the overhead of TCP while retaining the benefits of stream or datagram semantics.
In Rama, using Unix (Domain) Sockets (UDS) is as simple as switching out
the transport service—your layers, middleware, and application logic don’t need to change.

## Use Cases and Trade-offs

| Protocol | Abstraction | Communication | Reliable | Ordered | Typical Uses |
|---------|-------------|---------------|----------|---------|--------------|
| [TCP][rama-tcp]     | Stream      | Remote        | ✅        | ✅       | HTTP, SSH, DBs |
| [UDP][rama-udp]     | Datagram    | Remote        | ❌        | ❌       | DNS, VoIP, custom RPC |
| [QUIC][rama-quic]    | Stream/Datagram | Remote    | ✅/❌     | per stream/❌ | Multiplexed RPC, tunneling, real-time media |
| [Unix][rama-unix]    | Stream/Datagram | Local     | ✅/❌     | ✅/❌     | IPC, reverse proxies, system daemons |

Each protocol has its place in the network programming toolbox. In Rama, your choice of protocol doesn't lock you into a specific architecture. Because the transport is just another service, you can build once and deploy across protocols with minimal changes.

Note that typical uses do not mean that these are the only uses or that a use mentioned for 1 protocol
cannot be served by another one. As usually it's a set of trade offs.

This transport-first model is also part of why Rama's [gRPC support](./http/grpc.md) fits naturally in the framework: gRPC often runs over HTTP/2, but the transport and lower networking concerns remain fully programmable.

## Integration in Rama

- For both TCP and Unix (stream) sockets there are listeners that are the servers in this kind of relationship:
  - TCP: <https://ramaproxy.org/docs/rama/tcp/server/struct.TcpListener.html>
  - Unix: <https://ramaproxy.org/docs/rama/unix/server/struct.UnixListener.html>
- For connectionless communication using datagrams there is no client or server,
  and for those there are only the sockets to work with, regardless of which party:
  - UDP: <https://ramaproxy.org/docs/rama/udp/struct.UdpSocket.html>
  - Unix: <https://ramaproxy.org/docs/rama/unix/struct.UnixSocket.html>
- QUIC has one endpoint type for both roles, since a single endpoint may act as client and
  server for different connections:
  - <https://ramaproxy.org/docs/rama/quic/struct.Endpoint.html>
  - built on an application's own executor with
    <https://ramaproxy.org/docs/rama/quic/struct.EndpointBuilder.html>, so a graceful shutdown
    the application holds a guard for stops the endpoint too

QUIC needs the `quic` feature and a TLS provider: either `boring`, or `rustls` together with
`ring` or `aws-lc`. Select an implementation with `TlsOptions::with_backend`; automatic
selection prefers Rustls when both are available. It is built on [rama-udp][rama-udp], so
the socket options and packet features of that layer apply to it. Boring builds do not require
Rustls, ring, or AWS-LC. Applications can also implement the interfaces in
`rama::quic::tls::provider` and construct `ClientConfig` and `ServerConfig` with their own
TLS 1.3 and packet-crypto provider, without enabling a built-in backend.

For the connection-oriented streams there are also connectors to make it easy to establish connections in bigger stacks
(e.g. http within tls on top of tcp):

- TCP: <https://ramaproxy.org/docs/rama/tcp/client/service/struct.TcpConnector.html>
- Unix: <https://ramaproxy.org/docs/rama/unix/client/struct.UnixConnector.html>

Rama can also enumerate the host's own network interfaces and the addresses assigned to them,
e.g. to discover which devices exist prior to binding, or for diagnostics (`rama probe iface`):

- interfaces: <https://ramaproxy.org/docs/rama/net/socket/fn.interfaces.html>
- local addresses: <https://ramaproxy.org/docs/rama/net/socket/fn.local_addresses.html>

## Examples

These examples show how easy it is to set up and extend Rama’s transport services,
and how they integrate seamlessly with the rest of the stack.

Rama doesn’t just support networking—it *is* networking, from transport to application.

- TCP:
  - [/examples/src/tcp_listener_fd_passing.rs](https://github.com/plabayo/rama/blob/main/examples/src/tcp_listener_fd_passing.rs):
    FD passing via SCM_RIGHTS for zero-downtime restarts (Unix-only)
  - [/examples/src/tcp_listener_hello.rs](https://github.com/plabayo/rama/blob/main/examples/src/tcp_listener_hello.rs):
    minimal tcp listener example
- QUIC:
  - [/examples/src/quic_client_server.rs](https://github.com/plabayo/rama/blob/main/examples/src/quic_client_server.rs):
    an authenticated client and server on one shared graceful runtime, exchanging a
    bidirectional request and a unidirectional upload. Run it with
    `--features=quic,rustls,ring`
  - [/examples/src/quic_terminating_relay.rs](https://github.com/plabayo/rama/blob/main/examples/src/quic_terminating_relay.rs):
    a terminating relay: it presents its own identity to the client and authenticates the
    origin itself, over two independent handshakes, and carries client-initiated bidirectional
    streams between them.
    It relays neither unidirectional nor server-initiated streams. It needs an origin to
    relay to and that origin's certificate
- UDP:
  - [/examples/src/udp_codec.rs](https://github.com/plabayo/rama/blob/main/examples/src/udp_codec.rs):
    an example which leverages `BytesCodec` to create a UDP client and server which speak a custom protocol
  - [/examples/src/udp_over_tcp.rs](https://github.com/plabayo/rama/blob/main/examples/src/udp_over_tcp.rs):
    tunnels UDP datagrams over a single TCP connection (with `u16` length-prefix framing on the TCP side),
    useful for reaching a UDP service from a TCP-only network. Inspired by Jon Gjengset's
    [`udp-over-tcp`](https://github.com/jonhoo/udp-over-tcp); demonstrates `ConnectedUdpFramed`
    + `StreamForwardService`
- Unix:
  - [/examples/src/unix_socket.rs](https://github.com/plabayo/rama/blob/main/examples/src/unix_socket.rs):
    a minimal example of a unix socket listener
  - [/examples/src/unix_socket_http.rs](https://github.com/plabayo/rama/blob/main/examples/src/unix_socket_http.rs):
    an example demonstrating how easy rama makes it to get a stack similar to tcp-http but with unix as the transport
  - [/examples/src/unix_datagram_codec.rs](https://github.com/plabayo/rama/blob/main/examples/src/unix_datagram_codec.rs):
    similar to the `udp_codec` example but using Unix datagram sockets

[rama-tcp]: https://ramaproxy.org/docs/rama/tcp/index.html
[rama-udp]: https://ramaproxy.org/docs/rama/udp/index.html
[rama-quic]: https://ramaproxy.org/docs/rama/quic/index.html
[rama-unix]: https://ramaproxy.org/docs/rama/unix/index.html
[rfc-9221]: https://datatracker.ietf.org/doc/html/rfc9221
