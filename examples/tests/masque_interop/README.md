# Independent CONNECT-UDP interop

`just examples/tests/masque-interop /tmp/new-results` builds Rama and the pinned
masque-go v0.6.0 / quic-go v0.63.0 peer, runs the harness verdict tests and Go vet,
and executes six groups. Output directories must be new; every client result,
process log, exit code, and shutdown result is retained locally in `results.json`
and adjacent logs. The default repetition count is ten.

| Group | Evidence |
| --- | --- |
| Rama client → masque-go proxy → quic-go origin | Exact POST response bytes and HTTP/3 status on every run. The origin's observed UDP source must match the proxy's actual egress socket, proving tunnel traversal. Uses a query-based URI template. |
| masque-go client → Rama proxy → Rama origin | Ten fresh CONNECT-UDP tunnels and inner QUIC connections, HTTP/3 status and nonempty response required; every Rama process must shut down gracefully. |
| quic-go HTTP/3 through Rama CONNECT-UDP | 2 MiB upload, SHA-256 response trailers, eight parallel streams, cancellation and subsequent request. |
| Datagram and policy matrix | Eight open tunnels on one outer IPv4 connection, each exchanging distinct 0-, 1-, 1000-, and 1200-byte datagrams to IPv4 and IPv6 targets. Valid credentials succeed; missing/wrong credentials produce 407. Private targets denied by default produce 502 with `destination_ip_prohibited`. Rejections must send zero target datagrams. |
| Capsule-only carrier and policy matrix | Go HTTP/1.1 upgrade, HTTP/2 Extended CONNECT, and HTTP/3 Extended CONNECT exchange the same payload sizes and IPv4/IPv6/policy cases. QUIC DATAGRAM is disabled on the H3 client. Unknown capsule types and unregistered context IDs precede valid datagrams; only context-zero payloads may reach UDP. |
| Transparent interception of the client's own proxy | Independent Go clients connect through Rama MITM to an authenticated proxy with a custom query template. H1/H2/H3 capsules and H3 native datagrams must survive. The inner TLS leaf must differ from the direct baseline, proving interception. Wrong inner credentials still produce 407 and zero target traffic. The outer and inner proxy credentials differ. |

The shared Go peer supplies protocol behavior through upstream libraries. Its
inner QUIC origin uses a 1200-byte MTU with discovery disabled to leave room for
outer HTTP/QUIC datagram headers. It supports loopback-only insecure TLS for the
CLI harness's ephemeral identities; the direct Rust H3 suite passes an explicit
test CA. The harness clears caller proxy variables so `NO_PROXY` cannot bypass
the tested proxy.

PR CI runs this recipe. The CLI uses Boring. The separate
[direct HTTP/3 suite](../../../rama-quic/e2e/http-interop/) runs Rama client and
server against the same Go peer with Boring, Rustls/ring, and Rustls/AWS-LC.
The existing internal MASQUE matrix covers additional Rama-to-Rama combinations;
this oracle does not cover CONNECT-IP. Live dynamic QPACK is covered by the direct
HTTP/3 suite using aioquic/ls-qpack. The nested native-DATAGRAM interception case
uses 0/1/1000-byte payloads within its 1200-byte inner QUIC MTU; the capsule
interception cases also carry 1200-byte UDP payloads. Native datagrams cannot carry
a payload as large as the whole path MTU because QUIC/HTTP headers need space.
