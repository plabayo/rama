# QUIC interoperability

These standalone projects exercise Rama's QUIC client and server against
independent implementations. They live outside the main Cargo workspace.
See the [QUIC justfile](../justfile) for QA recipes and backend selection.

The Quinn and quiche projects accept `boring`, `rustls-ring`, or `rustls-aws-lc` as their
Rama backend feature. Selection is explicit even when the peer enables another TLS
implementation. The Boring runs cover both roles, including resumption, early-data
acceptance/rejection, and certificate failures. Boring rejects early data by changing
the transport context bound to a ticket while retaining its native ticket keys.

- [Shared scenarios](interop-common/)
- [Quinn](quinn-interop/)
- [quiche](quiche-interop/)
- [aioquic](aioquic-interop/)
- [Docker interop runner](interop-runner/)
