# QUIC interoperability

These standalone projects exercise Rama's QUIC client and server against
independent implementations. They live outside the main Cargo workspace.
See the [QUIC justfile](../justfile) for QA recipes and backend selection.

- [Shared scenarios](interop-common/)
- [Quinn](quinn-interop/)
- [quiche](quiche-interop/)
- [aioquic](aioquic-interop/)
- [Docker interop runner](interop-runner/)
