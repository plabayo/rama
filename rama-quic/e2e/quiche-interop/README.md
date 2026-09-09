# quiche interoperability

Rama's QUIC transport against [quiche](https://github.com/cloudflare/quiche), in both roles,
through the public API of the umbrella `rama` crate only.

The project is standalone: it is not a member of the rama workspace and has its own
`Cargo.lock`, so the peer's dependencies never reach the workspace resolution. quiche brings
its own TLS, a vendored BoringSSL built from its default features, so the only thing the two
stacks share is the wire.

## Prerequisites

- A Rust toolchain.
- A C toolchain and `cmake`, which quiche's build needs to compile BoringSSL. The first build
  is slow for that reason; later ones are not.

## Running

```
cargo test --locked
```

These are the commands CI should invoke from this directory. No CI job is wired up yet. The
project is not part of the workspace, so `cargo test` at the repository root does not reach it.

## What is covered

`tests/interop.rs` has the handshakes, streams and the two certificate-refusal controls.
`tests/datagrams.rs` has DATAGRAM in both Rama roles. quiche advertises 65536 as its
`max_datagram_frame_size` whenever datagrams are enabled, from draft-ietf-quic-datagram-01
rather than RFC 9221's 65535, and either value is far above the path budget: towards a quiche
peer the binding limit is the path. The aioquic project covers the other case, where the peer's
advertised size is small enough to be the binding one. The size boundary and the
unsupported-peer case are covered for the client role here; the server-role test covers
delivery and support.

`tests/resumption.rs` has resumption and 0-RTT. quiche can be the same resumption authority
twice through `set_ticket_key`, and can accept or refuse early data independently of that, so
the three outcomes are separate tests: early data accepted, early data refused while the
session still resumes, and the resumption itself refused.

`tests/names.rs` has what the server is asked for and what it reports: a name reported as a
domain, a client that sends none reported as absent, a Rama client connecting to an IPv4 or
IPv6 literal sending no SNI and checking the address in the certificate, and two negatives
where a trusted certificate covers a different identity. The literal and the bind address are
separate arguments, so the shape of the name and the family of the socket are not conflated.

## What the driver does not do yet

quiche owns neither sockets nor timers, so its side of each test is driven by hand. Two limits
of that driver are worth knowing before extending these tests:

- Datagrams are read and written through a 1350-byte buffer. A scenario that raises the path
  MTU has to raise that with it, or larger datagrams from the peer will be truncated.
- `SendInfo::at`, the moment quiche asks for a datagram to leave, is ignored: everything is
  sent as soon as it is produced. Nothing here is paced, so pacing-sensitive and loss scenarios
  need the driver to honour it and to account for it against the remaining deadline.

Neither quiche's public API nor aioquic's exposes a TLS keying-material exporter, and quiche
exposes no key update. Those two features are covered against Quinn in `../quinn-interop`
rather than here.
