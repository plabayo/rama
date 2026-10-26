# Specifications

## MASQUE

A non-exhaustive collection of specifications as implemented,
relied upon by rama-masque or related to.

Status (updates and errata) last checked on 2026-10-23 against
`https://www.rfc-editor.org/rfc/rfcNNNN.json`; re-check before each release.

### RFCs

* [rfc9298.txt](./rfc9298.txt)  
  Proxying UDP in HTTP (CONNECT-UDP). Updated by RFC 9484 (registry only:
  the `masque` well-known URI gains `udp/` and `ip/`) and RFC 9931 (no optimistic
  sending on HTTP/1.x). No errata.

* [rfc9931.txt](./rfc9931.txt)  
  Security Considerations for Optimistic Protocol Transitions in HTTP/1.1.
  Replaces RFC 9298 §5's optimistic-sending text and adds HTTP/1.1 CONNECT
  requirements (updates RFC 9112). No errata.

* [rfc6570.txt](./rfc6570.txt)  
  URI Template, levels 1–3 as restricted by RFC 9298 §2. Errata: one verified,
  one rejected.

### Related, vendored in sibling crates

* [rfc9297.txt](../../rama-http-core/specifications/rfc9297.txt) —
  HTTP Datagrams and the Capsule Protocol.
* [rfc8441.txt](../../rama-http-core/specifications/rfc8441.txt) and
  [rfc9220.txt](../../rama-http-core/specifications/rfc9220.txt) —
  Extended CONNECT for HTTP/2 and HTTP/3.
* [rfc9112.txt](../../rama-http-core/specifications/rfc9112.txt) — HTTP/1.1.
* [rfc9000.txt](../../rama-quic/specifications/rfc9000.txt) — QUIC variable-length
  integers (Context IDs) and the 1200-byte minimum datagram size.
* [rfc9221.txt](../../rama-quic/specifications/rfc9221.txt) — QUIC DATAGRAM.
* [rfc9209.txt](../../rama-http-headers/specifications/rfc9209.txt) —
  The Proxy-Status HTTP Response Header Field (CONNECT-UDP refusals).
* [rfc9651.txt](../../rama-http-headers/specifications/rfc9651.txt) —
  Structured Field Values (`Capsule-Protocol`, `Proxy-Status`).
