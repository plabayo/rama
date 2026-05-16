# Specifications

## Net

A non-exhaustive collection of specifications as implemented or
relied upon by `rama-net`. The interests of this crate are broad,
so this set also includes specifications that govern parsers and
validators here even when only part of the document is materially
used.

For each entry below we point to the primary implementation
file(s) inside `rama-net/src`. Specifications used by sibling
crates (e.g. `rama-ws`, `rama-socks5`) are not vendored again
here; see the cross-references at the bottom.

### URI

* [rfc3986.txt](./uri/rfc3986.txt) — URI generic syntax.
  Implemented in [`src/address/`](../src/address) (host, authority,
  domain, IPv4/IPv6 parsers), [`src/uri.rs`](../src/uri.rs) and
  the scheme grammar in [`src/proto.rs`](../src/proto.rs).

* [rfc3987.txt](./uri/rfc3987.txt) — Internationalized Resource
  Identifiers (IRIs). Kept as reference; IRI/IDN handling is not
  yet implemented (`address/domain/` is ASCII-only).

### TLS

* [rfc8446.txt](./tls/rfc8446.txt) — TLS 1.3.
  Used by the ClientHello parser
  [`src/tls/client/parser.rs`](../src/tls/client/parser.rs) and
  the enum definitions in [`src/tls/enums.rs`](../src/tls/enums.rs).

* [rfc5246.txt](./tls/rfc5246.txt) — TLS 1.2 (record / handshake
  framing inherited by 1.3 extensions).

* [rfc6066.txt](./tls/rfc6066.txt) — TLS extensions (SNI, MFL,
  status_request, etc.). SNI handling lives in
  [`src/tls/server/sni.rs`](../src/tls/server/sni.rs) and
  `parser.rs`.

* [rfc7301.txt](./tls/rfc7301.txt) — ALPN. See
  [`src/tls/enums.rs`](../src/tls/enums.rs)' `ApplicationProtocol`
  and `parse_protocol_name_list` in `parser.rs`.

* [rfc6962.txt](./tls/rfc6962.txt) — Certificate Transparency.
  Kept as reference; only the `signed_certificate_timestamp`
  extension id is currently surfaced.

* [rfc5280.txt](./tls/rfc5280.txt) — X.509 / PKIX. Certificate
  chain types are part of the public API of
  [`src/tls/server/config.rs`](../src/tls/server/config.rs) and
  `src/tls/client/config.rs`. Validation itself lives in the
  `rama-tls-*` crates.

* [rfc5077.txt](./tls/rfc5077.txt) — TLS session resumption with
  session tickets. Kept as reference; only the `session_ticket`
  extension id is currently surfaced.

### Forwarded

* [rfc7239.txt](./forwarded/rfc7239.txt) — `Forwarded` HTTP header.
  Implemented in [`src/forwarded/`](../src/forwarded); see
  `element/parser.rs`, `node.rs`, `obfuscated.rs`.

* [rfc7230.txt](./forwarded/rfc7230.txt) — HTTP/1.1 message
  syntax. Used for the `token`, `quoted-string`, `quoted-pair`
  and `OWS` rules consumed by the `Forwarded` parser.

### IP

Specifications enumerated by
[`src/stream/matcher/private_ip.rs`](../src/stream/matcher/private_ip.rs):

* [rfc1122.txt](./ip/rfc1122.txt) — Internet host requirements
  (loopback, "this network").
* [rfc1918.txt](./ip/rfc1918.txt) — IPv4 private address space.
* [rfc3927.txt](./ip/rfc3927.txt) — IPv4 link-local (169.254/16).
* [rfc4193.txt](./ip/rfc4193.txt) — IPv6 unique local addresses.
* [rfc4291.txt](./ip/rfc4291.txt) — IPv6 addressing architecture
  (loopback, unspecified, link-local, multicast).
* [rfc6598.txt](./ip/rfc6598.txt) — IPv4 shared address space
  (CGNAT, 100.64/10).
* [rfc6890.txt](./ip/rfc6890.txt) — IANA special-purpose address
  registries.

### Misc

* [rfc863.txt](./misc/rfc863.txt) — Discard protocol. Implemented
  in [`src/stream/service/discard.rs`](../src/stream/service/discard.rs).

### See also (vendored by sibling crates)

* WebSocket — RFC 6455 (with RFC 7692 and RFC 8441) is vendored
  under [`rama-ws/specifications/`](../../rama-ws/specifications).
  `rama-net` only declares the `ws`/`wss` URI schemes in
  [`src/proto.rs`](../src/proto.rs).
* SOCKS5 — RFC 1928 / 1929 / 1961 are vendored under
  [`rama-socks5/specifications/`](../../rama-socks5/specifications).
  `rama-net` only declares the `socks5`/`socks5h` URI schemes.
