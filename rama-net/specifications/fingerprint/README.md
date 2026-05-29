# Fingerprinting specifications

The fingerprint algorithms implemented under
[`src/fingerprint/`](../../src/fingerprint) — JA3, JA4 / JA4H, the
Akamai HTTP/2 client fingerprint, and PeetPrint — are not RFCs. Their
authoritative descriptions live in third-party repositories or
whitepapers whose licensing makes verbatim redistribution either
restricted, incompatible with `rama`'s permissive MIT/Apache-2.0
dual-licensing, or simply not possible at all. We therefore do **not**
vendor any of these documents here; we link out to the authoritative
upstream source, cite the licence, and pin the implementation file
inside [`rama-net/src/fingerprint/`](../../src/fingerprint) so the
spec is always one click from the code that materialises it.

## JA3 (TLS client fingerprint)

* Upstream: <https://github.com/salesforce/ja3> (licensed BSD-3-Clause;
  Salesforce no longer actively maintains it but the README remains
  the canonical reference for the algorithm).
* Authoritative blog post: ["TLS Fingerprinting with JA3 and
  JA3S"](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967).
* Implementation:
  [`src/fingerprint/ja3.rs`](../../src/fingerprint/ja3.rs).
  `Ja3::compute` gathers SSL Version, Cipher Suites, Extensions,
  Elliptic Curves, and EC Point Formats from the captured TLS
  ClientHello, filters out GREASE values (RFC 8701) per spec, and
  MD5-hashes the dash/comma-delimited string.

## JA4 family (JA4 / JA4H)

* Upstream: <https://github.com/FoxIO-LLC/ja4>, maintained by FoxIO,
  LLC. Distributed under the **FoxIO License 1.1**, which permits
  non-commercial use only — incompatible with `rama`'s permissive
  dual-licensing, so the spec text is not vendored here.
* Per-format specs:
  * JA4 (TLS):
    <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>
  * JA4H (HTTP):
    <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md>
* Implementations:
  * [`src/fingerprint/ja4/tls.rs`](../../src/fingerprint/ja4/tls.rs)
    — `Ja4::compute` builds the `q/t13d / GREASE-aware` raw string
    and the truncated SHA-256 hash from the ClientHello extensions.
  * [`src/fingerprint/ja4/http.rs`](../../src/fingerprint/ja4/http.rs)
    — `Ja4H::compute` extracts the HTTP method, version,
    cookie/referer presence, the `Accept-Language` value, and the
    ordered header list to derive the JA4H string and 12-character
    truncated hash.

## Akamai HTTP/2 fingerprint

* Upstream whitepaper: *Passive Fingerprinting of HTTP/2 Clients*
  (<https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf>,
  presented at Black Hat Europe 2017),
  copyright Akamai Technologies. Not freely redistributable, so not
  vendored here.
* Format (re-implemented from the whitepaper): four pipe-separated
  fields drawn from the SETTINGS frame parameters in declared order,
  the client-initiated WINDOW_UPDATE increment, the ordered list of
  PRIORITY frames, and the HTTP/2 pseudo-header order:

  ```text
  SETTINGS|WINDOW_UPDATE|PRIORITY|HEADER_ORDER
  ```

* Implementation:
  [`src/fingerprint/akamai/h2.rs`](../../src/fingerprint/akamai/h2.rs).
  `AkamaiH2::compute` reads the captured early frames (SETTINGS,
  WINDOW_UPDATE, PRIORITY) and the `PseudoHeaderOrder` extension to
  emit both the raw `|`-delimited string and an MD5 hash.

## PeetPrint (TLS fingerprint, sorted-extension variant)

* Upstream: <https://github.com/wwhtrbbtt/TrackMe>, licensed
  **GPL-3.0** — incompatible with `rama`'s permissive
  dual-licensing, so the upstream sources cannot be vendored. The
  algorithm itself (sorted extension list, explicit `(GREASE)`
  marker) is re-implemented from observation against the upstream
  tool.
* Implementation:
  [`src/fingerprint/peet/tls.rs`](../../src/fingerprint/peet/tls.rs).
  `PeetPrint::compute` mirrors the canonical PeetPrint extension
  ordering, retains the literal `(GREASE)` token for the GREASE
  family, and hashes the resulting string with MD5.
