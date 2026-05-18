# Fingerprinting specifications

The fingerprint algorithms implemented under
[`src/fingerprint/`](../../src/fingerprint) — JA3, JA4 / JA4H, the Akamai
HTTP/2 client fingerprint, and PeetPrint — are not RFCs. Their
authoritative descriptions live in third-party repositories or blog
posts whose licensing makes redistribution either permissive (JA3),
restricted (JA4), or simply not possible at all (Akamai's whitepaper,
Peet's GPL-licensed implementation). This directory therefore vendors
only what can be safely redistributed, and links out for the rest.

For each entry below we cite the implementation file inside
`rama-net/src/fingerprint/` so the spec is always one click from the
code that materialises it.

## JA3 (TLS client fingerprint, vendored)

Implemented by [`src/fingerprint/ja3.rs`](../../src/fingerprint/ja3.rs): the
`Ja3::compute` entry point gathers SSL Version, Cipher Suites,
Extensions, Elliptic Curves, and EC Point Formats from the captured
TLS ClientHello, filters out GREASE values (RFC 8701) per spec, and
MD5-hashes the dash/comma-delimited string.

## JA4 family (not vendored — see upstream)

The JA4+ suite (JA4 for TLS, JA4H for HTTP, etc.) is maintained by
FoxIO, LLC at <https://github.com/FoxIO-LLC/ja4>. The spec is
distributed under the **FoxIO License 1.1**, which permits
non-commercial use only; because `rama` is dual-licensed
MIT/Apache-2.0 (and therefore intended for unconstrained downstream
use), the JA4 spec text is not vendored here.

* Spec: <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>
  * Implemented by
    [`src/fingerprint/ja4/tls.rs`](../../src/fingerprint/ja4/tls.rs):
    `Ja4::compute` builds the `q/t13d / GREASE-aware` raw string and
    the truncated SHA-256 hash from the ClientHello extensions.
* Spec: <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md>
  * Implemented by
    [`src/fingerprint/ja4/http.rs`](../../src/fingerprint/ja4/http.rs):
    `Ja4H::compute` extracts the HTTP method, version, cookie/referer
    presence, the `Accept-Language` value, and the ordered header
    list to derive the JA4H string and 12-character truncated hash.

## Akamai HTTP/2 fingerprint (not vendored — proprietary whitepaper)

Akamai's HTTP/2 fingerprint format ("Akamai H2") was first described
in their whitepaper *Passive Fingerprinting of HTTP/2 Clients*
(<https://www.akamai.com/site/en/documents/research-paper/passive-fingerprinting-of-http2-clients-white-paper.pdf>).
The whitepaper is copyrighted by Akamai Technologies and is not
freely redistributable, so it is not vendored here.

The format concatenates four pipe-separated fields:

```
SETTINGS|WINDOW_UPDATE|PRIORITY|HEADER_ORDER
```

drawn from the SETTINGS frame parameters in declared order, the
client-initiated WINDOW_UPDATE increment, any ordered list of
PRIORITY frames, and the HTTP/2 pseudo-header order.

* Implemented by
  [`src/fingerprint/akamai/h2.rs`](../../src/fingerprint/akamai/h2.rs):
  `AkamaiH2::compute` reads the captured early frames (SETTINGS,
  WINDOW_UPDATE, PRIORITY) and the `PseudoHeaderOrder` extension to
  emit both the raw `|`-delimited string and an MD5 hash.

## PeetPrint (not vendored — GPL-3.0)

PeetPrint is a JA3-style TLS fingerprint variant (sorted extensions,
explicit GREASE marker `(GREASE)`) originally implemented in
<https://github.com/wwhtrbbtt/TrackMe>. That repository is licensed
under GPL-3.0 and is therefore license-incompatible with `rama`'s
permissive MIT/Apache-2.0 dual licensing; we do not vendor its
sources, only re-implement the documented algorithm.

* Implemented by
  [`src/fingerprint/peet/tls.rs`](../../src/fingerprint/peet/tls.rs):
  `PeetPrint::compute` mirrors PeetPrint's canonical extension
  ordering, retains the literal `(GREASE)` token for the GREASE
  family, and hashes the resulting string with MD5.
