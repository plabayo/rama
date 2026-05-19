# Specifications

## HTTP Core

A non-exhaustive collection of specifications as implemented,
relied upon by rama-http-core or related to.

### RFCs

* [rfc1945.txt](./rfc1945.txt)  
  Hypertext Transfer Protocol -- HTTP/1.0

* [rfc5234.txt](./rfc5234.txt)  
  Augmented BNF for Syntax Specifications: ABNF. Referenced by the VCHAR /
  obs-text grammar used in reason-phrase and header-value validators.

* [rfc5789.txt](./rfc5789.txt)  
  PATCH Method for HTTP

* [rfc7230.txt](./rfc7230.txt)  
  HTTP/1.1: Message Syntax and Routing. Superseded by RFC 9112 but still
  cited throughout the h1 wire-format code; vendored for offline auditability.

* [rfc7231.txt](./rfc7231.txt)  
  HTTP/1.1: Semantics and Content. Superseded by RFC 9110 but still cited
  for safe/cacheable method definitions; vendored for offline auditability.

* [rfc7540.txt](./rfc7540.txt)  
  HTTP/2. Superseded by RFC 9113; vendored because the `NoRfc7540Priorities`
  setting and stream-priority logic are historically anchored to this text.

* [rfc7541.txt](./rfc7541.txt)  
  HPACK: Header Compression for HTTP/2

* [rfc8470.txt](./rfc8470.txt)  
  Using Early Data in HTTP

* [rfc9110.txt](./rfc9110.txt)  
  HTTP Semantics. This document describes the overall architecture of HTTP,
  establishes common terminology, and defines aspects of the protocol
  that are shared by all versions.

* [rfc9112.txt](./rfc9112.txt)  
  HTTP/1.1

* [rfc9113.txt](./rfc9113.txt)  
  HTTP/2

### Related, vendored in sibling crates

To avoid duplication, the following load-bearing specifications live next
to the crate that owns their primary concern:

* [rfc3986.txt](../../rama-net/specifications/uri/rfc3986.txt) —
  URI Generic Syntax (request-target and `:authority` parsing).
* [rfc6455.txt](../../rama-ws/specifications/rfc6455.txt) —
  The WebSocket Protocol (h1 `Upgrade` handshake).
* [rfc7239.txt](../../rama-http-headers/specifications/rfc7239.txt) —
  `Forwarded` header.
* [rfc7838.txt](../../rama-http/specifications/rfc7838.txt) — `Alt-Svc`.
* [rfc8441.txt](../../rama-ws/specifications/rfc8441.txt) —
  Bootstrapping WebSockets with HTTP/2 (Extended CONNECT / `:protocol`).
* [rfc9111.txt](../../rama-http/specifications/rfc9111.txt) — HTTP Caching
  (hop-by-hop / `Cache-Control` semantics relevant to proxy forwarding).
