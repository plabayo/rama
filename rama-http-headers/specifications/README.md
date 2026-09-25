# Specifications

## HTTP Headers

A non-exhaustive collection of specifications as implemented,
relied upon by rama-http-headers or related to.

Note that most of the (typed) headers module is only useful when combined
with implemented code in other rama crates. As such this module cannot be seen
on itself as an implementation of any of these listed specifications, that is even
if we have implemented it at all.

### RFCs

* [rfc6797.txt](./rfc6797.txt)  
  HTTP Strict Transport Security (HSTS).

* [rfc7034.txt](./rfc7034.txt)  
  HTTP Header Field X-Frame-Options.

* [rfc7239.txt](./rfc7239.txt)  
  Forwarded HTTP Extension.

* [rfc9651.txt](./rfc9651.txt)  
  Structured Field Values for HTTP. Parsed by `rama-http-types`'
  `structured_fields` module; used by typed `Priority` and `Capsule-Protocol`.

### Related, vendored in sibling crates

* [rfc9297.txt](../../rama-http-core/specifications/rfc9297.txt) —
  HTTP Datagrams and the Capsule Protocol (`Capsule-Protocol` field).

### WHATWG

* [fetch.whatwg.org.md](./fetch.whatwg.org.md)  
  Fetch Living Standard. Defines the `X-Content-Type-Options` header
  (see the "X-Content-Type-Options header" section).
