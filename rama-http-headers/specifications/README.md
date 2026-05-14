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

### WHATWG

* [fetch.whatwg.org.bs](./fetch.whatwg.org.bs)  
  Fetch Living Standard (bikeshed source). Defines the `X-Content-Type-Options` header
  (see the "X-Content-Type-Options header" section).
