# Specifications

## Dns

A non-exhaustive collection of specifications as implemented,
relied upon by rama-dns or related to. The DNS specifications are not often
implemented in this crate directly but are here mostly for reference.

### RFCs

* [rfc1034.txt](./rfc1034.txt): Defines DNS concepts and facilities.

* [rfc1035.txt](./rfc1035.txt): Defines DNS implementation and message formats.

* [rfc3596.txt](./rfc3596.txt): Defines the `AAAA` resource record for IPv6
  address resolution
  (obsoletes RFC 1886 and RFC 3152).

* [rfc9460.txt](./rfc9460.txt): Defines the SVCB and HTTPS resource records and
  their shared service parameter wire format.

* [rfc9848.txt](./rfc9848.txt): Defines the `ech` SVCB service parameter used to
  bootstrap TLS Encrypted ClientHello.

* [rfc9849.txt](./rfc9849.txt): Defines TLS Encrypted ClientHello, including the
  `ECHConfigList` framing carried by the `ech` service parameter.
