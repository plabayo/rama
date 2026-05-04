# Specifications

## HTTP

A non-exhaustive collection of specifications as implemented,
relied upon by rama-http or related to.

These are often specs that cross into most of the rama http crates,
and even rama net crates.

### RFCs

* [rfc2046.txt](./rfc2046.txt)  
  MIME Part Two: Media Types. Defines the `multipart/*` and
  `application/octet-stream` media types.

* [rfc6265.txt](./rfc6265.txt)  
  HTTP State Management Mechanism (Cookies)

* [rfc6266.txt](./rfc6266.txt)  
  Use of the Content-Disposition Header Field in HTTP, including
  the `attachment` and `filename`/`filename*` parameters.

* [rfc6648.txt](./rfc6648.txt)  
  Deprecating the "X-" Prefix
  and Similar Constructs in Application Protocols

* [rfc7578.txt](./rfc7578.txt)  
  Returning Values from Forms: `multipart/form-data`. Obsoletes
  RFC 2388.

* [rfc7838.txt](./rfc7838.txt)  
  HTTP Alternative Services (ALTSVC / Alt-Svc)

* [rfc8187.txt](./rfc8187.txt)  
  Indicating Character Encoding and Language for HTTP Header Field
  Parameters (the `filename*` ext-value form).

* [rfc9111.txt](./rfc9111.txt)  
  HTTP Caching. This document defines HTTP caches and the associated header
  fields that control cache behavior or indicate cacheable response
  messages.

#### Content Encoding and Compression

* [rfc1950.txt](./content-encoding-and-compression/rfc1950.txt)  
  Defines the zlib compressed data format.

* [rfc1951.txt](./content-encoding-and-compression/rfc1951.txt)  
  Defines the DEFLATE compression algorithm.

* [rfc1952.txt](./content-encoding-and-compression/rfc1952.txt)  
  Defines the gzip file format.

* [rfc7932.txt](./content-encoding-and-compression/rfc7932.txt)  
  Defines the Brotli compression algorithm.
