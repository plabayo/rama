# Specifications

## HTTP

A non-exhaustive collection of specifications as implemented,
relied upon by rama-http or related to.

These are often specs that cross into most of the rama http crates,
and even rama net crates.

### RFCs

* [rfc6265.txt](./rfc6265.txt)  
  HTTP State Management Mechanism (Cookies)

* [rfc6648.txt](./rfc6648.txt)  
  Deprecating the "X-" Prefix
  and Similar Constructs in Application Protocols

* [rfc7838.txt](./rfc7838.txt)  
  HTTP Alternative Services (ALTSVC / Alt-Svc)

* [rfc9111.txt](./rfc9111.txt)  
  HTTP Caching. This document defines HTTP caches and the associated header
  fields that control cache behavior or indicate cacheable response
  messages.

#### RSS and Atom Feeds

* [RSS 2.0 Specification](https://www.rssboard.org/rss-specification)  
  RSS 2.0 channel and item format, including `<enclosure>`, `<guid>`, and RFC 2822 date fields.

* [RFC 4287](https://www.rfc-editor.org/rfc/rfc4287)  
  The Atom Syndication Format. Defines `<feed>`, `<entry>`, text constructs, and RFC 3339 dates.

* [RFC 822 §5](https://www.rfc-editor.org/rfc/rfc822#section-5)  
  Internet Message Format date/time used in RSS 2.0 `<pubDate>` and `<lastBuildDate>`.

* [iTunes Podcast Tag Specification](https://podcasters.apple.com/support/823-podcast-requirements)  
  Apple iTunes namespace (`itunes:`) extensions for podcast feeds.

* [Podcasting 2.0 Namespace](https://podcastindex.org/namespace/1.0)  
  The `podcast:` namespace for open podcast extensions (chapters, transcripts, persons, etc.).

* [Media RSS Specification](https://www.rssboard.org/media-rss)  
  The `media:` namespace for multimedia content metadata in RSS feeds.

* [Dublin Core Metadata Element Set](https://www.dublincore.org/specifications/dublin-core/dces/)  
  The `dc:` namespace providing 15 metadata elements (title, creator, date, etc.).

#### Content Encoding and Compression

* [rfc1950.txt](./content-encoding-and-compression/rfc1950.txt)  
  Defines the zlib compressed data format.

* [rfc1951.txt](./content-encoding-and-compression/rfc1951.txt)  
  Defines the DEFLATE compression algorithm.

* [rfc1952.txt](./content-encoding-and-compression/rfc1952.txt)  
  Defines the gzip file format.

* [rfc7932.txt](./content-encoding-and-compression/rfc7932.txt)  
  Defines the Brotli compression algorithm.
