# RSS and Atom Feeds

<div class="book-article-intro">
    <div>
        <strong>RSS 2.0</strong> and <strong>Atom 1.0</strong> are the two ubiquitous
        XML formats for publishing a feed of regularly-updated items — blog posts,
        news articles, and especially podcast episodes. A feed reader, podcast app,
        or aggregator polls the feed and renders the new items.
        <p>— <a href="https://www.rssboard.org/rss-specification">RSS Advisory Board</a> /
        <a href="https://www.rfc-editor.org/rfc/rfc4287">RFC 4287 — The Atom Syndication Format</a></p>
    </div>
</div>

## Description

A feed is a small XML document that describes a channel (or "feed", in Atom
terminology) and an ordered list of items (or "entries"). Subscribers fetch the
URL on a schedule and present any new items to the user. The two formats are
contemporaries that solve the same problem with slightly different vocabularies;
in practice most podcasts use RSS 2.0 and most modern blog platforms emit Atom,
but the choice is opaque to most subscribers.

The wire format is rarely interesting on its own — most of the operational
detail lives in *extension namespaces* that the core specs were intentionally
left open for. The ones that matter in the wild:

| Namespace | Used for |
|---|---|
| `itunes:` | Apple Podcasts metadata (artwork, explicit flag, episode/season numbers) |
| `podcast:` | [Podcasting 2.0](https://podcastindex.org/namespace/1.0) — chapters, transcripts, persons, locations, funding |
| `media:` | [Media RSS](https://www.rssboard.org/media-rss) — alternate media renditions, thumbnails |
| `dc:` | [Dublin Core](https://www.dublincore.org/specifications/dublin-core/dces/) — generic bibliographic metadata |
| `content:encoded` | Full HTML body of an item (RSS 1.0 content module) |

The authoritative specs (RSS 2.0, RFC 4287, the iTunes podcast tag spec, the
Podcasting 2.0 namespace, Media RSS, Dublin Core) are listed in
[`rama-http/specifications/README.md`](https://github.com/plabayo/rama/blob/main/rama-http/specifications/README.md).

## Rama Support

> 📚 Rust Docs: <https://ramaproxy.org/docs/rama/http/protocols/rss/index.html>

Enable the `rss` feature on the mono `rama` crate (or `http-full`, which pulls
it in). Everything lives under `rama::http::protocols::rss`.

Rama gives you:

- **Type-state builders** that make `RSS 2.0` (`title` + `link` + `description`)
  and `Atom 1.0` (`id` + `title` + `updated`) required fields a compile-time
  obligation — you cannot call `.build()` until the required fields are set.
- **Spec-compliant serialization** with the well-known extension namespaces
  (`itunes`, `podcast`, `dc`, `content`, `media`, `psc` — Podlove Simple
  Chapters, item-level only) declared up front on the root element and
  CDATA properly escaped (including the `]]>` case that
  breaks naive emitters). The streaming writer commits the channel/feed
  header before any item is seen, so declaring the recognised extensions
  on the root keeps the document namespace-well-formed regardless of what
  the item stream actually carries.
- **Lenient parsing by default, strict opt-in.** Unknown elements are skipped;
  malformed entities and missing required fields are tolerated. A strict mode
  is available on every reader entry point for the cases where you'd rather
  see the structural violation than silently absorb it.
- **Lossless round-trip** for both formats across all supported extensions.
  Parse → mutate → re-serialize is the proxy/aggregator case and is a first-class
  goal: every field the writer emits, the parser reads back.
- **Resolved-namespace routing** — extension elements are matched by their
  namespace URI rather than by literal prefix, so a feed declaring
  `xmlns:pod="https://podcastindex.org/namespace/1.0"` is parsed identically
  to one using the conventional `xmlns:podcast`.
- **Streaming-first, both directions, symmetric model.** Reading and writing
  both treat the feed as a header followed by an async stream of items, and
  both use the *same* header and item types — what the reader drains is what
  the writer expects to be given. On the read side the channel/feed header is
  parsed up front and inspectable before any item is pulled, so a consumer can
  decide whether to keep going (or apply a filter) without buffering the whole
  document. On the write side the symmetric path lets a server build the
  header first and pipe items in from any async source (database pagination,
  upstream proxy, scheduled job) so the response starts flowing before every
  item is materialised. Everything async; there's no sync serialization path.
  The in-memory whole-feed adapters are thin conveniences on top of the same
  streams.
- **Partial results on failure.** If an item partway through a feed fails to
  parse, the error carries the header and every item that succeeded before it,
  so a client doesn't lose the rest of a long feed to one bad entry. A lossy
  drain variant is also provided for the common "skip and keep going" case.
- **A format-agnostic `Feed` umbrella** for callers that want to consume a feed
  without caring whether the upstream chose RSS or Atom.
- **`IntoResponse` impls** so a handler can return a built feed directly and
  the correct `application/rss+xml` or `application/atom+xml` `Content-Type`
  is set for you.

### Examples

The ready-to-run examples cover the common shapes:

- [`http_rss_blog.rs`](https://github.com/plabayo/rama/blob/main/examples/src/http_rss_blog.rs)
  — serve an RSS 2.0 feed and an Atom 1.0 feed from the same router.
- [`http_rss_podcast.rs`](https://github.com/plabayo/rama/blob/main/examples/src/http_rss_podcast.rs)
  — serve a podcast feed with iTunes + Podcasting 2.0 extensions, both as a
  one-shot response and as a streamed response.

These are the canonical "how do I…" references; they're tested in CI so they
won't drift away from the API.

## Use cases

The same API serves three distinct callers:

- **Authors** (blog or podcast publisher) build a feed in code with the
  type-state builder, optionally driving items from a database via a `Stream`
  when the feed is large or the items are paginated.
- **Aggregators / clients** (podcast apps, feed readers, search indexers) fetch
  a feed from the wire and parse it. Default leniency is what you want here —
  third-party feeds in the wild are routinely a little off-spec and the right
  behaviour is to skip what you don't understand, not to reject the whole
  document. The streaming reader lets you inspect the channel header before
  committing to the rest of the feed and lets you discard items as they're
  produced, which keeps memory bounded for very large podcast or aggregator
  feeds.
- **Proxies** (MITM tooling, transformation gateways, ad-injection pipelines)
  parse a feed, mutate it, and re-serialize. Lossless round-trip is the
  property that makes this safe — anything the proxy doesn't touch must come
  out of the other side byte-for-byte equivalent at the model level. Apply a
  `BodyLimit` layer upstream of any untrusted parse to cap the memory cost.

## See also

- [Server-Sent Events](./sse.md) — for *pushing* updates as they happen rather
  than the *polling* model RSS/Atom assume.
- [Binary Bodies and Multipart Uploads](./multipart.md) — for `<enclosure>`
  binaries (podcast audio) the feed points at.
