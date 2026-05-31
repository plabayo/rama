# RSS / Atom feed corpus

A small set of feed fixtures the parser is exercised against in
[`rama-http/tests/rss_corpus.rs`](../rss_corpus.rs).

Each `.xml` file is a self-contained RSS 2.0 or Atom 1.0 feed designed to
stress one specific area:

| File | Purpose |
|---|---|
| `blog-minimal.rss.xml` | RSS 2.0 happy path — minimum required fields plus one item. |
| `blog-atom.atom.xml` | Atom 1.0 happy path — every spec field at least once. |
| `podcast-itunes.rss.xml` | Real-shaped podcast with full `itunes:` extension. |
| `podcast-v2.rss.xml` | Podcasting 2.0 namespace (guid, locked, funding, person, location, trailer, transcript, chapters, soundbite, season, episode). |
| `atom-xhtml.atom.xml` | Atom `type="xhtml"` text constructs — inner subtree, not flat text. |
| `edge-ampersand-attrs.rss.xml` | Attribute values containing `&`, `<`, `"`. Round-trip must not double-escape. |
| `edge-cdata-terminator.rss.xml` | `content:encoded` payload containing `]]>` — naive single-CDATA emit would close the section early. |
| `edge-atom-source.atom.xml` | Atom entry with `<source>`; source's children must not leak into the entry. |
| `edge-prefixed-atom-root.atom.xml` | `<a:feed xmlns:a="…Atom">` — prefix is non-default but the namespace URI is the Atom one. |
| `edge-nonstandard-podcast-prefix.rss.xml` | Podcasting 2.0 namespace bound to `pod:` instead of `podcast:`. |
| `edge-multiple-enclosures.rss.xml` | Item with both an audio and a video `<enclosure>`. |
| `edge-atom-contributors.atom.xml` | `<contributor>` at both feed level and entry level — must NOT merge into `authors`. |
| `edge-atom-source-xhtml.atom.xml` | `<source>` containing a `type="xhtml"` `<title>` — must NOT overwrite the enclosing entry's own title. |

The fixtures are intentionally synthetic — they're not scraped from any real
podcast or blog — but they reproduce the shapes the corresponding *real* feeds
take in the wild (Apple Podcasts iTunes tag spec, Podcast Index 2.0 examples,
generic Atom 1.0 blogs).
