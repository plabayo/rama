//! Smoke + round-trip tests against the vendored RSS / Atom feed corpus.
//!
//! See `tests/rss-corpus/README.md` for what each fixture covers. The general
//! shape is: every `.xml` file under `tests/rss-corpus/` must parse, must
//! re-serialize to well-formed XML, and (for happy-path fixtures) must parse
//! again to a model equal to the first parse.

#![cfg(feature = "rss")]
#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "integration test: panicking on unexpected input is the assertion"
)]

use std::fs;
use std::path::{Path, PathBuf};

use rama_http::protocols::rss::{AtomFeedStream, Feed, FeedStream, Rss2FeedStream};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("rss-corpus")
}

fn corpus_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(corpus_dir())
        .expect("open corpus dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("xml"))
        .collect();
    files.sort();
    files
}

fn load(p: &Path) -> Vec<u8> {
    fs::read(p).unwrap_or_else(|err| panic!("read {}: {err}", p.display()))
}

fn name(p: &Path) -> &str {
    p.file_name().and_then(|n| n.to_str()).unwrap_or("?")
}

async fn parse_bytes(bytes: Vec<u8>) -> Feed {
    let cursor = std::io::Cursor::new(bytes);
    let reader = tokio::io::BufReader::new(cursor);
    FeedStream::new(reader)
        .await
        .expect("FeedStream::new")
        .collect()
        .await
        .unwrap_or_else(|err| panic!("collect: {}", err.error))
}

/// Every fixture must parse (lenient).
#[tokio::test]
async fn corpus_parses_lenient() {
    let files = corpus_files();
    assert!(!files.is_empty(), "corpus is empty");
    for path in &files {
        let bytes = load(path);
        let cursor = std::io::Cursor::new(bytes);
        let reader = tokio::io::BufReader::new(cursor);
        FeedStream::new(reader)
            .await
            .unwrap_or_else(|err| panic!("{} should parse: {err}", name(path)));
    }
}

/// Every fixture must serialize back to a well-formed XML document.
#[tokio::test]
async fn corpus_serializes_to_wellformed_xml() {
    for path in corpus_files() {
        let bytes = load(&path);
        let feed = parse_bytes(bytes).await;
        let out = serialize(feed)
            .await
            .unwrap_or_else(|err| panic!("{}: serialize: {err}", name(&path)));
        // Round-trip through the reader once more to assert well-formedness.
        let mut r = quick_xml::Reader::from_reader(out.as_slice());
        loop {
            match r.read_event() {
                Ok(quick_xml::events::Event::Eof) => break,
                Err(err) => panic!("{}: re-emitted XML is not well-formed: {err}", name(&path)),
                Ok(_) => {}
            }
        }
    }
}

/// Every fixture must round-trip: parse -> serialize -> parse must give an
/// equal model. (This is the property a MITM proxy or aggregator relies on.)
#[tokio::test]
async fn corpus_round_trips_losslessly() {
    for path in corpus_files() {
        let bytes = load(&path);
        let first = parse_bytes(bytes).await;
        let serialized = serialize(first.clone()).await.unwrap();
        let second = parse_bytes(serialized).await;
        assert_eq!(
            first,
            second,
            "{}: model not equal after parse -> serialize -> parse",
            name(&path)
        );
    }
}

/// Drain a [`Feed`] through its async stream writer into a single buffer.
async fn serialize(feed: Feed) -> Result<Vec<u8>, rama_core::error::BoxError> {
    match feed {
        Feed::Rss2(f) => f.to_xml().await,
        Feed::Atom(f) => f.to_xml().await,
    }
}

/// The Atom `<source>` fixture is the regression for a specific bug: the
/// source's child id/title/updated/author/link/category must NOT leak into the
/// enclosing entry's collections.
#[tokio::test]
async fn atom_source_does_not_leak_into_entry() {
    let bytes = load(&corpus_dir().join("edge-atom-source.atom.xml"));
    let Feed::Atom(feed) = parse_bytes(bytes).await else {
        panic!("expected Atom");
    };
    let entry = &feed.entries[0];

    assert_eq!(entry.id, "https://aggregator.example.com/republished/1");
    assert_eq!(entry.title.value, "Republished Post");
    assert_eq!(entry.authors.len(), 1);
    assert_eq!(entry.authors[0].name, "EntryAuthor");
    // The single <link> on the entry is the entry's own, NOT the source's.
    assert_eq!(entry.links.len(), 1);
    assert_eq!(
        entry.links[0].href,
        "https://aggregator.example.com/republished/1"
    );
    // No source category leaked.
    assert!(entry.categories.is_empty());
    // Source itself was parsed.
    let src = entry.source.as_ref().expect("source parsed");
    assert_eq!(src.id.as_deref(), Some("https://origin.example.com/feed"));
}

/// Atom `<contributor>` must land in `contributors`, not `authors`.
/// Regression for a parser bug where both `<author>` and `<contributor>`
/// Start arms had the same body and contributors were silently merged into
/// authors.
#[tokio::test]
async fn atom_contributors_do_not_merge_into_authors() {
    let bytes = load(&corpus_dir().join("edge-atom-contributors.atom.xml"));
    let Feed::Atom(feed) = parse_bytes(bytes).await else {
        panic!("expected Atom");
    };

    // Feed level
    assert_eq!(feed.authors.len(), 1, "exactly one feed-level author");
    assert_eq!(feed.authors[0].name, "Primary Author");
    assert_eq!(
        feed.contributors.len(),
        2,
        "both feed-level contributors retained, not merged into authors",
    );
    let contrib_names: Vec<&str> = feed.contributors.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(contrib_names, ["Feed Contributor A", "Feed Contributor B"]);
    assert_eq!(feed.contributors[0].email.as_deref(), Some("a@example.com"));

    // Entry level
    let entry = &feed.entries[0];
    assert_eq!(entry.authors.len(), 1);
    assert_eq!(entry.authors[0].name, "Entry Author");
    assert_eq!(entry.contributors.len(), 1);
    assert_eq!(entry.contributors[0].name, "Entry Contributor");
}

/// xhtml-typed `<title>` (and other typed text constructs) inside an Atom
/// `<source>` must NOT overwrite the enclosing entry's own title/rights/etc.
/// Regression for a parser bug where `start_typed_text` bypassed the
/// `<source>` containment check on the xhtml path.
#[tokio::test]
async fn atom_xhtml_source_title_does_not_leak_into_entry() {
    use rama_http::protocols::rss::AtomTextKind;
    let bytes = load(&corpus_dir().join("edge-atom-source-xhtml.atom.xml"));
    let Feed::Atom(feed) = parse_bytes(bytes).await else {
        panic!("expected Atom");
    };
    let entry = &feed.entries[0];

    // Entry's own title must be untouched.
    assert_eq!(entry.title.value, "Republished item");
    assert_eq!(entry.title.kind, AtomTextKind::Text);

    // Source's xhtml title is captured on the source itself.
    let src = entry.source.as_ref().expect("source parsed");
    let src_title = src.title.as_ref().expect("source has a title");
    assert_eq!(src_title.kind, AtomTextKind::Xhtml);
    assert!(
        src_title.value.contains("<em>Origin</em>"),
        "xhtml subtree captured: {src_title:?}",
    );
}

/// Attributes carrying `&`/`"`/`<` must come back unescaped (no `&amp;` left in
/// `Rss2Enclosure.url` etc.).
#[tokio::test]
async fn ampersand_attrs_decode_to_raw_text() {
    let bytes = load(&corpus_dir().join("edge-ampersand-attrs.rss.xml"));
    let Feed::Rss2(feed) = parse_bytes(bytes).await else {
        panic!("expected RSS");
    };
    assert_eq!(feed.link, "https://example.com/?a=1&b=2");
    let item = &feed.items[0];
    assert_eq!(
        item.link.as_deref(),
        Some("https://example.com/post?utm_source=a&utm_medium=b")
    );
    let enc = &item.enclosures[0];
    assert_eq!(enc.url, "https://cdn.example.com/x?token=a&b=2&c=\"3\"");
    assert_eq!(
        item.categories[0].domain.as_deref(),
        Some("https://example.com/?tag=a&b=2"),
    );
}

/// `]]>` inside `content:encoded` must survive the round-trip.
#[tokio::test]
async fn cdata_terminator_round_trips() {
    let bytes = load(&corpus_dir().join("edge-cdata-terminator.rss.xml"));
    let Feed::Rss2(feed) = parse_bytes(bytes).await else {
        panic!("expected RSS");
    };
    let original = feed.items[0]
        .content()
        .and_then(|c| c.encoded.as_deref())
        .expect("content:encoded")
        .to_owned();
    assert!(
        original.contains("]]>"),
        "fixture should carry literal `]]>`, got {original:?}"
    );
    let serialized = feed.to_xml().await.unwrap();
    let Feed::Rss2(feed2) = parse_bytes(serialized).await else {
        panic!()
    };
    let after = feed2.items[0].content().and_then(|c| c.encoded.as_deref());
    assert_eq!(Some(original.as_str()), after);
}

/// Non-conventional Atom prefix must be detected and fully parsed.
#[tokio::test]
async fn prefixed_atom_root_parses() {
    let bytes = load(&corpus_dir().join("edge-prefixed-atom-root.atom.xml"));
    let Feed::Atom(feed) = parse_bytes(bytes).await else {
        panic!("expected Atom even though root is <a:feed>");
    };
    assert_eq!(feed.entries.len(), 1);
    assert_eq!(
        feed.entries[0].title.value,
        "An entry under a non-default Atom prefix"
    );
}

/// Non-conventional `pod:` prefix bound to the Podcasting 2.0 namespace must
/// be routed to the `podcast` extension exactly like the conventional prefix.
#[tokio::test]
async fn nonstandard_podcast_prefix_routes_by_uri() {
    let bytes = load(&corpus_dir().join("edge-nonstandard-podcast-prefix.rss.xml"));
    let Feed::Rss2(feed) = parse_bytes(bytes).await else {
        panic!("expected RSS");
    };
    let pf = feed.extensions.podcast.as_ref().expect("podcast feed ext");
    assert!(pf.guid.is_some());
    assert_eq!(pf.locked, Some(true));
    let item = &feed.items[0];
    let p = item.podcast().expect("podcast item ext");
    assert_eq!(p.persons.len(), 1);
    assert_eq!(p.persons[0].name, "Alice");
}

/// Multiple `<enclosure>` elements on one item must all survive the round-trip.
#[tokio::test]
async fn multiple_enclosures_preserved() {
    let bytes = load(&corpus_dir().join("edge-multiple-enclosures.rss.xml"));
    let Feed::Rss2(feed) = parse_bytes(bytes).await else {
        panic!()
    };
    assert_eq!(feed.items[0].enclosures.len(), 2);
    assert_eq!(feed.items[0].enclosures[1].type_, "video/mp4");
}

/// The typed streams expose `.channel()` / `.header()` BEFORE the items are
/// drained, and `.drain()` splits cleanly into `(header, item_stream)`.
#[tokio::test]
async fn typed_stream_header_visible_before_items_and_drain_works() {
    use rama_core::futures::StreamExt as _;

    // RSS path.
    let bytes = load(&corpus_dir().join("podcast-itunes.rss.xml"));
    let cursor = std::io::Cursor::new(bytes);
    let reader = tokio::io::BufReader::new(cursor);
    let s = Rss2FeedStream::new(reader).await.unwrap();
    assert_eq!(s.channel().title, "Example Pod");
    let (channel, mut items) = s.drain();
    assert_eq!(channel.title, "Example Pod");
    let first = items.next().await.unwrap().unwrap();
    assert_eq!(first.title.as_deref(), Some("Episode 1 \u{2014} Hello"));

    // Atom path.
    let bytes = load(&corpus_dir().join("blog-atom.atom.xml"));
    let cursor = std::io::Cursor::new(bytes);
    let reader = tokio::io::BufReader::new(cursor);
    let s = AtomFeedStream::new(reader).await.unwrap();
    assert_eq!(s.header().title.value, "Example Blog");
    let (header, mut entries) = s.drain();
    assert_eq!(header.id, "urn:uuid:6e95a2c8-9d5e-4f9f-9b6f-21f7d5b1f9aa");
    let first = entries.next().await.unwrap().unwrap();
    assert_eq!(first.title.value, "Hello, world");
}

/// `collect_filtered` must keep only items the predicate accepts, drop the
/// rest, and still return a complete `Rss2Feed` with the header intact.
#[tokio::test]
async fn collect_filtered_keeps_only_matching_items() {
    let bytes = load(&corpus_dir().join("podcast-itunes.rss.xml"));
    let cursor = std::io::Cursor::new(bytes);
    let reader = tokio::io::BufReader::new(cursor);
    let s = Rss2FeedStream::new(reader).await.unwrap();
    // The fixture has one item titled "Episode 1 — Hello"; filter for that.
    let feed = s
        .collect_filtered(|item| item.title.as_deref() == Some("Episode 1 \u{2014} Hello"))
        .await
        .expect("collect_filtered");
    assert_eq!(feed.title, "Example Pod");
    assert_eq!(feed.items.len(), 1);

    // And the inverse predicate yields a zero-item feed that still carries
    // the channel header.
    let bytes = load(&corpus_dir().join("podcast-itunes.rss.xml"));
    let cursor = std::io::Cursor::new(bytes);
    let reader = tokio::io::BufReader::new(cursor);
    let s = Rss2FeedStream::new(reader).await.unwrap();
    let feed = s
        .collect_filtered(|_| false)
        .await
        .expect("collect_filtered");
    assert_eq!(feed.title, "Example Pod");
    assert_eq!(feed.items.len(), 0);
}

/// `Feed::from_body` over a multi-chunk `Body::from_stream` body must produce
/// the same model as a single-chunk body. Exercises the streaming path's
/// behaviour at chunk boundaries (where a tag/attribute might straddle two
/// chunks).
#[tokio::test]
async fn from_body_handles_chunked_streams() {
    use rama_core::bytes::Bytes;
    use rama_core::futures::stream;
    use rama_http::Body;

    for path in corpus_files() {
        let bytes = load(&path);
        // Single-chunk reference.
        let reference = parse_bytes(bytes.clone()).await;

        // Multi-chunk: split into 11-byte chunks, awkward enough to land
        // boundaries inside tags, attributes, CDATA, etc.
        let chunks: Vec<Result<Bytes, std::io::Error>> = bytes
            .chunks(11)
            .map(|c| Ok::<_, std::io::Error>(Bytes::copy_from_slice(c)))
            .collect();
        let body = Body::from_stream(stream::iter(chunks));
        let chunked = Feed::from_body(body)
            .await
            .unwrap_or_else(|err| panic!("{}: chunked from_body: {err}", name(&path)));
        assert_eq!(
            reference,
            chunked,
            "{}: multi-chunk body parsed to a different model than single-chunk",
            name(&path)
        );
    }
}

/// Whole-feed write through [`FeedStreamWriter::from_feed`] must produce
/// byte-for-byte the same XML as draining a strongly-typed stream writer
/// (which is what `Rss2Feed::to_xml` / `AtomFeed::to_xml` do under the hood).
#[tokio::test]
async fn feed_stream_writer_matches_typed_writer() {
    use rama_core::futures::StreamExt as _;
    use rama_http::protocols::rss::FeedStreamWriter;

    for path in corpus_files() {
        let bytes = load(&path);
        let feed = parse_bytes(bytes).await;
        let typed = serialize(feed.clone()).await.unwrap();
        let mut umbrella = FeedStreamWriter::from_feed(feed);
        let mut umbrella_bytes = Vec::new();
        while let Some(chunk) = umbrella.next().await {
            umbrella_bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(
            typed,
            umbrella_bytes,
            "{}: FeedStreamWriter::from_feed bytes diverge from typed writer",
            name(&path),
        );
    }
}

/// Caller-supplied async item stream: build a feed by piping items from a
/// faux "database" (a stream that yields one item at a time) through the
/// streaming writer, then parse the result back and check item count.
#[tokio::test]
async fn rss2_stream_writer_from_async_item_source() {
    use rama_core::futures::StreamExt as _;
    use rama_http::protocols::rss::{Rss2Channel, Rss2Item, Rss2StreamWriter};

    let channel = Rss2Channel {
        title: "From DB".into(),
        link: "https://example.com".into(),
        description: "stream".into(),
        ..Default::default()
    };

    let items = rama_core::futures::stream::iter((0..5).map(|n| {
        Ok::<_, std::convert::Infallible>(
            Rss2Item::new()
                .with_title(format!("Item {n}"))
                .with_link(format!("https://example.com/{n}")),
        )
    }));

    let mut writer = Rss2StreamWriter::new(channel, items);
    let mut buf = Vec::new();
    while let Some(chunk) = writer.next().await {
        buf.extend_from_slice(&chunk.unwrap());
    }

    let Feed::Rss2(parsed) = parse_bytes(buf).await else {
        panic!("expected RSS");
    };
    assert_eq!(parsed.items.len(), 5);
    assert_eq!(parsed.title, "From DB");
}
