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

use rama_http::protocols::rss::Feed;

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

fn load(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_else(|err| panic!("read {}: {err}", p.display()))
}

fn name(p: &Path) -> &str {
    p.file_name().and_then(|n| n.to_str()).unwrap_or("?")
}

/// Every fixture must parse (lenient).
#[test]
fn corpus_parses_lenient() {
    let files = corpus_files();
    assert!(!files.is_empty(), "corpus is empty");
    for path in &files {
        let xml = load(path);
        Feed::parse(&xml).unwrap_or_else(|err| panic!("{} should parse: {err}", name(path)));
    }
}

/// Every fixture must serialize back to a well-formed XML document.
#[test]
fn corpus_serializes_to_wellformed_xml() {
    for path in corpus_files() {
        let xml = load(&path);
        let feed = Feed::parse(&xml).unwrap();
        let out = match feed {
            Feed::Rss2(f) => f.to_xml(),
            Feed::Atom(f) => f.to_xml(),
        }
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
#[test]
fn corpus_round_trips_losslessly() {
    for path in corpus_files() {
        let xml = load(&path);
        let first = Feed::parse(&xml).unwrap();
        let serialized = match &first {
            Feed::Rss2(f) => f.to_xml(),
            Feed::Atom(f) => f.to_xml(),
        }
        .unwrap();
        let xml2 = std::str::from_utf8(&serialized).unwrap();
        let second = Feed::parse(xml2)
            .unwrap_or_else(|err| panic!("{}: re-parse failed: {err}", name(&path)));
        assert_eq!(
            first,
            second,
            "{}: model not equal after parse -> serialize -> parse",
            name(&path)
        );
    }
}

/// The Atom `<source>` fixture is the regression for a specific bug: the
/// source's child id/title/updated/author/link/category must NOT leak into the
/// enclosing entry's collections.
#[test]
fn atom_source_does_not_leak_into_entry() {
    let xml = load(&corpus_dir().join("edge-atom-source.atom.xml"));
    let Feed::Atom(feed) = Feed::parse(&xml).unwrap() else {
        panic!("expected Atom");
    };
    let entry = &feed.entries[0];

    assert_eq!(entry.id, "https://aggregator.example.com/republished/1");
    assert_eq!(entry.title.value(), "Republished Post");
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

/// Attributes carrying `&`/`"`/`<` must come back unescaped (no `&amp;` left in
/// `Rss2Enclosure.url` etc.).
#[test]
fn ampersand_attrs_decode_to_raw_text() {
    let xml = load(&corpus_dir().join("edge-ampersand-attrs.rss.xml"));
    let Feed::Rss2(feed) = Feed::parse(&xml).unwrap() else {
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

/// `]]>` inside `content:encoded` must survive the round-trip; the writer
/// splits at every occurrence so the output is well-formed.
#[test]
fn cdata_terminator_round_trips() {
    let xml = load(&corpus_dir().join("edge-cdata-terminator.rss.xml"));
    let Feed::Rss2(feed) = Feed::parse(&xml).unwrap() else {
        panic!("expected RSS");
    };
    let original = feed.items[0]
        .content()
        .and_then(|c| c.encoded.as_deref())
        .expect("content:encoded");
    assert!(
        original.contains("]]>"),
        "fixture should carry literal `]]>`, got {original:?}"
    );
    let xml2 = String::from_utf8(feed.to_xml().unwrap()).unwrap();
    let Feed::Rss2(feed2) = Feed::parse(&xml2).unwrap() else {
        panic!()
    };
    let after = feed2.items[0].content().and_then(|c| c.encoded.as_deref());
    assert_eq!(Some(original), after);
}

/// Non-conventional Atom prefix must be detected and fully parsed.
#[test]
fn prefixed_atom_root_parses() {
    let xml = load(&corpus_dir().join("edge-prefixed-atom-root.atom.xml"));
    let Feed::Atom(feed) = Feed::parse(&xml).unwrap() else {
        panic!("expected Atom even though root is <a:feed>");
    };
    assert_eq!(feed.entries.len(), 1);
    assert_eq!(
        feed.entries[0].title.value(),
        "An entry under a non-default Atom prefix"
    );
}

/// Non-conventional `pod:` prefix bound to the Podcasting 2.0 namespace must
/// be routed to the `podcast` extension exactly like the conventional prefix.
#[test]
fn nonstandard_podcast_prefix_routes_by_uri() {
    let xml = load(&corpus_dir().join("edge-nonstandard-podcast-prefix.rss.xml"));
    let Feed::Rss2(feed) = Feed::parse(&xml).unwrap() else {
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

/// Drive every fixture through the **async streaming reader** + `collect_*`
/// adapter and assert it produces the same model as the sync `Feed::parse`.
/// This is the property a `Feed::from_body` caller (and `Rss2Feed::to_byte_stream`
/// round-trip) depend on.
#[tokio::test]
async fn corpus_streaming_reader_matches_sync_parser() {
    use rama_http::protocols::rss::{AtomFeedStream, Rss2FeedStream};

    for path in corpus_files() {
        let xml = load(&path);
        let sync = Feed::parse(&xml).unwrap();
        let cursor = std::io::Cursor::new(xml.into_bytes());
        let buf = tokio::io::BufReader::new(cursor);
        let streamed = match &sync {
            Feed::Rss2(_) => Feed::Rss2(
                Rss2FeedStream::new(buf)
                    .await
                    .unwrap_or_else(|err| panic!("{}: streaming RSS new: {err}", name(&path)))
                    .collect()
                    .await
                    .unwrap_or_else(|err| panic!("{}: streaming RSS collect: {err}", name(&path))),
            ),
            Feed::Atom(_) => Feed::Atom(
                AtomFeedStream::new(buf)
                    .await
                    .unwrap_or_else(|err| panic!("{}: streaming Atom new: {err}", name(&path)))
                    .collect()
                    .await
                    .unwrap_or_else(|err| panic!("{}: streaming Atom collect: {err}", name(&path))),
            ),
        };
        assert_eq!(
            sync,
            streamed,
            "{}: streaming reader and sync parser produced different models",
            name(&path)
        );
    }
}

/// `Rss2FeedStream::channel` / `AtomFeedStream::header` must expose the parsed
/// header *before* any item is read, and `drain` must split into
/// `(header, items)` exactly the way the docs promise.
#[tokio::test]
async fn typed_stream_header_visible_before_items_and_drain_works() {
    use rama_core::futures::StreamExt as _;
    use rama_http::protocols::rss::{AtomFeedStream, FeedStream, Rss2FeedStream};

    // RSS path: prove `.channel()` returns the title before any item is read.
    let xml = load(&corpus_dir().join("podcast-itunes.rss.xml"));
    let buf = tokio::io::BufReader::new(std::io::Cursor::new(xml.into_bytes()));
    let s = Rss2FeedStream::new(buf).await.unwrap();
    assert_eq!(s.channel().title, "Example Pod");
    let (channel, mut items) = s.drain();
    assert_eq!(channel.title, "Example Pod");
    let first = items.next().await.unwrap().unwrap();
    assert_eq!(first.title.as_deref(), Some("Episode 1 \u{2014} Hello"));
    // Atom path.
    let xml = load(&corpus_dir().join("blog-atom.atom.xml"));
    let buf = tokio::io::BufReader::new(std::io::Cursor::new(xml.into_bytes()));
    let s = AtomFeedStream::new(buf).await.unwrap();
    assert_eq!(s.header().title.value(), "Example Blog");
    let (header, mut entries) = s.drain();
    assert_eq!(header.id, "urn:uuid:6e95a2c8-9d5e-4f9f-9b6f-21f7d5b1f9aa");
    let first = entries.next().await.unwrap().unwrap();
    assert_eq!(first.title.value(), "Hello, world");
    // Umbrella FeedStream over an arbitrary corpus file.
    let xml = load(&corpus_dir().join("podcast-v2.rss.xml"));
    let body = rama_http::Body::from(xml.into_bytes());
    let umbrella = FeedStream::from_body(body).await.unwrap();
    let feed = umbrella.collect().await.unwrap();
    assert!(matches!(feed, Feed::Rss2(_)));
}

/// `Feed::from_body` must produce the same model as `Feed::parse(&str)` for
/// every fixture. Exercises the new stream-first body parser end-to-end.
#[tokio::test]
async fn from_body_matches_sync_parse_on_corpus() {
    use rama_http::Body;

    for path in corpus_files() {
        let xml = load(&path);
        let sync = Feed::parse(&xml).unwrap();
        let body = Body::from(xml.into_bytes());
        let via_body = Feed::from_body(body)
            .await
            .unwrap_or_else(|err| panic!("{}: from_body: {err}", name(&path)));
        assert_eq!(
            sync,
            via_body,
            "{}: from_body produced a different model than sync parse",
            name(&path)
        );
    }
}

/// `Rss2Feed::to_byte_stream` / `AtomFeed::to_byte_stream` must produce the
/// same byte sequence (modulo chunk boundaries) as `to_xml()`.
#[tokio::test]
async fn to_byte_stream_matches_to_xml() {
    use rama_core::futures::StreamExt as _;

    for path in corpus_files() {
        let xml = load(&path);
        let feed = Feed::parse(&xml).unwrap();
        let blob = match &feed {
            Feed::Rss2(f) => f.to_xml().unwrap(),
            Feed::Atom(f) => f.to_xml().unwrap(),
        };
        let mut streamed = Vec::new();
        let stream: std::pin::Pin<
            Box<
                dyn rama_core::futures::Stream<
                        Item = Result<rama_core::bytes::Bytes, rama_core::error::BoxError>,
                    > + Send,
            >,
        > = match feed {
            Feed::Rss2(f) => Box::pin(f.to_byte_stream()),
            Feed::Atom(f) => Box::pin(f.to_byte_stream()),
        };
        let mut s = stream;
        while let Some(chunk) = s.next().await {
            streamed.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(
            blob,
            streamed,
            "{}: to_byte_stream bytes != to_xml bytes",
            name(&path),
        );
    }
}

/// Multiple `<enclosure>` elements on one item must all survive the round-trip.
#[test]
fn multiple_enclosures_preserved() {
    let xml = load(&corpus_dir().join("edge-multiple-enclosures.rss.xml"));
    let Feed::Rss2(feed) = Feed::parse(&xml).unwrap() else {
        panic!()
    };
    assert_eq!(feed.items[0].enclosures.len(), 2);
    assert_eq!(feed.items[0].enclosures[1].type_, "video/mp4");
}
