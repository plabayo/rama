//! Smoke + round-trip tests against the vendored RSS / Atom feed corpus.
//!
//! Each `.xml` under `tests/rss-corpus/` is a self-contained feed pinning one
//! specific behaviour; the XML comment at the top of each fixture states what
//! it covers. Every fixture must parse, must re-serialize to well-formed XML,
//! and must round-trip through parse → serialize → parse to an equal model.
//! Specific edge cases get their own per-fixture test below.

#![cfg(feature = "rss")]
#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "integration test: panicking on unexpected input is the assertion"
)]

use std::fs;
use std::path::{Path, PathBuf};

use rama_http::protocols::rss::{AtomFeedStream, Feed, FeedStream, Rss2FeedStream};
use rama_net::uri::Uri;

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

/// Happy-path fixtures must preserve every significant text/attribute value
/// through parse -> serialize. Strengthens `corpus_round_trips_losslessly`:
/// model-equality alone hides parser-side drops (both parses miss the field,
/// so the assertion holds even though data was lost). This harvest checks
/// every non-date token in a recognised namespace from the input also
/// appears in the serialized output, catching silent parser drops.
///
/// Edge-case fixtures (filename `edge-*`) are excluded — they deliberately
/// exercise behaviour where some input is expected to drop (e.g. the
/// `<source>` containment regressions).
#[tokio::test]
async fn happy_path_fixtures_preserve_significant_tokens() {
    use ahash::HashSet;
    for path in corpus_files() {
        if name(&path).starts_with("edge-") {
            continue;
        }
        let bytes = load(&path);
        let feed = parse_bytes(bytes.clone()).await;
        let out = serialize(feed).await.unwrap();
        let input_tokens: HashSet<String> =
            harvest_significant_tokens(&bytes).into_iter().collect();
        let output_tokens: HashSet<String> = harvest_significant_tokens(&out).into_iter().collect();
        // Numeric tokens may reformat losslessly (e.g. "42.0" -> "42")
        // because Duration/u64/etc. don't preserve trailing zeros. Treat
        // a missing string token as found if its f64 value matches any
        // output token's f64 value.
        let output_numeric: HashSet<u64> = output_tokens
            .iter()
            .filter_map(|s| s.parse::<f64>().ok())
            .map(f64::to_bits)
            .collect();
        let missing: Vec<&String> = input_tokens
            .difference(&output_tokens)
            .filter(|s| {
                s.parse::<f64>()
                    .ok()
                    .is_none_or(|v| !output_numeric.contains(&v.to_bits()))
            })
            .collect();
        assert!(
            missing.is_empty(),
            "{}: parse -> serialize dropped tokens: {missing:?}",
            name(&path),
        );
    }
}

/// Walk a feed XML and collect every "significant" text + attribute value
/// from elements in a recognised namespace. Filters out tokens that are
/// expected to be reformatted by our writer (RFC 822/3339 date strings),
/// namespace-declaration URIs (xmlns attribute values), and pure whitespace.
fn harvest_significant_tokens(xml: &[u8]) -> Vec<String> {
    use quick_xml::NsReader;
    use quick_xml::events::Event;
    use quick_xml::name::ResolveResult;

    const RECOGNISED_NS: &[&[u8]] = &[
        b"http://www.w3.org/2005/Atom",
        b"http://www.itunes.com/dtds/podcast-1.0.dtd",
        b"https://podcastindex.org/namespace/1.0",
        b"http://purl.org/dc/elements/1.1/",
        b"http://search.yahoo.com/mrss/",
        b"http://purl.org/rss/1.0/modules/content/",
        b"http://podlove.org/simple-chapters",
    ];

    fn is_recognised(rr: &ResolveResult<'_>) -> bool {
        match rr {
            // RSS core has no namespace; the channel/item elements are
            // always significant.
            ResolveResult::Unbound => true,
            ResolveResult::Bound(n) => RECOGNISED_NS.contains(&n.0),
            ResolveResult::Unknown(_) => false,
        }
    }

    // RFC 822 ("Mon, 12 May 2025 09:00:00 GMT") and RFC 3339
    // ("2025-05-12T09:00:00Z") both reformat through our parser; exclude.
    fn looks_like_date(s: &str) -> bool {
        (s.contains(", ") && (s.ends_with("GMT") || s.ends_with("UTC")))
            || (s.len() >= 10
                && s.as_bytes().get(4) == Some(&b'-')
                && s.as_bytes().get(7) == Some(&b'-')
                && s.contains('T'))
    }

    let mut nsr = NsReader::from_reader(xml);
    nsr.config_mut().trim_text(true);
    let mut tokens = Vec::new();
    let mut buf = Vec::new();
    // Stack of "recognised" flags per open element — the text inside
    // inherits the recognition of its enclosing element.
    let mut stack: Vec<bool> = Vec::new();

    loop {
        buf.clear();
        let Ok((rr, ev)) = nsr.read_resolved_event_into(&mut buf) else {
            break;
        };
        fn harvest_attrs(
            e: &quick_xml::events::BytesStart<'_>,
            recognised: bool,
            tokens: &mut Vec<String>,
        ) {
            if !recognised {
                return;
            }
            for attr in e.attributes().filter_map(Result::ok) {
                if attr.key.as_ref().starts_with(b"xmlns") {
                    continue;
                }
                if let Ok(v) = attr.unescape_value() {
                    let v = v.trim();
                    if !v.is_empty() && !looks_like_date(v) {
                        tokens.push(v.to_owned());
                    }
                }
            }
        }
        match ev {
            Event::Start(e) => {
                let recognised = is_recognised(&rr);
                harvest_attrs(&e, recognised, &mut tokens);
                stack.push(recognised);
            }
            Event::Empty(e) => {
                let recognised = is_recognised(&rr);
                harvest_attrs(&e, recognised, &mut tokens);
            }
            Event::Text(e) => {
                if *stack.last().unwrap_or(&true)
                    && let Ok(t) = e.unescape()
                {
                    let t = t.trim();
                    if !t.is_empty() && !looks_like_date(t) {
                        tokens.push(t.to_owned());
                    }
                }
            }
            Event::CData(e) => {
                if *stack.last().unwrap_or(&true)
                    && let Ok(s) = std::str::from_utf8(e.as_ref())
                {
                    let s = s.trim();
                    if !s.is_empty() {
                        tokens.push(s.to_owned());
                    }
                }
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    tokens
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

    assert_eq!(
        entry.id,
        Uri::from_static("https://aggregator.example.com/republished/1")
    );
    assert_eq!(entry.title.value, "Republished Post");
    assert_eq!(entry.authors.len(), 1);
    assert_eq!(entry.authors[0].name, "EntryAuthor");
    // The single <link> on the entry is the entry's own, NOT the source's.
    assert_eq!(entry.links.len(), 1);
    assert_eq!(
        entry.links[0].href,
        Uri::from_static("https://aggregator.example.com/republished/1")
    );
    // No source category leaked.
    assert!(entry.categories.is_empty());
    // Source itself was parsed.
    let src = entry.source.as_ref().expect("source parsed");
    assert_eq!(
        src.id,
        Some(Uri::from_static("https://origin.example.com/feed"))
    );
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

/// RFC 4287 §3.2: an Atom `<author>`/`<contributor>` may only contain
/// `<name>`/`<uri>`/`<email>`. Disallowed children (`<link>`, `<category>`,
/// `<content>`, `<source>`, …) must NOT leak into the enclosing entry/feed.
/// Lenient mode silently ignores them; strict mode rejects.
#[tokio::test]
async fn atom_person_disallowed_children_do_not_leak() {
    let bytes = load(&corpus_dir().join("edge-atom-person-malformed.atom.xml"));

    // Lenient: parses, person-subtree children dropped, entry/feed untouched.
    let Feed::Atom(feed) = parse_bytes(bytes.clone()).await else {
        panic!("expected Atom");
    };

    // Feed level: no link/category leaked from <author> or <contributor>.
    assert!(
        feed.links.is_empty(),
        "no feed-level links must come from <author>/<contributor> subtrees, got {:?}",
        feed.links,
    );
    assert!(
        feed.categories.is_empty(),
        "no feed-level categories must come from <author>/<contributor> subtrees, got {:?}",
        feed.categories,
    );
    assert_eq!(feed.authors[0].name, "Feed Author");
    assert_eq!(
        feed.authors[0].uri,
        Some(Uri::from_static("https://example.com/feed-author"))
    );
    assert_eq!(feed.contributors[0].name, "Feed Contributor");

    // Entry level: only the entry's own link/category/content (the ones
    // outside any person subtree) survive.
    let entry = &feed.entries[0];
    assert_eq!(entry.links.len(), 1, "exactly the entry's own <link>");
    assert_eq!(
        entry.links[0].href,
        Uri::from_static("https://example.com/entry/1")
    );
    assert_eq!(entry.categories.len(), 1);
    assert_eq!(entry.categories[0].term, "legit-entry-category");
    let content = entry.content.as_ref().expect("entry has its own content");
    assert_eq!(content.value.value, "Real entry content.");
    assert!(
        entry.source.is_none(),
        "<source> inside <author> must not become the entry's source",
    );
    // The xhtml-typed <content> inside <author> must have been consumed
    // (depth stays synced) but its captured value discarded — the entry's
    // own text content survives untouched.

    // Strict: rejects on the first disallowed person child. The feed-level
    // <author><link/> trips during header read, so the error surfaces from
    // `new_strict` itself.
    let cursor = std::io::Cursor::new(bytes);
    let reader = tokio::io::BufReader::new(cursor);
    let Err(err) = FeedStream::new_strict(reader).await else {
        panic!("strict mode must reject disallowed person children");
    };
    assert!(
        err.message.contains("Atom person element"),
        "error mentions the person constraint: {err}",
    );
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

/// Nested `<source>` is invalid Atom. A naive parser using a single
/// `in_source` boolean lets the inner `</source>` prematurely finalise the
/// outer one and the outer source's remaining children then leak into the
/// enclosing entry. With proper depth tracking the outer source preserves
/// its full state and only the inner is dropped. Strict mode rejects the
/// nesting outright.
#[tokio::test]
async fn atom_nested_source_does_not_corrupt_entry() {
    let bytes = load(&corpus_dir().join("edge-atom-source-nested.atom.xml"));

    // Lenient: outer source preserved verbatim, inner dropped, entry clean.
    let Feed::Atom(feed) = parse_bytes(bytes.clone()).await else {
        panic!("expected Atom");
    };
    let entry = &feed.entries[0];
    assert_eq!(
        entry.id,
        Uri::from_static("https://aggregator.example.com/republished/1")
    );
    assert_eq!(entry.links.len(), 1, "exactly the entry's own <link>");

    let src = entry.source.as_ref().expect("source parsed");
    assert_eq!(
        src.id,
        Some(Uri::from_static("https://outer.example.com/feed"))
    );
    // The outer source's title must NOT be overwritten by the inner.
    let title = src.title.as_ref().expect("outer source has a title");
    assert_eq!(title.value, "Outer source");
    // The outer <updated>, which appears AFTER the inner </source>, must
    // still land on the outer source — proving the inner </source> did
    // not finalise the outer prematurely.
    assert!(
        src.updated.is_some(),
        "outer source <updated> after inner </source> must be captured",
    );

    // Strict: the nested <source> Start raises an error.
    let cursor = std::io::Cursor::new(bytes);
    let reader = tokio::io::BufReader::new(cursor);
    let stream = FeedStream::new_strict(reader)
        .await
        .expect("feed header parses");
    let collect = stream.collect().await;
    let err = collect.expect_err("strict mode must reject nested <source>");
    assert!(
        err.error.message.contains("nested"),
        "error mentions nested source: {}",
        err.error,
    );
}

/// Atom xhtml text constructs must preserve whitespace between and around
/// inline elements. The outer reader runs with `trim_text(true)` for core
/// fields; the xhtml capture must toggle that off so significant spaces
/// (`Hello <em>world</em> there` vs `Hello<em>world</em>there`) survive.
#[tokio::test]
async fn atom_xhtml_whitespace_preserved() {
    use rama_http::protocols::rss::AtomTextKind;
    let bytes = load(&corpus_dir().join("edge-atom-xhtml-whitespace.atom.xml"));
    let Feed::Atom(feed) = parse_bytes(bytes).await else {
        panic!("expected Atom");
    };
    let content = feed.entries[0].content.as_ref().expect("entry has content");
    assert_eq!(content.value.kind, AtomTextKind::Xhtml);
    // Inter-element whitespace between the inline <em> and the surrounding
    // text must survive verbatim.
    assert!(
        content.value.value.contains("Hello <em>world</em> there"),
        "intra-paragraph whitespace lost: {:?}",
        content.value.value,
    );
    // Whitespace between sibling <p> blocks (a literal space) must also
    // survive.
    assert!(
        content
            .value
            .value
            .contains("<p>Sentence one.</p> <p>Sentence two.</p>"),
        "inter-element whitespace lost: {:?}",
        content.value.value,
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
    assert_eq!(feed.link, Uri::from_static("https://example.com/?a=1&b=2"));
    let item = &feed.items[0];
    assert_eq!(
        item.link.as_ref(),
        Some(&Uri::from_static(
            "https://example.com/post?utm_source=a&utm_medium=b"
        ))
    );
    let enc = &item.enclosures[0];
    assert_eq!(
        enc.url,
        Uri::from_static("https://cdn.example.com/x?token=a&b=2&c=\"3\"")
    );
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

/// `<podcast:locked owner="...">` must preserve the owner attribute, not
/// just the truthy body. Regression for an audit finding.
#[tokio::test]
async fn podcast_locked_owner_attribute_preserved() {
    let bytes = load(&corpus_dir().join("podcast-v2.rss.xml"));
    let Feed::Rss2(feed) = parse_bytes(bytes).await else {
        panic!("expected RSS");
    };
    let pf = feed.extensions.podcast.as_ref().expect("podcast feed ext");
    assert_eq!(pf.locked, Some(false));
    assert_eq!(
        pf.locked_owner.as_deref(),
        Some("alice@example.com"),
        "owner attribute on <podcast:locked> must survive parse",
    );
}

/// `<podcast:remoteItem>` is valid at *both* feed level and item level.
/// Regression for an audit finding where item-level remoteItems were dropped.
#[tokio::test]
async fn podcast_remote_item_at_item_level_preserved() {
    // Inline fixture — small enough to keep next to the test for clarity.
    const BYTES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:podcast="https://podcastindex.org/namespace/1.0">
  <channel>
    <title>Cross-feed value split</title>
    <link>https://example.com</link>
    <description>One item points at another publisher's episode.</description>
    <item>
      <title>Co-hosted episode</title>
      <description>This episode borrows from another feed.</description>
      <podcast:remoteItem feedGuid="urn:uuid:1111-2222"
                          itemGuid="urn:uuid:aaaa-bbbb"
                          feedUrl="https://other.example.com/feed.rss"
                          medium="podcast"/>
    </item>
  </channel>
</rss>"#;
    let feed = parse_bytes(BYTES.to_vec()).await;
    let Feed::Rss2(feed) = feed else {
        panic!("expected RSS")
    };
    let p = feed.items[0].podcast().expect("podcast item ext");
    assert_eq!(p.remote_items.len(), 1, "item-level remoteItem captured");
    let ri = &p.remote_items[0];
    assert_eq!(ri.feed_guid, "urn:uuid:1111-2222");
    assert_eq!(ri.item_guid.as_deref(), Some("urn:uuid:aaaa-bbbb"));
    assert_eq!(
        ri.feed_url.as_deref(),
        Some("https://other.example.com/feed.rss")
    );
    assert_eq!(ri.medium.as_deref(), Some("podcast"));
}

/// Strict RSS mode rejects a channel missing `<description>` (required by
/// the spec alongside `<title>` and `<link>`).
#[tokio::test]
async fn strict_rss_rejects_channel_missing_description() {
    const BYTES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>T</title>
  <link>https://example.com</link>
</channel></rss>"#;
    let cursor = std::io::Cursor::new(BYTES.to_vec());
    let reader = tokio::io::BufReader::new(cursor);
    let Err(err) = FeedStream::new_strict(reader).await else {
        panic!("strict mode must reject a channel without description");
    };
    assert!(
        err.message.contains("description"),
        "error mentions the missing element: {err}"
    );
}

/// Strict RSS mode rejects an item that carries neither `<title>` nor
/// `<description>` (RSS 2.0 spec requires at least one).
#[tokio::test]
async fn strict_rss_rejects_item_without_title_or_description() {
    const BYTES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>T</title>
  <link>https://example.com</link>
  <description>D</description>
  <item>
    <link>https://example.com/x</link>
  </item>
</channel></rss>"#;
    let cursor = std::io::Cursor::new(BYTES.to_vec());
    let reader = tokio::io::BufReader::new(cursor);
    // FeedStream::new_strict succeeds (channel header is OK); the error
    // surfaces when the item finalises.
    let stream = FeedStream::new_strict(reader)
        .await
        .expect("channel header is valid");
    let collect = stream.collect().await;
    let err = collect.expect_err("strict mode must reject an item without title or description");
    assert!(
        err.error.message.contains("title") || err.error.message.contains("description"),
        "error mentions title/description: {}",
        err.error,
    );
}

/// Strict atom mode rejects xhtml content that isn't wrapped in a single
/// XHTML-namespaced `<div>` (RFC 4287 §3.1.1.3).
#[tokio::test]
async fn strict_atom_rejects_xhtml_without_div_wrapper() {
    const BYTES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>urn:uuid:c0ffee</id>
  <title type="text">T</title>
  <updated>2025-05-20T12:00:00Z</updated>
  <entry>
    <id>urn:uuid:1</id>
    <title type="xhtml"><p>missing wrapper</p></title>
    <updated>2025-05-20T12:00:00Z</updated>
  </entry>
</feed>"#;
    let cursor = std::io::Cursor::new(BYTES.to_vec());
    let reader = tokio::io::BufReader::new(cursor);
    let stream = FeedStream::new_strict(reader).await.expect("header valid");
    let err = stream
        .collect()
        .await
        .expect_err("strict mode must reject missing xhtml <div> wrapper");
    assert!(
        err.error.message.contains("xhtml") || err.error.message.contains("XHTML"),
        "error mentions xhtml: {}",
        err.error,
    );
}

/// Nested or re-opened `<item>` / `<entry>` is malformed input. Strict mode
/// rejects (matching the doc: "structural violations surface"); lenient mode
/// silently resets (and traces) — the outer partial is discarded.
#[tokio::test]
async fn strict_rejects_nested_item_and_entry() {
    // RSS: nested <item>.
    const RSS: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>T</title>
  <link>https://example.com</link>
  <description>D</description>
  <item>
    <title>outer</title>
    <item>
      <title>nested</title>
    </item>
  </item>
</channel></rss>"#;
    let cursor = std::io::Cursor::new(RSS.to_vec());
    let reader = tokio::io::BufReader::new(cursor);
    let stream = FeedStream::new_strict(reader).await.expect("header valid");
    let err = stream
        .collect()
        .await
        .expect_err("strict mode must reject nested <item>");
    assert!(
        err.error.message.contains("nested or re-opened <item>"),
        "error mentions nested item: {}",
        err.error,
    );

    // Atom: nested <entry>.
    const ATOM: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>urn:uuid:f</id>
  <title>T</title>
  <updated>2025-05-20T12:00:00Z</updated>
  <entry>
    <id>urn:uuid:e1</id>
    <title>outer</title>
    <updated>2025-05-20T12:00:00Z</updated>
    <entry>
      <id>urn:uuid:e2</id>
      <title>nested</title>
      <updated>2025-05-20T12:00:00Z</updated>
    </entry>
  </entry>
</feed>"#;
    let cursor = std::io::Cursor::new(ATOM.to_vec());
    let reader = tokio::io::BufReader::new(cursor);
    let stream = FeedStream::new_strict(reader).await.expect("header valid");
    let err = stream
        .collect()
        .await
        .expect_err("strict mode must reject nested <entry>");
    assert!(
        err.error.message.contains("nested or re-opened <entry>"),
        "error mentions nested entry: {}",
        err.error,
    );

    // Lenient: both parse (the outer partial is discarded, the inner takes its
    // slot) — no error, the document is consumed end-to-end.
    let _ = parse_bytes(RSS.to_vec()).await;
    let _ = parse_bytes(ATOM.to_vec()).await;
}

/// `FeedItem::content()` returns `None` for Atom out-of-line content
/// (`<content src="..." type="..."/>`) — the body lives at a remote URL,
/// not in the feed.
#[tokio::test]
async fn feed_item_content_returns_none_for_atom_out_of_line() {
    const BYTES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>urn:uuid:1</id>
  <title type="text">T</title>
  <updated>2025-05-20T12:00:00Z</updated>
  <entry>
    <id>urn:uuid:e1</id>
    <title type="text">E</title>
    <updated>2025-05-20T12:00:00Z</updated>
    <content src="https://example.com/body.html" type="text/html"/>
  </entry>
</feed>"#;
    let Feed::Atom(feed) = parse_bytes(BYTES.to_vec()).await else {
        panic!("expected Atom");
    };
    let item = rama_http::protocols::rss::FeedItem::Atom(feed.entries[0].clone());
    assert_eq!(
        item.content(),
        None,
        "out-of-line content must not leak the MIME-type-stuffed body",
    );
}

/// Podlove Simple Chapters: `<psc:chapters>` and inner `<psc:chapter>` markers
/// at item level must parse into PodloveChapters and survive round-trip.
#[tokio::test]
async fn podlove_chapters_preserved() {
    use std::time::Duration;
    let bytes = load(&corpus_dir().join("edge-podlove-chapters.rss.xml"));
    let Feed::Rss2(feed) = parse_bytes(bytes).await else {
        panic!("expected RSS");
    };
    let item = &feed.items[0];
    let ch = item
        .extensions
        .podlove
        .as_deref()
        .expect("psc chapters parsed");
    assert_eq!(ch.version, "1.2");
    assert_eq!(ch.chapters.len(), 4, "all four chapter markers captured");

    assert_eq!(ch.chapters[0].title, "Intro");
    assert_eq!(ch.chapters[0].start, Duration::ZERO);

    assert_eq!(ch.chapters[1].title, "Sponsor");
    assert!(
        (ch.chapters[1].start.as_secs_f64() - 154.5).abs() < 1e-6,
        "00:02:34.500 → 154.5 s, got {:?}",
        ch.chapters[1].start,
    );
    assert_eq!(
        ch.chapters[1].href.as_deref(),
        Some("https://sponsor.example.com"),
    );

    assert_eq!(ch.chapters[2].title, "Main topic");
    assert_eq!(ch.chapters[2].start, Duration::from_secs(5 * 60 + 42));
    assert_eq!(
        ch.chapters[2].image.as_deref(),
        Some("https://example.com/chapter3.png"),
    );

    assert_eq!(ch.chapters[3].title, "Wrap-up");
    assert!(
        (ch.chapters[3].start.as_secs_f64() - 3723.456).abs() < 1e-6,
        "01:02:03.456 → 3723.456 s",
    );
}

/// Apple Podcasts' canonical category shape nests subcategories inside their
/// parent `<itunes:category>`. The parent name lives on the Start event's
/// `text` attribute; a parser that only handles the self-closing form silently
/// drops every top-level category name. Regression for an audit finding.
#[tokio::test]
async fn itunes_nested_categories_parent_text_preserved() {
    let bytes = load(&corpus_dir().join("podcast-itunes.rss.xml"));
    let Feed::Rss2(feed) = parse_bytes(bytes).await else {
        panic!("expected RSS");
    };
    let itunes = feed.extensions.itunes.as_deref().expect("itunes feed ext");
    assert_eq!(
        itunes.categories,
        vec!["Technology".to_owned(), "Software How-To".to_owned()],
        "parent <itunes:category text=...> must be captured alongside its nested subcategory",
    );
}

/// `<itunes:category>` appears in three wire shapes in the wild — all three
/// must flatten to the same `categories: Vec<String>`.
///
/// 1. Self-closing empty (common in flat publisher feeds: BBC, NPR, …).
/// 2. Start + nested empty subcategory + End (Apple canonical).
/// 3. Start + End with no children (rare but valid).
#[tokio::test]
async fn itunes_category_all_three_wire_shapes_flatten() {
    const BYTES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">
  <channel>
    <title>T</title>
    <link>https://example.com</link>
    <description>D</description>
    <itunes:category text="News"/>
    <itunes:category text="Technology">
      <itunes:category text="Software How-To"/>
    </itunes:category>
    <itunes:category text="Education"></itunes:category>
  </channel>
</rss>"#;
    let Feed::Rss2(feed) = parse_bytes(BYTES.to_vec()).await else {
        panic!("expected RSS");
    };
    let itunes = feed.extensions.itunes.as_deref().expect("itunes feed ext");
    assert_eq!(
        itunes.categories,
        vec![
            "News".to_owned(),
            "Technology".to_owned(),
            "Software How-To".to_owned(),
            "Education".to_owned(),
        ],
        "every wire shape of <itunes:category> must contribute its name",
    );
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
    assert_eq!(
        header.id,
        Uri::from_static("urn:uuid:6e95a2c8-9d5e-4f9f-9b6f-21f7d5b1f9aa")
    );
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
        link: Uri::from_static("https://example.com"),
        description: "stream".into(),
        ..Default::default()
    };

    let items = rama_core::futures::stream::iter((0..5).map(|n| {
        Ok::<_, std::convert::Infallible>(
            Rss2Item::new().with_title(format!("Item {n}")).with_link({
                let mut uri = Uri::from_static("https://example.com");
                uri.path_mut().push_segment(n.to_string());
                uri
            }),
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
