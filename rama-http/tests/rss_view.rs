//! Cross-format property accessor tests for `Feed` / `FeedStream` /
//! `FeedItem`.
//!
//! The two corpus fixtures `blog-minimal.rss.xml` and `blog-atom.atom.xml`
//! carry deliberately parallel content (both call the feed "Example Blog",
//! both have an item titled "Hello, world" linking to the same URL). The
//! tests below assert that the cross-format accessors reflect that — same
//! method names, same return shape, equal values where the underlying spec
//! allows. Per-spec differences (Atom's required `id`/`updated`, RSS items
//! having no `updated` at all) are asserted as documented divergence.

#![cfg(feature = "rss")]
#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "integration test: panicking on unexpected input is the assertion"
)]

use std::path::PathBuf;

use rama_core::futures::StreamExt as _;
use rama_http::protocols::rss::{Feed, FeedItem, FeedStream};
use rama_net::uri::Uri;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("rss-corpus")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

async fn parse(bytes: Vec<u8>) -> Feed {
    let cursor = std::io::Cursor::new(bytes);
    let reader = tokio::io::BufReader::new(cursor);
    FeedStream::new(reader)
        .await
        .expect("FeedStream::new")
        .collect()
        .await
        .unwrap_or_else(|e| panic!("collect: {}", e.error))
}

/// Feed-level: properties present in both specs should report the same value
/// across the two parallel fixtures.
#[tokio::test]
async fn feed_accessors_agree_on_shared_properties() {
    let rss = parse(fixture("blog-minimal.rss.xml")).await;
    let atom = parse(fixture("blog-atom.atom.xml")).await;

    assert_eq!(rss.title(), "Example Blog");
    assert_eq!(atom.title(), "Example Blog");

    // Both fixtures point at "https://example.com/" as the home page — RSS
    // via <link>, Atom via <link rel="alternate">.
    assert_eq!(rss.link(), Some(&Uri::from_static("https://example.com/")));
    assert_eq!(atom.link(), Some(&Uri::from_static("https://example.com/")));
}

/// Feed-level: spec-divergent fields are reported as the docs promise.
#[tokio::test]
async fn feed_accessors_document_per_spec_divergence() {
    let rss = parse(fixture("blog-minimal.rss.xml")).await;
    let atom = parse(fixture("blog-atom.atom.xml")).await;

    // id: required in Atom, not present in RSS.
    assert_eq!(rss.id(), None);
    assert!(atom.id().is_some(), "Atom id missing");

    // updated: RSS source has no <lastBuildDate>; Atom <updated> is required.
    assert_eq!(rss.updated(), None);
    assert!(atom.updated().is_some(), "Atom updated missing");

    // published: RSS source carries <pubDate>; Atom has no feed-level equivalent.
    assert!(rss.published().is_some(), "RSS pubDate missing");
    assert_eq!(atom.published(), None);

    // language: RSS source carries <language>; Atom (no xml:lang capture yet) None.
    assert_eq!(rss.language(), Some("en-us"));
    assert_eq!(atom.language(), None);

    // self_link: only the Atom fixture declares one.
    assert_eq!(rss.self_link(), None);
    assert_eq!(
        atom.self_link(),
        Some(&Uri::from_static("https://example.com/feed.atom")),
        "Atom rel=self should be picked up"
    );

    // icon / logo: only Atom carries them.
    assert_eq!(rss.icon_url(), None);
    assert_eq!(
        atom.icon_url(),
        Some(&Uri::from_static("https://example.com/icon.png"))
    );
    assert_eq!(rss.image_url(), None);
    assert_eq!(
        atom.image_url(),
        Some(&Uri::from_static("https://example.com/logo.png"))
    );
}

/// Item-level: shared properties should agree across the two parallel
/// fixtures when iterated through `FeedStream` as a stream of `FeedItem`s.
#[tokio::test]
async fn feed_item_accessors_via_feedstream_agree_across_formats() {
    for fname in ["blog-minimal.rss.xml", "blog-atom.atom.xml"] {
        let cursor = std::io::Cursor::new(fixture(fname));
        let reader = tokio::io::BufReader::new(cursor);
        let mut stream = FeedStream::new(reader).await.expect("FeedStream::new");

        // FeedStream's own accessors reflect the header that was parsed at
        // construction.
        assert_eq!(stream.title(), "Example Blog", "{fname}");

        let mut items = Vec::new();
        while let Some(item) = stream.next().await {
            items.push(item.expect("item ok"));
        }
        assert_eq!(items.len(), 1, "{fname}: expected exactly one item");

        let item = &items[0];
        assert_eq!(item.title(), Some("Hello, world"), "{fname}");
        assert_eq!(
            item.link(),
            Some(&Uri::from_static("https://example.com/posts/hello")),
            "{fname}",
        );
        assert!(item.id().is_some(), "{fname}: both fixtures carry an id");
        assert!(
            item.published().is_some(),
            "{fname}: both fixtures carry a published timestamp",
        );
    }
}

/// The `content()` fallback: an RSS item without `<content:encoded>` should
/// surface its `<description>` from `content()`.
#[tokio::test]
async fn feed_item_rss_content_falls_back_to_description() {
    let Feed::Rss2(feed) = parse(fixture("blog-minimal.rss.xml")).await else {
        panic!("expected RSS");
    };
    let fi: FeedItem = feed.items.into_iter().next().expect("one item").into();
    // RSS fixture has <description>A first post.</description>, no
    // <content:encoded>.
    assert_eq!(fi.summary(), Some("A first post."));
    assert_eq!(
        fi.content(),
        Some("A first post."),
        "content() should fall back to description when no content:encoded",
    );
}

/// Atom items keep summary and content distinct.
#[tokio::test]
async fn feed_item_atom_keeps_summary_and_content_distinct() {
    let Feed::Atom(feed) = parse(fixture("blog-atom.atom.xml")).await else {
        panic!("expected Atom");
    };
    let fi: FeedItem = feed.entries.into_iter().next().expect("one entry").into();
    assert_eq!(fi.summary(), Some("A first post."));
    assert_eq!(
        fi.content(),
        Some("<p>Hello <strong>world</strong>.</p>"),
        "Atom content should be returned distinct from summary",
    );
}

// ---------------------------------------------------------------------------
// Regression: whitespace adjacent to entities (quick-xml 0.40 migration).
//
// 0.40 splits a text run around every entity / character reference into
// separate `Text` and `GeneralRef` events. The readers must reassemble the
// value with interior whitespace intact and trim only the field's outer ends —
// otherwise a space next to an entity is lost: a `type="html"` body drops the
// space before a tag, and `Tom &amp; Jerry` collapses to `Tom&Jerry`. These
// pin the behavior across formats, content types, and reference kinds.
// ---------------------------------------------------------------------------

async fn parse_str(xml: &str) -> Feed {
    parse(xml.as_bytes().to_vec()).await
}

#[tokio::test]
async fn atom_preserves_whitespace_around_entities() {
    let Feed::Atom(feed) = parse_str(
        r#"<feed xmlns="http://www.w3.org/2005/Atom">
  <id>urn:test</id><title>t</title><updated>2025-01-01T00:00:00Z</updated>
  <entry>
    <id>urn:e1</id>
    <title type="text">Tom &amp; Jerry</title>
    <updated>2025-01-01T00:00:00Z</updated>
    <content type="html">&lt;p&gt;a &lt;b&gt;c&lt;/b&gt; d&lt;/p&gt;</content>
  </entry>
</feed>"#,
    )
    .await
    else {
        panic!("expected Atom");
    };
    let fi: FeedItem = feed.entries.into_iter().next().expect("entry").into();
    assert_eq!(
        fi.title(),
        Some("Tom & Jerry"),
        "spaces around `&amp;` must survive entity splitting",
    );
    assert_eq!(
        fi.content(),
        Some("<p>a <b>c</b> d</p>"),
        "html body must keep whitespace interior to the value (incl. around tags)",
    );
}

#[tokio::test]
async fn atom_preserves_numeric_char_ref_midword() {
    let Feed::Atom(feed) = parse_str(
        r#"<feed xmlns="http://www.w3.org/2005/Atom">
  <id>urn:test</id><title>t</title><updated>2025-01-01T00:00:00Z</updated>
  <entry>
    <id>urn:e1</id>
    <title type="text">caf&#233; au lait</title>
    <updated>2025-01-01T00:00:00Z</updated>
  </entry>
</feed>"#,
    )
    .await
    else {
        panic!("expected Atom");
    };
    let fi: FeedItem = feed.entries.into_iter().next().expect("entry").into();
    assert_eq!(
        fi.title(),
        Some("café au lait"),
        "a numeric char ref must not split the surrounding word",
    );
}

#[tokio::test]
async fn rss2_trims_outer_whitespace_but_keeps_interior_entity_spacing() {
    let Feed::Rss2(feed) = parse_str(
        r#"<rss version="2.0"><channel>
  <title>t</title><link>https://e.com/</link><description>d</description>
  <item>
    <title>Tom &amp; Jerry</title>
    <description>  before &amp; after  </description>
  </item>
</channel></rss>"#,
    )
    .await
    else {
        panic!("expected RSS2");
    };
    let fi: FeedItem = feed.items.into_iter().next().expect("item").into();
    assert_eq!(fi.title(), Some("Tom & Jerry"));
    assert_eq!(
        fi.summary(),
        Some("before & after"),
        "outer whitespace trimmed; interior spacing around `&amp;` preserved",
    );
}

/// `FeedItem::enclosures()` should normalise across RSS `<enclosure>` and
/// Atom `<link rel="enclosure">`.
#[tokio::test]
async fn feed_item_enclosures_normalised_across_formats() {
    // The RSS multi-enclosure fixture has both audio and video enclosures.
    let Feed::Rss2(rss) = parse(fixture("edge-multiple-enclosures.rss.xml")).await else {
        panic!()
    };
    let item: FeedItem = rss.items.into_iter().next().expect("one item").into();
    let encs: Vec<_> = item.enclosures().collect();
    assert!(
        !encs.is_empty(),
        "fixture should declare at least one enclosure",
    );
    for enc in &encs {
        // RSS encodes length + type as required attributes.
        assert!(enc.length.is_some(), "RSS enclosure length should be Some");
        assert!(enc.mime.is_some(), "RSS enclosure mime should be Some");
    }
}
