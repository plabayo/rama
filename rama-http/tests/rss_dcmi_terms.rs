//! DCMI Metadata Terms resource-relationship coverage for RSS 2.0 and Atom.

#![cfg(feature = "rss")]
#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "integration test: fixed test data and unexpected feed variants are assertions"
)]

use jiff::Timestamp;
use rama_core::futures::{StreamExt as _, stream};
use rama_http::protocols::rss::{
    AtomEntry, AtomFeed, DublinCoreTerms, DublinCoreTermsFeed, Feed, FeedExtensions,
    ItemExtensions, Rss2Channel, Rss2Feed, Rss2Item, Rss2StreamWriter,
};
use rama_net::uri::Uri;

const RELATIONSHIP_TERMS: &[&str] = &[
    "relation",
    "conformsTo",
    "hasFormat",
    "isFormatOf",
    "hasPart",
    "isPartOf",
    "hasVersion",
    "isVersionOf",
    "references",
    "isReferencedBy",
    "replaces",
    "isReplacedBy",
    "requires",
    "isRequiredBy",
    "source",
];

fn uri(value: &str) -> Uri {
    value.parse().expect("valid URI in test data")
}

fn term_uri(base: &str, term: &str) -> Uri {
    uri(&format!("{base}/{term}"))
}

fn complete_item_terms(base: &str) -> DublinCoreTerms {
    DublinCoreTerms {
        relation: vec![
            term_uri(base, "relation?a=1&b=2"),
            term_uri(base, "relation-second"),
        ],
        conforms_to: vec![term_uri(base, "conforms-to")],
        has_format: vec![term_uri(base, "has-format")],
        is_format_of: vec![term_uri(base, "is-format-of")],
        has_part: vec![term_uri(base, "has-part")],
        is_part_of: vec![term_uri(base, "is-part-of")],
        has_version: vec![term_uri(base, "has-version")],
        is_version_of: vec![
            term_uri(base, "is-version-of-first"),
            term_uri(base, "is-version-of-second"),
        ],
        references: vec![term_uri(base, "references")],
        is_referenced_by: vec![term_uri(base, "is-referenced-by")],
        replaces: vec![term_uri(base, "replaces")],
        is_replaced_by: vec![term_uri(base, "is-replaced-by")],
        requires: vec![term_uri(base, "requires")],
        is_required_by: vec![term_uri(base, "is-required-by")],
        source: vec![term_uri(base, "source")],
    }
}

fn complete_feed_terms(base: &str) -> DublinCoreTermsFeed {
    let DublinCoreTerms {
        relation,
        conforms_to,
        has_format,
        is_format_of,
        has_part,
        is_part_of,
        has_version,
        is_version_of,
        references,
        is_referenced_by,
        replaces,
        is_replaced_by,
        requires,
        is_required_by,
        source,
    } = complete_item_terms(base);
    DublinCoreTermsFeed {
        relation,
        conforms_to,
        has_format,
        is_format_of,
        has_part,
        is_part_of,
        has_version,
        is_version_of,
        references,
        is_referenced_by,
        replaces,
        is_replaced_by,
        requires,
        is_required_by,
        source,
    }
}

async fn parse(xml: impl Into<String>) -> Feed {
    Feed::from_body(rama_http::Body::from(xml.into()))
        .await
        .expect("parse feed")
}

async fn parse_rss(xml: impl Into<String>) -> Rss2Feed {
    match parse(xml).await {
        Feed::Rss2(feed) => feed,
        Feed::Atom(_) => panic!("expected RSS 2.0"),
    }
}

async fn parse_atom(xml: impl Into<String>) -> AtomFeed {
    match parse(xml).await {
        Feed::Atom(feed) => feed,
        Feed::Rss2(_) => panic!("expected Atom"),
    }
}

fn assert_complete_wire_family(xml: &str) {
    assert!(
        xml.contains(r#"xmlns:dcterms="http://purl.org/dc/terms/""#),
        "missing DCTERMS namespace: {xml}"
    );
    for local in RELATIONSHIP_TERMS {
        let tag = format!("<dcterms:{local}>");
        assert!(
            xml.matches(&tag).count() >= 2,
            "expected feed- and item-level {tag}: {xml}"
        );
    }
    assert!(
        xml.contains("relation?a=1&amp;b=2"),
        "URI query separators must be XML-escaped: {xml}"
    );
}

#[tokio::test]
async fn rss_fixture_preserves_repeats_and_dc_independence_while_ignoring_invalid_values() {
    let feed = parse_rss(include_str!("rss-corpus/edge-dcmi-relationships.rss.xml")).await;

    let feed_terms = feed.dublin_core_terms().expect("channel DCTERMS");
    assert_eq!(
        feed_terms.has_version,
        [Uri::from_static("https://example.com/feed-v2.xml")]
    );

    let first = &feed.items[0];
    assert_eq!(
        first.dublin_core().and_then(|dc| dc.relation.as_deref()),
        Some("Legacy untyped relation")
    );
    let terms = first.dublin_core_terms().expect("item DCTERMS");
    assert_eq!(
        terms.is_version_of,
        [
            Uri::from_static("https://example.com/episodes/original"),
            Uri::from_static("https://example.com/episodes/earlier-cut"),
        ]
    );
    assert_eq!(
        terms.relation,
        [Uri::from_static(
            "https://example.com/episodes/duplicate?a=1&b=2"
        )]
    );

    assert!(
        feed.items[1].dublin_core_terms().is_none(),
        "unknown and case-mismatched terms must not create an extension"
    );
}

#[tokio::test]
async fn atom_alternate_prefix_parses_at_feed_and_entry_levels() {
    let feed = parse_atom(include_str!("rss-corpus/dcmi-relationships.atom.xml")).await;
    let feed_terms = feed.dublin_core_terms().expect("feed DCTERMS");
    assert_eq!(
        feed_terms.has_version,
        [Uri::from_static("https://example.com/feed-v2.atom")]
    );
    assert_eq!(
        feed_terms.relation,
        [Uri::from_static("https://example.com/feed-related")]
    );

    let terms = feed.entries[0].dublin_core_terms().expect("entry DCTERMS");
    assert_eq!(
        terms.is_version_of,
        [
            Uri::from_static("https://example.com/entries/original"),
            Uri::from_static("https://example.com/entries/earlier-cut"),
        ]
    );
    assert_eq!(
        terms.relation,
        [Uri::from_static(
            "https://example.com/entries/duplicate?a=1&b=2"
        )]
    );
}

#[tokio::test]
async fn rss_complete_relationship_family_round_trips_at_both_levels() {
    let feed = Rss2Feed::builder()
        .title("Relationships")
        .link(Uri::from_static("https://example.com/"))
        .description("Complete DCTERMS relationship family")
        .with_feed_extensions(FeedExtensions {
            dublin_core_terms: Some(Box::new(complete_feed_terms("https://example.com/feed"))),
            ..Default::default()
        })
        .with_item(
            Rss2Item::new()
                .with_title("Entry")
                .with_extensions(ItemExtensions {
                    dublin_core_terms: Some(Box::new(complete_item_terms(
                        "https://example.com/item",
                    ))),
                    ..Default::default()
                }),
        )
        .build();

    let xml =
        String::from_utf8(feed.clone().to_xml().await.expect("serialize RSS")).expect("UTF-8 XML");
    assert_complete_wire_family(&xml);
    assert_eq!(parse_rss(xml).await, feed);
}

#[tokio::test]
async fn atom_complete_relationship_family_round_trips_at_both_levels() {
    let feed = AtomFeed::builder()
        .id(Uri::from_static("https://example.com/feed.atom"))
        .title("Relationships")
        .updated(Timestamp::UNIX_EPOCH)
        .with_feed_extensions(FeedExtensions {
            dublin_core_terms: Some(Box::new(complete_feed_terms("https://example.com/feed"))),
            ..Default::default()
        })
        .with_entry(
            AtomEntry::new(
                Uri::from_static("https://example.com/entry"),
                "Entry",
                Timestamp::UNIX_EPOCH,
            )
            .with_extensions(ItemExtensions {
                dublin_core_terms: Some(Box::new(complete_item_terms("https://example.com/item"))),
                ..Default::default()
            }),
        )
        .build();

    let xml =
        String::from_utf8(feed.clone().to_xml().await.expect("serialize Atom")).expect("UTF-8 XML");
    assert_complete_wire_family(&xml);
    assert_eq!(parse_atom(xml).await, feed);
}

#[test]
fn empty_relationship_models_and_extension_containers_report_presence_correctly() {
    assert!(DublinCoreTerms::default().is_empty());
    assert!(DublinCoreTermsFeed::default().is_empty());
    assert!(ItemExtensions::default().is_empty());
    assert!(FeedExtensions::default().is_empty());

    let item_extensions = ItemExtensions {
        dublin_core_terms: Some(Box::default()),
        ..Default::default()
    };
    let feed_extensions = FeedExtensions {
        dublin_core_terms: Some(Box::default()),
        ..Default::default()
    };
    assert!(
        !item_extensions.is_empty(),
        "an explicitly present extension is not an empty container"
    );
    assert!(
        !feed_extensions.is_empty(),
        "an explicitly present extension is not an empty container"
    );
}

#[tokio::test]
async fn rss_stream_declares_dcterms_before_emitting_relationship_items() {
    let channel = Rss2Channel {
        title: "Relationships".into(),
        link: Uri::from_static("https://example.com/"),
        description: "Streamed".into(),
        ..Default::default()
    };
    let item = Rss2Item::new()
        .with_title("Entry")
        .with_extensions(ItemExtensions {
            dublin_core_terms: Some(Box::new(DublinCoreTerms {
                relation: vec![Uri::from_static("https://example.com/related")],
                ..Default::default()
            })),
            ..Default::default()
        });
    let items = stream::iter([Ok::<_, std::convert::Infallible>(item)]);
    let mut writer = Rss2StreamWriter::new(channel, items);

    let header = writer
        .next()
        .await
        .expect("header chunk")
        .expect("write header");
    let header = std::str::from_utf8(&header).expect("UTF-8 header");
    assert!(
        header.contains(r#"xmlns:dcterms="http://purl.org/dc/terms/""#),
        "namespace must be available before an item is polled: {header}"
    );

    let item = writer
        .next()
        .await
        .expect("item chunk")
        .expect("write item");
    let item = std::str::from_utf8(&item).expect("UTF-8 item");
    assert!(
        item.contains("<dcterms:relation>https://example.com/related</dcterms:relation>"),
        "streamed DCTERMS item missing: {item}"
    );
}
