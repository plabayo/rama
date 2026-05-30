//! Unit tests for the RSS 2.0 / Atom 1.0 parsers and the shared helpers.

use super::super::atom::{
    AtomContent, AtomEntry, AtomFeed, AtomGenerator, AtomLink, AtomPerson, AtomSource, AtomText,
};
use super::super::feed::Feed;
use super::super::rss2::{Rss2Category, Rss2Feed, Rss2Item, Rss2Source};
use super::*;

const SAMPLE_RSS2: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>My Blog</title>
    <link>https://example.com</link>
    <description>A sample blog</description>
    <language>en</language>
    <item>
      <title>First Post</title>
      <link>https://example.com/1</link>
      <description>Hello world</description>
      <guid isPermaLink="true">https://example.com/1</guid>
    </item>
  </channel>
</rss>"#;

const SAMPLE_ATOM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>https://example.com/feed</id>
  <title type="text">My Blog</title>
  <updated>2024-01-15T00:00:00Z</updated>
  <author><name>Alice</name></author>
  <entry>
    <id>https://example.com/1</id>
    <title type="text">First Post</title>
    <updated>2024-01-15T00:00:00Z</updated>
    <summary>Hello world</summary>
  </entry>
</feed>"#;

#[test]
fn detects_and_parses_rss2() {
    let feed = parse_feed(SAMPLE_RSS2, false).unwrap();
    let Feed::Rss2(rss) = feed else {
        panic!("expected RSS 2.0")
    };
    assert_eq!(rss.title, "My Blog");
    assert_eq!(rss.link, "https://example.com");
    assert_eq!(rss.items.len(), 1);
    assert_eq!(rss.items[0].title.as_deref(), Some("First Post"));
}

#[test]
fn detects_and_parses_atom() {
    let feed = parse_feed(SAMPLE_ATOM, false).unwrap();
    let Feed::Atom(atom) = feed else {
        panic!("expected Atom")
    };
    assert_eq!(atom.id, "https://example.com/feed");
    assert_eq!(atom.entries.len(), 1);
    assert_eq!(atom.entries[0].id, "https://example.com/1");
}

#[test]
fn strict_errors_on_missing_rss2_required_fields() {
    parse_feed(
        "<rss><channel><description>x</description></channel></rss>",
        true,
    )
    .unwrap_err();
}

#[test]
fn parse_does_not_panic_on_utf8_boundary() {
    // Regression: format detection used to byte-slice at index 2048/1024,
    // panicking when that index fell inside a multi-byte UTF-8 char.
    let mut s = String::from("<?xml version=\"1.0\"?>\n");
    while s.len() < 2047 {
        s.push('a');
    }
    s.push('€'); // 3 bytes spanning index 2047..2050
    while s.len() < 4096 {
        s.push('b');
    }
    _ = parse_feed(&s, false);
    _ = parse_feed(&s, true);
}

#[test]
fn rss2_parses_channel_image() {
    let xml = r#"<rss version="2.0"><channel>
            <title>T</title><link>https://e.com</link><description>D</description>
            <image>
                <url>https://e.com/i.png</url>
                <title>Logo</title>
                <link>https://e.com</link>
                <width>88</width>
            </image>
        </channel></rss>"#;
    let Feed::Rss2(rss) = parse_feed(xml, false).unwrap() else {
        panic!("expected RSS 2.0")
    };
    let img = rss.image.expect("channel image should be parsed");
    assert_eq!(img.url, "https://e.com/i.png");
    assert_eq!(img.title, "Logo");
    assert_eq!(img.width, Some(88));
    // the image's inner <title>/<link> must not clobber the channel's
    assert_eq!(rss.title, "T");
}

#[test]
fn atom_strict_requires_id_title_updated() {
    // missing <updated>
    parse_feed(
        r#"<feed xmlns="http://www.w3.org/2005/Atom"><id>urn:f</id><title>T</title></feed>"#,
        true,
    )
    .unwrap_err();
    // missing <title>
    parse_feed(
            r#"<feed xmlns="http://www.w3.org/2005/Atom"><id>urn:f</id><updated>2024-01-01T00:00:00Z</updated></feed>"#,
            true,
        )
        .unwrap_err();
    // all present -> ok
    parse_feed(
            r#"<feed xmlns="http://www.w3.org/2005/Atom"><id>urn:f</id><title>T</title><updated>2024-01-01T00:00:00Z</updated></feed>"#,
            true,
        )
        .unwrap();
}

#[test]
fn atom_parses_entry_category_and_typed_summary() {
    let xml = r#"<feed xmlns="http://www.w3.org/2005/Atom">
            <id>urn:f</id><title>T</title><updated>2024-01-01T00:00:00Z</updated>
            <entry>
                <id>urn:1</id><title>E</title><updated>2024-01-01T00:00:00Z</updated>
                <category term="rust" label="Rust"/>
                <summary type="html">&lt;b&gt;hi&lt;/b&gt;</summary>
            </entry>
        </feed>"#;
    let Feed::Atom(atom) = parse_feed(xml, false).unwrap() else {
        panic!("expected Atom")
    };
    let entry = &atom.entries[0];
    assert_eq!(entry.categories.len(), 1, "entry category should be parsed");
    assert_eq!(entry.categories[0].term, "rust");
    assert!(matches!(entry.summary, Some(AtomText::Html(_))));
}

#[test]
fn rss2_extensions_round_trip() {
    use super::super::feed_ext::{
        Content, DublinCore, DublinCoreFeed, FeedExtensions, ITunes, ITunesFeed, ItemExtensions,
        MediaContent, MediaRss, MediaThumbnail, Podcast, PodcastEpisode, PodcastFeed,
        PodcastFunding, PodcastPerson, PodcastSeason, PodcastSoundbite, PodcastTranscript,
    };

    let feed = Rss2Feed::builder()
        .title("Pod")
        .link("https://e.com")
        .description("D")
        .feed_extensions(FeedExtensions {
            itunes: Some(ITunesFeed {
                author: Some("Host".into()),
                owner_name: Some("Owner".into()),
                owner_email: Some("o@e.com".into()),
                new_feed_url: Some("https://e.com/new".into()),
                block: Some(true),
                complete: Some(false),
                categories: vec!["Tech".into()],
                ..Default::default()
            }),
            podcast: Some(PodcastFeed {
                guid: Some("g".into()),
                locked: Some(true),
                medium: Some("podcast".into()),
                fundings: vec![PodcastFunding {
                    url: "https://fund".into(),
                    title: Some("Support".into()),
                }],
                ..Default::default()
            }),
            dublin_core: Some(DublinCoreFeed {
                creator: Some("DC".into()),
                ..Default::default()
            }),
        })
        .item(
            Rss2Item::new()
                .with_title("E1")
                .with_extensions(ItemExtensions {
                    itunes: Some(ITunes {
                        duration: Some("10:00".into()),
                        episode: Some(1),
                        season: Some(2),
                        keywords: Some("k".into()),
                        block: Some(true),
                        ..Default::default()
                    }),
                    podcast: Some(Podcast {
                        persons: vec![PodcastPerson {
                            name: "Jane".into(),
                            role: Some("host".into()),
                            group: None,
                            img: None,
                            href: None,
                        }],
                        season: Some(PodcastSeason {
                            number: 2,
                            name: Some("S2".into()),
                        }),
                        episode: Some(PodcastEpisode {
                            number: 1.0,
                            display: None,
                        }),
                        transcripts: vec![PodcastTranscript {
                            url: "https://t".into(),
                            type_: "text/vtt".into(),
                            language: Some("en".into()),
                            rel: None,
                        }],
                        soundbites: vec![PodcastSoundbite {
                            start_time: 1.0,
                            duration: 5.0,
                            title: Some("clip".into()),
                        }],
                        ..Default::default()
                    }),
                    dublin_core: Some(DublinCore {
                        creator: Some("Writer".into()),
                        ..Default::default()
                    }),
                    media: Some(MediaRss {
                        contents: vec![MediaContent {
                            url: Some("https://m.mp3".into()),
                            type_: Some("audio/mpeg".into()),
                            title: Some("MT".into()),
                            ..Default::default()
                        }],
                        thumbnail: Some(MediaThumbnail {
                            url: "https://th".into(),
                            width: Some(10),
                            height: Some(20),
                        }),
                        keywords: Some("mk".into()),
                        ..Default::default()
                    }),
                    content: Some(Content {
                        encoded: Some("<p>x</p>".into()),
                    }),
                }),
        )
        .build();

    let xml = feed.to_string();
    let Feed::Rss2(got) = parse_feed(&xml, false).unwrap() else {
        panic!("expected RSS 2.0")
    };

    let it = got.extensions.itunes.as_ref().expect("feed itunes");
    assert_eq!(it.owner_name.as_deref(), Some("Owner"));
    assert_eq!(it.owner_email.as_deref(), Some("o@e.com"));
    assert_eq!(it.new_feed_url.as_deref(), Some("https://e.com/new"));
    assert_eq!(it.block, Some(true));
    assert_eq!(it.complete, Some(false));

    let pf = got.extensions.podcast.as_ref().expect("feed podcast");
    assert_eq!(pf.guid.as_deref(), Some("g"));
    assert_eq!(pf.locked, Some(true));
    assert_eq!(pf.fundings.len(), 1);
    assert_eq!(pf.fundings[0].title.as_deref(), Some("Support"));

    assert_eq!(
        got.extensions
            .dublin_core
            .as_ref()
            .unwrap()
            .creator
            .as_deref(),
        Some("DC")
    );

    let item = &got.items[0];
    let iit = item.itunes().expect("item itunes");
    assert_eq!(iit.episode, Some(1));
    assert_eq!(iit.season, Some(2));
    assert_eq!(iit.keywords.as_deref(), Some("k"));
    assert_eq!(iit.block, Some(true));

    let pod = item.podcast().expect("item podcast");
    assert_eq!(pod.persons.len(), 1);
    assert_eq!(pod.persons[0].name, "Jane");
    assert_eq!(pod.persons[0].role.as_deref(), Some("host"));
    assert_eq!(pod.season.as_ref().unwrap().number, 2);
    assert!((pod.episode.as_ref().unwrap().number - 1.0).abs() < f64::EPSILON);
    assert_eq!(pod.transcripts.len(), 1);
    assert_eq!(pod.soundbites.len(), 1);
    assert_eq!(pod.soundbites[0].title.as_deref(), Some("clip"));

    assert_eq!(
        item.dublin_core().unwrap().creator.as_deref(),
        Some("Writer")
    );

    let media = item.media().expect("item media");
    assert_eq!(media.contents.len(), 1);
    assert_eq!(media.contents[0].url.as_deref(), Some("https://m.mp3"));
    assert_eq!(media.contents[0].title.as_deref(), Some("MT"));
    assert_eq!(media.thumbnail.as_ref().unwrap().url, "https://th");
    assert_eq!(media.keywords.as_deref(), Some("mk"));

    assert_eq!(item.content().unwrap().encoded.as_deref(), Some("<p>x</p>"));
}

#[test]
fn rss2_category_domain_round_trips() {
    let feed = Rss2Feed::builder()
        .title("T")
        .link("https://e.com")
        .description("D")
        .category(Rss2Category::new("Tech").with_domain("https://taxonomy"))
        .item(
            Rss2Item::new()
                .with_title("I")
                .with_category(Rss2Category::new("Sub").with_domain("https://d2")),
        )
        .build();
    let xml = feed.to_string();
    let Feed::Rss2(got) = parse_feed(&xml, false).unwrap() else {
        panic!("expected RSS 2.0")
    };
    assert_eq!(got.categories.len(), 1);
    assert_eq!(got.categories[0].name, "Tech");
    assert_eq!(
        got.categories[0].domain.as_deref(),
        Some("https://taxonomy")
    );
    assert_eq!(got.items[0].categories[0].name, "Sub");
    assert_eq!(
        got.items[0].categories[0].domain.as_deref(),
        Some("https://d2")
    );
}

#[test]
fn atom_extensions_round_trip() {
    use super::super::feed_ext::{
        DublinCore, DublinCoreFeed, FeedExtensions, ITunes, ITunesFeed, ItemExtensions,
        MediaContent, MediaRss, Podcast, PodcastFeed, PodcastPerson,
    };

    let ts = jiff::Timestamp::UNIX_EPOCH;
    let feed = AtomFeed::builder()
        .id("urn:f")
        .title("F")
        .updated(ts)
        .feed_extensions(FeedExtensions {
            itunes: Some(ITunesFeed {
                author: Some("Host".into()),
                owner_name: Some("O".into()),
                categories: vec!["Tech".into()],
                explicit: Some(true),
                ..Default::default()
            }),
            podcast: Some(PodcastFeed {
                guid: Some("g".into()),
                locked: Some(true),
                persons: vec![PodcastPerson {
                    name: "Jane".into(),
                    role: Some("host".into()),
                    group: None,
                    img: None,
                    href: None,
                }],
                ..Default::default()
            }),
            dublin_core: Some(DublinCoreFeed {
                creator: Some("DC".into()),
                ..Default::default()
            }),
        })
        .entry(
            AtomEntry::new("urn:1", "E", ts).with_extensions(ItemExtensions {
                itunes: Some(ITunes {
                    duration: Some("9:00".into()),
                    episode: Some(3),
                    ..Default::default()
                }),
                podcast: Some(Podcast {
                    persons: vec![PodcastPerson {
                        name: "Bob".into(),
                        role: Some("guest".into()),
                        group: None,
                        img: None,
                        href: None,
                    }],
                    ..Default::default()
                }),
                dublin_core: Some(DublinCore {
                    creator: Some("W".into()),
                    ..Default::default()
                }),
                media: Some(MediaRss {
                    contents: vec![MediaContent {
                        url: Some("https://m".into()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }),
        )
        .build();

    let xml = feed.to_string();
    let Feed::Atom(got) = parse_feed(&xml, false).unwrap() else {
        panic!("expected Atom")
    };

    let fit = got.extensions.itunes.as_ref().expect("feed itunes");
    assert_eq!(fit.author.as_deref(), Some("Host"));
    assert_eq!(fit.owner_name.as_deref(), Some("O"));
    assert_eq!(fit.explicit, Some(true));
    let fp = got.extensions.podcast.as_ref().expect("feed podcast");
    assert_eq!(fp.guid.as_deref(), Some("g"));
    assert_eq!(fp.locked, Some(true));
    assert_eq!(fp.persons.len(), 1);
    assert_eq!(fp.persons[0].name, "Jane");
    assert_eq!(
        got.extensions
            .dublin_core
            .as_ref()
            .unwrap()
            .creator
            .as_deref(),
        Some("DC")
    );

    let entry = &got.entries[0];
    assert_eq!(entry.itunes().expect("entry itunes").episode, Some(3));
    assert_eq!(
        entry.podcast().expect("entry podcast").persons[0].name,
        "Bob"
    );
    assert_eq!(entry.dublin_core().unwrap().creator.as_deref(), Some("W"));
    assert_eq!(
        entry.media().unwrap().contents[0].url.as_deref(),
        Some("https://m")
    );
}

#[test]
fn atom_full_fields_round_trip() {
    let ts = jiff::Timestamp::UNIX_EPOCH;
    let mut entry = AtomEntry::new("urn:e1", AtomText::text("Entry Title"), ts);
    entry
        .contributors
        .push(AtomPerson::new("Carol").with_email("carol@example.com"));
    entry.rights = Some(AtomText::text("CC-BY"));
    entry.source = Some(AtomSource {
        id: Some("urn:src".into()),
        title: Some(AtomText::text("Origin")),
        updated: Some(ts),
    });
    entry.links.push(AtomLink {
        href: "https://e.com/x".into(),
        rel: Some("related".into()),
        type_: Some("text/html".into()),
        hreflang: Some("en".into()),
        title: Some("X".into()),
        length: Some(7),
    });
    entry.content = Some(AtomContent::out_of_line(
        "https://cdn/x.bin",
        "application/octet-stream",
    ));

    let feed = AtomFeed::builder()
        .id("urn:f")
        .title("Feed")
        .updated(ts)
        .generator(AtomGenerator {
            value: "rama".into(),
            uri: Some("https://r".into()),
            version: Some("1".into()),
        })
        .icon("https://e.com/icon.png")
        .contributor(AtomPerson::new("Dave"))
        .rights(AtomText::text("Public"))
        .entry(entry)
        .build();

    let xml = feed.to_string();
    let Feed::Atom(got) = parse_feed(&xml, false).unwrap() else {
        panic!("expected Atom")
    };

    let g = got.generator.expect("generator");
    assert_eq!(g.value, "rama");
    assert_eq!(g.uri.as_deref(), Some("https://r"));
    assert_eq!(g.version.as_deref(), Some("1"));
    assert_eq!(got.icon.as_deref(), Some("https://e.com/icon.png"));
    assert_eq!(got.contributors.len(), 1);
    assert_eq!(got.contributors[0].name, "Dave");
    assert!(got.rights.is_some());

    let e = &got.entries[0];
    // critically: <source> children must NOT overwrite the entry's own id/title/updated
    assert_eq!(e.id, "urn:e1");
    assert_eq!(e.title, AtomText::text("Entry Title"));
    assert_eq!(e.updated, ts);
    assert_eq!(e.contributors.len(), 1);
    assert_eq!(e.contributors[0].name, "Carol");
    assert_eq!(
        e.contributors[0].email.as_deref(),
        Some("carol@example.com")
    );
    assert!(e.rights.is_some());
    let src = e.source.as_ref().expect("entry source");
    assert_eq!(src.id.as_deref(), Some("urn:src"));
    assert_eq!(src.title.as_ref().map(AtomText::value), Some("Origin"));
    assert_eq!(src.updated, Some(ts));
    let link = e
        .links
        .iter()
        .find(|l| l.hreflang.is_some())
        .expect("link with hreflang");
    assert_eq!(link.hreflang.as_deref(), Some("en"));
    assert_eq!(link.title.as_deref(), Some("X"));
    assert_eq!(link.length, Some(7));
    let content = e.content.as_ref().expect("content");
    assert_eq!(content.src.as_deref(), Some("https://cdn/x.bin"));
    assert_eq!(content.value.value(), "application/octet-stream");
}

#[test]
fn rss2_item_source_round_trips() {
    let feed = Rss2Feed::builder()
        .title("T")
        .link("https://e.com")
        .description("D")
        .item(Rss2Item::new().with_title("I").with_source(Rss2Source {
            title: "Origin".into(),
            url: "https://origin".into(),
        }))
        .build();
    let xml = feed.to_string();
    let Feed::Rss2(got) = parse_feed(&xml, false).unwrap() else {
        panic!("expected RSS 2.0")
    };
    let src = got.items[0].source.as_ref().expect("item source");
    assert_eq!(src.title, "Origin");
    assert_eq!(src.url, "https://origin");
}

#[test]
fn lenient_rejects_non_feed() {
    parse_feed("<html><body>not a feed</body></html>", false).unwrap_err();
    parse_feed("just some text, definitely not xml", false).unwrap_err();
    // a real feed still parses fine in lenient mode
    parse_feed(
            r#"<rss version="2.0"><channel><title>T</title><link>l</link><description>d</description></channel></rss>"#,
            false,
        )
        .unwrap();
}

#[test]
fn rss2_recognises_arbitrary_extension_prefix() {
    // Bind the Podcasting 2.0 namespace to a non-standard prefix and verify
    // the parser resolves by namespace URI rather than literal prefix.
    let xml = r#"<?xml version="1.0"?>
<rss version="2.0" xmlns:pod="https://podcastindex.org/namespace/1.0">
  <channel>
    <title>T</title><link>https://e.com</link><description>D</description>
    <item>
      <title>E</title>
      <pod:person role="host">Jane</pod:person>
    </item>
  </channel>
</rss>"#;
    let Feed::Rss2(feed) = parse_feed(xml, false).unwrap() else {
        panic!("expected RSS 2.0")
    };
    let podcast = feed.items[0]
        .podcast()
        .expect("podcast extension parsed via non-standard prefix");
    assert_eq!(podcast.persons.len(), 1);
    assert_eq!(podcast.persons[0].name, "Jane");
    assert_eq!(podcast.persons[0].role.as_deref(), Some("host"));
}

#[test]
fn atom_parses_with_prefixed_root() {
    // Atom feed with a non-default prefix for the Atom namespace itself.
    let xml = r#"<?xml version="1.0"?>
<a:feed xmlns:a="http://www.w3.org/2005/Atom">
  <a:id>urn:f</a:id>
  <a:title>T</a:title>
  <a:updated>2024-01-01T00:00:00Z</a:updated>
  <a:entry>
    <a:id>urn:1</a:id>
    <a:title>E</a:title>
    <a:updated>2024-01-01T00:00:00Z</a:updated>
    <a:summary>hi</a:summary>
  </a:entry>
</a:feed>"#;
    let Feed::Atom(feed) = parse_feed(xml, false).unwrap() else {
        panic!("expected Atom")
    };
    assert_eq!(feed.id, "urn:f");
    assert_eq!(feed.entries.len(), 1);
    assert_eq!(feed.entries[0].id, "urn:1");
    match &feed.entries[0].summary {
        Some(AtomText::Text(s)) => assert_eq!(s, "hi"),
        other => panic!("unexpected summary: {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Regression tests for the audit findings
// ---------------------------------------------------------------------

#[test]
fn rss2_attr_unescape_round_trips() {
    // URLs containing `&` are the dominant real-world case the
    // attr_value-without-unescape bug corrupted.
    use super::super::rss2::Rss2Enclosure;
    let feed = Rss2Feed::builder()
        .title("T")
        .link("https://e.com")
        .description("D")
        .item(
            Rss2Item::new()
                .with_title("I")
                .with_enclosure(Rss2Enclosure::new(
                    "https://e.com/x?a=1&b=2",
                    1,
                    "audio/mpeg",
                )),
        )
        .build();
    let Feed::Rss2(got) = parse_feed(&feed.to_string(), false).unwrap() else {
        panic!("expected RSS")
    };
    assert_eq!(
        got.items[0].enclosures[0].url, "https://e.com/x?a=1&b=2",
        "& in url should be unescaped on parse"
    );
}

#[test]
fn rss2_content_encoded_with_cdata_terminator_round_trips() {
    use super::super::feed_ext::{Content, ItemExtensions};
    let payload = "before ]]> after <script>".to_owned();
    let feed = Rss2Feed::builder()
        .title("T")
        .link("https://e.com")
        .description("D")
        .item(
            Rss2Item::new()
                .with_title("I")
                .with_extensions(ItemExtensions {
                    content: Some(Content {
                        encoded: Some(payload.clone()),
                    }),
                    ..Default::default()
                }),
        )
        .build();
    let wire = feed.to_string();
    let Feed::Rss2(got) = parse_feed(&wire, false).unwrap() else {
        panic!("expected RSS")
    };
    assert_eq!(
        got.items[0].content().unwrap().encoded.as_deref(),
        Some(payload.as_str()),
        "`]]>` inside content:encoded must round-trip exactly"
    );
}

#[test]
fn rss2_multiple_enclosures_round_trip() {
    use super::super::rss2::Rss2Enclosure;
    let feed = Rss2Feed::builder()
        .title("T")
        .link("https://e.com")
        .description("D")
        .item(
            Rss2Item::new()
                .with_title("I")
                .with_enclosure(Rss2Enclosure::new("https://a.mp3", 1, "audio/mpeg"))
                .with_enclosure(Rss2Enclosure::new("https://b.aac", 2, "audio/aac")),
        )
        .build();
    let Feed::Rss2(got) = parse_feed(&feed.to_string(), false).unwrap() else {
        panic!()
    };
    assert_eq!(got.items[0].enclosures.len(), 2);
    assert_eq!(got.items[0].enclosures[1].url, "https://b.aac");
}

#[test]
fn rss2_atom_self_link_round_trips() {
    use super::super::atom::AtomLink;
    let feed = Rss2Feed::builder()
        .title("T")
        .link("https://e.com")
        .description("D")
        .atom_link(AtomLink::self_link("https://e.com/feed.rss"))
        .build();
    let wire = feed.to_string();
    assert!(wire.contains(r#"xmlns:atom="http://www.w3.org/2005/Atom""#));
    let Feed::Rss2(got) = parse_feed(&wire, false).unwrap() else {
        panic!()
    };
    assert_eq!(got.atom_links.len(), 1);
    assert_eq!(got.atom_links[0].href, "https://e.com/feed.rss");
    assert_eq!(got.atom_links[0].rel.as_deref(), Some("self"));
}

#[test]
fn rss2_lenient_preserves_text_around_bad_entity() {
    let xml = r#"<rss version="2.0"><channel>
            <title>T</title><link>l</link>
            <description>before&junk;after</description>
        </channel></rss>"#;
    let Feed::Rss2(f) = parse_feed(xml, false).unwrap() else {
        panic!()
    };
    let d = &f.description;
    assert!(
        d.contains("before") && d.contains("after"),
        "lenient must keep surrounding text around an unknown entity: {d:?}"
    );
}

#[test]
fn lenient_rejects_truncated_input() {
    let xml = "<rss version=\"2.0\"><channel><title>Real</title>";
    parse_feed(xml, false).unwrap_err();
}

#[test]
fn rss2_nested_item_preserves_outer() {
    let xml = r#"<rss version="2.0"><channel>
            <title>T</title><link>l</link><description>D</description>
            <item><title>Outer</title>
                <item><title>Inner</title></item>
            </item>
        </channel></rss>"#;
    let Feed::Rss2(f) = parse_feed(xml, false).unwrap() else {
        panic!()
    };
    let titles: Vec<_> = f.items.iter().filter_map(|i| i.title.clone()).collect();
    assert!(titles.contains(&"Outer".to_owned()), "{titles:?}");
    assert!(titles.contains(&"Inner".to_owned()), "{titles:?}");
}

#[test]
fn atom_source_children_do_not_leak_into_entry() {
    let xml = r#"<feed xmlns="http://www.w3.org/2005/Atom">
            <id>urn:f</id><title>T</title><updated>2024-01-01T00:00:00Z</updated>
            <entry><id>urn:e</id><title>E</title><updated>2024-01-01T00:00:00Z</updated>
                <source>
                    <id>urn:src</id>
                    <title>SrcTitle</title>
                    <updated>2000-01-01T00:00:00Z</updated>
                    <author><name>SrcAuthor</name></author>
                    <contributor><name>SrcContrib</name></contributor>
                    <link href="https://src.example/feed"/>
                    <category term="src-cat"/>
                </source>
            </entry>
        </feed>"#;
    let Feed::Atom(f) = parse_feed(xml, false).unwrap() else {
        panic!()
    };
    let e = &f.entries[0];
    assert_eq!(e.id, "urn:e", "source.id must not overwrite entry.id");
    assert!(
        e.authors.is_empty(),
        "source.author must not leak into entry.authors"
    );
    assert!(
        e.contributors.is_empty(),
        "source.contributor must not leak into entry.contributors"
    );
    assert!(
        e.links.is_empty(),
        "source.link must not leak into entry.links"
    );
    assert!(
        e.categories.is_empty(),
        "source.category must not leak into entry.categories"
    );
    let src = e.source.as_ref().expect("source preserved");
    assert_eq!(src.id.as_deref(), Some("urn:src"));
}

#[test]
fn atom_strict_per_entry_required_fields() {
    // missing entry <id>
    parse_feed(
        r#"<feed xmlns="http://www.w3.org/2005/Atom">
                <id>urn:f</id><title>F</title><updated>2024-01-01T00:00:00Z</updated>
                <entry><title>E</title><updated>2024-01-01T00:00:00Z</updated></entry>
            </feed>"#,
        true,
    )
    .unwrap_err();
    // unparseable feed <updated>
    parse_feed(
        r#"<feed xmlns="http://www.w3.org/2005/Atom">
                <id>urn:f</id><title>F</title><updated>not-a-date</updated>
            </feed>"#,
        true,
    )
    .unwrap_err();
    // unparseable entry <updated>
    parse_feed(
        r#"<feed xmlns="http://www.w3.org/2005/Atom">
                <id>urn:f</id><title>F</title><updated>2024-01-01T00:00:00Z</updated>
                <entry><id>urn:e</id><title>E</title><updated>not-a-date</updated></entry>
            </feed>"#,
        true,
    )
    .unwrap_err();
}

#[test]
fn atom_xhtml_round_trips_inner_markup() {
    use jiff::Timestamp;
    let ts = Timestamp::UNIX_EPOCH;
    let feed = AtomFeed::builder()
        .id("urn:f")
        .title("T")
        .updated(ts)
        .entry(AtomEntry::new("urn:e", "E", ts).with_content(AtomContent {
            value: AtomText::xhtml("<p>hello <em>world</em></p>"),
            src: None,
        }))
        .build();
    let wire = feed.to_string();
    let Feed::Atom(got) = parse_feed(&wire, false).unwrap() else {
        panic!()
    };
    match &got.entries[0].content.as_ref().unwrap().value {
        AtomText::Xhtml(s) => {
            assert!(s.contains("<p>"), "xhtml inner markup dropped: {s:?}");
            assert!(s.contains("<em>"), "xhtml inner markup dropped: {s:?}");
        }
        other => panic!("expected xhtml, got {other:?}"),
    }
}

#[test]
fn podcast_soundbite_rejects_nan_inf() {
    use super::super::feed_ext::{ItemExtensions, MediaRss};
    // Build a feed by hand-crafting XML so we control attribute values.
    let xml = r#"<rss version="2.0" xmlns:podcast="https://podcastindex.org/namespace/1.0">
            <channel><title>T</title><link>l</link><description>D</description>
                <item><title>I</title>
                    <podcast:soundbite startTime="NaN" duration="-inf"/>
                </item>
            </channel>
        </rss>"#;
    let Feed::Rss2(f) = parse_feed(xml, false).unwrap() else {
        panic!()
    };
    let sb = &f.items[0].podcast().expect("podcast ext").soundbites[0];
    assert!(sb.start_time.is_finite(), "NaN must be rejected");
    assert!(sb.duration.is_finite(), "-inf must be rejected");
    // unused imports silenced
    let _ = ItemExtensions::default();
    let _ = MediaRss::default();
}

#[test]
fn nested_media_content_preserves_outer() {
    let xml = r#"<rss version="2.0" xmlns:media="http://search.yahoo.com/mrss/">
            <channel><title>T</title><link>l</link><description>D</description>
                <item><title>I</title>
                    <media:content url="outer" type="application/octet-stream">
                        <media:content url="inner" type="application/octet-stream"/>
                    </media:content>
                </item>
            </channel>
        </rss>"#;
    let Feed::Rss2(f) = parse_feed(xml, false).unwrap() else {
        panic!()
    };
    let urls: Vec<_> = f.items[0]
        .media()
        .expect("media")
        .contents
        .iter()
        .filter_map(|c| c.url.clone())
        .collect();
    assert!(urls.contains(&"outer".to_owned()), "{urls:?}");
    assert!(urls.contains(&"inner".to_owned()), "{urls:?}");
}

#[test]
fn display_does_not_panic_on_malformed_xhtml() {
    use jiff::Timestamp;
    let ts = Timestamp::UNIX_EPOCH;
    let mut feed = AtomFeed::builder()
        .id("urn:f")
        .title("T")
        .updated(ts)
        .build();
    feed.entries
        .push(AtomEntry::new("urn:e", "E", ts).with_content(AtomContent {
            value: AtomText::xhtml("<p>broken"),
            src: None,
        }));
    // Must not panic: Display falls back to an error comment.
    let s = feed.to_string();
    assert!(s.contains("serialization error"), "{s:?}");
}
