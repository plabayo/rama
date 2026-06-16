use jiff::Timestamp;
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};

use super::names::elem;
use super::read::Rss2Channel;
use super::types::{Rss2Category, Rss2Item};
use crate::protocols::rss::feed_ext::names::{attr, content};
use crate::protocols::rss::feed_ext::write as ext_write;
use crate::protocols::rss::ns;
use crate::protocols::rss::ser::{
    XmlWriteError, write_cdata_escaped, write_opt_text_elem, write_text_elem,
};

/// Open `<rss>` + `<channel>` and emit all channel-level metadata + feed-level
/// extension blocks. Stops just before items so the caller can stream them in.
///
/// Always declares the well-known extension namespaces (`itunes`, `podcast`,
/// `content`, `dc`, `media`, plus `atom` when the channel carries any
/// `atom_links`). The header is written before items are known, so the writer
/// can't gate declarations on what items actually use — declaring up front
/// keeps the document well-formed for any item the caller goes on to emit.
pub(in crate::protocols::rss) fn write_rss2_channel_open<W: std::io::Write>(
    w: &mut Writer<W>,
    channel: &Rss2Channel,
) -> Result<(), XmlWriteError> {
    let mut rss_tag = BytesStart::new(elem::RSS);
    rss_tag.push_attribute((attr::VERSION, "2.0"));

    ns::push_xmlns_itunes(&mut rss_tag);
    ns::push_xmlns_podcast(&mut rss_tag);
    ns::push_xmlns_dc(&mut rss_tag);
    ns::push_xmlns_content(&mut rss_tag);
    ns::push_xmlns_media(&mut rss_tag);
    ns::push_xmlns_psc(&mut rss_tag);
    if !channel.atom_links.is_empty() {
        ns::push_xmlns_atom(&mut rss_tag);
    }

    w.write_event(Event::Start(rss_tag))?;
    w.write_event(Event::Start(BytesStart::new(elem::CHANNEL)))?;

    write_text_elem(w, elem::TITLE, &channel.title)?;
    write_text_elem(w, elem::LINK, &channel.link.to_string())?;
    write_text_elem(w, elem::DESCRIPTION, &channel.description)?;
    write_opt_text_elem(w, elem::LANGUAGE, channel.language.as_deref())?;
    write_opt_text_elem(w, elem::COPYRIGHT, channel.copyright.as_deref())?;
    write_opt_text_elem(w, elem::MANAGING_EDITOR, channel.managing_editor.as_deref())?;
    write_opt_text_elem(w, elem::WEB_MASTER, channel.web_master.as_deref())?;

    if let Some(ts) = &channel.pub_date {
        write_text_elem(w, elem::PUB_DATE, &format_rss2_date(ts))?;
    }
    if let Some(ts) = &channel.last_build_date {
        write_text_elem(w, elem::LAST_BUILD_DATE, &format_rss2_date(ts))?;
    }

    for cat in &channel.categories {
        write_rss2_category(w, cat)?;
    }

    write_opt_text_elem(w, elem::GENERATOR, channel.generator.as_deref())?;
    write_opt_text_elem(w, elem::DOCS, channel.docs.as_deref())?;

    if let Some(ttl) = channel.ttl {
        write_text_elem(w, elem::TTL, &ttl.to_string())?;
    }

    if let Some(img) = &channel.image {
        w.write_event(Event::Start(BytesStart::new(elem::IMAGE)))?;
        write_text_elem(w, elem::URL, &img.url.to_string())?;
        write_text_elem(w, elem::TITLE, &img.title)?;
        write_text_elem(w, elem::LINK, &img.link.to_string())?;
        if let Some(width) = img.width {
            write_text_elem(w, elem::WIDTH, &width.to_string())?;
        }
        if let Some(height) = img.height {
            write_text_elem(w, elem::HEIGHT, &height.to_string())?;
        }
        write_opt_text_elem(w, elem::DESCRIPTION, img.description.as_deref())?;
        w.write_event(Event::End(BytesEnd::new(elem::IMAGE)))?;
    }

    for atom_link in &channel.atom_links {
        let mut tag = BytesStart::new(elem::ATOM_LINK);
        let href = atom_link.href.to_string();
        tag.push_attribute((attr::HREF, href.as_str()));
        if let Some(rel) = &atom_link.rel {
            tag.push_attribute((attr::REL, rel.as_str()));
        }
        if let Some(type_) = &atom_link.type_ {
            tag.push_attribute((attr::TYPE, type_.as_str()));
        }
        if let Some(hreflang) = &atom_link.hreflang {
            tag.push_attribute((attr::HREFLANG, hreflang.as_str()));
        }
        if let Some(title) = &atom_link.title {
            tag.push_attribute((attr::TITLE, title.as_str()));
        }
        if let Some(len) = atom_link.length {
            tag.push_attribute((attr::LENGTH, len.to_string().as_str()));
        }
        w.write_event(Event::Empty(tag))?;
    }

    if let Some(itunes) = &channel.extensions.itunes {
        ext_write::write_itunes_feed(w, itunes)?;
    }
    if let Some(podcast) = &channel.extensions.podcast {
        ext_write::write_podcast_feed(w, podcast)?;
    }
    if let Some(dc) = &channel.extensions.dublin_core {
        ext_write::write_dc_feed_fields(w, dc)?;
    }

    Ok(())
}

/// Write a single `<category>` element (with optional `domain` attribute).
/// Shared by the channel- and item-level category loops.
fn write_rss2_category<W: std::io::Write>(
    w: &mut Writer<W>,
    cat: &Rss2Category,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new(elem::CATEGORY);
    if let Some(domain) = &cat.domain {
        tag.push_attribute((attr::DOMAIN, domain.as_str()));
    }
    w.write_event(Event::Start(tag))?;
    w.write_event(Event::Text(BytesText::new(&cat.name)))?;
    w.write_event(Event::End(BytesEnd::new(elem::CATEGORY)))?;
    Ok(())
}

/// Close `</channel></rss>`. Pairs with [`write_rss2_channel_open`] so callers
/// can interleave items from an external source between the two.
pub(in crate::protocols::rss) fn write_rss2_channel_close<W: std::io::Write>(
    w: &mut Writer<W>,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::End(BytesEnd::new(elem::CHANNEL)))?;
    w.write_event(Event::End(BytesEnd::new(elem::RSS)))?;
    Ok(())
}

pub(in crate::protocols::rss) fn write_rss2_item<W: std::io::Write>(
    w: &mut Writer<W>,
    item: &Rss2Item,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::Start(BytesStart::new(elem::ITEM)))?;

    write_opt_text_elem(w, elem::TITLE, item.title.as_deref())?;
    if let Some(link) = &item.link {
        write_text_elem(w, elem::LINK, &link.to_string())?;
    }
    write_opt_text_elem(w, elem::DESCRIPTION, item.description.as_deref())?;
    write_opt_text_elem(w, elem::AUTHOR, item.author.as_deref())?;

    for cat in &item.categories {
        write_rss2_category(w, cat)?;
    }

    write_opt_text_elem(w, elem::COMMENTS, item.comments.as_deref())?;

    for enc in &item.enclosures {
        let mut tag = BytesStart::new(elem::ENCLOSURE);
        let url = enc.url.to_string();
        tag.push_attribute((attr::URL, url.as_str()));
        tag.push_attribute((attr::LENGTH, enc.length.to_string().as_str()));
        tag.push_attribute((attr::TYPE, enc.type_.as_str()));
        w.write_event(Event::Empty(tag))?;
    }

    if let Some(guid) = &item.guid {
        let mut tag = BytesStart::new(elem::GUID);
        tag.push_attribute((
            attr::IS_PERMALINK,
            if guid.permalink { "true" } else { "false" },
        ));
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&guid.value)))?;
        w.write_event(Event::End(BytesEnd::new(elem::GUID)))?;
    }

    if let Some(ts) = &item.pub_date {
        write_text_elem(w, elem::PUB_DATE, &format_rss2_date(ts))?;
    }

    if let Some(src) = &item.source {
        let mut tag = BytesStart::new(elem::SOURCE);
        let url = src.url.to_string();
        tag.push_attribute((attr::URL, url.as_str()));
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&src.title)))?;
        w.write_event(Event::End(BytesEnd::new(elem::SOURCE)))?;
    }

    if let Some(c) = &item.extensions.content
        && let Some(encoded) = &c.encoded
    {
        w.write_event(Event::Start(BytesStart::new(content::ENCODED_TAG)))?;
        write_cdata_escaped(w, encoded)?;
        w.write_event(Event::End(BytesEnd::new(content::ENCODED_TAG)))?;
    }

    if let Some(dc) = &item.extensions.dublin_core {
        ext_write::write_dc_item_fields(w, dc)?;
    }

    if let Some(itunes) = &item.extensions.itunes {
        ext_write::write_itunes_item(w, itunes)?;
    }

    if let Some(podcast) = &item.extensions.podcast {
        ext_write::write_podcast_item(w, podcast)?;
    }

    if let Some(media) = &item.extensions.media {
        ext_write::write_media_item(w, media)?;
    }

    if let Some(chapters) = &item.extensions.podlove {
        ext_write::write_podlove_chapters(w, chapters)?;
    }

    w.write_event(Event::End(BytesEnd::new(elem::ITEM)))?;
    Ok(())
}

pub(in crate::protocols::rss) fn format_rss2_date(ts: &Timestamp) -> String {
    use jiff::fmt::rfc2822;
    use jiff::tz::TimeZone;
    let zdt = ts.to_zoned(TimeZone::UTC);
    let mut buf = String::new();
    if rfc2822::DateTimePrinter::new()
        .print_zoned(&zdt, &mut buf)
        .is_ok()
    {
        buf
    } else {
        ts.to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::protocols::rss::Feed;
    use crate::protocols::rss::feed_ext::{
        FeedExtensions, ITunes, ITunesFeed, ItemExtensions, Podcast, PodcastAlternateEnclosure,
        PodcastIntegrity, PodcastSource,
    };
    use crate::protocols::rss::rss2::types::{Rss2Feed, Rss2Guid, Rss2Item};
    use rama_net::uri::Uri;

    fn feed_with_alternate_enclosures() -> Rss2Feed {
        Rss2Feed::builder()
            .title("Podcast")
            .link(Uri::from_static("https://example.com"))
            .description("A podcast")
            .with_item(
                Rss2Item::new()
                    .with_title("Episode 1")
                    .with_extensions(ItemExtensions {
                        podcast: Some(Box::new(Podcast {
                            alternate_enclosures: vec![
                                PodcastAlternateEnclosure {
                                    type_: "audio/mp4".into(),
                                    length: Some(2_490_970),
                                    bitrate: Some(681_483.55),
                                    height: Some(720),
                                    lang: Some("en".into()),
                                    title: Some("Standard".into()),
                                    rel: Some("main".into()),
                                    codecs: Some("mp4a.40.2".into()),
                                    default: true,
                                    sources: vec![
                                        PodcastSource {
                                            uri: Uri::from_static(
                                                "https://example.com/ep1/audio.m4a",
                                            ),
                                            content_type: Some("audio/mp4".into()),
                                        },
                                        PodcastSource {
                                            uri: Uri::from_static("ipfs://QmExample/audio.m4a"),
                                            content_type: None,
                                        },
                                    ],
                                    integrity: Some(PodcastIntegrity {
                                        type_: "sri".into(),
                                        value: "sha384-abc".into(),
                                    }),
                                },
                                PodcastAlternateEnclosure {
                                    type_: "audio/opus".into(),
                                    length: Some(1_020_000),
                                    bitrate: Some(32_000.5),
                                    height: None,
                                    lang: None,
                                    title: Some("Low".into()),
                                    rel: None,
                                    codecs: None,
                                    default: false,
                                    sources: vec![PodcastSource {
                                        uri: Uri::from_static("https://example.com/ep1/audio.opus"),
                                        content_type: None,
                                    }],
                                    integrity: None,
                                },
                            ],
                            ..Default::default()
                        })),
                        ..Default::default()
                    }),
            )
            .build()
    }

    async fn parse_rss2(xml: String) -> Rss2Feed {
        match Feed::from_body(crate::Body::from(xml))
            .await
            .expect("parse feed")
        {
            Feed::Rss2(feed) => feed,
            Feed::Atom(_) => panic!("expected RSS 2.0 feed"),
        }
    }

    #[test]
    fn builder_enforces_all_required_fields() {
        let feed = Rss2Feed::builder()
            .description("A test blog")
            .title("My Blog")
            .link(Uri::from_static("https://example.com"))
            .build();
        assert_eq!(feed.title, "My Blog");
        assert_eq!(feed.link.to_string(), "https://example.com");
        assert_eq!(feed.description, "A test blog");
    }

    #[tokio::test]
    async fn feed_serializes_to_valid_xml() {
        let feed = Rss2Feed::builder()
            .title("Test Feed")
            .link(Uri::from_static("https://example.com"))
            .description("A test feed")
            .with_item(
                Rss2Item::new()
                    .with_title("Post 1")
                    .with_link(Uri::from_static("https://example.com/1"))
                    .with_guid(Rss2Guid::permalink("https://example.com/1")),
            )
            .build();

        let xml_bytes = feed.to_xml().await.expect("serialize");
        let xml = String::from_utf8(xml_bytes).expect("utf-8");
        assert!(xml.contains("<?xml"));
        assert!(xml.contains(r#"<rss version="2.0""#));
        assert!(xml.contains("<title>Test Feed</title>"));
        assert!(xml.contains("<link>https://example.com</link>"));
        assert!(xml.contains("<item>"));
        assert!(xml.contains("Post 1"));
    }

    #[test]
    fn item_extension_shortcuts_match_generic() {
        let item = Rss2Item::new().with_extensions(ItemExtensions {
            itunes: Some(Box::new(ITunes {
                author: Some("Author".into()),
                ..Default::default()
            })),
            ..Default::default()
        });
        assert!(item.itunes().is_some());
        assert_eq!(
            item.itunes().and_then(|i| i.author.as_deref()),
            Some("Author")
        );
    }

    #[tokio::test]
    async fn itunes_namespaced_xml_emitted_when_extension_present() {
        let feed =
            Rss2Feed::builder()
                .title("Podcast")
                .link(Uri::from_static("https://example.com"))
                .description("A podcast")
                .with_feed_extensions(FeedExtensions {
                    itunes: Some(Box::new(ITunesFeed {
                        author: Some("Host Name".into()),
                        categories: vec!["Technology".into()],
                        explicit: Some(false),
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .with_item(Rss2Item::new().with_title("Episode 1").with_extensions(
                    ItemExtensions {
                        itunes: Some(Box::new(ITunes {
                            duration: Some("30:00".into()),
                            episode: Some(1),
                            season: Some(1),
                            ..Default::default()
                        })),
                        ..Default::default()
                    },
                ))
                .build();

        let xml_bytes = feed.to_xml().await.expect("serialize");
        let xml = String::from_utf8(xml_bytes).expect("utf-8");
        assert!(xml.contains("xmlns:itunes="));
        assert!(xml.contains("itunes:author"));
        assert!(xml.contains("itunes:duration"));
    }

    #[tokio::test]
    async fn podcast_alternate_enclosures_serialize_with_sources_and_integrity() {
        let xml_bytes = feed_with_alternate_enclosures()
            .to_xml()
            .await
            .expect("serialize");
        let xml = String::from_utf8(xml_bytes).expect("utf-8");

        assert!(
            xml.contains(
                r#"<podcast:alternateEnclosure type="audio/mp4" length="2490970" bitrate="681483.55" height="720" lang="en" title="Standard" rel="main" codecs="mp4a.40.2" default="true">"#
            ),
            "{xml}"
        );
        assert!(
            xml.contains(
                r#"<podcast:source uri="https://example.com/ep1/audio.m4a" contentType="audio/mp4"/>"#
            ),
            "{xml}"
        );
        assert!(
            xml.contains(r#"<podcast:source uri="ipfs://QmExample/audio.m4a"/>"#),
            "{xml}"
        );
        assert!(
            xml.contains(r#"<podcast:integrity type="sri" value="sha384-abc"/>"#),
            "{xml}"
        );
        assert!(
            xml.contains(
                r#"<podcast:alternateEnclosure type="audio/opus" length="1020000" bitrate="32000.5" title="Low">"#
            ),
            "{xml}"
        );
        assert!(
            xml.contains(r#"<podcast:source uri="https://example.com/ep1/audio.opus"/>"#),
            "{xml}"
        );
        assert!(!xml.contains(r#"default="false""#), "{xml}");
        assert!(!xml.contains(r#"language="en""#), "{xml}");
        assert!(
            !xml.contains(r#"url="https://example.com/ep1/audio.m4a""#),
            "{xml}"
        );
    }

    #[tokio::test]
    async fn podcast_alternate_enclosures_round_trip() {
        let feed = feed_with_alternate_enclosures();
        let xml =
            String::from_utf8(feed.clone().to_xml().await.expect("serialize")).expect("utf-8");
        let parsed = parse_rss2(xml).await;

        assert_eq!(parsed, feed);
    }

    #[tokio::test]
    async fn podcast_alternate_enclosures_parse_spec_shape_and_missing_optionals() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:podcast="https://podcastindex.org/namespace/1.0">
  <channel>
    <title>Podcast</title>
    <link>https://example.com</link>
    <description>A podcast</description>
    <item>
      <title>Episode 1</title>
      <podcast:alternateEnclosure type="audio/mp4">
        <podcast:source uri="https://example.com/ep1/audio.m4a" />
      </podcast:alternateEnclosure>
      <podcast:alternateEnclosure type="audio/ogg" length="not-an-int" bitrate="not-a-float" height="-1" default="false">
        <podcast:source uri="ipfs://QmExample/audio.ogg" contentType="audio/ogg"></podcast:source>
      </podcast:alternateEnclosure>
    </item>
  </channel>
</rss>"#;
        let parsed = parse_rss2(xml.into()).await;
        let podcast = parsed.items[0].podcast().expect("podcast extension");

        assert_eq!(podcast.alternate_enclosures.len(), 2);
        let first = &podcast.alternate_enclosures[0];
        assert_eq!(first.type_, "audio/mp4");
        assert_eq!(first.length, None);
        assert_eq!(first.bitrate, None);
        assert_eq!(first.height, None);
        assert_eq!(first.lang, None);
        assert!(!first.default);
        assert_eq!(first.sources.len(), 1);
        assert_eq!(
            first.sources[0].uri.to_string(),
            "https://example.com/ep1/audio.m4a"
        );
        assert_eq!(first.sources[0].content_type, None);

        let second = &podcast.alternate_enclosures[1];
        assert_eq!(second.type_, "audio/ogg");
        assert_eq!(second.length, None);
        assert_eq!(second.bitrate, None);
        assert_eq!(second.height, None);
        assert!(!second.default);
        assert_eq!(second.sources.len(), 1);
        assert_eq!(
            second.sources[0].uri.to_string(),
            "ipfs://QmExample/audio.ogg"
        );
        assert_eq!(second.sources[0].content_type.as_deref(), Some("audio/ogg"));
    }

    #[tokio::test]
    async fn empty_podcast_alternate_enclosures_do_not_change_serialization() {
        let base = Rss2Feed::builder()
            .title("Podcast")
            .link(Uri::from_static("https://example.com"))
            .description("A podcast")
            .with_item(Rss2Item::new().with_title("Episode 1"))
            .build();
        let with_empty_podcast =
            Rss2Feed::builder()
                .title("Podcast")
                .link(Uri::from_static("https://example.com"))
                .description("A podcast")
                .with_item(Rss2Item::new().with_title("Episode 1").with_extensions(
                    ItemExtensions {
                        podcast: Some(Box::new(Podcast::default())),
                        ..Default::default()
                    },
                ))
                .build();

        let base_xml = base.to_xml().await.expect("serialize");
        let with_empty_podcast_xml = with_empty_podcast.to_xml().await.expect("serialize");

        assert_eq!(with_empty_podcast_xml, base_xml);
    }
}
