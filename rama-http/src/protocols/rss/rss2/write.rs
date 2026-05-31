use jiff::Timestamp;
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};

use super::names::elem;
use super::read::Rss2Channel;
use super::types::Rss2Item;
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
    if !channel.atom_links.is_empty() {
        ns::push_xmlns_atom(&mut rss_tag);
    }

    w.write_event(Event::Start(rss_tag))?;
    w.write_event(Event::Start(BytesStart::new(elem::CHANNEL)))?;

    write_text_elem(w, elem::TITLE, &channel.title)?;
    write_text_elem(w, elem::LINK, &channel.link)?;
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
        let mut tag = BytesStart::new(elem::CATEGORY);
        if let Some(domain) = &cat.domain {
            tag.push_attribute((attr::DOMAIN, domain.as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&cat.name)))?;
        w.write_event(Event::End(BytesEnd::new(elem::CATEGORY)))?;
    }

    write_opt_text_elem(w, elem::GENERATOR, channel.generator.as_deref())?;
    write_opt_text_elem(w, elem::DOCS, channel.docs.as_deref())?;

    if let Some(ttl) = channel.ttl {
        write_text_elem(w, elem::TTL, &ttl.to_string())?;
    }

    if let Some(img) = &channel.image {
        w.write_event(Event::Start(BytesStart::new(elem::IMAGE)))?;
        write_text_elem(w, elem::URL, &img.url)?;
        write_text_elem(w, elem::TITLE, &img.title)?;
        write_text_elem(w, elem::LINK, &img.link)?;
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
        tag.push_attribute((attr::HREF, atom_link.href.as_str()));
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
    write_opt_text_elem(w, elem::LINK, item.link.as_deref())?;
    write_opt_text_elem(w, elem::DESCRIPTION, item.description.as_deref())?;
    write_opt_text_elem(w, elem::AUTHOR, item.author.as_deref())?;

    for cat in &item.categories {
        let mut tag = BytesStart::new(elem::CATEGORY);
        if let Some(domain) = &cat.domain {
            tag.push_attribute((attr::DOMAIN, domain.as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&cat.name)))?;
        w.write_event(Event::End(BytesEnd::new(elem::CATEGORY)))?;
    }

    write_opt_text_elem(w, elem::COMMENTS, item.comments.as_deref())?;

    for enc in &item.enclosures {
        let mut tag = BytesStart::new(elem::ENCLOSURE);
        tag.push_attribute((attr::URL, enc.url.as_str()));
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
        tag.push_attribute((attr::URL, src.url.as_str()));
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
    use crate::protocols::rss::feed_ext::{FeedExtensions, ITunes, ITunesFeed, ItemExtensions};
    use crate::protocols::rss::rss2::types::{Rss2Feed, Rss2Guid, Rss2Item};

    #[test]
    fn builder_enforces_all_required_fields() {
        let feed = Rss2Feed::builder()
            .description("A test blog")
            .title("My Blog")
            .link("https://example.com")
            .build();
        assert_eq!(feed.title, "My Blog");
        assert_eq!(feed.link, "https://example.com");
        assert_eq!(feed.description, "A test blog");
    }

    #[tokio::test]
    async fn feed_serializes_to_valid_xml() {
        let feed = Rss2Feed::builder()
            .title("Test Feed")
            .link("https://example.com")
            .description("A test feed")
            .item(
                Rss2Item::new()
                    .with_title("Post 1")
                    .with_link("https://example.com/1")
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
            itunes: Some(ITunes {
                author: Some("Author".into()),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert!(item.itunes().is_some());
        assert!(item.extension::<ITunes>().is_some());
        assert_eq!(item.itunes(), item.extension::<ITunes>());
    }

    #[tokio::test]
    async fn itunes_namespaced_xml_emitted_when_extension_present() {
        let feed = Rss2Feed::builder()
            .title("Podcast")
            .link("https://example.com")
            .description("A podcast")
            .feed_extensions(FeedExtensions {
                itunes: Some(ITunesFeed {
                    author: Some("Host Name".into()),
                    categories: vec!["Technology".into()],
                    explicit: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .item(
                Rss2Item::new()
                    .with_title("Episode 1")
                    .with_extensions(ItemExtensions {
                        itunes: Some(ITunes {
                            duration: Some("30:00".into()),
                            episode: Some(1),
                            season: Some(1),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
            )
            .build();

        let xml_bytes = feed.to_xml().await.expect("serialize");
        let xml = String::from_utf8(xml_bytes).expect("utf-8");
        assert!(xml.contains("xmlns:itunes="));
        assert!(xml.contains("itunes:author"));
        assert!(xml.contains("itunes:duration"));
    }
}
