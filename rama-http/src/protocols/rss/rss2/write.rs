use jiff::Timestamp;
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};

use super::super::ext_write;
use super::super::ns;
use super::super::ser::{XmlWriteError, write_cdata_escaped, write_opt_text_elem, write_text_elem};
use super::types::{Rss2Feed, Rss2Item};

pub(super) fn write_rss2_feed<W: std::io::Write>(
    w: &mut Writer<W>,
    feed: &Rss2Feed,
) -> Result<(), XmlWriteError> {
    let mut rss_tag = BytesStart::new("rss");
    rss_tag.push_attribute(("version", "2.0"));

    let needs_itunes = feed.extensions.itunes.is_some()
        || feed.items.iter().any(|i| i.extensions.itunes.is_some());
    let needs_podcast = feed.extensions.podcast.is_some()
        || feed.items.iter().any(|i| i.extensions.podcast.is_some());
    let needs_dc = feed.extensions.dublin_core.is_some()
        || feed
            .items
            .iter()
            .any(|i| i.extensions.dublin_core.is_some());
    let needs_content = feed.items.iter().any(|i| i.extensions.content.is_some());
    let needs_media = feed.items.iter().any(|i| i.extensions.media.is_some());
    let needs_atom = !feed.atom_links.is_empty();

    if needs_itunes {
        ns::push_xmlns_itunes(&mut rss_tag);
    }
    if needs_podcast {
        ns::push_xmlns_podcast(&mut rss_tag);
    }
    if needs_dc {
        ns::push_xmlns_dc(&mut rss_tag);
    }
    if needs_content {
        ns::push_xmlns_content(&mut rss_tag);
    }
    if needs_media {
        ns::push_xmlns_media(&mut rss_tag);
    }
    if needs_atom {
        ns::push_xmlns_atom(&mut rss_tag);
    }

    w.write_event(Event::Start(rss_tag))?;
    w.write_event(Event::Start(BytesStart::new("channel")))?;

    write_text_elem(w, "title", &feed.title)?;
    write_text_elem(w, "link", &feed.link)?;
    write_text_elem(w, "description", &feed.description)?;
    write_opt_text_elem(w, "language", feed.language.as_deref())?;
    write_opt_text_elem(w, "copyright", feed.copyright.as_deref())?;
    write_opt_text_elem(w, "managingEditor", feed.managing_editor.as_deref())?;
    write_opt_text_elem(w, "webMaster", feed.web_master.as_deref())?;

    if let Some(ts) = &feed.pub_date {
        write_text_elem(w, "pubDate", &format_rss2_date(ts))?;
    }
    if let Some(ts) = &feed.last_build_date {
        write_text_elem(w, "lastBuildDate", &format_rss2_date(ts))?;
    }

    for cat in &feed.categories {
        let mut tag = BytesStart::new("category");
        if let Some(domain) = &cat.domain {
            tag.push_attribute(("domain", domain.as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&cat.name)))?;
        w.write_event(Event::End(BytesEnd::new("category")))?;
    }

    write_opt_text_elem(w, "generator", feed.generator.as_deref())?;
    write_opt_text_elem(w, "docs", feed.docs.as_deref())?;

    if let Some(ttl) = feed.ttl {
        write_text_elem(w, "ttl", &ttl.to_string())?;
    }

    if let Some(img) = &feed.image {
        w.write_event(Event::Start(BytesStart::new("image")))?;
        write_text_elem(w, "url", &img.url)?;
        write_text_elem(w, "title", &img.title)?;
        write_text_elem(w, "link", &img.link)?;
        if let Some(width) = img.width {
            write_text_elem(w, "width", &width.to_string())?;
        }
        if let Some(height) = img.height {
            write_text_elem(w, "height", &height.to_string())?;
        }
        write_opt_text_elem(w, "description", img.description.as_deref())?;
        w.write_event(Event::End(BytesEnd::new("image")))?;
    }

    for atom_link in &feed.atom_links {
        let mut tag = BytesStart::new("atom:link");
        tag.push_attribute(("href", atom_link.href.as_str()));
        if let Some(rel) = &atom_link.rel {
            tag.push_attribute(("rel", rel.as_str()));
        }
        if let Some(type_) = &atom_link.type_ {
            tag.push_attribute(("type", type_.as_str()));
        }
        if let Some(hreflang) = &atom_link.hreflang {
            tag.push_attribute(("hreflang", hreflang.as_str()));
        }
        if let Some(title) = &atom_link.title {
            tag.push_attribute(("title", title.as_str()));
        }
        if let Some(len) = atom_link.length {
            tag.push_attribute(("length", len.to_string().as_str()));
        }
        w.write_event(Event::Empty(tag))?;
    }

    if let Some(itunes) = &feed.extensions.itunes {
        ext_write::write_itunes_feed(w, itunes)?;
    }
    if let Some(podcast) = &feed.extensions.podcast {
        ext_write::write_podcast_feed(w, podcast)?;
    }
    if let Some(dc) = &feed.extensions.dublin_core {
        ext_write::write_dc_feed_fields(w, dc)?;
    }

    for item in &feed.items {
        write_rss2_item(w, item)?;
    }

    w.write_event(Event::End(BytesEnd::new("channel")))?;
    w.write_event(Event::End(BytesEnd::new("rss")))?;
    Ok(())
}

pub(in super::super) fn write_rss2_item<W: std::io::Write>(
    w: &mut Writer<W>,
    item: &Rss2Item,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::Start(BytesStart::new("item")))?;

    write_opt_text_elem(w, "title", item.title.as_deref())?;
    write_opt_text_elem(w, "link", item.link.as_deref())?;
    write_opt_text_elem(w, "description", item.description.as_deref())?;
    write_opt_text_elem(w, "author", item.author.as_deref())?;

    for cat in &item.categories {
        let mut tag = BytesStart::new("category");
        if let Some(domain) = &cat.domain {
            tag.push_attribute(("domain", domain.as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&cat.name)))?;
        w.write_event(Event::End(BytesEnd::new("category")))?;
    }

    write_opt_text_elem(w, "comments", item.comments.as_deref())?;

    for enc in &item.enclosures {
        let mut tag = BytesStart::new("enclosure");
        tag.push_attribute(("url", enc.url.as_str()));
        tag.push_attribute(("length", enc.length.to_string().as_str()));
        tag.push_attribute(("type", enc.type_.as_str()));
        w.write_event(Event::Empty(tag))?;
    }

    if let Some(guid) = &item.guid {
        let mut tag = BytesStart::new("guid");
        tag.push_attribute(("isPermaLink", if guid.permalink { "true" } else { "false" }));
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&guid.value)))?;
        w.write_event(Event::End(BytesEnd::new("guid")))?;
    }

    if let Some(ts) = &item.pub_date {
        write_text_elem(w, "pubDate", &format_rss2_date(ts))?;
    }

    if let Some(src) = &item.source {
        let mut tag = BytesStart::new("source");
        tag.push_attribute(("url", src.url.as_str()));
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&src.title)))?;
        w.write_event(Event::End(BytesEnd::new("source")))?;
    }

    if let Some(content) = &item.extensions.content
        && let Some(encoded) = &content.encoded
    {
        w.write_event(Event::Start(BytesStart::new("content:encoded")))?;
        write_cdata_escaped(w, encoded)?;
        w.write_event(Event::End(BytesEnd::new("content:encoded")))?;
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

    w.write_event(Event::End(BytesEnd::new("item")))?;
    Ok(())
}

pub(in super::super) fn format_rss2_date(ts: &Timestamp) -> String {
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
    use super::super::super::feed_ext::{FeedExtensions, ITunes, ITunesFeed, ItemExtensions};
    use super::super::types::{Rss2Feed, Rss2Guid, Rss2Item};

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

    #[test]
    fn feed_serializes_to_valid_xml() {
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

        let xml = feed.to_string();
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

    #[test]
    fn itunes_namespaced_xml_emitted_when_extension_present() {
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

        let xml = feed.to_string();
        assert!(xml.contains("xmlns:itunes="));
        assert!(xml.contains("itunes:author"));
        assert!(xml.contains("itunes:duration"));
    }
}
