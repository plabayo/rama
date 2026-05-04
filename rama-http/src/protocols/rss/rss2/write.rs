use jiff::Timestamp;
use quick_xml::{
    Writer,
    events::{BytesCData, BytesEnd, BytesStart, BytesText, Event},
};

use super::super::feed_ext::{
    ITunes, ITunesFeed, MediaRss, Podcast, PodcastFeed, PodcastLocation, PodcastPerson,
};
use super::super::ser::{write_opt_text_elem, write_text_elem, XmlWriteError};
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
        || feed.items.iter().any(|i| i.extensions.dublin_core.is_some());
    let needs_content = feed.items.iter().any(|i| i.extensions.content.is_some());
    let needs_media = feed.items.iter().any(|i| i.extensions.media.is_some());

    if needs_itunes {
        rss_tag.push_attribute(("xmlns:itunes", "http://www.itunes.com/dtds/podcast-1.0.dtd"));
    }
    if needs_podcast {
        rss_tag.push_attribute(("xmlns:podcast", "https://podcastindex.org/namespace/1.0"));
    }
    if needs_dc {
        rss_tag.push_attribute(("xmlns:dc", "http://purl.org/dc/elements/1.1/"));
    }
    if needs_content {
        rss_tag.push_attribute(("xmlns:content", "http://purl.org/rss/1.0/modules/content/"));
    }
    if needs_media {
        rss_tag.push_attribute(("xmlns:media", "http://search.yahoo.com/mrss/"));
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

    if let Some(itunes) = &feed.extensions.itunes {
        write_itunes_feed(w, itunes)?;
    }
    if let Some(podcast) = &feed.extensions.podcast {
        write_podcast_feed(w, podcast)?;
    }
    if let Some(dc) = &feed.extensions.dublin_core {
        write_dc_fields(
            w,
            dc.title.as_deref(),
            dc.creator.as_deref(),
            dc.subject.as_deref(),
            dc.description.as_deref(),
            dc.publisher.as_deref(),
            dc.contributor.as_deref(),
            dc.date.as_ref(),
            dc.type_.as_deref(),
            dc.format.as_deref(),
            dc.identifier.as_deref(),
            dc.source.as_deref(),
            dc.language.as_deref(),
            dc.relation.as_deref(),
            dc.coverage.as_deref(),
            dc.rights.as_deref(),
        )?;
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

    if let Some(enc) = &item.enclosure {
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
        w.write_event(Event::CData(BytesCData::new(encoded)))?;
        w.write_event(Event::End(BytesEnd::new("content:encoded")))?;
    }

    if let Some(dc) = &item.extensions.dublin_core {
        write_dc_fields(
            w,
            dc.title.as_deref(),
            dc.creator.as_deref(),
            dc.subject.as_deref(),
            dc.description.as_deref(),
            dc.publisher.as_deref(),
            dc.contributor.as_deref(),
            dc.date.as_ref(),
            dc.type_.as_deref(),
            dc.format.as_deref(),
            dc.identifier.as_deref(),
            dc.source.as_deref(),
            dc.language.as_deref(),
            dc.relation.as_deref(),
            dc.coverage.as_deref(),
            dc.rights.as_deref(),
        )?;
    }

    if let Some(itunes) = &item.extensions.itunes {
        write_itunes_item(w, itunes)?;
    }

    if let Some(podcast) = &item.extensions.podcast {
        write_podcast_item(w, podcast)?;
    }

    if let Some(media) = &item.extensions.media {
        write_media_item(w, media)?;
    }

    w.write_event(Event::End(BytesEnd::new("item")))?;
    Ok(())
}

fn write_itunes_feed<W: std::io::Write>(
    w: &mut Writer<W>,
    itunes: &ITunesFeed,
) -> Result<(), XmlWriteError> {
    write_opt_text_elem(w, "itunes:title", itunes.title.as_deref())?;
    write_opt_text_elem(w, "itunes:author", itunes.author.as_deref())?;
    write_opt_text_elem(w, "itunes:subtitle", itunes.subtitle.as_deref())?;
    write_opt_text_elem(w, "itunes:summary", itunes.summary.as_deref())?;
    if let Some(img) = &itunes.image {
        let mut tag = BytesStart::new("itunes:image");
        tag.push_attribute(("href", img.as_str()));
        w.write_event(Event::Empty(tag))?;
    }
    for cat in &itunes.categories {
        let mut tag = BytesStart::new("itunes:category");
        tag.push_attribute(("text", cat.as_str()));
        w.write_event(Event::Empty(tag))?;
    }
    if let Some(explicit) = itunes.explicit {
        write_text_elem(w, "itunes:explicit", if explicit { "true" } else { "false" })?;
    }
    write_opt_text_elem(w, "itunes:type", itunes.type_.as_deref())?;
    write_opt_text_elem(w, "itunes:new-feed-url", itunes.new_feed_url.as_deref())?;
    if let Some(block) = itunes.block {
        write_text_elem(w, "itunes:block", if block { "Yes" } else { "No" })?;
    }
    if let Some(complete) = itunes.complete {
        write_text_elem(w, "itunes:complete", if complete { "Yes" } else { "No" })?;
    }
    if itunes.owner_name.is_some() || itunes.owner_email.is_some() {
        w.write_event(Event::Start(BytesStart::new("itunes:owner")))?;
        write_opt_text_elem(w, "itunes:name", itunes.owner_name.as_deref())?;
        write_opt_text_elem(w, "itunes:email", itunes.owner_email.as_deref())?;
        w.write_event(Event::End(BytesEnd::new("itunes:owner")))?;
    }
    Ok(())
}

fn write_itunes_item<W: std::io::Write>(
    w: &mut Writer<W>,
    itunes: &ITunes,
) -> Result<(), XmlWriteError> {
    write_opt_text_elem(w, "itunes:title", itunes.title.as_deref())?;
    write_opt_text_elem(w, "itunes:author", itunes.author.as_deref())?;
    write_opt_text_elem(w, "itunes:subtitle", itunes.subtitle.as_deref())?;
    write_opt_text_elem(w, "itunes:summary", itunes.summary.as_deref())?;
    if let Some(img) = &itunes.image {
        let mut tag = BytesStart::new("itunes:image");
        tag.push_attribute(("href", img.as_str()));
        w.write_event(Event::Empty(tag))?;
    }
    write_opt_text_elem(w, "itunes:duration", itunes.duration.as_deref())?;
    if let Some(explicit) = itunes.explicit {
        write_text_elem(w, "itunes:explicit", if explicit { "true" } else { "false" })?;
    }
    if let Some(ep) = itunes.episode {
        write_text_elem(w, "itunes:episode", &ep.to_string())?;
    }
    if let Some(s) = itunes.season {
        write_text_elem(w, "itunes:season", &s.to_string())?;
    }
    write_opt_text_elem(w, "itunes:episodeType", itunes.episode_type.as_deref())?;
    write_opt_text_elem(w, "itunes:keywords", itunes.keywords.as_deref())?;
    if let Some(block) = itunes.block {
        write_text_elem(w, "itunes:block", if block { "Yes" } else { "No" })?;
    }
    Ok(())
}

fn write_podcast_feed<W: std::io::Write>(
    w: &mut Writer<W>,
    podcast: &PodcastFeed,
) -> Result<(), XmlWriteError> {
    write_opt_text_elem(w, "podcast:guid", podcast.guid.as_deref())?;
    if let Some(locked) = podcast.locked {
        write_text_elem(w, "podcast:locked", if locked { "yes" } else { "no" })?;
    }
    for f in &podcast.fundings {
        let mut tag = BytesStart::new("podcast:funding");
        tag.push_attribute(("url", f.url.as_str()));
        if let Some(title) = &f.title {
            w.write_event(Event::Start(tag))?;
            w.write_event(Event::Text(BytesText::new(title)))?;
            w.write_event(Event::End(BytesEnd::new("podcast:funding")))?;
        } else {
            w.write_event(Event::Empty(tag))?;
        }
    }
    write_opt_text_elem(w, "podcast:medium", podcast.medium.as_deref())?;
    write_opt_text_elem(w, "podcast:license", podcast.license.as_deref())?;
    for person in &podcast.persons {
        write_podcast_person(w, person)?;
    }
    if let Some(loc) = &podcast.location {
        write_podcast_location(w, loc)?;
    }
    for trailer in &podcast.trailers {
        let mut tag = BytesStart::new("podcast:trailer");
        tag.push_attribute(("url", trailer.url.as_str()));
        if let Some(pd) = &trailer.pub_date {
            tag.push_attribute(("pubDate", format_rss2_date(pd).as_str()));
        }
        if let Some(len) = trailer.length {
            tag.push_attribute(("length", len.to_string().as_str()));
        }
        if let Some(t) = &trailer.type_ {
            tag.push_attribute(("type", t.as_str()));
        }
        if let Some(s) = trailer.season {
            tag.push_attribute(("season", s.to_string().as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&trailer.title)))?;
        w.write_event(Event::End(BytesEnd::new("podcast:trailer")))?;
    }
    Ok(())
}

fn write_podcast_item<W: std::io::Write>(
    w: &mut Writer<W>,
    podcast: &Podcast,
) -> Result<(), XmlWriteError> {
    for tr in &podcast.transcripts {
        let mut tag = BytesStart::new("podcast:transcript");
        tag.push_attribute(("url", tr.url.as_str()));
        tag.push_attribute(("type", tr.type_.as_str()));
        if let Some(lang) = &tr.language {
            tag.push_attribute(("language", lang.as_str()));
        }
        if let Some(rel) = &tr.rel {
            tag.push_attribute(("rel", rel.as_str()));
        }
        w.write_event(Event::Empty(tag))?;
    }
    if let Some(ch) = &podcast.chapters {
        let mut tag = BytesStart::new("podcast:chapters");
        tag.push_attribute(("url", ch.url.as_str()));
        tag.push_attribute(("type", ch.type_.as_str()));
        w.write_event(Event::Empty(tag))?;
    }
    for sb in &podcast.soundbites {
        let mut tag = BytesStart::new("podcast:soundbite");
        tag.push_attribute(("startTime", sb.start_time.to_string().as_str()));
        tag.push_attribute(("duration", sb.duration.to_string().as_str()));
        if let Some(title) = &sb.title {
            w.write_event(Event::Start(tag))?;
            w.write_event(Event::Text(BytesText::new(title)))?;
            w.write_event(Event::End(BytesEnd::new("podcast:soundbite")))?;
        } else {
            w.write_event(Event::Empty(tag))?;
        }
    }
    for person in &podcast.persons {
        write_podcast_person(w, person)?;
    }
    if let Some(loc) = &podcast.location {
        write_podcast_location(w, loc)?;
    }
    if let Some(season) = &podcast.season {
        let mut tag = BytesStart::new("podcast:season");
        if let Some(name) = &season.name {
            tag.push_attribute(("name", name.as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&season.number.to_string())))?;
        w.write_event(Event::End(BytesEnd::new("podcast:season")))?;
    }
    if let Some(ep) = &podcast.episode {
        let mut tag = BytesStart::new("podcast:episode");
        if let Some(display) = &ep.display {
            tag.push_attribute(("display", display.as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&ep.number.to_string())))?;
        w.write_event(Event::End(BytesEnd::new("podcast:episode")))?;
    }
    Ok(())
}

fn write_podcast_person<W: std::io::Write>(
    w: &mut Writer<W>,
    person: &PodcastPerson,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new("podcast:person");
    if let Some(role) = &person.role {
        tag.push_attribute(("role", role.as_str()));
    }
    if let Some(group) = &person.group {
        tag.push_attribute(("group", group.as_str()));
    }
    if let Some(img) = &person.img {
        tag.push_attribute(("img", img.as_str()));
    }
    if let Some(href) = &person.href {
        tag.push_attribute(("href", href.as_str()));
    }
    w.write_event(Event::Start(tag))?;
    w.write_event(Event::Text(BytesText::new(&person.name)))?;
    w.write_event(Event::End(BytesEnd::new("podcast:person")))?;
    Ok(())
}

fn write_podcast_location<W: std::io::Write>(
    w: &mut Writer<W>,
    loc: &PodcastLocation,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new("podcast:location");
    if let Some(geo) = &loc.geo {
        tag.push_attribute(("geo", geo.as_str()));
    }
    if let Some(osm) = &loc.osm {
        tag.push_attribute(("osm", osm.as_str()));
    }
    w.write_event(Event::Start(tag))?;
    w.write_event(Event::Text(BytesText::new(&loc.name)))?;
    w.write_event(Event::End(BytesEnd::new("podcast:location")))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_dc_fields<W: std::io::Write>(
    w: &mut Writer<W>,
    title: Option<&str>,
    creator: Option<&str>,
    subject: Option<&str>,
    description: Option<&str>,
    publisher: Option<&str>,
    contributor: Option<&str>,
    date: Option<&Timestamp>,
    type_: Option<&str>,
    format: Option<&str>,
    identifier: Option<&str>,
    source: Option<&str>,
    language: Option<&str>,
    relation: Option<&str>,
    coverage: Option<&str>,
    rights: Option<&str>,
) -> Result<(), XmlWriteError> {
    write_opt_text_elem(w, "dc:title", title)?;
    write_opt_text_elem(w, "dc:creator", creator)?;
    write_opt_text_elem(w, "dc:subject", subject)?;
    write_opt_text_elem(w, "dc:description", description)?;
    write_opt_text_elem(w, "dc:publisher", publisher)?;
    write_opt_text_elem(w, "dc:contributor", contributor)?;
    if let Some(d) = date {
        write_text_elem(w, "dc:date", &d.to_string())?;
    }
    write_opt_text_elem(w, "dc:type", type_)?;
    write_opt_text_elem(w, "dc:format", format)?;
    write_opt_text_elem(w, "dc:identifier", identifier)?;
    write_opt_text_elem(w, "dc:source", source)?;
    write_opt_text_elem(w, "dc:language", language)?;
    write_opt_text_elem(w, "dc:relation", relation)?;
    write_opt_text_elem(w, "dc:coverage", coverage)?;
    write_opt_text_elem(w, "dc:rights", rights)?;
    Ok(())
}

fn write_media_item<W: std::io::Write>(
    w: &mut Writer<W>,
    media: &MediaRss,
) -> Result<(), XmlWriteError> {
    for mc in &media.contents {
        let mut tag = BytesStart::new("media:content");
        if let Some(url) = &mc.url {
            tag.push_attribute(("url", url.as_str()));
        }
        if let Some(t) = &mc.type_ {
            tag.push_attribute(("type", t.as_str()));
        }
        if let Some(m) = &mc.medium {
            tag.push_attribute(("medium", m.as_str()));
        }
        if let Some(d) = mc.duration {
            tag.push_attribute(("duration", d.to_string().as_str()));
        }
        if let Some(width) = mc.width {
            tag.push_attribute(("width", width.to_string().as_str()));
        }
        if let Some(height) = mc.height {
            tag.push_attribute(("height", height.to_string().as_str()));
        }
        if let Some(fs) = mc.file_size {
            tag.push_attribute(("fileSize", fs.to_string().as_str()));
        }
        if let Some(br) = mc.bitrate {
            tag.push_attribute(("bitrate", br.to_string().as_str()));
        }
        let has_children = mc.title.is_some() || mc.description.is_some();
        if has_children {
            w.write_event(Event::Start(tag))?;
            write_opt_text_elem(w, "media:title", mc.title.as_deref())?;
            write_opt_text_elem(w, "media:description", mc.description.as_deref())?;
            w.write_event(Event::End(BytesEnd::new("media:content")))?;
        } else {
            w.write_event(Event::Empty(tag))?;
        }
    }
    if let Some(thumb) = &media.thumbnail {
        let mut tag = BytesStart::new("media:thumbnail");
        tag.push_attribute(("url", thumb.url.as_str()));
        if let Some(width) = thumb.width {
            tag.push_attribute(("width", width.to_string().as_str()));
        }
        if let Some(height) = thumb.height {
            tag.push_attribute(("height", height.to_string().as_str()));
        }
        w.write_event(Event::Empty(tag))?;
    }
    write_opt_text_elem(w, "media:title", media.title.as_deref())?;
    write_opt_text_elem(w, "media:description", media.description.as_deref())?;
    write_opt_text_elem(w, "media:keywords", media.keywords.as_deref())?;
    write_opt_text_elem(w, "media:rating", media.rating.as_deref())?;
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
