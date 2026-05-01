use jiff::Timestamp;
use quick_xml::{
    Writer,
    events::{BytesCData, BytesEnd, BytesStart, BytesText, Event},
};

use super::super::feed_ext::{
    ITunes, ITunesFeed, MediaRss, Podcast, PodcastFeed, PodcastLocation, PodcastPerson,
};
use super::super::rss2::format_rss2_date;
use super::super::ser::{write_opt_text_elem, write_text_elem, XmlWriteError};
use super::types::{AtomCategory, AtomContent, AtomEntry, AtomFeed, AtomLink, AtomPerson, AtomText};

pub(super) fn write_atom_feed<W: std::io::Write>(
    w: &mut Writer<W>,
    feed: &AtomFeed,
) -> Result<(), XmlWriteError> {
    let mut feed_tag = BytesStart::new("feed");
    feed_tag.push_attribute(("xmlns", "http://www.w3.org/2005/Atom"));

    let needs_itunes = feed.extensions.itunes.is_some()
        || feed.entries.iter().any(|e| e.extensions.itunes.is_some());
    let needs_podcast = feed.extensions.podcast.is_some()
        || feed.entries.iter().any(|e| e.extensions.podcast.is_some());
    let needs_dc = feed.extensions.dublin_core.is_some()
        || feed.entries.iter().any(|e| e.extensions.dublin_core.is_some());
    let needs_media = feed.entries.iter().any(|e| e.extensions.media.is_some());

    if needs_itunes {
        feed_tag.push_attribute(("xmlns:itunes", "http://www.itunes.com/dtds/podcast-1.0.dtd"));
    }
    if needs_podcast {
        feed_tag.push_attribute(("xmlns:podcast", "https://podcastindex.org/namespace/1.0"));
    }
    if needs_dc {
        feed_tag.push_attribute(("xmlns:dc", "http://purl.org/dc/elements/1.1/"));
    }
    if needs_media {
        feed_tag.push_attribute(("xmlns:media", "http://search.yahoo.com/mrss/"));
    }

    w.write_event(Event::Start(feed_tag))?;

    write_text_elem(w, "id", &feed.id)?;
    write_atom_text(w, "title", &feed.title)?;
    write_text_elem(w, "updated", &feed.updated.to_string())?;

    for author in &feed.authors {
        write_atom_person(w, "author", author)?;
    }
    for link in &feed.links {
        write_atom_link(w, link)?;
    }
    for cat in &feed.categories {
        write_atom_category(w, cat)?;
    }
    for contrib in &feed.contributors {
        write_atom_person(w, "contributor", contrib)?;
    }
    if let Some(generator) = &feed.generator {
        let mut tag = BytesStart::new("generator");
        if let Some(uri) = &generator.uri {
            tag.push_attribute(("uri", uri.as_str()));
        }
        if let Some(ver) = &generator.version {
            tag.push_attribute(("version", ver.as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&generator.value)))?;
        w.write_event(Event::End(BytesEnd::new("generator")))?;
    }
    write_opt_text_elem(w, "icon", feed.icon.as_deref())?;
    write_opt_text_elem(w, "logo", feed.logo.as_deref())?;
    if let Some(rights) = &feed.rights {
        write_atom_text(w, "rights", rights)?;
    }
    if let Some(subtitle) = &feed.subtitle {
        write_atom_text(w, "subtitle", subtitle)?;
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

    for entry in &feed.entries {
        write_atom_entry(w, entry)?;
    }

    w.write_event(Event::End(BytesEnd::new("feed")))?;
    Ok(())
}

fn write_atom_entry<W: std::io::Write>(
    w: &mut Writer<W>,
    entry: &AtomEntry,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::Start(BytesStart::new("entry")))?;

    write_text_elem(w, "id", &entry.id)?;
    write_atom_text(w, "title", &entry.title)?;
    write_text_elem(w, "updated", &entry.updated.to_string())?;

    for author in &entry.authors {
        write_atom_person(w, "author", author)?;
    }
    for link in &entry.links {
        write_atom_link(w, link)?;
    }
    if let Some(summary) = &entry.summary {
        write_atom_text(w, "summary", summary)?;
    }
    if let Some(content) = &entry.content {
        write_atom_content(w, content)?;
    }
    for cat in &entry.categories {
        write_atom_category(w, cat)?;
    }
    for contrib in &entry.contributors {
        write_atom_person(w, "contributor", contrib)?;
    }
    if let Some(published) = &entry.published {
        write_text_elem(w, "published", &published.to_string())?;
    }
    if let Some(rights) = &entry.rights {
        write_atom_text(w, "rights", rights)?;
    }
    if let Some(source) = &entry.source {
        w.write_event(Event::Start(BytesStart::new("source")))?;
        write_opt_text_elem(w, "id", source.id.as_deref())?;
        if let Some(title) = &source.title {
            write_atom_text(w, "title", title)?;
        }
        if let Some(updated) = &source.updated {
            write_text_elem(w, "updated", &updated.to_string())?;
        }
        w.write_event(Event::End(BytesEnd::new("source")))?;
    }

    if let Some(dc) = &entry.extensions.dublin_core {
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
    if let Some(itunes) = &entry.extensions.itunes {
        write_itunes_item(w, itunes)?;
    }
    if let Some(podcast) = &entry.extensions.podcast {
        write_podcast_item(w, podcast)?;
    }
    if let Some(media) = &entry.extensions.media {
        write_media_item(w, media)?;
    }

    w.write_event(Event::End(BytesEnd::new("entry")))?;
    Ok(())
}

fn write_atom_content<W: std::io::Write>(
    w: &mut Writer<W>,
    content: &AtomContent,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new("content");
    if let Some(src) = &content.src {
        tag.push_attribute(("src", src.as_str()));
        tag.push_attribute(("type", content.value.value()));
        w.write_event(Event::Empty(tag))?;
    } else {
        tag.push_attribute(("type", content.value.type_attr()));
        w.write_event(Event::Start(tag))?;
        match &content.value {
            AtomText::Html(s) => {
                w.write_event(Event::CData(BytesCData::new(s)))?;
            }
            AtomText::Text(s) | AtomText::Xhtml(s) => {
                w.write_event(Event::Text(BytesText::new(s)))?;
            }
        }
        w.write_event(Event::End(BytesEnd::new("content")))?;
    }
    Ok(())
}

fn write_atom_text<W: std::io::Write>(
    w: &mut Writer<W>,
    name: &str,
    text: &AtomText,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new(name);
    tag.push_attribute(("type", text.type_attr()));
    w.write_event(Event::Start(tag))?;
    match text {
        AtomText::Html(s) => {
            w.write_event(Event::CData(BytesCData::new(s)))?;
        }
        AtomText::Text(s) | AtomText::Xhtml(s) => {
            w.write_event(Event::Text(BytesText::new(s)))?;
        }
    }
    w.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

fn write_atom_person<W: std::io::Write>(
    w: &mut Writer<W>,
    tag_name: &str,
    person: &AtomPerson,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::Start(BytesStart::new(tag_name)))?;
    write_text_elem(w, "name", &person.name)?;
    write_opt_text_elem(w, "email", person.email.as_deref())?;
    write_opt_text_elem(w, "uri", person.uri.as_deref())?;
    w.write_event(Event::End(BytesEnd::new(tag_name)))?;
    Ok(())
}

fn write_atom_link<W: std::io::Write>(
    w: &mut Writer<W>,
    link: &AtomLink,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new("link");
    tag.push_attribute(("href", link.href.as_str()));
    if let Some(rel) = &link.rel {
        tag.push_attribute(("rel", rel.as_str()));
    }
    if let Some(type_) = &link.type_ {
        tag.push_attribute(("type", type_.as_str()));
    }
    if let Some(lang) = &link.hreflang {
        tag.push_attribute(("hreflang", lang.as_str()));
    }
    if let Some(title) = &link.title {
        tag.push_attribute(("title", title.as_str()));
    }
    if let Some(len) = link.length {
        tag.push_attribute(("length", len.to_string().as_str()));
    }
    w.write_event(Event::Empty(tag))?;
    Ok(())
}

fn write_atom_category<W: std::io::Write>(
    w: &mut Writer<W>,
    cat: &AtomCategory,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new("category");
    tag.push_attribute(("term", cat.term.as_str()));
    if let Some(scheme) = &cat.scheme {
        tag.push_attribute(("scheme", scheme.as_str()));
    }
    if let Some(label) = &cat.label {
        tag.push_attribute(("label", label.as_str()));
    }
    w.write_event(Event::Empty(tag))?;
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
    write_opt_text_elem(w, "podcast:medium", podcast.medium.as_deref())?;
    write_opt_text_elem(w, "podcast:license", podcast.license.as_deref())?;
    for person in &podcast.persons {
        write_podcast_person(w, person)?;
    }
    if let Some(loc) = &podcast.location {
        write_podcast_location(w, loc)?;
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
    for trailer in &podcast.trailers {
        let mut tag = BytesStart::new("podcast:trailer");
        tag.push_attribute(("url", trailer.url.as_str()));
        if let Some(pd) = &trailer.pub_date {
            tag.push_attribute(("pubDate", format_rss2_date(pd).as_str()));
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
        w.write_event(Event::Empty(tag))?;
    }
    if let Some(ch) = &podcast.chapters {
        let mut tag = BytesStart::new("podcast:chapters");
        tag.push_attribute(("url", ch.url.as_str()));
        tag.push_attribute(("type", ch.type_.as_str()));
        w.write_event(Event::Empty(tag))?;
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
        w.write_event(Event::Empty(tag))?;
    }
    if let Some(thumb) = &media.thumbnail {
        let mut tag = BytesStart::new("media:thumbnail");
        tag.push_attribute(("url", thumb.url.as_str()));
        w.write_event(Event::Empty(tag))?;
    }
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

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::super::types::{AtomContent, AtomEntry, AtomFeed, AtomLink, AtomPerson, AtomText};

    #[test]
    fn builder_enforces_all_required_fields() {
        let ts = Timestamp::now();
        let feed = AtomFeed::builder()
            .updated(ts)
            .id("urn:uuid:test")
            .title("Test Feed")
            .build();
        assert_eq!(feed.id, "urn:uuid:test");
        assert_eq!(feed.title, AtomText::Text("Test Feed".into()));
        assert_eq!(feed.updated, ts);
    }

    #[test]
    fn feed_serializes_to_valid_xml() {
        let ts = Timestamp::now();
        let feed = AtomFeed::builder()
            .id("https://example.com/feed")
            .title("My Blog")
            .updated(ts)
            .author(AtomPerson::new("Author"))
            .link(AtomLink::alternate("https://example.com"))
            .entry(
                AtomEntry::new("https://example.com/1", "Post 1", ts)
                    .with_content(AtomContent::html("<p>Hello</p>")),
            )
            .build();

        let xml = feed.to_string();
        assert!(xml.contains("<?xml"));
        assert!(xml.contains(r#"xmlns="http://www.w3.org/2005/Atom""#));
        assert!(xml.contains("<id>https://example.com/feed</id>"));
        assert!(xml.contains("My Blog"));
        assert!(xml.contains("<entry>"));
        assert!(xml.contains("Post 1"));
    }

    #[test]
    fn atom_text_preserves_type() {
        let text = AtomText::html("<b>bold</b>");
        assert_eq!(text.type_attr(), "html");
        assert_eq!(text.value(), "<b>bold</b>");
    }
}
