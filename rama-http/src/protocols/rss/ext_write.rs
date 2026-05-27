//! Shared serialization for extension namespaces (`itunes:`, `podcast:`,
//! `dc:`, `media:`). These elements are namespace-identical regardless of the
//! host format, so RSS 2.0 and Atom serialization both route through here.

use jiff::Timestamp;
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};

use super::feed_ext::{
    DublinCore, DublinCoreFeed, ITunes, ITunesFeed, MediaRss, Podcast, PodcastFeed,
    PodcastLocation, PodcastPerson, PodcastRemoteItem,
};
use super::rss2::format_rss2_date;
use super::ser::{XmlWriteError, write_opt_text_elem, write_text_elem};

pub(super) fn write_itunes_feed<W: std::io::Write>(
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
        write_text_elem(
            w,
            "itunes:explicit",
            if explicit { "true" } else { "false" },
        )?;
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

pub(super) fn write_itunes_item<W: std::io::Write>(
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
        write_text_elem(
            w,
            "itunes:explicit",
            if explicit { "true" } else { "false" },
        )?;
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

pub(super) fn write_podcast_feed<W: std::io::Write>(
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
    for ri in &podcast.remote_items {
        write_podcast_remote_item(w, ri)?;
    }
    Ok(())
}

pub(super) fn write_podcast_item<W: std::io::Write>(
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

fn write_podcast_remote_item<W: std::io::Write>(
    w: &mut Writer<W>,
    ri: &PodcastRemoteItem,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new("podcast:remoteItem");
    tag.push_attribute(("feedGuid", ri.feed_guid.as_str()));
    if let Some(item_guid) = &ri.item_guid {
        tag.push_attribute(("itemGuid", item_guid.as_str()));
    }
    if let Some(feed_url) = &ri.feed_url {
        tag.push_attribute(("feedUrl", feed_url.as_str()));
    }
    if let Some(title) = &ri.title {
        tag.push_attribute(("title", title.as_str()));
    }
    if let Some(medium) = &ri.medium {
        tag.push_attribute(("medium", medium.as_str()));
    }
    w.write_event(Event::Empty(tag))?;
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

/// Shared accessor so the item-level [`DublinCore`] and feed-level
/// [`DublinCoreFeed`] (identical field sets) reuse one writer.
trait DcFields {
    fn fields(&self) -> DcView<'_>;
}

struct DcView<'a> {
    title: Option<&'a str>,
    creator: Option<&'a str>,
    subject: Option<&'a str>,
    description: Option<&'a str>,
    publisher: Option<&'a str>,
    contributor: Option<&'a str>,
    date: Option<&'a Timestamp>,
    type_: Option<&'a str>,
    format: Option<&'a str>,
    identifier: Option<&'a str>,
    source: Option<&'a str>,
    language: Option<&'a str>,
    relation: Option<&'a str>,
    coverage: Option<&'a str>,
    rights: Option<&'a str>,
}

macro_rules! impl_dc_fields {
    ($t:ty) => {
        impl DcFields for $t {
            fn fields(&self) -> DcView<'_> {
                DcView {
                    title: self.title.as_deref(),
                    creator: self.creator.as_deref(),
                    subject: self.subject.as_deref(),
                    description: self.description.as_deref(),
                    publisher: self.publisher.as_deref(),
                    contributor: self.contributor.as_deref(),
                    date: self.date.as_ref(),
                    type_: self.type_.as_deref(),
                    format: self.format.as_deref(),
                    identifier: self.identifier.as_deref(),
                    source: self.source.as_deref(),
                    language: self.language.as_deref(),
                    relation: self.relation.as_deref(),
                    coverage: self.coverage.as_deref(),
                    rights: self.rights.as_deref(),
                }
            }
        }
    };
}

impl_dc_fields!(DublinCore);
impl_dc_fields!(DublinCoreFeed);

pub(super) fn write_dc_item_fields<W: std::io::Write>(
    w: &mut Writer<W>,
    dc: &DublinCore,
) -> Result<(), XmlWriteError> {
    write_dc_fields(w, &dc.fields())
}

pub(super) fn write_dc_feed_fields<W: std::io::Write>(
    w: &mut Writer<W>,
    dc: &DublinCoreFeed,
) -> Result<(), XmlWriteError> {
    write_dc_fields(w, &dc.fields())
}

fn write_dc_fields<W: std::io::Write>(
    w: &mut Writer<W>,
    dc: &DcView<'_>,
) -> Result<(), XmlWriteError> {
    write_opt_text_elem(w, "dc:title", dc.title)?;
    write_opt_text_elem(w, "dc:creator", dc.creator)?;
    write_opt_text_elem(w, "dc:subject", dc.subject)?;
    write_opt_text_elem(w, "dc:description", dc.description)?;
    write_opt_text_elem(w, "dc:publisher", dc.publisher)?;
    write_opt_text_elem(w, "dc:contributor", dc.contributor)?;
    if let Some(d) = dc.date {
        write_text_elem(w, "dc:date", &d.to_string())?;
    }
    write_opt_text_elem(w, "dc:type", dc.type_)?;
    write_opt_text_elem(w, "dc:format", dc.format)?;
    write_opt_text_elem(w, "dc:identifier", dc.identifier)?;
    write_opt_text_elem(w, "dc:source", dc.source)?;
    write_opt_text_elem(w, "dc:language", dc.language)?;
    write_opt_text_elem(w, "dc:relation", dc.relation)?;
    write_opt_text_elem(w, "dc:coverage", dc.coverage)?;
    write_opt_text_elem(w, "dc:rights", dc.rights)?;
    Ok(())
}

pub(super) fn write_media_item<W: std::io::Write>(
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
