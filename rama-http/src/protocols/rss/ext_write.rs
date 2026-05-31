//! Shared serialization for extension namespaces (`itunes:`, `podcast:`,
//! `dc:`, `media:`). These elements are namespace-identical regardless of the
//! host format, so RSS 2.0 and Atom serialization both route through here.

use jiff::Timestamp;
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};

use super::ext_names::{dc, itunes, media, podcast};
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
    write_opt_text_elem(w, itunes::TITLE_TAG, itunes.title.as_deref())?;
    write_opt_text_elem(w, itunes::AUTHOR_TAG, itunes.author.as_deref())?;
    write_opt_text_elem(w, itunes::SUBTITLE_TAG, itunes.subtitle.as_deref())?;
    write_opt_text_elem(w, itunes::SUMMARY_TAG, itunes.summary.as_deref())?;
    if let Some(img) = &itunes.image {
        let mut tag = BytesStart::new(itunes::IMAGE_TAG);
        tag.push_attribute(("href", img.as_str()));
        w.write_event(Event::Empty(tag))?;
    }
    for cat in &itunes.categories {
        let mut tag = BytesStart::new(itunes::CATEGORY_TAG);
        tag.push_attribute(("text", cat.as_str()));
        w.write_event(Event::Empty(tag))?;
    }
    if let Some(explicit) = itunes.explicit {
        write_text_elem(
            w,
            itunes::EXPLICIT_TAG,
            if explicit { "true" } else { "false" },
        )?;
    }
    write_opt_text_elem(w, itunes::TYPE_TAG, itunes.type_.as_deref())?;
    write_opt_text_elem(w, itunes::NEW_FEED_URL_TAG, itunes.new_feed_url.as_deref())?;
    if let Some(block) = itunes.block {
        write_text_elem(w, itunes::BLOCK_TAG, if block { "Yes" } else { "No" })?;
    }
    if let Some(complete) = itunes.complete {
        write_text_elem(w, itunes::COMPLETE_TAG, if complete { "Yes" } else { "No" })?;
    }
    if itunes.owner_name.is_some() || itunes.owner_email.is_some() {
        w.write_event(Event::Start(BytesStart::new(itunes::OWNER_TAG)))?;
        write_opt_text_elem(w, itunes::NAME_TAG, itunes.owner_name.as_deref())?;
        write_opt_text_elem(w, itunes::EMAIL_TAG, itunes.owner_email.as_deref())?;
        w.write_event(Event::End(BytesEnd::new(itunes::OWNER_TAG)))?;
    }
    Ok(())
}

pub(super) fn write_itunes_item<W: std::io::Write>(
    w: &mut Writer<W>,
    itunes: &ITunes,
) -> Result<(), XmlWriteError> {
    write_opt_text_elem(w, itunes::TITLE_TAG, itunes.title.as_deref())?;
    write_opt_text_elem(w, itunes::AUTHOR_TAG, itunes.author.as_deref())?;
    write_opt_text_elem(w, itunes::SUBTITLE_TAG, itunes.subtitle.as_deref())?;
    write_opt_text_elem(w, itunes::SUMMARY_TAG, itunes.summary.as_deref())?;
    if let Some(img) = &itunes.image {
        let mut tag = BytesStart::new(itunes::IMAGE_TAG);
        tag.push_attribute(("href", img.as_str()));
        w.write_event(Event::Empty(tag))?;
    }
    write_opt_text_elem(w, itunes::DURATION_TAG, itunes.duration.as_deref())?;
    if let Some(explicit) = itunes.explicit {
        write_text_elem(
            w,
            itunes::EXPLICIT_TAG,
            if explicit { "true" } else { "false" },
        )?;
    }
    if let Some(ep) = itunes.episode {
        write_text_elem(w, itunes::EPISODE_TAG, &ep.to_string())?;
    }
    if let Some(s) = itunes.season {
        write_text_elem(w, itunes::SEASON_TAG, &s.to_string())?;
    }
    write_opt_text_elem(w, itunes::EPISODE_TYPE_TAG, itunes.episode_type.as_deref())?;
    write_opt_text_elem(w, itunes::KEYWORDS_TAG, itunes.keywords.as_deref())?;
    if let Some(block) = itunes.block {
        write_text_elem(w, itunes::BLOCK_TAG, if block { "Yes" } else { "No" })?;
    }
    Ok(())
}

pub(super) fn write_podcast_feed<W: std::io::Write>(
    w: &mut Writer<W>,
    pc: &PodcastFeed,
) -> Result<(), XmlWriteError> {
    write_opt_text_elem(w, podcast::GUID_TAG, pc.guid.as_deref())?;
    if let Some(locked) = pc.locked {
        write_text_elem(w, podcast::LOCKED_TAG, if locked { "yes" } else { "no" })?;
    }
    for f in &pc.fundings {
        let mut tag = BytesStart::new(podcast::FUNDING_TAG);
        tag.push_attribute(("url", f.url.as_str()));
        if let Some(title) = &f.title {
            w.write_event(Event::Start(tag))?;
            w.write_event(Event::Text(BytesText::new(title)))?;
            w.write_event(Event::End(BytesEnd::new(podcast::FUNDING_TAG)))?;
        } else {
            w.write_event(Event::Empty(tag))?;
        }
    }
    write_opt_text_elem(w, podcast::MEDIUM_TAG, pc.medium.as_deref())?;
    write_opt_text_elem(w, podcast::LICENSE_TAG, pc.license.as_deref())?;
    for person in &pc.persons {
        write_podcast_person(w, person)?;
    }
    if let Some(loc) = &pc.location {
        write_podcast_location(w, loc)?;
    }
    for trailer in &pc.trailers {
        let mut tag = BytesStart::new(podcast::TRAILER_TAG);
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
        w.write_event(Event::End(BytesEnd::new(podcast::TRAILER_TAG)))?;
    }
    for ri in &pc.remote_items {
        write_podcast_remote_item(w, ri)?;
    }
    Ok(())
}

pub(super) fn write_podcast_item<W: std::io::Write>(
    w: &mut Writer<W>,
    pc: &Podcast,
) -> Result<(), XmlWriteError> {
    for tr in &pc.transcripts {
        let mut tag = BytesStart::new(podcast::TRANSCRIPT_TAG);
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
    if let Some(ch) = &pc.chapters {
        let mut tag = BytesStart::new(podcast::CHAPTERS_TAG);
        tag.push_attribute(("url", ch.url.as_str()));
        tag.push_attribute(("type", ch.type_.as_str()));
        w.write_event(Event::Empty(tag))?;
    }
    for sb in &pc.soundbites {
        let mut tag = BytesStart::new(podcast::SOUNDBITE_TAG);
        tag.push_attribute(("startTime", sb.start_time.to_string().as_str()));
        tag.push_attribute(("duration", sb.duration.to_string().as_str()));
        if let Some(title) = &sb.title {
            w.write_event(Event::Start(tag))?;
            w.write_event(Event::Text(BytesText::new(title)))?;
            w.write_event(Event::End(BytesEnd::new(podcast::SOUNDBITE_TAG)))?;
        } else {
            w.write_event(Event::Empty(tag))?;
        }
    }
    for person in &pc.persons {
        write_podcast_person(w, person)?;
    }
    if let Some(loc) = &pc.location {
        write_podcast_location(w, loc)?;
    }
    if let Some(season) = &pc.season {
        let mut tag = BytesStart::new(podcast::SEASON_TAG);
        if let Some(name) = &season.name {
            tag.push_attribute(("name", name.as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&season.number.to_string())))?;
        w.write_event(Event::End(BytesEnd::new(podcast::SEASON_TAG)))?;
    }
    if let Some(ep) = &pc.episode {
        let mut tag = BytesStart::new(podcast::EPISODE_TAG);
        if let Some(display) = &ep.display {
            tag.push_attribute(("display", display.as_str()));
        }
        w.write_event(Event::Start(tag))?;
        w.write_event(Event::Text(BytesText::new(&ep.number.to_string())))?;
        w.write_event(Event::End(BytesEnd::new(podcast::EPISODE_TAG)))?;
    }
    Ok(())
}

fn write_podcast_remote_item<W: std::io::Write>(
    w: &mut Writer<W>,
    ri: &PodcastRemoteItem,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new(podcast::REMOTE_ITEM_TAG);
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
    let mut tag = BytesStart::new(podcast::PERSON_TAG);
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
    w.write_event(Event::End(BytesEnd::new(podcast::PERSON_TAG)))?;
    Ok(())
}

fn write_podcast_location<W: std::io::Write>(
    w: &mut Writer<W>,
    loc: &PodcastLocation,
) -> Result<(), XmlWriteError> {
    let mut tag = BytesStart::new(podcast::LOCATION_TAG);
    if let Some(geo) = &loc.geo {
        tag.push_attribute(("geo", geo.as_str()));
    }
    if let Some(osm) = &loc.osm {
        tag.push_attribute(("osm", osm.as_str()));
    }
    w.write_event(Event::Start(tag))?;
    w.write_event(Event::Text(BytesText::new(&loc.name)))?;
    w.write_event(Event::End(BytesEnd::new(podcast::LOCATION_TAG)))?;
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
    view: &DcView<'_>,
) -> Result<(), XmlWriteError> {
    write_opt_text_elem(w, dc::TITLE_TAG, view.title)?;
    write_opt_text_elem(w, dc::CREATOR_TAG, view.creator)?;
    write_opt_text_elem(w, dc::SUBJECT_TAG, view.subject)?;
    write_opt_text_elem(w, dc::DESCRIPTION_TAG, view.description)?;
    write_opt_text_elem(w, dc::PUBLISHER_TAG, view.publisher)?;
    write_opt_text_elem(w, dc::CONTRIBUTOR_TAG, view.contributor)?;
    if let Some(d) = view.date {
        write_text_elem(w, dc::DATE_TAG, &d.to_string())?;
    }
    write_opt_text_elem(w, dc::TYPE_TAG, view.type_)?;
    write_opt_text_elem(w, dc::FORMAT_TAG, view.format)?;
    write_opt_text_elem(w, dc::IDENTIFIER_TAG, view.identifier)?;
    write_opt_text_elem(w, dc::SOURCE_TAG, view.source)?;
    write_opt_text_elem(w, dc::LANGUAGE_TAG, view.language)?;
    write_opt_text_elem(w, dc::RELATION_TAG, view.relation)?;
    write_opt_text_elem(w, dc::COVERAGE_TAG, view.coverage)?;
    write_opt_text_elem(w, dc::RIGHTS_TAG, view.rights)?;
    Ok(())
}

pub(super) fn write_media_item<W: std::io::Write>(
    w: &mut Writer<W>,
    m: &MediaRss,
) -> Result<(), XmlWriteError> {
    for mc in &m.contents {
        let mut tag = BytesStart::new(media::CONTENT_TAG);
        if let Some(url) = &mc.url {
            tag.push_attribute(("url", url.as_str()));
        }
        if let Some(t) = &mc.type_ {
            tag.push_attribute(("type", t.as_str()));
        }
        if let Some(medium) = &mc.medium {
            tag.push_attribute(("medium", medium.as_str()));
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
            write_opt_text_elem(w, media::TITLE_TAG, mc.title.as_deref())?;
            write_opt_text_elem(w, media::DESCRIPTION_TAG, mc.description.as_deref())?;
            w.write_event(Event::End(BytesEnd::new(media::CONTENT_TAG)))?;
        } else {
            w.write_event(Event::Empty(tag))?;
        }
    }
    if let Some(thumb) = &m.thumbnail {
        let mut tag = BytesStart::new(media::THUMBNAIL_TAG);
        tag.push_attribute(("url", thumb.url.as_str()));
        if let Some(width) = thumb.width {
            tag.push_attribute(("width", width.to_string().as_str()));
        }
        if let Some(height) = thumb.height {
            tag.push_attribute(("height", height.to_string().as_str()));
        }
        w.write_event(Event::Empty(tag))?;
    }
    write_opt_text_elem(w, media::TITLE_TAG, m.title.as_deref())?;
    write_opt_text_elem(w, media::DESCRIPTION_TAG, m.description.as_deref())?;
    write_opt_text_elem(w, media::KEYWORDS_TAG, m.keywords.as_deref())?;
    write_opt_text_elem(w, media::RATING_TAG, m.rating.as_deref())?;
    Ok(())
}
