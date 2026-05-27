//! Lenient (default) and strict RSS 2.0 / Atom 1.0 parsing.
//!
//! The entry points are [`Feed::parse`] (lenient) and [`Feed::parse_strict`]
//! (strict). Lenient parsing silently skips elements it cannot understand;
//! strict parsing returns an error for any structural violation.

use jiff::Timestamp;
use quick_xml::{Reader, events::Event};
use rama_core::telemetry::tracing;

use super::atom::{AtomCategory, AtomContent, AtomEntry, AtomFeed, AtomLink, AtomPerson, AtomText};
use super::feed::Feed;
use super::feed_ext::{
    Content, DublinCore, DublinCoreFeed, FeedExtensions, ITunes, ITunesFeed, ItemExtensions,
    MediaContent, MediaRss, MediaThumbnail, Podcast, PodcastChapters, PodcastEpisode, PodcastFeed,
    PodcastFunding, PodcastLocation, PodcastPerson, PodcastRemoteItem, PodcastSeason,
    PodcastSoundbite, PodcastTrailer, PodcastTranscript,
};
use super::rss2::{Rss2Category, Rss2Enclosure, Rss2Feed, Rss2Guid, Rss2Image, Rss2Item};

// ---------------------------------------------------------------------------
// Public error type
// ---------------------------------------------------------------------------

/// Returned by strict-mode parsing when the document structure is invalid.
#[derive(Debug, Clone, PartialEq)]
pub struct FeedParseError {
    pub message: String,
}

impl FeedParseError {
    fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl std::fmt::Display for FeedParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "feed parse error: {}", self.message)
    }
}

impl std::error::Error for FeedParseError {}

// ---------------------------------------------------------------------------
// Parse entry points
// ---------------------------------------------------------------------------

pub(super) fn parse_feed(input: &str, strict: bool) -> Result<Feed, FeedParseError> {
    // Quick sniff for format detection before full parse.
    let trimmed = input.trim_start();
    let is_atom = detect_atom(trimmed);
    let is_rss = !is_atom && detect_rss(trimmed);

    if is_atom {
        parse_atom(input, strict).map(Feed::Atom)
    } else if is_rss {
        parse_rss2(input, strict).map(Feed::Rss2)
    } else if strict {
        Err(FeedParseError::new(
            "document is neither RSS 2.0 nor Atom 1.0",
        ))
    } else {
        // Try RSS 2.0 as a fallback
        parse_rss2(input, false)
            .map(Feed::Rss2)
            .or_else(|_err| parse_atom(input, false).map(Feed::Atom))
            .map_err(|_err| FeedParseError::new("unrecognized feed format"))
    }
}

fn detect_atom(s: &str) -> bool {
    // Look for `<feed` with the Atom namespace within the first few KB.
    let probe = probe_prefix(s, 2048);
    probe.contains("<feed") && (probe.contains("w3.org/2005/Atom") || probe.contains("<feed>"))
}

fn detect_rss(s: &str) -> bool {
    let probe = probe_prefix(s, 1024);
    probe.contains("<rss") || probe.contains("<channel")
}

/// Largest prefix of `s` no longer than `max` bytes, never splitting a
/// multi-byte UTF-8 char (plain byte slicing would panic on a non-boundary).
fn probe_prefix(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ---------------------------------------------------------------------------
// RSS 2.0 parser
// ---------------------------------------------------------------------------

fn parse_rss2(input: &str, strict: bool) -> Result<Rss2Feed, FeedParseError> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(true);

    // Working state
    let mut title = String::new();
    let mut link = String::new();
    let mut description = String::new();
    let mut language: Option<String> = None;
    let mut copyright: Option<String> = None;
    let mut managing_editor: Option<String> = None;
    let mut web_master: Option<String> = None;
    let mut pub_date: Option<Timestamp> = None;
    let mut last_build_date: Option<Timestamp> = None;
    let mut generator: Option<String> = None;
    let mut docs: Option<String> = None;
    let mut ttl: Option<u32> = None;
    let mut image: Option<Rss2Image> = None;
    let mut image_url = String::new();
    let mut image_title = String::new();
    let mut image_link = String::new();
    let mut image_width: Option<u32> = None;
    let mut image_height: Option<u32> = None;
    let mut image_description: Option<String> = None;
    let mut items: Vec<Rss2Item> = Vec::new();
    let mut feed_ext = FeedExtensions::default();
    let mut itunes_feed = ITunesFeed::default();
    let mut has_itunes = false;
    let mut dc_feed = DublinCoreFeed::default();
    let mut has_dc_feed = false;
    let mut podcast_feed = PodcastFeed::default();
    let mut has_podcast_feed = false;
    let mut in_itunes_owner = false;

    // Item working state
    let mut in_item = false;
    let mut in_image_block = false;
    let mut current_item = Rss2Item::default();
    let mut current_item_itunes = ITunes::default();
    let mut current_item_has_itunes = false;
    let mut current_item_content: Option<Content> = None;
    let mut current_item_dc = DublinCore::default();
    let mut current_item_has_dc = false;
    let mut current_item_media = MediaRss::default();
    let mut current_item_has_media = false;
    let mut current_item_podcast = Podcast::default();
    let mut current_item_has_podcast = false;

    // Pending attribute-bearing extension elements whose text/children arrive
    // between their start and end events.
    let mut in_media_content = false;
    let mut pending_media: Option<MediaContent> = None;
    let mut pending_person: Option<PodcastPerson> = None;
    let mut pending_location: Option<PodcastLocation> = None;
    let mut pending_funding: Option<PodcastFunding> = None;
    let mut pending_trailer: Option<PodcastTrailer> = None;
    let mut pending_soundbite: Option<PodcastSoundbite> = None;
    let mut pending_season: Option<PodcastSeason> = None;
    let mut pending_episode: Option<PodcastEpisode> = None;

    let mut text_buf = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                text_buf.clear();

                match full_tag.as_str() {
                    "item" => {
                        in_item = true;
                        current_item = Rss2Item::default();
                        current_item_itunes = ITunes::default();
                        current_item_has_itunes = false;
                        current_item_content = None;
                        current_item_dc = DublinCore::default();
                        current_item_has_dc = false;
                        current_item_media = MediaRss::default();
                        current_item_has_media = false;
                        current_item_podcast = Podcast::default();
                        current_item_has_podcast = false;
                    }
                    "image" if !in_item => {
                        in_image_block = true;
                    }
                    "enclosure" => {
                        // enclosure is an empty element with attributes
                        let url = attr_value(&e, b"url");
                        let length = attr_value(&e, b"length")
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or_default();
                        let type_ = attr_value(&e, b"type").unwrap_or_default();
                        if in_item {
                            current_item.enclosure = Some(Rss2Enclosure {
                                url: url.unwrap_or_default(),
                                length,
                                type_,
                            });
                        }
                    }
                    "guid" if in_item => {
                        let permalink = attr_value(&e, b"isPermaLink")
                            .map(|v| v != "false")
                            .unwrap_or(true);
                        // value is captured later on the text event
                        current_item.guid = Some(Rss2Guid {
                            value: String::new(),
                            permalink,
                        });
                    }
                    "itunes:image" => {
                        let href = attr_value(&e, b"href");
                        if in_item {
                            if let Some(v) = href {
                                current_item_itunes.image = Some(v);
                                current_item_has_itunes = true;
                            }
                        } else if let Some(v) = href {
                            itunes_feed.image = Some(v);
                            has_itunes = true;
                        }
                    }
                    "itunes:owner" if !in_item => {
                        in_itunes_owner = true;
                        has_itunes = true;
                    }
                    "media:content" => {
                        pending_media = Some(media_content_from_attrs(&e));
                        in_media_content = true;
                    }
                    "podcast:person" => {
                        pending_person = Some(podcast_person_from_attrs(&e));
                    }
                    "podcast:location" => {
                        pending_location = Some(podcast_location_from_attrs(&e));
                    }
                    "podcast:funding" => {
                        pending_funding = Some(PodcastFunding {
                            url: attr_value(&e, b"url").unwrap_or_default(),
                            title: None,
                        });
                    }
                    "podcast:trailer" => {
                        pending_trailer = Some(podcast_trailer_from_attrs(&e));
                    }
                    "podcast:soundbite" => {
                        pending_soundbite = Some(PodcastSoundbite {
                            start_time: attr_value(&e, b"startTime")
                                .and_then(|v| v.parse().ok())
                                .unwrap_or_default(),
                            duration: attr_value(&e, b"duration")
                                .and_then(|v| v.parse().ok())
                                .unwrap_or_default(),
                            title: None,
                        });
                    }
                    "podcast:season" => {
                        pending_season = Some(PodcastSeason {
                            number: 0,
                            name: attr_value(&e, b"name"),
                        });
                    }
                    "podcast:episode" => {
                        pending_episode = Some(PodcastEpisode {
                            number: 0.0,
                            display: attr_value(&e, b"display"),
                        });
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match full_tag.as_str() {
                    "enclosure" => {
                        let url = attr_value(&e, b"url");
                        let length = attr_value(&e, b"length")
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or_default();
                        let type_ = attr_value(&e, b"type").unwrap_or_default();
                        if in_item {
                            current_item.enclosure = Some(Rss2Enclosure {
                                url: url.unwrap_or_default(),
                                length,
                                type_,
                            });
                        }
                    }
                    "itunes:image" => {
                        let href = attr_value(&e, b"href");
                        if in_item {
                            if let Some(v) = href {
                                current_item_itunes.image = Some(v);
                                current_item_has_itunes = true;
                            }
                        } else if let Some(v) = href {
                            itunes_feed.image = Some(v);
                            has_itunes = true;
                        }
                    }
                    "itunes:category" => {
                        if let Some(v) = attr_value(&e, b"text") {
                            itunes_feed.categories.push(v);
                            has_itunes = true;
                        }
                    }
                    "media:content" if in_item => {
                        current_item_media
                            .contents
                            .push(media_content_from_attrs(&e));
                        current_item_has_media = true;
                    }
                    "media:thumbnail" if in_item => {
                        current_item_media.thumbnail = Some(media_thumbnail_from_attrs(&e));
                        current_item_has_media = true;
                    }
                    "podcast:transcript" if in_item => {
                        current_item_podcast.transcripts.push(PodcastTranscript {
                            url: attr_value(&e, b"url").unwrap_or_default(),
                            type_: attr_value(&e, b"type").unwrap_or_default(),
                            language: attr_value(&e, b"language"),
                            rel: attr_value(&e, b"rel"),
                        });
                        current_item_has_podcast = true;
                    }
                    "podcast:chapters" if in_item => {
                        current_item_podcast.chapters = Some(PodcastChapters {
                            url: attr_value(&e, b"url").unwrap_or_default(),
                            type_: attr_value(&e, b"type").unwrap_or_default(),
                        });
                        current_item_has_podcast = true;
                    }
                    "podcast:remoteItem" if !in_item => {
                        podcast_feed
                            .remote_items
                            .push(podcast_remote_item_from_attrs(&e));
                        has_podcast_feed = true;
                    }
                    "podcast:person" => {
                        let p = podcast_person_from_attrs(&e);
                        if in_item {
                            current_item_podcast.persons.push(p);
                            current_item_has_podcast = true;
                        } else {
                            podcast_feed.persons.push(p);
                            has_podcast_feed = true;
                        }
                    }
                    "podcast:location" => {
                        let l = podcast_location_from_attrs(&e);
                        if in_item {
                            current_item_podcast.location = Some(l);
                            current_item_has_podcast = true;
                        } else {
                            podcast_feed.location = Some(l);
                            has_podcast_feed = true;
                        }
                    }
                    "podcast:funding" if !in_item => {
                        podcast_feed.fundings.push(PodcastFunding {
                            url: attr_value(&e, b"url").unwrap_or_default(),
                            title: None,
                        });
                        has_podcast_feed = true;
                    }
                    "podcast:trailer" if !in_item => {
                        podcast_feed.trailers.push(podcast_trailer_from_attrs(&e));
                        has_podcast_feed = true;
                    }
                    "podcast:soundbite" if in_item => {
                        current_item_podcast.soundbites.push(PodcastSoundbite {
                            start_time: attr_value(&e, b"startTime")
                                .and_then(|v| v.parse().ok())
                                .unwrap_or_default(),
                            duration: attr_value(&e, b"duration")
                                .and_then(|v| v.parse().ok())
                                .unwrap_or_default(),
                            title: None,
                        });
                        current_item_has_podcast = true;
                    }
                    "podcast:season" if in_item => {
                        current_item_podcast.season = Some(PodcastSeason {
                            number: 0,
                            name: attr_value(&e, b"name"),
                        });
                        current_item_has_podcast = true;
                    }
                    "podcast:episode" if in_item => {
                        current_item_podcast.episode = Some(PodcastEpisode {
                            number: 0.0,
                            display: attr_value(&e, b"display"),
                        });
                        current_item_has_podcast = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if let Ok(t) = e.unescape() {
                    text_buf.push_str(&t);
                }
            }
            Ok(Event::CData(e)) => {
                if let Ok(t) = std::str::from_utf8(e.as_ref()) {
                    text_buf.push_str(t);
                }
            }
            Ok(Event::End(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();

                let text = std::mem::take(&mut text_buf);

                if in_item {
                    match full_tag.as_str() {
                        "title" => current_item.title = Some(text),
                        "link" => current_item.link = Some(text),
                        "description" => current_item.description = Some(text),
                        "author" => current_item.author = Some(text),
                        "comments" => current_item.comments = Some(text),
                        "pubDate" => {
                            current_item.pub_date = parse_rss2_date(&text);
                        }
                        "guid" => {
                            if let Some(guid) = &mut current_item.guid {
                                guid.value = text;
                            }
                        }
                        "category" => {
                            current_item.categories.push(Rss2Category::new(text));
                        }
                        "itunes:title" => {
                            current_item_itunes.title = Some(text);
                            current_item_has_itunes = true;
                        }
                        "itunes:author" => {
                            current_item_itunes.author = Some(text);
                            current_item_has_itunes = true;
                        }
                        "itunes:subtitle" => {
                            current_item_itunes.subtitle = Some(text);
                            current_item_has_itunes = true;
                        }
                        "itunes:summary" => {
                            current_item_itunes.summary = Some(text);
                            current_item_has_itunes = true;
                        }
                        "itunes:duration" => {
                            current_item_itunes.duration = Some(text);
                            current_item_has_itunes = true;
                        }
                        "itunes:explicit" => {
                            current_item_itunes.explicit = Some(text == "true" || text == "yes");
                            current_item_has_itunes = true;
                        }
                        "itunes:episode" => {
                            current_item_itunes.episode = text.parse().ok();
                            current_item_has_itunes = true;
                        }
                        "itunes:season" => {
                            current_item_itunes.season = text.parse().ok();
                            current_item_has_itunes = true;
                        }
                        "itunes:episodeType" => {
                            current_item_itunes.episode_type = Some(text);
                            current_item_has_itunes = true;
                        }
                        "itunes:keywords" => {
                            current_item_itunes.keywords = Some(text);
                            current_item_has_itunes = true;
                        }
                        "itunes:block" => {
                            current_item_itunes.block = Some(is_truthy(&text));
                            current_item_has_itunes = true;
                        }
                        "content:encoded" => {
                            current_item_content = Some(Content {
                                encoded: Some(text),
                            });
                        }
                        "dc:title" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "title",
                            text,
                        ),
                        "dc:creator" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "creator",
                            text,
                        ),
                        "dc:subject" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "subject",
                            text,
                        ),
                        "dc:description" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "description",
                            text,
                        ),
                        "dc:publisher" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "publisher",
                            text,
                        ),
                        "dc:contributor" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "contributor",
                            text,
                        ),
                        "dc:date" => {
                            set_dc(&mut current_item_dc, &mut current_item_has_dc, "date", text)
                        }
                        "dc:type" => {
                            set_dc(&mut current_item_dc, &mut current_item_has_dc, "type", text)
                        }
                        "dc:format" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "format",
                            text,
                        ),
                        "dc:identifier" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "identifier",
                            text,
                        ),
                        "dc:source" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "source",
                            text,
                        ),
                        "dc:language" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "language",
                            text,
                        ),
                        "dc:relation" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "relation",
                            text,
                        ),
                        "dc:coverage" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "coverage",
                            text,
                        ),
                        "dc:rights" => set_dc(
                            &mut current_item_dc,
                            &mut current_item_has_dc,
                            "rights",
                            text,
                        ),
                        "media:content" => {
                            if let Some(m) = pending_media.take() {
                                current_item_media.contents.push(m);
                                current_item_has_media = true;
                            }
                            in_media_content = false;
                        }
                        "media:title" => {
                            if in_media_content {
                                if let Some(m) = &mut pending_media {
                                    m.title = Some(text);
                                }
                            } else {
                                current_item_media.title = Some(text);
                                current_item_has_media = true;
                            }
                        }
                        "media:description" => {
                            if in_media_content {
                                if let Some(m) = &mut pending_media {
                                    m.description = Some(text);
                                }
                            } else {
                                current_item_media.description = Some(text);
                                current_item_has_media = true;
                            }
                        }
                        "media:keywords" => {
                            current_item_media.keywords = Some(text);
                            current_item_has_media = true;
                        }
                        "media:rating" => {
                            current_item_media.rating = Some(text);
                            current_item_has_media = true;
                        }
                        "podcast:person" => {
                            if let Some(mut p) = pending_person.take() {
                                p.name = text;
                                current_item_podcast.persons.push(p);
                                current_item_has_podcast = true;
                            }
                        }
                        "podcast:location" => {
                            if let Some(mut l) = pending_location.take() {
                                l.name = text;
                                current_item_podcast.location = Some(l);
                                current_item_has_podcast = true;
                            }
                        }
                        "podcast:soundbite" => {
                            if let Some(mut s) = pending_soundbite.take() {
                                if !text.is_empty() {
                                    s.title = Some(text);
                                }
                                current_item_podcast.soundbites.push(s);
                                current_item_has_podcast = true;
                            }
                        }
                        "podcast:season" => {
                            if let Some(mut s) = pending_season.take() {
                                s.number = text.trim().parse().unwrap_or(0);
                                current_item_podcast.season = Some(s);
                                current_item_has_podcast = true;
                            }
                        }
                        "podcast:episode" => {
                            if let Some(mut ep) = pending_episode.take() {
                                ep.number = text.trim().parse().unwrap_or(0.0);
                                current_item_podcast.episode = Some(ep);
                                current_item_has_podcast = true;
                            }
                        }
                        "item" => {
                            if current_item_has_itunes {
                                current_item.extensions.itunes = Some(current_item_itunes.clone());
                            }
                            if let Some(c) = current_item_content.take() {
                                current_item.extensions.content = Some(c);
                            }
                            if current_item_has_dc {
                                current_item.extensions.dublin_core = Some(current_item_dc.clone());
                            }
                            if current_item_has_media {
                                current_item.extensions.media = Some(current_item_media.clone());
                            }
                            if current_item_has_podcast {
                                current_item.extensions.podcast =
                                    Some(current_item_podcast.clone());
                            }
                            items.push(std::mem::take(&mut current_item));
                            in_item = false;
                        }
                        _ => {}
                    }
                } else if in_image_block {
                    match full_tag.as_str() {
                        "url" => image_url = text,
                        "title" => image_title = text,
                        "link" => image_link = text,
                        "width" => image_width = text.parse().ok(),
                        "height" => image_height = text.parse().ok(),
                        "description" => image_description = Some(text),
                        "image" => {
                            in_image_block = false;
                            image = Some(Rss2Image {
                                url: std::mem::take(&mut image_url),
                                title: std::mem::take(&mut image_title),
                                link: std::mem::take(&mut image_link),
                                width: image_width.take(),
                                height: image_height.take(),
                                description: image_description.take(),
                            });
                        }
                        _ => {}
                    }
                } else {
                    // Channel-level
                    match full_tag.as_str() {
                        "title" => title = text,
                        "link" => link = text,
                        "description" => description = text,
                        "language" => language = Some(text),
                        "copyright" => copyright = Some(text),
                        "managingEditor" => managing_editor = Some(text),
                        "webMaster" => web_master = Some(text),
                        "pubDate" => pub_date = parse_rss2_date(&text),
                        "lastBuildDate" => last_build_date = parse_rss2_date(&text),
                        "generator" => generator = Some(text),
                        "ttl" => ttl = text.parse().ok(),
                        "itunes:author" => {
                            itunes_feed.author = Some(text);
                            has_itunes = true;
                        }
                        "itunes:title" => {
                            itunes_feed.title = Some(text);
                            has_itunes = true;
                        }
                        "itunes:subtitle" => {
                            itunes_feed.subtitle = Some(text);
                            has_itunes = true;
                        }
                        "itunes:summary" => {
                            itunes_feed.summary = Some(text);
                            has_itunes = true;
                        }
                        "itunes:type" => {
                            itunes_feed.type_ = Some(text);
                            has_itunes = true;
                        }
                        "itunes:explicit" => {
                            itunes_feed.explicit = Some(text == "true" || text == "yes");
                            has_itunes = true;
                        }
                        "docs" => docs = Some(text),
                        "itunes:new-feed-url" => {
                            itunes_feed.new_feed_url = Some(text);
                            has_itunes = true;
                        }
                        "itunes:block" => {
                            itunes_feed.block = Some(is_truthy(&text));
                            has_itunes = true;
                        }
                        "itunes:complete" => {
                            itunes_feed.complete = Some(is_truthy(&text));
                            has_itunes = true;
                        }
                        "itunes:name" if in_itunes_owner => {
                            itunes_feed.owner_name = Some(text);
                            has_itunes = true;
                        }
                        "itunes:email" if in_itunes_owner => {
                            itunes_feed.owner_email = Some(text);
                            has_itunes = true;
                        }
                        "itunes:owner" => in_itunes_owner = false,
                        "dc:title" => set_dc_feed(&mut dc_feed, &mut has_dc_feed, "title", text),
                        "dc:creator" => {
                            set_dc_feed(&mut dc_feed, &mut has_dc_feed, "creator", text)
                        }
                        "dc:subject" => {
                            set_dc_feed(&mut dc_feed, &mut has_dc_feed, "subject", text)
                        }
                        "dc:description" => {
                            set_dc_feed(&mut dc_feed, &mut has_dc_feed, "description", text)
                        }
                        "dc:publisher" => {
                            set_dc_feed(&mut dc_feed, &mut has_dc_feed, "publisher", text)
                        }
                        "dc:contributor" => {
                            set_dc_feed(&mut dc_feed, &mut has_dc_feed, "contributor", text)
                        }
                        "dc:date" => set_dc_feed(&mut dc_feed, &mut has_dc_feed, "date", text),
                        "dc:type" => set_dc_feed(&mut dc_feed, &mut has_dc_feed, "type", text),
                        "dc:format" => set_dc_feed(&mut dc_feed, &mut has_dc_feed, "format", text),
                        "dc:identifier" => {
                            set_dc_feed(&mut dc_feed, &mut has_dc_feed, "identifier", text)
                        }
                        "dc:source" => set_dc_feed(&mut dc_feed, &mut has_dc_feed, "source", text),
                        "dc:language" => {
                            set_dc_feed(&mut dc_feed, &mut has_dc_feed, "language", text)
                        }
                        "dc:relation" => {
                            set_dc_feed(&mut dc_feed, &mut has_dc_feed, "relation", text)
                        }
                        "dc:coverage" => {
                            set_dc_feed(&mut dc_feed, &mut has_dc_feed, "coverage", text)
                        }
                        "dc:rights" => set_dc_feed(&mut dc_feed, &mut has_dc_feed, "rights", text),
                        "podcast:guid" => {
                            podcast_feed.guid = Some(text);
                            has_podcast_feed = true;
                        }
                        "podcast:locked" => {
                            podcast_feed.locked = Some(is_truthy(&text));
                            has_podcast_feed = true;
                        }
                        "podcast:medium" => {
                            podcast_feed.medium = Some(text);
                            has_podcast_feed = true;
                        }
                        "podcast:license" => {
                            podcast_feed.license = Some(text);
                            has_podcast_feed = true;
                        }
                        "podcast:person" => {
                            if let Some(mut p) = pending_person.take() {
                                p.name = text;
                                podcast_feed.persons.push(p);
                                has_podcast_feed = true;
                            }
                        }
                        "podcast:location" => {
                            if let Some(mut l) = pending_location.take() {
                                l.name = text;
                                podcast_feed.location = Some(l);
                                has_podcast_feed = true;
                            }
                        }
                        "podcast:funding" => {
                            if let Some(mut f) = pending_funding.take() {
                                if !text.is_empty() {
                                    f.title = Some(text);
                                }
                                podcast_feed.fundings.push(f);
                                has_podcast_feed = true;
                            }
                        }
                        "podcast:trailer" => {
                            if let Some(mut t) = pending_trailer.take() {
                                t.title = text;
                                podcast_feed.trailers.push(t);
                                has_podcast_feed = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                if strict {
                    return Err(FeedParseError::new(format!("xml error: {e}")));
                }
                tracing::debug!("rss2 parse xml error (lenient): {e}");
                break;
            }
            _ => {}
        }
    }

    if strict && title.is_empty() {
        return Err(FeedParseError::new(
            "RSS 2.0 channel missing required <title>",
        ));
    }
    if strict && link.is_empty() {
        return Err(FeedParseError::new(
            "RSS 2.0 channel missing required <link>",
        ));
    }

    if has_itunes {
        feed_ext.itunes = Some(itunes_feed);
    }
    if has_dc_feed {
        feed_ext.dublin_core = Some(dc_feed);
    }
    if has_podcast_feed {
        feed_ext.podcast = Some(podcast_feed);
    }

    Ok(Rss2Feed {
        title,
        link,
        description,
        language,
        copyright,
        managing_editor,
        web_master,
        pub_date,
        last_build_date,
        categories: Vec::new(),
        generator,
        docs,
        ttl,
        image,
        items,
        extensions: feed_ext,
    })
}

// ---------------------------------------------------------------------------
// Atom parser
// ---------------------------------------------------------------------------

fn parse_atom(input: &str, strict: bool) -> Result<AtomFeed, FeedParseError> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(true);

    let mut feed_id = String::new();
    let mut feed_title = AtomText::text("");
    let mut feed_updated = Timestamp::UNIX_EPOCH;
    let mut feed_authors: Vec<AtomPerson> = Vec::new();
    let mut feed_links: Vec<AtomLink> = Vec::new();
    let mut feed_categories: Vec<AtomCategory> = Vec::new();
    let mut feed_subtitle: Option<AtomText> = None;
    let mut feed_rights: Option<AtomText> = None;
    let mut feed_logo: Option<String> = None;
    let mut entries: Vec<AtomEntry> = Vec::new();

    let mut in_entry = false;
    let mut in_author = false;
    let mut in_feed_author = false;
    let mut current_entry_id = String::new();
    let mut current_entry_title = AtomText::text("");
    let mut current_entry_updated = Timestamp::UNIX_EPOCH;
    let mut current_entry_authors: Vec<AtomPerson> = Vec::new();
    let mut current_entry_links: Vec<AtomLink> = Vec::new();
    let mut current_entry_categories: Vec<AtomCategory> = Vec::new();
    let mut current_entry_summary: Option<AtomText> = None;
    let mut current_entry_content: Option<AtomContent> = None;
    let mut current_entry_published: Option<Timestamp> = None;
    let mut current_entry_ext = ItemExtensions::default();
    let mut current_author = AtomPerson::new("");
    let mut current_content_type = String::from("text");
    let mut current_title_type = String::from("text");
    let mut current_summary_type = String::from("text");

    let mut text_buf = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                text_buf.clear();

                match full_tag.as_str() {
                    "entry" => {
                        in_entry = true;
                        current_entry_id = String::new();
                        current_entry_title = AtomText::text("");
                        current_entry_updated = Timestamp::UNIX_EPOCH;
                        current_entry_authors = Vec::new();
                        current_entry_links = Vec::new();
                        current_entry_categories = Vec::new();
                        current_entry_summary = None;
                        current_entry_content = None;
                        current_entry_published = None;
                        current_entry_ext = ItemExtensions::default();
                    }
                    "author" => {
                        current_author = AtomPerson::new("");
                        if in_entry {
                            in_author = true;
                        } else {
                            in_feed_author = true;
                        }
                    }
                    "link" => {
                        let href = attr_value(&e, b"href").unwrap_or_default();
                        let rel = attr_value(&e, b"rel");
                        let type_ = attr_value(&e, b"type");
                        let length = attr_value(&e, b"length").and_then(|v| v.parse().ok());
                        let link = AtomLink {
                            href,
                            rel,
                            type_,
                            hreflang: None,
                            title: None,
                            length,
                        };
                        if in_entry {
                            current_entry_links.push(link);
                        } else {
                            feed_links.push(link);
                        }
                    }
                    "category" => {
                        let term = attr_value(&e, b"term").unwrap_or_default();
                        let scheme = attr_value(&e, b"scheme");
                        let label = attr_value(&e, b"label");
                        let cat = AtomCategory {
                            term,
                            scheme,
                            label,
                        };
                        if in_entry {
                            current_entry_categories.push(cat);
                        } else {
                            feed_categories.push(cat);
                        }
                    }
                    "title" => {
                        current_title_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "summary" => {
                        current_summary_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "content" => {
                        current_content_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match full_tag.as_str() {
                    "link" => {
                        let href = attr_value(&e, b"href").unwrap_or_default();
                        let rel = attr_value(&e, b"rel");
                        let type_ = attr_value(&e, b"type");
                        let length = attr_value(&e, b"length").and_then(|v| v.parse().ok());
                        let link = AtomLink {
                            href,
                            rel,
                            type_,
                            hreflang: None,
                            title: None,
                            length,
                        };
                        if in_entry {
                            current_entry_links.push(link);
                        } else {
                            feed_links.push(link);
                        }
                    }
                    "category" => {
                        let term = attr_value(&e, b"term").unwrap_or_default();
                        let scheme = attr_value(&e, b"scheme");
                        let label = attr_value(&e, b"label");
                        let cat = AtomCategory {
                            term,
                            scheme,
                            label,
                        };
                        if in_entry {
                            current_entry_categories.push(cat);
                        } else {
                            feed_categories.push(cat);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if let Ok(t) = e.unescape() {
                    text_buf.push_str(&t);
                }
            }
            Ok(Event::CData(e)) => {
                if let Ok(t) = std::str::from_utf8(e.as_ref()) {
                    text_buf.push_str(t);
                }
            }
            Ok(Event::End(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let text = std::mem::take(&mut text_buf);

                if in_author {
                    match full_tag.as_str() {
                        "name" => current_author.name = text,
                        "email" => current_author.email = Some(text),
                        "uri" => current_author.uri = Some(text),
                        "author" => {
                            current_entry_authors
                                .push(std::mem::replace(&mut current_author, AtomPerson::new("")));
                            in_author = false;
                        }
                        _ => {}
                    }
                } else if in_feed_author {
                    match full_tag.as_str() {
                        "name" => current_author.name = text,
                        "email" => current_author.email = Some(text),
                        "uri" => current_author.uri = Some(text),
                        "author" => {
                            feed_authors
                                .push(std::mem::replace(&mut current_author, AtomPerson::new("")));
                            in_feed_author = false;
                        }
                        _ => {}
                    }
                } else if in_entry {
                    match full_tag.as_str() {
                        "id" => current_entry_id = text,
                        "title" => {
                            current_entry_title = make_atom_text(&current_title_type, text);
                        }
                        "updated" => {
                            current_entry_updated =
                                parse_rfc3339_lax(&text).unwrap_or(Timestamp::UNIX_EPOCH);
                        }
                        "published" => {
                            current_entry_published = parse_rfc3339_lax(&text);
                        }
                        "summary" => {
                            current_entry_summary =
                                Some(make_atom_text(&current_summary_type, text));
                        }
                        "content" => {
                            let at = make_atom_text(&current_content_type, text);
                            current_entry_content = Some(AtomContent {
                                value: at,
                                src: None,
                            });
                        }
                        "entry" => {
                            let entry = AtomEntry {
                                id: std::mem::take(&mut current_entry_id),
                                title: std::mem::replace(
                                    &mut current_entry_title,
                                    AtomText::text(""),
                                ),
                                updated: current_entry_updated,
                                authors: std::mem::take(&mut current_entry_authors),
                                content: current_entry_content.take(),
                                links: std::mem::take(&mut current_entry_links),
                                summary: current_entry_summary.take(),
                                categories: std::mem::take(&mut current_entry_categories),
                                contributors: Vec::new(),
                                published: current_entry_published,
                                rights: None,
                                source: None,
                                extensions: std::mem::take(&mut current_entry_ext),
                            };
                            entries.push(entry);
                            in_entry = false;
                        }
                        _ => {}
                    }
                } else {
                    match full_tag.as_str() {
                        "id" => feed_id = text,
                        "title" => {
                            feed_title = make_atom_text(&current_title_type, text);
                        }
                        "updated" => {
                            feed_updated =
                                parse_rfc3339_lax(&text).unwrap_or(Timestamp::UNIX_EPOCH);
                        }
                        "subtitle" => feed_subtitle = Some(AtomText::text(text)),
                        "rights" => feed_rights = Some(AtomText::text(text)),
                        "logo" => feed_logo = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                if strict {
                    return Err(FeedParseError::new(format!("xml error: {e}")));
                }
                tracing::debug!("atom parse xml error (lenient): {e}");
                break;
            }
            _ => {}
        }
    }

    if strict && feed_id.is_empty() {
        return Err(FeedParseError::new("Atom feed missing required <id>"));
    }

    Ok(AtomFeed {
        id: feed_id,
        title: feed_title,
        updated: feed_updated,
        authors: feed_authors,
        links: feed_links,
        categories: feed_categories,
        contributors: Vec::new(),
        generator: None,
        icon: None,
        logo: feed_logo,
        rights: feed_rights,
        subtitle: feed_subtitle,
        entries,
        extensions: FeedExtensions::default(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn attr_value(e: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| {
            std::str::from_utf8(a.value.as_ref())
                .ok()
                .map(str::to_owned)
        })
}

fn parse_rss2_date(s: &str) -> Option<Timestamp> {
    use jiff::fmt::rfc2822;
    let s = s.trim();
    rfc2822::parse(s)
        .ok()
        .map(|zdt| zdt.timestamp())
        .or_else(|| parse_rfc3339_lax(s))
}

type Attrs<'a> = quick_xml::events::BytesStart<'a>;

fn media_content_from_attrs(e: &Attrs<'_>) -> MediaContent {
    MediaContent {
        url: attr_value(e, b"url"),
        type_: attr_value(e, b"type"),
        medium: attr_value(e, b"medium"),
        duration: attr_value(e, b"duration").and_then(|v| v.parse().ok()),
        width: attr_value(e, b"width").and_then(|v| v.parse().ok()),
        height: attr_value(e, b"height").and_then(|v| v.parse().ok()),
        file_size: attr_value(e, b"fileSize").and_then(|v| v.parse().ok()),
        bitrate: attr_value(e, b"bitrate").and_then(|v| v.parse().ok()),
        title: None,
        description: None,
    }
}

fn media_thumbnail_from_attrs(e: &Attrs<'_>) -> MediaThumbnail {
    MediaThumbnail {
        url: attr_value(e, b"url").unwrap_or_default(),
        width: attr_value(e, b"width").and_then(|v| v.parse().ok()),
        height: attr_value(e, b"height").and_then(|v| v.parse().ok()),
    }
}

fn podcast_person_from_attrs(e: &Attrs<'_>) -> PodcastPerson {
    PodcastPerson {
        name: String::new(),
        role: attr_value(e, b"role"),
        group: attr_value(e, b"group"),
        img: attr_value(e, b"img"),
        href: attr_value(e, b"href"),
    }
}

fn podcast_location_from_attrs(e: &Attrs<'_>) -> PodcastLocation {
    PodcastLocation {
        name: String::new(),
        geo: attr_value(e, b"geo"),
        osm: attr_value(e, b"osm"),
    }
}

fn podcast_trailer_from_attrs(e: &Attrs<'_>) -> PodcastTrailer {
    PodcastTrailer {
        title: String::new(),
        url: attr_value(e, b"url").unwrap_or_default(),
        pub_date: attr_value(e, b"pubDate").and_then(|v| parse_rss2_date(&v)),
        length: attr_value(e, b"length").and_then(|v| v.parse().ok()),
        type_: attr_value(e, b"type"),
        season: attr_value(e, b"season").and_then(|v| v.parse().ok()),
    }
}

fn podcast_remote_item_from_attrs(e: &Attrs<'_>) -> PodcastRemoteItem {
    PodcastRemoteItem {
        feed_guid: attr_value(e, b"feedGuid").unwrap_or_default(),
        item_guid: attr_value(e, b"itemGuid"),
        feed_url: attr_value(e, b"feedUrl"),
        title: attr_value(e, b"title"),
        medium: attr_value(e, b"medium"),
    }
}

/// `true` for the case-insensitive `"yes"`/`"true"` values used by the iTunes
/// and Podcasting boolean elements.
fn is_truthy(text: &str) -> bool {
    text.eq_ignore_ascii_case("yes") || text.eq_ignore_ascii_case("true")
}

// `DublinCore` (item) and `DublinCoreFeed` (feed) share the same flat field set;
// one macro generates a setter for each so the parser stays single-sourced.
macro_rules! impl_set_dc {
    ($name:ident, $t:ty) => {
        fn $name(dc: &mut $t, has: &mut bool, field: &str, text: String) {
            *has = true;
            match field {
                "title" => dc.title = Some(text),
                "creator" => dc.creator = Some(text),
                "subject" => dc.subject = Some(text),
                "description" => dc.description = Some(text),
                "publisher" => dc.publisher = Some(text),
                "contributor" => dc.contributor = Some(text),
                "date" => dc.date = parse_rss2_date(&text),
                "type" => dc.type_ = Some(text),
                "format" => dc.format = Some(text),
                "identifier" => dc.identifier = Some(text),
                "source" => dc.source = Some(text),
                "language" => dc.language = Some(text),
                "relation" => dc.relation = Some(text),
                "coverage" => dc.coverage = Some(text),
                "rights" => dc.rights = Some(text),
                _ => {}
            }
        }
    };
}

impl_set_dc!(set_dc, DublinCore);
impl_set_dc!(set_dc_feed, DublinCoreFeed);

fn parse_rfc3339_lax(s: &str) -> Option<Timestamp> {
    s.trim().parse::<Timestamp>().ok()
}

fn make_atom_text(type_attr: &str, value: String) -> AtomText {
    match type_attr {
        "html" | "text/html" => AtomText::Html(value),
        "xhtml" => AtomText::Xhtml(value),
        _ => AtomText::Text(value),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
            Content, DublinCore, DublinCoreFeed, FeedExtensions, ITunes, ITunesFeed,
            ItemExtensions, MediaContent, MediaRss, MediaThumbnail, Podcast, PodcastEpisode,
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
}
