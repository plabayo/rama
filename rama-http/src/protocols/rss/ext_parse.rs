//! Shared parsing of extension-namespace elements (`itunes:`, `podcast:`,
//! `dc:`, `media:`, `content:encoded`) for both the RSS 2.0 and Atom parsers.
//!
//! [`ItemExtAcc`] accumulates item-/entry-level extensions and [`FeedExtAcc`]
//! channel-/feed-level ones. A parser feeds resolved-namespace XML events for
//! the extension-prefixed elements to the matching accumulator; the accumulator
//! reports whether it consumed the event so the parser can fall back to its own
//! core-element handling.
//!
//! Routing is by **resolved namespace URI**, not literal element prefix, so any
//! prefix the feed binds to a recognised namespace works (e.g. a feed declaring
//! `xmlns:pod="https://podcastindex.org/namespace/1.0"` and writing
//! `<pod:person>` is parsed identically to `<podcast:person>`).

use quick_xml::name::ResolveResult;

use super::feed_ext::{
    Content, DublinCore, DublinCoreFeed, FeedExtensions, ITunes, ITunesFeed, ItemExtensions,
    MediaContent, MediaRss, MediaThumbnail, Podcast, PodcastChapters, PodcastEpisode, PodcastFeed,
    PodcastFunding, PodcastLocation, PodcastPerson, PodcastRemoteItem, PodcastSeason,
    PodcastSoundbite, PodcastTrailer, PodcastTranscript,
};
use super::parse::{Attrs, attr_value, parse_rss2_date};

/// Recognised XML namespaces. Anything outside this set is treated as unknown
/// and ignored by the accumulators.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Ns {
    /// No namespace — RSS 2.0 core elements (`<rss>`, `<channel>`, `<item>`, …).
    None,
    /// `http://www.w3.org/2005/Atom` — Atom 1.0 core.
    Atom,
    /// `http://www.itunes.com/dtds/podcast-1.0.dtd`.
    ITunes,
    /// `https://podcastindex.org/namespace/1.0`.
    Podcast,
    /// `http://purl.org/dc/elements/1.1/`.
    Dc,
    /// `http://search.yahoo.com/mrss/`.
    Media,
    /// `http://purl.org/rss/1.0/modules/content/` — carries `content:encoded`.
    Content,
    /// Any other / unknown namespace.
    Other,
}

/// Resolve a [`ResolveResult`] from `NsReader` into one of the namespaces we
/// recognise. Comparison is on the namespace URI bytes, so the actual prefix
/// the document uses is irrelevant.
pub(super) fn classify_ns(rr: &ResolveResult<'_>) -> Ns {
    match rr {
        ResolveResult::Unbound => Ns::None,
        ResolveResult::Bound(ns) => match ns.0 {
            b"http://www.w3.org/2005/Atom" => Ns::Atom,
            b"http://www.itunes.com/dtds/podcast-1.0.dtd" => Ns::ITunes,
            b"https://podcastindex.org/namespace/1.0" => Ns::Podcast,
            b"http://purl.org/dc/elements/1.1/" => Ns::Dc,
            b"http://search.yahoo.com/mrss/" => Ns::Media,
            b"http://purl.org/rss/1.0/modules/content/" => Ns::Content,
            _ => Ns::Other,
        },
        ResolveResult::Unknown(_) => Ns::Other,
    }
}

fn is_truthy(text: &str) -> bool {
    text.eq_ignore_ascii_case("yes") || text.eq_ignore_ascii_case("true")
}

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

fn podcast_funding_from_attrs(e: &Attrs<'_>) -> PodcastFunding {
    PodcastFunding {
        url: attr_value(e, b"url").unwrap_or_default(),
        title: None,
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

fn podcast_soundbite_from_attrs(e: &Attrs<'_>) -> PodcastSoundbite {
    PodcastSoundbite {
        start_time: attr_value(e, b"startTime")
            .and_then(|v| v.parse().ok())
            .unwrap_or_default(),
        duration: attr_value(e, b"duration")
            .and_then(|v| v.parse().ok())
            .unwrap_or_default(),
        title: None,
    }
}

fn podcast_transcript_from_attrs(e: &Attrs<'_>) -> PodcastTranscript {
    PodcastTranscript {
        url: attr_value(e, b"url").unwrap_or_default(),
        type_: attr_value(e, b"type").unwrap_or_default(),
        language: attr_value(e, b"language"),
        rel: attr_value(e, b"rel"),
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

// `DublinCore` (item) and `DublinCoreFeed` (feed) share the same flat field set;
// one macro generates a setter for each so parsing stays single-sourced.
macro_rules! impl_set_dc {
    ($name:ident, $t:ty) => {
        fn $name(dc: &mut $t, has: &mut bool, local: &str, text: String) {
            *has = true;
            match local {
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
                _ => *has = false,
            }
        }
    };
}

impl_set_dc!(set_dc_item, DublinCore);
impl_set_dc!(set_dc_feed, DublinCoreFeed);

/// Accumulates item-/entry-level extension elements into an [`ItemExtensions`].
#[derive(Default)]
pub(super) struct ItemExtAcc {
    itunes: ITunes,
    has_itunes: bool,
    dc: DublinCore,
    has_dc: bool,
    media: MediaRss,
    has_media: bool,
    podcast: Podcast,
    has_podcast: bool,
    content: Option<Content>,
    in_media_content: bool,
    pending_media: Option<MediaContent>,
    pending_person: Option<PodcastPerson>,
    pending_location: Option<PodcastLocation>,
    pending_soundbite: Option<PodcastSoundbite>,
    pending_season: Option<PodcastSeason>,
    pending_episode: Option<PodcastEpisode>,
}

impl ItemExtAcc {
    /// Handle a start event; returns `true` if the element was consumed.
    pub(super) fn on_start(&mut self, ns: Ns, local: &str, e: &Attrs<'_>) -> bool {
        match (ns, local) {
            (Ns::ITunes, "image") => {
                if let Some(href) = attr_value(e, b"href") {
                    self.itunes.image = Some(href);
                    self.has_itunes = true;
                }
            }
            (Ns::Media, "content") => {
                self.pending_media = Some(media_content_from_attrs(e));
                self.in_media_content = true;
            }
            (Ns::Podcast, "person") => self.pending_person = Some(podcast_person_from_attrs(e)),
            (Ns::Podcast, "location") => {
                self.pending_location = Some(podcast_location_from_attrs(e))
            }
            (Ns::Podcast, "soundbite") => {
                self.pending_soundbite = Some(podcast_soundbite_from_attrs(e));
            }
            (Ns::Podcast, "season") => {
                self.pending_season = Some(PodcastSeason {
                    number: 0,
                    name: attr_value(e, b"name"),
                });
            }
            (Ns::Podcast, "episode") => {
                self.pending_episode = Some(PodcastEpisode {
                    number: 0.0,
                    display: attr_value(e, b"display"),
                });
            }
            _ => return false,
        }
        true
    }

    /// Handle a self-closing element; returns `true` if consumed.
    pub(super) fn on_empty(&mut self, ns: Ns, local: &str, e: &Attrs<'_>) -> bool {
        match (ns, local) {
            (Ns::ITunes, "image") => {
                if let Some(href) = attr_value(e, b"href") {
                    self.itunes.image = Some(href);
                    self.has_itunes = true;
                }
            }
            (Ns::Media, "content") => {
                self.media.contents.push(media_content_from_attrs(e));
                self.has_media = true;
            }
            (Ns::Media, "thumbnail") => {
                self.media.thumbnail = Some(media_thumbnail_from_attrs(e));
                self.has_media = true;
            }
            (Ns::Podcast, "transcript") => {
                self.podcast
                    .transcripts
                    .push(podcast_transcript_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, "chapters") => {
                self.podcast.chapters = Some(PodcastChapters {
                    url: attr_value(e, b"url").unwrap_or_default(),
                    type_: attr_value(e, b"type").unwrap_or_default(),
                });
                self.has_podcast = true;
            }
            (Ns::Podcast, "person") => {
                self.podcast.persons.push(podcast_person_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, "location") => {
                self.podcast.location = Some(podcast_location_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, "soundbite") => {
                self.podcast
                    .soundbites
                    .push(podcast_soundbite_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, "season") => {
                self.podcast.season = Some(PodcastSeason {
                    number: 0,
                    name: attr_value(e, b"name"),
                });
                self.has_podcast = true;
            }
            (Ns::Podcast, "episode") => {
                self.podcast.episode = Some(PodcastEpisode {
                    number: 0.0,
                    display: attr_value(e, b"display"),
                });
                self.has_podcast = true;
            }
            _ => return false,
        }
        true
    }

    /// Handle an end event carrying the element's text. Returns `Some(text)`
    /// when the element was not consumed (so the caller can do its own
    /// core-element processing).
    pub(super) fn on_end(&mut self, ns: Ns, local: &str, text: String) -> Option<String> {
        match (ns, local) {
            // iTunes item text elements
            (Ns::ITunes, "title") => self.itunes.title = Some(text),
            (Ns::ITunes, "author") => self.itunes.author = Some(text),
            (Ns::ITunes, "subtitle") => self.itunes.subtitle = Some(text),
            (Ns::ITunes, "summary") => self.itunes.summary = Some(text),
            (Ns::ITunes, "duration") => self.itunes.duration = Some(text),
            (Ns::ITunes, "explicit") => self.itunes.explicit = Some(is_truthy(&text)),
            (Ns::ITunes, "episode") => self.itunes.episode = text.trim().parse().ok(),
            (Ns::ITunes, "season") => self.itunes.season = text.trim().parse().ok(),
            (Ns::ITunes, "episodeType") => self.itunes.episode_type = Some(text),
            (Ns::ITunes, "keywords") => self.itunes.keywords = Some(text),
            (Ns::ITunes, "block") => self.itunes.block = Some(is_truthy(&text)),
            // content:encoded
            (Ns::Content, "encoded") => {
                self.content = Some(Content {
                    encoded: Some(text),
                });
                return None;
            }
            // Media RSS
            (Ns::Media, "content") => {
                if let Some(m) = self.pending_media.take() {
                    self.media.contents.push(m);
                    self.has_media = true;
                }
                self.in_media_content = false;
                return None;
            }
            (Ns::Media, "title") => {
                if self.in_media_content {
                    if let Some(m) = &mut self.pending_media {
                        m.title = Some(text);
                    }
                } else {
                    self.media.title = Some(text);
                    self.has_media = true;
                }
                return None;
            }
            (Ns::Media, "description") => {
                if self.in_media_content {
                    if let Some(m) = &mut self.pending_media {
                        m.description = Some(text);
                    }
                } else {
                    self.media.description = Some(text);
                    self.has_media = true;
                }
                return None;
            }
            (Ns::Media, "keywords") => {
                self.media.keywords = Some(text);
                self.has_media = true;
                return None;
            }
            (Ns::Media, "rating") => {
                self.media.rating = Some(text);
                self.has_media = true;
                return None;
            }
            // Podcast 2.0 item-level pending finalizers
            (Ns::Podcast, "person") => {
                if let Some(mut p) = self.pending_person.take() {
                    p.name = text;
                    self.podcast.persons.push(p);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, "location") => {
                if let Some(mut l) = self.pending_location.take() {
                    l.name = text;
                    self.podcast.location = Some(l);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, "soundbite") => {
                if let Some(mut s) = self.pending_soundbite.take() {
                    if !text.is_empty() {
                        s.title = Some(text);
                    }
                    self.podcast.soundbites.push(s);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, "season") => {
                if let Some(mut s) = self.pending_season.take() {
                    s.number = text.trim().parse().unwrap_or(0);
                    self.podcast.season = Some(s);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, "episode") => {
                if let Some(mut ep) = self.pending_episode.take() {
                    ep.number = text.trim().parse().unwrap_or(0.0);
                    self.podcast.episode = Some(ep);
                    self.has_podcast = true;
                }
                return None;
            }
            // Dublin Core (any field)
            (Ns::Dc, field) => {
                set_dc_item(&mut self.dc, &mut self.has_dc, field, text);
                return None;
            }
            _ => return Some(text),
        }
        // Reached via the iTunes text arms above (they assign and fall through).
        self.has_itunes = true;
        None
    }

    pub(super) fn finish(self) -> ItemExtensions {
        ItemExtensions {
            itunes: self.has_itunes.then_some(self.itunes),
            podcast: self.has_podcast.then_some(self.podcast),
            dublin_core: self.has_dc.then_some(self.dc),
            content: self.content,
            media: self.has_media.then_some(self.media),
        }
    }
}

/// Accumulates channel-/feed-level extension elements into a [`FeedExtensions`].
#[derive(Default)]
pub(super) struct FeedExtAcc {
    itunes: ITunesFeed,
    has_itunes: bool,
    dc: DublinCoreFeed,
    has_dc: bool,
    podcast: PodcastFeed,
    has_podcast: bool,
    in_itunes_owner: bool,
    pending_person: Option<PodcastPerson>,
    pending_location: Option<PodcastLocation>,
    pending_funding: Option<PodcastFunding>,
    pending_trailer: Option<PodcastTrailer>,
}

impl FeedExtAcc {
    pub(super) fn on_start(&mut self, ns: Ns, local: &str, e: &Attrs<'_>) -> bool {
        match (ns, local) {
            (Ns::ITunes, "image") => {
                if let Some(href) = attr_value(e, b"href") {
                    self.itunes.image = Some(href);
                    self.has_itunes = true;
                }
            }
            (Ns::ITunes, "owner") => {
                self.in_itunes_owner = true;
                self.has_itunes = true;
            }
            (Ns::Podcast, "person") => self.pending_person = Some(podcast_person_from_attrs(e)),
            (Ns::Podcast, "location") => {
                self.pending_location = Some(podcast_location_from_attrs(e))
            }
            (Ns::Podcast, "funding") => self.pending_funding = Some(podcast_funding_from_attrs(e)),
            (Ns::Podcast, "trailer") => self.pending_trailer = Some(podcast_trailer_from_attrs(e)),
            _ => return false,
        }
        true
    }

    pub(super) fn on_empty(&mut self, ns: Ns, local: &str, e: &Attrs<'_>) -> bool {
        match (ns, local) {
            (Ns::ITunes, "image") => {
                if let Some(href) = attr_value(e, b"href") {
                    self.itunes.image = Some(href);
                    self.has_itunes = true;
                }
            }
            (Ns::ITunes, "category") => {
                if let Some(v) = attr_value(e, b"text") {
                    self.itunes.categories.push(v);
                    self.has_itunes = true;
                }
            }
            (Ns::Podcast, "remoteItem") => {
                self.podcast
                    .remote_items
                    .push(podcast_remote_item_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, "person") => {
                self.podcast.persons.push(podcast_person_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, "location") => {
                self.podcast.location = Some(podcast_location_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, "funding") => {
                self.podcast.fundings.push(podcast_funding_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, "trailer") => {
                self.podcast.trailers.push(podcast_trailer_from_attrs(e));
                self.has_podcast = true;
            }
            _ => return false,
        }
        true
    }

    pub(super) fn on_end(&mut self, ns: Ns, local: &str, text: String) -> Option<String> {
        match (ns, local) {
            // iTunes feed text elements
            (Ns::ITunes, "author") => self.itunes.author = Some(text),
            (Ns::ITunes, "title") => self.itunes.title = Some(text),
            (Ns::ITunes, "subtitle") => self.itunes.subtitle = Some(text),
            (Ns::ITunes, "summary") => self.itunes.summary = Some(text),
            (Ns::ITunes, "type") => self.itunes.type_ = Some(text),
            (Ns::ITunes, "explicit") => self.itunes.explicit = Some(is_truthy(&text)),
            (Ns::ITunes, "new-feed-url") => self.itunes.new_feed_url = Some(text),
            (Ns::ITunes, "block") => self.itunes.block = Some(is_truthy(&text)),
            (Ns::ITunes, "complete") => self.itunes.complete = Some(is_truthy(&text)),
            (Ns::ITunes, "name") if self.in_itunes_owner => self.itunes.owner_name = Some(text),
            (Ns::ITunes, "email") if self.in_itunes_owner => self.itunes.owner_email = Some(text),
            (Ns::ITunes, "owner") => {
                self.in_itunes_owner = false;
                return None;
            }
            // Podcast 2.0 feed text elements + pending finalizers
            (Ns::Podcast, "guid") => {
                self.podcast.guid = Some(text);
                self.has_podcast = true;
                return None;
            }
            (Ns::Podcast, "locked") => {
                self.podcast.locked = Some(is_truthy(&text));
                self.has_podcast = true;
                return None;
            }
            (Ns::Podcast, "medium") => {
                self.podcast.medium = Some(text);
                self.has_podcast = true;
                return None;
            }
            (Ns::Podcast, "license") => {
                self.podcast.license = Some(text);
                self.has_podcast = true;
                return None;
            }
            (Ns::Podcast, "person") => {
                if let Some(mut p) = self.pending_person.take() {
                    p.name = text;
                    self.podcast.persons.push(p);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, "location") => {
                if let Some(mut l) = self.pending_location.take() {
                    l.name = text;
                    self.podcast.location = Some(l);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, "funding") => {
                if let Some(mut f) = self.pending_funding.take() {
                    if !text.is_empty() {
                        f.title = Some(text);
                    }
                    self.podcast.fundings.push(f);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, "trailer") => {
                if let Some(mut t) = self.pending_trailer.take() {
                    t.title = text;
                    self.podcast.trailers.push(t);
                    self.has_podcast = true;
                }
                return None;
            }
            // Dublin Core (any field)
            (Ns::Dc, field) => {
                set_dc_feed(&mut self.dc, &mut self.has_dc, field, text);
                return None;
            }
            _ => return Some(text),
        }
        // Reached via the iTunes text arms above (they assign and fall through).
        self.has_itunes = true;
        None
    }

    pub(super) fn finish(self) -> FeedExtensions {
        FeedExtensions {
            itunes: self.has_itunes.then_some(self.itunes),
            podcast: self.has_podcast.then_some(self.podcast),
            dublin_core: self.has_dc.then_some(self.dc),
        }
    }
}
