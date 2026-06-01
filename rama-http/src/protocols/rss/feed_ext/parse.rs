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

use super::names::{attr, content, dc, itunes, media, podcast, psc};
use super::podlove::{PodloveChapter, parse_start as parse_psc_start};
use super::{
    Content, DublinCore, DublinCoreFeed, FeedExtensions, ITunes, ITunesFeed, ItemExtensions,
    MediaContent, MediaRss, MediaThumbnail, Podcast, PodcastChapters, PodcastEpisode, PodcastFeed,
    PodcastFunding, PodcastLocation, PodcastPerson, PodcastRemoteItem, PodcastSeason,
    PodcastSoundbite, PodcastTrailer, PodcastTranscript, PodloveChapters,
};
use crate::protocols::rss::parse_util::{Attrs, attr_value, parse_rss2_date};

/// Recognised XML namespaces. Anything outside this set is treated as unknown
/// and ignored by the accumulators.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::protocols::rss) enum Ns {
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
    /// `http://podlove.org/simple-chapters` — inline per-episode chapter
    /// markers (separate from Podcasting 2.0's external `<podcast:chapters>`).
    Psc,
    /// Any other / unknown namespace.
    Other,
}

/// Resolve a [`ResolveResult`] from `NsReader` into one of the namespaces we
/// recognise. Comparison is on the namespace URI bytes, so the actual prefix
/// the document uses is irrelevant. URIs come from [`super::ns`] so the writer
/// and parser never disagree on a single byte.
pub(in crate::protocols::rss) fn classify_ns(rr: &ResolveResult<'_>) -> Ns {
    use crate::protocols::rss::ns;
    const ATOM: &[u8] = ns::ATOM_NS.as_bytes();
    const ITUNES: &[u8] = ns::ITUNES_NS.as_bytes();
    const PODCAST: &[u8] = ns::PODCAST_NS.as_bytes();
    const DC: &[u8] = ns::DC_NS.as_bytes();
    const MEDIA: &[u8] = ns::MEDIA_NS.as_bytes();
    const CONTENT: &[u8] = ns::CONTENT_NS.as_bytes();
    const PSC: &[u8] = ns::PSC_NS.as_bytes();

    match rr {
        ResolveResult::Unbound => Ns::None,
        ResolveResult::Bound(n) => match n.0 {
            ATOM => Ns::Atom,
            ITUNES => Ns::ITunes,
            PODCAST => Ns::Podcast,
            DC => Ns::Dc,
            MEDIA => Ns::Media,
            CONTENT => Ns::Content,
            PSC => Ns::Psc,
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
        url: attr_value(e, attr::URL),
        type_: attr_value(e, attr::TYPE),
        medium: attr_value(e, attr::MEDIUM),
        duration: attr_value(e, attr::DURATION)
            .and_then(|v| v.parse::<u64>().ok())
            .map(std::time::Duration::from_secs),
        width: attr_value(e, attr::WIDTH).and_then(|v| v.parse().ok()),
        height: attr_value(e, attr::HEIGHT).and_then(|v| v.parse().ok()),
        file_size: attr_value(e, attr::FILE_SIZE).and_then(|v| v.parse().ok()),
        bitrate: attr_value(e, attr::BITRATE).and_then(|v| v.parse().ok()),
        title: None,
        description: None,
    }
}

fn media_thumbnail_from_attrs(e: &Attrs<'_>) -> MediaThumbnail {
    MediaThumbnail {
        url: attr_value(e, attr::URL).unwrap_or_default(),
        width: attr_value(e, attr::WIDTH).and_then(|v| v.parse().ok()),
        height: attr_value(e, attr::HEIGHT).and_then(|v| v.parse().ok()),
    }
}

fn podcast_person_from_attrs(e: &Attrs<'_>) -> PodcastPerson {
    PodcastPerson {
        name: String::new(),
        role: attr_value(e, attr::ROLE),
        group: attr_value(e, attr::GROUP),
        img: attr_value(e, attr::IMG),
        href: attr_value(e, attr::HREF),
    }
}

fn podcast_location_from_attrs(e: &Attrs<'_>) -> PodcastLocation {
    PodcastLocation {
        name: String::new(),
        geo: attr_value(e, attr::GEO),
        osm: attr_value(e, attr::OSM),
    }
}

fn podcast_funding_from_attrs(e: &Attrs<'_>) -> PodcastFunding {
    PodcastFunding {
        url: attr_value(e, attr::URL).unwrap_or_default(),
        title: None,
    }
}

fn podcast_trailer_from_attrs(e: &Attrs<'_>) -> PodcastTrailer {
    PodcastTrailer {
        title: String::new(),
        url: attr_value(e, attr::URL).unwrap_or_default(),
        pub_date: attr_value(e, attr::PUB_DATE).and_then(|v| parse_rss2_date(&v)),
        length: attr_value(e, attr::LENGTH).and_then(|v| v.parse().ok()),
        type_: attr_value(e, attr::TYPE),
        season: attr_value(e, attr::SEASON).and_then(|v| v.parse().ok()),
    }
}

/// Parse a non-negative decimal-seconds attribute into a [`Duration`].
/// Rejects non-finite (NaN/+Inf/-Inf) and negative values — most podcast
/// clients refuse such timestamps and some crash on them. Returns
/// [`Duration::ZERO`] when the attribute is absent or unparseable.
fn duration_attr(e: &Attrs<'_>, name: &str) -> std::time::Duration {
    attr_value(e, name)
        .and_then(|v| v.parse::<f64>().ok())
        .and_then(|v| std::time::Duration::try_from_secs_f64(v).ok())
        .unwrap_or_default()
}

fn podcast_soundbite_from_attrs(e: &Attrs<'_>) -> PodcastSoundbite {
    PodcastSoundbite {
        start_time: duration_attr(e, attr::START_TIME),
        duration: duration_attr(e, attr::DURATION),
        title: None,
    }
}

fn podcast_transcript_from_attrs(e: &Attrs<'_>) -> PodcastTranscript {
    PodcastTranscript {
        url: attr_value(e, attr::URL).unwrap_or_default(),
        type_: attr_value(e, attr::TYPE).unwrap_or_default(),
        language: attr_value(e, attr::LANGUAGE),
        rel: attr_value(e, attr::REL),
    }
}

fn podcast_remote_item_from_attrs(e: &Attrs<'_>) -> PodcastRemoteItem {
    PodcastRemoteItem {
        feed_guid: attr_value(e, attr::FEED_GUID).unwrap_or_default(),
        item_guid: attr_value(e, attr::ITEM_GUID),
        feed_url: attr_value(e, attr::FEED_URL),
        title: attr_value(e, attr::TITLE),
        medium: attr_value(e, attr::MEDIUM),
    }
}

// `DublinCore` (item) and `DublinCoreFeed` (feed) share the same flat field set;
// one macro generates a setter for each so parsing stays single-sourced.
macro_rules! impl_set_dc {
    ($name:ident, $t:ty) => {
        fn $name(d: &mut $t, has: &mut bool, local: &str, text: String) {
            *has = true;
            match local {
                dc::TITLE => d.title = Some(text),
                dc::CREATOR => d.creator = Some(text),
                dc::SUBJECT => d.subject = Some(text),
                dc::DESCRIPTION => d.description = Some(text),
                dc::PUBLISHER => d.publisher = Some(text),
                dc::CONTRIBUTOR => d.contributor = Some(text),
                dc::DATE => d.date = parse_rss2_date(&text),
                dc::TYPE => d.type_ = Some(text),
                dc::FORMAT => d.format = Some(text),
                dc::IDENTIFIER => d.identifier = Some(text),
                dc::SOURCE => d.source = Some(text),
                dc::LANGUAGE => d.language = Some(text),
                dc::RELATION => d.relation = Some(text),
                dc::COVERAGE => d.coverage = Some(text),
                dc::RIGHTS => d.rights = Some(text),
                _ => *has = false,
            }
        }
    };
}

impl_set_dc!(set_dc_item, DublinCore);
impl_set_dc!(set_dc_feed, DublinCoreFeed);

/// Accumulates item-/entry-level extension elements into an [`ItemExtensions`].
#[derive(Default)]
pub(in crate::protocols::rss) struct ItemExtAcc {
    itunes: ITunes,
    has_itunes: bool,
    dc: DublinCore,
    has_dc: bool,
    media: MediaRss,
    has_media: bool,
    podcast: Podcast,
    has_podcast: bool,
    content: Option<Content>,
    /// Stack of `<media:content>` elements currently open. The topmost entry
    /// receives nested `<media:title>`/`<media:description>` children; on its
    /// End event it is popped into `media.contents`. A stack (rather than a
    /// single slot) is required so a nested `<media:content>` doesn't silently
    /// overwrite its parent.
    pending_media: Vec<MediaContent>,
    pending_person: Option<PodcastPerson>,
    pending_location: Option<PodcastLocation>,
    pending_soundbite: Option<PodcastSoundbite>,
    pending_season: Option<PodcastSeason>,
    pending_episode: Option<PodcastEpisode>,
    /// Open `<psc:chapters>` block accumulating its `<psc:chapter>` children.
    /// Finalised into `podlove` on the matching End event.
    pending_psc: Option<PodloveChapters>,
    podlove: Option<PodloveChapters>,
}

impl ItemExtAcc {
    /// Handle a start event; returns `true` if the element was consumed.
    pub(in crate::protocols::rss) fn on_start(
        &mut self,
        ns: Ns,
        local: &str,
        e: &Attrs<'_>,
    ) -> bool {
        match (ns, local) {
            (Ns::ITunes, itunes::IMAGE) => {
                if let Some(href) = attr_value(e, attr::HREF) {
                    self.itunes.image = Some(href);
                    self.has_itunes = true;
                }
            }
            (Ns::Media, media::CONTENT) => {
                self.pending_media.push(media_content_from_attrs(e));
            }
            (Ns::Podcast, podcast::PERSON) => {
                self.pending_person = Some(podcast_person_from_attrs(e))
            }
            (Ns::Podcast, podcast::LOCATION) => {
                self.pending_location = Some(podcast_location_from_attrs(e))
            }
            (Ns::Podcast, podcast::SOUNDBITE) => {
                self.pending_soundbite = Some(podcast_soundbite_from_attrs(e));
            }
            (Ns::Podcast, podcast::SEASON) => {
                self.pending_season = Some(PodcastSeason {
                    number: 0,
                    name: attr_value(e, attr::NAME),
                });
            }
            (Ns::Podcast, podcast::EPISODE) => {
                self.pending_episode = Some(PodcastEpisode {
                    number: 0.0,
                    display: attr_value(e, attr::DISPLAY),
                });
            }
            (Ns::Psc, psc::CHAPTERS) => {
                // Spec default for version is "1.2" if the attribute is absent.
                let version = attr_value(e, attr::VERSION).unwrap_or_else(|| "1.2".into());
                self.pending_psc = Some(PodloveChapters {
                    version,
                    chapters: Vec::new(),
                });
            }
            _ => return false,
        }
        true
    }

    /// Handle a self-closing element; returns `true` if consumed.
    pub(in crate::protocols::rss) fn on_empty(
        &mut self,
        ns: Ns,
        local: &str,
        e: &Attrs<'_>,
    ) -> bool {
        match (ns, local) {
            (Ns::ITunes, itunes::IMAGE) => {
                if let Some(href) = attr_value(e, attr::HREF) {
                    self.itunes.image = Some(href);
                    self.has_itunes = true;
                }
            }
            (Ns::Media, media::CONTENT) => {
                self.media.contents.push(media_content_from_attrs(e));
                self.has_media = true;
            }
            (Ns::Media, media::THUMBNAIL) => {
                self.media.thumbnail = Some(media_thumbnail_from_attrs(e));
                self.has_media = true;
            }
            (Ns::Podcast, podcast::TRANSCRIPT) => {
                self.podcast
                    .transcripts
                    .push(podcast_transcript_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, podcast::CHAPTERS) => {
                self.podcast.chapters = Some(PodcastChapters {
                    url: attr_value(e, attr::URL).unwrap_or_default(),
                    type_: attr_value(e, attr::TYPE).unwrap_or_default(),
                });
                self.has_podcast = true;
            }
            (Ns::Podcast, podcast::PERSON) => {
                self.podcast.persons.push(podcast_person_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, podcast::LOCATION) => {
                self.podcast.location = Some(podcast_location_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, podcast::SOUNDBITE) => {
                self.podcast
                    .soundbites
                    .push(podcast_soundbite_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, podcast::SEASON) => {
                self.podcast.season = Some(PodcastSeason {
                    number: 0,
                    name: attr_value(e, attr::NAME),
                });
                self.has_podcast = true;
            }
            (Ns::Podcast, podcast::EPISODE) => {
                self.podcast.episode = Some(PodcastEpisode {
                    number: 0.0,
                    display: attr_value(e, attr::DISPLAY),
                });
                self.has_podcast = true;
            }
            (Ns::Podcast, podcast::REMOTE_ITEM) => {
                self.podcast
                    .remote_items
                    .push(podcast_remote_item_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Psc, psc::CHAPTER) => {
                // <psc:chapter> only makes sense inside a <psc:chapters>
                // block; in lenient mode we accumulate into the open block
                // and drop free-floating ones.
                if let Some(chapters) = self.pending_psc.as_mut() {
                    chapters.chapters.push(PodloveChapter {
                        start: attr_value(e, attr::START)
                            .map(|s| parse_psc_start(&s))
                            .unwrap_or_default(),
                        title: attr_value(e, attr::TITLE).unwrap_or_default(),
                        href: attr_value(e, attr::HREF),
                        image: attr_value(e, attr::IMAGE),
                    });
                }
            }
            _ => return false,
        }
        true
    }

    /// Handle an end event carrying the element's text. Returns `Some(text)`
    /// when the element was not consumed (so the caller can do its own
    /// core-element processing).
    pub(in crate::protocols::rss) fn on_end(
        &mut self,
        ns: Ns,
        local: &str,
        text: String,
    ) -> Option<String> {
        match (ns, local) {
            // iTunes item text elements
            (Ns::ITunes, itunes::TITLE) => self.itunes.title = Some(text),
            (Ns::ITunes, itunes::AUTHOR) => self.itunes.author = Some(text),
            (Ns::ITunes, itunes::SUBTITLE) => self.itunes.subtitle = Some(text),
            (Ns::ITunes, itunes::SUMMARY) => self.itunes.summary = Some(text),
            (Ns::ITunes, itunes::DURATION) => self.itunes.duration = Some(text),
            (Ns::ITunes, itunes::EXPLICIT) => self.itunes.explicit = Some(is_truthy(&text)),
            (Ns::ITunes, itunes::EPISODE) => self.itunes.episode = text.trim().parse().ok(),
            (Ns::ITunes, itunes::SEASON) => self.itunes.season = text.trim().parse().ok(),
            (Ns::ITunes, itunes::EPISODE_TYPE) => self.itunes.episode_type = Some(text),
            (Ns::ITunes, itunes::KEYWORDS) => self.itunes.keywords = Some(text),
            (Ns::ITunes, itunes::BLOCK) => self.itunes.block = Some(is_truthy(&text)),
            // content:encoded
            (Ns::Content, content::ENCODED) => {
                self.content = Some(Content {
                    encoded: Some(text),
                });
                return None;
            }
            // Media RSS
            (Ns::Media, media::CONTENT) => {
                if let Some(m) = self.pending_media.pop() {
                    self.media.contents.push(m);
                    self.has_media = true;
                }
                return None;
            }
            (Ns::Media, media::TITLE) => {
                if let Some(m) = self.pending_media.last_mut() {
                    m.title = Some(text);
                } else {
                    self.media.title = Some(text);
                    self.has_media = true;
                }
                return None;
            }
            (Ns::Media, media::DESCRIPTION) => {
                if let Some(m) = self.pending_media.last_mut() {
                    m.description = Some(text);
                } else {
                    self.media.description = Some(text);
                    self.has_media = true;
                }
                return None;
            }
            (Ns::Media, media::KEYWORDS) => {
                self.media.keywords = Some(text);
                self.has_media = true;
                return None;
            }
            (Ns::Media, media::RATING) => {
                self.media.rating = Some(text);
                self.has_media = true;
                return None;
            }
            // Podcast 2.0 item-level pending finalizers
            (Ns::Podcast, podcast::PERSON) => {
                if let Some(mut p) = self.pending_person.take() {
                    p.name = text;
                    self.podcast.persons.push(p);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, podcast::LOCATION) => {
                if let Some(mut l) = self.pending_location.take() {
                    l.name = text;
                    self.podcast.location = Some(l);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, podcast::SOUNDBITE) => {
                if let Some(mut s) = self.pending_soundbite.take() {
                    if !text.is_empty() {
                        s.title = Some(text);
                    }
                    self.podcast.soundbites.push(s);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, podcast::SEASON) => {
                if let Some(mut s) = self.pending_season.take() {
                    s.number = text.trim().parse().unwrap_or(0);
                    self.podcast.season = Some(s);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, podcast::EPISODE) => {
                if let Some(mut ep) = self.pending_episode.take() {
                    ep.number = text
                        .trim()
                        .parse::<f64>()
                        .ok()
                        .filter(|v| v.is_finite())
                        .unwrap_or(0.0);
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
            // Podlove Simple Chapters
            (Ns::Psc, psc::CHAPTERS) => {
                self.podlove = self.pending_psc.take();
                return None;
            }
            _ => return Some(text),
        }
        // Reached via the iTunes text arms above (they assign and fall through).
        self.has_itunes = true;
        None
    }

    pub(in crate::protocols::rss) fn finish(self) -> ItemExtensions {
        ItemExtensions {
            itunes: self.has_itunes.then(|| Box::new(self.itunes)),
            podcast: self.has_podcast.then(|| Box::new(self.podcast)),
            dublin_core: self.has_dc.then(|| Box::new(self.dc)),
            content: self.content.map(Box::new),
            media: self.has_media.then(|| Box::new(self.media)),
            podlove: self.podlove.map(Box::new),
        }
    }
}

/// Accumulates channel-/feed-level extension elements into a [`FeedExtensions`].
#[derive(Default)]
pub(in crate::protocols::rss) struct FeedExtAcc {
    itunes: ITunesFeed,
    has_itunes: bool,
    dc: DublinCoreFeed,
    has_dc: bool,
    podcast: PodcastFeed,
    has_podcast: bool,
    in_itunes_owner: bool,
    in_podcast_locked: bool,
    pending_locked_owner: Option<String>,
    pending_person: Option<PodcastPerson>,
    pending_location: Option<PodcastLocation>,
    pending_funding: Option<PodcastFunding>,
    pending_trailer: Option<PodcastTrailer>,
}

impl FeedExtAcc {
    pub(in crate::protocols::rss) fn on_start(
        &mut self,
        ns: Ns,
        local: &str,
        e: &Attrs<'_>,
    ) -> bool {
        match (ns, local) {
            (Ns::ITunes, itunes::IMAGE) => {
                if let Some(href) = attr_value(e, attr::HREF) {
                    self.itunes.image = Some(href);
                    self.has_itunes = true;
                }
            }
            (Ns::ITunes, itunes::CATEGORY) => {
                // Apple's canonical shape nests subcategories inside their
                // parent: `<itunes:category text="Technology">
                //   <itunes:category text="Software How-To"/>
                // </itunes:category>`. The parent's Start event carries the
                // parent name on the `text` attribute, which the self-closing
                // arm (in `on_empty`) would never see. Both forms flatten to
                // the same `categories` Vec; the writer emits them as flat
                // siblings.
                if let Some(v) = attr_value(e, attr::TEXT) {
                    self.itunes.categories.push(v);
                    self.has_itunes = true;
                }
            }
            (Ns::ITunes, itunes::OWNER) => {
                self.in_itunes_owner = true;
                self.has_itunes = true;
            }
            (Ns::Podcast, podcast::PERSON) => {
                self.pending_person = Some(podcast_person_from_attrs(e))
            }
            (Ns::Podcast, podcast::LOCATION) => {
                self.pending_location = Some(podcast_location_from_attrs(e))
            }
            (Ns::Podcast, podcast::FUNDING) => {
                self.pending_funding = Some(podcast_funding_from_attrs(e))
            }
            (Ns::Podcast, podcast::TRAILER) => {
                self.pending_trailer = Some(podcast_trailer_from_attrs(e))
            }
            (Ns::Podcast, podcast::LOCKED) => {
                // `<podcast:locked owner="...">yes|no</podcast:locked>` — the
                // owner attribute lives only on the Start; capture it now and
                // finalise on End alongside the truthy text content.
                self.in_podcast_locked = true;
                self.pending_locked_owner = attr_value(e, attr::OWNER);
            }
            _ => return false,
        }
        true
    }

    pub(in crate::protocols::rss) fn on_empty(
        &mut self,
        ns: Ns,
        local: &str,
        e: &Attrs<'_>,
    ) -> bool {
        match (ns, local) {
            (Ns::ITunes, itunes::IMAGE) => {
                if let Some(href) = attr_value(e, attr::HREF) {
                    self.itunes.image = Some(href);
                    self.has_itunes = true;
                }
            }
            (Ns::ITunes, itunes::CATEGORY) => {
                if let Some(v) = attr_value(e, attr::TEXT) {
                    self.itunes.categories.push(v);
                    self.has_itunes = true;
                }
            }
            (Ns::Podcast, podcast::REMOTE_ITEM) => {
                self.podcast
                    .remote_items
                    .push(podcast_remote_item_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, podcast::PERSON) => {
                self.podcast.persons.push(podcast_person_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, podcast::LOCATION) => {
                self.podcast.location = Some(podcast_location_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, podcast::FUNDING) => {
                self.podcast.fundings.push(podcast_funding_from_attrs(e));
                self.has_podcast = true;
            }
            (Ns::Podcast, podcast::TRAILER) => {
                self.podcast.trailers.push(podcast_trailer_from_attrs(e));
                self.has_podcast = true;
            }
            _ => return false,
        }
        true
    }

    pub(in crate::protocols::rss) fn on_end(
        &mut self,
        ns: Ns,
        local: &str,
        text: String,
    ) -> Option<String> {
        match (ns, local) {
            // iTunes feed text elements
            (Ns::ITunes, itunes::AUTHOR) => self.itunes.author = Some(text),
            (Ns::ITunes, itunes::TITLE) => self.itunes.title = Some(text),
            (Ns::ITunes, itunes::SUBTITLE) => self.itunes.subtitle = Some(text),
            (Ns::ITunes, itunes::SUMMARY) => self.itunes.summary = Some(text),
            (Ns::ITunes, itunes::TYPE) => self.itunes.type_ = Some(text),
            (Ns::ITunes, itunes::EXPLICIT) => self.itunes.explicit = Some(is_truthy(&text)),
            (Ns::ITunes, itunes::NEW_FEED_URL) => self.itunes.new_feed_url = Some(text),
            (Ns::ITunes, itunes::BLOCK) => self.itunes.block = Some(is_truthy(&text)),
            (Ns::ITunes, itunes::COMPLETE) => self.itunes.complete = Some(is_truthy(&text)),
            (Ns::ITunes, itunes::NAME) if self.in_itunes_owner => {
                self.itunes.owner_name = Some(text)
            }
            (Ns::ITunes, itunes::EMAIL) if self.in_itunes_owner => {
                self.itunes.owner_email = Some(text)
            }
            (Ns::ITunes, itunes::OWNER) => {
                self.in_itunes_owner = false;
                return None;
            }
            // Podcast 2.0 feed text elements + pending finalizers
            (Ns::Podcast, podcast::GUID) => {
                self.podcast.guid = Some(text);
                self.has_podcast = true;
                return None;
            }
            (Ns::Podcast, podcast::LOCKED) => {
                self.podcast.locked = Some(is_truthy(&text));
                self.podcast.locked_owner = self.pending_locked_owner.take();
                self.in_podcast_locked = false;
                self.has_podcast = true;
                return None;
            }
            (Ns::Podcast, podcast::MEDIUM) => {
                self.podcast.medium = Some(text);
                self.has_podcast = true;
                return None;
            }
            (Ns::Podcast, podcast::LICENSE) => {
                self.podcast.license = Some(text);
                self.has_podcast = true;
                return None;
            }
            (Ns::Podcast, podcast::PERSON) => {
                if let Some(mut p) = self.pending_person.take() {
                    p.name = text;
                    self.podcast.persons.push(p);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, podcast::LOCATION) => {
                if let Some(mut l) = self.pending_location.take() {
                    l.name = text;
                    self.podcast.location = Some(l);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, podcast::FUNDING) => {
                if let Some(mut f) = self.pending_funding.take() {
                    if !text.is_empty() {
                        f.title = Some(text);
                    }
                    self.podcast.fundings.push(f);
                    self.has_podcast = true;
                }
                return None;
            }
            (Ns::Podcast, podcast::TRAILER) => {
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

    pub(in crate::protocols::rss) fn finish(self) -> FeedExtensions {
        FeedExtensions {
            itunes: self.has_itunes.then(|| Box::new(self.itunes)),
            podcast: self.has_podcast.then(|| Box::new(self.podcast)),
            dublin_core: self.has_dc.then(|| Box::new(self.dc)),
        }
    }
}
