//! RSS/Atom feed extension system.
//!
//! Seven supported extension namespaces: iTunes, Podcasting 2.0, Dublin Core,
//! DCMI Metadata Terms, `content:encoded`, Media RSS, and Podlove Simple Chapters
//! ([`PodloveChapters`], item-level only). Each contributes a typed struct
//! stored on [`ItemExtensions`] (item-level) and [`FeedExtensions`]
//! (feed/channel-level) — direct field access (`item.extensions.itunes`)
//! or via inherent shortcuts on the per-format types
//! (`.itunes()`, `.podcast()`, `.dublin_core()`, `.dublin_core_terms()`,
//! `.content()`, `.media()`, `.podlove()`). The DCMI relationship shortcut is
//! available on whole feeds and streaming headers as well as items/entries.

// Per-extension type definitions, organised by namespace.
pub mod content;
pub mod dublin_core;
pub mod dublin_core_terms;
pub mod itunes;
pub mod media;
pub mod podcast;
pub mod podlove;

// Shared parser / writer / element + attribute names. Internal infrastructure
// the per-format readers and writers (in [`super::rss2`] and [`super::atom`])
// call into.
pub(super) mod names;
pub(super) mod parse;
pub(super) mod write;

pub use content::Content;
pub use dublin_core::{DublinCore, DublinCoreFeed};
pub use dublin_core_terms::{DublinCoreTerms, DublinCoreTermsFeed};
pub use itunes::{ITunes, ITunesFeed};
pub use media::{MediaContent, MediaRss, MediaThumbnail};
pub use podcast::{
    Podcast, PodcastAlternateEnclosure, PodcastChapters, PodcastEpisode, PodcastFeed,
    PodcastFunding, PodcastIntegrity, PodcastLocation, PodcastPerson, PodcastRemoteItem,
    PodcastSeason, PodcastSoundbite, PodcastSource, PodcastTrailer, PodcastTranscript,
};
pub use podlove::{PodloveChapter, PodloveChapters};

// ---------------------------------------------------------------------------
// Extension containers
// ---------------------------------------------------------------------------

/// Extension container for feed items (RSS 2.0 items and Atom entries).
///
/// Each present extension is boxed so the empty case is just seven
/// pointer-sized `None`s (56 B on a 64-bit target), not seven inline
/// extension structs (≥800 B). Most items have at most one or two
/// extensions populated; the boxed-Option shape pays heap only for what's
/// actually set and lets `Box<T>` auto-deref carry the field-access API.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ItemExtensions {
    pub itunes: Option<Box<ITunes>>,
    pub podcast: Option<Box<Podcast>>,
    pub dublin_core: Option<Box<DublinCore>>,
    pub dublin_core_terms: Option<Box<DublinCoreTerms>>,
    pub content: Option<Box<Content>>,
    pub media: Option<Box<MediaRss>>,
    pub podlove: Option<Box<PodloveChapters>>,
}

impl ItemExtensions {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.itunes.is_none()
            && self.podcast.is_none()
            && self.dublin_core.is_none()
            && self.dublin_core_terms.is_none()
            && self.content.is_none()
            && self.media.is_none()
            && self.podlove.is_none()
    }
}

/// Extension container for feeds (channel-level for RSS 2.0, feed-level for Atom).
///
/// Same boxed-Option shape as [`ItemExtensions`]; see that type for the
/// rationale.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FeedExtensions {
    pub itunes: Option<Box<ITunesFeed>>,
    pub podcast: Option<Box<PodcastFeed>>,
    pub dublin_core: Option<Box<DublinCoreFeed>>,
    pub dublin_core_terms: Option<Box<DublinCoreTermsFeed>>,
}

impl FeedExtensions {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.itunes.is_none()
            && self.podcast.is_none()
            && self.dublin_core.is_none()
            && self.dublin_core_terms.is_none()
    }
}
