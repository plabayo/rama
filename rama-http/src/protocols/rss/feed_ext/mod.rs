//! RSS/Atom feed extension system.
//!
//! There are five supported extension namespaces: iTunes, Podcasting 2.0,
//! Dublin Core, `content:encoded`, and Media RSS. Each contributes a typed
//! struct stored on [`ItemExtensions`] (item-level) and [`FeedExtensions`]
//! (feed/channel-level) — direct field access (`item.extensions.itunes`)
//! or via the inherent shortcuts on the per-format item/feed types
//! (`.itunes()`, `.podcast()`, etc.).

// Per-extension type definitions, organised by namespace.
pub mod content;
pub mod dublin_core;
pub mod itunes;
pub mod media;
pub mod podcast;

// Shared parser / writer / element + attribute names. Internal infrastructure
// the per-format readers and writers (in [`super::rss2`] and [`super::atom`])
// call into.
pub(super) mod names;
pub(super) mod parse;
pub(super) mod write;

pub use content::Content;
pub use dublin_core::{DublinCore, DublinCoreFeed};
pub use itunes::{ITunes, ITunesFeed};
pub use media::{MediaContent, MediaRss, MediaThumbnail};
pub use podcast::{
    Podcast, PodcastChapters, PodcastEpisode, PodcastFeed, PodcastFunding, PodcastLocation,
    PodcastPerson, PodcastRemoteItem, PodcastSeason, PodcastSoundbite, PodcastTrailer,
    PodcastTranscript,
};

// ---------------------------------------------------------------------------
// Extension containers
// ---------------------------------------------------------------------------

/// Extension container for feed items (RSS 2.0 items and Atom entries).
///
/// Each present extension is boxed so the empty case is just five
/// pointer-sized `None`s (40 B on a 64-bit target), not five inline
/// extension structs (≥800 B). Most items have at most one or two
/// extensions populated; the boxed-Option shape pays heap only for what's
/// actually set and lets `Box<T>` auto-deref carry the field-access API.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ItemExtensions {
    pub itunes: Option<Box<ITunes>>,
    pub podcast: Option<Box<Podcast>>,
    pub dublin_core: Option<Box<DublinCore>>,
    pub content: Option<Box<Content>>,
    pub media: Option<Box<MediaRss>>,
}

impl ItemExtensions {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.itunes.is_none()
            && self.podcast.is_none()
            && self.dublin_core.is_none()
            && self.content.is_none()
            && self.media.is_none()
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
}

impl FeedExtensions {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.itunes.is_none() && self.podcast.is_none() && self.dublin_core.is_none()
    }
}
