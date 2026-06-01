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
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ItemExtensions {
    pub itunes: Option<ITunes>,
    pub podcast: Option<Podcast>,
    pub dublin_core: Option<DublinCore>,
    pub content: Option<Content>,
    pub media: Option<MediaRss>,
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
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FeedExtensions {
    pub itunes: Option<ITunesFeed>,
    pub podcast: Option<PodcastFeed>,
    pub dublin_core: Option<DublinCoreFeed>,
}

impl FeedExtensions {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.itunes.is_none() && self.podcast.is_none() && self.dublin_core.is_none()
    }
}
