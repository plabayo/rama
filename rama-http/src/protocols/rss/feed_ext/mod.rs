//! RSS/Atom feed extension system.
//!
//! The [`FeedExtension`] trait is sealed; only the built-in extension types
//! implement it.  Use the generic [`ItemExtensions::get`] /
//! [`FeedExtensions::get`] methods or the inherent shortcuts on item/feed
//! types (`.itunes()`, `.podcast()`, etc.) to access extension data.

pub mod content;
pub mod dublin_core;
pub mod itunes;
pub mod media;
pub mod podcast;

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
// Sealing
// ---------------------------------------------------------------------------

pub(crate) mod private {
    pub trait Sealed {}
}

/// Marker trait for types that can be stored as feed extensions.
///
/// Sealed: only the built-in extension types implement this.
pub trait FeedExtension: private::Sealed {}

// ---------------------------------------------------------------------------
// Generic accessor helpers (sealed)
// ---------------------------------------------------------------------------

pub trait ItemExtensionGet: private::Sealed {
    fn get_from_item(ext: &ItemExtensions) -> Option<&Self>
    where
        Self: Sized;
}

pub trait FeedExtensionGet: private::Sealed {
    fn get_from_feed(ext: &FeedExtensions) -> Option<&Self>
    where
        Self: Sized;
}

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
    pub fn get<T: FeedExtension + ItemExtensionGet>(&self) -> Option<&T> {
        T::get_from_item(self)
    }

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
    pub fn get<T: FeedExtension + FeedExtensionGet>(&self) -> Option<&T> {
        T::get_from_feed(self)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.itunes.is_none() && self.podcast.is_none() && self.dublin_core.is_none()
    }
}
