//! RSS 2.0 and Atom 1.0 feed support.
//!
//! ## Building feeds
//!
//! Both formats use type-state builders that enforce required fields at
//! compile time.  Call `.build()` only after all required fields are set.
//!
//! ```rust,ignore
//! use rama_http::protocols::rss::{Rss2Feed, Rss2Item, Rss2Guid};
//!
//! let feed = Rss2Feed::builder()
//!     .title("My Blog")
//!     .link("https://example.com")
//!     .description("Latest posts")
//!     .item(
//!         Rss2Item::new()
//!             .with_title("Hello World")
//!             .with_guid(Rss2Guid::permalink("https://example.com/1")),
//!     )
//!     .build();
//! ```
//!
//! ## Serving feeds
//!
//! All feed types implement `IntoResponse`.  The correct `Content-Type`
//! header (`application/rss+xml` or `application/atom+xml`) is set
//! automatically.
//!
//! ## Parsing feeds
//!
//! Use [`Feed::from_body`] (or [`FeedStream::from_body`] for true streaming
//! item-by-item processing) to parse a feed from an HTTP response. There is
//! no sync top-level parser — everything goes through the async streaming
//! reader.
//!
//! ## Streaming
//!
//! [`Rss2StreamWriter`] and [`AtomStreamWriter`] wrap an async item stream and
//! produce a streaming `Body` without buffering the full document.
//!
//! ## Extensions
//!
//! All extension fields are in the [`feed_ext`] sub-module.  Items expose
//! inherent shortcuts (`.itunes()`, `.podcast()`, etc.) as well as a generic
//! `.extension::<T>()` method.

pub mod feed_ext;

mod atom;
mod error;
mod ext_parse;
mod ext_write;
mod feed;
mod ns;
mod parse_util;
mod read;
mod rss2;
mod ser;
mod stream;

pub use error::{
    AtomCollectError, CollectError, FeedCollectError, FeedParseError, Rss2CollectError,
};
pub use read::{AtomFeedStream, AtomHeader, FeedStream, Rss2Channel, Rss2FeedStream};

// ---------------------------------------------------------------------------
// Re-exports: RSS 2.0
// ---------------------------------------------------------------------------

pub use rss2::{
    Missing, Present, Rss2Category, Rss2Enclosure, Rss2Feed, Rss2FeedBuilder, Rss2Guid, Rss2Image,
    Rss2Item, Rss2Source,
};

// ---------------------------------------------------------------------------
// Re-exports: Atom 1.0
// ---------------------------------------------------------------------------

pub use atom::{
    AtomCategory, AtomContent, AtomEntry, AtomFeed, AtomFeedBuilder, AtomGenerator, AtomLink,
    AtomPerson, AtomSource, AtomText,
};

// ---------------------------------------------------------------------------
// Re-exports: Feed umbrella, parsing, streaming
// ---------------------------------------------------------------------------

pub use feed::{EnclosureView, Feed, FeedItem};
pub use stream::{AtomStreamWriter, FeedStreamWriter, Rss2StreamWriter};

// ---------------------------------------------------------------------------
// Re-exports: Extensions
// ---------------------------------------------------------------------------

pub use feed_ext::{
    Content, DublinCore, DublinCoreFeed, FeedExtension, FeedExtensions, ITunes, ITunesFeed,
    ItemExtensions, MediaContent, MediaRss, MediaThumbnail, Podcast, PodcastChapters,
    PodcastEpisode, PodcastFeed, PodcastFunding, PodcastLocation, PodcastPerson, PodcastRemoteItem,
    PodcastSeason, PodcastSoundbite, PodcastTrailer, PodcastTranscript,
};
