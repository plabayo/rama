//! Podcasting 2.0 namespace extension (<https://podcastindex.org/namespace/1.0>).

use std::time::Duration;

use jiff::Timestamp;
use rama_net::uri::Uri;

/// A `podcast:transcript` element.
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastTranscript {
    pub url: String,
    pub type_: String,
    pub language: Option<String>,
    pub rel: Option<String>,
}

/// A `podcast:alternateEnclosure` element.
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastAlternateEnclosure {
    pub type_: String,
    pub length: Option<u64>,
    pub bitrate: Option<f64>,
    pub height: Option<u64>,
    pub lang: Option<String>,
    /// Podcasting 2.0 limits this to 32 characters; the lenient parser and
    /// writer preserve caller input rather than enforcing it.
    pub title: Option<String>,
    /// Podcasting 2.0 limits this to 32 characters; the lenient parser and
    /// writer preserve caller input rather than enforcing it.
    pub rel: Option<String>,
    pub codecs: Option<String>,
    /// Whether this alternate is the default rendition. The writer emits the
    /// attribute only when true; callers are responsible for keeping at most
    /// one default alternate per item.
    pub default: bool,
    pub sources: Vec<PodcastSource>,
    pub integrity: Option<PodcastIntegrity>,
}

/// A `podcast:source` child of `podcast:alternateEnclosure`.
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastSource {
    pub uri: Uri,
    pub content_type: Option<String>,
}

/// A `podcast:integrity` child of `podcast:alternateEnclosure`.
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastIntegrity {
    pub type_: String,
    pub value: String,
}

/// A `podcast:chapters` reference.
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastChapters {
    pub url: String,
    pub type_: String,
}

/// A `podcast:soundbite` element. Podcasting 2.0 spec uses decimal seconds
/// for both start and duration (sub-second precision is meaningful).
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastSoundbite {
    pub start_time: Duration,
    pub duration: Duration,
    pub title: Option<String>,
}

/// A `podcast:person` element (used at both item and feed level).
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastPerson {
    pub name: String,
    pub role: Option<String>,
    pub group: Option<String>,
    pub img: Option<String>,
    pub href: Option<String>,
}

/// A `podcast:location` element.
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastLocation {
    pub name: String,
    pub geo: Option<String>,
    pub osm: Option<String>,
}

/// A `podcast:season` element.
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastSeason {
    pub number: u64,
    pub name: Option<String>,
}

/// A `podcast:episode` element.
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastEpisode {
    pub number: f64,
    pub display: Option<String>,
}

/// A `podcast:funding` element (feed-level).
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastFunding {
    pub url: String,
    pub title: Option<String>,
}

/// A `podcast:trailer` element (feed-level).
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastTrailer {
    pub title: String,
    pub url: String,
    pub pub_date: Option<Timestamp>,
    pub length: Option<u64>,
    pub type_: Option<String>,
    pub season: Option<u64>,
}

/// A `podcast:remoteItem` element (feed-level).
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastRemoteItem {
    pub feed_guid: String,
    pub item_guid: Option<String>,
    pub feed_url: Option<String>,
    pub title: Option<String>,
    pub medium: Option<String>,
}

/// Podcasting 2.0 extension fields for a single episode item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Podcast {
    pub transcripts: Vec<PodcastTranscript>,
    pub alternate_enclosures: Vec<PodcastAlternateEnclosure>,
    pub chapters: Option<PodcastChapters>,
    pub soundbites: Vec<PodcastSoundbite>,
    pub persons: Vec<PodcastPerson>,
    pub location: Option<PodcastLocation>,
    pub season: Option<PodcastSeason>,
    pub episode: Option<PodcastEpisode>,
    /// `<podcast:remoteItem>` inside `<item>` — points the host episode at
    /// another feed's item (used for cross-feed value-split or inter-publisher
    /// references in Podcasting 2.0).
    pub remote_items: Vec<PodcastRemoteItem>,
}

/// Podcasting 2.0 extension fields at the feed (channel) level.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PodcastFeed {
    pub guid: Option<String>,
    /// `<podcast:locked>` truthy content (yes/no → true/false).
    pub locked: Option<bool>,
    /// `<podcast:locked owner="...">` attribute — the email of the host
    /// authorised to approve a feed-import request. Optional per spec;
    /// preserved on round-trip when present.
    pub locked_owner: Option<String>,
    pub fundings: Vec<PodcastFunding>,
    pub persons: Vec<PodcastPerson>,
    pub location: Option<PodcastLocation>,
    pub trailers: Vec<PodcastTrailer>,
    pub license: Option<String>,
    pub medium: Option<String>,
    pub remote_items: Vec<PodcastRemoteItem>,
}
