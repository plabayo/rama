//! Podcasting 2.0 namespace extension (<https://podcastindex.org/namespace/1.0>).

use jiff::Timestamp;

use super::private;
use super::{FeedExtension, FeedExtensionGet, FeedExtensions, ItemExtensionGet, ItemExtensions};

/// A `podcast:transcript` element.
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastTranscript {
    pub url: String,
    pub type_: String,
    pub language: Option<String>,
    pub rel: Option<String>,
}

/// A `podcast:chapters` reference.
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastChapters {
    pub url: String,
    pub type_: String,
}

/// A `podcast:soundbite` element.
#[derive(Debug, Clone, PartialEq)]
pub struct PodcastSoundbite {
    pub start_time: f64,
    pub duration: f64,
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
    pub chapters: Option<PodcastChapters>,
    pub soundbites: Vec<PodcastSoundbite>,
    pub persons: Vec<PodcastPerson>,
    pub location: Option<PodcastLocation>,
    pub season: Option<PodcastSeason>,
    pub episode: Option<PodcastEpisode>,
}

impl private::Sealed for Podcast {}
impl FeedExtension for Podcast {}

impl ItemExtensionGet for Podcast {
    fn get_from_item(ext: &ItemExtensions) -> Option<&Self> {
        ext.podcast.as_ref()
    }
}

/// Podcasting 2.0 extension fields at the feed (channel) level.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PodcastFeed {
    pub guid: Option<String>,
    pub locked: Option<bool>,
    pub fundings: Vec<PodcastFunding>,
    pub persons: Vec<PodcastPerson>,
    pub location: Option<PodcastLocation>,
    pub trailers: Vec<PodcastTrailer>,
    pub license: Option<String>,
    pub medium: Option<String>,
    pub remote_items: Vec<PodcastRemoteItem>,
}

impl private::Sealed for PodcastFeed {}
impl FeedExtension for PodcastFeed {}

impl FeedExtensionGet for PodcastFeed {
    fn get_from_feed(ext: &FeedExtensions) -> Option<&Self> {
        ext.podcast.as_ref()
    }
}
