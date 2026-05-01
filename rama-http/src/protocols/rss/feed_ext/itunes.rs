//! iTunes podcast extension (<http://www.itunes.com/dtds/podcast-1.0.dtd>).

use super::private;
use super::{FeedExtension, FeedExtensionGet, FeedExtensions, ItemExtensionGet, ItemExtensions};

/// iTunes extension fields for a single podcast episode item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ITunes {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subtitle: Option<String>,
    pub summary: Option<String>,
    pub image: Option<String>,
    pub duration: Option<String>,
    pub explicit: Option<bool>,
    pub episode: Option<u64>,
    pub season: Option<u64>,
    pub episode_type: Option<String>,
    pub block: Option<bool>,
    pub keywords: Option<String>,
}

impl private::Sealed for ITunes {}
impl FeedExtension for ITunes {}

impl ItemExtensionGet for ITunes {
    fn get_from_item(ext: &ItemExtensions) -> Option<&Self> {
        ext.itunes.as_ref()
    }
}

/// iTunes extension fields at the feed (channel) level.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ITunesFeed {
    pub author: Option<String>,
    pub owner_name: Option<String>,
    pub owner_email: Option<String>,
    pub image: Option<String>,
    pub categories: Vec<String>,
    pub explicit: Option<bool>,
    pub type_: Option<String>,
    pub new_feed_url: Option<String>,
    pub block: Option<bool>,
    pub complete: Option<bool>,
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub summary: Option<String>,
}

impl private::Sealed for ITunesFeed {}
impl FeedExtension for ITunesFeed {}

impl FeedExtensionGet for ITunesFeed {
    fn get_from_feed(ext: &FeedExtensions) -> Option<&Self> {
        ext.itunes.as_ref()
    }
}
