//! Media RSS extension (<http://search.yahoo.com/mrss/>).

use super::private;
use super::{FeedExtension, ItemExtensionGet, ItemExtensions};

/// A single `media:content` element.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MediaContent {
    pub url: Option<String>,
    pub type_: Option<String>,
    pub medium: Option<String>,
    pub duration: Option<u64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub file_size: Option<u64>,
    pub bitrate: Option<u32>,
    pub title: Option<String>,
    pub description: Option<String>,
}

/// A `media:thumbnail` element.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaThumbnail {
    pub url: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

/// Media RSS extension for a feed item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MediaRss {
    pub contents: Vec<MediaContent>,
    pub thumbnail: Option<MediaThumbnail>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub keywords: Option<String>,
    pub rating: Option<String>,
}

impl private::Sealed for MediaRss {}
impl FeedExtension for MediaRss {}

impl ItemExtensionGet for MediaRss {
    fn get_from_item(ext: &ItemExtensions) -> Option<&Self> {
        ext.media.as_ref()
    }
}
