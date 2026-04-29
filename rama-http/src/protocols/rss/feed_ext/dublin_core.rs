//! Dublin Core elements extension (<http://purl.org/dc/elements/1.1/>).

use jiff::Timestamp;

use super::private;
use super::{FeedExtension, FeedExtensionGet, FeedExtensions, ItemExtensionGet, ItemExtensions};

/// Dublin Core extension fields for a feed item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DublinCore {
    pub title: Option<String>,
    pub creator: Option<String>,
    pub subject: Option<String>,
    pub description: Option<String>,
    pub publisher: Option<String>,
    pub contributor: Option<String>,
    pub date: Option<Timestamp>,
    pub type_: Option<String>,
    pub format: Option<String>,
    pub identifier: Option<String>,
    pub source: Option<String>,
    pub language: Option<String>,
    pub relation: Option<String>,
    pub coverage: Option<String>,
    pub rights: Option<String>,
}

impl private::Sealed for DublinCore {}
impl FeedExtension for DublinCore {}

impl ItemExtensionGet for DublinCore {
    fn get_from_item(ext: &ItemExtensions) -> Option<&Self> {
        ext.dublin_core.as_ref()
    }
}

/// Dublin Core extension fields at the feed (channel) level.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DublinCoreFeed {
    pub title: Option<String>,
    pub creator: Option<String>,
    pub subject: Option<String>,
    pub description: Option<String>,
    pub publisher: Option<String>,
    pub contributor: Option<String>,
    pub date: Option<Timestamp>,
    pub type_: Option<String>,
    pub format: Option<String>,
    pub identifier: Option<String>,
    pub source: Option<String>,
    pub language: Option<String>,
    pub relation: Option<String>,
    pub coverage: Option<String>,
    pub rights: Option<String>,
}

impl private::Sealed for DublinCoreFeed {}
impl FeedExtension for DublinCoreFeed {}

impl FeedExtensionGet for DublinCoreFeed {
    fn get_from_feed(ext: &FeedExtensions) -> Option<&Self> {
        ext.dublin_core.as_ref()
    }
}
