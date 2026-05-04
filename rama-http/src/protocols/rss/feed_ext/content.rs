//! `content:encoded` extension (<http://purl.org/rss/1.0/modules/content/>).

use super::private;
use super::{FeedExtension, ItemExtensionGet, ItemExtensions};

/// `content:encoded` extension — carries full HTML/XHTML body for a feed item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Content {
    pub encoded: Option<String>,
}

impl private::Sealed for Content {}
impl FeedExtension for Content {}

impl ItemExtensionGet for Content {
    fn get_from_item(ext: &ItemExtensions) -> Option<&Self> {
        ext.content.as_ref()
    }
}
