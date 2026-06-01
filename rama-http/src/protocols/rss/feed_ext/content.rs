//! `content:encoded` extension (<http://purl.org/rss/1.0/modules/content/>).

/// `content:encoded` extension — carries full HTML/XHTML body for a feed item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Content {
    pub encoded: Option<String>,
}
