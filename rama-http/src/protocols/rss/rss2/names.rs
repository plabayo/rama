//! Core RSS 2.0 element and attribute local-name constants. Same single-source
//! guarantee as [`crate::protocols::rss::feed_ext::names`]: parser and writer reference
//! the same const so a typo can't desync them.

/// `<rss>`, `<channel>`, `<item>` and friends.
pub(in crate::protocols::rss) mod elem {
    pub(in crate::protocols::rss) const RSS: &str = "rss";
    pub(in crate::protocols::rss) const CHANNEL: &str = "channel";
    pub(in crate::protocols::rss) const ITEM: &str = "item";
    pub(in crate::protocols::rss) const TITLE: &str = "title";
    pub(in crate::protocols::rss) const LINK: &str = "link";
    pub(in crate::protocols::rss) const DESCRIPTION: &str = "description";
    pub(in crate::protocols::rss) const LANGUAGE: &str = "language";
    pub(in crate::protocols::rss) const COPYRIGHT: &str = "copyright";
    pub(in crate::protocols::rss) const MANAGING_EDITOR: &str = "managingEditor";
    pub(in crate::protocols::rss) const WEB_MASTER: &str = "webMaster";
    pub(in crate::protocols::rss) const PUB_DATE: &str = "pubDate";
    pub(in crate::protocols::rss) const LAST_BUILD_DATE: &str = "lastBuildDate";
    pub(in crate::protocols::rss) const CATEGORY: &str = "category";
    pub(in crate::protocols::rss) const GENERATOR: &str = "generator";
    pub(in crate::protocols::rss) const DOCS: &str = "docs";
    pub(in crate::protocols::rss) const TTL: &str = "ttl";
    pub(in crate::protocols::rss) const IMAGE: &str = "image";
    pub(in crate::protocols::rss) const URL: &str = "url";
    pub(in crate::protocols::rss) const WIDTH: &str = "width";
    pub(in crate::protocols::rss) const HEIGHT: &str = "height";
    pub(in crate::protocols::rss) const AUTHOR: &str = "author";
    pub(in crate::protocols::rss) const COMMENTS: &str = "comments";
    pub(in crate::protocols::rss) const ENCLOSURE: &str = "enclosure";
    pub(in crate::protocols::rss) const GUID: &str = "guid";
    pub(in crate::protocols::rss) const SOURCE: &str = "source";
    /// `<atom:link>` channel-level link element (uses the Atom prefix even
    /// when embedded in an RSS document).
    pub(in crate::protocols::rss) const ATOM_LINK: &str = "atom:link";
}
