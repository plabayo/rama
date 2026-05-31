//! Core RSS 2.0 element and attribute local-name constants. Same single-source
//! guarantee as [`super::super::feed_ext::names`]: parser and writer reference
//! the same const so a typo can't desync them.

/// `<rss>`, `<channel>`, `<item>` and friends.
pub(in super::super) mod elem {
    pub(in super::super::super) const RSS: &str = "rss";
    pub(in super::super::super) const CHANNEL: &str = "channel";
    pub(in super::super::super) const ITEM: &str = "item";
    pub(in super::super::super) const TITLE: &str = "title";
    pub(in super::super::super) const LINK: &str = "link";
    pub(in super::super::super) const DESCRIPTION: &str = "description";
    pub(in super::super::super) const LANGUAGE: &str = "language";
    pub(in super::super::super) const COPYRIGHT: &str = "copyright";
    pub(in super::super::super) const MANAGING_EDITOR: &str = "managingEditor";
    pub(in super::super::super) const WEB_MASTER: &str = "webMaster";
    pub(in super::super::super) const PUB_DATE: &str = "pubDate";
    pub(in super::super::super) const LAST_BUILD_DATE: &str = "lastBuildDate";
    pub(in super::super::super) const CATEGORY: &str = "category";
    pub(in super::super::super) const GENERATOR: &str = "generator";
    pub(in super::super::super) const DOCS: &str = "docs";
    pub(in super::super::super) const TTL: &str = "ttl";
    pub(in super::super::super) const IMAGE: &str = "image";
    pub(in super::super::super) const URL: &str = "url";
    pub(in super::super::super) const WIDTH: &str = "width";
    pub(in super::super::super) const HEIGHT: &str = "height";
    pub(in super::super::super) const AUTHOR: &str = "author";
    pub(in super::super::super) const COMMENTS: &str = "comments";
    pub(in super::super::super) const ENCLOSURE: &str = "enclosure";
    pub(in super::super::super) const GUID: &str = "guid";
    pub(in super::super::super) const SOURCE: &str = "source";
    /// `<atom:link>` channel-level link element (uses the Atom prefix even
    /// when embedded in an RSS document).
    pub(in super::super::super) const ATOM_LINK: &str = "atom:link";
}
