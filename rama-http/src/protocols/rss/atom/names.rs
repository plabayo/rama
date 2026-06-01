//! Core Atom 1.0 element local-name constants. Same single-source guarantee
//! as [`crate::protocols::rss::feed_ext::names`]: parser and writer reference the
//! same const so a typo can't desync them.

pub(in crate::protocols::rss) mod elem {
    pub(in crate::protocols::rss) const FEED: &str = "feed";
    pub(in crate::protocols::rss) const ENTRY: &str = "entry";
    pub(in crate::protocols::rss) const ID: &str = "id";
    pub(in crate::protocols::rss) const TITLE: &str = "title";
    pub(in crate::protocols::rss) const UPDATED: &str = "updated";
    pub(in crate::protocols::rss) const PUBLISHED: &str = "published";
    pub(in crate::protocols::rss) const AUTHOR: &str = "author";
    pub(in crate::protocols::rss) const CONTRIBUTOR: &str = "contributor";
    pub(in crate::protocols::rss) const LINK: &str = "link";
    pub(in crate::protocols::rss) const CATEGORY: &str = "category";
    pub(in crate::protocols::rss) const GENERATOR: &str = "generator";
    pub(in crate::protocols::rss) const ICON: &str = "icon";
    pub(in crate::protocols::rss) const LOGO: &str = "logo";
    pub(in crate::protocols::rss) const RIGHTS: &str = "rights";
    pub(in crate::protocols::rss) const SUBTITLE: &str = "subtitle";
    pub(in crate::protocols::rss) const SUMMARY: &str = "summary";
    pub(in crate::protocols::rss) const CONTENT: &str = "content";
    pub(in crate::protocols::rss) const SOURCE: &str = "source";
    pub(in crate::protocols::rss) const NAME: &str = "name";
    pub(in crate::protocols::rss) const EMAIL: &str = "email";
    pub(in crate::protocols::rss) const URI: &str = "uri";
    pub(in crate::protocols::rss) const DIV: &str = "div";
}
