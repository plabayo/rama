//! Core Atom 1.0 element local-name constants. Same single-source guarantee
//! as [`super::super::feed_ext::names`]: parser and writer reference the
//! same const so a typo can't desync them.

pub(in super::super) mod elem {
    pub(in super::super::super) const FEED: &str = "feed";
    pub(in super::super::super) const ENTRY: &str = "entry";
    pub(in super::super::super) const ID: &str = "id";
    pub(in super::super::super) const TITLE: &str = "title";
    pub(in super::super::super) const UPDATED: &str = "updated";
    pub(in super::super::super) const PUBLISHED: &str = "published";
    pub(in super::super::super) const AUTHOR: &str = "author";
    pub(in super::super::super) const CONTRIBUTOR: &str = "contributor";
    pub(in super::super::super) const LINK: &str = "link";
    pub(in super::super::super) const CATEGORY: &str = "category";
    pub(in super::super::super) const GENERATOR: &str = "generator";
    pub(in super::super::super) const ICON: &str = "icon";
    pub(in super::super::super) const LOGO: &str = "logo";
    pub(in super::super::super) const RIGHTS: &str = "rights";
    pub(in super::super::super) const SUBTITLE: &str = "subtitle";
    pub(in super::super::super) const SUMMARY: &str = "summary";
    pub(in super::super::super) const CONTENT: &str = "content";
    pub(in super::super::super) const SOURCE: &str = "source";
    pub(in super::super::super) const NAME: &str = "name";
    pub(in super::super::super) const EMAIL: &str = "email";
    pub(in super::super::super) const URI: &str = "uri";
    pub(in super::super::super) const DIV: &str = "div";
}
