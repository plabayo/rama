use std::marker::PhantomData;

use jiff::Timestamp;

use super::super::feed_ext::FeedExtensions;
use super::super::rss2::{Missing, Present};
use super::types::{
    AtomCategory, AtomEntry, AtomFeed, AtomGenerator, AtomLink, AtomPerson, AtomText,
};

/// Type-state builder for [`AtomFeed`].
///
/// `I`, `T`, and `U` track whether `id`, `title`, and `updated` have been
/// provided. [`build`](AtomFeedBuilder::build) is only available once all
/// three are `Present`.
pub struct AtomFeedBuilder<I, T, U> {
    pub(super) id: String,
    pub(super) title: AtomText,
    pub(super) updated: Option<Timestamp>,
    pub(super) authors: Vec<AtomPerson>,
    pub(super) links: Vec<AtomLink>,
    pub(super) categories: Vec<AtomCategory>,
    pub(super) contributors: Vec<AtomPerson>,
    pub(super) generator: Option<AtomGenerator>,
    pub(super) icon: Option<String>,
    pub(super) logo: Option<String>,
    pub(super) rights: Option<AtomText>,
    pub(super) subtitle: Option<AtomText>,
    pub(super) entries: Vec<AtomEntry>,
    pub(super) extensions: FeedExtensions,
    pub(super) _pd: PhantomData<(I, T, U)>,
}

impl AtomFeedBuilder<Missing, Missing, Missing> {
    pub(super) fn new() -> Self {
        Self {
            id: String::new(),
            title: AtomText::Text(String::new()),
            updated: None,
            authors: Vec::new(),
            links: Vec::new(),
            categories: Vec::new(),
            contributors: Vec::new(),
            generator: None,
            icon: None,
            logo: None,
            rights: None,
            subtitle: None,
            entries: Vec::new(),
            extensions: FeedExtensions::default(),
            _pd: PhantomData,
        }
    }
}

impl<T, U> AtomFeedBuilder<Missing, T, U> {
    #[must_use]
    pub fn id(self, id: impl Into<String>) -> AtomFeedBuilder<Present, T, U> {
        AtomFeedBuilder {
            id: id.into(),
            title: self.title,
            updated: self.updated,
            authors: self.authors,
            links: self.links,
            categories: self.categories,
            contributors: self.contributors,
            generator: self.generator,
            icon: self.icon,
            logo: self.logo,
            rights: self.rights,
            subtitle: self.subtitle,
            entries: self.entries,
            extensions: self.extensions,
            _pd: PhantomData,
        }
    }
}

impl<I, U> AtomFeedBuilder<I, Missing, U> {
    #[must_use]
    pub fn title(self, title: impl Into<AtomText>) -> AtomFeedBuilder<I, Present, U> {
        AtomFeedBuilder {
            id: self.id,
            title: title.into(),
            updated: self.updated,
            authors: self.authors,
            links: self.links,
            categories: self.categories,
            contributors: self.contributors,
            generator: self.generator,
            icon: self.icon,
            logo: self.logo,
            rights: self.rights,
            subtitle: self.subtitle,
            entries: self.entries,
            extensions: self.extensions,
            _pd: PhantomData,
        }
    }
}

impl<I, T> AtomFeedBuilder<I, T, Missing> {
    #[must_use]
    pub fn updated(self, ts: Timestamp) -> AtomFeedBuilder<I, T, Present> {
        AtomFeedBuilder {
            id: self.id,
            title: self.title,
            updated: Some(ts),
            authors: self.authors,
            links: self.links,
            categories: self.categories,
            contributors: self.contributors,
            generator: self.generator,
            icon: self.icon,
            logo: self.logo,
            rights: self.rights,
            subtitle: self.subtitle,
            entries: self.entries,
            extensions: self.extensions,
            _pd: PhantomData,
        }
    }
}

impl<I, T, U> AtomFeedBuilder<I, T, U> {
    #[must_use]
    pub fn author(mut self, author: AtomPerson) -> Self {
        self.authors.push(author);
        self
    }

    #[must_use]
    pub fn link(mut self, link: AtomLink) -> Self {
        self.links.push(link);
        self
    }

    #[must_use]
    pub fn category(mut self, cat: AtomCategory) -> Self {
        self.categories.push(cat);
        self
    }

    #[must_use]
    pub fn contributor(mut self, c: AtomPerson) -> Self {
        self.contributors.push(c);
        self
    }

    #[must_use]
    pub fn generator(mut self, generator: AtomGenerator) -> Self {
        self.generator = Some(generator);
        self
    }

    #[must_use]
    pub fn icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    #[must_use]
    pub fn logo(mut self, logo: impl Into<String>) -> Self {
        self.logo = Some(logo.into());
        self
    }

    #[must_use]
    pub fn rights(mut self, rights: impl Into<AtomText>) -> Self {
        self.rights = Some(rights.into());
        self
    }

    #[must_use]
    pub fn subtitle(mut self, subtitle: impl Into<AtomText>) -> Self {
        self.subtitle = Some(subtitle.into());
        self
    }

    #[must_use]
    pub fn entry(mut self, entry: AtomEntry) -> Self {
        self.entries.push(entry);
        self
    }

    #[must_use]
    pub fn entries(mut self, entries: impl IntoIterator<Item = AtomEntry>) -> Self {
        self.entries.extend(entries);
        self
    }

    #[must_use]
    pub fn feed_extensions(mut self, ext: FeedExtensions) -> Self {
        self.extensions = ext;
        self
    }
}

impl AtomFeedBuilder<Present, Present, Present> {
    #[must_use]
    pub fn build(self) -> AtomFeed {
        AtomFeed {
            id: self.id,
            title: self.title,
            #[allow(clippy::expect_used)]
            updated: self.updated.expect("updated is Present"),
            authors: self.authors,
            links: self.links,
            categories: self.categories,
            contributors: self.contributors,
            generator: self.generator,
            icon: self.icon,
            logo: self.logo,
            rights: self.rights,
            subtitle: self.subtitle,
            entries: self.entries,
            extensions: self.extensions,
        }
    }
}
