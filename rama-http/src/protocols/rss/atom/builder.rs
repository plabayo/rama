use std::marker::PhantomData;

use jiff::Timestamp;
use rama_net::uri::Uri;
use rama_utils::macros::generate_set_and_with;

use super::types::{
    AtomCategory, AtomEntry, AtomFeed, AtomGenerator, AtomLink, AtomPerson, AtomText,
};
use crate::protocols::rss::feed_ext::FeedExtensions;
use crate::protocols::rss::rss2::{Missing, Present};

/// Type-state builder for [`AtomFeed`].
///
/// `I`, `T`, and `U` track whether `id`, `title`, and `updated` have been
/// provided. [`build`](AtomFeedBuilder::build) is only available once all
/// three are `Present`.
pub struct AtomFeedBuilder<I, T, U> {
    pub(super) id: Option<Uri>,
    pub(super) title: AtomText,
    pub(super) updated: Option<Timestamp>,
    pub(super) authors: Vec<AtomPerson>,
    pub(super) links: Vec<AtomLink>,
    pub(super) categories: Vec<AtomCategory>,
    pub(super) contributors: Vec<AtomPerson>,
    pub(super) generator: Option<AtomGenerator>,
    pub(super) icon: Option<Uri>,
    pub(super) logo: Option<Uri>,
    pub(super) rights: Option<AtomText>,
    pub(super) subtitle: Option<AtomText>,
    pub(super) entries: Vec<AtomEntry>,
    pub(super) extensions: FeedExtensions,
    pub(super) _pd: PhantomData<(I, T, U)>,
}

impl AtomFeedBuilder<Missing, Missing, Missing> {
    pub(super) fn new() -> Self {
        Self {
            id: None,
            title: AtomText::text(""),
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
    pub fn id(self, id: Uri) -> AtomFeedBuilder<Present, T, U> {
        AtomFeedBuilder {
            id: Some(id),
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
    generate_set_and_with! {
        /// Append a feed-level author. Call multiple times to add more.
        pub fn author(mut self, author: AtomPerson) -> Self {
            self.authors.push(author);
            self
        }
    }

    generate_set_and_with! {
        /// Append a feed-level `<link>`. Call multiple times to add more.
        pub fn link(mut self, link: AtomLink) -> Self {
            self.links.push(link);
            self
        }
    }

    generate_set_and_with! {
        /// Append a feed-level category. Call multiple times to add more.
        pub fn category(mut self, cat: AtomCategory) -> Self {
            self.categories.push(cat);
            self
        }
    }

    generate_set_and_with! {
        /// Append a feed-level contributor. Call multiple times to add more.
        pub fn contributor(mut self, c: AtomPerson) -> Self {
            self.contributors.push(c);
            self
        }
    }

    generate_set_and_with! {
        pub fn generator(mut self, generator: AtomGenerator) -> Self {
            self.generator = Some(generator);
            self
        }
    }

    generate_set_and_with! {
        pub fn icon(mut self, icon: Uri) -> Self {
            self.icon = Some(icon);
            self
        }
    }

    generate_set_and_with! {
        pub fn logo(mut self, logo: Uri) -> Self {
            self.logo = Some(logo);
            self
        }
    }

    generate_set_and_with! {
        pub fn rights(mut self, rights: impl Into<AtomText>) -> Self {
            self.rights = Some(rights.into());
            self
        }
    }

    generate_set_and_with! {
        pub fn subtitle(mut self, subtitle: impl Into<AtomText>) -> Self {
            self.subtitle = Some(subtitle.into());
            self
        }
    }

    generate_set_and_with! {
        /// Append a single entry. Call multiple times to attach more.
        pub fn entry(mut self, entry: AtomEntry) -> Self {
            self.entries.push(entry);
            self
        }
    }

    generate_set_and_with! {
        pub fn entries(mut self, entries: impl IntoIterator<Item = AtomEntry>) -> Self {
            self.entries.extend(entries);
            self
        }
    }

    generate_set_and_with! {
        pub fn feed_extensions(mut self, ext: FeedExtensions) -> Self {
            self.extensions = ext;
            self
        }
    }
}

impl AtomFeedBuilder<Present, Present, Present> {
    #[must_use]
    pub fn build(self) -> AtomFeed {
        AtomFeed {
            #[expect(
                clippy::expect_used,
                reason = "type-state guarantees `id` is Present once build() is callable"
            )]
            id: self.id.expect("id is Present"),
            title: self.title,
            #[expect(
                clippy::expect_used,
                reason = "type-state guarantees `updated` is Present once build() is callable"
            )]
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
