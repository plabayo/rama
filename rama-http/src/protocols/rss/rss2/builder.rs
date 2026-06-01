use std::marker::PhantomData;

use jiff::Timestamp;
use rama_utils::macros::generate_set_and_with;

use super::types::{Missing, Present, Rss2Category, Rss2Feed, Rss2Image, Rss2Item};
use crate::protocols::rss::atom::AtomLink;
use crate::protocols::rss::feed_ext::FeedExtensions;

/// Type-state builder for [`Rss2Feed`].
///
/// `T`, `L`, and `D` track whether `title`, `link`, and `description` have
/// been provided. [`build`](Rss2FeedBuilder::build) is only available once
/// all three are `Present`.
pub struct Rss2FeedBuilder<T, L, D> {
    pub(super) title: String,
    pub(super) link: String,
    pub(super) description: String,
    pub(super) language: Option<String>,
    pub(super) copyright: Option<String>,
    pub(super) managing_editor: Option<String>,
    pub(super) web_master: Option<String>,
    pub(super) pub_date: Option<Timestamp>,
    pub(super) last_build_date: Option<Timestamp>,
    pub(super) categories: Vec<Rss2Category>,
    pub(super) generator: Option<String>,
    pub(super) docs: Option<String>,
    pub(super) ttl: Option<u32>,
    pub(super) image: Option<Rss2Image>,
    pub(super) atom_links: Vec<AtomLink>,
    pub(super) items: Vec<Rss2Item>,
    pub(super) extensions: FeedExtensions,
    pub(super) _pd: PhantomData<(T, L, D)>,
}

impl Rss2FeedBuilder<Missing, Missing, Missing> {
    pub(super) fn new() -> Self {
        Self {
            title: String::new(),
            link: String::new(),
            description: String::new(),
            language: None,
            copyright: None,
            managing_editor: None,
            web_master: None,
            pub_date: None,
            last_build_date: None,
            categories: Vec::new(),
            generator: None,
            docs: None,
            ttl: None,
            image: None,
            atom_links: Vec::new(),
            items: Vec::new(),
            extensions: FeedExtensions::default(),
            _pd: PhantomData,
        }
    }
}

impl<L, D> Rss2FeedBuilder<Missing, L, D> {
    #[must_use]
    pub fn title(self, title: impl Into<String>) -> Rss2FeedBuilder<Present, L, D> {
        Rss2FeedBuilder {
            title: title.into(),
            link: self.link,
            description: self.description,
            language: self.language,
            copyright: self.copyright,
            managing_editor: self.managing_editor,
            web_master: self.web_master,
            pub_date: self.pub_date,
            last_build_date: self.last_build_date,
            categories: self.categories,
            generator: self.generator,
            docs: self.docs,
            ttl: self.ttl,
            image: self.image,
            atom_links: self.atom_links,
            items: self.items,
            extensions: self.extensions,
            _pd: PhantomData,
        }
    }
}

impl<T, D> Rss2FeedBuilder<T, Missing, D> {
    #[must_use]
    pub fn link(self, link: impl Into<String>) -> Rss2FeedBuilder<T, Present, D> {
        Rss2FeedBuilder {
            title: self.title,
            link: link.into(),
            description: self.description,
            language: self.language,
            copyright: self.copyright,
            managing_editor: self.managing_editor,
            web_master: self.web_master,
            pub_date: self.pub_date,
            last_build_date: self.last_build_date,
            categories: self.categories,
            generator: self.generator,
            docs: self.docs,
            ttl: self.ttl,
            image: self.image,
            atom_links: self.atom_links,
            items: self.items,
            extensions: self.extensions,
            _pd: PhantomData,
        }
    }
}

impl<T, L> Rss2FeedBuilder<T, L, Missing> {
    #[must_use]
    pub fn description(self, desc: impl Into<String>) -> Rss2FeedBuilder<T, L, Present> {
        Rss2FeedBuilder {
            title: self.title,
            link: self.link,
            description: desc.into(),
            language: self.language,
            copyright: self.copyright,
            managing_editor: self.managing_editor,
            web_master: self.web_master,
            pub_date: self.pub_date,
            last_build_date: self.last_build_date,
            categories: self.categories,
            generator: self.generator,
            docs: self.docs,
            ttl: self.ttl,
            image: self.image,
            atom_links: self.atom_links,
            items: self.items,
            extensions: self.extensions,
            _pd: PhantomData,
        }
    }
}

impl<T, L, D> Rss2FeedBuilder<T, L, D> {
    generate_set_and_with! {
        pub fn language(mut self, lang: impl Into<String>) -> Self {
            self.language = Some(lang.into());
            self
        }
    }

    generate_set_and_with! {
        pub fn copyright(mut self, copyright: impl Into<String>) -> Self {
            self.copyright = Some(copyright.into());
            self
        }
    }

    generate_set_and_with! {
        pub fn managing_editor(mut self, editor: impl Into<String>) -> Self {
            self.managing_editor = Some(editor.into());
            self
        }
    }

    generate_set_and_with! {
        pub fn web_master(mut self, wm: impl Into<String>) -> Self {
            self.web_master = Some(wm.into());
            self
        }
    }

    generate_set_and_with! {
        pub fn pub_date(mut self, date: Timestamp) -> Self {
            self.pub_date = Some(date);
            self
        }
    }

    generate_set_and_with! {
        pub fn last_build_date(mut self, date: Timestamp) -> Self {
            self.last_build_date = Some(date);
            self
        }
    }

    generate_set_and_with! {
        /// Append a channel-level category. Call multiple times to attach more.
        pub fn category(mut self, cat: Rss2Category) -> Self {
            self.categories.push(cat);
            self
        }
    }

    generate_set_and_with! {
        pub fn generator(mut self, generator: impl Into<String>) -> Self {
            self.generator = Some(generator.into());
            self
        }
    }

    generate_set_and_with! {
        /// RSS 2.0 `<docs>` — URL pointing at the RSS specification this
        /// document conforms to. Optional; the conventional value is
        /// `https://www.rssboard.org/rss-specification`.
        pub fn docs(mut self, docs: impl Into<String>) -> Self {
            self.docs = Some(docs.into());
            self
        }
    }

    generate_set_and_with! {
        pub fn ttl(mut self, ttl: u32) -> Self {
            self.ttl = Some(ttl);
            self
        }
    }

    generate_set_and_with! {
        pub fn image(mut self, image: Rss2Image) -> Self {
            self.image = Some(image);
            self
        }
    }

    generate_set_and_with! {
        /// Append a channel-level `<atom:link>`. The conventional `rel="self"`
        /// element required by podcast directories is built via
        /// [`AtomLink::self_link`].
        pub fn atom_link(mut self, link: AtomLink) -> Self {
            self.atom_links.push(link);
            self
        }
    }

    generate_set_and_with! {
        /// Append a single item. Call multiple times to attach more.
        pub fn item(mut self, item: Rss2Item) -> Self {
            self.items.push(item);
            self
        }
    }

    generate_set_and_with! {
        pub fn items(mut self, items: impl IntoIterator<Item = Rss2Item>) -> Self {
            self.items.extend(items);
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

impl Rss2FeedBuilder<Present, Present, Present> {
    #[must_use]
    pub fn build(self) -> Rss2Feed {
        Rss2Feed {
            title: self.title,
            link: self.link,
            description: self.description,
            language: self.language,
            copyright: self.copyright,
            managing_editor: self.managing_editor,
            web_master: self.web_master,
            pub_date: self.pub_date,
            last_build_date: self.last_build_date,
            categories: self.categories,
            generator: self.generator,
            docs: self.docs,
            ttl: self.ttl,
            image: self.image,
            atom_links: self.atom_links,
            items: self.items,
            extensions: self.extensions,
        }
    }
}
