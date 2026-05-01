use std::marker::PhantomData;

use jiff::Timestamp;

use super::super::feed_ext::FeedExtensions;
use super::types::{
    Missing, Present, Rss2Category, Rss2Feed, Rss2Image, Rss2Item,
};

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
            items: self.items,
            extensions: self.extensions,
            _pd: PhantomData,
        }
    }
}

impl<T, L, D> Rss2FeedBuilder<T, L, D> {
    #[must_use]
    pub fn language(mut self, lang: impl Into<String>) -> Self {
        self.language = Some(lang.into());
        self
    }

    #[must_use]
    pub fn copyright(mut self, copyright: impl Into<String>) -> Self {
        self.copyright = Some(copyright.into());
        self
    }

    #[must_use]
    pub fn managing_editor(mut self, editor: impl Into<String>) -> Self {
        self.managing_editor = Some(editor.into());
        self
    }

    #[must_use]
    pub fn web_master(mut self, wm: impl Into<String>) -> Self {
        self.web_master = Some(wm.into());
        self
    }

    #[must_use]
    pub fn pub_date(mut self, date: Timestamp) -> Self {
        self.pub_date = Some(date);
        self
    }

    #[must_use]
    pub fn last_build_date(mut self, date: Timestamp) -> Self {
        self.last_build_date = Some(date);
        self
    }

    #[must_use]
    pub fn category(mut self, cat: Rss2Category) -> Self {
        self.categories.push(cat);
        self
    }

    #[must_use]
    pub fn generator(mut self, generator: impl Into<String>) -> Self {
        self.generator = Some(generator.into());
        self
    }

    #[must_use]
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    #[must_use]
    pub fn image(mut self, image: Rss2Image) -> Self {
        self.image = Some(image);
        self
    }

    #[must_use]
    pub fn item(mut self, item: Rss2Item) -> Self {
        self.items.push(item);
        self
    }

    #[must_use]
    pub fn items(mut self, items: impl IntoIterator<Item = Rss2Item>) -> Self {
        self.items.extend(items);
        self
    }

    #[must_use]
    pub fn feed_extensions(mut self, ext: FeedExtensions) -> Self {
        self.extensions = ext;
        self
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
            items: self.items,
            extensions: self.extensions,
        }
    }
}
