use jiff::Timestamp;
use rama_utils::macros::generate_set_and_with;

use crate::protocols::rss::atom::AtomLink;
use crate::protocols::rss::feed_ext::{
    Content, DublinCore, ITunes, ItemExtensions, MediaRss, Podcast,
};

// Type-state markers shared with the atom module.
#[doc(hidden)]
pub struct Missing;
#[doc(hidden)]
pub struct Present;

/// An RSS 2.0 feed.
#[derive(Debug, Clone, PartialEq)]
pub struct Rss2Feed {
    pub title: String,
    pub link: String,
    pub description: String,
    pub language: Option<String>,
    pub copyright: Option<String>,
    pub managing_editor: Option<String>,
    pub web_master: Option<String>,
    pub pub_date: Option<Timestamp>,
    pub last_build_date: Option<Timestamp>,
    pub categories: Vec<Rss2Category>,
    pub generator: Option<String>,
    pub docs: Option<String>,
    pub ttl: Option<u32>,
    pub image: Option<Rss2Image>,
    /// Channel-level `<atom:link>` elements (most commonly the
    /// `rel="self"` link required by podcast directories, but any are kept).
    /// Serialized with `xmlns:atom` declared on `<rss>` when non-empty.
    pub atom_links: Vec<AtomLink>,
    pub items: Vec<Rss2Item>,
    pub extensions: crate::protocols::rss::feed_ext::FeedExtensions,
}

impl Rss2Feed {
    #[must_use]
    pub fn builder() -> super::builder::Rss2FeedBuilder<Missing, Missing, Missing> {
        super::builder::Rss2FeedBuilder::new()
    }

    /// Stream the feed as XML bytes. Equivalent to
    /// [`crate::protocols::rss::Rss2StreamWriter::from_feed`]; provided as a method for
    /// discoverability when starting from a whole in-memory feed.
    ///
    /// Plugs directly into [`crate::Body::from_stream`].
    #[must_use]
    pub fn into_stream_writer(
        self,
    ) -> crate::protocols::rss::Rss2StreamWriter<
        rama_core::futures::stream::BoxStream<
            'static,
            Result<Rss2Item, rama_core::error::BoxError>,
        >,
    > {
        crate::protocols::rss::Rss2StreamWriter::from_feed(self)
    }

    /// Drain [`Self::into_stream_writer`] into an in-memory `Vec<u8>`. The
    /// convenience "collect" form when you don't actually need streaming.
    pub async fn to_xml(self) -> Result<Vec<u8>, rama_core::error::BoxError> {
        use rama_core::futures::StreamExt as _;
        let mut stream = self.into_stream_writer();
        let mut buf = Vec::with_capacity(4096);
        while let Some(chunk) = stream.next().await {
            buf.extend_from_slice(&chunk?);
        }
        Ok(buf)
    }
}

/// An RSS 2.0 channel item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Rss2Item {
    pub title: Option<String>,
    pub link: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub categories: Vec<Rss2Category>,
    pub comments: Option<String>,
    /// All `<enclosure>` elements on this item. Most real-world feeds carry
    /// exactly one, but some (multi-format podcasts, Spotify-exclusive
    /// previews) emit several — we keep them all to round-trip.
    pub enclosures: Vec<Rss2Enclosure>,
    pub guid: Option<Rss2Guid>,
    pub pub_date: Option<Timestamp>,
    pub source: Option<Rss2Source>,
    pub extensions: ItemExtensions,
}

impl Rss2Item {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        pub fn title(mut self, title: impl Into<String>) -> Self {
            self.title = Some(title.into());
            self
        }
    }

    generate_set_and_with! {
        pub fn link(mut self, link: impl Into<String>) -> Self {
            self.link = Some(link.into());
            self
        }
    }

    generate_set_and_with! {
        pub fn description(mut self, desc: impl Into<String>) -> Self {
            self.description = Some(desc.into());
            self
        }
    }

    generate_set_and_with! {
        pub fn author(mut self, author: impl Into<String>) -> Self {
            self.author = Some(author.into());
            self
        }
    }

    generate_set_and_with! {
        /// Append a category. Call multiple times to attach more.
        pub fn category(mut self, cat: Rss2Category) -> Self {
            self.categories.push(cat);
            self
        }
    }

    generate_set_and_with! {
        pub fn guid(mut self, guid: Rss2Guid) -> Self {
            self.guid = Some(guid);
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
        /// Append an `<enclosure>`. Call multiple times to attach more than one.
        pub fn enclosure(mut self, enc: Rss2Enclosure) -> Self {
            self.enclosures.push(enc);
            self
        }
    }

    generate_set_and_with! {
        pub fn source(mut self, src: Rss2Source) -> Self {
            self.source = Some(src);
            self
        }
    }

    generate_set_and_with! {
        pub fn extensions(mut self, ext: ItemExtensions) -> Self {
            self.extensions = ext;
            self
        }
    }

    #[must_use]
    pub fn itunes(&self) -> Option<&ITunes> {
        self.extensions.itunes.as_ref()
    }

    #[must_use]
    pub fn podcast(&self) -> Option<&Podcast> {
        self.extensions.podcast.as_ref()
    }

    #[must_use]
    pub fn dublin_core(&self) -> Option<&DublinCore> {
        self.extensions.dublin_core.as_ref()
    }

    #[must_use]
    pub fn content(&self) -> Option<&Content> {
        self.extensions.content.as_ref()
    }

    #[must_use]
    pub fn media(&self) -> Option<&MediaRss> {
        self.extensions.media.as_ref()
    }
}

/// RSS 2.0 category element.
#[derive(Debug, Clone, PartialEq)]
pub struct Rss2Category {
    pub name: String,
    pub domain: Option<String>,
}

impl Rss2Category {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            domain: None,
        }
    }

    generate_set_and_with! {
        pub fn domain(mut self, domain: impl Into<String>) -> Self {
            self.domain = Some(domain.into());
            self
        }
    }
}

/// RSS 2.0 image element.
#[derive(Debug, Clone, PartialEq)]
pub struct Rss2Image {
    pub url: String,
    pub title: String,
    pub link: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub description: Option<String>,
}

impl Rss2Image {
    #[must_use]
    pub fn new(url: impl Into<String>, title: impl Into<String>, link: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            title: title.into(),
            link: link.into(),
            width: None,
            height: None,
            description: None,
        }
    }
}

/// RSS 2.0 enclosure element.
#[derive(Debug, Clone, PartialEq)]
pub struct Rss2Enclosure {
    pub url: String,
    pub length: u64,
    pub type_: String,
}

impl Rss2Enclosure {
    #[must_use]
    pub fn new(url: impl Into<String>, length: u64, type_: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            length,
            type_: type_.into(),
        }
    }
}

/// RSS 2.0 guid element.
#[derive(Debug, Clone, PartialEq)]
pub struct Rss2Guid {
    pub value: String,
    pub permalink: bool,
}

impl Rss2Guid {
    #[must_use]
    pub fn permalink(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            permalink: true,
        }
    }

    #[must_use]
    pub fn tag(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            permalink: false,
        }
    }
}

/// RSS 2.0 source element.
#[derive(Debug, Clone, PartialEq)]
pub struct Rss2Source {
    pub title: String,
    pub url: String,
}
