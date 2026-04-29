use jiff::Timestamp;

use super::super::feed_ext::{
    Content, DublinCore, FeedExtension, ITunes, ItemExtensionGet, ItemExtensions, MediaRss, Podcast,
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
    pub items: Vec<Rss2Item>,
    pub extensions: super::super::feed_ext::FeedExtensions,
}

impl Rss2Feed {
    #[must_use]
    pub fn builder() -> super::builder::Rss2FeedBuilder<Missing, Missing, Missing> {
        super::builder::Rss2FeedBuilder::new()
    }

    pub fn to_xml(&self) -> Result<Vec<u8>, super::super::ser::XmlWriteError> {
        use quick_xml::{Writer, events::{BytesDecl, Event}};
        let mut buf = Vec::with_capacity(4096);
        let mut w = Writer::new(&mut buf);
        w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
        super::write::write_rss2_feed(&mut w, self)?;
        Ok(buf)
    }
}

impl std::fmt::Display for Rss2Feed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let xml = self.to_xml().map_err(|_| std::fmt::Error)?;
        f.write_str(std::str::from_utf8(&xml).map_err(|_| std::fmt::Error)?)
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
    pub enclosure: Option<Rss2Enclosure>,
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

    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    #[must_use]
    pub fn with_link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(link.into());
        self
    }

    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    #[must_use]
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    #[must_use]
    pub fn with_category(mut self, cat: Rss2Category) -> Self {
        self.categories.push(cat);
        self
    }

    #[must_use]
    pub fn with_guid(mut self, guid: Rss2Guid) -> Self {
        self.guid = Some(guid);
        self
    }

    #[must_use]
    pub fn with_pub_date(mut self, date: Timestamp) -> Self {
        self.pub_date = Some(date);
        self
    }

    #[must_use]
    pub fn with_enclosure(mut self, enc: Rss2Enclosure) -> Self {
        self.enclosure = Some(enc);
        self
    }

    #[must_use]
    pub fn with_source(mut self, src: Rss2Source) -> Self {
        self.source = Some(src);
        self
    }

    #[must_use]
    pub fn with_extensions(mut self, ext: ItemExtensions) -> Self {
        self.extensions = ext;
        self
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

    #[must_use]
    pub fn extension<T>(&self) -> Option<&T>
    where
        T: FeedExtension + ItemExtensionGet,
    {
        self.extensions.get::<T>()
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

    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
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
