use jiff::Timestamp;

use super::super::feed_ext::{
    Content, DublinCore, FeedExtension, ITunes, ItemExtensionGet, ItemExtensions, MediaRss, Podcast,
};
use super::super::rss2::Missing;

/// Atom text construct — `text`, `html`, or `xhtml`.
#[derive(Debug, Clone, PartialEq)]
pub enum AtomText {
    Text(String),
    Html(String),
    Xhtml(String),
}

impl AtomText {
    #[must_use]
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(s.into())
    }

    #[must_use]
    pub fn html(s: impl Into<String>) -> Self {
        Self::Html(s.into())
    }

    #[must_use]
    pub fn xhtml(s: impl Into<String>) -> Self {
        Self::Xhtml(s.into())
    }

    pub(crate) fn type_attr(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::Html(_) => "html",
            Self::Xhtml(_) => "xhtml",
        }
    }

    pub(crate) fn value(&self) -> &str {
        match self {
            Self::Text(s) | Self::Html(s) | Self::Xhtml(s) => s,
        }
    }
}

impl From<&str> for AtomText {
    fn from(s: &str) -> Self {
        Self::Text(s.to_owned())
    }
}

impl From<String> for AtomText {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}

/// An Atom person construct.
#[derive(Debug, Clone, PartialEq)]
pub struct AtomPerson {
    pub name: String,
    pub email: Option<String>,
    pub uri: Option<String>,
}

impl AtomPerson {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            email: None,
            uri: None,
        }
    }

    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    #[must_use]
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }
}

/// An Atom link element.
#[derive(Debug, Clone, PartialEq)]
pub struct AtomLink {
    pub href: String,
    pub rel: Option<String>,
    pub type_: Option<String>,
    pub hreflang: Option<String>,
    pub title: Option<String>,
    pub length: Option<u64>,
}

impl AtomLink {
    #[must_use]
    pub fn new(href: impl Into<String>) -> Self {
        Self {
            href: href.into(),
            rel: None,
            type_: None,
            hreflang: None,
            title: None,
            length: None,
        }
    }

    #[must_use]
    pub fn alternate(href: impl Into<String>) -> Self {
        Self {
            href: href.into(),
            rel: Some("alternate".into()),
            type_: Some("text/html".into()),
            hreflang: None,
            title: None,
            length: None,
        }
    }

    #[must_use]
    pub fn self_link(href: impl Into<String>) -> Self {
        Self {
            href: href.into(),
            rel: Some("self".into()),
            type_: Some("application/atom+xml".into()),
            hreflang: None,
            title: None,
            length: None,
        }
    }

    #[must_use]
    pub fn enclosure(href: impl Into<String>, length: u64, type_: impl Into<String>) -> Self {
        Self {
            href: href.into(),
            rel: Some("enclosure".into()),
            type_: Some(type_.into()),
            hreflang: None,
            title: None,
            length: Some(length),
        }
    }
}

/// An Atom category element.
#[derive(Debug, Clone, PartialEq)]
pub struct AtomCategory {
    pub term: String,
    pub scheme: Option<String>,
    pub label: Option<String>,
}

impl AtomCategory {
    #[must_use]
    pub fn new(term: impl Into<String>) -> Self {
        Self {
            term: term.into(),
            scheme: None,
            label: None,
        }
    }
}

/// An Atom generator element.
#[derive(Debug, Clone, PartialEq)]
pub struct AtomGenerator {
    pub value: String,
    pub uri: Option<String>,
    pub version: Option<String>,
}

impl AtomGenerator {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            uri: None,
            version: None,
        }
    }
}

/// An Atom content element.
#[derive(Debug, Clone, PartialEq)]
pub struct AtomContent {
    pub value: AtomText,
    pub src: Option<String>,
}

impl AtomContent {
    #[must_use]
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            value: AtomText::text(s),
            src: None,
        }
    }

    #[must_use]
    pub fn html(s: impl Into<String>) -> Self {
        Self {
            value: AtomText::html(s),
            src: None,
        }
    }

    #[must_use]
    pub fn out_of_line(src: impl Into<String>, type_: impl Into<String>) -> Self {
        Self {
            value: AtomText::Text(type_.into()),
            src: Some(src.into()),
        }
    }
}

/// An Atom source element (entry's original feed metadata).
#[derive(Debug, Clone, PartialEq)]
pub struct AtomSource {
    pub id: Option<String>,
    pub title: Option<AtomText>,
    pub updated: Option<Timestamp>,
}

/// An Atom feed.
#[derive(Debug, Clone, PartialEq)]
pub struct AtomFeed {
    pub id: String,
    pub title: AtomText,
    pub updated: Timestamp,
    pub authors: Vec<AtomPerson>,
    pub links: Vec<AtomLink>,
    pub categories: Vec<AtomCategory>,
    pub contributors: Vec<AtomPerson>,
    pub generator: Option<AtomGenerator>,
    pub icon: Option<String>,
    pub logo: Option<String>,
    pub rights: Option<AtomText>,
    pub subtitle: Option<AtomText>,
    pub entries: Vec<AtomEntry>,
    pub extensions: super::super::feed_ext::FeedExtensions,
}

impl AtomFeed {
    #[must_use]
    pub fn builder() -> super::builder::AtomFeedBuilder<Missing, Missing, Missing> {
        super::builder::AtomFeedBuilder::new()
    }

    pub fn to_xml(&self) -> Result<Vec<u8>, super::super::ser::XmlWriteError> {
        use quick_xml::{Writer, events::{BytesDecl, Event}};
        let mut buf = Vec::with_capacity(4096);
        let mut w = Writer::new(&mut buf);
        w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
        super::write::write_atom_feed(&mut w, self)?;
        Ok(buf)
    }
}

impl std::fmt::Display for AtomFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let xml = self.to_xml().map_err(|_| std::fmt::Error)?;
        f.write_str(std::str::from_utf8(&xml).map_err(|_| std::fmt::Error)?)
    }
}

/// An Atom entry.
#[derive(Debug, Clone, PartialEq)]
pub struct AtomEntry {
    pub id: String,
    pub title: AtomText,
    pub updated: Timestamp,
    pub authors: Vec<AtomPerson>,
    pub content: Option<AtomContent>,
    pub links: Vec<AtomLink>,
    pub summary: Option<AtomText>,
    pub categories: Vec<AtomCategory>,
    pub contributors: Vec<AtomPerson>,
    pub published: Option<Timestamp>,
    pub rights: Option<AtomText>,
    pub source: Option<AtomSource>,
    pub extensions: ItemExtensions,
}

impl AtomEntry {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        title: impl Into<AtomText>,
        updated: Timestamp,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            updated,
            authors: Vec::new(),
            content: None,
            links: Vec::new(),
            summary: None,
            categories: Vec::new(),
            contributors: Vec::new(),
            published: None,
            rights: None,
            source: None,
            extensions: ItemExtensions::default(),
        }
    }

    #[must_use]
    pub fn with_author(mut self, author: AtomPerson) -> Self {
        self.authors.push(author);
        self
    }

    #[must_use]
    pub fn with_content(mut self, content: AtomContent) -> Self {
        self.content = Some(content);
        self
    }

    #[must_use]
    pub fn with_link(mut self, link: AtomLink) -> Self {
        self.links.push(link);
        self
    }

    #[must_use]
    pub fn with_summary(mut self, summary: impl Into<AtomText>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    #[must_use]
    pub fn with_category(mut self, cat: AtomCategory) -> Self {
        self.categories.push(cat);
        self
    }

    #[must_use]
    pub fn with_published(mut self, ts: Timestamp) -> Self {
        self.published = Some(ts);
        self
    }

    #[must_use]
    pub fn with_rights(mut self, rights: impl Into<AtomText>) -> Self {
        self.rights = Some(rights.into());
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
    pub fn content_ext(&self) -> Option<&Content> {
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
