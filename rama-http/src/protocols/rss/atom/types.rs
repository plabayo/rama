use jiff::Timestamp;
use rama_utils::macros::generate_set_and_with;

use crate::protocols::rss::feed_ext::{
    Content, DublinCore, ITunes, ItemExtensions, MediaRss, Podcast, PodloveChapters,
};
use crate::protocols::rss::rss2::Missing;

/// Atom text construct: a string body plus a [`AtomTextKind`] that says how
/// to interpret/serialize it. Equivalent of the spec's "Text Construct"
/// (RFC 4287 §3.1).
///
/// For `Xhtml`, `value` is the raw inner XML *with the wrapping `<div>`
/// stripped* — the serializer puts the `<div xmlns="…/xhtml">` back on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomText {
    pub value: String,
    pub kind: AtomTextKind,
}

/// Which Atom `type=` attribute applies to an [`AtomText`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomTextKind {
    Text,
    Html,
    Xhtml,
}

impl AtomTextKind {
    /// The lowercased `type=` attribute value Atom uses on the wire
    /// (`"text"`, `"html"`, `"xhtml"`).
    #[must_use]
    pub fn type_attr(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Html => "html",
            Self::Xhtml => "xhtml",
        }
    }
}

impl AtomText {
    #[must_use]
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            value: s.into(),
            kind: AtomTextKind::Text,
        }
    }

    #[must_use]
    pub fn html(s: impl Into<String>) -> Self {
        Self {
            value: s.into(),
            kind: AtomTextKind::Html,
        }
    }

    /// Construct an `xhtml` text construct.
    ///
    /// **Pass the inner markup only** — the wrapping
    /// `<div xmlns="http://www.w3.org/1999/xhtml">…</div>` mandated by
    /// RFC 4287 §3.1.1.3 is added on serialize and stripped on parse.
    /// Passing a string that *includes* the wrapping `<div>` will cause
    /// the writer to emit a redundant outer `<div>`.
    #[must_use]
    pub fn xhtml(s: impl Into<String>) -> Self {
        Self {
            value: s.into(),
            kind: AtomTextKind::Xhtml,
        }
    }
}

impl From<&str> for AtomText {
    fn from(s: &str) -> Self {
        Self::text(s)
    }
}

impl From<String> for AtomText {
    fn from(s: String) -> Self {
        Self::text(s)
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

    generate_set_and_with! {
        pub fn email(mut self, email: impl Into<String>) -> Self {
            self.email = Some(email.into());
            self
        }
    }

    generate_set_and_with! {
        pub fn uri(mut self, uri: impl Into<String>) -> Self {
            self.uri = Some(uri.into());
            self
        }
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

    /// Construct a `rel="self"` link with `type="application/atom+xml"` —
    /// the conventional shape for an Atom feed's self-link.
    ///
    /// **Note**: if you're embedding an `<atom:link rel="self">` in an
    /// **RSS** feed (the iTunes / Podcasting 2.0 requirement), use
    /// [`AtomLink::new`] and set `type="application/rss+xml"` yourself —
    /// the constructor here hardcodes the Atom MIME and would be wrong on
    /// the wire.
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

/// An Atom `<content>` element.
///
/// Two shapes:
///
/// * **Inline** — `src` is `None`. The body lives in `value`; its
///   [`AtomText::kind`] drives the wire `type=` attribute (text/html/xhtml).
/// * **Out-of-line** — `src` is `Some(url)`. The body lives at the URL,
///   and `out_of_line_type` carries the wire `type=` attribute (e.g.
///   `"text/html"`). When `out_of_line_type` is `None` the writer falls
///   back to `value.kind.type_attr()`.
///
/// The `out_of_line_type` field exists so the MIME type can't accidentally
/// be conflated with the body. Earlier versions stuffed the type into
/// `value.value` and the writer wrote it back from there; constructing
/// `AtomContent { value: AtomText::html("real body"), src: Some(_) }` then
/// produced `type="real body"` on the wire. Now the body and the MIME
/// type are two distinct slots.
#[derive(Debug, Clone, PartialEq)]
pub struct AtomContent {
    pub value: AtomText,
    pub src: Option<String>,
    pub out_of_line_type: Option<String>,
}

impl AtomContent {
    #[must_use]
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            value: AtomText::text(s),
            src: None,
            out_of_line_type: None,
        }
    }

    #[must_use]
    pub fn html(s: impl Into<String>) -> Self {
        Self {
            value: AtomText::html(s),
            src: None,
            out_of_line_type: None,
        }
    }

    #[must_use]
    pub fn out_of_line(src: impl Into<String>, mime: impl Into<String>) -> Self {
        Self {
            value: AtomText::text(""),
            src: Some(src.into()),
            out_of_line_type: Some(mime.into()),
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
    pub extensions: crate::protocols::rss::feed_ext::FeedExtensions,
}

impl AtomFeed {
    #[must_use]
    pub fn builder() -> super::builder::AtomFeedBuilder<Missing, Missing, Missing> {
        super::builder::AtomFeedBuilder::new()
    }

    /// Stream the feed as XML bytes. Equivalent to
    /// [`crate::protocols::rss::AtomStreamWriter::from_feed`]; provided as a method for
    /// discoverability when starting from a whole in-memory feed.
    ///
    /// Plugs directly into [`crate::Body::from_stream`].
    #[must_use]
    pub fn into_stream_writer(
        self,
    ) -> crate::protocols::rss::AtomStreamWriter<
        rama_core::futures::stream::BoxStream<
            'static,
            Result<AtomEntry, rama_core::error::BoxError>,
        >,
    > {
        crate::protocols::rss::AtomStreamWriter::from_feed(self)
    }

    /// Drain [`Self::into_stream_writer`] into an in-memory `Vec<u8>`.
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
    pub fn new(id: impl Into<String>, title: impl Into<AtomText>, updated: Timestamp) -> Self {
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

    generate_set_and_with! {
        /// Append an author. Call multiple times to attach more.
        pub fn author(mut self, author: AtomPerson) -> Self {
            self.authors.push(author);
            self
        }
    }

    generate_set_and_with! {
        pub fn content(mut self, content: AtomContent) -> Self {
            self.content = Some(content);
            self
        }
    }

    generate_set_and_with! {
        /// Append a link. Call multiple times to attach more.
        pub fn link(mut self, link: AtomLink) -> Self {
            self.links.push(link);
            self
        }
    }

    generate_set_and_with! {
        pub fn summary(mut self, summary: impl Into<AtomText>) -> Self {
            self.summary = Some(summary.into());
            self
        }
    }

    generate_set_and_with! {
        /// Append a category. Call multiple times to attach more.
        pub fn category(mut self, cat: AtomCategory) -> Self {
            self.categories.push(cat);
            self
        }
    }

    generate_set_and_with! {
        pub fn published(mut self, ts: Timestamp) -> Self {
            self.published = Some(ts);
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
        pub fn extensions(mut self, ext: ItemExtensions) -> Self {
            self.extensions = ext;
            self
        }
    }

    #[must_use]
    pub fn itunes(&self) -> Option<&ITunes> {
        self.extensions.itunes.as_deref()
    }

    #[must_use]
    pub fn podcast(&self) -> Option<&Podcast> {
        self.extensions.podcast.as_deref()
    }

    #[must_use]
    pub fn dublin_core(&self) -> Option<&DublinCore> {
        self.extensions.dublin_core.as_deref()
    }

    #[must_use]
    pub fn content_ext(&self) -> Option<&Content> {
        self.extensions.content.as_deref()
    }

    #[must_use]
    pub fn media(&self) -> Option<&MediaRss> {
        self.extensions.media.as_deref()
    }

    /// Podlove Simple Chapters extension (`<psc:chapters>` markers).
    #[must_use]
    pub fn podlove(&self) -> Option<&PodloveChapters> {
        self.extensions.podlove.as_deref()
    }
}
