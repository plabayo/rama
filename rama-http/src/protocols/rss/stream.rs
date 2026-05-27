//! Streaming XML output for RSS 2.0 and Atom feeds.
//!
//! [`Rss2StreamWriter`] and [`AtomStreamWriter`] wrap an item/entry stream and
//! produce `Bytes` chunks that form a complete, well-formed XML document.
//! They implement `Stream<Item = Result<Bytes, BoxError>>` and integrate
//! directly with [`Body::from_stream`].
//!
//! Zero-copy read sides: [`Rss2ItemRef`] and [`AtomEntryRef`] hold
//! `Cow<'_, str>` fields so parsers can borrow from source buffers without
//! allocating when escape processing is not needed.

use std::borrow::Cow;
use std::pin::Pin;
use std::task::{Context, Poll};

use jiff::Timestamp;
use pin_project_lite::pin_project;
use quick_xml::{
    Writer,
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
};
use rama_core::bytes::{BufMut as _, Bytes, BytesMut};
use rama_core::error::BoxError;
use rama_core::futures::Stream;

use super::atom::{AtomEntry, write_atom_entry};
use super::rss2::{Rss2Item, write_rss2_item};
use super::ser::XmlWriteError;

// ---------------------------------------------------------------------------
// Zero-copy item references
// ---------------------------------------------------------------------------

/// A borrowed view of an RSS 2.0 item, usable during streaming parse passes
/// without allocating for every field.
#[derive(Debug, Clone, Default)]
pub struct Rss2ItemRef<'a> {
    pub title: Option<Cow<'a, str>>,
    pub link: Option<Cow<'a, str>>,
    pub description: Option<Cow<'a, str>>,
    pub author: Option<Cow<'a, str>>,
    pub guid: Option<Cow<'a, str>>,
    pub pub_date: Option<Cow<'a, str>>,
}

impl<'a> Rss2ItemRef<'a> {
    /// Allocate a fully-owned [`Rss2Item`] from this reference.
    #[must_use]
    pub fn to_owned_item(&self) -> Rss2Item {
        Rss2Item {
            title: self.title.as_deref().map(str::to_owned),
            link: self.link.as_deref().map(str::to_owned),
            description: self.description.as_deref().map(str::to_owned),
            author: self.author.as_deref().map(str::to_owned),
            ..Default::default()
        }
    }
}

/// A borrowed view of an Atom entry.
#[derive(Debug, Clone)]
pub struct AtomEntryRef<'a> {
    pub id: Cow<'a, str>,
    pub title: Cow<'a, str>,
    pub updated: Cow<'a, str>,
    pub author_name: Option<Cow<'a, str>>,
    pub summary: Option<Cow<'a, str>>,
    pub content: Option<Cow<'a, str>>,
    pub link_href: Option<Cow<'a, str>>,
}

// ---------------------------------------------------------------------------
// RSS 2.0 stream writer
// ---------------------------------------------------------------------------

/// State machine for the RSS 2.0 stream writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rss2Phase {
    Header,
    Items,
    Footer,
    Done,
}

pin_project! {
    /// Wraps a stream of [`Rss2Item`]s and produces a streaming RSS 2.0 XML
    /// document as [`Bytes`] chunks.
    ///
    /// The header (XML declaration + `<rss>` + `<channel>` metadata) is
    /// written on the first poll, items are serialized one by one, and the
    /// footer (`</channel></rss>`) is written after the item stream exhausts.
    pub struct Rss2StreamWriter<S> {
        phase: Rss2Phase,
        meta: Rss2FeedMeta,
        #[pin]
        items: S,
        scratch: BytesMut,
    }
}

/// Channel-level metadata emitted once in the stream header.
#[derive(Debug, Clone)]
pub struct Rss2FeedMeta {
    pub title: String,
    pub link: String,
    pub description: String,
    pub language: Option<String>,
    pub generator: Option<String>,
}

impl<S, E> Rss2StreamWriter<S>
where
    S: Stream<Item = Result<Rss2Item, E>>,
    E: Into<BoxError>,
{
    pub fn new(meta: Rss2FeedMeta, items: S) -> Self {
        Self {
            phase: Rss2Phase::Header,
            meta,
            items,
            scratch: BytesMut::with_capacity(4096),
        }
    }
}

impl<S, E> Stream for Rss2StreamWriter<S>
where
    S: Stream<Item = Result<Rss2Item, E>>,
    E: Into<BoxError>,
{
    type Item = Result<Bytes, BoxError>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, BoxError>>> {
        let mut this = self.project();

        loop {
            match *this.phase {
                Rss2Phase::Header => {
                    this.scratch.clear();
                    if let Err(e) = write_rss2_header(this.scratch, this.meta) {
                        return Poll::Ready(Some(Err(e.into())));
                    }
                    *this.phase = Rss2Phase::Items;
                    let chunk = this.scratch.split().freeze();
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Rss2Phase::Items => match this.items.as_mut().poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => {
                        *this.phase = Rss2Phase::Footer;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Some(Err(e.into())));
                    }
                    Poll::Ready(Some(Ok(item))) => {
                        this.scratch.clear();
                        let mut w = Writer::new(this.scratch.writer());
                        if let Err(e) = write_rss2_item(&mut w, &item) {
                            return Poll::Ready(Some(Err(BoxError::from(e))));
                        }
                        let chunk = this.scratch.split().freeze();
                        return Poll::Ready(Some(Ok(chunk)));
                    }
                },
                Rss2Phase::Footer => {
                    this.scratch.clear();
                    if let Err(e) = write_rss2_footer(this.scratch) {
                        return Poll::Ready(Some(Err(e.into())));
                    }
                    *this.phase = Rss2Phase::Done;
                    let chunk = this.scratch.split().freeze();
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Rss2Phase::Done => return Poll::Ready(None),
            }
        }
    }
}

fn write_rss2_header(buf: &mut BytesMut, meta: &Rss2FeedMeta) -> Result<(), XmlWriteError> {
    let mut w = Writer::new(buf.writer());
    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
    let mut rss_tag = BytesStart::new("rss");
    rss_tag.push_attribute(("version", "2.0"));
    // A streaming header is written before any item is seen, so it cannot know
    // which extension prefixes the items will use. Declare the supported ones
    // up front to keep the document namespace-well-formed regardless.
    rss_tag.push_attribute(("xmlns:itunes", "http://www.itunes.com/dtds/podcast-1.0.dtd"));
    rss_tag.push_attribute(("xmlns:podcast", "https://podcastindex.org/namespace/1.0"));
    rss_tag.push_attribute(("xmlns:content", "http://purl.org/rss/1.0/modules/content/"));
    rss_tag.push_attribute(("xmlns:dc", "http://purl.org/dc/elements/1.1/"));
    rss_tag.push_attribute(("xmlns:media", "http://search.yahoo.com/mrss/"));
    w.write_event(Event::Start(rss_tag))?;
    w.write_event(Event::Start(BytesStart::new("channel")))?;
    write_text_elem_to(&mut w, "title", &meta.title)?;
    write_text_elem_to(&mut w, "link", &meta.link)?;
    write_text_elem_to(&mut w, "description", &meta.description)?;
    if let Some(lang) = &meta.language {
        write_text_elem_to(&mut w, "language", lang)?;
    }
    if let Some(generator) = &meta.generator {
        write_text_elem_to(&mut w, "generator", generator)?;
    }
    Ok(())
}

fn write_rss2_footer(buf: &mut BytesMut) -> Result<(), XmlWriteError> {
    let mut w = Writer::new(buf.writer());
    w.write_event(Event::End(BytesEnd::new("channel")))?;
    w.write_event(Event::End(BytesEnd::new("rss")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Atom stream writer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtomPhase {
    Header,
    Entries,
    Footer,
    Done,
}

/// Channel-level metadata for the Atom stream header.
#[derive(Debug, Clone)]
pub struct AtomFeedMeta {
    pub id: String,
    pub title: String,
    pub updated: Timestamp,
    pub author_name: Option<String>,
    pub link_href: Option<String>,
}

pin_project! {
    /// Wraps a stream of [`AtomEntry`] values and produces a streaming Atom
    /// XML document as [`Bytes`] chunks.
    pub struct AtomStreamWriter<S> {
        phase: AtomPhase,
        meta: AtomFeedMeta,
        #[pin]
        entries: S,
        scratch: BytesMut,
    }
}

impl<S, E> AtomStreamWriter<S>
where
    S: Stream<Item = Result<AtomEntry, E>>,
    E: Into<BoxError>,
{
    pub fn new(meta: AtomFeedMeta, entries: S) -> Self {
        Self {
            phase: AtomPhase::Header,
            meta,
            entries,
            scratch: BytesMut::with_capacity(4096),
        }
    }
}

impl<S, E> Stream for AtomStreamWriter<S>
where
    S: Stream<Item = Result<AtomEntry, E>>,
    E: Into<BoxError>,
{
    type Item = Result<Bytes, BoxError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            match *this.phase {
                AtomPhase::Header => {
                    this.scratch.clear();
                    if let Err(e) = write_atom_header(this.scratch, this.meta) {
                        return Poll::Ready(Some(Err(e.into())));
                    }
                    *this.phase = AtomPhase::Entries;
                    let chunk = this.scratch.split().freeze();
                    return Poll::Ready(Some(Ok(chunk)));
                }
                AtomPhase::Entries => match this.entries.as_mut().poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => {
                        *this.phase = AtomPhase::Footer;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Some(Err(e.into())));
                    }
                    Poll::Ready(Some(Ok(entry))) => {
                        this.scratch.clear();
                        let mut w = Writer::new(this.scratch.writer());
                        if let Err(e) = write_atom_entry(&mut w, &entry) {
                            return Poll::Ready(Some(Err(BoxError::from(e))));
                        }
                        let chunk = this.scratch.split().freeze();
                        return Poll::Ready(Some(Ok(chunk)));
                    }
                },
                AtomPhase::Footer => {
                    this.scratch.clear();
                    if let Err(e) = write_atom_footer(this.scratch) {
                        return Poll::Ready(Some(Err(e.into())));
                    }
                    *this.phase = AtomPhase::Done;
                    let chunk = this.scratch.split().freeze();
                    return Poll::Ready(Some(Ok(chunk)));
                }
                AtomPhase::Done => return Poll::Ready(None),
            }
        }
    }
}

fn write_atom_header(buf: &mut BytesMut, meta: &AtomFeedMeta) -> Result<(), XmlWriteError> {
    let mut w = Writer::new(buf.writer());
    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
    let mut feed_tag = BytesStart::new("feed");
    feed_tag.push_attribute(("xmlns", "http://www.w3.org/2005/Atom"));
    // Declared up front because entries are streamed after this header and may
    // carry extension-namespaced elements (see Rss2StreamWriter header).
    feed_tag.push_attribute(("xmlns:itunes", "http://www.itunes.com/dtds/podcast-1.0.dtd"));
    feed_tag.push_attribute(("xmlns:podcast", "https://podcastindex.org/namespace/1.0"));
    feed_tag.push_attribute(("xmlns:dc", "http://purl.org/dc/elements/1.1/"));
    feed_tag.push_attribute(("xmlns:media", "http://search.yahoo.com/mrss/"));
    w.write_event(Event::Start(feed_tag))?;
    write_text_elem_to(&mut w, "id", &meta.id)?;
    {
        let mut title_tag = BytesStart::new("title");
        title_tag.push_attribute(("type", "text"));
        w.write_event(Event::Start(title_tag))?;
        w.write_event(Event::Text(BytesText::new(&meta.title)))?;
        w.write_event(Event::End(BytesEnd::new("title")))?;
    }
    write_text_elem_to(&mut w, "updated", &meta.updated.to_string())?;
    if let Some(name) = &meta.author_name {
        w.write_event(Event::Start(BytesStart::new("author")))?;
        write_text_elem_to(&mut w, "name", name)?;
        w.write_event(Event::End(BytesEnd::new("author")))?;
    }
    if let Some(href) = &meta.link_href {
        let mut link_tag = BytesStart::new("link");
        link_tag.push_attribute(("rel", "alternate"));
        link_tag.push_attribute(("href", href.as_str()));
        w.write_event(Event::Empty(link_tag))?;
    }
    Ok(())
}

fn write_atom_footer(buf: &mut BytesMut) -> Result<(), XmlWriteError> {
    let mut w = Writer::new(buf.writer());
    w.write_event(Event::End(BytesEnd::new("feed")))?;
    Ok(())
}

fn write_text_elem_to<W: std::io::Write>(
    w: &mut Writer<W>,
    name: &str,
    value: &str,
) -> Result<(), XmlWriteError> {
    w.write_event(Event::Start(BytesStart::new(name)))?;
    w.write_event(Event::Text(BytesText::new(value)))?;
    w.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::rss::AtomContent;
    use crate::protocols::rss::feed_ext::{ITunes, ItemExtensions};
    use rama_core::futures::StreamExt as _;

    async fn drain<S>(mut s: S) -> String
    where
        S: Stream<Item = Result<Bytes, BoxError>> + Unpin,
    {
        let mut out = Vec::new();
        while let Some(chunk) = s.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        String::from_utf8(out).unwrap()
    }

    #[tokio::test]
    async fn rss2_stream_declares_extension_namespaces() {
        let meta = Rss2FeedMeta {
            title: "T".into(),
            link: "https://e.com".into(),
            description: "D".into(),
            language: None,
            generator: None,
        };
        let item = Rss2Item::new()
            .with_title("Ep1")
            .with_extensions(ItemExtensions {
                itunes: Some(ITunes {
                    author: Some("A".into()),
                    ..Default::default()
                }),
                ..Default::default()
            });
        let items = rama_core::futures::stream::iter(vec![Ok::<_, std::convert::Infallible>(item)]);
        let xml = drain(Rss2StreamWriter::new(meta, items)).await;
        assert!(
            xml.contains("xmlns:itunes="),
            "namespace not declared: {xml}"
        );
        assert!(xml.contains("<itunes:author>A</itunes:author>"), "{xml}");
        assert!(
            xml.contains("</channel>") && xml.contains("</rss>"),
            "{xml}"
        );
    }

    #[tokio::test]
    async fn atom_stream_keeps_content_and_declares_namespaces() {
        let meta = AtomFeedMeta {
            id: "urn:x".into(),
            title: "T".into(),
            updated: Timestamp::UNIX_EPOCH,
            author_name: None,
            link_href: None,
        };
        let entry = AtomEntry::new("urn:1", "E1", Timestamp::UNIX_EPOCH)
            .with_content(AtomContent::html("<p>hi</p>"));
        let entries =
            rama_core::futures::stream::iter(vec![Ok::<_, std::convert::Infallible>(entry)]);
        let xml = drain(AtomStreamWriter::new(meta, entries)).await;
        assert!(
            xml.contains("xmlns:itunes="),
            "namespace not declared: {xml}"
        );
        // content used to be dropped by the streaming writer
        assert!(
            xml.contains("<![CDATA[<p>hi</p>]]>"),
            "content missing: {xml}"
        );
        assert!(xml.contains("</feed>"), "{xml}");
    }
}
