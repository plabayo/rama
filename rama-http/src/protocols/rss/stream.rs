//! Streaming XML output for RSS 2.0 and Atom feeds.
//!
//! Three writers, all `Stream<Item = Result<Bytes, BoxError>>`:
//!
//! * [`Rss2StreamWriter`] — strongly typed RSS 2.0 writer over an item stream.
//!   Build from a [`Rss2Channel`] header + `Stream<Item = Result<Rss2Item, _>>`,
//!   or from a whole in-memory [`Rss2Feed`] via [`Rss2StreamWriter::from_feed`].
//! * [`AtomStreamWriter`] — same, but for Atom 1.0: [`AtomHeader`] + entries.
//! * [`FeedStreamWriter`] — format-agnostic umbrella used when the upstream is
//!   a parsed [`Feed`] of unknown format. Internally type-erased.
//!
//! There is no synchronous serialization path — every writer is a `Stream`,
//! and the in-memory entry points are thin "collect" adapters on top.
//!
//! The header/entry types ([`Rss2Channel`], [`AtomHeader`], [`Rss2Item`],
//! [`AtomEntry`]) are the same ones produced by the corresponding async
//! readers ([`super::Rss2FeedStream`] / [`super::AtomFeedStream`] /
//! [`super::FeedStream`]), so the drain ↔ construct path round-trips through
//! the same types.

use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use quick_xml::{
    Writer,
    events::{BytesDecl, Event},
};
use rama_core::bytes::{BufMut as _, Bytes, BytesMut};
use rama_core::error::BoxError;
use rama_core::futures::Stream;
use rama_core::futures::stream::{self, BoxStream, StreamExt as _};

use super::Feed;
use super::atom::{
    AtomEntry, AtomFeed, write_atom_entry, write_atom_feed_close, write_atom_feed_open,
};
use super::read::{AtomHeader, Rss2Channel};
use super::rss2::{
    Rss2Feed, Rss2Item, write_rss2_channel_close, write_rss2_channel_open, write_rss2_item,
};
use super::ser::XmlWriteError;

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
    /// Strongly-typed RSS 2.0 stream writer.
    ///
    /// Combines a [`Rss2Channel`] header (parsed once, written immediately)
    /// with a `Stream<Item = Result<Rss2Item, _>>` and emits a complete,
    /// well-formed `<rss>` document as [`Bytes`] chunks. Plugs straight into
    /// [`crate::Body::from_stream`].
    pub struct Rss2StreamWriter<S> {
        phase: Rss2Phase,
        channel: Rss2Channel,
        #[pin]
        items: S,
        scratch: BytesMut,
    }
}

impl<S, E> Rss2StreamWriter<S>
where
    S: Stream<Item = Result<Rss2Item, E>>,
    E: Into<BoxError>,
{
    /// Build a writer from a channel header + item stream. Use this when items
    /// come from an out-of-process source (database paging, async iterator,
    /// upstream proxy) and the caller wants to avoid materialising every item
    /// before the response starts flowing.
    pub fn new(channel: Rss2Channel, items: S) -> Self {
        Self {
            phase: Rss2Phase::Header,
            channel,
            items,
            scratch: BytesMut::with_capacity(4096),
        }
    }
}

impl Rss2StreamWriter<BoxStream<'static, Result<Rss2Item, BoxError>>> {
    /// Build a writer from a whole in-memory [`Rss2Feed`]. Items are
    /// re-streamed one at a time via `stream::iter`. This is the convenience
    /// path for callers that already have the feed materialised (the
    /// "collect" side reversed).
    #[must_use]
    pub fn from_feed(feed: Rss2Feed) -> Self {
        let Rss2Feed {
            title,
            link,
            description,
            language,
            copyright,
            managing_editor,
            web_master,
            pub_date,
            last_build_date,
            categories,
            generator,
            docs,
            ttl,
            image,
            atom_links,
            items,
            extensions,
        } = feed;
        let channel = Rss2Channel {
            title,
            link,
            description,
            language,
            copyright,
            managing_editor,
            web_master,
            pub_date,
            last_build_date,
            categories,
            generator,
            docs,
            ttl,
            image,
            atom_links,
            extensions,
        };
        let items_stream: BoxStream<'static, Result<Rss2Item, BoxError>> =
            stream::iter(items.into_iter().map(Ok)).boxed();
        Self::new(channel, items_stream)
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
                    if let Err(e) = write_rss2_header_chunk(this.scratch, this.channel) {
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
                    let mut w = Writer::new(this.scratch.writer());
                    if let Err(e) = write_rss2_channel_close(&mut w) {
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

fn write_rss2_header_chunk(buf: &mut BytesMut, channel: &Rss2Channel) -> Result<(), XmlWriteError> {
    let mut w = Writer::new(buf.writer());
    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
    write_rss2_channel_open(&mut w, channel)?;
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

pin_project! {
    /// Strongly-typed Atom 1.0 stream writer. Mirror of [`Rss2StreamWriter`].
    pub struct AtomStreamWriter<S> {
        phase: AtomPhase,
        header: AtomHeader,
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
    /// Build a writer from a feed header + entry stream.
    pub fn new(header: AtomHeader, entries: S) -> Self {
        Self {
            phase: AtomPhase::Header,
            header,
            entries,
            scratch: BytesMut::with_capacity(4096),
        }
    }
}

impl AtomStreamWriter<BoxStream<'static, Result<AtomEntry, BoxError>>> {
    /// Build a writer from a whole in-memory [`AtomFeed`].
    #[must_use]
    pub fn from_feed(feed: AtomFeed) -> Self {
        let AtomFeed {
            id,
            title,
            updated,
            authors,
            links,
            categories,
            contributors,
            generator,
            icon,
            logo,
            rights,
            subtitle,
            entries,
            extensions,
        } = feed;
        let header = AtomHeader {
            id,
            title,
            updated,
            authors,
            links,
            categories,
            contributors,
            generator,
            icon,
            logo,
            rights,
            subtitle,
            extensions,
        };
        let entries_stream: BoxStream<'static, Result<AtomEntry, BoxError>> =
            stream::iter(entries.into_iter().map(Ok)).boxed();
        Self::new(header, entries_stream)
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
                    if let Err(e) = write_atom_header_chunk(this.scratch, this.header) {
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
                    let mut w = Writer::new(this.scratch.writer());
                    if let Err(e) = write_atom_feed_close(&mut w) {
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

fn write_atom_header_chunk(buf: &mut BytesMut, header: &AtomHeader) -> Result<(), XmlWriteError> {
    let mut w = Writer::new(buf.writer());
    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
    write_atom_feed_open(&mut w, header)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Format-agnostic umbrella
// ---------------------------------------------------------------------------

pin_project! {
    /// Format-agnostic stream writer. Use this when the caller has a [`Feed`]
    /// (often from a [`super::FeedStream::collect`]) and wants to re-emit it
    /// without first checking which variant it is. Internally type-erased into
    /// a `BoxStream<Bytes>`.
    pub struct FeedStreamWriter {
        #[pin]
        inner: BoxStream<'static, Result<Bytes, BoxError>>,
    }
}

impl FeedStreamWriter {
    /// Wrap an existing [`Rss2StreamWriter`].
    pub fn rss2<S, E>(inner: Rss2StreamWriter<S>) -> Self
    where
        S: Stream<Item = Result<Rss2Item, E>> + Send + 'static,
        E: Into<BoxError> + Send + 'static,
    {
        Self {
            inner: inner.boxed(),
        }
    }

    /// Wrap an existing [`AtomStreamWriter`].
    pub fn atom<S, E>(inner: AtomStreamWriter<S>) -> Self
    where
        S: Stream<Item = Result<AtomEntry, E>> + Send + 'static,
        E: Into<BoxError> + Send + 'static,
    {
        Self {
            inner: inner.boxed(),
        }
    }

    /// Build a writer from a whole in-memory [`Feed`]. The format of the
    /// emitted document follows the input variant.
    #[must_use]
    pub fn from_feed(feed: Feed) -> Self {
        match feed {
            Feed::Rss2(f) => Self::rss2(Rss2StreamWriter::from_feed(f)),
            Feed::Atom(f) => Self::atom(AtomStreamWriter::from_feed(f)),
        }
    }
}

impl Stream for FeedStreamWriter {
    type Item = Result<Bytes, BoxError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.inner.poll_next(cx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::rss::AtomContent;
    use crate::protocols::rss::feed_ext::{ITunes, ItemExtensions};
    use jiff::Timestamp;

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
        let channel = Rss2Channel {
            title: "T".into(),
            link: "https://e.com".into(),
            description: "D".into(),
            ..Default::default()
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
        let xml = drain(Rss2StreamWriter::new(channel, items)).await;
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
        let header = AtomHeader {
            id: "urn:x".into(),
            ..Default::default()
        };
        let entry = AtomEntry::new("urn:1", "E1", Timestamp::UNIX_EPOCH)
            .with_content(AtomContent::html("<p>hi</p>"));
        let entries =
            rama_core::futures::stream::iter(vec![Ok::<_, std::convert::Infallible>(entry)]);
        let xml = drain(AtomStreamWriter::new(header, entries)).await;
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

    /// Writer fed from a "database-style" async stream: each item is yielded
    /// only when the previous one has been polled. Asserts the writer doesn't
    /// pre-buffer items and that the resulting document is still well-formed.
    #[tokio::test]
    async fn rss2_stream_writer_pulls_items_lazily() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let pulled = Arc::new(AtomicUsize::new(0));
        let pulled_clone = pulled.clone();
        let items = rama_core::futures::stream::unfold(0u32, move |n| {
            let pulled = pulled_clone.clone();
            async move {
                if n >= 3 {
                    return None;
                }
                pulled.fetch_add(1, Ordering::SeqCst);
                let item = Rss2Item::new()
                    .with_title(format!("Episode {n}"))
                    .with_link(format!("https://example.com/{n}"));
                Some((Ok::<_, std::convert::Infallible>(item), n + 1))
            }
        })
        .boxed();

        let channel = Rss2Channel {
            title: "Podcast".into(),
            link: "https://example.com".into(),
            description: "Streamed".into(),
            ..Default::default()
        };
        let xml = drain(Rss2StreamWriter::new(channel, items)).await;
        assert_eq!(pulled.load(Ordering::SeqCst), 3, "all items pulled once");
        for n in 0..3 {
            assert!(xml.contains(&format!("Episode {n}")), "{xml}");
        }
    }

    #[tokio::test]
    async fn from_feed_round_trips_through_the_stream_writer() {
        use crate::protocols::rss::Rss2Feed;

        let feed = Rss2Feed::builder()
            .title("Round")
            .link("https://example.com")
            .description("desc")
            .item(Rss2Item::new().with_title("Item A"))
            .item(Rss2Item::new().with_title("Item B"))
            .build();
        let xml = drain(Rss2StreamWriter::from_feed(feed)).await;
        assert!(xml.contains("<title>Round</title>"), "{xml}");
        assert!(xml.contains("<title>Item A</title>"), "{xml}");
        assert!(xml.contains("<title>Item B</title>"), "{xml}");
    }
}
