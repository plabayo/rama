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
use rama_net::uri::Uri;

use super::atom::{
    AtomEntry, AtomFeed, AtomFeedStream, AtomHeader, write_atom_entry, write_atom_feed_close,
    write_atom_feed_open,
};
use super::error::{CollectError, FeedCollectError, FeedParseError};
use super::feed::{Feed, FeedItem, pick_alternate, pick_rel};
use super::parse_util::{detect_atom, detect_rss};
use super::rss2::{
    Rss2Channel, Rss2Feed, Rss2FeedStream, Rss2Item, write_rss2_channel_close,
    write_rss2_channel_open, write_rss2_item,
};
use super::ser::XmlWriteError;
use jiff::Timestamp;
use tokio::io::AsyncBufRead;

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
// FeedStream — format-agnostic async streaming reader.
// ---------------------------------------------------------------------------

/// One async stream per supported feed format. Use [`FeedStream::new`] when
/// the input format isn't known ahead of time, or [`Rss2FeedStream`] /
/// [`AtomFeedStream`] directly when it is.
///
/// Construction peeks the first chunk, decides the format, and builds the
/// matching strongly-typed inner stream — the header (channel / feed-level
/// metadata) is parsed at that point and is inspectable via [`channel`] /
/// [`header`] or the cross-format accessors below.
///
/// [`channel`]: Self::channel
/// [`header`]: Self::header
pub enum FeedStream {
    Rss2(Rss2FeedStream),
    Atom(AtomFeedStream),
}

impl FeedStream {
    /// Peek the prefix of `reader`, decide the format, and build the matching
    /// inner stream.
    pub async fn new<R>(reader: R) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        Self::new_with_mode(reader, false).await
    }

    /// Strict variant of [`Self::new`].
    pub async fn new_strict<R>(reader: R) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        Self::new_with_mode(reader, true).await
    }

    async fn new_with_mode<R>(reader: R, strict: bool) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        use tokio::io::AsyncReadExt as _;

        // Pull enough bytes to detect the format. `fill_buf` alone only
        // returns whatever's currently buffered, which on a multi-chunk
        // `Body` stream can be a few bytes per `fill_buf` call. We instead
        // read into a local probe buffer until we have at least
        // `PROBE_MIN_BYTES` (or EOF), then prepend it back to the reader
        // via `Cursor::chain` so the inner stream sees the full document.
        // The loop exits as soon as `probe.len() >= PROBE_MIN_BYTES`, so
        // probe.len() is bounded by `PROBE_MIN_BYTES + CHUNK - 1` (≈ 1279).
        const PROBE_MIN_BYTES: usize = 1024;
        const CHUNK: usize = 256;
        let mut reader = reader;
        let mut probe = Vec::with_capacity(PROBE_MIN_BYTES + CHUNK);
        let mut chunk = [0u8; CHUNK];
        while probe.len() < PROBE_MIN_BYTES {
            match reader.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => probe.extend_from_slice(&chunk[..n]),
                Err(e) => {
                    return Err(FeedParseError {
                        message: format!("read feed body: {e}"),
                    });
                }
            }
        }
        // probe may end mid multi-byte UTF-8 char; trim back to the
        // last valid boundary before handing to the detectors.
        let probe_str = std::str::from_utf8(&probe)
            .unwrap_or_else(|e| std::str::from_utf8(&probe[..e.valid_up_to()]).unwrap_or(""));
        let is_atom = detect_atom(probe_str);
        let is_rss = !is_atom && detect_rss(probe_str);

        // Re-prepend the probe bytes so the underlying parser sees the whole
        // document, even though we consumed those bytes for detection.
        let prefix = std::io::Cursor::new(probe);
        let chained = tokio::io::AsyncReadExt::chain(prefix, reader);
        let buf_reader = tokio::io::BufReader::with_capacity(8 * 1024, chained);

        if is_atom {
            return Ok(Self::Atom(
                AtomFeedStream::new_with_mode(buf_reader, strict).await?,
            ));
        }
        if is_rss {
            return Ok(Self::Rss2(
                Rss2FeedStream::new_with_mode(buf_reader, strict).await?,
            ));
        }
        Err(FeedParseError {
            message: "document is neither RSS 2.0 nor Atom 1.0".to_owned(),
        })
    }

    /// Build a stream directly from an HTTP body.
    pub async fn from_body(body: crate::Body) -> Result<Self, FeedParseError> {
        Self::new(body_reader(body)).await
    }

    /// Strict variant of [`Self::from_body`].
    pub async fn from_body_strict(body: crate::Body) -> Result<Self, FeedParseError> {
        Self::new_strict(body_reader(body)).await
    }

    /// Borrow the RSS channel header, if this is an RSS stream.
    #[must_use]
    pub fn channel(&self) -> Option<&Rss2Channel> {
        match self {
            Self::Rss2(s) => Some(s.channel()),
            Self::Atom(_) => None,
        }
    }

    /// Borrow the Atom feed header, if this is an Atom stream.
    #[must_use]
    pub fn header(&self) -> Option<&AtomHeader> {
        match self {
            Self::Atom(s) => Some(s.header()),
            Self::Rss2(_) => None,
        }
    }

    /// Drain into a complete in-memory [`Feed`]. On a per-item parse error,
    /// returns a [`FeedCollectError`] whose `partial` field is a `Feed` of the
    /// same variant carrying everything parsed so far.
    pub async fn collect(self) -> Result<Feed, FeedCollectError> {
        match self {
            Self::Rss2(s) => s.collect().await.map(Feed::Rss2).map_err(|e| CollectError {
                error: e.error,
                partial: Feed::Rss2(e.partial),
            }),
            Self::Atom(s) => s.collect().await.map(Feed::Atom).map_err(|e| CollectError {
                error: e.error,
                partial: Feed::Atom(e.partial),
            }),
        }
    }

    /// Drain, silently dropping (and `tracing::debug!`-logging) items / entries
    /// that fail to parse.
    pub async fn collect_lossy(self) -> Feed {
        match self {
            Self::Rss2(s) => Feed::Rss2(s.collect_lossy().await),
            Self::Atom(s) => Feed::Atom(s.collect_lossy().await),
        }
    }

    /// Drain into a feed retaining only items / entries the predicate accepts.
    /// Mirrors [`Rss2FeedStream::collect_filtered`] and
    /// [`AtomFeedStream::collect_filtered`] for the format-agnostic case
    /// (the predicate sees a [`FeedItem`] so the same closure works across
    /// both formats).
    pub async fn collect_filtered<F>(self, mut predicate: F) -> Result<Feed, FeedCollectError>
    where
        F: FnMut(&FeedItem) -> bool + Send,
    {
        match self {
            Self::Rss2(s) => s
                .collect_filtered(|i| predicate(&FeedItem::Rss2(i.clone())))
                .await
                .map(Feed::Rss2)
                .map_err(|e| CollectError {
                    error: e.error,
                    partial: Feed::Rss2(e.partial),
                }),
            Self::Atom(s) => s
                .collect_filtered(|e| predicate(&FeedItem::Atom(e.clone())))
                .await
                .map(Feed::Atom)
                .map_err(|e| CollectError {
                    error: e.error,
                    partial: Feed::Atom(e.partial),
                }),
        }
    }

    // -----------------------------------------------------------------
    // Cross-format accessors over the header.
    //
    // These mirror the ones on [`Feed`] / [`FeedItem`] so a caller that's
    // streaming a feed of unknown format can inspect the header (parsed at
    // stream construction time) without having to match on the variant.
    // -----------------------------------------------------------------

    /// See [`Feed::title`].
    #[must_use]
    pub fn title(&self) -> &str {
        match self {
            Self::Rss2(s) => &s.channel().title,
            Self::Atom(s) => s.header().title.value.as_str(),
        }
    }

    /// See [`Feed::description`].
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        match self {
            Self::Rss2(s) => Some(&s.channel().description),
            Self::Atom(s) => s.header().subtitle.as_ref().map(|t| t.value.as_str()),
        }
    }

    /// See [`Feed::link`].
    #[must_use]
    pub fn link(&self) -> Option<&Uri> {
        match self {
            Self::Rss2(s) => Some(&s.channel().link),
            Self::Atom(s) => pick_alternate(&s.header().links).map(|l| &l.href),
        }
    }

    /// See [`Feed::self_link`].
    #[must_use]
    pub fn self_link(&self) -> Option<&Uri> {
        match self {
            Self::Rss2(s) => pick_rel(&s.channel().atom_links, "self").map(|l| &l.href),
            Self::Atom(s) => pick_rel(&s.header().links, "self").map(|l| &l.href),
        }
    }

    /// See [`Feed::id`].
    #[must_use]
    pub fn id(&self) -> Option<&Uri> {
        match self {
            Self::Rss2(_) => None,
            Self::Atom(s) => Some(&s.header().id),
        }
    }

    /// See [`Feed::language`].
    #[must_use]
    pub fn language(&self) -> Option<&str> {
        match self {
            Self::Rss2(s) => s.channel().language.as_deref(),
            Self::Atom(_) => None,
        }
    }

    /// See [`Feed::copyright`].
    #[must_use]
    pub fn copyright(&self) -> Option<&str> {
        match self {
            Self::Rss2(s) => s.channel().copyright.as_deref(),
            Self::Atom(s) => s.header().rights.as_ref().map(|t| t.value.as_str()),
        }
    }

    /// See [`Feed::generator`].
    #[must_use]
    pub fn generator(&self) -> Option<&str> {
        match self {
            Self::Rss2(s) => s.channel().generator.as_deref(),
            Self::Atom(s) => s.header().generator.as_ref().map(|g| g.value.as_str()),
        }
    }

    /// See [`Feed::image_url`].
    #[must_use]
    pub fn image_url(&self) -> Option<&Uri> {
        match self {
            Self::Rss2(s) => s.channel().image.as_ref().map(|i| &i.url),
            Self::Atom(s) => s.header().logo.as_ref(),
        }
    }

    /// See [`Feed::icon_url`].
    #[must_use]
    pub fn icon_url(&self) -> Option<&Uri> {
        match self {
            Self::Rss2(_) => None,
            Self::Atom(s) => s.header().icon.as_ref(),
        }
    }

    /// See [`Feed::published`].
    #[must_use]
    pub fn published(&self) -> Option<Timestamp> {
        match self {
            Self::Rss2(s) => s.channel().pub_date,
            Self::Atom(_) => None,
        }
    }

    /// See [`Feed::updated`].
    #[must_use]
    pub fn updated(&self) -> Option<Timestamp> {
        match self {
            Self::Rss2(s) => s.channel().last_build_date,
            Self::Atom(s) => Some(s.header().updated),
        }
    }

    /// See [`Feed::authors`].
    pub fn authors(&self) -> impl Iterator<Item = &str> {
        use rama_core::combinators::Either;
        match self {
            Self::Rss2(s) => {
                let c = s.channel();
                Either::A(
                    [c.managing_editor.as_deref(), c.web_master.as_deref()]
                        .into_iter()
                        .flatten()
                        .filter(|v| !v.is_empty()),
                )
            }
            Self::Atom(s) => Either::B(s.header().authors.iter().map(|p| p.name.as_str())),
        }
    }

    /// See [`Feed::categories`].
    pub fn categories(&self) -> impl Iterator<Item = &str> {
        use rama_core::combinators::Either;
        match self {
            Self::Rss2(s) => Either::A(s.channel().categories.iter().map(|c| c.name.as_str())),
            Self::Atom(s) => Either::B(s.header().categories.iter().map(|c| c.term.as_str())),
        }
    }
}

/// `FeedStream` is itself a `Stream` of [`FeedItem`]s: each inner stream
/// yields its strongly-typed item, and the dispatch here wraps it in the
/// umbrella enum so a caller can iterate format-agnostically.
impl Stream for FeedStream {
    type Item = Result<FeedItem, FeedParseError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this {
            Self::Rss2(s) => Pin::new(s)
                .poll_next(cx)
                .map(|opt| opt.map(|r| r.map(FeedItem::Rss2))),
            Self::Atom(s) => Pin::new(s)
                .poll_next(cx)
                .map(|opt| opt.map(|r| r.map(FeedItem::Atom))),
        }
    }
}

/// Wrap an HTTP body in an [`AsyncBufRead`] for the streaming readers.
fn body_reader(
    body: crate::Body,
) -> tokio::io::BufReader<
    rama_core::stream::io::StreamReader<BodyDataStream, rama_core::bytes::Bytes>,
> {
    use rama_core::stream::io::StreamReader;

    let stream: BodyDataStream = body
        .into_data_stream()
        .map(|r| r.map_err(std::io::Error::other))
        .boxed();
    let inner = StreamReader::new(stream);
    tokio::io::BufReader::with_capacity(8 * 1024, inner)
}

type BodyDataStream = BoxStream<'static, std::io::Result<rama_core::bytes::Bytes>>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::rss::feed_ext::{ITunes, ItemExtensions};

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
            link: Uri::from_static("https://e.com"),
            description: "D".into(),
            ..Default::default()
        };
        let item = Rss2Item::new()
            .with_title("Ep1")
            .with_extensions(ItemExtensions {
                itunes: Some(Box::new(ITunes {
                    author: Some("A".into()),
                    ..Default::default()
                })),
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
    #[cfg(feature = "html")]
    async fn atom_stream_keeps_content_and_declares_namespaces() {
        use crate::protocols::html::p;
        use crate::protocols::rss::AtomContent;
        use jiff::Timestamp;

        let header = AtomHeader {
            id: Uri::from_static("urn:x"),
            ..Default::default()
        };
        let entry = AtomEntry::new(Uri::from_static("urn:1"), "E1", Timestamp::UNIX_EPOCH)
            .with_content(AtomContent::html(p!("hi")));
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
                    .with_link(
                        Uri::from_static("https://example.com").with_additional_path_segment(n),
                    );
                Some((Ok::<_, std::convert::Infallible>(item), n + 1))
            }
        })
        .boxed();

        let channel = Rss2Channel {
            title: "Podcast".into(),
            link: Uri::from_static("https://example.com"),
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
            .link(Uri::from_static("https://example.com"))
            .description("desc")
            .with_item(Rss2Item::new().with_title("Item A"))
            .with_item(Rss2Item::new().with_title("Item B"))
            .build();
        let xml = drain(Rss2StreamWriter::from_feed(feed)).await;
        assert!(xml.contains("<title>Round</title>"), "{xml}");
        assert!(xml.contains("<title>Item A</title>"), "{xml}");
        assert!(xml.contains("<title>Item B</title>"), "{xml}");
    }
}
