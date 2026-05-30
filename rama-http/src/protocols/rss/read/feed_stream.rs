//! Strongly-typed async streaming readers for RSS 2.0 and Atom 1.0.
//!
//! The public surface is intentionally narrow: the **header is read at
//! construction time** (XML guarantees it comes before any item/entry), and
//! the resulting [`Rss2FeedStream`] / [`AtomFeedStream`] yields the items /
//! entries one by one over the underlying byte source.
//!
//! From a stream you can:
//!
//! * borrow the header with `.channel()` / `.header()` while items are still
//!   being streamed,
//! * walk items lazily via the [`Stream`] impl,
//! * split into `(header, items)` with `.drain()`,
//! * collect everything into an in-memory feed with `.collect()`,
//! * collect with a filter via `.collect_filtered(...)`,
//! * (for the umbrella) build directly from a [`crate::Body`] with
//!   [`FeedStream::from_body`].
//!
//! This is the **stream-first** entry point. The synchronous
//! [`super::super::Feed::parse`] and in-memory `Rss2Feed`/`AtomFeed`
//! constructors sit on top.
//!
//! [`Stream`]: rama_core::futures::Stream

use std::pin::Pin;
use std::task::{Context, Poll};

use rama_core::futures::Stream;
use rama_core::futures::StreamExt as _;
use rama_core::futures::stream::BoxStream;
use tokio::io::AsyncBufRead;

use super::super::atom::{AtomEntry, AtomFeed};
use super::super::parse::FeedParseError;
use super::super::rss2::{Rss2Feed, Rss2Item};
use super::atom1::{AtomHeader, AtomReadEvent, atom_event_stream};
use super::rss2::{Rss2Channel, Rss2ReadEvent, rss2_event_stream};

/// Async streaming reader for an RSS 2.0 feed.
///
/// Construction reads the document up to (but not including) the first
/// `<item>` and exposes the parsed [`Rss2Channel`] header via [`channel`].
/// The stream then yields one [`Rss2Item`] per channel item until the document
/// ends. The stream is the natural way to process a feed of arbitrary size
/// with bounded memory; use [`collect`] when the whole document fits.
///
/// [`channel`]: Self::channel
/// [`collect`]: Self::collect
pub struct Rss2FeedStream {
    channel: Rss2Channel,
    items: BoxStream<'static, Result<Rss2Item, FeedParseError>>,
}

impl Rss2FeedStream {
    /// Build the stream over `reader` in lenient mode (the parser tolerates
    /// unknown elements and recoverable text issues).
    pub async fn new<R>(reader: R) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        Self::new_with_mode(reader, false).await
    }

    /// Strict variant of [`Self::new`]: structural violations propagate as
    /// `Err` (missing required fields, malformed entities, etc.).
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
        let mut events = Box::pin(rss2_event_stream(reader, strict));

        // The internal event stream guarantees: `Channel` is yielded before
        // any `Item`, then any number of `Item`s, then `Eof`. So the first
        // event is always either Channel, Eof (item-less / not-a-feed), or
        // an error — no real loop is needed.
        let channel = match events.next().await {
            Some(Ok(Rss2ReadEvent::Channel(c))) => c,
            Some(Ok(Rss2ReadEvent::Item(_))) => {
                // Defensive: shouldn't happen given the contract above.
                return Err(FeedParseError {
                    message: "internal: item yielded before channel header".to_owned(),
                });
            }
            Some(Ok(Rss2ReadEvent::Eof)) | None => {
                return Err(FeedParseError {
                    message: "no <rss>/<channel> root encountered".to_owned(),
                });
            }
            Some(Err(e)) => return Err(e),
        };

        // From here on, the event stream produces zero or more `Item`s and
        // exactly one `Eof`. Map it into a clean item stream.
        let items: BoxStream<'static, Result<Rss2Item, FeedParseError>> = Box::pin(
            rama_core::futures::async_stream::stream_fn(move |mut yielder| async move {
                while let Some(ev) = events.next().await {
                    match ev {
                        Ok(Rss2ReadEvent::Item(item)) => {
                            yielder.yield_item(Ok(*item)).await;
                        }
                        Ok(Rss2ReadEvent::Eof) => return,
                        Ok(Rss2ReadEvent::Channel(_)) => {
                            // Already consumed above; the inner stream
                            // never re-emits it. Treat as a hard stop.
                            return;
                        }
                        Err(e) => {
                            yielder.yield_item(Err(e)).await;
                            return;
                        }
                    }
                }
            }),
        );

        Ok(Self { channel, items })
    }

    /// Borrow the channel-level metadata that was parsed at construction
    /// time. Cheap; the channel lives on the stream and is unmoved until
    /// [`drain`](Self::drain) or [`collect`](Self::collect) is called.
    #[must_use]
    pub fn channel(&self) -> &Rss2Channel {
        &self.channel
    }

    /// Split the stream into the channel header and the bare item stream so
    /// the caller can map/filter/fold over the items without giving up the
    /// header.
    #[must_use]
    pub fn drain(
        self,
    ) -> (
        Rss2Channel,
        BoxStream<'static, Result<Rss2Item, FeedParseError>>,
    ) {
        (self.channel, self.items)
    }

    /// Drain the stream into a complete in-memory [`Rss2Feed`].
    pub async fn collect(mut self) -> Result<Rss2Feed, FeedParseError> {
        let mut items = Vec::new();
        while let Some(item) = self.items.next().await {
            items.push(item?);
        }
        Ok(self.channel.into_feed_with_items(items))
    }

    /// Drain the stream into a complete [`Rss2Feed`], retaining only items for
    /// which `predicate` returns `true`. The remaining items are dropped as
    /// they're read so memory stays proportional to the kept set.
    pub async fn collect_filtered<F>(mut self, mut predicate: F) -> Result<Rss2Feed, FeedParseError>
    where
        F: FnMut(&Rss2Item) -> bool + Send,
    {
        let mut items = Vec::new();
        while let Some(item) = self.items.next().await {
            let item = item?;
            if predicate(&item) {
                items.push(item);
            }
        }
        Ok(self.channel.into_feed_with_items(items))
    }
}

impl Stream for Rss2FeedStream {
    type Item = Result<Rss2Item, FeedParseError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // We don't hold the items stream inline as a pin-projected field; it
        // already lives behind a `BoxStream` (a pinned trait object), so we
        // can just borrow-and-poll without a custom projection.
        let this = Pin::into_inner(self);
        this.items.poll_next_unpin(cx)
    }
}

/// Async streaming reader for an Atom 1.0 feed.
///
/// Mirror of [`Rss2FeedStream`] for Atom: header read at construction time,
/// entries yielded one by one.
pub struct AtomFeedStream {
    header: AtomHeader,
    entries: BoxStream<'static, Result<AtomEntry, FeedParseError>>,
}

impl AtomFeedStream {
    /// Build the stream over `reader` in lenient mode.
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
        let mut events = Box::pin(atom_event_stream(reader, strict));

        let header = match events.next().await {
            Some(Ok(AtomReadEvent::Feed(h))) => h,
            Some(Ok(AtomReadEvent::Entry(_))) => {
                return Err(FeedParseError {
                    message: "internal: entry yielded before feed header".to_owned(),
                });
            }
            Some(Ok(AtomReadEvent::Eof)) | None => {
                return Err(FeedParseError {
                    message: "no <feed> root encountered".to_owned(),
                });
            }
            Some(Err(e)) => return Err(e),
        };

        let entries: BoxStream<'static, Result<AtomEntry, FeedParseError>> = Box::pin(
            rama_core::futures::async_stream::stream_fn(move |mut yielder| async move {
                while let Some(ev) = events.next().await {
                    match ev {
                        Ok(AtomReadEvent::Entry(entry)) => {
                            yielder.yield_item(Ok(*entry)).await;
                        }
                        // Eof terminates the stream; a second Feed header
                        // shouldn't appear per the contract, but if it did
                        // we'd also stop here.
                        Ok(AtomReadEvent::Eof | AtomReadEvent::Feed(_)) => return,
                        Err(e) => {
                            yielder.yield_item(Err(e)).await;
                            return;
                        }
                    }
                }
            }),
        );

        Ok(Self { header, entries })
    }

    /// Borrow the feed-level metadata that was parsed at construction time.
    #[must_use]
    pub fn header(&self) -> &AtomHeader {
        &self.header
    }

    /// Split into `(header, entries)` so the caller can transform the entry
    /// stream without dropping the header.
    #[must_use]
    pub fn drain(
        self,
    ) -> (
        AtomHeader,
        BoxStream<'static, Result<AtomEntry, FeedParseError>>,
    ) {
        (self.header, self.entries)
    }

    /// Drain the stream into a complete in-memory [`AtomFeed`].
    pub async fn collect(mut self) -> Result<AtomFeed, FeedParseError> {
        let mut entries = Vec::new();
        while let Some(entry) = self.entries.next().await {
            entries.push(entry?);
        }
        Ok(self.header.into_feed_with_entries(entries))
    }

    /// Drain the stream into a complete [`AtomFeed`], keeping only entries
    /// for which `predicate` returns `true`.
    pub async fn collect_filtered<F>(mut self, mut predicate: F) -> Result<AtomFeed, FeedParseError>
    where
        F: FnMut(&AtomEntry) -> bool + Send,
    {
        let mut entries = Vec::new();
        while let Some(entry) = self.entries.next().await {
            let entry = entry?;
            if predicate(&entry) {
                entries.push(entry);
            }
        }
        Ok(self.header.into_feed_with_entries(entries))
    }
}

impl Stream for AtomFeedStream {
    type Item = Result<AtomEntry, FeedParseError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = Pin::into_inner(self);
        this.entries.poll_next_unpin(cx)
    }
}

/// Format-agnostic streaming reader.
///
/// [`FeedStream::new`] peeks the prefix of the input, detects whether it is
/// RSS 2.0 or Atom 1.0, and constructs the right inner stream — so callers
/// that don't know the format up front can still use a single entry point.
/// [`FeedStream::from_body`] is the same with an HTTP [`crate::Body`].
pub enum FeedStream {
    /// RSS 2.0 stream.
    Rss2(Rss2FeedStream),
    /// Atom 1.0 stream.
    Atom(AtomFeedStream),
}

impl FeedStream {
    /// Detect the format from the prefix of `reader` and build the matching
    /// inner stream. UTF-8 / UTF-16 BOMs are honoured (the UTF-16 path falls
    /// back to a buffered sync parse since the streaming reader is UTF-8).
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

    async fn new_with_mode<R>(mut reader: R, strict: bool) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        use tokio::io::AsyncBufReadExt as _;

        // Peek without consuming so the same reader carries the full document
        // into the format-specific stream.
        let peek = reader.fill_buf().await.map_err(|e| FeedParseError {
            message: format!("read feed body: {e}"),
        })?;

        // UTF-16 path: streaming-decode is out of scope; buffer + sync parse.
        if peek.starts_with(&[0xFF, 0xFE]) || peek.starts_with(&[0xFE, 0xFF]) {
            return Self::utf16_fallback(reader, strict).await;
        }
        // Strip UTF-8 BOM if present so detection sees `<?xml`/`<rss`/`<feed`.
        if peek.starts_with(&[0xEF, 0xBB, 0xBF]) {
            reader.consume(3);
        }

        let peek = reader.fill_buf().await.map_err(|e| FeedParseError {
            message: format!("read feed body: {e}"),
        })?;
        let probe_len = peek.len().min(2048);
        let probe = std::str::from_utf8(&peek[..probe_len]).unwrap_or("");
        let is_atom = super::super::parse::detect_atom(probe);
        let is_rss = !is_atom && super::super::parse::detect_rss(probe);

        if is_atom {
            return Ok(Self::Atom(
                AtomFeedStream::new_with_mode(reader, strict).await?,
            ));
        }
        if is_rss {
            return Ok(Self::Rss2(
                Rss2FeedStream::new_with_mode(reader, strict).await?,
            ));
        }

        if strict {
            return Err(FeedParseError {
                message: "document is neither RSS 2.0 nor Atom 1.0".to_owned(),
            });
        }
        // Lenient fallback: detection missed in the prefix. Buffer the rest
        // and let the sync parser take its second-chance pass.
        Self::utf16_fallback(reader, strict).await
    }

    async fn utf16_fallback<R>(reader: R, strict: bool) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        use tokio::io::AsyncReadExt as _;

        let mut reader = reader;
        let mut bytes = Vec::with_capacity(8 * 1024);
        reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| FeedParseError {
                message: format!("read feed body: {e}"),
            })?;
        let text = super::super::feed::decode_xml_body(&bytes)?;
        let feed = if strict {
            super::super::Feed::parse_strict(&text)?
        } else {
            super::super::Feed::parse(&text)?
        };
        // Re-wrap the in-memory feed as a single-shot stream so the public
        // API stays uniform regardless of which path was taken.
        match feed {
            super::super::Feed::Rss2(f) => Ok(Self::Rss2(Rss2FeedStream::from_owned(f))),
            super::super::Feed::Atom(f) => Ok(Self::Atom(AtomFeedStream::from_owned(f))),
        }
    }

    /// Build a stream directly from an HTTP body. Convenience wrapper that
    /// turns the body's byte stream into an async reader and delegates to
    /// [`Self::new`].
    pub async fn from_body(body: crate::Body) -> Result<Self, FeedParseError> {
        Self::new(body_reader(body)).await
    }

    /// Strict variant of [`Self::from_body`].
    pub async fn from_body_strict(body: crate::Body) -> Result<Self, FeedParseError> {
        Self::new_strict(body_reader(body)).await
    }

    /// Drain the entire stream into an in-memory [`super::super::Feed`].
    pub async fn collect(self) -> Result<super::super::Feed, FeedParseError> {
        match self {
            Self::Rss2(s) => s.collect().await.map(super::super::Feed::Rss2),
            Self::Atom(s) => s.collect().await.map(super::super::Feed::Atom),
        }
    }
}

/// Wrap a [`crate::Body`] in an [`AsyncBufRead`] sufficient for the streaming
/// readers.
fn body_reader(
    body: crate::Body,
) -> tokio::io::BufReader<
    rama_core::stream::io::StreamReader<BodyDataStream, rama_core::bytes::Bytes>,
> {
    use rama_core::futures::StreamExt as _;
    use rama_core::stream::io::StreamReader;

    let stream: BodyDataStream = body
        .into_data_stream()
        .map(|r| r.map_err(std::io::Error::other))
        .boxed();
    let inner = StreamReader::new(stream);
    tokio::io::BufReader::with_capacity(8 * 1024, inner)
}

type BodyDataStream = BoxStream<'static, std::io::Result<rama_core::bytes::Bytes>>;

// Wrap an already-collected feed back into a single-shot stream so the
// UTF-16 / lenient-fallback path can return a `FeedStream` uniformly.
impl Rss2FeedStream {
    pub(super) fn from_owned(feed: Rss2Feed) -> Self {
        let (channel, items) = split_rss2_feed(feed);
        let items_stream =
            rama_core::futures::stream::iter(items.into_iter().map(Ok::<_, FeedParseError>));
        Self {
            channel,
            items: Box::pin(items_stream),
        }
    }
}

impl AtomFeedStream {
    pub(super) fn from_owned(feed: AtomFeed) -> Self {
        let (header, entries) = split_atom_feed(feed);
        let entries_stream =
            rama_core::futures::stream::iter(entries.into_iter().map(Ok::<_, FeedParseError>));
        Self {
            header,
            entries: Box::pin(entries_stream),
        }
    }
}

fn split_rss2_feed(feed: Rss2Feed) -> (Rss2Channel, Vec<Rss2Item>) {
    let channel = Rss2Channel {
        title: feed.title,
        link: feed.link,
        description: feed.description,
        language: feed.language,
        copyright: feed.copyright,
        managing_editor: feed.managing_editor,
        web_master: feed.web_master,
        pub_date: feed.pub_date,
        last_build_date: feed.last_build_date,
        categories: feed.categories,
        generator: feed.generator,
        docs: feed.docs,
        ttl: feed.ttl,
        image: feed.image,
        atom_links: feed.atom_links,
        extensions: feed.extensions,
    };
    (channel, feed.items)
}

fn split_atom_feed(feed: AtomFeed) -> (AtomHeader, Vec<AtomEntry>) {
    let header = AtomHeader {
        id: feed.id,
        title: feed.title,
        updated: feed.updated,
        authors: feed.authors,
        links: feed.links,
        categories: feed.categories,
        contributors: feed.contributors,
        generator: feed.generator,
        icon: feed.icon,
        logo: feed.logo,
        rights: feed.rights,
        subtitle: feed.subtitle,
        extensions: feed.extensions,
    };
    (header, feed.entries)
}
