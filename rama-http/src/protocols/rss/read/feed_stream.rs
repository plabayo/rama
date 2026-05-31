//! Format-agnostic async streaming reader.
//!
//! [`FeedStream`] peeks the first chunk of an [`AsyncBufRead`] (or an HTTP
//! `Body`), detects whether the input is RSS 2.0 or Atom 1.0, and constructs
//! the matching strongly-typed inner stream. Use it when the caller doesn't
//! know the format up front.
//!
//! The header is read at construction time (each inner stream's
//! [`Rss2FeedStream::new`] / [`AtomFeedStream::new`] does that), so by the
//! time `FeedStream::new` returns the caller can already inspect channel/feed
//! metadata via [`FeedStream::channel`] / [`FeedStream::header`].

use std::pin::Pin;
use std::task::{Context, Poll};

use jiff::Timestamp;
use rama_core::futures::Stream;
use rama_core::futures::stream::BoxStream;
use tokio::io::AsyncBufRead;

use super::super::error::{CollectError, FeedCollectError, FeedParseError};
use super::super::feed::{Feed, FeedItem, pick_alternate, pick_rel};
use super::super::parse_util::{detect_atom, detect_rss};
use super::{AtomFeedStream, AtomHeader, Rss2Channel, Rss2FeedStream};

/// One async stream per supported feed format. Use [`FeedStream::new`] when
/// the input format isn't known ahead of time, or [`Rss2FeedStream`] /
/// [`AtomFeedStream`] directly when it is.
pub enum FeedStream {
    Rss2(Rss2FeedStream),
    Atom(AtomFeedStream),
}

impl FeedStream {
    /// Peek the prefix of `reader`, decide the format, and build the
    /// matching inner stream.
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
        // `PROBE_MIN_BYTES` (or EOF), then prepend it back to the reader via
        // `Cursor::chain` so the inner stream sees the full document.
        const PROBE_MIN_BYTES: usize = 1024;
        const PROBE_MAX_BYTES: usize = 2048;
        let mut reader = reader;
        let mut probe = Vec::with_capacity(PROBE_MAX_BYTES);
        let mut chunk = [0u8; 256];
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
        let probe_str =
            std::str::from_utf8(&probe[..probe.len().min(PROBE_MAX_BYTES)]).unwrap_or("");
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
    pub fn link(&self) -> Option<&str> {
        match self {
            Self::Rss2(s) => Some(&s.channel().link),
            Self::Atom(s) => pick_alternate(&s.header().links).map(|l| l.href.as_str()),
        }
    }

    /// See [`Feed::self_link`].
    #[must_use]
    pub fn self_link(&self) -> Option<&str> {
        match self {
            Self::Rss2(s) => pick_rel(&s.channel().atom_links, "self").map(|l| l.href.as_str()),
            Self::Atom(s) => pick_rel(&s.header().links, "self").map(|l| l.href.as_str()),
        }
    }

    /// See [`Feed::id`].
    #[must_use]
    pub fn id(&self) -> Option<&str> {
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
    pub fn image_url(&self) -> Option<&str> {
        match self {
            Self::Rss2(s) => s.channel().image.as_ref().map(|i| i.url.as_str()),
            Self::Atom(s) => s.header().logo.as_deref(),
        }
    }

    /// See [`Feed::icon_url`].
    #[must_use]
    pub fn icon_url(&self) -> Option<&str> {
        match self {
            Self::Rss2(_) => None,
            Self::Atom(s) => s.header().icon.as_deref(),
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
    #[must_use]
    pub fn authors(&self) -> Vec<&str> {
        match self {
            Self::Rss2(s) => {
                let c = s.channel();
                [c.managing_editor.as_deref(), c.web_master.as_deref()]
                    .into_iter()
                    .flatten()
                    .filter(|v| !v.is_empty())
                    .collect()
            }
            Self::Atom(s) => s.header().authors.iter().map(|p| p.name.as_str()).collect(),
        }
    }

    /// See [`Feed::categories`].
    #[must_use]
    pub fn categories(&self) -> Vec<&str> {
        match self {
            Self::Rss2(s) => s
                .channel()
                .categories
                .iter()
                .map(|c| c.name.as_str())
                .collect(),
            Self::Atom(s) => s
                .header()
                .categories
                .iter()
                .map(|c| c.term.as_str())
                .collect(),
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
