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

use rama_core::futures::stream::BoxStream;
use tokio::io::AsyncBufRead;

use super::super::Feed;
use super::super::error::{CollectError, FeedCollectError, FeedParseError};
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
