//! Replay storage for the HTTP retry layer.
//!
//! A store can be shared by many requests. Each request gets a writer, and
//! only a writer that has seen the complete upload can publish a replay source.
//! Each attempt clones a cursor pointing at the start of that source.
//!
//! Choose a store when configuring the managed policy. Store instances can
//! carry their own limits and resources, such as a disk budget shared across
//! all requests served by the same client.
//!
//! ```
//! use rama_http::layer::retry::{ManagedPolicy, storage::{MemoryReplay, FsReplayStore}};
//! use rama_utils::octets::kib_u64;
//! use std::{path::Path, time::Duration};
//!
//! let memory = MemoryReplay::new(kib_u64(128)).with_timeout(Duration::from_secs(5));
//! let policy = ManagedPolicy::default().with_replay_store(memory);
//!
//! # async fn configure_disk(parent: &Path) -> std::io::Result<()> {
//! let disk = FsReplayStore::in_dir(parent).await?;
//! let policy = ManagedPolicy::default().with_replay_store(disk);
//! # Ok(())
//! # }
//! ```

use super::body::MemoryCursor;
use crate::{HeaderMap, StreamingBody};
use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    futures::future::BoxFuture,
};
use std::{
    collections::TryReserveError,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

mod fs;
pub use fs::FsReplayStore;

/// Default maximum payload retained per request by the in-memory store.
pub const DEFAULT_MAX_BYTES: u64 = rama_utils::octets::kib_u64(64);

/// Default time allowed to capture an upload, including any post-attempt drain.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Creates independent writers for uploads selected by a retry policy.
///
/// Limits apply to the replay copy. When capture exceeds a limit the original
/// request can continue to stream. The byte limit counts HTTP data bytes.
/// Trailer fields are retained separately. The per-request `start` method must
/// avoid blocking the executor. Acquire asynchronous resources in the writer.
pub trait ReplayStore: Send + Sync + 'static {
    /// Inclusive per-request data limit. Exactly this many bytes plus trailers
    /// can still form a complete replay.
    fn max_bytes(&self) -> u64;

    /// Maximum duration of capture, measured from the start of the first attempt.
    fn timeout(&self) -> Duration;

    /// Allow an already buffered, trailerless body to be replayed directly from
    /// its shared bytes, bypassing the writer. The layer still enforces its
    /// capture limits. Leave this disabled if the store needs to observe or
    /// account for these uploads.
    fn reuse_buffered_bytes(&self) -> bool {
        false
    }

    /// Begin a new, empty capture.
    fn start(&self) -> Box<dyn ReplayWriter>;
}

impl<S: ReplayStore + ?Sized> ReplayStore for Arc<S> {
    fn max_bytes(&self) -> u64 {
        (**self).max_bytes()
    }

    fn timeout(&self) -> Duration {
        (**self).timeout()
    }

    fn reuse_buffered_bytes(&self) -> bool {
        (**self).reuse_buffered_bytes()
    }

    fn start(&self) -> Box<dyn ReplayWriter> {
        (**self).start()
    }
}

/// Receives data frames in order for one upload.
///
/// The retry layer keeps the current frame available to the first attempt
/// while the append is pending. An append error abandons capture. A deadline
/// or cancellation can drop a pending operation and the writer at any time.
/// Implementations must arrange for partial resources to be reclaimed.
pub trait ReplayWriter: Send + 'static {
    /// Append one data frame. Until this returns ready, the caller keeps the
    /// same bytes and polls again with the current task's waker. Store any
    /// in-flight write in `self` and arrange a wakeup when it can progress.
    /// A successful append consumes the entire frame.
    fn poll_append(&mut self, cx: &mut Context<'_>, data: &Bytes) -> Poll<Result<(), BoxError>>;

    /// Seal the payload and trailers after EOF and successful completion of
    /// every append. Drop the writer if an append fails or capture is canceled.
    fn finish(
        self: Box<Self>,
        trailers: Option<HeaderMap>,
    ) -> BoxFuture<'static, Result<Arc<dyn ReplaySource>, BoxError>>;
}

/// A body cursor that can independently replay its remaining data and trailers.
///
/// A writer returns a cursor positioned at the start of the completed upload.
/// Report the exact remaining data length through [`StreamingBody::size_hint`].
pub trait ReplaySource:
    StreamingBody<Data = Bytes, Error = BoxError> + Send + Sync + Unpin + std::any::Any
{
    /// Clone the current read position. Each cursor owns its progress and keeps
    /// the stored payload alive. Start I/O when polled so cloning never blocks.
    fn clone_cursor(&self) -> Box<dyn ReplaySource>;
}

impl std::fmt::Debug for dyn ReplaySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplaySource")
            .field("size_hint", &self.size_hint())
            .finish_non_exhaustive()
    }
}

/// Bounded, per-request memory storage. The default retains up to 64 KiB of
/// data per upload and allows up to 30 seconds to finish capture.
#[derive(Debug, Clone, Copy)]
pub struct MemoryReplay {
    max_bytes: u64,
    timeout: Duration,
}

impl MemoryReplay {
    /// Configure the inclusive per-request data limit.
    #[must_use]
    pub const fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Configure the time allowed to complete capture.
        pub const fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }
}

impl Default for MemoryReplay {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_BYTES)
    }
}

impl ReplayStore for MemoryReplay {
    fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn reuse_buffered_bytes(&self) -> bool {
        true
    }

    fn start(&self) -> Box<dyn ReplayWriter> {
        Box::new(MemoryWriter {
            capture: MemoryCapture::default(),
            max_bytes: self.max_bytes,
        })
    }
}

struct MemoryWriter {
    capture: MemoryCapture,
    max_bytes: u64,
}

impl ReplayWriter for MemoryWriter {
    fn poll_append(&mut self, _: &mut Context<'_>, data: &Bytes) -> Poll<Result<(), BoxError>> {
        if data.len() as u64 > self.max_bytes.saturating_sub(self.capture.len() as u64) {
            return Poll::Ready(Err(BoxError::from_static_str(
                "replay exceeds the configured memory limit",
            )));
        }
        Poll::Ready(self.capture.push(data).map_err(Into::into))
    }

    fn finish(
        self: Box<Self>,
        trailers: Option<HeaderMap>,
    ) -> BoxFuture<'static, Result<Arc<dyn ReplaySource>, BoxError>> {
        Box::pin(async move { Ok(self.capture.seal(trailers)) })
    }
}

/// Retain a single frame directly. Coalesce fragmented uploads into one buffer
/// so arbitrarily small frames do not require a descriptor each.
#[derive(Debug, Default)]
enum MemoryCapture {
    #[default]
    Empty,
    Single(Bytes),
    Multiple(Vec<u8>),
}

impl MemoryCapture {
    fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Single(data) => data.len(),
            Self::Multiple(data) => data.len(),
        }
    }

    fn push(&mut self, data: &Bytes) -> Result<(), TryReserveError> {
        if data.is_empty() {
            return Ok(());
        }
        match self {
            Self::Empty => *self = Self::Single(data.clone()),
            Self::Single(first) => {
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(first.len().saturating_add(data.len()))?;
                bytes.extend_from_slice(first);
                bytes.extend_from_slice(data);
                *self = Self::Multiple(bytes);
            }
            Self::Multiple(bytes) => {
                bytes.try_reserve(data.len())?;
                bytes.extend_from_slice(data);
            }
        }
        Ok(())
    }

    fn into_bytes(self) -> Bytes {
        match self {
            Self::Empty => Bytes::new(),
            Self::Single(data) => data,
            Self::Multiple(data) => Bytes::from(data),
        }
    }

    fn seal(self, trailers: Option<HeaderMap>) -> Arc<dyn ReplaySource> {
        Arc::new(MemoryCursor::new(self.into_bytes(), trailers))
    }
}

#[cfg(test)]
async fn append(writer: &mut dyn ReplayWriter, data: Bytes) -> Result<(), BoxError> {
    std::future::poll_fn(|cx| writer.poll_append(cx, &data)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::util::BodyExt as _;

    #[tokio::test]
    async fn memory_store_readers_have_independent_data_and_trailers() {
        let mut writer = MemoryReplay::new(5).start();
        append(&mut *writer, Bytes::from_static(b"he"))
            .await
            .unwrap();
        append(&mut *writer, Bytes::from_static(b"llo"))
            .await
            .unwrap();
        let mut trailers = HeaderMap::new();
        trailers.insert("x-finished", "yes".parse().unwrap());
        let source = writer.finish(Some(trailers.clone())).await.unwrap();
        let mut first = source.clone_cursor();
        let second = source.clone_cursor();
        drop(source);
        assert_eq!(first.size_hint().exact(), Some(5));
        assert_eq!(
            first.frame().await.unwrap().unwrap().into_data().unwrap(),
            "hello"
        );
        assert_eq!(first.size_hint().exact(), Some(0));
        assert!(!first.is_end_stream());
        assert_eq!(
            first
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap(),
            trailers
        );
        let mut complete = second.collect().await.unwrap();
        assert_eq!(complete.take_trailers(), Some(trailers));
        assert_eq!(complete.to_bytes(), "hello");
    }

    #[tokio::test]
    async fn memory_store_rejects_bytes_beyond_its_own_limit() {
        let mut writer = MemoryReplay::new(1).start();
        append(&mut *writer, Bytes::from_static(b"a"))
            .await
            .unwrap();
        assert!(
            append(&mut *writer, Bytes::from_static(b"b"))
                .await
                .is_err()
        );
    }
}
