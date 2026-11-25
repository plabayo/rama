//! Replay storage for the HTTP retry layer.
//!
//! A store can be shared by many requests. Each request gets a writer, and
//! only a writer that has seen the complete upload can publish a replay source.
//! Each attempt clones a cursor pointing at the start of that source.
//!
//! Choose a store when configuring the managed policy, for example a
//! [`MemoryReplay`] with its own limits or an [`FsReplayStore`] that spills
//! larger uploads to disk. Store instances can carry their own limits and
//! resources, such as a disk budget shared across all requests served by the
//! same client.

use std::{
    collections::TryReserveError,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    futures::future::BoxFuture,
};
use rama_utils::{macros::generate_set_and_with, octets::kib};

use super::body::MemoryCursor;
use crate::{HeaderMap, StreamingBody, body::SizeHint};

mod fs;
pub use fs::FsReplayStore;

/// Default maximum payload retained per request by the in-memory store.
pub const DEFAULT_MAX_BYTES: u64 = rama_utils::octets::kib_u64(64);

/// Default time allowed to capture an upload, including any post-attempt drain.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default time a retry waits for a still-live first reader to release the upload.
pub const DEFAULT_HANDOFF_TIMEOUT: Duration = Duration::from_secs(1);

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

    /// Longest wait, within [`Self::timeout`], for a first reader still alive
    /// after its attempt returned to finish or drop before a retry.
    fn handoff_timeout(&self) -> Duration;

    /// Allow an already buffered, trailerless body to be replayed directly from
    /// its shared bytes, bypassing the writer. The layer still enforces its
    /// capture limits. Return `false` if the store needs to observe or
    /// account for these uploads.
    fn reuse_buffered_bytes(&self) -> bool;

    /// Begin a new, empty capture.
    ///
    /// `size_hint` describes the upload; its upper bound, when known, is capped
    /// at the capture limit, so a store can bound how far its buffer grows.
    fn start(&self, size_hint: &SizeHint) -> Box<dyn ReplayWriter>;
}

impl<S: ReplayStore + ?Sized> ReplayStore for Arc<S> {
    fn max_bytes(&self) -> u64 {
        (**self).max_bytes()
    }

    fn timeout(&self) -> Duration {
        (**self).timeout()
    }

    fn handoff_timeout(&self) -> Duration {
        (**self).handoff_timeout()
    }

    fn reuse_buffered_bytes(&self) -> bool {
        (**self).reuse_buffered_bytes()
    }

    fn start(&self, size_hint: &SizeHint) -> Box<dyn ReplayWriter> {
        (**self).start(size_hint)
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
    handoff_timeout: Duration,
}

impl MemoryReplay {
    /// The default store: up to 64 KiB of data per upload within 30 seconds.
    pub const DEFAULT: Self = Self::new(DEFAULT_MAX_BYTES);

    /// Configure the inclusive per-request data limit.
    #[must_use]
    pub const fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            timeout: DEFAULT_TIMEOUT,
            handoff_timeout: DEFAULT_HANDOFF_TIMEOUT,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Configure the time allowed to complete capture.
        pub const fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Configure how long a retry waits for a still-live first reader.
        pub const fn handoff_timeout(mut self, timeout: Duration) -> Self {
            self.handoff_timeout = timeout;
            self
        }
    }
}

impl Default for MemoryReplay {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl ReplayStore for MemoryReplay {
    fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn handoff_timeout(&self) -> Duration {
        self.handoff_timeout
    }

    fn reuse_buffered_bytes(&self) -> bool {
        true
    }

    fn start(&self, size_hint: &SizeHint) -> Box<dyn ReplayWriter> {
        let limit = usize::try_from(self.max_bytes).unwrap_or(usize::MAX);
        Box::new(MemoryWriter {
            capture: MemoryCapture::new(expected_len(size_hint).min(limit), limit),
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

/// Expected upload length: the exact or upper bound when known, else the lower bound.
fn expected_len(size_hint: &SizeHint) -> usize {
    usize::try_from(size_hint.upper().unwrap_or(size_hint.lower())).unwrap_or(usize::MAX)
}

/// Transport bodies slice frames out of read buffers of at least 8 KiB, so a
/// smaller frame retained as-is pins at least twice its size.
const OWN_FRAMES_UP_TO: usize = kib(4);

/// Bytes retained for replay.
///
/// A lone large frame is kept as-is. Small or fragmented uploads are copied
/// into one store-owned buffer that grows with the received bytes.
#[derive(Debug, Default)]
struct MemoryCapture {
    data: Captured,
    // Growth stops here while the upload stays within it, so a matching upload has no slack.
    expected: usize,
    // Growth never reserves beyond this, unless one frame needs more.
    limit: usize,
}

/// Make room for `additional` bytes, doubling with what arrived rather than
/// reserving a length the peer only announced.
fn grow_for(
    bytes: &mut Vec<u8>,
    additional: usize,
    expected: usize,
    limit: usize,
) -> Result<(), TryReserveError> {
    let len = bytes.len().saturating_add(additional);
    if len <= bytes.capacity() {
        return Ok(());
    }
    let ceiling = if len <= expected {
        expected
    } else {
        limit.max(len)
    };
    let target = len.max(bytes.capacity().saturating_mul(2)).min(ceiling);
    bytes.try_reserve_exact(target - bytes.len())
}

#[derive(Debug, Default)]
enum Captured {
    #[default]
    Empty,
    Single(Bytes),
    Owned(Vec<u8>),
}

impl MemoryCapture {
    fn new(expected: usize, limit: usize) -> Self {
        Self {
            data: Captured::Empty,
            expected,
            limit,
        }
    }

    fn len(&self) -> usize {
        match &self.data {
            Captured::Empty => 0,
            Captured::Single(data) => data.len(),
            Captured::Owned(data) => data.len(),
        }
    }

    fn push(&mut self, data: &Bytes) -> Result<(), TryReserveError> {
        if data.is_empty() {
            return Ok(());
        }
        let (expected, limit) = (self.expected, self.limit);
        match &mut self.data {
            Captured::Empty if data.len() >= expected && data.len() > OWN_FRAMES_UP_TO => {
                self.data = Captured::Single(data.clone());
            }
            Captured::Empty => {
                let mut bytes = Vec::new();
                grow_for(&mut bytes, data.len(), expected, limit)?;
                bytes.extend_from_slice(data);
                self.data = Captured::Owned(bytes);
            }
            Captured::Single(first) => {
                let mut bytes = Vec::new();
                grow_for(
                    &mut bytes,
                    first.len().saturating_add(data.len()),
                    expected,
                    limit,
                )?;
                bytes.extend_from_slice(first);
                bytes.extend_from_slice(data);
                self.data = Captured::Owned(bytes);
            }
            Captured::Owned(bytes) => {
                grow_for(bytes, data.len(), expected, limit)?;
                bytes.extend_from_slice(data);
            }
        }
        Ok(())
    }

    fn into_bytes(self) -> Bytes {
        match self.data {
            Captured::Empty => Bytes::new(),
            Captured::Single(data) => data,
            Captured::Owned(data) => Bytes::from(data),
        }
    }

    fn into_replay_bytes(mut self) -> Bytes {
        if let Captured::Owned(bytes) = &mut self.data
            && bytes.capacity() - bytes.len() > bytes.len() / 4
        {
            // The replay lives as long as the request. Slack within a quarter
            // stays: allocator size classes are about that far apart anyway.
            bytes.shrink_to_fit();
        }
        self.into_bytes()
    }

    fn seal(self, trailers: Option<HeaderMap>) -> Arc<dyn ReplaySource> {
        Arc::new(MemoryCursor::new(self.into_replay_bytes(), trailers))
    }
}

#[cfg(test)]
async fn append(writer: &mut dyn ReplayWriter, data: Bytes) -> Result<(), BoxError> {
    std::future::poll_fn(|cx| writer.poll_append(cx, &data)).await
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use rama_utils::{
        fs::TempDir,
        octets::{kib, kib_u64, mib_u64},
    };

    use super::*;
    use crate::{
        Request, Response,
        body::util::BodyExt as _,
        layer::retry::{ManagedPolicy, Policy},
        request::Parts,
    };

    /// A transport read buffer that records when its allocation is released.
    struct ReadBuffer {
        bytes: Vec<u8>,
        released: Arc<AtomicBool>,
    }

    impl AsRef<[u8]> for ReadBuffer {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for ReadBuffer {
        fn drop(&mut self) {
            self.released.store(true, Ordering::SeqCst);
        }
    }

    fn frame_of_read_buffer(len: usize) -> (Bytes, Arc<AtomicBool>) {
        let released = Arc::new(AtomicBool::new(false));
        let buffer = Bytes::from_owner(ReadBuffer {
            bytes: vec![7; kib(64)],
            released: released.clone(),
        });
        (buffer.slice(..len), released)
    }

    fn parts() -> Parts {
        Request::new(()).into_parts().0
    }

    #[tokio::test]
    async fn small_frames_do_not_pin_their_read_buffer() {
        for (len, pinned) in [(100, false), (OWN_FRAMES_UP_TO, false), (kib(16), true)] {
            let (frame, released) = frame_of_read_buffer(len);
            let mut writer = MemoryReplay::DEFAULT.start(&SizeHint::with_exact(len as u64));
            append(&mut *writer, frame).await.unwrap();
            let source = writer.finish(None).await.unwrap();
            assert_eq!(released.load(Ordering::SeqCst), !pinned, "{len}");
            let replay = source.clone_cursor().collect().await.unwrap().to_bytes();
            assert_eq!(replay, vec![7; len]);
            drop((replay, source));
            assert!(released.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn fragmented_capture_grows_to_its_length_without_slack() {
        let frame = Bytes::from(vec![1; kib(1)]);
        // Known length: growth stops at it.
        let mut sized = MemoryCapture::new(kib(40), kib(64));
        // Unknown length: growth never reserves beyond the limit.
        let mut capped = MemoryCapture::new(0, kib(40));
        for _ in 0..40 {
            sized.push(&frame).unwrap();
            capped.push(&frame).unwrap();
        }
        for capture in [sized, capped] {
            let Captured::Owned(bytes) = &capture.data else {
                panic!("fragmented uploads are owned");
            };
            assert_eq!(bytes.capacity(), kib(40));
            let sealed = capture.into_replay_bytes();
            assert_eq!(sealed.len(), kib(40));
            assert_eq!(sealed.try_into_mut().unwrap().capacity(), kib(40));
        }

        // Growth toward the limit: large slack is released, small slack is kept.
        for (frames, retained) in [(40, kib(40)), (56, kib(64)), (64, kib(64))] {
            let mut grown = MemoryCapture::new(0, kib(64));
            for _ in 0..frames {
                grown.push(&frame).unwrap();
            }
            let sealed = grown.into_replay_bytes();
            assert_eq!(sealed.len(), kib(frames));
            assert_eq!(
                sealed.try_into_mut().unwrap().capacity(),
                retained,
                "{frames}"
            );
        }
    }

    #[test]
    fn announced_length_is_not_reserved_before_it_arrives() {
        let mut slow = MemoryCapture::new(kib(64), kib(64));
        slow.push(&Bytes::from(vec![1; 100])).unwrap();
        let Captured::Owned(bytes) = &slow.data else {
            panic!("a small frame is owned");
        };
        assert_eq!(bytes.capacity(), 100);
        slow.push(&Bytes::from(vec![1; 100])).unwrap();
        let Captured::Owned(bytes) = &slow.data else {
            panic!("a small frame is owned");
        };
        assert_eq!(bytes.capacity(), 200);
    }

    #[tokio::test]
    async fn configured_stores_back_the_managed_policy() {
        let memory = MemoryReplay::new(kib_u64(128)).with_timeout(Duration::from_secs(5));
        let policy = ManagedPolicy::default().with_replay_store(memory);
        let store = Policy::<Response, BoxError>::replay_store(&policy, &parts());
        assert_eq!(store.max_bytes(), kib_u64(128));
        assert_eq!(store.timeout(), Duration::from_secs(5));
        assert!(store.reuse_buffered_bytes());

        let parent = TempDir::new().await.unwrap();
        let disk = FsReplayStore::in_dir(parent.path()).await.unwrap();
        let policy = ManagedPolicy::default().with_replay_store(disk);
        let store = Policy::<Response, BoxError>::replay_store(&policy, &parts());
        assert_eq!(store.max_bytes(), mib_u64(8));
        assert_eq!(store.timeout(), DEFAULT_TIMEOUT);
        assert!(!store.reuse_buffered_bytes());
    }

    #[tokio::test]
    async fn memory_store_readers_have_independent_data_and_trailers() {
        let mut writer = MemoryReplay::new(5).start(&SizeHint::default());
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
        let mut writer = MemoryReplay::new(1).start(&SizeHint::default());
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
