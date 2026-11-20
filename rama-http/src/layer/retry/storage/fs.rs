//! Bounded memory capture with overflow to a private temporary file.

use super::{DEFAULT_TIMEOUT, MemoryCapture, ReplaySource, ReplayStore, ReplayWriter};
use crate::{
    HeaderMap, StreamingBody,
    body::{Frame, SizeHint},
};
use parking_lot::Mutex;
#[cfg(any(unix, windows))]
use rama_core::io::ReadAt as _;
use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    futures::future::BoxFuture,
};
use rama_utils::{
    fs::TempDir,
    octets::{kib, mib, mib_u64},
};
#[cfg(not(any(unix, windows)))]
use std::io::{Read as _, Seek as _, SeekFrom};
use std::{
    fs::File,
    io::{self, Write},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{runtime::Handle, task::JoinHandle};

const MAX_FILES: usize = 64;
const READ_CHUNK: usize = kib(64);

/// Capture small uploads in memory and spill larger uploads into temporary files.
///
/// Per-request limits count payload bytes. Clones share a disk budget for all
/// file payloads, including memory prefixes migrated to disk, and at most 64
/// live files. A request can use the full limit. A reservation that would
/// exceed a limit immediately disables replay for that request.
///
/// After spilling, writes smaller than the lesser of the memory threshold and
/// 16 KiB can be batched in memory. Disk quota is reserved before submitting
/// each frame. A retry flushes all pending writes before it can open a reader.
/// If the first attempt is final, the buffer is discarded and any write
/// already submitted to the filesystem settles before its quota is returned.
///
/// The backing file is anonymous on Unix and delete-on-close on Windows.
/// Readers and outstanding blocking I/O retain both the file and its quota.
/// Dropping the last owner closes the descriptor before releasing its charge.
#[derive(Clone, Debug)]
pub struct FsReplayStore {
    storage: Arc<Storage>,
    memory_threshold: usize,
    max_body_bytes: usize,
    timeout: Duration,
}

#[derive(Debug)]
struct Storage {
    max_disk_bytes: u64,
    usage: Mutex<Usage>,
    directory: TempDir,
}

#[derive(Debug, Default)]
struct Usage {
    bytes: u64,
    files: usize,
}

impl FsReplayStore {
    /// Create a store under an existing parent with a 64 KiB memory threshold,
    /// an 8 MiB limit per upload, and a shared 512 MiB disk budget. The capture
    /// timeout defaults to 30 seconds. Use [`Self::new`] for custom limits.
    pub async fn in_dir(parent: impl AsRef<Path>) -> io::Result<Self> {
        Self::new(
            parent,
            super::DEFAULT_MAX_BYTES as usize,
            mib(8),
            mib_u64(512),
        )
        .await
    }

    /// Create a private per-store directory under the existing trusted parent.
    /// A body stays in memory through the inclusive memory threshold and can
    /// replay through the inclusive per-body maximum. Zero threshold spills
    /// every nonempty body; zero disk budget permits only memory captures.
    pub async fn new(
        parent: impl AsRef<Path>,
        memory_threshold: usize,
        max_body_bytes: usize,
        max_disk_bytes: u64,
    ) -> io::Result<Self> {
        let directory = TempDir::with_prefix_in("rama-http-retry-", parent).await?;
        Ok(Self {
            storage: Arc::new(Storage {
                directory,
                max_disk_bytes,
                usage: Mutex::default(),
            }),
            memory_threshold,
            max_body_bytes,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the capture deadline for requests using this handle.
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    /// Private temporary directory. Its lifetime includes outstanding readers.
    pub fn directory(&self) -> &Path {
        self.storage.directory.path()
    }
}

impl ReplayStore for FsReplayStore {
    fn start(&self) -> Box<dyn ReplayWriter> {
        Box::new(Writer {
            store: self.clone(),
            state: State::Memory,
            buffered: MemoryCapture::default(),
        })
    }

    fn max_bytes(&self) -> u64 {
        self.max_body_bytes as u64
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }
}

struct Writer {
    store: FsReplayStore,
    state: State,
    // Kept only until this upload spills to disk.
    buffered: MemoryCapture,
}

enum State {
    Memory,
    Opening(JoinHandle<io::Result<ReplayFile>>),
    File(ReplayFile),
    Writing(JoinHandle<io::Result<ReplayFile>>),
}

struct ReplayFile {
    file: File,
    charge: Charge,
    batch: Vec<u8>,
    #[cfg(not(any(unix, windows)))]
    cursor: Mutex<()>,
}

struct Charge {
    storage: Arc<Storage>,
    bytes: u64,
}

fn quota_error() -> io::Error {
    io::Error::other("HTTP replay disk quota exceeded")
}

impl Charge {
    fn new(storage: Arc<Storage>, bytes: u64) -> io::Result<Self> {
        {
            let mut usage = storage.usage.lock();
            if bytes > storage.max_disk_bytes - usage.bytes || usage.files >= MAX_FILES {
                return Err(quota_error());
            }
            usage.files += 1;
            usage.bytes += bytes;
        }
        Ok(Self { storage, bytes })
    }

    fn grow(&mut self, additional: u64) -> io::Result<()> {
        let mut usage = self.storage.usage.lock();
        if additional > self.storage.max_disk_bytes - usage.bytes {
            return Err(quota_error());
        }
        usage.bytes += additional;
        self.bytes += additional;
        Ok(())
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        let mut usage = self.storage.usage.lock();
        usage.bytes -= self.bytes;
        usage.files -= 1;
    }
}

impl ReplayFile {
    fn new(file: File, charge: Charge) -> Self {
        Self {
            file,
            charge,
            batch: Vec::new(),
            #[cfg(not(any(unix, windows)))]
            cursor: Mutex::new(()),
        }
    }

    fn write(mut self, frame: &[u8]) -> io::Result<Self> {
        self.file.write_all(&self.batch)?;
        self.batch.clear();
        self.file.write_all(frame)?;
        Ok(self)
    }

    fn queue_write(self, frame: Bytes) -> io::Result<JoinHandle<io::Result<Self>>> {
        let runtime = Handle::try_current().map_err(io::Error::other)?;
        Ok(runtime.spawn_blocking(move || self.write(&frame)))
    }
}

impl ReplayWriter for Writer {
    fn poll_append(&mut self, cx: &mut Context<'_>, data: &Bytes) -> Poll<Result<(), BoxError>> {
        loop {
            match &mut self.state {
                State::Opening(job) => {
                    self.state = State::File(ready!(Pin::new(job).poll(cx))??);
                    return Poll::Ready(Ok(()));
                }
                State::Writing(job) => {
                    // The preceding batch was accepted. Only one write can be
                    // in flight, so its result is checked before the next frame.
                    self.state = State::File(ready!(Pin::new(job).poll(cx))??);
                }
                _ => {}
            }
            if data.is_empty() {
                return Poll::Ready(Ok(()));
            }

            if let State::File(mut file) = std::mem::replace(&mut self.state, State::Memory) {
                if data.len() as u64 > self.store.max_bytes().saturating_sub(file.charge.bytes) {
                    return Poll::Ready(Err(BoxError::from_static_str(
                        "HTTP replay body exceeds per-body limit",
                    )));
                }
                file.charge.grow(data.len() as u64)?;
                let batch = self.store.memory_threshold.min(kib(16));
                let frame = if data.len() < batch && data.len() <= batch - file.batch.len() {
                    if file.batch.capacity() == 0 {
                        file.batch.try_reserve_exact(batch)?;
                    }
                    file.batch.extend_from_slice(data);
                    if file.batch.len() < batch {
                        self.state = State::File(file);
                        return Poll::Ready(Ok(()));
                    }
                    Bytes::new()
                } else {
                    data.clone()
                };
                self.state = State::Writing(file.queue_write(frame)?);
                return Poll::Ready(Ok(()));
            }

            let len = self
                .buffered
                .len()
                .checked_add(data.len())
                .filter(|len| *len <= self.store.max_body_bytes)
                .ok_or_else(|| {
                    BoxError::from_static_str("HTTP replay body exceeds per-body limit")
                })?;
            if len <= self.store.memory_threshold {
                return Poll::Ready(self.buffered.push(data).map_err(Into::into));
            }

            let runtime = Handle::try_current().map_err(io::Error::other)?;
            let charge = Charge::new(self.store.storage.clone(), len as u64)?;
            let prefix = std::mem::take(&mut self.buffered).into_bytes();
            let frame = data.clone();
            self.state = State::Opening(runtime.spawn_blocking(move || {
                let mut file = charge.storage.directory.anonymous_file_sync()?;
                file.write_all(&prefix)?;
                ReplayFile::new(file, charge).write(&frame)
            }));
        }
    }

    fn finish(
        self: Box<Self>,
        trailers: Option<HeaderMap>,
    ) -> BoxFuture<'static, Result<Arc<dyn ReplaySource>, BoxError>> {
        Box::pin(async move {
            let mut file = match self.state {
                State::Memory => return Ok(self.buffered.seal(trailers)),
                State::File(file) => file,
                State::Opening(job) | State::Writing(job) => job.await??,
            };
            if !file.batch.is_empty() {
                file = file.queue_write(Bytes::new())?.await??;
            }
            file.batch = Vec::new();
            Ok(Arc::new(FileCursor {
                disk: Arc::new(file),
                offset: 0,
                read: None,
                trailers,
            }) as Arc<dyn ReplaySource>)
        })
    }
}

struct FileCursor {
    disk: Arc<ReplayFile>,
    offset: u64,
    read: Option<JoinHandle<io::Result<Bytes>>>,
    trailers: Option<HeaderMap>,
}

impl FileCursor {
    fn poll_chunk(&mut self, cx: &mut Context<'_>, remaining: u64) -> Poll<io::Result<Bytes>> {
        let read = if let Some(read) = &mut self.read {
            read
        } else {
            let runtime = Handle::try_current().map_err(io::Error::other)?;
            let disk = self.disk.clone();
            let offset = self.offset;
            self.read.insert(runtime.spawn_blocking(move || {
                let mut bytes = vec![0; remaining.min(READ_CHUNK as u64) as usize];
                #[cfg(any(unix, windows))]
                disk.file.read_exact_at(&mut bytes, offset)?;
                #[cfg(not(any(unix, windows)))]
                {
                    // Serialize seek and read only on systems without positioned file reads.
                    let _guard = disk.cursor.lock();
                    let mut file = &disk.file;
                    file.seek(SeekFrom::Start(offset))?;
                    file.read_exact(&mut bytes)?;
                }
                Ok(Bytes::from(bytes))
            }))
        };
        Poll::Ready(ready!(Pin::new(read).poll(cx)).map_err(io::Error::other)?)
    }
}

impl ReplaySource for FileCursor {
    fn clone_cursor(&self) -> Box<dyn ReplaySource> {
        Box::new(Self {
            disk: self.disk.clone(),
            offset: self.offset,
            read: None,
            trailers: self.trailers.clone(),
        })
    }
}

impl StreamingBody for FileCursor {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let remaining = self.disk.charge.bytes - self.offset;
        if remaining == 0 {
            return Poll::Ready(self.trailers.take().map(|t| Ok(Frame::trailers(t))));
        }
        let next = ready!(self.poll_chunk(cx, remaining));
        self.read = None;
        match next {
            Ok(bytes) => {
                self.offset += bytes.len() as u64;
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Err(err) => {
                self.offset = self.disk.charge.bytes;
                self.trailers = None;
                Poll::Ready(Some(Err(err.into())))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.offset == self.disk.charge.bytes && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.disk.charge.bytes - self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::super::append;
    use super::*;
    use crate::body::util::BodyExt as _;
    use rama_core::futures::FutureExt as _;

    fn single_io_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap()
    }

    // Keep Tokio's only blocking I/O thread occupied across a cancellation.
    async fn pause_io() -> tokio::sync::oneshot::Sender<()> {
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            _ = wait.blocking_recv();
        });
        ready.await.unwrap();
        release
    }

    async fn wait_for_cleanup(store: &FsReplayStore) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while store.storage.usage.lock().files != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled I/O should settle and release its reservation");
    }

    #[test]
    fn spill_readers_have_independent_offsets_and_retain_quota() {
        single_io_runtime().block_on(async {
            let parent = TempDir::new().await.unwrap();
            let size = READ_CHUNK * 2 + 1;
            let store = FsReplayStore::in_dir(parent.path()).await.unwrap();
            let mut writer = store.start();
            append(&mut *writer, "ab".into()).await.unwrap();
            assert_eq!(store.storage.usage.lock().files, 0);
            append(&mut *writer, vec![b'x'; size - 2].into())
                .await
                .unwrap();
            let mut trailers = HeaderMap::new();
            trailers.insert("x-check", "ok".parse().unwrap());
            let source = writer.finish(Some(trailers.clone())).await.unwrap();
            let mut cursor = source.clone_cursor();
            drop(source);
            assert_eq!(cursor.size_hint().exact(), Some(size as u64));
            let first = cursor.frame().await.unwrap().unwrap().into_data().unwrap();
            assert_eq!(&first[..2], b"ab");
            let remaining = size - first.len();
            let release = pause_io().await;
            assert!(cursor.frame().now_or_never().is_none());
            let clone = cursor.clone_cursor(); // a pending read has not advanced this cursor
            drop(release);
            assert_eq!(clone.size_hint().exact(), Some(remaining as u64));
            let mut rest = tokio::time::timeout(Duration::from_secs(5), clone.collect())
                .await
                .expect("a parked cursor must not block another reader")
                .unwrap();
            assert_eq!(rest.take_trailers(), Some(trailers.clone()));
            assert_eq!(rest.to_bytes(), vec![b'x'; remaining]);
            assert_eq!(store.storage.usage.lock().bytes, size as u64);
            let mut rest = cursor.collect().await.unwrap();
            assert_eq!(rest.take_trailers(), Some(trailers));
            assert_eq!(rest.to_bytes(), vec![b'x'; remaining]);
            wait_for_cleanup(&store).await;
        });
    }

    #[tokio::test]
    async fn concurrent_spills_share_quota_and_admit_after_reader_drop() {
        let parent = TempDir::new().await.unwrap();
        let store = FsReplayStore::new(parent.path(), 0, 4, 4).await.unwrap();
        let mut first = store.start();
        let mut second = store.clone().start();
        let (a, b) = tokio::join!(
            append(&mut *first, "1234".into()),
            append(&mut *second, "5678".into())
        );
        assert_ne!(a.is_ok(), b.is_ok());
        assert_eq!(store.storage.usage.lock().bytes, 4);
        let source = if a.is_ok() { first } else { second }
            .finish(None)
            .await
            .unwrap();
        let reader = source.clone_cursor();
        drop(source);
        assert!(append(&mut *store.start(), "x".into()).await.is_err());
        drop(reader);
        wait_for_cleanup(&store).await;
        append(&mut *store.start(), "x".into()).await.unwrap();
        wait_for_cleanup(&store).await;
    }

    #[tokio::test]
    async fn simultaneous_uploads_own_separate_files_until_their_last_reader_drops() {
        let parent = TempDir::new().await.unwrap();
        let first = Bytes::from(vec![b'a'; READ_CHUNK + 1]);
        let second = Bytes::from_static(b"second upload");
        let budget = (first.len() + second.len()) as u64;
        let store = FsReplayStore::new(parent.path(), 0, first.len(), budget)
            .await
            .unwrap();
        let capture = async |bytes: Bytes, marker: &'static str| {
            let mut writer = store.start();
            append(&mut *writer, bytes).await.unwrap();
            let mut trailers = HeaderMap::new();
            trailers.insert("x-upload", marker.parse().unwrap());
            writer.finish(Some(trailers)).await.unwrap()
        };
        let (large, small) = tokio::join!(
            capture(first.clone(), "first"),
            capture(second.clone(), "second")
        );
        {
            let usage = store.storage.usage.lock();
            assert_eq!((usage.files, usage.bytes), (2, budget));
        }
        let mut reader = large.clone_cursor();
        drop(large);
        let prefix = reader.frame().await.unwrap().unwrap().into_data().unwrap();
        assert!(!prefix.is_empty() && prefix.len() < first.len());
        assert_eq!(prefix, first.slice(..prefix.len()));
        drop(reader);
        {
            let usage = store.storage.usage.lock();
            assert_eq!((usage.files, usage.bytes), (1, second.len() as u64));
        }
        for _ in 0..2 {
            let reader = small.clone_cursor();
            assert_eq!(reader.size_hint().exact(), Some(second.len() as u64));
            let mut received = reader.collect().await.unwrap();
            assert_eq!(received.take_trailers().unwrap()["x-upload"], "second");
            assert_eq!(received.to_bytes(), second);
        }
        drop(small);
        let usage = store.storage.usage.lock();
        assert_eq!((usage.files, usage.bytes), (0, 0));
    }

    #[tokio::test]
    async fn file_slot_limit_releases_one_slot_per_upload() {
        let parent = TempDir::new().await.unwrap();
        let store = FsReplayStore::new(parent.path(), 0, 8, 1024).await.unwrap();
        let mut uploads = Vec::new();
        for _ in 0..MAX_FILES {
            let mut writer = store.start();
            append(&mut *writer, "a".into()).await.unwrap();
            append(&mut *writer, "b".into()).await.unwrap();
            uploads.push(writer.finish(None).await.unwrap());
        }
        {
            let usage = store.storage.usage.lock();
            assert_eq!(usage.files, MAX_FILES);
            assert_eq!(usage.bytes, (2 * MAX_FILES) as u64);
        }
        assert!(append(&mut *store.start(), "c".into()).await.is_err());
        drop(uploads.pop().unwrap());
        append(&mut *store.start(), "d".into()).await.unwrap();
        drop(uploads);
        wait_for_cleanup(&store).await;
    }

    #[tokio::test]
    async fn small_spilled_frames_are_charged_and_flushed_on_replay() {
        let parent = TempDir::new().await.unwrap();
        let store = FsReplayStore::new(parent.path(), 4, 12, 12).await.unwrap();
        let mut writer = store.start();
        for chunk in ["12345", "", "a", "bc", "d", "ef"] {
            append(&mut *writer, chunk.into()).await.unwrap();
        }
        assert_eq!(store.storage.usage.lock().bytes, 11);
        let mut trailers = HeaderMap::new();
        trailers.insert("x-check", "ok".parse().unwrap());
        let source = writer.finish(Some(trailers.clone())).await.unwrap();
        let mut replay = source.clone_cursor().collect().await.unwrap();
        assert_eq!(replay.take_trailers(), Some(trailers));
        assert_eq!(replay.to_bytes(), "12345abcdef");
        drop(source);
        wait_for_cleanup(&store).await;
    }

    #[test]
    fn cancellation_of_pending_spill_keeps_charge_until_io_finishes() {
        single_io_runtime().block_on(async {
            let parent = TempDir::new().await.unwrap();
            let store = FsReplayStore::new(parent.path(), 1, 16, 16).await.unwrap();
            let mut writer = store.start();
            append(&mut *writer, "a".into()).await.unwrap();
            let release = pause_io().await;
            assert!(append(&mut *writer, "bc".into()).now_or_never().is_none());
            drop(writer);
            assert_eq!(store.storage.usage.lock().bytes, 3);
            drop(release);
            wait_for_cleanup(&store).await;
            assert!(
                tokio::fs::read_dir(store.directory())
                    .await
                    .unwrap()
                    .next_entry()
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn an_accepted_disk_write_can_outlive_the_writer() {
        single_io_runtime().block_on(async {
            let parent = TempDir::new().await.unwrap();
            let store = FsReplayStore::new(parent.path(), 0, 3, 3).await.unwrap();
            let mut writer = store.start();
            append(&mut *writer, "a".into()).await.unwrap();
            let release = pause_io().await;
            // With a zero buffer threshold this append submits a file write.
            // The first attempt may forward the frame before the write runs.
            append(&mut *writer, "bc".into())
                .now_or_never()
                .expect("append should not flush each frame")
                .unwrap();
            drop(writer);
            assert_eq!(store.storage.usage.lock().bytes, 3);
            assert!(
                append(&mut *store.start(), "x".into())
                    .now_or_never()
                    .expect("the outstanding write still holds the full quota")
                    .is_err()
            );
            drop(release);
            wait_for_cleanup(&store).await;
        });
    }

    #[test]
    fn canceling_a_flush_outside_tokio_reclaims_quota_across_runtime_shutdown() {
        let runtime = single_io_runtime();
        let (parent, store, release, seal) = runtime.block_on(async {
            let parent = TempDir::new().await.unwrap();
            let store = FsReplayStore::new(parent.path(), 8, 10, 10).await.unwrap();
            let mut writer = store.start();
            append(&mut *writer, "123456789".into()).await.unwrap();
            let release = pause_io().await;
            // The tail fits in the write buffer even with the only I/O thread
            // busy. A retry must flush it before any reader is available.
            append(&mut *writer, "x".into())
                .now_or_never()
                .unwrap()
                .unwrap();
            let mut seal = writer.finish(None);
            assert!(rama_core::futures::poll!(&mut seal).is_pending());
            (parent, store, release, seal)
        });
        drop(seal);
        assert_eq!(store.storage.usage.lock().bytes, 10);
        runtime.shutdown_background();
        drop(release);
        single_io_runtime().block_on(async move {
            // The outstanding write owns its file and quota even across
            // shutdown. Its completion frees the full budget for another runtime.
            wait_for_cleanup(&store).await;
            let mut writer = store.start();
            append(&mut *writer, "abcdefghij".into()).await.unwrap();
            let replay = writer.finish(None).await.unwrap();
            assert_eq!(
                replay.clone_cursor().collect().await.unwrap().to_bytes(),
                "abcdefghij"
            );
            drop(replay);
            drop(store);
            drop(parent);
        });
    }

    #[test]
    fn dropping_a_pending_replay_read_holds_quota_until_io_finishes() {
        single_io_runtime().block_on(async {
            let parent = TempDir::new().await.unwrap();
            let store = FsReplayStore::new(parent.path(), 0, 8, 8).await.unwrap();
            let mut writer = store.start();
            append(&mut *writer, "12345678".into()).await.unwrap();
            let source = writer.finish(None).await.unwrap();
            let mut cursor = source.clone_cursor();
            drop(source);
            let release = pause_io().await;
            assert!(cursor.frame().now_or_never().is_none());
            drop(cursor);
            assert_eq!(store.storage.usage.lock().bytes, 8);
            drop(release);
            wait_for_cleanup(&store).await;
            append(&mut *store.start(), "12345678".into())
                .await
                .unwrap();
        });
    }

    #[test]
    fn reading_a_spilled_body_outside_tokio_returns_one_error_then_eof() {
        let (_parent, mut reader) = single_io_runtime().block_on(async {
            let parent = TempDir::new().await.unwrap();
            let store = FsReplayStore::new(parent.path(), 0, 8, 8).await.unwrap();
            let mut writer = store.start();
            append(&mut *writer, "data".into()).await.unwrap();
            let mut trailers = HeaderMap::new();
            trailers.insert("x-upload", "finished".parse().unwrap());
            let replay = writer.finish(Some(trailers)).await.unwrap();
            (parent, replay.clone_cursor())
        });
        assert_eq!(reader.size_hint().exact(), Some(4));
        reader.frame().now_or_never().unwrap().unwrap().unwrap_err();
        assert!(reader.is_end_stream());
        assert_eq!(reader.size_hint().exact(), Some(0));
        assert!(reader.frame().now_or_never().unwrap().is_none());
    }

    #[tokio::test]
    async fn a_submitted_write_error_is_reported_on_the_next_append_or_seal() {
        let parent = TempDir::new().await.unwrap();
        let store = FsReplayStore::new(parent.path(), 0, 8, 8).await.unwrap();
        let path = parent.path().join("readonly");
        tokio::fs::write(&path, b"a").await.unwrap();

        for seal in [false, true] {
            // Open read-only to make the actual OS write fail on every platform.
            let file = tokio::fs::File::open(&path).await.unwrap().into_std().await;
            let charge = Charge::new(store.storage.clone(), 1).unwrap();
            let mut writer = Box::new(Writer {
                store: store.clone(),
                buffered: MemoryCapture::default(),
                state: State::File(ReplayFile::new(file, charge)),
            });
            append(&mut *writer, "b".into()).await.unwrap();
            let error = if seal {
                writer
                    .finish(None)
                    .await
                    .expect_err("failed write cannot produce a replay")
            } else {
                let error = append(&mut *writer, "c".into()).await.unwrap_err();
                drop(writer);
                error
            };
            assert!(error.is::<io::Error>());
            wait_for_cleanup(&store).await;
        }
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"a");
    }

    #[tokio::test]
    async fn failed_capture_releases_reservations() {
        let parent = TempDir::new().await.unwrap();
        let store = FsReplayStore::new(parent.path(), 1, 4, 3).await.unwrap();
        let mut writer = store.start();
        append(&mut *writer, "ab".into()).await.unwrap();
        assert!(append(&mut *writer, "cd".into()).await.is_err());
        drop(writer);
        wait_for_cleanup(&store).await;
        tokio::fs::remove_dir(store.directory()).await.unwrap();
        assert!(append(&mut *store.start(), "ab".into()).await.is_err());
        assert_eq!(store.storage.usage.lock().files, 0);
    }
}
