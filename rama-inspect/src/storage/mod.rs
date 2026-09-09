//! Streaming record storage. Logical identifiers never expose filesystem offsets.
//!
//! An append publishes exactly one complete record. Dropping its future may leave
//! backend work in flight, but it must not publish a partial record or damage a
//! previous record. A backend must recover before accepting the next append.
//! These are visibility guarantees, not promises of crash durability.

use std::{
    fmt,
    ops::Range,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use rama_core::{Service, bytes::Bytes, error::BoxError, service::BoxService};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

mod memory;
pub use memory::MemoryStore;
mod file;
pub use file::FileStore;

/// An owned reader, suitable for streaming to a response, file, or native UI.
pub type Reader = Pin<Box<dyn AsyncRead + Send + 'static>>;

/// Logical record identifier within a collection. Never a byte offset.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct RecordId(pub u64);

/// Create a collection with an application-assigned, instance-unique identifier.
#[derive(Debug, Clone, Copy)]
pub struct CreateCollection {
    pub id: u64,
}

/// Append an owned stream. Success publishes the record; cancellation aborts it.
pub enum AppendRecord {
    /// An already owned record; memory storage retains these bytes without copying.
    Bytes(Bytes),
    /// A streaming source, read with backpressure and bounded scratch space.
    Stream(Reader),
}

impl fmt::Debug for AppendRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppendRecord").finish_non_exhaustive()
    }
}

impl AppendRecord {
    pub fn new(source: impl AsyncRead + Send + 'static) -> Self {
        Self::Stream(Box::pin(source))
    }

    pub fn bytes(bytes: Bytes) -> Self {
        Self::Bytes(bytes)
    }

    pub fn into_reader(self) -> Reader {
        match self {
            Self::Bytes(bytes) => Box::pin(std::io::Cursor::new(bytes)),
            Self::Stream(reader) => reader,
        }
    }
}

/// Read a committed record or a range of its logical bytes. The end is exclusive;
/// bounds beyond EOF clamp to the record length, and reversed ranges are rejected.
/// Memory and file storage address ranges directly. Streaming layers such as
/// encryption may need to consume the preceding bytes; see the layer's contract.
#[derive(Debug, Clone)]
pub struct ReadRecord {
    pub id: RecordId,
    pub range: Option<Range<u64>>,
}

impl ReadRecord {
    pub fn new(id: RecordId) -> Self {
        Self { id, range: None }
    }
}

/// Snapshot the identifiers of currently committed records.
#[derive(Debug, Clone, Copy)]
pub struct ListRecords;

/// Storage admission limits, shared across collections. Defaults bound retained
/// bytes to 64 MiB and each record to 8 MiB. Explicit zero fields mean unlimited.
/// Counts logical record bytes, not backing-allocation capacity or index memory;
/// protocol adapters should also bound their retained record count.
#[derive(Debug, Clone, Copy)]
pub struct StorageLimits {
    pub total_bytes: u64,
    pub record_bytes: u64,
}

impl Default for StorageLimits {
    fn default() -> Self {
        Self {
            total_bytes: rama_utils::octets::mib_u64(64),
            record_bytes: rama_utils::octets::mib_u64(8),
        }
    }
}

// Bound admitted I/O and scratch use without serializing unrelated operations.
const MAX_CONCURRENT_APPENDS: usize = 64;

/// An owned collection. Dropping its last capability or reader releases its storage.
/// Read handles pin their underlying data independently of registry eviction.
#[derive(Debug, Clone)]
pub struct Collection {
    reader: CollectionReader,
    writer: CollectionWriter,
}

/// Read-only access to a collection, independent of append serialization.
/// Both this handle and its readers retain the underlying storage.
#[derive(Debug, Clone)]
pub struct CollectionReader {
    read: BoxService<ReadRecord, Reader, BoxError>,
    list: BoxService<ListRecords, Vec<RecordId>, BoxError>,
}

/// Append access to a collection. Keep this capability behind a lock when
/// publication of application indexes must remain ordered with storage writes.
#[derive(Debug, Clone)]
pub struct CollectionWriter {
    append: BoxService<AppendRecord, RecordId, BoxError>,
}

impl Collection {
    /// Adapt a custom backend using Rama services. No filesystem or crypto required.
    pub fn new<S>(service: S) -> Self
    where
        S: Clone
            + Service<AppendRecord, Output = RecordId, Error = BoxError>
            + Service<ReadRecord, Output = Reader, Error = BoxError>
            + Service<ListRecords, Output = Vec<RecordId>, Error = BoxError>,
    {
        Self {
            writer: CollectionWriter {
                append: BoxService::new(service.clone()),
            },
            reader: CollectionReader {
                read: BoxService::new(service.clone()),
                list: BoxService::new(service),
            },
        }
    }

    /// Separate read and append capabilities without allocating or cloning services.
    pub fn split(self) -> (CollectionReader, CollectionWriter) {
        (self.reader, self.writer)
    }

    pub async fn append(
        &self,
        source: impl AsyncRead + Send + 'static,
    ) -> Result<RecordId, BoxError> {
        self.serve(AppendRecord::new(source)).await
    }

    pub async fn read(&self, id: RecordId) -> Result<Reader, BoxError> {
        self.serve(ReadRecord::new(id)).await
    }

    pub async fn snapshot(&self) -> Result<Vec<RecordId>, BoxError> {
        self.serve(ListRecords).await
    }
}

impl CollectionReader {
    pub async fn read(&self, id: RecordId) -> Result<Reader, BoxError> {
        self.serve(ReadRecord::new(id)).await
    }

    pub async fn snapshot(&self) -> Result<Vec<RecordId>, BoxError> {
        self.serve(ListRecords).await
    }
}

impl CollectionWriter {
    pub async fn append(
        &self,
        source: impl AsyncRead + Send + 'static,
    ) -> Result<RecordId, BoxError> {
        self.serve(AppendRecord::new(source)).await
    }
}

impl Service<AppendRecord> for Collection {
    type Output = RecordId;
    type Error = BoxError;

    async fn serve(&self, input: AppendRecord) -> Result<Self::Output, Self::Error> {
        self.writer.serve(input).await
    }
}

impl Service<ReadRecord> for Collection {
    type Output = Reader;
    type Error = BoxError;

    async fn serve(&self, input: ReadRecord) -> Result<Self::Output, Self::Error> {
        self.reader.serve(input).await
    }
}

impl Service<ListRecords> for Collection {
    type Output = Vec<RecordId>;
    type Error = BoxError;

    async fn serve(&self, input: ListRecords) -> Result<Self::Output, Self::Error> {
        self.reader.serve(input).await
    }
}

impl Service<AppendRecord> for CollectionWriter {
    type Output = RecordId;
    type Error = BoxError;

    async fn serve(&self, input: AppendRecord) -> Result<Self::Output, Self::Error> {
        self.append.serve(input).await
    }
}

impl Service<ReadRecord> for CollectionReader {
    type Output = Reader;
    type Error = BoxError;

    async fn serve(&self, input: ReadRecord) -> Result<Self::Output, Self::Error> {
        self.read.serve(input).await
    }
}

impl Service<ListRecords> for CollectionReader {
    type Output = Vec<RecordId>;
    type Error = BoxError;

    async fn serve(&self, input: ListRecords) -> Result<Self::Output, Self::Error> {
        self.list.serve(input).await
    }
}

/// Erase the storage implementation only at the composition boundary.
pub type Storage = BoxService<CreateCollection, Collection, BoxError>;

#[derive(Debug)]
struct Budget {
    limit: u64,
    used: AtomicU64,
}

impl Budget {
    fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicU64::new(0),
        })
    }

    fn reserve(self: &Arc<Self>, amount: u64) -> Result<Reservation, BoxError> {
        self.add(amount)?;
        Ok(Reservation {
            budget: self.clone(),
            amount,
        })
    }

    fn add(&self, amount: u64) -> Result<(), BoxError> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                let next = used.checked_add(amount)?;
                (self.limit == 0 || next <= self.limit).then_some(next)
            })
            .map_err(|_used| std::io::Error::other("capture storage budget exhausted"))?;
        Ok(())
    }
}

struct Reservation {
    budget: Arc<Budget>,
    amount: u64,
}

impl Reservation {
    fn grow(&mut self, amount: u64) -> Result<(), BoxError> {
        self.budget.add(amount)?;
        self.amount += amount;
        Ok(())
    }

    fn absorb(&mut self, other: &mut Self) {
        debug_assert!(Arc::ptr_eq(&self.budget, &other.budget));
        self.amount += std::mem::take(&mut other.amount);
    }

    fn clear(&mut self) {
        self.budget
            .used
            .fetch_sub(std::mem::take(&mut self.amount), Ordering::AcqRel);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.amount, Ordering::AcqRel);
    }
}

struct OwnedReader<R, O> {
    reader: R,
    _owner: Arc<O>,
}

impl<R: AsyncRead + Unpin, O> AsyncRead for OwnedReader<R, O> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

fn record_range(range: Option<Range<u64>>, length: u64) -> Result<Range<u64>, BoxError> {
    match range {
        None => Ok(0..length),
        Some(range) if range.start <= range.end => {
            Ok(range.start.min(length)..range.end.min(length))
        }
        Some(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid record range",
        )
        .into()),
    }
}

/// Select a range from a streaming reader without buffering its contents.
/// A non-zero start consumes the prefix; seekable backends should address it directly.
/// Bounds beyond EOF clamp to the content length; errors while reading the prefix
/// still propagate, including errors from an authenticating storage layer.
pub async fn range_reader(
    mut reader: Reader,
    range: Option<Range<u64>>,
) -> Result<Reader, BoxError> {
    match range {
        None => Ok(reader),
        Some(range) if range.start <= range.end => {
            tokio::io::copy(&mut (&mut reader).take(range.start), &mut tokio::io::sink()).await?;
            Ok(Box::pin(reader.take(range.end - range.start)))
        }
        Some(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid record range",
        )
        .into()),
    }
}

fn check_record_limit(length: u64, limit: u64) -> Result<(), BoxError> {
    if limit != 0 && length > limit {
        return Err(std::io::Error::other("capture record limit exceeded").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
