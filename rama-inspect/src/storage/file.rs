use super::*;
use rama_utils::fs::{
    CreatedFilePermissions, OpenOptions, OpenOptionsSync, TempDir, TempPath, TempPathCleanup,
};
use tokio::{
    fs::File,
    io::{AsyncSeekExt, AsyncWriteExt},
    sync::Mutex,
};

/// Temporary filesystem storage, using Rama's private-directory and cleanup helpers.
/// Each collection has its own file and append lock. There is no global I/O lock.
#[derive(Debug, Clone)]
pub struct FileStore {
    inner: Arc<Factory>,
}
#[derive(Debug)]
struct Factory {
    limits: StorageLimits,
    budget: Arc<Budget>,
    cleanup: TempPathCleanup,
    directory: TempDir,
}
impl FileStore {
    pub fn temporary(limits: StorageLimits) -> Result<Self, BoxError> {
        let directory = TempDir::with_prefix("rama-inspect-")?;
        let (cleanup, worker) = TempPathCleanup::new();
        rama_core::rt::spawn(worker.run());
        Ok(Self {
            inner: Arc::new(Factory {
                limits,
                budget: Budget::new(limits.total_bytes),
                cleanup,
                directory,
            }),
        })
    }
    /// Implementation-specific diagnostic, deliberately absent from storage contracts.
    pub fn directory(&self) -> &std::path::Path {
        self.inner.directory.path()
    }
    pub async fn flush_cleanup(&self) {
        self.inner.cleanup.flush().await;
    }
}
impl Service<CreateCollection> for FileStore {
    type Output = Collection;
    type Error = BoxError;
    async fn serve(&self, input: CreateCollection) -> Result<Collection, BoxError> {
        let factory = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let name = format!("collection-{}.capture", input.id);
            let file = OpenOptionsSync::new()
                .read(true)
                .write(true)
                .create_new(true)
                .jail(factory.directory.path())
                .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
                .open(&name)?;
            let path = TempPath::new(factory.directory.path().join(name), factory.cleanup.clone());
            Ok::<_, BoxError>(Collection::new(FileCollection(Arc::new(FileInner {
                state: Mutex::new(State {
                    file: File::from_std(file),
                    committed: 0,
                    recovery: false,
                    reservations: Vec::new(),
                    pending_reservations: Vec::new(),
                }),
                records: parking_lot::RwLock::new(Vec::new()),
                path,
                factory,
            }))))
        })
        .await?
    }
}
struct State {
    file: File,
    committed: u64,
    recovery: bool,
    reservations: Vec<Reservation>,
    // Failed/cancelled tails still occupy disk until recovery or collection drop.
    pending_reservations: Vec<Reservation>,
}
struct FileInner {
    state: Mutex<State>,
    records: parking_lot::RwLock<Vec<(u64, u64)>>,
    path: TempPath,
    factory: Arc<Factory>,
}
#[derive(Clone)]
struct FileCollection(Arc<FileInner>);
impl Service<AppendRecord> for FileCollection {
    type Output = RecordId;
    type Error = BoxError;
    async fn serve(&self, mut input: AppendRecord) -> Result<RecordId, BoxError> {
        let mut state = self.0.state.lock().await;
        let start = state.committed;
        if state.recovery {
            // Tokio filesystem work can outlive the cancelled future. Settle it
            // before truncation, and keep the flag set if recovery is cancelled.
            state.file.flush().await?;
            state.file.set_len(start).await?;
            state.file.seek(std::io::SeekFrom::Start(start)).await?;
            state.pending_reservations.clear();
            state.recovery = false;
        }
        state.recovery = true;
        let mut length = 0u64;
        let mut buffer = [0u8; rama_utils::octets::kib(16)];
        loop {
            let count = input.source.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            length = length
                .checked_add(count as u64)
                .ok_or_else(|| std::io::Error::other("capture length overflow"))?;
            check_record_limit(length, self.0.factory.limits.record_bytes)?;
            state
                .pending_reservations
                .push(self.0.factory.budget.reserve(count as u64)?);
            state.file.write_all(&buffer[..count]).await?;
        }
        state.file.flush().await?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| std::io::Error::other("capture length overflow"))?;
        let mut records = self.0.records.write();
        let id = RecordId(records.len() as u64);
        // No await between successful completion and publication/accounting.
        records.push((start, length));
        state.committed = end;
        let reservations = std::mem::take(&mut state.pending_reservations);
        state.reservations.extend(reservations);
        state.recovery = false;
        Ok(id)
    }
}
impl Service<ReadRecord> for FileCollection {
    type Output = Reader;
    type Error = BoxError;
    async fn serve(&self, input: ReadRecord) -> Result<Reader, BoxError> {
        let (offset, length) = self
            .0
            .records
            .read()
            .get(usize::try_from(input.id.0)?)
            .copied()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "capture record not found")
            })?;
        let mut file = OpenOptions::new()
            .read(true)
            .jail(self.0.factory.directory.path())
            .open(
                self.0
                    .path
                    .as_ref()
                    .file_name()
                    .ok_or_else(|| std::io::Error::other("invalid capture filename"))?,
            )
            .await?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let reader = OwnedReader {
            reader: file.take(length),
            _owner: self.0.clone(),
        };
        range_reader(Box::pin(reader), input.range).await
    }
}
impl Service<ListRecords> for FileCollection {
    type Output = Vec<RecordId>;
    type Error = BoxError;
    async fn serve(&self, _: ListRecords) -> Result<Vec<RecordId>, BoxError> {
        Ok((0..self.0.records.read().len() as u64)
            .map(RecordId)
            .collect())
    }
}
