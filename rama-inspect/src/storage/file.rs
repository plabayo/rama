use super::*;
use rama_utils::fs::{
    CreatedFilePermissions, OpenOptions, OpenOptionsSync, TempDir, TempPath, TempPathCleanup,
};
use tokio::{
    fs::File,
    io::{AsyncSeekExt, AsyncWriteExt},
    sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore},
};

/// Temporary filesystem storage, using Rama's private-directory and cleanup helpers.
/// Each collection has its own file and append lock. Idle committed collections
/// keep no file descriptor. At most 64 appends perform I/O concurrently; reads pin
/// independent descriptors. Cancelled appends settle and release their descriptor
/// in a background recovery task, retaining their admission permit until then.
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
    appends: Arc<Semaphore>,
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
                appends: Arc::new(Semaphore::new(MAX_CONCURRENT_APPENDS)),
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
            drop(file);
            let path = TempPath::new(factory.directory.path().join(name), factory.cleanup.clone());
            Ok::<_, BoxError>(Collection::new(FileCollection(Arc::new(FileInner {
                state: Arc::new(Mutex::new(State {
                    file: None,
                    committed: 0,
                    recovery: false,
                    reservation: factory.budget.reserve(0)?,
                    pending_reservation: factory.budget.reserve(0)?,
                })),
                records: parking_lot::RwLock::new(Vec::new()),
                path,
                factory,
            }))))
        })
        .await?
    }
}
struct State {
    // Only active or unsettled appends retain a descriptor. A cancelled Tokio
    // operation must be settled on this same handle before recovery can truncate.
    file: Option<File>,
    committed: u64,
    recovery: bool,
    reservation: Reservation,
    // Failed/cancelled tails still occupy disk until recovery or collection drop.
    pending_reservation: Reservation,
}
impl State {
    fn writer(&mut self) -> std::io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("capture writer is not open"))
    }
}
struct FileInner {
    state: Arc<Mutex<State>>,
    records: parking_lot::RwLock<Vec<(u64, u64)>>,
    path: TempPath,
    factory: Arc<Factory>,
}
// Own the lock and admission permit across recovery even if the append future is
// dropped. The next append cannot race a Tokio filesystem operation left in flight.
struct ActiveAppend {
    state: Option<OwnedMutexGuard<State>>,
    permit: Option<OwnedSemaphorePermit>,
    owner: Arc<FileInner>,
}
impl Drop for ActiveAppend {
    fn drop(&mut self) {
        let Some(mut state) = self.state.take() else {
            return;
        };
        if state.file.is_none() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            // Outside a runtime retain the original handle for the next append to
            // settle; reopening another handle must never race an unfinished write.
            return;
        };
        let permit = self.permit.take();
        let owner = self.owner.clone();
        runtime.spawn(async move {
            let start = state.committed;
            let recovered: Result<(), std::io::Error> = async {
                state.writer()?.flush().await?;
                state.writer()?.set_len(start).await?;
                Ok(())
            }
            .await;
            if recovered.is_ok() {
                state.pending_reservation.clear();
                state.recovery = false;
            }
            // Any failed operation has settled as well. A failed truncate leaves
            // recovery set, so a later append retries before touching the tail.
            state.file = None;
            drop((state, permit, owner));
        });
    }
}
#[derive(Clone)]
struct FileCollection(Arc<FileInner>);
impl Service<AppendRecord> for FileCollection {
    type Output = RecordId;
    type Error = BoxError;
    async fn serve(&self, input: AppendRecord) -> Result<RecordId, BoxError> {
        let state = self.0.state.clone().lock_owned().await;
        let permit = self.0.factory.appends.clone().acquire_owned().await?;
        let mut append = ActiveAppend {
            state: Some(state),
            permit: Some(permit),
            owner: self.0.clone(),
        };
        let state = append
            .state
            .as_deref_mut()
            .ok_or_else(|| std::io::Error::other("capture append state missing"))?;
        let start = state.committed;
        if state.file.is_none() {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .jail(self.0.factory.directory.path())
                .open(
                    self.0
                        .path
                        .as_ref()
                        .file_name()
                        .ok_or_else(|| std::io::Error::other("invalid capture filename"))?,
                )
                .await?;
            file.seek(std::io::SeekFrom::Start(start)).await?;
            state.file = Some(file);
        }
        if state.recovery {
            // Tokio filesystem work can outlive the cancelled future. Settle it
            // before truncation, and keep the flag set if recovery is cancelled.
            state.writer()?.flush().await?;
            state.writer()?.set_len(start).await?;
            state
                .writer()?
                .seek(std::io::SeekFrom::Start(start))
                .await?;
            state.pending_reservation.clear();
            state.recovery = false;
        }
        state.recovery = true;
        let length = match input {
            AppendRecord::Bytes(bytes) => {
                check_record_limit(bytes.len() as u64, self.0.factory.limits.record_bytes)?;
                state.pending_reservation.grow(bytes.len() as u64)?;
                state.writer()?.write_all(&bytes).await?;
                bytes.len() as u64
            }
            AppendRecord::Stream(mut source) => {
                let mut length = 0u64;
                let mut buffer = vec![0u8; rama_utils::octets::kib(16)];
                loop {
                    let count = source.read(&mut buffer).await?;
                    if count == 0 {
                        break;
                    }
                    length = length
                        .checked_add(count as u64)
                        .ok_or_else(|| std::io::Error::other("capture length overflow"))?;
                    check_record_limit(length, self.0.factory.limits.record_bytes)?;
                    state.pending_reservation.grow(count as u64)?;
                    state.writer()?.write_all(&buffer[..count]).await?;
                }
                length
            }
        };
        state.writer()?.flush().await?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| std::io::Error::other("capture length overflow"))?;
        let mut records = self.0.records.write();
        let id = RecordId(records.len() as u64);
        // No await between successful completion and publication/accounting.
        records.push((start, length));
        state.committed = end;
        let State {
            reservation,
            pending_reservation,
            ..
        } = &mut *state;
        reservation.absorb(pending_reservation);
        state.recovery = false;
        state.file = None;
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
            .get(usize::try_from(input.id.0).unwrap_or(usize::MAX))
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
        let range = record_range(input.range, length)?;
        file.seek(std::io::SeekFrom::Start(offset + range.start))
            .await?;
        Ok(Box::pin(OwnedReader {
            reader: file.take(range.end - range.start),
            _owner: self.0.clone(),
        }))
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
