use super::*;
use tokio::sync::Mutex;

/// Bounded memory storage. Open readers keep evicted data and its budget alive.
#[derive(Debug, Clone)]
pub struct MemoryStore {
    limits: StorageLimits,
    budget: Arc<Budget>,
}
impl MemoryStore {
    pub fn new(limits: StorageLimits) -> Self {
        Self {
            limits,
            budget: Budget::new(limits.total_bytes),
        }
    }
}
impl Service<CreateCollection> for MemoryStore {
    type Output = Collection;
    type Error = BoxError;
    async fn serve(&self, _: CreateCollection) -> Result<Collection, BoxError> {
        Ok(Collection::new(MemoryCollection(Arc::new(MemoryInner {
            records: parking_lot::RwLock::new(Vec::new()),
            append_lock: Mutex::new(()),
            limit: self.limits.record_bytes,
            budget: self.budget.clone(),
        }))))
    }
}
struct Blob {
    bytes: Bytes,
    _reservations: Vec<Reservation>,
}
struct MemoryInner {
    records: parking_lot::RwLock<Vec<Arc<Blob>>>,
    append_lock: Mutex<()>,
    limit: u64,
    budget: Arc<Budget>,
}
#[derive(Clone)]
struct MemoryCollection(Arc<MemoryInner>);
impl Service<AppendRecord> for MemoryCollection {
    type Output = RecordId;
    type Error = BoxError;
    async fn serve(&self, mut input: AppendRecord) -> Result<RecordId, BoxError> {
        // Match file storage's per-collection serialization and cancellation boundary.
        let _append = self.0.append_lock.lock().await;
        let mut data = Vec::new();
        let mut reservations = Vec::new();
        let mut buffer = [0u8; rama_utils::octets::kib(16)];
        loop {
            let count = input.source.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            check_record_limit(data.len() as u64 + count as u64, self.0.limit)?;
            reservations.push(self.0.budget.reserve(count as u64)?);
            data.extend_from_slice(&buffer[..count]);
        }
        let mut records = self.0.records.write();
        let id = RecordId(records.len() as u64);
        records.push(Arc::new(Blob {
            bytes: Bytes::from(data),
            _reservations: reservations,
        }));
        Ok(id)
    }
}
impl Service<ReadRecord> for MemoryCollection {
    type Output = Reader;
    type Error = BoxError;
    async fn serve(&self, input: ReadRecord) -> Result<Reader, BoxError> {
        let record = self
            .0
            .records
            .read()
            .get(usize::try_from(input.id.0)?)
            .cloned()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "capture record not found")
            })?;
        let reader = OwnedReader {
            reader: std::io::Cursor::new(record.bytes.clone()),
            _owner: record,
        };
        range_reader(Box::pin(reader), input.range).await
    }
}
impl Service<ListRecords> for MemoryCollection {
    type Output = Vec<RecordId>;
    type Error = BoxError;
    async fn serve(&self, _: ListRecords) -> Result<Vec<RecordId>, BoxError> {
        Ok((0..self.0.records.read().len() as u64)
            .map(RecordId)
            .collect())
    }
}
