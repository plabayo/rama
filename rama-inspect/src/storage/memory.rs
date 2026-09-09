use tokio::sync::Semaphore;

use super::*;

/// Bounded memory storage. Open readers keep evicted data and its budget alive.
#[derive(Debug, Clone)]
pub struct MemoryStore {
    limits: StorageLimits,
    budget: Arc<Budget>,
    appends: Arc<Semaphore>,
}

impl MemoryStore {
    pub fn new(limits: StorageLimits) -> Self {
        Self {
            limits,
            budget: Budget::new(limits.total_bytes),
            appends: Arc::new(Semaphore::new(MAX_CONCURRENT_APPENDS)),
        }
    }
}

impl Service<CreateCollection> for MemoryStore {
    type Output = Collection;
    type Error = BoxError;

    async fn serve(&self, _: CreateCollection) -> Result<Collection, BoxError> {
        Ok(Collection::new(MemoryCollection(Arc::new(MemoryInner {
            records: parking_lot::RwLock::new(Vec::new()),
            limit: self.limits.record_bytes,
            budget: self.budget.clone(),
            appends: self.appends.clone(),
        }))))
    }
}

struct Blob {
    bytes: Bytes,
    _reservation: Reservation,
}

struct MemoryInner {
    records: parking_lot::RwLock<Vec<Arc<Blob>>>,
    limit: u64,
    budget: Arc<Budget>,
    appends: Arc<Semaphore>,
}

#[derive(Clone)]
struct MemoryCollection(Arc<MemoryInner>);

impl Service<AppendRecord> for MemoryCollection {
    type Output = RecordId;
    type Error = BoxError;

    async fn serve(&self, input: AppendRecord) -> Result<RecordId, BoxError> {
        let (bytes, reservation) = match input {
            AppendRecord::Bytes(bytes) => {
                check_record_limit(bytes.len() as u64, self.0.limit)?;
                let reservation = self.0.budget.reserve(bytes.len() as u64)?;
                (bytes, reservation)
            }
            AppendRecord::Stream(mut source) => {
                let _permit = self.0.appends.acquire().await?;
                let mut data = Vec::new();
                let mut reservation = self.0.budget.reserve(0)?;
                let mut buffer = vec![0u8; rama_utils::octets::kib(16)];
                loop {
                    let count = source.read(&mut buffer).await?;
                    if count == 0 {
                        break;
                    }
                    let length = (data.len() as u64)
                        .checked_add(count as u64)
                        .ok_or_else(|| std::io::Error::other("capture length overflow"))?;
                    check_record_limit(length, self.0.limit)?;
                    reservation.grow(count as u64)?;
                    data.extend_from_slice(&buffer[..count]);
                }
                (Bytes::from(data), reservation)
            }
        };
        let mut records = self.0.records.write();
        let id = RecordId(records.len() as u64);
        records.push(Arc::new(Blob {
            bytes,
            _reservation: reservation,
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
            .get(usize::try_from(input.id.0).unwrap_or(usize::MAX))
            .cloned()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "capture record not found")
            })?;
        let range = record_range(input.range, record.bytes.len() as u64)?;
        Ok(Box::pin(OwnedReader {
            reader: std::io::Cursor::new(
                record.bytes.slice(range.start as usize..range.end as usize),
            ),
            _owner: record,
        }))
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
