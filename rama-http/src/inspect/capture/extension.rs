//! Typed attachment records for protocols carried by an HTTP upgrade.
use super::*;
use serde::de::DeserializeOwned;
use std::{any::TypeId, ops::Range};

/// A protocol-owned record stored alongside an HTTP exchange. Each Rust type has
/// an independent index; HTTP never decodes another protocol's record as its own.
pub(super) struct RecordIndex {
    pub ids: Vec<RecordId>,
    pub matches: fn(&[u8], &str) -> bool,
}
impl RecordIndex {
    fn new<T: CapturedRecord>() -> Self {
        Self {
            ids: Vec::new(),
            matches: |data, needle| {
                serde_json::from_slice::<T>(data).is_ok_and(|record| record.matches_search(needle))
            },
        }
    }
}

pub trait CapturedRecord: Serialize + DeserializeOwned + Send + Sync + 'static {
    fn matches_search(&self, needle: &str) -> bool;
}

/// Pins an exchange, its observations and storage while an adapter or reader uses it.
#[derive(Clone)]
pub struct ExchangeCapture {
    pub(super) store: CaptureStore,
    pub(super) entry: Arc<CapturedExchange>,
}
impl fmt::Debug for ExchangeCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeCapture")
            .field("id", &self.entry.summary_template.id)
            .finish_non_exhaustive()
    }
}
impl CaptureStore {
    pub fn exchange_capture(&self, id: u64) -> Result<ExchangeCapture, BoxError> {
        Ok(ExchangeCapture {
            entry: self.exchange(id)?,
            store: self.clone(),
        })
    }
}
impl ExchangeCapture {
    /// Read HTTP metadata without loading bodies, retaining this exchange across clears.
    pub async fn inspector_details(&self) -> Result<CaptureDetails, BoxError> {
        self.store.inspector_details_for_entry(&self.entry).await
    }

    pub async fn details(&self) -> Result<CaptureDetails, BoxError> {
        self.store.details_for_entry(self.entry.clone()).await
    }
    pub fn id(&self) -> u64 {
        self.entry.summary_template.id
    }
    pub fn metadata(&self) -> &CaptureMetadata {
        &self.entry.metadata
    }
    pub fn inspection_state(&self) -> InspectionState {
        self.store.inspection_state()
    }
    pub fn snapshot(&self) -> HttpExchangeSummary {
        self.entry.snapshot()
    }
    pub fn state<T: Extension + Default>(&self) -> Arc<T> {
        // Serialize first registration; Extensions themselves are append-only.
        let _registration = self.entry.extension_records.write();
        self.entry
            .extensions
            .get_arc_or_insert(|| Arc::new(T::default()))
    }
    pub fn changed(&self) {
        self.store.changed();
    }
    pub fn set_active(&self) {
        self.entry.active.store(true, Ordering::Release);
        self.changed();
    }
    pub fn mark_truncated(&self) {
        self.entry.request_truncated.store(true, Ordering::Release);
        self.entry.response_truncated.store(true, Ordering::Release);
        self.changed();
    }
    pub fn record_bytes(&self, direction: CapturedBody, length: u64) {
        let (exchange, connection) = match direction {
            CapturedBody::Request => (
                &self.entry.request_bytes,
                self.entry.connection.as_ref().map(|c| &c.bytes_in),
            ),
            CapturedBody::Response => (
                &self.entry.response_bytes,
                self.entry.connection.as_ref().map(|c| &c.bytes_out),
            ),
        };
        saturating_add(exchange, length);
        if let Some(counter) = connection {
            saturating_add(counter, length);
        }
    }
    pub fn reserve_body(&self, direction: CapturedBody, length: u64) -> bool {
        let counter = match direction {
            CapturedBody::Request => &self.entry.request_stored,
            CapturedBody::Response => &self.entry.response_stored,
        };
        reserve_capture_bytes(counter, self.store.0.body_limit, length)
    }
    pub fn count<T: CapturedRecord>(&self) -> usize {
        self.entry
            .extension_records
            .read()
            .get(&TypeId::of::<T>())
            .map_or(0, |index| index.ids.len())
    }
    pub async fn append<T: CapturedRecord>(&self, record: &T) -> Result<bool, BoxError> {
        let data = serde_json::to_vec(record)?;
        let Some(mut budget) = self.store.0.budget.try_reserve(data.len() as u64) else {
            return Ok(false);
        };
        let _append = self.entry.append_lock.lock().await;
        let id = self
            .entry
            .collection
            .serve(AppendRecord::bytes(Bytes::from(data)))
            .await?;
        self.entry
            .extension_records
            .write()
            .entry(TypeId::of::<T>())
            .or_insert_with(RecordIndex::new::<T>)
            .ids
            .push(id);
        budget.commit(&self.entry);
        self.entry.search_revision.fetch_add(1, Ordering::Release);
        self.changed();
        Ok(true)
    }
    /// Read one protocol-owned record without allocating an index or result vector.
    pub async fn record<T: CapturedRecord>(&self, index: usize) -> Result<Option<T>, BoxError> {
        let id = self
            .entry
            .extension_records
            .read()
            .get(&TypeId::of::<T>())
            .and_then(|records| records.ids.get(index))
            .copied();
        let Some(id) = id else {
            return Ok(None);
        };
        let mut reader = self.entry.collection.read(id).await?;
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await?;
        Ok(Some(serde_json::from_slice(&data)?))
    }
    pub async fn records<T: CapturedRecord>(
        &self,
        range: Range<usize>,
    ) -> Result<Vec<T>, BoxError> {
        let ids = {
            let indexes = self.entry.extension_records.read();
            let Some(index) = indexes.get(&TypeId::of::<T>()) else {
                return Ok(Vec::new());
            };
            let index = &index.ids;
            index[range.start.min(index.len())
                ..range.end.min(index.len()).max(range.start.min(index.len()))]
                .to_vec()
        };
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            let mut reader = self.entry.collection.read(id).await?;
            let mut data = Vec::new();
            reader.read_to_end(&mut data).await?;
            records.push(serde_json::from_slice(&data)?);
        }
        Ok(records)
    }
}
