//! Typed attachment records for protocols carried by an HTTP upgrade.

use std::{any::TypeId, ops::Range};

use super::*;

/// A protocol-owned record stored alongside an HTTP exchange. Each Rust type has
/// an independent index; HTTP never decodes another protocol's record as its own.
pub(super) struct RecordIndex {
    pub ids: Vec<RecordId>,
    pub matches: super::attachment::SearchRecord,
}

impl RecordIndex {
    fn new<T: CapturedRecord>() -> Self {
        Self {
            ids: Vec::new(),
            matches: super::attachment::search::<T>,
        }
    }
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
    /// Snapshot summary and observations without reading stored metadata records.
    pub fn summary_details(&self) -> CaptureDetails {
        CaptureDetails {
            summary: self.entry.snapshot(),
            records: Vec::new(),
            metadata: self.entry.metadata.clone(),
            connection: self
                .entry
                .connection
                .as_ref()
                .map(|connection| connection.snapshot()),
        }
    }

    /// Read bounded HTTP metadata without body or interception payload bytes.
    /// Upgraded message history is paged separately with `message_interceptions`.
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
        let (source, length) = super::attachment::encode(record)?;
        let Some(mut budget) = self.store.0.budget.try_reserve(length) else {
            return Ok(false);
        };
        let writer = self.entry.writer.lock().await;
        let id = writer.serve(source).await?;
        self.entry
            .extension_records
            .write()
            .entry(TypeId::of::<T>())
            .or_insert_with(RecordIndex::new::<T>)
            .ids
            .push(id);
        budget.commit(&self.entry);
        self.changed();
        Ok(true)
    }

    /// Read typed metadata and stream the payload without materializing it.
    pub async fn record_stream<T: CapturedRecord>(
        &self,
        index: usize,
    ) -> Result<Option<CapturedRecordStream<T::Metadata>>, BoxError> {
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
        super::attachment::read(Box::pin(attachment::PinnedRecordReader {
            reader: self.entry.collection.read(id).await?,
            _entry: self.entry.clone(),
        }))
        .await
        .map(Some)
    }

    /// Explicitly read one owned record. Prefer `record_stream` for large payloads.
    pub async fn record<T: CapturedRecord>(&self, index: usize) -> Result<Option<T>, BoxError> {
        match self.record_stream::<T>(index).await? {
            Some(record) => record.into_record::<T>().await.map(Some),
            None => Ok(None),
        }
    }

    pub async fn records<T: CapturedRecord>(
        &self,
        range: Range<usize>,
    ) -> Result<Vec<T>, BoxError> {
        let end = range.end.min(self.count::<T>());
        let mut records = Vec::new();
        for index in range.start.min(end)..end {
            if let Some(record) = self.record::<T>(index).await? {
                records.push(record);
            }
        }
        Ok(records)
    }
}
