//! HTTP record heads remain bounded; interception payloads stream independently.

use rama_utils::octets::kib_u64;

use super::*;

pub(super) const MAX_HTTP_RECORDS: usize = 32;

pub(super) fn is_http_metadata(record: &StoredRecord) -> bool {
    match record {
        StoredRecord::Interception { kind, .. } => kind.is_none(),
        StoredRecord::RequestBody { .. }
        | StoredRecord::ResponseBody { .. }
        | StoredRecord::ReplayResult { .. } => false,
        StoredRecord::RequestHead { .. }
        | StoredRecord::RequestTrailers { .. }
        | StoredRecord::RequestEnd { .. }
        | StoredRecord::ResponseHead { .. }
        | StoredRecord::ResponseTrailers { .. }
        | StoredRecord::ResponseEnd { .. } => true,
    }
}

pub(super) async fn read(
    collection: &CollectionReader,
    location: RecordLocation,
    payload_limit: Option<u64>,
) -> Result<StoredRecord, BoxError> {
    let mut record = attachment::read::<StoredRecord>(collection.read(location.id).await?).await?;
    if let StoredRecord::Interception {
        original_payload, ..
    } = &mut record.metadata
    {
        if payload_limit == Some(0) {
            *original_payload = None;
        } else if let Some(payload) = original_payload {
            let mut bytes = Vec::new();
            match payload_limit {
                Some(limit) => {
                    record.payload.take(limit).read_to_end(&mut bytes).await?;
                }
                None => {
                    record.payload.read_to_end(&mut bytes).await?;
                }
            }
            payload.replace_bytes(bytes.into());
        }
    }
    Ok(record.metadata)
}

impl ExchangeCapture {
    /// Read a page of upgraded-message decisions, newest page first. Each payload
    /// preview is bounded to 1 KiB and each page to 16 records. Full records remain
    /// available through explicit capture downloads or `details`.
    pub async fn message_interceptions(&self, page: usize) -> Result<Vec<StoredRecord>, BoxError> {
        const PAGE_SIZE: usize = 16;
        let count = self.entry.message_decisions.read().len();
        let end = count.saturating_sub(page.saturating_mul(PAGE_SIZE));
        let start = end.saturating_sub(PAGE_SIZE);
        let mut records = Vec::with_capacity(end - start);
        for index in start..end {
            let location = self.entry.message_decisions.read()[index];
            records.push(read(&self.entry.collection, location, Some(kib_u64(1))).await?);
        }
        Ok(records)
    }
}
