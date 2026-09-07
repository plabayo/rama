//! CLI storage composition for the reusable inspector.

use rama::{Layer, error::BoxError};
pub(super) use rama_inspect::http::capture::*;
use rama_inspect::storage::{FileStore, Storage, StorageLimits, encrypt::EncryptLayer};

pub(super) fn storage(total_bytes: u64) -> Result<Storage, BoxError> {
    let files = FileStore::temporary(StorageLimits {
        total_bytes,
        record_bytes: 0,
    })?;
    Ok(Storage::new(EncryptLayer::random()?.layer(files)))
}

#[cfg(test)]
pub(super) fn test_store(
    max_connections: usize,
    max_exchanges: usize,
    body_limit: u64,
    profiles: std::sync::Arc<rama::ua::profile::UserAgentDatabase>,
) -> Result<CaptureStore, BoxError> {
    Ok(CaptureStore::with_storage(
        storage(0)?,
        CaptureConfig {
            max_connections,
            max_exchanges,
            max_websocket_messages: max_exchanges,
            body_limit,
            total_limit: 0,
            profiles,
        },
        rama_inspect::InspectionState::default(),
    ))
}
