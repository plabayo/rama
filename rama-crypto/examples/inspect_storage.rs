//! Encryption is layered over a caller-selected streaming storage service.

use rama_core::{Layer, Service};
use rama_crypto::inspect::EncryptStorageLayer;
use rama_inspect::storage::{CreateCollection, FileStore, StorageLimits};

#[tokio::main]
async fn main() -> Result<(), rama_core::error::BoxError> {
    let storage = EncryptStorageLayer::random()?.layer(FileStore::temporary(StorageLimits {
        total_bytes: rama_utils::octets::mib_u64(1),
        record_bytes: rama_utils::octets::kib_u64(64),
    })?);
    let collection = storage.serve(CreateCollection { id: 1 }).await?;
    let id = collection
        .append(std::io::Cursor::new(b"captured record"))
        .await?;
    let mut reader = collection.read(id).await?;
    assert_eq!(
        tokio::io::copy(&mut reader, &mut tokio::io::sink()).await?,
        15
    );
    Ok(())
}
