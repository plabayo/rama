//! Encryption is layered over a caller-selected streaming storage service.
use rama_core::{Layer, Service};
use rama_inspect::storage::{CreateCollection, FileStore, StorageLimits, encrypt::EncryptLayer};

#[tokio::main]
async fn main() -> Result<(), rama_core::error::BoxError> {
    let storage = EncryptLayer::random()?.layer(FileStore::temporary(StorageLimits {
        total_bytes: 1024 * 1024,
        record_bytes: 64 * 1024,
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
