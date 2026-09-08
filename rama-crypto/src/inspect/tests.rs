use super::*;
use rama_core::Layer;
use rama_inspect::storage::{FileStore, MemoryStore, StorageLimits};
use tokio::io::AsyncSeekExt;
use tokio::io::AsyncWriteExt;
async fn content(collection: &Collection, id: RecordId) -> Vec<u8> {
    let mut bytes = Vec::new();
    collection
        .read(id)
        .await
        .unwrap()
        .read_to_end(&mut bytes)
        .await
        .unwrap();
    bytes
}
async fn exercise(store: impl Service<CreateCollection, Output = Collection, Error = BoxError>) {
    let collection = store.serve(CreateCollection { id: 1 }).await.unwrap();
    let first = collection
        .append(std::io::Cursor::new(b"original"))
        .await
        .unwrap();
    // A bounded pipe ensures the append has consumed some data before cancellation.
    let (mut writer, reader) = tokio::io::duplex(1);
    let task = tokio::spawn({
        let collection = collection.clone();
        async move { collection.append(reader).await }
    });
    writer.write_all(b"incomplete").await.unwrap();
    let previous = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        content(&collection, first),
    )
    .await
    .unwrap();
    assert_eq!(previous, b"original");
    assert_eq!(collection.snapshot().await.unwrap(), vec![first]);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(collection.snapshot().await.unwrap(), vec![first]);
    assert_eq!(content(&collection, first).await, b"original");
    let next = collection
        .append(std::io::Cursor::new(b"replacement"))
        .await
        .unwrap();
    assert_eq!(content(&collection, first).await, b"original");
    assert_eq!(content(&collection, next).await, b"replacement");
    let mut range = collection
        .serve(ReadRecord {
            id: next,
            range: Some(2..7),
        })
        .await
        .unwrap();
    let mut bytes = Vec::new();
    range.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"place");

    let mut tasks = Vec::new();
    for n in 0..32u8 {
        let collection = collection.clone();
        tasks.push(tokio::spawn(async move {
            let payload = vec![n; 100_000];
            let id = collection
                .append(std::io::Cursor::new(payload.clone()))
                .await
                .unwrap();
            assert_eq!(content(&collection, id).await, payload);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(collection.snapshot().await.unwrap().len(), 34);

    // A stalled writer in one collection must not block another collection.
    let (mut writer, reader) = tokio::io::duplex(1);
    let task = tokio::spawn({
        let collection = collection.clone();
        async move { collection.append(reader).await }
    });
    writer.write_all(b"pending").await.unwrap();
    let other = store.serve(CreateCollection { id: 2 }).await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        other.append(std::io::Cursor::new(b"independent")),
    )
    .await
    .unwrap()
    .unwrap();
    task.abort();
    _ = task.await;
    let mut pinned = collection.read(first).await.unwrap();
    drop(collection);
    drop(store);
    let mut bytes = Vec::new();
    pinned.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"original");
}
#[tokio::test]
async fn encrypted_memory_streaming_cancel_concurrency_and_retention() {
    exercise(EncryptStorageLayer::new([42; 32]).layer(MemoryStore::new(StorageLimits::default())))
        .await;
}
#[tokio::test]
async fn encrypted_file_streaming_cancel_concurrency_and_retention() {
    exercise(
        EncryptStorageLayer::new([42; 32])
            .layer(FileStore::temporary(StorageLimits::default()).unwrap()),
    )
    .await;
}
#[tokio::test]
async fn encryption_rejects_tampering_before_exposing_the_chunk() {
    let files = FileStore::temporary(StorageLimits::default()).unwrap();
    let store = EncryptStorageLayer::new([42; 32]).layer(files.clone());
    let collection = store.serve(CreateCollection { id: 1 }).await.unwrap();
    let id = collection
        .append(std::io::Cursor::new(b"secret content"))
        .await
        .unwrap();
    let path = files.directory().join("collection-1.capture");
    let disk = tokio::fs::read(&path).await.unwrap();
    assert!(!disk.windows(6).any(|chunk| chunk == b"secret"));
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .await
        .unwrap();
    file.seek(std::io::SeekFrom::Start(56)).await.unwrap();
    file.write_all(&[disk[56] ^ 1]).await.unwrap();
    file.flush().await.unwrap();
    let mut plaintext = Vec::new();
    collection
        .read(id)
        .await
        .unwrap()
        .read_to_end(&mut plaintext)
        .await
        .unwrap_err();
    assert!(plaintext.is_empty());
}
#[tokio::test]
async fn encryption_rejects_substitution_reordered_chunks_and_missing_terminators() {
    let files = FileStore::temporary(StorageLimits::default()).unwrap();
    let store = EncryptStorageLayer::new([42; 32]).layer(files.clone());
    let collection = store.serve(CreateCollection { id: 1 }).await.unwrap();
    let first = collection
        .append(std::io::Cursor::new(vec![
            1u8;
            rama_utils::octets::kib(128)
        ]))
        .await
        .unwrap();
    let second = collection
        .append(std::io::Cursor::new(vec![
            2u8;
            rama_utils::octets::kib(128)
        ]))
        .await
        .unwrap();
    let path = files.directory().join("collection-1.capture");
    let original = tokio::fs::read(&path).await.unwrap();
    let record_len = original.len() / 2;
    let mut substituted = original.clone();
    substituted[..record_len].copy_from_slice(&original[record_len..]);
    tokio::fs::write(&path, &substituted).await.unwrap();
    let mut bytes = Vec::new();
    collection
        .read(first)
        .await
        .unwrap()
        .read_to_end(&mut bytes)
        .await
        .unwrap_err();
    assert!(bytes.is_empty());
    let frame_len = 32 + rama_utils::octets::kib(64);
    let mut reordered = original.clone();
    reordered[24..24 + frame_len].copy_from_slice(&original[24 + frame_len..24 + 2 * frame_len]);
    reordered[24 + frame_len..24 + 2 * frame_len].copy_from_slice(&original[24..24 + frame_len]);
    tokio::fs::write(&path, reordered).await.unwrap();
    collection
        .read(first)
        .await
        .unwrap()
        .read_to_end(&mut bytes)
        .await
        .unwrap_err();
    assert!(bytes.is_empty());
    tokio::fs::write(&path, &original[..original.len() - 32])
        .await
        .unwrap();
    collection
        .read(second)
        .await
        .unwrap()
        .read_to_end(&mut bytes)
        .await
        .unwrap_err();
}
