use super::*;
use tokio::io::AsyncWriteExt;
#[cfg(feature = "fs")]
use tokio::sync::oneshot;

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
async fn memory_streaming_cancel_concurrency_and_retention() {
    exercise(MemoryStore::new(StorageLimits::default())).await;
}
#[cfg(feature = "fs")]
#[tokio::test]
async fn file_streaming_cancel_concurrency_and_retention() {
    exercise(FileStore::temporary(StorageLimits::default()).unwrap()).await;
}
#[cfg(feature = "encryption")]
#[tokio::test]
async fn encrypted_memory_streaming_cancel_concurrency_and_retention() {
    use rama_core::Layer;
    exercise(
        encrypt::EncryptLayer::new([42; 32]).layer(MemoryStore::new(StorageLimits::default())),
    )
    .await;
}
#[cfg(all(feature = "fs", feature = "encryption"))]
#[tokio::test]
async fn encrypted_file_streaming_cancel_concurrency_and_retention() {
    use rama_core::Layer;
    exercise(
        encrypt::EncryptLayer::new([42; 32])
            .layer(FileStore::temporary(StorageLimits::default()).unwrap()),
    )
    .await;
}

async fn budget(store: impl Service<CreateCollection, Output = Collection, Error = BoxError>) {
    let collection = store.serve(CreateCollection { id: 10 }).await.unwrap();
    collection
        .append(std::io::Cursor::new(vec![0; 17]))
        .await
        .unwrap_err();
    let id = collection
        .append(std::io::Cursor::new(vec![1; 12]))
        .await
        .unwrap();
    collection
        .append(std::io::Cursor::new(vec![2; 12]))
        .await
        .unwrap_err();
    assert_eq!(collection.snapshot().await.unwrap(), vec![id]);
    let pinned = collection.read(id).await.unwrap();
    drop(collection);
    let other = store.serve(CreateCollection { id: 11 }).await.unwrap();
    other
        .append(std::io::Cursor::new(vec![3; 12]))
        .await
        .unwrap_err();
    drop(pinned);
    other
        .append(std::io::Cursor::new(vec![4; 12]))
        .await
        .unwrap();
}
#[tokio::test]
async fn memory_budget_aborted_appends_and_pinned_readers() {
    budget(MemoryStore::new(StorageLimits {
        total_bytes: 20,
        record_bytes: 16,
    }))
    .await;
}
#[cfg(feature = "fs")]
#[tokio::test]
async fn file_budget_aborted_appends_and_pinned_readers() {
    budget(
        FileStore::temporary(StorageLimits {
            total_bytes: 20,
            record_bytes: 16,
        })
        .unwrap(),
    )
    .await;
}

#[cfg(feature = "fs")]
struct FailingReader(Option<oneshot::Sender<()>>);
#[cfg(feature = "fs")]
impl AsyncRead for FailingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(signal) = self.0.take() {
            buf.put_slice(b"partial");
            _ = signal.send(());
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(std::io::Error::other("source failure")))
        }
    }
}
#[cfg(feature = "fs")]
#[tokio::test]
async fn filesystem_truncates_failed_tail_before_next_append() {
    let store = FileStore::temporary(StorageLimits::default()).unwrap();
    let collection = store.serve(CreateCollection { id: 1 }).await.unwrap();
    let first = collection
        .append(std::io::Cursor::new(b"first"))
        .await
        .unwrap();
    let (signal, _) = oneshot::channel();
    collection
        .append(FailingReader(Some(signal)))
        .await
        .unwrap_err();
    let last = collection
        .append(std::io::Cursor::new(b"last"))
        .await
        .unwrap();
    assert_eq!(content(&collection, first).await, b"first");
    assert_eq!(content(&collection, last).await, b"last");
    assert_eq!(
        tokio::fs::read(store.directory().join("collection-1.capture"))
            .await
            .unwrap(),
        b"firstlast"
    );
}

#[cfg(all(feature = "fs", feature = "encryption"))]
#[tokio::test]
async fn encryption_rejects_tampering_before_exposing_the_chunk() {
    use rama_core::Layer;
    use tokio::io::AsyncSeekExt;
    let files = FileStore::temporary(StorageLimits::default()).unwrap();
    let store = encrypt::EncryptLayer::new([42; 32]).layer(files.clone());
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

#[cfg(feature = "fs")]
#[tokio::test]
async fn file_cleanup_waits_for_readers_and_preserves_existing_collections() {
    let files = FileStore::temporary(StorageLimits::default()).unwrap();
    let directory = files.directory().to_owned();
    let collection = files.serve(CreateCollection { id: 1 }).await.unwrap();
    let id = collection
        .append(std::io::Cursor::new(b"retained"))
        .await
        .unwrap();
    files.serve(CreateCollection { id: 1 }).await.unwrap_err();
    let reader = collection.read(id).await.unwrap();
    drop(collection);
    files.flush_cleanup().await;
    assert!(directory.join("collection-1.capture").exists());
    drop(reader);
    files.flush_cleanup().await;
    assert!(!directory.join("collection-1.capture").exists());
    drop(files);
    assert!(!directory.exists());
}

#[cfg(all(feature = "fs", feature = "encryption"))]
#[tokio::test]
async fn encryption_rejects_substitution_reordered_chunks_and_missing_terminators() {
    use rama_core::Layer;
    let files = FileStore::temporary(StorageLimits::default()).unwrap();
    let store = encrypt::EncryptLayer::new([42; 32]).layer(files.clone());
    let collection = store.serve(CreateCollection { id: 1 }).await.unwrap();
    let first = collection
        .append(std::io::Cursor::new(vec![1u8; 128 * 1024]))
        .await
        .unwrap();
    let second = collection
        .append(std::io::Cursor::new(vec![2u8; 128 * 1024]))
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
    let frame_len = 32 + 64 * 1024;
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

#[cfg(feature = "fs")]
#[tokio::test]
async fn failed_file_tail_keeps_budget_until_recovery() {
    let files = FileStore::temporary(StorageLimits {
        total_bytes: 10,
        record_bytes: 0,
    })
    .unwrap();
    let collection = files.serve(CreateCollection { id: 1 }).await.unwrap();
    let first = collection.append(std::io::Cursor::new(b"a")).await.unwrap();
    let (signal, _) = oneshot::channel();
    collection
        .append(FailingReader(Some(signal)))
        .await
        .unwrap_err();
    let other = files.serve(CreateCollection { id: 2 }).await.unwrap();
    other
        .append(std::io::Cursor::new(b"123"))
        .await
        .unwrap_err();
    assert_eq!(content(&collection, first).await, b"a");
    // Recovery discards the seven-byte tail before reserving replacement bytes.
    collection.append(std::io::Cursor::new(b"b")).await.unwrap();
    other
        .append(std::io::Cursor::new(b"12345678"))
        .await
        .unwrap();
    assert_eq!(content(&collection, first).await, b"a");
}
