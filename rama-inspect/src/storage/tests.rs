use tokio::{io::AsyncWriteExt, sync::oneshot};

use super::*;

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

    for (range, expected) in [
        (9..20, b"nt".as_slice()),
        (11..11, b""),
        (20..30, b""),
        (20..20, b""),
    ] {
        let mut reader = collection
            .serve(ReadRecord {
                id: next,
                range: Some(range),
            })
            .await
            .unwrap();
        bytes.clear();
        reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, expected);
    }
    match collection
        .serve(ReadRecord {
            id: next,
            range: Some(Range { start: 2, end: 1 }),
        })
        .await
    {
        Ok(_) => panic!("reversed range accepted"),
        Err(error) => assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::InvalidInput,
        ),
    }

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

#[tokio::test]
async fn memory_stalled_append_does_not_block_another_record() {
    let store = MemoryStore::new(StorageLimits::default());
    let collection = store.serve(CreateCollection { id: 1 }).await.unwrap();
    let first = collection
        .serve(AppendRecord::bytes(Bytes::from_static(b"first")))
        .await
        .unwrap();
    let (mut source, stream) = tokio::io::duplex(1);
    let stalled = tokio::spawn({
        let collection = collection.clone();
        async move { collection.append(stream).await }
    });
    source.write_all(b"pending").await.unwrap();

    let next = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        collection.serve(AppendRecord::bytes(Bytes::from_static(b"next"))),
    )
    .await
    .expect("a private in-flight buffer must not prevent another record from publishing")
    .unwrap();
    assert_eq!(collection.snapshot().await.unwrap(), vec![first, next]);
    assert_eq!(content(&collection, next).await, b"next");

    stalled.abort();
    assert!(stalled.await.unwrap_err().is_cancelled());
    assert_eq!(collection.snapshot().await.unwrap(), vec![first, next]);
    assert_eq!(content(&collection, first).await, b"first");
}

#[tokio::test]
async fn file_streaming_cancel_concurrency_and_retention() {
    exercise(FileStore::temporary(StorageLimits::default()).unwrap()).await;
}

async fn split_capabilities(
    store: impl Service<CreateCollection, Output = Collection, Error = BoxError>,
) {
    let (read, write) = store
        .serve(CreateCollection { id: 1 })
        .await
        .unwrap()
        .split();
    let first = write
        .append(std::io::Cursor::new(b"committed"))
        .await
        .unwrap();
    let (mut source, stream) = tokio::io::duplex(1);
    let append = tokio::spawn({
        let write = write.clone();
        async move { write.append(stream).await }
    });
    source.write_all(b"pending").await.unwrap();
    let mut pinned = tokio::time::timeout(std::time::Duration::from_secs(2), read.read(first))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.snapshot().await.unwrap(), vec![first]);
    append.abort();
    assert!(append.await.unwrap_err().is_cancelled());
    let second = write.append(std::io::Cursor::new(b"next")).await.unwrap();
    assert_eq!(read.snapshot().await.unwrap(), vec![first, second]);
    drop((write, read, store));
    let mut bytes = Vec::new();
    pinned.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"committed");
}

#[tokio::test]
async fn memory_split_capabilities_preserve_concurrent_reads_and_retention() {
    split_capabilities(MemoryStore::new(StorageLimits::default())).await;
}

#[tokio::test]
async fn file_split_capabilities_preserve_concurrent_reads_and_retention() {
    split_capabilities(FileStore::temporary(StorageLimits::default()).unwrap()).await;
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

struct FailingReader(Option<oneshot::Sender<()>>);

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
    let replacement = files.serve(CreateCollection { id: 1 }).await.unwrap();
    assert!(replacement.snapshot().await.unwrap().is_empty());
    let id = replacement
        .append(std::io::Cursor::new(b"replacement"))
        .await
        .unwrap();
    assert_eq!(id, RecordId(0));
    assert_eq!(content(&replacement, id).await, b"replacement");
    drop(replacement);
    files.flush_cleanup().await;
    drop(files);
    assert!(!directory.exists());
}

#[tokio::test]
async fn failed_file_tail_recovers_without_another_append() {
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
    // Recovery releases the failed tail independently, even if this exchange
    // never receives another append. No storage budget is released before truncate.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if other
                .append(std::io::Cursor::new(b"123456789"))
                .await
                .is_ok()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        tokio::fs::read(files.directory().join("collection-1.capture"))
            .await
            .unwrap(),
        b"a"
    );
    assert_eq!(content(&collection, first).await, b"a");
    other.append(std::io::Cursor::new(b"x")).await.unwrap_err();
}

#[tokio::test]
async fn owned_bytes_and_range_share_allocation_and_budget() {
    let store = MemoryStore::new(StorageLimits {
        total_bytes: 12,
        record_bytes: 12,
    });
    let collection = store.serve(CreateCollection { id: 1 }).await.unwrap();
    let bytes = Bytes::from(Vec::from(&b"hello world!"[..]));
    assert!(bytes.is_unique());
    let id = collection
        .serve(AppendRecord::bytes(bytes.clone()))
        .await
        .unwrap();
    assert!(
        !bytes.is_unique(),
        "memory storage must retain the original allocation"
    );
    let mut reader = collection
        .serve(ReadRecord {
            id,
            range: Some(6..11),
        })
        .await
        .unwrap();
    drop(collection);
    let mut output = Vec::new();
    reader.read_to_end(&mut output).await.unwrap();
    assert_eq!(output, b"world");
    let other = store.serve(CreateCollection { id: 2 }).await.unwrap();
    other
        .serve(AppendRecord::bytes(bytes.clone()))
        .await
        .unwrap_err();
    drop(reader);
    assert!(bytes.is_unique());
    other
        .serve(AppendRecord::bytes(bytes.clone()))
        .await
        .unwrap();
}

#[tokio::test]
async fn default_memory_limits_reject_oversized_records() {
    let limits = StorageLimits::default();
    assert!(limits.record_bytes > 0 && limits.total_bytes >= limits.record_bytes);
    let store = MemoryStore::new(limits);
    let collection = store.serve(CreateCollection { id: 1 }).await.unwrap();
    let bytes = Bytes::from(vec![0; limits.record_bytes as usize + 1]);
    collection
        .serve(AppendRecord::bytes(bytes))
        .await
        .unwrap_err();
    assert!(collection.snapshot().await.unwrap().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn retained_file_collections_do_not_retain_descriptors() {
    let descriptor_count = || std::fs::read_dir("/dev/fd").unwrap().count();
    let before = descriptor_count();
    let store = FileStore::temporary(StorageLimits::default()).unwrap();
    let mut collections = Vec::new();
    for id in 0..256 {
        let collection = store.serve(CreateCollection { id }).await.unwrap();
        collection
            .serve(AppendRecord::bytes(Bytes::from_static(b"retained")))
            .await
            .unwrap();
        let (signal, _) = oneshot::channel();
        collection
            .append(FailingReader(Some(signal)))
            .await
            .unwrap_err();
        collections.push(collection);
    }
    // Allow descriptors used by other concurrently running tests; the old code
    // retained at least 256 descriptors for these collections alone.
    assert!(descriptor_count() < before + 128);
    assert_eq!(content(&collections[255], RecordId(0)).await, b"retained");
}
