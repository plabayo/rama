//! Conformance checks shared by every [`Collection`] storage backend and layer.
//!
//! Available with the `test-utils` feature so layers in other crates (such as
//! encryption) can prove they preserve the storage contract.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helper: failures must surface loudly to invalidate the test run"
)]

use std::ops::Range;

use rama_core::{Service, error::BoxError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{Collection, CreateCollection, ReadRecord, RecordId};

/// Read a whole record into memory, panicking on failure.
pub async fn content(collection: &Collection, id: RecordId) -> Vec<u8> {
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

/// Exercise the storage contract: cancelled appends publish nothing, ranges
/// clamp and reject reversal, concurrent appends stay isolated, a stalled
/// collection does not block another, and readers outlive their store.
pub async fn exercise(
    store: impl Service<CreateCollection, Output = Collection, Error = BoxError>,
) {
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
