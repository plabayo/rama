use std::{
    pin::Pin,
    task::{Context, Poll},
};

use rama_core::service::service_fn;
use rama_inspect::storage::{
    AppendRecord, Collection, CreateCollection, ListRecords, MemoryStore, ReadRecord, Reader,
    RecordId, Storage, StorageLimits,
};
use rama_utils::octets::{kib, kib_u64};
use tokio::io::{AsyncRead, ReadBuf};

use super::*;
use crate::inspect::control::{Direction, Message, Payload};

struct CountedReader {
    inner: Reader,
    read: Arc<AtomicUsize>,
}

impl AsyncRead for CountedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = self.inner.as_mut().poll_read(cx, buf);
        self.read
            .fetch_add(buf.filled().len() - before, Ordering::Relaxed);
        result
    }
}

#[derive(Clone)]
struct CountedCollection {
    inner: Collection,
    read: Arc<AtomicUsize>,
}

impl Service<AppendRecord> for CountedCollection {
    type Output = RecordId;
    type Error = BoxError;

    async fn serve(&self, input: AppendRecord) -> Result<RecordId, BoxError> {
        self.inner.serve(input).await
    }
}

impl Service<ListRecords> for CountedCollection {
    type Output = Vec<RecordId>;
    type Error = BoxError;

    async fn serve(&self, input: ListRecords) -> Result<Vec<RecordId>, BoxError> {
        self.inner.serve(input).await
    }
}

impl Service<ReadRecord> for CountedCollection {
    type Output = Reader;
    type Error = BoxError;

    async fn serve(&self, input: ReadRecord) -> Result<Reader, BoxError> {
        Ok(Box::pin(CountedReader {
            inner: self.inner.serve(input).await?,
            read: self.read.clone(),
        }))
    }
}

#[tokio::test]
async fn interception_history_is_separate_and_previews_do_not_read_full_payloads() {
    let read = Arc::new(AtomicUsize::new(0));
    let storage = Storage::new(service_fn({
        let memory = MemoryStore::new(StorageLimits::default());
        let read = read.clone();
        move |input: CreateCollection| {
            let memory = memory.clone();
            let read = read.clone();
            async move {
                Ok::<_, BoxError>(Collection::new(CountedCollection {
                    inner: memory.serve(input).await?,
                    read,
                }))
            }
        }
    }));
    let store = CaptureStore::with_storage(
        storage,
        CaptureConfig::default(),
        InspectionState::default(),
    );
    let (parts, _) = Request::new(Body::empty()).into_parts();
    let id = store.begin_exchange(&parts).await.unwrap().unwrap();
    let message = Message {
        direction: Direction::Ingress,
        kind: Some("text".parse().unwrap()),
        payload: Some(Payload::text("x".repeat(kib(128)))),
        ..Message::default()
    };
    for _ in 0..40 {
        store.record_decision(id, &message, "Forwarded", None).await;
    }
    let exchange = store.exchange_capture(id).unwrap();
    read.store(0, Ordering::Relaxed);
    let metadata = exchange.inspector_details().await.unwrap();
    assert_eq!(metadata.records.len(), 1);
    assert!(read.load(Ordering::Relaxed) < kib(1));
    for (page, count) in [(0, 16), (1, 16), (2, 8), (3, 0)] {
        read.store(0, Ordering::Relaxed);
        let previews = exchange.message_interceptions(page).await.unwrap();
        assert_eq!(previews.len(), count);
        assert!(read.load(Ordering::Relaxed) <= count * kib(2));
        for preview in previews {
            let StoredRecord::Interception {
                original_payload: Some(payload),
                original_payload_length,
                ..
            } = preview
            else {
                panic!("missing decision preview")
            };
            assert_eq!(payload.len(), kib(1));
            assert_eq!(original_payload_length, Some(kib_u64(128)));
        }
    }
    let owned = exchange.details().await.unwrap();
    assert_eq!(
        owned
            .records
            .iter()
            .filter_map(|record| match record {
                StoredRecord::Interception {
                    original_payload: Some(payload),
                    ..
                } => Some(payload.len()),
                _ => None,
            })
            .sum::<usize>(),
        40 * kib(128)
    );
}

#[tokio::test]
async fn tiny_frames_stop_retention_at_the_record_limit_and_readers_pin_the_budget() {
    let store = CaptureStore::with_storage(
        Storage::new(MemoryStore::new(StorageLimits::default())),
        CaptureConfig {
            max_records: 8,
            ..CaptureConfig::default()
        },
        InspectionState::default(),
    );
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(service_fn(
        async |request: Request| {
            let forwarded = request.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(forwarded.len(), 100);
            Ok::<_, Infallible>(Response::new(Body::empty()))
        },
    ));
    let body = Body::from_stream(rama_core::futures::stream::iter(
        (0..100).map(|_| Ok::<_, Infallible>(Bytes::from_static(b"x"))),
    ));
    service
        .serve(Request::new(body))
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let id = 1;
    let (parts, _) = Request::new(Body::empty()).into_parts();
    let exchange = store.exchange_capture(id).unwrap();
    assert_eq!(exchange.snapshot().request_bytes, 100);
    assert!(exchange.snapshot().request_truncated);
    assert_eq!(exchange.entry.records.read().len(), 8);
    let reader = exchange.body_source(CapturedBody::Request).reader();
    drop(exchange);
    store.clear().await;
    assert_eq!(store.0.budget.records.load(Ordering::Acquire), 8);
    assert!(store.begin_exchange(&parts).await.unwrap().is_none());
    drop(reader);
    assert_eq!(store.0.budget.records.load(Ordering::Acquire), 0);
    assert!(store.begin_exchange(&parts).await.unwrap().is_some());
}

#[tokio::test]
async fn binary_interception_search_preserves_hex_even_for_utf8_payloads() {
    let store = test_store();
    let id = store
        .begin_exchange(&Request::new(Body::empty()).into_parts().0)
        .await
        .unwrap()
        .unwrap();
    let message = Message {
        direction: Direction::Ingress,
        kind: Some("text".parse().unwrap()),
        payload: Some(Payload::binary(Bytes::from_static(b"ab"))),
        ..Message::default()
    };
    store.record_decision(id, &message, "Forwarded", None).await;
    let filter = CaptureFilter {
        search: "0x6162".into(),
        ..CaptureFilter::default()
    };
    assert_eq!(store.snapshot(&filter).await.exchanges.len(), 1);
    let filter = CaptureFilter {
        search: "\"\"".into(),
        ..CaptureFilter::default()
    };
    assert!(store.snapshot(&filter).await.exchanges.is_empty());
}
