use std::{
    convert::Infallible,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use rama_core::{
    Layer, Service, ServiceInput, bytes::Bytes, error::BoxError, futures::StreamExt,
    service::service_fn,
};
use rama_http::{
    Body, Method, Request, Response, StatusCode, Version,
    body::util::BodyExt,
    header,
    inspect::capture::{
        CaptureConfig, CaptureFilter, CaptureHttpLayer, CaptureMetadata, CaptureObserver,
        CaptureStore, ConnectionId, HttpExchangeId, HttpUpgradeCaptureGuard,
    },
};
use rama_inspect::{
    InspectionState,
    storage::{
        AppendRecord, Collection, CreateCollection, ListRecords, MemoryStore, ReadRecord, Reader,
        RecordId, Storage, StorageLimits,
    },
};
use rama_net::Protocol;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use super::*;
use crate::handshake::mitm::{WebSocketBridge, WebSocketRelayDirection};

#[derive(Debug)]
struct Observer(WebSocketLimits);

impl CaptureObserver for Observer {
    fn request(&self, parts: &rama_http::request::Parts, metadata: &CaptureMetadata) {
        observe_handshake(parts, metadata, self.0);
    }

    fn response(&self, _: &rama_http::response::Parts, _: &CaptureMetadata) {}
}

fn store(messages: usize, bytes: u64, total: u64) -> CaptureStore {
    CaptureStore::with_storage(
        Storage::new(MemoryStore::new(StorageLimits::default())),
        CaptureConfig {
            body_limit: bytes,
            total_limit: total,
            observer: Arc::new(Observer(WebSocketLimits { messages })),
            ..CaptureConfig::default()
        },
        InspectionState::default(),
    )
}

async fn handshake(store: &CaptureStore, version: Version, status: StatusCode) -> Response {
    let connection = store
        .begin_connection_if_enabled(None, rama_net::Protocol::HTTPS, None)
        .unwrap();
    store.confirm_connection_if_enabled(connection);
    let request = Request::builder()
        .uri("https://example.test/socket")
        .version(version)
        .extension(ConnectionId(connection));
    let request = if version == Version::HTTP_2 {
        request
            .method("CONNECT")
            .extension(rama_http::proto::h2::ext::Protocol::from_static(
                "websocket",
            ))
    } else {
        request
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
    };
    CaptureHttpLayer::new(Some(store.clone()))
        .layer(service_fn(move |request: Request| async move {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(
                Response::builder()
                    .status(status)
                    .version(version)
                    .body(Body::empty())
                    .unwrap(),
            )
        }))
        .serve(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn message(kind: WebSocketMessageKind, data: &'static [u8]) -> CapturedWebSocketMessage {
    CapturedWebSocketMessage::new(
        WebSocketRelayDirection::Ingress,
        kind,
        Bytes::from_static(data),
    )
}

#[test]
fn handshake_capture_uses_the_shared_protocol_matcher() {
    for (method, upgrade, connection, expected) in [
        (Method::GET, "websocket", Some("upgrade"), true),
        (Method::POST, "websocket", Some("upgrade"), false),
        (Method::GET, "websocket", None, false),
        (Method::GET, "websocket", Some("keep-alive"), false),
        (
            Method::GET,
            "websocket",
            Some("upgrade, invalid token"),
            false,
        ),
        (
            Method::GET,
            "h2c, WebSocket",
            Some("keep-alive, Upgrade"),
            true,
        ),
        (Method::GET, "websocket/13", Some("upgrade"), false),
    ] {
        let request = Request::builder()
            .method(method)
            .uri("https://example.test/socket")
            .header(header::UPGRADE, upgrade);
        let request = if let Some(connection) = connection {
            request.header(header::CONNECTION, connection)
        } else {
            request
        };
        let (parts, ()) = request.body(()).unwrap().into_parts();
        let metadata = CaptureMetadata::default();
        assert_eq!(
            observe_handshake(&parts, &metadata, WebSocketLimits::default()),
            expected,
        );
        assert_eq!(
            metadata.exchange.get_ref::<Protocol>(),
            expected.then_some(&Protocol::WSS),
        );
        assert_eq!(metadata.exchange.contains::<WebSocketLimits>(), expected);
    }
}

#[tokio::test]
async fn pages_streams_and_search_keep_protocol_records_separate() {
    let store = store(16, rama_utils::octets::kib_u64(1), 0);
    let _response = handshake(&store, Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS).await;
    for kind in [
        WebSocketMessageKind::Text,
        WebSocketMessageKind::Binary,
        WebSocketMessageKind::Ping,
        WebSocketMessageKind::Pong,
        WebSocketMessageKind::Close,
    ] {
        store
            .record_websocket_message(1, message(kind, b"needle"))
            .await;
    }
    let first = store.websocket_details(1, 0, 2).await.unwrap();
    assert_eq!(first.total, 5);
    assert_eq!(first.messages[0].kind, WebSocketMessageKind::Pong);
    assert_eq!(first.messages[1].kind, WebSocketMessageKind::Close);
    let last = store.websocket_details(1, usize::MAX, 2).await.unwrap();
    assert_eq!(last.page, 2);
    assert_eq!(last.messages.len(), 1);
    assert_eq!(last.messages[0].kind, WebSocketMessageKind::Text);
    assert!(
        store
            .websocket_details(1, 0, 0)
            .await
            .unwrap()
            .messages
            .is_empty()
    );
    let chunks = store
        .websocket_message_stream(1, 0)
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    assert_eq!(chunks[0].as_ref().unwrap(), b"needle".as_slice());
    assert!(store.websocket_message_stream(1, 5).is_err());
    assert_eq!(store.inspector_details(1).await.unwrap().records.len(), 3);
    assert_eq!(
        store
            .snapshot(&CaptureFilter {
                search: "NEEDLE".into(),
                ..Default::default()
            })
            .await
            .total_requests,
        1
    );
}

#[tokio::test]
async fn message_and_byte_limits_never_publish_partial_messages() {
    for (count, bytes) in [(1, rama_utils::octets::kib_u64(1)), (8, 3)] {
        let store = store(count, bytes, 0);
        let _response = handshake(&store, Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS).await;
        store
            .record_websocket_message(1, message(WebSocketMessageKind::Text, b"first"))
            .await;
        store
            .record_websocket_message(1, message(WebSocketMessageKind::Text, b"second"))
            .await;
        let details = store.details(1).await.unwrap();
        assert_eq!(details.summary.request_bytes, 11);
        assert!(details.summary.request_truncated && details.summary.response_truncated);
        assert_eq!(
            store.websocket_details(1, 0, 10).await.unwrap().total,
            usize::from(bytes > 3)
        );
    }
}

#[tokio::test]
async fn a_paused_gap_preserves_data_and_disables_replay() {
    let store = store(16, rama_utils::octets::kib_u64(1), 0);
    let _response = handshake(&store, Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS).await;
    store
        .record_websocket_message(1, message(WebSocketMessageKind::Text, b"before"))
        .await;
    store.inspection_state().pause().await;
    store
        .record_websocket_message(1, message(WebSocketMessageKind::Text, b"during"))
        .await;
    store.inspection_state().resume().await;
    store
        .record_websocket_message(1, message(WebSocketMessageKind::Text, b"after"))
        .await;
    assert_eq!(store.websocket_details(1, 0, 10).await.unwrap().total, 2);
    assert!(matches!(
        store.replay_websocket_message(1, 0).await,
        Err(WebSocketReplayError::Truncated)
    ));
}

#[tokio::test]
async fn typed_records_stay_readable_after_clearing_and_do_not_pollute_http_har() {
    let store = store(16, rama_utils::octets::kib_u64(1), 0);
    let _response = handshake(&store, Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS).await;
    store
        .record_websocket_message(1, message(WebSocketMessageKind::Binary, &[0, 255]))
        .await;
    let mut selected = store.selected_exchanges(&[1].into(), &Default::default());
    let selected = selected.next_capture().unwrap();
    store.clear().await;
    let mut output = Vec::new();
    rama_http::layer::har::inspect::write_captured_har_entry(&mut output, &selected, &())
        .await
        .unwrap();
    let entry: rama_http::layer::har::spec::Entry = serde_json::from_slice(&output).unwrap();
    assert!(entry.web_socket_messages.is_none());
    output.clear();
    rama_http::layer::har::inspect::write_captured_har_entry(
        &mut output,
        &selected,
        &har::WebSocketHarExtension(&selected),
    )
    .await
    .unwrap();
    let entry: rama_http::layer::har::spec::Entry = serde_json::from_slice(&output).unwrap();
    assert_eq!(entry.web_socket_messages.unwrap()[0].data, "AP8=");
}

#[tokio::test]
async fn only_successful_upgrades_hold_the_connection_open() {
    for (version, status, upgraded) in [
        (Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS, true),
        (Version::HTTP_11, StatusCode::OK, false),
        (Version::HTTP_2, StatusCode::OK, true),
        (Version::HTTP_2, StatusCode::FORBIDDEN, false),
    ] {
        let store = store(16, rama_utils::octets::kib_u64(1), 0);
        let response = handshake(&store, version, status).await;
        let (parts, body) = response.into_parts();
        body.collect().await.unwrap();
        store.finish_connection(1);
        assert_eq!(store.details(1).await.unwrap().summary.active, upgraded);
        assert_eq!(
            store.details(1).await.unwrap().summary.protocol,
            rama_net::Protocol::WSS
        );
        drop(parts);
        assert!(!store.details(1).await.unwrap().summary.active);
    }
}

#[tokio::test]
async fn relay_completion_and_cancellation_finish_the_upgrade() {
    for (cancel, retain_response_guard) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let store = store(16, rama_utils::octets::kib_u64(1), 0);
        let response = handshake(&store, Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS).await;
        let (parts, body) = response.into_parts();
        body.collect().await.unwrap();
        store.finish_connection(1);
        let ingress = ServiceInput::new(());
        let egress = ServiceInput::new(());
        egress.extensions.insert(HttpExchangeId(1));
        if retain_response_guard {
            egress.extensions.insert_arc(
                parts
                    .extensions
                    .get_arc::<HttpUpgradeCaptureGuard>()
                    .unwrap(),
            );
        }
        let entered = Arc::new(tokio::sync::Notify::new());
        let notify = entered.clone();
        let service = CaptureWebSocketLayer::new(Some(store.clone())).layer(service_fn(
            move |bridge: WebSocketBridge<ServiceInput<()>, ServiceInput<()>>| {
                let entered = entered.clone();
                async move {
                    assert_eq!(
                        bridge.ingress.extensions.get_ref::<HttpExchangeId>(),
                        Some(&HttpExchangeId(1))
                    );
                    entered.notify_one();
                    if cancel {
                        std::future::pending::<()>().await;
                    }
                    Ok::<_, Infallible>(())
                }
            },
        ));
        let task =
            tokio::spawn(async move { service.serve(WebSocketBridge { ingress, egress }).await });
        tokio::time::timeout(Duration::from_secs(1), notify.notified())
            .await
            .unwrap();
        if cancel {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            task.await.unwrap().unwrap();
        }
        // Keep the original response parts alive: relay completion must not
        // depend on the last shared owner of its extension guard going away.
        assert!(!store.details(1).await.unwrap().summary.active);
        drop(parts);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_messages_publish_each_complete_record_once() {
    let store = store(64, rama_utils::octets::kib_u64(8), 0);
    let _response = handshake(&store, Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS).await;
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..32u8 {
        let store = store.clone();
        tasks.spawn(async move {
            store
                .record_websocket_message(
                    1,
                    CapturedWebSocketMessage::new(
                        WebSocketRelayDirection::Ingress,
                        WebSocketMessageKind::Binary,
                        Bytes::copy_from_slice(&[index; 16]),
                    ),
                )
                .await;
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    let details = store.websocket_details(1, 0, 64).await.unwrap();
    assert_eq!(details.total, 32);
    let mut indexes = std::collections::BTreeSet::new();
    for message in details.messages {
        assert_eq!(message.data.len(), 16);
        assert!(message.data.iter().all(|byte| *byte == message.data[0]));
        assert!(indexes.insert(message.data[0]));
    }
    assert_eq!(
        store.details(1).await.unwrap().summary.request_bytes,
        32 * 16
    );
}

#[tokio::test]
async fn cancelled_message_append_preserves_committed_records_and_marks_a_gap() {
    struct StopAfterChunk {
        reader: Reader,
        entered: Arc<tokio::sync::Notify>,
        read: bool,
    }

    impl AsyncRead for StopAfterChunk {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.read {
                self.entered.notify_one();
                return Poll::Pending;
            }
            let mut bytes = [0u8; 8];
            let mut chunk = ReadBuf::new(&mut bytes[..buf.remaining().min(8)]);
            let result = self.reader.as_mut().poll_read(cx, &mut chunk);
            let count = chunk.filled().len();
            if matches!(result, Poll::Ready(Ok(()))) {
                self.read = true;
                buf.put_slice(&bytes[..count]);
            }
            result
        }
    }

    #[derive(Clone)]
    struct Backend {
        inner: Collection,
        stop: Arc<AtomicBool>,
        entered: Arc<tokio::sync::Notify>,
    }

    impl Service<AppendRecord> for Backend {
        type Output = RecordId;
        type Error = BoxError;

        async fn serve(&self, mut input: AppendRecord) -> Result<RecordId, BoxError> {
            if self.stop.load(Ordering::Acquire) {
                input = AppendRecord::new(StopAfterChunk {
                    reader: input.into_reader(),
                    entered: self.entered.clone(),
                    read: false,
                });
            }
            self.inner.serve(input).await
        }
    }

    impl Service<ReadRecord> for Backend {
        type Output = Reader;
        type Error = BoxError;

        async fn serve(&self, input: ReadRecord) -> Result<Reader, BoxError> {
            self.inner.serve(input).await
        }
    }

    impl Service<ListRecords> for Backend {
        type Output = Vec<RecordId>;
        type Error = BoxError;

        async fn serve(&self, input: ListRecords) -> Result<Vec<RecordId>, BoxError> {
            self.inner.serve(input).await
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(tokio::sync::Notify::new());
    let storage = Storage::new(service_fn({
        let stop = stop.clone();
        let entered = entered.clone();
        move |input: CreateCollection| {
            let stop = stop.clone();
            let entered = entered.clone();
            async move {
                Ok::<_, BoxError>(Collection::new(Backend {
                    inner: MemoryStore::new(StorageLimits::default())
                        .serve(input)
                        .await?,
                    stop,
                    entered,
                }))
            }
        }
    }));
    let store = CaptureStore::with_storage(
        storage,
        CaptureConfig::default(),
        InspectionState::default(),
    );
    let _response = handshake(&store, Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS).await;
    store
        .record_websocket_message(1, message(WebSocketMessageKind::Text, b"committed"))
        .await;
    let retained = store.exchange_capture(1).unwrap();
    stop.store(true, Ordering::Release);
    let task = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .record_websocket_message(1, message(WebSocketMessageKind::Text, b"interrupted"))
                .await;
        }
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    store.clear().await;
    let details = read_details(&retained, 0, 10).await.unwrap();
    assert_eq!(details.total, 1);
    assert_eq!(details.messages[0].data, "committed");
    assert!(
        retained
            .inspector_details()
            .await
            .unwrap()
            .summary
            .request_truncated
    );
}

#[tokio::test]
async fn binary_capture_stores_raw_bytes_with_compact_wire_serde() {
    let store = store(
        16,
        rama_utils::octets::kib_u64(128),
        rama_utils::octets::kib_u64(66),
    );
    let _response = handshake(&store, Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS).await;
    let payload = Bytes::from(vec![0xaa; rama_utils::octets::kib(64)]);
    store
        .record_websocket_message(
            1,
            CapturedWebSocketMessage::new(
                WebSocketRelayDirection::Ingress,
                WebSocketMessageKind::Binary,
                payload.clone(),
            ),
        )
        .await;
    let details = store.websocket_details(1, 0, 1).await.unwrap();
    assert_eq!(details.total, 1);
    assert_eq!(details.messages[0].data, payload);
    let encoded = serde_json::to_vec(&details.messages[0]).unwrap();
    assert!(encoded.len() < rama_utils::octets::kib(90));
    #[derive(serde::Deserialize)]
    struct WireMessage {
        data: String,
    }
    let wire: WireMessage = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, wire.data).unwrap(),
        payload
    );
}

struct PayloadReadGuard(usize);

impl AsyncRead for PayloadReadGuard {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.0 >= rama_utils::octets::kib(64) {
            return Poll::Ready(Err(std::io::Error::other(
                "export drained the payload before yielding",
            )));
        }
        let count = output.remaining().min(rama_utils::octets::kib(8));
        output.initialize_unfilled_to(count).fill(0xaa);
        output.advance(count);
        self.0 += count;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn preview_pages_read_bounded_prefixes_and_preserve_full_downloads() {
    #[derive(Clone)]
    struct Backend {
        inner: Collection,
        guarded: Arc<AtomicBool>,
    }

    impl Service<AppendRecord> for Backend {
        type Output = RecordId;
        type Error = BoxError;

        async fn serve(&self, input: AppendRecord) -> Result<RecordId, BoxError> {
            self.inner.serve(input).await
        }
    }

    impl Service<ListRecords> for Backend {
        type Output = Vec<RecordId>;
        type Error = BoxError;

        async fn serve(&self, input: ListRecords) -> Result<Vec<RecordId>, BoxError> {
            self.inner.serve(input).await
        }
    }

    impl Service<ReadRecord> for Backend {
        type Output = Reader;
        type Error = BoxError;

        async fn serve(&self, input: ReadRecord) -> Result<Reader, BoxError> {
            let reader = self.inner.serve(input).await?;
            if self.guarded.load(Ordering::Relaxed) {
                // Include space for typed metadata, then fail if a consumer
                // drains a message instead of stopping at its preview bound.
                Ok(Box::pin(
                    reader
                        .take(rama_utils::octets::kib_u64(1))
                        .chain(PayloadReadGuard(rama_utils::octets::kib(64))),
                ))
            } else {
                Ok(reader)
            }
        }
    }
    let guarded = Arc::new(AtomicBool::new(true));
    let storage = Storage::new(service_fn({
        let memory = MemoryStore::new(StorageLimits::default());
        let guarded = guarded.clone();
        move |input: CreateCollection| {
            let memory = memory.clone();
            let guarded = guarded.clone();
            async move {
                Ok::<_, BoxError>(Collection::new(Backend {
                    inner: memory.serve(input).await?,
                    guarded,
                }))
            }
        }
    }));
    let store = CaptureStore::with_storage(
        storage,
        CaptureConfig {
            observer: Arc::new(Observer(WebSocketLimits { messages: 16 })),
            body_limit: rama_utils::octets::mib_u64(4),
            ..CaptureConfig::default()
        },
        InspectionState::default(),
    );
    let _response = handshake(&store, Version::HTTP_11, StatusCode::SWITCHING_PROTOCOLS).await;
    let payload = Bytes::from(vec![b'a'; rama_utils::octets::mib(1)]);
    for kind in [WebSocketMessageKind::Text, WebSocketMessageKind::Binary] {
        store
            .record_websocket_message(
                1,
                CapturedWebSocketMessage::new(
                    WebSocketRelayDirection::Ingress,
                    kind,
                    payload.clone(),
                ),
            )
            .await;
    }
    let exchange = store.exchange_capture(1).unwrap();
    let preview = read_preview_details(&exchange, 0, 2, |metadata| match metadata.kind {
        WebSocketMessageKind::Text => 128,
        _ => 256,
    })
    .await
    .unwrap();
    assert_eq!(preview.total, 2);
    assert_eq!(preview.messages.len(), 2);
    for (message, length) in preview.messages.iter().zip([128, 256]) {
        assert_eq!(message.metadata.payload_length, payload.len() as u64);
        assert_eq!(message.data, payload.slice(..length));
    }
    let older = read_preview_details(&exchange, usize::MAX, 1, |_| 0)
        .await
        .unwrap();
    assert_eq!(older.page, 1);
    assert_eq!(older.messages.len(), 1);
    assert_eq!(older.messages[0].metadata.kind, WebSocketMessageKind::Text);
    assert!(older.messages[0].data.is_empty());
    assert!(
        read_preview_details(&exchange, 0, 0, |_| 256)
            .await
            .unwrap()
            .messages
            .is_empty()
    );
    // Closed replay must reject from metadata, without reaching the guarded payload.
    assert!(matches!(
        store.replay_websocket_message(1, 0).await,
        Err(WebSocketReplayError::ConnectionClosed)
    ));
    // The guard really rejects eager materialization, rather than returning EOF.
    read_details(&exchange, 0, 1).await.unwrap_err();
    guarded.store(false, Ordering::Relaxed);
    let mut reader = exchange
        .record_stream::<CapturedWebSocketMessage>(0)
        .await
        .unwrap()
        .unwrap()
        .payload;
    let mut downloaded = Vec::new();
    reader.read_to_end(&mut downloaded).await.unwrap();
    assert_eq!(downloaded, payload);
}
