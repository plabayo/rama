use super::*;
use rama::extensions::ExtensionsRef as _;
use rama::futures::StreamExt as _;
use std::{convert::Infallible, time::Duration};
use tokio::task::JoinSet;

fn test_store() -> CaptureStore {
    test_store_with_limits(8, 8, 1024)
}

fn test_store_with_limits(
    max_connections: usize,
    max_exchanges: usize,
    body_limit: u64,
) -> CaptureStore {
    CaptureStore::new(
        max_connections,
        max_exchanges,
        body_limit,
        Arc::new(UserAgentDatabase::try_embedded().unwrap()),
    )
    .unwrap()
}

fn test_store_with_total_limit(
    max_exchanges: usize,
    body_limit: u64,
    total_limit: u64,
) -> CaptureStore {
    CaptureStore::new_with_total_limit(
        8,
        max_exchanges,
        body_limit,
        total_limit,
        Arc::new(UserAgentDatabase::try_embedded().unwrap()),
    )
    .unwrap()
}

fn decoded_body(records: &[StoredRecord], request: bool) -> Vec<u8> {
    records
        .iter()
        .filter_map(|record| match (request, record) {
            (true, StoredRecord::RequestBody { data })
            | (false, StoredRecord::ResponseBody { data }) => BASE64.decode(data).ok(),
            _ => None,
        })
        .flatten()
        .collect()
}

#[test]
fn captured_http_versions_have_stable_display_labels() {
    for (version, label) in [
        (rama::http::Version::HTTP_09, "HTTP/0.9"),
        (rama::http::Version::HTTP_10, "HTTP/1.0"),
        (rama::http::Version::HTTP_11, "HTTP/1.1"),
        (rama::http::Version::HTTP_2, "HTTP/2"),
        (rama::http::Version::HTTP_3, "HTTP/3"),
    ] {
        assert_eq!(http_version_label(version), label);
        assert_eq!(captured_http_version(label).unwrap(), version);
    }
    assert_eq!(
        captured_http_version("HTTP/2.0").unwrap(),
        rama::http::Version::HTTP_2
    );
    assert_eq!(
        captured_http_version("HTTP/3").unwrap(),
        rama::http::Version::HTTP_3
    );
    captured_http_version("HTTP/4").unwrap_err();
}

#[tokio::test]
async fn confirming_a_connection_assigns_one_visible_number() {
    let store = test_store();
    let id = store.begin_connection(None, "classifying");
    let connection = store
        .0
        .connections
        .read()
        .entries
        .get(&id)
        .cloned()
        .unwrap();

    assert!(store.confirm_connection_entry(&connection));
    assert_eq!(connection.display_id.get(), Some(&1));
    assert!(!store.confirm_connection_entry(&connection));
    assert_eq!(connection.display_id.get(), Some(&1));
}

#[tokio::test]
async fn encrypted_records_round_trip_without_plaintext_on_disk() {
    let store = test_store();
    let request = Request::builder()
        .method("POST")
        .uri("http://example.test/private")
        .header("authorization", "Bearer secret-value")
        .body(Body::from("private-payload"))
        .unwrap();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |_request: Request| {
            Ok::<_, Infallible>(Response::new(Body::from("private-response")))
        },
    ));
    let response = service.serve(request).await.unwrap();
    response.into_body().collect().await.unwrap();

    let details = store.details(1).await.unwrap();
    assert_eq!(details.summary.status, Some(200));
    let bytes = tokio::fs::read(store.0.temp_dir.path().join("exchange-1.capture"))
        .await
        .unwrap();
    assert!(!bytes.windows(12).any(|window| window == b"secret-value"));
    assert!(!bytes.windows(15).any(|window| window == b"private-payload"));
    assert!(details.records.iter().any(|record| matches!(
        record,
        StoredRecord::ResponseBody { data } if BASE64.decode(data).unwrap() == b"private-response"
    )));
}

#[tokio::test]
async fn inspector_metadata_is_body_free_and_body_decryption_streams_with_a_limit() {
    let store = test_store_with_limits(8, 8, 4096);
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |request: Request| {
            assert_eq!(
                request.into_body().collect().await.unwrap().to_bytes(),
                "request-stream"
            );
            Ok::<_, Infallible>(Response::new(Body::from("response-stream")))
        },
    ));
    service
        .serve(Request::new(Body::from("request-stream")))
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    let details = store.inspector_details(1, 0, 100).await.unwrap();
    assert!(!details.records.iter().any(|record| matches!(
        record,
        StoredRecord::RequestBody { .. } | StoredRecord::ResponseBody { .. }
    )));

    let stream = store
        .body_stream(1, CapturedBody::Request, Some(7))
        .await
        .unwrap();
    let chunks = stream.collect::<Vec<_>>().await;
    let body = chunks
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(body, b"request");

    let stream = store
        .body_stream(1, CapturedBody::Response, None)
        .await
        .unwrap();
    let chunks = stream.collect::<Vec<_>>().await;
    let body = chunks
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(body, b"response-stream");
}

#[tokio::test]
async fn websocket_inspector_pages_are_bounded_and_include_control_events() {
    let store = test_store_with_limits(8, 128, 4096);
    let request = Request::builder()
        .uri("http://example.test/socket")
        .body(Body::empty())
        .unwrap();
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    for index in 0..100 {
        store
            .record_websocket_message(
                exchange_id,
                "Ingress".to_owned(),
                "text".to_owned(),
                format!("message-{index}").into_bytes(),
                None,
            )
            .await;
    }
    store
        .record_websocket_message(
            exchange_id,
            "Egress".to_owned(),
            "close".to_owned(),
            b"done".to_vec(),
            Some(1000),
        )
        .await;

    let first_message = store
        .websocket_message_stream(exchange_id, 0)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(first_message, b"message-0");
    let close_message = store
        .websocket_message_stream(exchange_id, 100)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(close_message, b"done");

    let latest = store.inspector_details(exchange_id, 0, 100).await.unwrap();
    assert_eq!(latest.websocket_total, 101);
    assert_eq!(
        latest
            .records
            .iter()
            .filter(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
            .count(),
        100
    );
    assert!(latest.records.iter().any(|record| matches!(
        record,
        StoredRecord::WebSocketMessage {
            kind,
            close_code: Some(1000),
            ..
        } if kind == "close"
    )));
    let disabled = store.inspector_details(exchange_id, 99, 0).await.unwrap();
    assert_eq!(disabled.websocket_page, 0);
    assert_eq!(disabled.websocket_total, 101);
    assert!(
        !disabled
            .records
            .iter()
            .any(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
    );

    let older = store.inspector_details(exchange_id, 1, 100).await.unwrap();
    assert_eq!(older.websocket_page, 1);
    assert_eq!(
        older
            .records
            .iter()
            .filter(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
            .count(),
        1
    );
    let clamped = store
        .inspector_details(exchange_id, usize::MAX, 100)
        .await
        .unwrap();
    assert_eq!(clamped.websocket_page, 1);
    assert_eq!(
        clamped
            .records
            .iter()
            .filter(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
            .count(),
        1
    );
    let single_page = store
        .inspector_details(exchange_id, usize::MAX, 101)
        .await
        .unwrap();
    assert_eq!(single_page.websocket_page, 0);
    assert_eq!(
        single_page
            .records
            .iter()
            .filter(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
            .count(),
        101
    );
}

#[tokio::test]
async fn websocket_record_limit_stops_storage_with_one_truncation_state() {
    let store = test_store_with_limits(8, 3, 1024);
    let request = Request::builder()
        .uri("ws://example.test/bounded")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .body(Body::empty())
        .unwrap();
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();

    for index in 0..3 {
        store
            .record_websocket_message(
                exchange_id,
                "Ingress".to_owned(),
                "text".to_owned(),
                format!("message-{index}").into_bytes(),
                None,
            )
            .await;
    }
    let entry = store.exchange(exchange_id).unwrap();
    let committed_before = entry.file.lock().await.len;
    for _ in 0..100 {
        store
            .record_websocket_message(
                exchange_id,
                "Egress".to_owned(),
                "ping".to_owned(),
                Vec::new(),
                None,
            )
            .await;
    }

    let committed_after = entry.file.lock().await.len;
    let details = store.inspector_details(exchange_id, 0, 100).await.unwrap();
    assert_eq!(details.websocket_total, 3);
    assert_eq!(committed_after, committed_before);
    assert!(entry.websocket_truncated.load(Ordering::Acquire));
    assert!(details.summary.request_truncated);
    assert!(details.summary.response_truncated);
}

#[tokio::test]
async fn oversized_websocket_message_is_not_persisted_as_a_partial_message() {
    let store = test_store_with_limits(8, 8, 4);
    let request = Request::builder()
        .uri("ws://example.test/oversized")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .body(Body::empty())
        .unwrap();
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();

    store
        .record_websocket_message(
            exchange_id,
            "Ingress".to_owned(),
            "binary".to_owned(),
            b"12345".to_vec(),
            None,
        )
        .await;

    let details = store.inspector_details(exchange_id, 0, 100).await.unwrap();
    assert_eq!(details.websocket_total, 0);
    assert_eq!(details.summary.request_bytes, 5);
    assert!(details.summary.request_truncated);
    assert!(details.summary.response_truncated);
}

#[tokio::test]
async fn exhausted_total_budget_abandons_a_new_capture_without_failing_traffic() {
    let store = test_store_with_total_limit(8, 1024, FILE_MAGIC.len() as u64);
    let request = Request::builder()
        .uri("http://example.test/not-captured")
        .body(Body::empty())
        .unwrap();

    assert!(
        store
            .begin_exchange(&request.into_parts().0)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.0.exchanges.read().entries.is_empty());
    assert_eq!(store.0.budget.used.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn total_budget_charges_committed_files_and_releases_evicted_entries() {
    let store = test_store_with_total_limit(1, 1024, 4096);
    let request = Request::builder()
        .uri("http://example.test/first")
        .body(Body::empty())
        .unwrap();
    let first = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    store
        .body_event(
            first,
            BodyDirection::Response,
            BodyCaptureEvent::End(CaptureOutcome::Complete),
        )
        .await;

    let first_entry = store.exchange(first).unwrap();
    let first_file_len = first_entry.file.lock().await.len;
    assert_eq!(store.0.budget.used.load(Ordering::Acquire), first_file_len);
    drop(first_entry);

    let request = Request::builder()
        .uri("http://example.test/second")
        .body(Body::empty())
        .unwrap();
    let second = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(second, first);
    assert!(store.exchange(first).is_err());
    let second_entry = store.exchange(second).unwrap();
    let second_file_len = second_entry.file.lock().await.len;
    assert_eq!(store.0.budget.used.load(Ordering::Acquire), second_file_len);
    drop(second_entry);

    store.clear().await;
    assert_eq!(store.0.budget.used.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn selected_exchange_remains_readable_after_retention_evicts_it() {
    let store = test_store_with_limits(8, 1, 1024);
    let empty = store.selected_exchanges(&BTreeSet::new(), &BTreeSet::new());
    assert!(empty.is_empty());

    let first_request = Request::builder()
        .uri("http://example.test/first")
        .body(Body::empty())
        .unwrap();
    let first = store
        .begin_exchange(&first_request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    store
        .body_event(
            first,
            BodyDirection::Response,
            BodyCaptureEvent::End(CaptureOutcome::Complete),
        )
        .await;

    let mut selected = store.selected_exchanges(&BTreeSet::from([first]), &BTreeSet::new());
    assert!(!selected.is_empty());
    let second_request = Request::builder()
        .uri("http://example.test/second")
        .body(Body::empty())
        .unwrap();
    let second = store
        .begin_exchange(&second_request.into_parts().0)
        .await
        .unwrap()
        .unwrap();

    assert_ne!(first, second);
    assert!(store.exchange(first).is_err());
    let details = selected.next_details().await.unwrap().unwrap();
    assert_eq!(details.summary.id, first);
    assert!(selected.next_details().await.unwrap().is_none());
    assert!(selected.is_empty());
}

#[tokio::test]
async fn total_budget_stops_websocket_storage_but_keeps_byte_metrics_bounded() {
    let store = test_store_with_total_limit(100, 8192, 1024);
    let request = Request::builder()
        .uri("ws://example.test/aggregate-budget")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .body(Body::empty())
        .unwrap();
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();

    store
        .record_websocket_message(
            exchange_id,
            "Ingress".to_owned(),
            "binary".to_owned(),
            vec![0; 4096],
            None,
        )
        .await;

    let details = store.inspector_details(exchange_id, 0, 100).await.unwrap();
    assert_eq!(details.websocket_total, 0);
    assert_eq!(details.summary.request_bytes, 4096);
    assert!(details.summary.request_truncated);
    assert!(details.summary.response_truncated);
    assert!(store.0.budget.used.load(Ordering::Acquire) <= 1024);
}

#[tokio::test]
async fn dropping_store_removes_encrypted_capture_directory() {
    let directory = {
        let store = test_store();
        let directory = store.0.temp_dir.path().to_owned();
        let service = CaptureHttpLayer::new(Some(store)).into_layer(rama::service::service_fn(
            async |request: Request| {
                request.into_body().collect().await.unwrap();
                Ok::<_, Infallible>(Response::new(Body::from("captured")))
            },
        ));
        let response = service.serve(Request::new(Body::empty())).await.unwrap();
        response.into_body().collect().await.unwrap();
        assert!(directory.join("exchange-1.capture").exists());
        directory
    };

    assert!(
        !directory.exists(),
        "dropping the last store must clean its encrypted temporary files"
    );
}

#[tokio::test]
async fn clearing_capture_state_removes_encrypted_files_and_summaries() {
    let store = test_store();
    let connection_id = store.begin_connection_labeled(None, "http", Some("clear-test".to_owned()));
    store.confirm_connection(connection_id);
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |_request: Request| Ok::<_, Infallible>(Response::new(Body::from("response"))),
    ));
    service
        .serve(
            Request::builder()
                .uri("http://example.test/clear")
                .extension(ConnectionId(connection_id))
                .body(Body::from("request"))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    store.finish_connection(connection_id);
    let capture_path = store.0.temp_dir.path().join("exchange-1.capture");
    assert!(capture_path.exists());

    store.clear().await;

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert!(snapshot.connections.is_empty());
    assert!(snapshot.exchanges.is_empty());
    assert!(!capture_path.exists());
}

#[tokio::test]
async fn body_capture_limit_does_not_limit_forwarded_traffic() {
    let store = test_store_with_limits(8, 8, 4);
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |request: Request| {
            assert_eq!(
                request.into_body().collect().await.unwrap().to_bytes(),
                "request-body"
            );
            Ok::<_, Infallible>(Response::new(Body::from("response-body")))
        },
    ));

    let response = service
        .serve(Request::new(Body::from("request-body")))
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "response-body"
    );

    let details = store.details(1).await.unwrap();
    assert_eq!(details.summary.request_bytes, 12);
    assert_eq!(details.summary.response_bytes, 13);
    assert!(details.summary.request_truncated);
    assert!(details.summary.response_truncated);
    assert_eq!(decoded_body(&details.records, true), b"requ");
    assert_eq!(decoded_body(&details.records, false), b"resp");
    assert!(details.records.iter().any(|record| matches!(
        record,
        StoredRecord::RequestEnd { outcome } if outcome == "complete"
    )));
    assert!(details.records.iter().any(|record| matches!(
        record,
        StoredRecord::ResponseEnd { outcome } if outcome == "complete"
    )));
    assert!(
        store
            .replay_request(1)
            .await
            .unwrap_err()
            .to_string()
            .contains("truncated")
    );
}

#[tokio::test]
async fn pause_preserves_existing_data_and_resumes_an_existing_exchange() {
    let store = test_store();
    let connection_id = store.begin_connection(None, "http");
    let request = Request::builder()
        .uri("http://example.test/stream")
        .extension(ConnectionId(connection_id))
        .body(Body::empty())
        .unwrap();
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    let frame = |value: &'static [u8]| {
        BodyCaptureEvent::Frame(rama::http::body::Frame::data(Bytes::from_static(value)))
    };

    store
        .body_event(exchange_id, BodyDirection::Request, frame(b"before-"))
        .await;
    let inspection = store.inspection_state();
    assert!(inspection.pause().await);
    store
        .body_event(exchange_id, BodyDirection::Request, frame(b"paused-"))
        .await;
    let paused_request = Request::builder()
        .uri("http://example.test/not-captured")
        .body(Body::empty())
        .unwrap();
    assert!(
        store
            .begin_exchange(&paused_request.into_parts().0)
            .await
            .unwrap()
            .is_none()
    );
    assert!(inspection.resume().await);
    store
        .body_event(exchange_id, BodyDirection::Request, frame(b"after"))
        .await;
    store
        .body_event(
            exchange_id,
            BodyDirection::Response,
            BodyCaptureEvent::End(CaptureOutcome::Complete),
        )
        .await;

    let details = store.details(exchange_id).await.unwrap();
    assert_eq!(decoded_body(&details.records, true), b"before-after");
    assert_eq!(details.summary.request_bytes, 12);
    assert!(details.summary.request_truncated);
    store.replay_request(exchange_id).await.unwrap_err();
    assert_eq!(
        store
            .snapshot(&CaptureFilter::default())
            .await
            .total_requests,
        1
    );
}

#[tokio::test]
async fn websocket_capture_resumes_after_a_paused_gap() {
    let store = test_store();
    let request = Request::builder()
        .uri("ws://example.test/live")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .body(Body::empty())
        .unwrap();
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();

    store
        .record_websocket_message(
            exchange_id,
            "Ingress".to_owned(),
            "text".to_owned(),
            b"before".to_vec(),
            None,
        )
        .await;
    let inspection = store.inspection_state();
    assert!(inspection.pause().await);
    store
        .record_websocket_message(
            exchange_id,
            "Ingress".to_owned(),
            "text".to_owned(),
            b"paused".to_vec(),
            None,
        )
        .await;
    assert!(inspection.resume().await);
    store
        .record_websocket_message(
            exchange_id,
            "Ingress".to_owned(),
            "text".to_owned(),
            b"after".to_vec(),
            None,
        )
        .await;

    let entry = store.exchange(exchange_id).unwrap();
    assert!(!entry.websocket_truncated.load(Ordering::Acquire));
    let details = store.details(exchange_id).await.unwrap();
    let messages = details
        .records
        .iter()
        .filter_map(|record| match record {
            StoredRecord::WebSocketMessage { data, .. } => BASE64.decode(data).ok(),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(messages, [b"before".to_vec(), b"after".to_vec()]);
    assert!(details.summary.request_truncated);
    assert_eq!(details.summary.request_bytes, 11);
}

#[tokio::test]
async fn failed_upstream_response_finishes_the_capture_as_an_error() {
    let store = test_store();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |_request: Request| Err::<Response<Body>, _>("upstream failed"),
    ));

    service
        .serve(Request::new(Body::empty()))
        .await
        .unwrap_err();
    let details = store.details(1).await.unwrap();
    assert!(!details.summary.active);
    assert_eq!(details.summary.status, None);
    assert!(details.records.iter().any(|record| matches!(
        record,
        StoredRecord::ResponseEnd { outcome } if outcome == "error"
    )));
}

#[tokio::test]
async fn cancelled_http_service_finalizes_its_active_exchange() {
    let store = test_store();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(parking_lot::Mutex::new(Some(entered_tx)));
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        move |_request: Request| {
            let entered_tx = entered_tx.clone();
            async move {
                entered_tx.lock().take().unwrap().send(()).unwrap();
                std::future::pending::<Result<Response<Body>, Infallible>>().await
            }
        },
    ));

    let task = tokio::spawn(async move { service.serve(Request::new(Body::empty())).await });
    entered_rx.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert_eq!(snapshot.exchanges.len(), 1);
    assert!(!snapshot.exchanges[0].active);
    assert!(snapshot.exchanges[0].completed_at.is_some());
}

#[tokio::test]
async fn encrypted_capture_authentication_rejects_tampering() {
    let store = test_store();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |_request: Request| Ok::<_, Infallible>(Response::new(Body::from("captured"))),
    ));
    service
        .serve(Request::new(Body::empty()))
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    let path = store.0.temp_dir.path().join("exchange-1.capture");
    let mut bytes = tokio::fs::read(&path).await.unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    tokio::fs::write(path, bytes).await.unwrap();

    store.details(1).await.unwrap_err();
}

#[tokio::test]
async fn cancelled_append_is_truncated_before_the_next_record_is_published() {
    let store = test_store();
    let request = Request::builder()
        .uri("http://example.test/cancel-append")
        .body(Body::empty())
        .unwrap();
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    let entry = store.exchange(exchange_id).unwrap();
    let hook = Arc::new(AppendTestHook::default());
    *store.0.append_test_hook.lock().await = Some(hook.clone());

    let appending_store = store.clone();
    let appending_entry = entry.clone();
    let append_task = tokio::spawn(async move {
        let record = StoredRecord::ReplayResult {
            status: None,
            error: Some("must-not-be-published".to_owned()),
        };
        appending_store
            .append(exchange_id, &appending_entry, &record)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), hook.reached.notified())
        .await
        .expect("append did not reach the cancellation point");
    append_task.abort();
    assert!(append_task.await.unwrap_err().is_cancelled());

    store.record_replay_result(exchange_id, Ok(204)).await;
    let details = store.details(exchange_id).await.unwrap();
    let replay_results = details
        .records
        .iter()
        .filter_map(|record| match record {
            StoredRecord::ReplayResult { status, error } => Some((*status, error.clone())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(replay_results, vec![(Some(204), None)]);
    let committed_len = entry.file.lock().await.len;
    assert_eq!(
        tokio::fs::metadata(entry.path.as_ref())
            .await
            .unwrap()
            .len(),
        committed_len
    );
}

#[tokio::test]
async fn clear_prevents_an_in_flight_exchange_from_being_published_afterward() {
    let store = test_store();
    let hook = Arc::new(AppendTestHook::default());
    *store.0.append_test_hook.lock().await = Some(hook.clone());
    let request = Request::builder()
        .uri("http://example.test/in-flight-clear")
        .body(Body::empty())
        .unwrap();
    let parts = request.into_parts().0;

    let beginning_store = store.clone();
    let begin_task = tokio::spawn(async move { beginning_store.begin_exchange(&parts).await });
    tokio::time::timeout(Duration::from_secs(1), hook.reached.notified())
        .await
        .expect("exchange did not reach its provisional append");

    store.clear().await;
    hook.resume.notify_one();

    assert!(begin_task.await.unwrap().unwrap().is_none());
    assert!(
        store
            .snapshot(&CaptureFilter::default())
            .await
            .exchanges
            .is_empty()
    );
    store.0.temp_cleanup.flush().await;
    assert!(
        std::fs::read_dir(store.0.temp_dir.path())
            .unwrap()
            .next()
            .is_none()
    );
}

#[tokio::test]
async fn completing_oldest_connection_enforces_retention_limit() {
    let store = test_store_with_limits(1, 8, 1024);
    let first = store.begin_connection(None, "http");
    let second = store.begin_connection(None, "socks5");
    store.confirm_connection(first);
    store.confirm_connection(second);
    assert_eq!(
        store
            .snapshot(&CaptureFilter::default())
            .await
            .connections
            .len(),
        2
    );

    store.finish_connection(first);
    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert_eq!(snapshot.connections.len(), 1);
    assert_eq!(snapshot.connections[0].id, second);
    assert!(snapshot.connections[0].active);
}

#[tokio::test]
async fn active_connection_limit_declines_capture_without_blocking_the_connection() {
    let store = test_store_with_limits(1, 8, 1024);
    let first = store
        .begin_connection_if_enabled(None, "http", None)
        .expect("first connection should be captured");
    assert!(
        store
            .begin_connection_if_enabled(None, "http", None)
            .is_none(),
        "an active capture must make the next connection uncaptured"
    );
    assert_eq!(store.0.connections.read().entries.len(), 1);

    store.finish_connection(first);
    assert!(
        store
            .begin_connection_if_enabled(None, "http", None)
            .is_some(),
        "finishing the active connection must release capture capacity"
    );
}

#[tokio::test]
async fn active_exchange_limit_forwards_the_next_request_uncaptured() {
    let store = test_store_with_limits(8, 1, 1024);
    let first_request = Request::builder()
        .uri("http://example.test/active")
        .body(Body::empty())
        .unwrap();
    let first = store
        .begin_exchange(&first_request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    let forwarded = Arc::new(AtomicBool::new(false));
    let observing = forwarded.clone();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        move |request: Request| {
            let observing = observing.clone();
            async move {
                assert!(request.extensions().get_ref::<ExchangeId>().is_none());
                assert_eq!(
                    request.into_body().collect().await.unwrap().to_bytes(),
                    "forwarded"
                );
                observing.store(true, Ordering::Release);
                Ok::<_, Infallible>(Response::new(Body::from("response")))
            }
        },
    ));

    let response = service
        .serve(Request::new(Body::from("forwarded")))
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "response"
    );
    assert!(forwarded.load(Ordering::Acquire));
    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert_eq!(snapshot.exchanges.len(), 1);
    assert_eq!(snapshot.exchanges[0].id, first);
    assert!(snapshot.exchanges[0].active);
}

#[tokio::test]
async fn finishing_an_unused_connection_removes_it_from_the_inspector() {
    let store = test_store();
    let id = store.begin_connection(None, "http");
    store.finish_connection(id);
    assert!(store.0.connections.read().order.is_empty());
    assert_eq!(
        store
            .snapshot(&CaptureFilter::default())
            .await
            .total_connections,
        0
    );

    let socks = store.begin_connection(None, "socks5");
    store.confirm_connection(socks);
    store.finish_connection(socks);
    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert_eq!(snapshot.total_connections, 1);
    assert_eq!(snapshot.connections[0].id, socks);
    assert!(!snapshot.connections[0].active);
}

#[tokio::test]
async fn provisional_inspector_connections_do_not_emit_visible_changes() {
    let store = test_store();
    let mut changes = store.subscribe();

    let discarded = store.begin_connection(None, "classifying");
    store.set_connection_protocol(discarded, "http");
    assert!(store.discard_connection_if_empty(discarded));
    assert!(!changes.has_changed().unwrap());

    let closed = store.begin_connection(None, "classifying");
    store.set_connection_protocol(closed, "http");
    store.finish_connection(closed);
    assert!(!changes.has_changed().unwrap());

    let proxy = store.begin_connection(None, "classifying");
    store.confirm_connection(proxy);
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
}

#[tokio::test]
async fn visible_connection_numbers_ignore_discarded_inspector_sockets() {
    let store = test_store();
    let dashboard = store.begin_connection(None, "classifying");
    assert!(store.discard_connection_if_empty(dashboard));

    let first_proxy = store.begin_connection(None, "http");
    store.confirm_connection(first_proxy);
    let second_dashboard = store.begin_connection(None, "classifying");
    store.finish_connection(second_dashboard);
    let second_proxy = store.begin_connection(None, "https");
    store.confirm_connection(second_proxy);

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert_eq!(snapshot.connections.len(), 2);
    assert_eq!(snapshot.connections[0].id, second_proxy);
    assert_eq!(snapshot.connections[0].display_id, 2);
    assert_eq!(snapshot.connections[1].id, first_proxy);
    assert_eq!(snapshot.connections[1].display_id, 1);
}

#[tokio::test]
async fn cancelled_connection_service_is_finalized_by_lifecycle_guard() {
    let store = test_store();
    let confirming_store = store.clone();
    let service = ObserveConnectionLayer::new(store.clone(), "classifying").into_layer(
        rama::service::service_fn(move |input: rama::ServiceInput<tokio::io::DuplexStream>| {
            let confirming_store = confirming_store.clone();
            async move {
                let id = input.extensions().get_ref::<ConnectionId>().unwrap().0;
                confirming_store.confirm_connection(id);
                std::future::pending::<Result<(), Infallible>>().await
            }
        }),
    );
    let (client, _server) = tokio::io::duplex(64);

    tokio::time::timeout(
        Duration::from_millis(10),
        service.serve(rama::ServiceInput::new(client)),
    )
    .await
    .expect_err("pending connection service should time out");

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert_eq!(snapshot.connections.len(), 1);
    assert!(!snapshot.connections[0].active);
    assert!(snapshot.connections[0].ended_at.is_some());
}

#[tokio::test]
async fn websocket_capture_lifecycle_follows_the_relay_service_future() {
    let store = test_store();
    let connection_id = store.begin_connection(None, "http");
    store.confirm_connection(connection_id);
    let request = Request::builder()
        .uri("ws://example.test/socket")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .extension(ConnectionId(connection_id))
        .body(Body::empty())
        .unwrap();
    let (parts, _) = request.into_parts();
    let exchange_id = store.begin_exchange(&parts).await.unwrap().unwrap();
    let response = Response::builder()
        .status(rama::http::StatusCode::SWITCHING_PROTOCOLS)
        .body(Body::empty())
        .unwrap();
    let (response_parts, _) = response.into_parts();
    store
        .response_head(exchange_id, &response_parts)
        .await
        .unwrap();

    let connection = store
        .0
        .connections
        .read()
        .entries
        .get(&connection_id)
        .cloned()
        .unwrap();
    store.finish_connection(connection_id);
    assert!(connection.active.load(Ordering::SeqCst));
    let open = store.snapshot(&CaptureFilter::default()).await;
    assert!(open.connections[0].active);
    assert!(open.exchanges[0].active);

    let ingress = rama::ServiceInput::new(());
    let egress = rama::ServiceInput::new(());
    egress.extensions().insert(ExchangeId(exchange_id));
    let observing_store = store.clone();
    let service =
        CaptureWebSocketLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
            move |bridge: WebSocketBridge<rama::ServiceInput<()>, rama::ServiceInput<()>>| {
                let observing_store = observing_store.clone();
                async move {
                    assert_eq!(
                        bridge.ingress.extensions().get_ref::<ExchangeId>(),
                        Some(&ExchangeId(exchange_id))
                    );
                    let snapshot = observing_store.snapshot(&CaptureFilter::default()).await;
                    assert!(snapshot.exchanges[0].active);
                    Ok::<_, Infallible>(())
                }
            },
        ));
    service
        .serve(WebSocketBridge { ingress, egress })
        .await
        .unwrap();

    let closed = store.snapshot(&CaptureFilter::default()).await;
    assert!(!closed.connections[0].active);
    assert!(!closed.exchanges[0].active);
    assert!(closed.connections[0].ended_at.is_some());
    assert!(closed.exchanges[0].completed_at.is_some());
}

#[tokio::test]
async fn only_successful_websocket_responses_start_a_websocket_lifecycle() {
    let store = test_store();
    let ordinary_request = Request::builder()
        .uri("http://example.test/")
        .body(Body::empty())
        .unwrap();
    let ordinary_id = store
        .begin_exchange(&ordinary_request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    let ordinary = store.exchange(ordinary_id).unwrap();
    assert!(!successful_websocket_response(&ordinary, 200));

    let websocket_request = Request::builder()
        .uri("ws://example.test/socket")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .body(Body::empty())
        .unwrap();
    let websocket_id = store
        .begin_exchange(&websocket_request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    let websocket = store.exchange(websocket_id).unwrap();
    assert!(!successful_websocket_response(&websocket, 400));
    assert!(successful_websocket_response(&websocket, 101));
}

#[tokio::test]
async fn websocket_response_guard_finishes_when_the_relay_never_starts() {
    let store = test_store();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |_request: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(rama::http::StatusCode::SWITCHING_PROTOCOLS)
                    .body(Body::empty())
                    .unwrap(),
            )
        },
    ));
    let response = service
        .serve(
            Request::builder()
                .uri("ws://example.test/abandoned")
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let guard = response
        .extensions()
        .get_arc::<CaptureWebSocketExchangeGuard>()
        .expect("successful handshake response carries its lifecycle guard");

    assert!(store.snapshot(&CaptureFilter::default()).await.exchanges[0].active);
    drop(response);
    assert!(
        store.snapshot(&CaptureFilter::default()).await.exchanges[0].active,
        "the guard remains active while the upgrade task owns a cloned response extension"
    );
    drop(guard);

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert!(!snapshot.exchanges[0].active);
    assert!(snapshot.exchanges[0].completed_at.is_some());
}

#[tokio::test]
async fn concurrent_transport_and_websocket_completion_close_the_connection() {
    for iteration in 0..64 {
        let store = test_store();
        let connection_id = store.begin_connection(None, "http");
        store.confirm_connection(connection_id);
        let request = Request::builder()
            .uri(format!("ws://example.test/race/{iteration}"))
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .extension(ConnectionId(connection_id))
            .body(Body::empty())
            .unwrap();
        let exchange_id = store
            .begin_exchange(&request.into_parts().0)
            .await
            .unwrap()
            .unwrap();
        let connection = store
            .0
            .connections
            .read()
            .entries
            .get(&connection_id)
            .cloned()
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));

        let finish_transport = {
            let store = store.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store.finish_connection(connection_id);
            })
        };
        let finish_exchange = {
            let store = store.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store.finish_websocket_exchange(exchange_id);
            })
        };
        barrier.wait().await;
        finish_transport.await.unwrap();
        finish_exchange.await.unwrap();

        assert!(
            !connection.active.load(Ordering::SeqCst),
            "iteration {iteration} stranded an upgraded connection"
        );
    }
}

#[tokio::test]
async fn late_websocket_exchange_keeps_an_upgraded_connection_visibly_alive() {
    let store = test_store();
    let connection_id = store.begin_connection(None, "http");
    store.confirm_connection(connection_id);
    store.finish_connection(connection_id);

    let request = Request::builder()
        .uri("wss://example.test/late")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .extension(ConnectionId(connection_id))
        .extension(rama::tls::SecureTransport::default())
        .body(Body::empty())
        .unwrap();
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();

    let open = store.snapshot(&CaptureFilter::default()).await;
    assert!(open.connections[0].active);
    assert!(open.connections[0].ended_at.is_none());
    assert_eq!(open.exchanges[0].protocol, "wss");

    store.finish_websocket_exchange(exchange_id);
    let closed = store.snapshot(&CaptureFilter::default()).await;
    assert!(!closed.connections[0].active);
    assert_eq!(
        closed.connections[0].ended_at, closed.exchanges[0].completed_at,
        "the visible connection end follows the late WebSocket, not the earlier CONNECT service"
    );
}

#[tokio::test]
async fn completed_exchange_does_not_end_an_alive_transport_connection() {
    let store = test_store();
    let connection_id = store.begin_connection(None, "http");
    store.confirm_connection(connection_id);
    let request = Request::builder()
        .uri("http://example.test/complete")
        .extension(ConnectionId(connection_id))
        .body(Body::empty())
        .unwrap();
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    store
        .body_event(
            exchange_id,
            BodyDirection::Response,
            BodyCaptureEvent::End(CaptureOutcome::Complete),
        )
        .await;

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert!(snapshot.connections[0].active);
    assert!(snapshot.connections[0].ended_at.is_none());
}

#[tokio::test]
async fn cancelled_websocket_relay_finalizes_its_capture_guard() {
    let store = test_store();
    let request = Request::builder()
        .uri("ws://example.test/cancelled")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .body(Body::empty())
        .unwrap();
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    let response = Response::builder()
        .status(rama::http::StatusCode::SWITCHING_PROTOCOLS)
        .body(Body::empty())
        .unwrap();
    store
        .response_head(exchange_id, &response.into_parts().0)
        .await
        .unwrap();

    let ingress = rama::ServiceInput::new(());
    let egress = rama::ServiceInput::new(());
    egress.extensions().insert(ExchangeId(exchange_id));
    let service =
        CaptureWebSocketLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
            |_bridge: WebSocketBridge<rama::ServiceInput<()>, rama::ServiceInput<()>>| async {
                std::future::pending::<Result<(), Infallible>>().await
            },
        ));

    tokio::time::timeout(
        Duration::from_millis(10),
        service.serve(WebSocketBridge { ingress, egress }),
    )
    .await
    .expect_err("pending WebSocket relay should time out");

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert!(!snapshot.exchanges[0].active);
    assert!(snapshot.exchanges[0].completed_at.is_some());
}

#[tokio::test]
async fn active_oldest_connection_does_not_block_retiring_a_newer_one() {
    let store = test_store_with_limits(2, 8, 1024);
    let first = store.begin_connection(None, "http");
    let second = store.begin_connection(None, "https");
    store.confirm_connection(first);
    store.confirm_connection(second);
    store.finish_connection(second);
    let third = store.begin_connection(None, "socks5");
    store.confirm_connection(third);

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert_eq!(snapshot.connections.len(), 2);
    assert!(snapshot.connections.iter().any(|entry| entry.id == first));
    assert!(snapshot.connections.iter().any(|entry| entry.id == third));
    assert!(!snapshot.connections.iter().any(|entry| entry.id == second));
}

#[tokio::test]
async fn limited_snapshot_keeps_full_totals_without_cloning_every_row() {
    let store = test_store_with_limits(8, 8, 1024);
    let first = store.begin_connection(None, "http");
    let second = store.begin_connection(None, "https");
    let third = store.begin_connection(None, "socks5");
    store.confirm_connection(first);
    store.confirm_connection(second);
    store.confirm_connection(third);

    let snapshot = store
        .snapshot_limited(&CaptureFilter::default(), 2, 0)
        .await;
    assert_eq!(snapshot.total_connections, 3);
    assert_eq!(snapshot.connections.len(), 2);
    assert_eq!(snapshot.connections[0].id, third);
    assert_eq!(snapshot.connections[1].id, second);
    assert!(!snapshot.connections.iter().any(|entry| entry.id == first));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_frames_use_atomic_metrics_and_serialized_encrypted_writes() {
    const TASKS: usize = 32;
    const PAYLOAD: &[u8] = b"data";

    let store = test_store_with_limits(8, 8, 4096);
    let connection_id = store.begin_connection(None, "http");
    let request = Request::builder()
        .uri("http://example.test/concurrent")
        .body(Body::empty())
        .unwrap();
    request.extensions().insert(ConnectionId(connection_id));
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    let mut changes = store.subscribe();
    let before = *changes.borrow_and_update();

    let mut tasks = JoinSet::new();
    for _ in 0..TASKS {
        let store = store.clone();
        tasks.spawn(async move {
            store
                .body_event(
                    exchange_id,
                    BodyDirection::Request,
                    BodyCaptureEvent::Frame(rama::http::body::Frame::data(
                        rama::bytes::Bytes::from_static(PAYLOAD),
                    )),
                )
                .await;
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }

    tokio::time::timeout(Duration::from_secs(1), changes.changed())
        .await
        .expect("capture change notification timed out")
        .unwrap();
    assert_eq!(*changes.borrow_and_update() - before, TASKS as u64);
    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert_eq!(
        snapshot.connections[0].bytes_in,
        (TASKS * PAYLOAD.len()) as u64
    );
    assert_eq!(
        snapshot.exchanges[0].request_bytes,
        (TASKS * PAYLOAD.len()) as u64
    );
    let details = store.details(exchange_id).await.unwrap();
    assert_eq!(
        details
            .records
            .iter()
            .filter(|record| matches!(record, StoredRecord::RequestBody { .. }))
            .count(),
        TASKS
    );
}

#[tokio::test]
async fn active_oldest_exchange_does_not_block_retiring_a_newer_one() {
    let store = test_store_with_limits(8, 2, 1024);
    let request_parts = |path: &str| {
        Request::builder()
            .uri(format!("http://example.test/{path}"))
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0
    };
    let first = store
        .begin_exchange(&request_parts("first"))
        .await
        .unwrap()
        .unwrap();
    let second = store
        .begin_exchange(&request_parts("second"))
        .await
        .unwrap()
        .unwrap();
    store
        .body_event(
            second,
            BodyDirection::Response,
            BodyCaptureEvent::End(CaptureOutcome::Complete),
        )
        .await;
    let third = store
        .begin_exchange(&request_parts("third"))
        .await
        .unwrap()
        .unwrap();

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert_eq!(snapshot.exchanges.len(), 2);
    assert!(snapshot.exchanges.iter().any(|entry| entry.id == first));
    assert!(snapshot.exchanges.iter().any(|entry| entry.id == third));
    assert!(!snapshot.exchanges.iter().any(|entry| entry.id == second));
    store.details(second).await.unwrap_err();
}

#[tokio::test]
async fn filtered_limits_keep_exact_full_totals_and_connection_membership() {
    let store = test_store_with_limits(8, 8, 1024);
    let first = store.begin_connection(None, "http");
    let second = store.begin_connection(None, "http");
    let unrelated = store.begin_connection(None, "socks5");

    for (connection_id, path) in [(first, "matched-one"), (second, "matched-two")] {
        let request = Request::builder()
            .uri(format!("http://example.test/{path}"))
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ConnectionId(connection_id));
        store
            .begin_exchange(&request.into_parts().0)
            .await
            .unwrap()
            .unwrap();
    }

    let snapshot = store
        .snapshot_limited(
            &CaptureFilter {
                search: "matched".to_owned(),
                ..Default::default()
            },
            1,
            1,
        )
        .await;
    assert_eq!(snapshot.total_requests, 2);
    assert_eq!(snapshot.exchanges.len(), 1);
    assert_eq!(snapshot.total_connections, 2);
    assert_eq!(snapshot.active_connections, 2);
    assert_eq!(snapshot.connections.len(), 1);
    assert!(matches!(
        snapshot.connections[0].id,
        id if id == first || id == second
    ));
    assert_ne!(snapshot.connections[0].id, unrelated);
}

#[tokio::test]
async fn selected_connections_filter_exchanges_without_hiding_other_connections() {
    let store = test_store_with_limits(8, 8, 1024);
    let first = store.begin_connection(None, "http");
    let second = store.begin_connection(None, "socks5");

    for connection_id in [first, second] {
        let request = Request::builder()
            .uri(format!("http://example.test/{connection_id}"))
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ConnectionId(connection_id));
        store
            .begin_exchange(&request.into_parts().0)
            .await
            .unwrap()
            .unwrap();
    }

    let snapshot = store
        .snapshot_limited_for_connections(
            &CaptureFilter::default(),
            &BTreeSet::from([first]),
            0,
            8,
            8,
        )
        .await;
    assert_eq!(snapshot.total_connections, 2);
    assert_eq!(snapshot.connections.len(), 2);
    assert_eq!(snapshot.total_requests, 1);
    assert_eq!(snapshot.exchanges.len(), 1);
    assert_eq!(snapshot.exchanges[0].connection_id, first);

    let older_window = store
        .snapshot_limited_for_connections(&CaptureFilter::default(), &BTreeSet::new(), 1, 1, 8)
        .await;
    assert_eq!(older_window.total_connections, 2);
    assert_eq!(older_window.connections.len(), 1);
    assert_eq!(older_window.connections[0].id, first);

    let limited = store
        .snapshot_limited_for_connections(
            &CaptureFilter::default(),
            &BTreeSet::from([first, second]),
            0,
            8,
            1,
        )
        .await;
    assert_eq!(limited.total_requests, 2);
    assert_eq!(limited.exchanges.len(), 1);

    let structurally_filtered = store
        .snapshot_limited_for_connections(
            &CaptureFilter {
                connection_id: first.to_string(),
                ..Default::default()
            },
            &BTreeSet::from([first]),
            0,
            8,
            8,
        )
        .await;
    assert_eq!(structurally_filtered.total_connections, 1);
    assert_eq!(structurally_filtered.connections[0].id, first);
    assert_eq!(structurally_filtered.total_requests, 1);
    assert_eq!(structurally_filtered.exchanges[0].connection_id, first);
}

#[tokio::test]
async fn provisional_dashboard_connections_can_only_be_discarded_while_empty() {
    let store = test_store_with_limits(8, 8, 1024);
    let dashboard = store.begin_connection(None, "http");
    assert_eq!(
        store
            .snapshot(&CaptureFilter::default())
            .await
            .total_connections,
        0,
        "an accepted socket must stay hidden until classified as proxy traffic"
    );
    assert!(store.discard_connection_if_empty(dashboard));
    assert!(store.0.connections.read().order.is_empty());
    assert!(!store.discard_connection_if_empty(dashboard));
    store.finish_connection(dashboard);
    assert_eq!(
        store
            .snapshot(&CaptureFilter::default())
            .await
            .total_connections,
        0
    );

    let proxied = store.begin_connection(None, "http");
    let request = Request::builder()
        .uri("http://example.test/proxied")
        .body(Body::empty())
        .unwrap();
    request.extensions().insert(ConnectionId(proxied));
    store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    assert!(!store.discard_connection_if_empty(proxied));
    assert_eq!(
        store
            .snapshot(&CaptureFilter::default())
            .await
            .total_connections,
        1
    );
}

#[tokio::test]
async fn replay_reconstructs_relative_url_headers_and_captured_body() {
    let store = test_store();
    let request = Request::builder()
        .method("PATCH")
        .uri("/resource")
        .header("host", "example.test:8080")
        .header("x-replay", "yes")
        .body(Body::from("patch-body"))
        .unwrap();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
        },
    ));
    service
        .serve(request)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    let replay = store.replay_request(1).await.unwrap();
    assert_eq!(replay.method, "PATCH");
    assert_eq!(replay.url, "http://example.test:8080/resource");
    assert_eq!(replay.body, b"patch-body");
    assert!(
        replay
            .headers
            .iter()
            .any(|header| header == &("x-replay".to_owned(), "yes".to_owned()))
    );
}

#[tokio::test]
async fn replay_requires_one_complete_request_end_on_an_inactive_exchange() {
    let store = test_store_with_limits(8, 8, 1024);
    let request_parts = |path: &str| {
        Request::builder()
            .uri(format!("http://example.test/{path}"))
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0
    };

    let active = store
        .begin_exchange(&request_parts("active"))
        .await
        .unwrap()
        .unwrap();
    store
        .body_event(
            active,
            BodyDirection::Request,
            BodyCaptureEvent::End(CaptureOutcome::Complete),
        )
        .await;
    assert!(
        store
            .replay_request(active)
            .await
            .unwrap_err()
            .to_string()
            .contains("active")
    );

    for (path, outcome, expected) in [
        ("aborted", CaptureOutcome::Aborted, "aborted"),
        ("error", CaptureOutcome::Error, "error"),
    ] {
        let id = store
            .begin_exchange(&request_parts(path))
            .await
            .unwrap()
            .unwrap();
        store
            .body_event(id, BodyDirection::Request, BodyCaptureEvent::End(outcome))
            .await;
        store
            .body_event(
                id,
                BodyDirection::Response,
                BodyCaptureEvent::End(CaptureOutcome::Complete),
            )
            .await;
        assert!(
            store
                .replay_request(id)
                .await
                .unwrap_err()
                .to_string()
                .contains(expected)
        );
    }

    let missing = store
        .begin_exchange(&request_parts("missing"))
        .await
        .unwrap()
        .unwrap();
    store
        .body_event(
            missing,
            BodyDirection::Response,
            BodyCaptureEvent::End(CaptureOutcome::Complete),
        )
        .await;
    assert!(
        store
            .replay_request(missing)
            .await
            .unwrap_err()
            .to_string()
            .contains("completion record missing")
    );
}

#[test]
fn filter_is_case_insensitive_across_summary_fields() {
    let summary = ExchangeSummary {
        decision: None,
        id: 1,
        connection_id: 1,
        connection_display_id: 1,
        started_at: "1970-01-01T00:00:00Z".parse().unwrap(),
        method: "GET".to_owned(),
        http_version: "HTTP/1.1".to_owned(),
        url: "https://Example.Test/widgets".to_owned(),
        endpoint: "Example.Test".to_owned(),
        protocol: "HTTPS".to_owned(),
        ingress_local_address: None,
        ingress_peer_address: None,
        user_agent: Some("Rama Browser".to_owned()),
        user_agent_kind: None,
        status: Some(200),
        active: false,
        response_started_at: None,
        completed_at: None,
        egress_local_address: None,
        egress_peer_address: None,
        request_bytes: 0,
        response_bytes: 0,
        request_truncated: false,
        response_truncated: false,
        ja3: None,
        ja4: None,
        peetprint: None,
        ja4h: None,
        akamai_h2: None,
        known_fingerprint: None,
        has_emulation_profile: false,
    };
    assert!(
        CaptureFilter {
            search: "widgets".to_owned(),
            connection_id: "#1".to_owned(),
            user_agent: "rama".to_owned(),
            endpoint: "example".to_owned(),
            method: "get".to_owned(),
            status: "2xx".to_owned(),
            protocol: "https".to_owned(),
        }
        .matches_dimensions(&summary)
    );
    assert!(
        CaptureFilter {
            protocol: "http".to_owned(),
            ..Default::default()
        }
        .matches_dimensions(&ExchangeSummary {
            protocol: "http".to_owned(),
            ..summary.clone()
        })
    );
    assert!(
        !CaptureFilter {
            protocol: "http".to_owned(),
            ..Default::default()
        }
        .matches_dimensions(&summary),
        "HTTP must not accidentally match HTTPS"
    );
    assert!(
        CaptureFilter {
            protocol: "wss".to_owned(),
            ..Default::default()
        }
        .matches_dimensions(&ExchangeSummary {
            protocol: "wss".to_owned(),
            ..summary.clone()
        })
    );
    assert!(
        CaptureFilter {
            search: "widgets".to_owned(),
            ..Default::default()
        }
        .search_matches_summary(&summary)
    );

    for status in ["200", "2xx"] {
        assert!(matches_status(&summary, status), "status filter {status}");
    }
    for status in ["pending", "3xx", "4xx", "5xx", "404", "invalid"] {
        assert!(!matches_status(&summary, status), "status filter {status}");
    }
    assert!(matches_status(
        &ExchangeSummary {
            status: None,
            active: true,
            ..summary
        },
        "pending"
    ));
    assert!(matches_connection_id(1, "  #1 "));
    assert!(!matches_connection_id(1, "2"));
    assert!(!matches_connection_id(1, "not-a-number"));
    assert!(matches_protocol("ws", "ws"));
    assert!(matches_protocol("wss", "wss"));
    assert!(matches_protocol("grpc", "other"));
    assert!(!matches_protocol("https", "other"));
}

#[tokio::test]
async fn search_reads_encrypted_headers_and_payload_from_disk() {
    let store = test_store();
    let request = Request::builder()
        .method("POST")
        .uri("http://example.test/upload")
        .header("x-private-marker", "header-needle")
        .body(Body::from("payload-needle"))
        .unwrap();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
        },
    ));
    service
        .serve(request)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    for search in ["HEADER-NEEDLE", "payload-needle"] {
        let snapshot = store
            .snapshot(&CaptureFilter {
                search: search.to_owned(),
                ..Default::default()
            })
            .await;
        assert_eq!(snapshot.exchanges.len(), 1, "search {search:?}");
    }
    let snapshot = store
        .snapshot(&CaptureFilter {
            search: "absent-private-value".to_owned(),
            ..Default::default()
        })
        .await;
    assert_eq!(snapshot.total_requests, 0);
    assert!(snapshot.exchanges.is_empty());
    assert!(snapshot.connections.is_empty());

    let reads = store.0.record_reads.load(Ordering::Relaxed);
    let snapshot = store
        .snapshot(&CaptureFilter {
            search: "absent-private-value".to_owned(),
            ..Default::default()
        })
        .await;
    assert!(snapshot.exchanges.is_empty());
    assert_eq!(store.0.record_reads.load(Ordering::Relaxed), reads);
}

#[tokio::test]
async fn captured_tls_extensions_produce_actual_fingerprints_and_export_data() {
    const PROFILE_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";
    let database = Arc::new(UserAgentDatabase::try_embedded().unwrap());
    let client_hello = database
        .get_exact_header_str(PROFILE_UA)
        .unwrap()
        .tls
        .client_hello
        .clone();
    let store = CaptureStore::new(8, 8, 1024, database).unwrap();
    let request = Request::builder()
        .uri("https://example.test/")
        .header("user-agent", PROFILE_UA)
        .header("sec-fetch-mode", "navigate")
        .extension(SecureTransport::with_client_hello(client_hello))
        .extension(NegotiatedTlsParameters {
            protocol_version: rama::tls::ProtocolVersion::TLSv1_3,
            application_layer_protocol: Some(rama::net::tls::ApplicationProtocol::HTTP_2),
            peer_certificate_chain: None,
        })
        .body(Body::empty())
        .unwrap();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |_request: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .extension(NegotiatedTlsParameters {
                        protocol_version: rama::tls::ProtocolVersion::TLSv1_2,
                        application_layer_protocol: Some(
                            rama::net::tls::ApplicationProtocol::HTTP_11,
                        ),
                        peer_certificate_chain: None,
                    })
                    .body(Body::empty())
                    .unwrap(),
            )
        },
    ));
    service
        .serve(request)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    let details = store.details(1).await.unwrap();
    assert!(details.summary.ja3.is_some());
    assert!(details.summary.ja4.is_some());
    assert!(details.summary.peetprint.is_some());
    assert!(details.summary.ja4h.is_some());
    assert!(details.summary.known_fingerprint.is_some());
    assert!(details.records.iter().any(|record| matches!(
        record,
        StoredRecord::RequestHead {
            ingress_tls: Some(value),
            ..
        } if value.protocol_version == rama::tls::ProtocolVersion::TLSv1_3
            && value.application_layer_protocol
                == Some(rama::net::tls::ApplicationProtocol::HTTP_2)
    )));
    assert!(details.records.iter().any(|record| matches!(
        record,
        StoredRecord::ResponseHead {
            egress_tls: Some(value),
            ..
        } if value.protocol_version == rama::tls::ProtocolVersion::TLSv1_2
            && value.application_layer_protocol
                == Some(rama::net::tls::ApplicationProtocol::HTTP_11)
    )));
    let profile = captured_emulation_profile(&details).unwrap().unwrap();
    assert!(profile.tls_client_hello.is_some());
    assert!(profile.h1_settings.is_some());
    assert!(profile.h1_headers_navigate.is_some());
    assert!(profile.h2_settings.is_none());
    let serialized = serde_json::to_value(profile).unwrap();
    assert!(serialized.get("connection_id").is_none());
    assert!(serialized.get("request_id").is_none());
    assert!(serialized.get("fingerprints").is_none());
}

#[tokio::test]
async fn export_profiles_contains_only_observed_capture_data() {
    const PROFILE_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";
    let store = test_store();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |_request: Request| Ok::<_, Infallible>(Response::new(Body::empty())),
    ));
    service
        .serve(
            Request::builder()
                .uri("http://example.test/")
                .header("user-agent", PROFILE_UA)
                .header("sec-fetch-mode", "navigate")
                .extension(ConnectionId(7))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    service
        .serve(
            Request::builder()
                .uri("http://example.test/no-user-agent")
                .extension(ConnectionId(7))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    service
        .serve(
            Request::builder()
                .uri("http://example.test/latest-profile")
                .header("user-agent", PROFILE_UA)
                .header("sec-fetch-mode", "navigate")
                .extension(ConnectionId(7))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    let export = store
        .export_profiles(&BTreeSet::from([1, 2, 999]), &BTreeSet::new())
        .await
        .unwrap();
    let profiles = export.as_array().unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0]["uastr"], PROFILE_UA);
    assert!(profiles[0]["h1_settings"].is_object());
    assert!(profiles[0]["h1_headers_navigate"].is_array());
    assert!(profiles[0]["h2_settings"].is_null());
    assert!(profiles[0].get("connection_id").is_none());
    assert!(profiles[0].get("request_id").is_none());
    assert!(profiles[0].get("profile").is_none());
    assert!(profiles[0].get("fingerprints").is_none());

    let connection_export = store
        .export_profiles(&BTreeSet::new(), &BTreeSet::from([7]))
        .await
        .unwrap();
    assert_eq!(connection_export.as_array().unwrap().len(), 1);
    assert_eq!(connection_export[0]["uastr"], PROFILE_UA);

    let combined = store
        .export_profiles(&BTreeSet::from([1]), &BTreeSet::from([7]))
        .await
        .unwrap();
    assert_eq!(combined.as_array().unwrap().len(), 1);
}

#[test]
fn profile_export_does_not_guess_an_unobserved_request_initiator() {
    let (parts, _) = Request::builder()
        .uri("http://example.test/data")
        .header("user-agent", "curl/8.7.1")
        .body(())
        .unwrap()
        .into_parts();
    let profile: UserAgentProfileInput = serde_json::from_value(
        captured_profile(&parts, Some("curl/8.7.1"), None, None, false).unwrap(),
    )
    .unwrap();

    assert!(profile.h1_settings.is_some());
    assert!(profile.h1_headers_navigate.is_none());
    assert!(profile.h1_headers_fetch.is_none());
    assert!(profile.h1_headers_xhr.is_none());
    assert!(profile.h1_headers_form.is_none());
    assert!(profile.h1_headers_ws.is_none());
}

#[test]
fn h2_extended_connect_is_exported_as_websocket_observation() {
    let (parts, _) = Request::builder()
        .method(rama::http::Method::CONNECT)
        .version(rama::http::Version::HTTP_2)
        .uri("https://example.test/socket")
        .header("user-agent", "example/1")
        .extension(rama::http::proto::h2::ext::Protocol::from_static(
            "websocket",
        ))
        .body(())
        .unwrap()
        .into_parts();

    assert!(is_websocket_handshake(&parts));
    let profile: UserAgentProfileInput = serde_json::from_value(
        captured_profile(&parts, Some("example/1"), None, None, true).unwrap(),
    )
    .unwrap();
    assert!(profile.h2_headers_ws.is_some());
    assert!(profile.h2_headers_navigate.is_none());

    let (wrong_method, _) = Request::builder()
        .method(rama::http::Method::GET)
        .version(rama::http::Version::HTTP_2)
        .uri("https://example.test/socket")
        .extension(rama::http::proto::h2::ext::Protocol::from_static(
            "websocket",
        ))
        .body(())
        .unwrap()
        .into_parts();
    assert!(!is_websocket_handshake(&wrong_method));

    let (missing_protocol, _) = Request::builder()
        .method(rama::http::Method::CONNECT)
        .version(rama::http::Version::HTTP_2)
        .uri("https://example.test/socket")
        .body(())
        .unwrap()
        .into_parts();
    assert!(!is_websocket_handshake(&missing_protocol));
}

#[tokio::test]
async fn successful_h2_extended_connect_stays_active_until_the_websocket_relay_finishes() {
    let store = test_store();
    let request = Request::builder()
        .method(rama::http::Method::CONNECT)
        .version(rama::http::Version::HTTP_2)
        .uri("https://example.test/socket")
        .extension(rama::http::proto::h2::ext::Protocol::from_static(
            "websocket",
        ))
        .body(Body::empty())
        .unwrap();
    let exchange_id = store
        .begin_exchange(&request.into_parts().0)
        .await
        .unwrap()
        .unwrap();
    let response = Response::builder()
        .version(rama::http::Version::HTTP_2)
        .status(rama::http::StatusCode::OK)
        .body(Body::empty())
        .unwrap();
    store
        .response_head(exchange_id, &response.into_parts().0)
        .await
        .unwrap();
    let guard = store
        .websocket_exchange_guard_for_response(exchange_id, 200)
        .expect("successful h2 extended CONNECT owns a WebSocket lifecycle guard");
    store
        .body_event(
            exchange_id,
            BodyDirection::Response,
            BodyCaptureEvent::End(CaptureOutcome::Complete),
        )
        .await;

    assert!(store.snapshot(&CaptureFilter::default()).await.exchanges[0].active);
    drop(guard);
    assert!(!store.snapshot(&CaptureFilter::default()).await.exchanges[0].active);
}

#[test]
fn captured_header_values_round_trip_binary_bytes_and_reserved_prefix_text() {
    let mut headers = HeaderMap::new();
    headers.insert("x-binary", HeaderValue::from_bytes(&[0x80, b'a']).unwrap());
    headers.insert(
        "x-prefix",
        HeaderValue::from_static("rama-capture-base64:not-encoded-text"),
    );

    for (name, encoded) in headers_to_vec(&headers) {
        let restored = captured_header_value(&encoded).unwrap();
        assert_eq!(restored, headers[name.as_str()]);
    }
}

// These tests assert forwarding boundaries, rather than the controller's implementation.
#[derive(Debug)]
struct ApprovalBody {
    polls: Arc<AtomicUsize>,
    bytes: Option<Bytes>,
}
impl StreamingBody for ApprovalBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<rama::http::body::Frame<Bytes>, Infallible>>> {
        self.polls.fetch_add(1, Ordering::Relaxed);
        std::task::Poll::Ready(
            self.bytes
                .take()
                .map(|bytes| Ok(rama::http::body::Frame::data(bytes))),
        )
    }
}
async fn approval_id(store: &CaptureStore, direction: &str) -> u64 {
    let control = store.control();
    let mut changes = control.subscribe();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = serde_json::to_value(control.snapshot()).unwrap();
            if let Some(message) = snapshot["pending"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["direction"] == direction)
            {
                return message["id"].as_u64().unwrap();
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .expect("approval did not arrive")
}

#[tokio::test]
async fn approval_holds_heads_without_polling_bodies_and_preserves_header_edits() {
    use super::super::control::{Config, Decision};
    let store = test_store();
    store
        .control()
        .configure(
            0,
            Config {
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
    let request_polls = Arc::new(AtomicUsize::new(0));
    let response_polls = Arc::new(AtomicUsize::new(0));
    let called = Arc::new(AtomicUsize::new(0));
    let service =
        CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn({
            let called = called.clone();
            let response_polls = response_polls.clone();
            move |request: Request| {
                let called = called.clone();
                let response_polls = response_polls.clone();
                async move {
                    called.fetch_add(1, Ordering::Relaxed);
                    assert_eq!(request.headers().get_all("x-edit").iter().count(), 2);
                    assert_eq!(
                        request.into_body().collect().await.unwrap().to_bytes(),
                        "request body"
                    );
                    Ok::<_, Infallible>(Response::new(ApprovalBody {
                        polls: response_polls,
                        bytes: Some(Bytes::from_static(b"response body")),
                    }))
                }
            }
        }));
    let task = tokio::spawn({
        let polls = request_polls.clone();
        async move {
            service
                .serve(
                    Request::builder()
                        .uri("https://example.test/")
                        .body(ApprovalBody {
                            polls,
                            bytes: Some(Bytes::from_static(b"request body")),
                        })
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    });
    let id = approval_id(&store, "request").await;
    assert_eq!(called.load(Ordering::Relaxed), 0);
    assert_eq!(request_polls.load(Ordering::Relaxed), 0);
    store
        .control()
        .resolve(
            id,
            Decision::Forward {
                headers: Some(vec![
                    ("x-edit".into(), "one".into()),
                    ("x-edit".into(), "two".into()),
                ]),
                status: None,
                payload: None,
            },
        )
        .unwrap();
    let id = approval_id(&store, "response").await;
    assert_eq!(called.load(Ordering::Relaxed), 1);
    assert_eq!(response_polls.load(Ordering::Relaxed), 0);
    assert!(!task.is_finished());
    store
        .control()
        .resolve(
            id,
            Decision::Forward {
                headers: Some(vec![("x-result".into(), "edited".into())]),
                status: Some(201),
                payload: None,
            },
        )
        .unwrap();
    let response = task.await.unwrap();
    assert_eq!(response.status().as_u16(), 201);
    assert_eq!(response.headers()["x-result"], "edited");
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "response body"
    );
    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    let details = store.details(snapshot.exchanges[0].id).await.unwrap();
    assert_eq!(
        details
            .records
            .iter()
            .filter(|r| matches!(r, StoredRecord::Interception { .. }))
            .count(),
        2
    );
    let replay = store
        .replay_request(snapshot.exchanges[0].id)
        .await
        .unwrap();
    assert_eq!(
        replay
            .headers
            .iter()
            .filter(|(name, _)| name == "x-edit")
            .count(),
        2
    );
}

#[tokio::test]
async fn blocking_without_capture_admission_never_calls_origin_or_polls_upload() {
    use super::super::control::{Config, Decision};
    let store = test_store_with_total_limit(1, 1, 1);
    store
        .control()
        .configure(
            0,
            Config {
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
    let polls = Arc::new(AtomicUsize::new(0));
    let called = Arc::new(AtomicUsize::new(0));
    let service =
        CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn({
            let called = called.clone();
            move |_: Request| {
                called.fetch_add(1, Ordering::Relaxed);
                async { Ok::<_, Infallible>(Response::new(Body::empty())) }
            }
        }));
    let task = tokio::spawn({
        let polls = polls.clone();
        async move {
            service
                .serve(
                    Request::builder()
                        .method("POST")
                        .uri("http://example.test/upload")
                        .body(ApprovalBody {
                            polls,
                            bytes: Some(Bytes::from_static(b"secret body")),
                        })
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    });
    let id = approval_id(&store, "request").await;
    assert!(
        store
            .snapshot(&CaptureFilter::default())
            .await
            .exchanges
            .is_empty()
    );
    store.control().resolve(id, Decision::Block).unwrap();
    let response = task.await.unwrap();
    assert_eq!(response.status().as_u16(), 403);
    assert_eq!(response.headers()["connection"], "close");
    assert_eq!(called.load(Ordering::Relaxed), 0);
    assert_eq!(polls.load(Ordering::Relaxed), 0);
    assert!(store.control().snapshot().pending.is_empty());
}

#[tokio::test]
async fn paused_inspector_forwards_without_capturing_or_holding() {
    use super::super::control::Config;
    let store = test_store();
    store
        .control()
        .configure(
            0,
            Config {
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
    store.inspection_state().pause().await;
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
        async |_: Request| Ok::<_, Infallible>(Response::new(Body::empty())),
    ));
    let task = tokio::spawn(async move {
        service
            .serve(
                Request::builder()
                    .uri("http://example.test/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    });
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert!(store.control().snapshot().pending.is_empty());
    assert!(
        store
            .snapshot(&CaptureFilter::default())
            .await
            .exchanges
            .is_empty()
    );
}

#[tokio::test]
async fn http2_blocking_and_connection_release_preserve_sibling_streams() {
    use super::super::control::{Config, ControlConnection, Decision, ResponseSpec};
    use rama::{
        http::{Version, client::http_connect, core::h2, proxy::mitm::HttpMitmRelay},
        io::BridgeIo,
        layer::ArcLayer,
        net::test_utils::client::MockSocket,
        rt::Executor,
    };
    let store = test_store();
    let control = store.control();
    control
        .configure(
            0,
            Config {
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
    let (client_io, ingress_io) = tokio::io::duplex(64 * 1024);
    let (egress_io, origin_io) = tokio::io::duplex(64 * 1024);
    let calls = Arc::new(AtomicUsize::new(0));
    let origin_calls = calls.clone();
    let origin = tokio::spawn(async move {
        let mut connection = h2::server::handshake(MockSocket::new(origin_io))
            .await
            .unwrap();
        while let Some(Ok((_, mut reply))) = connection.accept().await {
            origin_calls.fetch_add(1, Ordering::Relaxed);
            reply
                .send_response(
                    Response::builder()
                        .header("x-upstream", "yes")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
        }
    });
    let ingress = MockSocket::new(ingress_io);
    let id = store.begin_connection(None, "https");
    ingress.extensions().insert(ConnectionId(id));
    ingress.extensions().insert(ControlConnection::new(id));
    let middleware = CaptureHttpLayer::new(Some(store.clone()));
    let relay = tokio::spawn(async move {
        Box::pin(
            HttpMitmRelay::new(Executor::default())
                .with_http_middleware((middleware, ArcLayer::new()))
                .serve(BridgeIo(ingress, MockSocket::new(egress_io))),
        )
        .await
        .unwrap();
    });
    let request = |path: &str| {
        Request::builder()
            .uri(format!("https://origin.test/{path}"))
            .version(Version::HTTP_2)
            .body(Body::empty())
            .unwrap()
    };
    let conn = Arc::new(
        http_connect(
            MockSocket::new(client_io),
            request("setup"),
            Executor::default(),
        )
        .await
        .unwrap()
        .conn,
    );
    let first_conn = conn.clone();
    let first_request = request("blocked");
    let first = tokio::spawn(async move { first_conn.serve(first_request).await.unwrap() });
    let first_id = approval_id(&store, "request").await;
    let second_conn = conn.clone();
    let second_request = request("replacement");
    let second = tokio::spawn(async move { second_conn.serve(second_request).await.unwrap() });
    let mut changes = control.subscribe();
    tokio::time::timeout(Duration::from_secs(3), async {
        while control.snapshot().pending.len() != 2 {
            changes.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    control.resolve(first_id, Decision::Block).unwrap();
    let response = first.await.unwrap();
    assert_eq!(response.status().as_u16(), 403);
    assert!(!response.headers().contains_key("connection"));
    response.into_body().collect().await.unwrap();
    assert!(!second.is_finished());
    let second_id = approval_id(&store, "request").await;
    assert_eq!(control.pending(second_id).unwrap().connection, id);
    control.resolve(second_id, Decision::forward()).unwrap();
    let response_id = approval_id(&store, "response").await;
    control
        .resolve(
            response_id,
            Decision::Respond {
                response: ResponseSpec::error(503, "locally replaced"),
            },
        )
        .unwrap();
    let response = second.await.unwrap();
    assert_eq!(response.status().as_u16(), 503);
    assert!(!response.headers().contains_key("connection"));
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "locally replaced"
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let third_conn = conn.clone();
    let third_request = request("release");
    let third = tokio::spawn(async move { third_conn.serve(third_request).await.unwrap() });
    let id = approval_id(&store, "request").await;
    control
        .resolve(
            id,
            Decision::Connection {
                headers: None,
                status: None,
                payload: None,
            },
        )
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), third)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.headers()["x-upstream"], "yes");
    response.into_body().collect().await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), conn.serve(request("future")))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    response.into_body().collect().await.unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 3);
    assert!(control.snapshot().pending.is_empty());
    drop(conn);
    relay.abort();
    origin.abort();
}
