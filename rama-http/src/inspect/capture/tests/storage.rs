use rama_core::futures::FutureExt as _;

use super::*;

#[tokio::test]
async fn inspector_metadata_is_body_free_and_body_streams_with_a_limit() {
    let store = test_store_with_limits(8, 8, rama_utils::octets::kib_u64(4));
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
        rama_core::service::service_fn(async |request: Request| {
            assert_eq!(
                request.into_body().collect().await.unwrap().to_bytes(),
                "request-stream"
            );
            Ok::<_, Infallible>(Response::new(Body::from("response-stream")))
        }),
    );
    service
        .serve(Request::new(Body::from("request-stream")))
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    let details = store.inspector_details(1).await.unwrap();
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
async fn exhausted_total_budget_abandons_a_new_capture_without_failing_traffic() {
    let store = test_store_with_total_limit(8, rama_utils::octets::kib_u64(1), 8);
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
async fn total_budget_charges_committed_records_and_releases_evicted_entries() {
    let store = test_store_with_total_limit(
        1,
        rama_utils::octets::kib_u64(1),
        rama_utils::octets::kib_u64(4),
    );
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
    let first_file_len = first_entry.stored_bytes.load(Ordering::Acquire);
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
    let second_file_len = second_entry.stored_bytes.load(Ordering::Acquire);
    assert_eq!(store.0.budget.used.load(Ordering::Acquire), second_file_len);
    drop(second_entry);

    store.clear().await;
    assert_eq!(store.0.budget.used.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn selected_exchange_remains_readable_after_retention_evicts_it() {
    let store = test_store_with_limits(8, 1, rama_utils::octets::kib_u64(1));
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
async fn clearing_capture_state_removes_summaries() {
    let store = test_store();
    let connection_id =
        store.begin_connection_labeled(None, Protocol::HTTP, Some("clear-test".to_owned()));
    store.confirm_connection(connection_id);
    let service =
        CaptureHttpLayer::new(Some(store.clone())).into_layer(rama_core::service::service_fn(
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

    store.clear().await;

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert!(snapshot.connections.is_empty());
    assert!(snapshot.exchanges.is_empty());
}

#[tokio::test]
async fn body_capture_limit_does_not_limit_forwarded_traffic() {
    let store = test_store_with_limits(8, 8, 4);
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
        rama_core::service::service_fn(async |request: Request| {
            assert_eq!(
                request.into_body().collect().await.unwrap().to_bytes(),
                "request-body"
            );
            Ok::<_, Infallible>(Response::new(Body::from("response-body")))
        }),
    );

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
        StoredRecord::RequestEnd { outcome } if *outcome == CaptureOutcome::Complete
    )));
    assert!(details.records.iter().any(|record| matches!(
        record,
        StoredRecord::ResponseEnd { outcome } if *outcome == CaptureOutcome::Complete
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
    let connection_id = store.begin_connection(None, Protocol::HTTP);
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
        BodyCaptureEvent::Frame(crate::body::Frame::data(Bytes::from_static(value)))
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
async fn failed_upstream_response_finishes_the_capture_as_an_error() {
    let store = test_store();
    let service =
        CaptureHttpLayer::new(Some(store.clone())).into_layer(rama_core::service::service_fn(
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
        StoredRecord::ResponseEnd { outcome } if *outcome == CaptureOutcome::Error
    )));
}

#[tokio::test]
async fn cancelled_http_service_finalizes_its_active_exchange() {
    let store = test_store();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered_tx = Arc::new(parking_lot::Mutex::new(Some(entered_tx)));
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
        rama_core::service::service_fn(move |_request: Request| {
            let entered_tx = entered_tx.clone();
            async move {
                entered_tx.lock().take().unwrap().send(()).unwrap();
                std::future::pending::<Result<Response<Body>, Infallible>>().await
            }
        }),
    );

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
async fn cancelled_append_is_not_published_in_capture_indexes() {
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
            .append(exchange_id, &appending_entry, record)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), hook.reached.notified())
        .await
        .expect("append did not reach the cancellation point");

    // Reads retain their own capability while the writer is locked in an append.
    let details =
        tokio::time::timeout(Duration::from_secs(1), store.inspector_details(exchange_id))
            .await
            .expect("reading committed metadata waited for the blocked writer")
            .unwrap();
    assert_eq!(details.records.len(), 1);
    assert!(matches!(
        details.records[0],
        StoredRecord::RequestHead { .. }
    ));

    // A second append must wait for that writer, then make progress when the
    // cancelled operation releases it. Its reservation must survive the wait.
    let next_append = store.record_replay_result(exchange_id, Ok(StatusCode::NO_CONTENT));
    tokio::pin!(next_append);
    assert!(next_append.as_mut().now_or_never().is_none());
    append_task.abort();
    assert!(append_task.await.unwrap_err().is_cancelled());

    next_append.await;
    let details = store.details(exchange_id).await.unwrap();
    let replay_results = details
        .records
        .iter()
        .filter_map(|record| match record {
            StoredRecord::ReplayResult { status, error } => Some((*status, error.clone())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(replay_results, vec![(Some(StatusCode::NO_CONTENT), None)]);
    assert_eq!(entry.records.read().len(), 2);
    assert_eq!(store.0.budget.records.load(Ordering::Acquire), 2);
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
}

#[tokio::test]
async fn active_exchange_limit_forwards_the_next_request_uncaptured() {
    let store = test_store_with_limits(8, 1, rama_utils::octets::kib_u64(1));
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
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
        rama_core::service::service_fn(move |request: Request| {
            let observing = observing.clone();
            async move {
                assert!(request.extensions().get_ref::<HttpExchangeId>().is_none());
                assert_eq!(
                    request.into_body().collect().await.unwrap().to_bytes(),
                    "forwarded"
                );
                observing.store(true, Ordering::Release);
                Ok::<_, Infallible>(Response::new(Body::from("response")))
            }
        }),
    );

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_frames_use_atomic_metrics_and_serialized_storage_writes() {
    const TASKS: usize = 32;
    const PAYLOAD: &[u8] = b"data";

    let store = test_store_with_limits(8, 8, rama_utils::octets::kib_u64(4));
    let connection_id = store.begin_connection(None, Protocol::HTTP);
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
    let mut changes = store.subscribe_changes();
    let before = *changes.borrow_and_update();

    let mut tasks = JoinSet::new();
    for _ in 0..TASKS {
        let store = store.clone();
        tasks.spawn(async move {
            store
                .body_event(
                    exchange_id,
                    BodyDirection::Request,
                    BodyCaptureEvent::Frame(crate::body::Frame::data(
                        rama_core::bytes::Bytes::from_static(PAYLOAD),
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
    let store = test_store_with_limits(8, 2, rama_utils::octets::kib_u64(1));
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

#[test]
fn native_header_serde_preserves_order_duplicates_and_binary_values() {
    let mut headers = crate::HeaderMap::new();
    headers.append(
        "x-text",
        crate::HeaderValue::from_static("rama-capture-base64:not-an-encoding"),
    );
    headers.append(
        "x-binary",
        crate::HeaderValue::from_bytes(&[0xff, 0x80]).unwrap(),
    );
    headers.append("x-text", crate::HeaderValue::from_static("second"));
    let encoded = serde_json::to_vec(&headers).unwrap();
    let decoded: crate::HeaderMap = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(
        headers.ordered_iter().collect::<Vec<_>>(),
        decoded.ordered_iter().collect::<Vec<_>>()
    );
}
