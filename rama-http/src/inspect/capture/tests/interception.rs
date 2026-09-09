use super::*;
use crate::inspect::control::{Config, Decision};

#[tokio::test]
async fn active_connection_limit_declines_capture_without_blocking_the_connection() {
    let store = test_store_with_limits(1, 8, rama_utils::octets::kib_u64(1));
    let first = store
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .expect("first connection should be captured");
    assert!(
        store
            .begin_connection_if_enabled(None, Protocol::HTTP, None)
            .is_none(),
        "an active capture must make the next connection uncaptured"
    );
    assert_eq!(store.0.connections.read().entries.len(), 1);

    store.finish_connection(first);
    assert!(
        store
            .begin_connection_if_enabled(None, Protocol::HTTP, None)
            .is_some(),
        "finishing the active connection must release capture capacity"
    );
}

#[tokio::test]
async fn approval_holds_heads_without_polling_bodies_and_preserves_header_edits() {
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
        CaptureHttpLayer::new(Some(store.clone())).into_layer(rama_core::service::service_fn({
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
    let id = approval_id(&store, rama_inspect::Direction::Ingress).await;
    assert_eq!(called.load(Ordering::Relaxed), 0);
    assert_eq!(request_polls.load(Ordering::Relaxed), 0);
    store
        .control()
        .resolve(
            id,
            Decision::Forward {
                headers: Some(
                    serde_json::from_value(serde_json::json!([
                        ("x-edit", "one"),
                        ("x-edit", "two"),
                    ]))
                    .unwrap(),
                ),
                status: None,
                payload: None,
            },
        )
        .unwrap();
    let id = approval_id(&store, rama_inspect::Direction::Egress).await;
    assert_eq!(called.load(Ordering::Relaxed), 1);
    assert_eq!(response_polls.load(Ordering::Relaxed), 0);
    assert!(!task.is_finished());
    store
        .control()
        .resolve(
            id,
            Decision::Forward {
                headers: Some(
                    serde_json::from_value(serde_json::json!([("x-result", "edited")])).unwrap(),
                ),
                status: Some(StatusCode::CREATED),
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
        CaptureHttpLayer::new(Some(store.clone())).into_layer(rama_core::service::service_fn({
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
    let id = approval_id(&store, rama_inspect::Direction::Ingress).await;
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
    let service =
        CaptureHttpLayer::new(Some(store.clone())).into_layer(rama_core::service::service_fn(
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
