use rama_core::error::BoxErrorExt as _;
use rama_inspect::storage::{Collection, ListRecords, MemoryStore, ReadRecord, Reader};

use super::*;

#[tokio::test]
async fn limited_snapshot_keeps_full_totals_without_cloning_every_row() {
    let store = test_store_with_limits(8, 8, rama_utils::octets::kib_u64(1));
    let first = store.begin_connection(None, Protocol::HTTP);
    let second = store.begin_connection(None, Protocol::HTTPS);
    let third = store.begin_connection(None, Protocol::SOCKS5);
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

#[tokio::test]
async fn filtered_limits_keep_exact_full_totals_and_connection_membership() {
    let store = test_store_with_limits(8, 8, rama_utils::octets::kib_u64(1));
    let first = store.begin_connection(None, Protocol::HTTP);
    let second = store.begin_connection(None, Protocol::HTTP);
    let unrelated = store.begin_connection(None, Protocol::SOCKS5);

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
                search: "matched".into(),
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
    let store = test_store_with_limits(8, 8, rama_utils::octets::kib_u64(1));
    let first = store.begin_connection(None, Protocol::HTTP);
    let second = store.begin_connection(None, Protocol::SOCKS5);

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
                connection_id: FilterValue::Value(ConnectionQuery(first)),
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

#[test]
fn filter_is_case_insensitive_across_summary_fields() {
    let summary = HttpExchangeSummary {
        decision: None,
        id: 1,
        connection_id: 1,
        connection_display_id: 1,
        started_at: "1970-01-01T00:00:00Z".parse().unwrap(),
        method: Method::GET,
        http_version: Version::HTTP_11,
        url: "https://Example.Test/widgets".parse().unwrap(),
        endpoint: Some("Example.Test".parse().unwrap()),
        protocol: Protocol::HTTPS,

        user_agent: Some(HeaderValue::from_static("Rama Browser")),

        status: Some(StatusCode::OK),
        active: false,
        response_started_at: None,
        completed_at: None,

        request_bytes: 0,
        response_bytes: 0,
        request_truncated: false,
        response_truncated: false,

        ja4h: None,
        metadata: CaptureMetadata::default(),
    };
    assert!(
        CaptureFilter {
            search: "widgets".into(),
            connection_id: "#1".into(),
            user_agent: "rama".into(),
            endpoint: "example".into(),
            method: "get".into(),
            status: "2xx".into(),
            protocol: "https".into(),
        }
        .matches_dimensions(&summary)
    );
    assert!(
        CaptureFilter {
            protocol: "http".into(),
            ..Default::default()
        }
        .matches_dimensions(&HttpExchangeSummary {
            protocol: Protocol::HTTP,
            ..summary.clone()
        })
    );
    assert!(
        !CaptureFilter {
            protocol: "http".into(),
            ..Default::default()
        }
        .matches_dimensions(&summary),
        "HTTP must not accidentally match HTTPS"
    );
    assert!(
        CaptureFilter {
            protocol: "wss".into(),
            ..Default::default()
        }
        .matches_dimensions(&HttpExchangeSummary {
            protocol: Protocol::WSS,
            ..summary.clone()
        })
    );
    assert!(
        CaptureFilter {
            search: "widgets".into(),
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
        &HttpExchangeSummary {
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
async fn search_reads_headers_and_payload_from_storage() {
    let store = test_store();
    let request = Request::builder()
        .method("POST")
        .uri("http://example.test/upload")
        .header("x-private-marker", "header-needle")
        .body(Body::from("payload-needle"))
        .unwrap();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
        rama_core::service::service_fn(async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }),
    );
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
                search: search.into(),
                ..Default::default()
            })
            .await;
        assert_eq!(snapshot.exchanges.len(), 1, "search {search:?}");
    }
    let snapshot = store
        .snapshot(&CaptureFilter {
            search: "absent-private-value".into(),
            ..Default::default()
        })
        .await;
    assert_eq!(snapshot.total_requests, 0);
    assert!(snapshot.exchanges.is_empty());
    assert!(snapshot.connections.is_empty());

    let reads = store.0.record_reads.load(Ordering::Relaxed);
    let snapshot = store
        .snapshot(&CaptureFilter {
            search: "absent-private-value".into(),
            ..Default::default()
        })
        .await;
    assert!(snapshot.exchanges.is_empty());
    assert_eq!(store.0.record_reads.load(Ordering::Relaxed), reads);
}

#[tokio::test]
async fn active_search_reads_each_committed_record_once() {
    let store = test_store();
    let (parts, _) = Request::builder()
        .uri("http://example.test/")
        .body(())
        .unwrap()
        .into_parts();
    let id = store.begin_exchange(&parts).await.unwrap().unwrap();
    let filter = CaptureFilter {
        search: "needle".into(),
        ..Default::default()
    };
    assert_eq!(store.snapshot(&filter).await.total_requests, 0);
    let initial = store.0.record_reads.load(Ordering::Relaxed);
    for index in 0..32 {
        store
            .body_event(
                id,
                BodyDirection::Request,
                BodyCaptureEvent::Frame(crate::body::Frame::data(Bytes::from_static(b"absent"))),
            )
            .await;
        let (a, b) = tokio::join!(store.snapshot(&filter), store.snapshot(&filter));
        assert_eq!(a.total_requests + b.total_requests, 0);
        assert_eq!(
            store.0.record_reads.load(Ordering::Relaxed),
            initial + index + 1
        );
    }
    store
        .body_event(
            id,
            BodyDirection::Request,
            BodyCaptureEvent::Frame(crate::body::Frame::data(Bytes::from_static(b"needle"))),
        )
        .await;
    assert_eq!(store.snapshot(&filter).await.total_requests, 1);
    let reads = store.0.record_reads.load(Ordering::Relaxed);
    store
        .body_event(
            id,
            BodyDirection::Request,
            BodyCaptureEvent::Frame(crate::body::Frame::data(Bytes::from_static(b"later"))),
        )
        .await;
    assert_eq!(store.snapshot(&filter).await.total_requests, 1);
    assert_eq!(store.0.record_reads.load(Ordering::Relaxed), reads);
}

#[tokio::test]
async fn search_resolves_the_needle_once_and_progress_dies_with_its_exchange() {
    let store = test_store_with_limits(8, 2, rama_utils::octets::kib_u64(1));
    let (parts, ()) = Request::new(()).into_parts();
    let first = store.begin_exchange(&parts).await.unwrap().unwrap();
    let second = store.begin_exchange(&parts).await.unwrap().unwrap();
    let filter = CaptureFilter {
        search: "absent-needle".into(),
        ..CaptureFilter::default()
    };
    for lookup in 1..=3 {
        assert_eq!(store.snapshot(&filter).await.total_requests, 0);
        assert_eq!(store.0.search_caches.lock().lookups, lookup);
    }
    let query = store.0.search_caches.lock().entries.back().unwrap().clone();
    let entry = store.exchange(first).unwrap();
    let progress = Arc::downgrade(&entry.searches.lock().get_or_insert(&query));
    drop(entry);
    assert!(progress.upgrade().is_some());
    store
        .body_event(
            first,
            BodyDirection::Response,
            BodyCaptureEvent::End(CaptureOutcome::Complete),
        )
        .await;
    store.begin_exchange(&parts).await.unwrap().unwrap();
    store.exchange(first).err().unwrap();
    store.exchange(second).unwrap();
    assert!(progress.upgrade().is_none());
}

#[derive(Clone)]
struct ReadFailureStore {
    memory: MemoryStore,
    blocked: Arc<AtomicU64>,
}

impl Service<CreateCollection> for ReadFailureStore {
    type Output = Collection;
    type Error = BoxError;

    async fn serve(&self, input: CreateCollection) -> Result<Collection, BoxError> {
        Ok(Collection::new(ReadFailureCollection {
            inner: self.memory.serve(input).await?,
            blocked: self.blocked.clone(),
        }))
    }
}

#[derive(Clone)]
struct ReadFailureCollection {
    inner: Collection,
    blocked: Arc<AtomicU64>,
}

impl Service<AppendRecord> for ReadFailureCollection {
    type Output = RecordId;
    type Error = BoxError;

    async fn serve(&self, input: AppendRecord) -> Result<RecordId, BoxError> {
        self.inner.serve(input).await
    }
}

impl Service<ListRecords> for ReadFailureCollection {
    type Output = Vec<RecordId>;
    type Error = BoxError;

    async fn serve(&self, input: ListRecords) -> Result<Self::Output, BoxError> {
        self.inner.serve(input).await
    }
}

impl Service<ReadRecord> for ReadFailureCollection {
    type Output = Reader;
    type Error = BoxError;

    async fn serve(&self, input: ReadRecord) -> Result<Reader, BoxError> {
        if input.id.0 == self.blocked.load(Ordering::Relaxed) {
            return Err(BoxError::from_static_str("injected read failure"));
        }
        self.inner.serve(input).await
    }
}

#[tokio::test(start_paused = true)]
async fn search_skips_failed_records_and_retries_them_without_rescanning_successes() {
    let blocked = Arc::new(AtomicU64::new(1));
    let store = CaptureStore::with_storage(
        Storage::new(ReadFailureStore {
            memory: MemoryStore::new(Default::default()),
            blocked: blocked.clone(),
        }),
        CaptureConfig::default(),
        InspectionState::default(),
    );
    let (parts, ()) = Request::new(()).into_parts();
    let id = store.begin_exchange(&parts).await.unwrap().unwrap();
    for bytes in [
        Bytes::from_static(b"early-needle"),
        Bytes::from_static(b"late-needle"),
    ] {
        store
            .body_event(
                id,
                BodyDirection::Request,
                BodyCaptureEvent::Frame(crate::body::Frame::data(bytes)),
            )
            .await;
    }
    let early = CaptureFilter {
        search: "early-needle".into(),
        ..CaptureFilter::default()
    };
    let late = CaptureFilter {
        search: "late-needle".into(),
        ..CaptureFilter::default()
    };
    assert_eq!(store.snapshot(&late).await.total_requests, 1);
    assert_eq!(store.snapshot(&early).await.total_requests, 0);
    let mut reads = store.0.record_reads.load(Ordering::Relaxed);
    for delay in [250, 500, 1000, 2000, 4000, 8000, 16000, 30000] {
        // Arbitrarily frequent snapshots must not amplify a failing storage read.
        for _ in 0..32 {
            assert_eq!(store.snapshot(&early).await.total_requests, 0);
        }
        assert_eq!(store.0.record_reads.load(Ordering::Relaxed), reads);
        tokio::time::advance(Duration::from_millis(delay)).await;
        assert_eq!(store.snapshot(&early).await.total_requests, 0);
        reads += 1;
        assert_eq!(store.0.record_reads.load(Ordering::Relaxed), reads);
    }
    blocked.store(u64::MAX, Ordering::Relaxed);
    // A long-lived outage can still recover; failures are never silently abandoned.
    tokio::time::advance(Duration::from_secs(30)).await;
    assert_eq!(store.snapshot(&early).await.total_requests, 1);
    assert_eq!(store.0.record_reads.load(Ordering::Relaxed), reads + 1);
}

#[tokio::test(start_paused = true)]
async fn search_warnings_are_bounded_across_queries_exchanges_and_partial_failures() {
    let store = CaptureStore::with_storage(
        Storage::new(ReadFailureStore {
            memory: MemoryStore::new(Default::default()),
            blocked: Arc::new(AtomicU64::new(1)),
        }),
        CaptureConfig::default(),
        InspectionState::default(),
    );
    let (parts, ()) = Request::new(()).into_parts();
    let mut ids = Vec::new();
    for _ in 0..32 {
        let id = store.begin_exchange(&parts).await.unwrap().unwrap();
        ids.push(id);
        store
            .body_event(
                id,
                BodyDirection::Request,
                BodyCaptureEvent::Frame(crate::body::Frame::data(Bytes::from_static(
                    b"unreadable",
                ))),
            )
            .await;
    }
    // Append readable bodies between retry rounds, so new successful reads are
    // interleaved with third failures. Resetting the gate on success would still
    // emit one warning per exchange here.
    let filters: Vec<_> = (0..8)
        .map(|n| CaptureFilter {
            search: format!("absent-{n}").into(),
            ..CaptureFilter::default()
        })
        .collect();
    for delay in [0, 250, 500] {
        tokio::time::advance(Duration::from_millis(delay)).await;
        for &id in &ids {
            store
                .body_event(
                    id,
                    BodyDirection::Request,
                    BodyCaptureEvent::Frame(crate::body::Frame::data(Bytes::from_static(
                        b"readable",
                    ))),
                )
                .await;
        }
        for filter in &filters {
            assert_eq!(store.snapshot(filter).await.total_requests, 0);
        }
    }
    assert_eq!(store.0.search_warnings.emitted.load(Ordering::Relaxed), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    for filter in &filters {
        store.snapshot(filter).await;
    }
    assert_eq!(store.0.search_warnings.emitted.load(Ordering::Relaxed), 1);
    // Persistent outages remain observable, with at most one reminder per store
    // per interval even when thousands of record/query retries become due together.
    tokio::time::advance(Duration::from_secs(30)).await;
    for filter in &filters {
        store.snapshot(filter).await;
    }
    assert_eq!(store.0.search_warnings.emitted.load(Ordering::Relaxed), 2);
}
