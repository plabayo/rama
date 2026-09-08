use super::*;

#[tokio::test]
async fn confirming_a_connection_assigns_one_visible_number() {
    let store = test_store();
    let id = store.begin_connection(None, Protocol::from_static("classifying"));
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
async fn completing_oldest_connection_enforces_retention_limit() {
    let store = test_store_with_limits(1, 8, rama_utils::octets::kib_u64(1));
    let first = store.begin_connection(None, Protocol::HTTP);
    let second = store.begin_connection(None, Protocol::SOCKS5);
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
async fn finishing_an_unused_connection_removes_it_from_the_inspector() {
    let store = test_store();
    let id = store.begin_connection(None, Protocol::HTTP);
    store.finish_connection(id);
    assert!(store.0.connections.read().order.is_empty());
    assert_eq!(
        store
            .snapshot(&CaptureFilter::default())
            .await
            .total_connections,
        0
    );

    let socks = store.begin_connection(None, Protocol::SOCKS5);
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
    let mut changes = store.subscribe_changes();

    let discarded = store.begin_connection(None, Protocol::from_static("classifying"));
    store.set_connection_protocol(discarded, Protocol::HTTP);
    assert!(store.discard_connection_if_empty(discarded));
    assert!(!changes.has_changed().unwrap());

    let closed = store.begin_connection(None, Protocol::from_static("classifying"));
    store.set_connection_protocol(closed, Protocol::HTTP);
    store.finish_connection(closed);
    assert!(!changes.has_changed().unwrap());

    let proxy = store.begin_connection(None, Protocol::from_static("classifying"));
    store.confirm_connection(proxy);
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
}

#[tokio::test]
async fn visible_connection_numbers_ignore_discarded_inspector_sockets() {
    let store = test_store();
    let dashboard = store.begin_connection(None, Protocol::from_static("classifying"));
    assert!(store.discard_connection_if_empty(dashboard));

    let first_proxy = store.begin_connection(None, Protocol::HTTP);
    store.confirm_connection(first_proxy);
    let second_dashboard = store.begin_connection(None, Protocol::from_static("classifying"));
    store.finish_connection(second_dashboard);
    let second_proxy = store.begin_connection(None, Protocol::HTTPS);
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
    let service = ObserveConnectionLayer::new(store.clone(), Protocol::from_static("classifying"))
        .into_layer(rama_core::service::service_fn(
            move |input: rama_core::ServiceInput<tokio::io::DuplexStream>| {
                let confirming_store = confirming_store.clone();
                async move {
                    let id = input.extensions().get_ref::<ConnectionId>().unwrap().0;
                    confirming_store.confirm_connection(id);
                    std::future::pending::<Result<(), Infallible>>().await
                }
            },
        ));
    let (client, _server) = tokio::io::duplex(64);

    tokio::time::timeout(
        Duration::from_millis(10),
        service.serve(rama_core::ServiceInput::new(client)),
    )
    .await
    .expect_err("pending connection service should time out");

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert_eq!(snapshot.connections.len(), 1);
    assert!(!snapshot.connections[0].active);
    assert!(snapshot.connections[0].ended_at.is_some());
}

#[tokio::test]
async fn completed_exchange_does_not_end_an_alive_transport_connection() {
    let store = test_store();
    let connection_id = store.begin_connection(None, Protocol::HTTP);
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
async fn active_oldest_connection_does_not_block_retiring_a_newer_one() {
    let store = test_store_with_limits(2, 8, rama_utils::octets::kib_u64(1));
    let first = store.begin_connection(None, Protocol::HTTP);
    let second = store.begin_connection(None, Protocol::HTTPS);
    store.confirm_connection(first);
    store.confirm_connection(second);
    store.finish_connection(second);
    let third = store.begin_connection(None, Protocol::SOCKS5);
    store.confirm_connection(third);

    let snapshot = store.snapshot(&CaptureFilter::default()).await;
    assert_eq!(snapshot.connections.len(), 2);
    assert!(snapshot.connections.iter().any(|entry| entry.id == first));
    assert!(snapshot.connections.iter().any(|entry| entry.id == third));
    assert!(!snapshot.connections.iter().any(|entry| entry.id == second));
}

#[tokio::test]
async fn provisional_dashboard_connections_can_only_be_discarded_while_empty() {
    let store = test_store_with_limits(8, 8, rama_utils::octets::kib_u64(1));
    let dashboard = store.begin_connection(None, Protocol::HTTP);
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

    let proxied = store.begin_connection(None, Protocol::HTTP);
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
