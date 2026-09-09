use rama::net::Protocol;

use super::*;

#[test]
fn icap_cli_builds_request_and_response_adaptation() {
    let cli = TestCli::parse_from([
        "test",
        "--icap",
        "icaps://icap.test:11344/echo",
        "--icap-preview",
        "2048",
        "--icap-allow-204",
        "--icap-allow-206",
        "--icap-connections",
        "4",
        "--icap-insecure",
    ]);
    let adaptation = build_icap_adaptation(
        &cli.proxy,
        Arc::new(SocketOptions::default_tcp()),
        Some(Duration::from_secs(1)),
    )
    .unwrap()
    .unwrap();
    let request = adaptation.request_service().unwrap();
    let response = adaptation.response_service().unwrap();
    assert_eq!(request.service_protocol(), &Protocol::ICAPS);
    assert_eq!(request.preview(), Some(Preview::new(2048)));
    assert!(request.allows_204());
    assert!(request.allows_206());
    assert_eq!(request.uri(), response.uri());
    assert_eq!(
        adaptation.physical_idle_timeout().unwrap(),
        Duration::from_secs(DEFAULT_ICAP_IDLE_TIMEOUT_SECS)
    );
}

#[test]
fn icap_cli_can_select_one_adaptation_direction() {
    let request_only = TestCli::parse_from([
        "test",
        "--icap",
        "icap://icap.test/echo",
        "--icap-respmod=false",
        "--icap-preview",
        "0",
    ]);
    let adaptation = build_icap_adaptation(
        &request_only.proxy,
        Arc::new(SocketOptions::default_tcp()),
        None,
    )
    .unwrap()
    .unwrap();
    assert!(adaptation.request_service().is_some());
    assert!(adaptation.response_service().is_none());
    assert_eq!(adaptation.request_service().unwrap().preview(), None);

    let response_only = TestCli::parse_from([
        "test",
        "--icap",
        "icap://icap.test/echo",
        "--icap-reqmod=false",
    ]);
    let adaptation = build_icap_adaptation(
        &response_only.proxy,
        Arc::new(SocketOptions::default_tcp()),
        None,
    )
    .unwrap()
    .unwrap();
    assert!(adaptation.request_service().is_none());
    assert!(adaptation.response_service().is_some());
}

#[test]
fn icap_cli_rejects_unusable_configuration() {
    assert!(
        TestCli::try_parse_from(["test", "--icap", "icap://[::1/echo"]).is_err(),
        "--icap is parsed as a typed URI by clap"
    );
    assert!(
        TestCli::try_parse_from(["test", "--icap-preview", "1"]).is_err(),
        "ICAP-specific flags require --icap"
    );

    let neither = TestCli::parse_from([
        "test",
        "--icap",
        "icap://icap.test/echo",
        "--icap-reqmod=false",
        "--icap-respmod=false",
    ]);
    let error = build_icap_adaptation(&neither.proxy, Arc::new(SocketOptions::default_tcp()), None)
        .err()
        .unwrap();
    assert!(error.to_string().contains("at least one"));

    let no_connections = TestCli::parse_from([
        "test",
        "--icap",
        "icap://icap.test/echo",
        "--icap-connections",
        "0",
    ]);
    let error = build_icap_adaptation(
        &no_connections.proxy,
        Arc::new(SocketOptions::default_tcp()),
        None,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("greater than zero"));

    let invalid_scheme = TestCli::parse_from(["test", "--icap", "https://icap.test/echo"]);
    let error = build_icap_adaptation(
        &invalid_scheme.proxy,
        Arc::new(SocketOptions::default_tcp()),
        None,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("ICAP service endpoint"));

    let allow_206_only = TestCli::parse_from([
        "test",
        "--icap",
        "icap://icap.test/echo",
        "--icap-allow-206",
    ]);
    let error = build_icap_adaptation(
        &allow_206_only.proxy,
        Arc::new(SocketOptions::default_tcp()),
        None,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("requires --icap-allow-204"));

    assert!(
        TestCli::try_parse_from([
            "test",
            "--icap",
            "icap://icap.test/echo",
            "--icap-timeout",
            "0",
        ])
        .is_err(),
        "ICAP I/O and pool waits must remain bounded"
    );
}

#[tokio::test]
async fn icap_connection_limit_tracks_capability_refreshes() {
    let limit = ConnectionLimiter::new(4, None);
    timeout(Duration::from_millis(250), limit.update(Some(3)))
        .await
        .expect("initial peer connection limit update stalled")
        .unwrap();
    assert_eq!(limit.semaphore.available_permits(), 3);
    let held = [
        limit.acquire().await.unwrap(),
        limit.acquire().await.unwrap(),
        limit.acquire().await.unwrap(),
    ];
    assert_eq!(
        limit.update(Some(1)).await.unwrap(),
        3,
        "a busy decrease from an applied peer limit retains that limit"
    );
    assert_eq!(
        limit.update(Some(0)).await.unwrap(),
        3,
        "an invalid peer limit retains the applied non-local limit"
    );
    drop(held);
    timeout(Duration::from_millis(250), limit.update(Some(1)))
        .await
        .expect("lower peer connection limit update stalled")
        .unwrap();
    assert_eq!(limit.semaphore.available_permits(), 1);
    timeout(Duration::from_millis(250), limit.update(Some(2)))
        .await
        .expect("higher peer connection limit update stalled")
        .unwrap();
    assert_eq!(limit.semaphore.available_permits(), 2);
    timeout(Duration::from_millis(250), limit.update(Some(3)))
        .await
        .expect("second higher peer connection limit update stalled")
        .unwrap();
    assert_eq!(limit.semaphore.available_permits(), 3);
    timeout(Duration::from_millis(250), limit.update(None))
        .await
        .expect("clearing peer connection limit stalled")
        .unwrap();
    assert_eq!(limit.semaphore.available_permits(), 4);

    let first = limit.acquire().await.unwrap();
    let second = limit.acquire().await.unwrap();
    let third = limit.acquire().await.unwrap();
    let fourth = limit.acquire().await.unwrap();
    assert_eq!(
        limit.update(Some(1)).await.unwrap(),
        4,
        "a busy decrease retains the last fully applied capacity"
    );
    assert_eq!(limit.semaphore.available_permits(), 0);

    drop(first);
    drop(second);
    drop(third);
    assert_eq!(limit.update(Some(1)).await.unwrap(), 1);
    assert_eq!(limit.semaphore.available_permits(), 0);
    drop(fourth);
    let only = limit.acquire().await.unwrap();
    assert_eq!(limit.semaphore.available_permits(), 0);
    drop(only);

    limit.update(None).await.unwrap();
    assert_eq!(limit.semaphore.available_permits(), 4);
    assert_eq!(limit.update(None).await.unwrap(), 4);
    assert_eq!(limit.update(Some(0)).await.unwrap(), 4);
}

#[tokio::test]
async fn icap_io_timeout_bounds_a_stalled_peer() {
    let (client, _server) = duplex(64);
    let mut client = IcapTimeoutIo::new(client, Duration::from_millis(10));
    let mut byte = [0_u8; 1];
    let error = client.read_exact(&mut byte).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn icap_pool_controller_replaces_only_changed_capacity() {
    let cli = TestCli::parse_from([
        "test",
        "--icap",
        "icap://icap.test/echo",
        "--icap-connections",
        "4",
    ]);
    let adaptation = build_icap_adaptation(
        &cli.proxy,
        Arc::new(SocketOptions::default_tcp()),
        Some(Duration::from_secs(1)),
    )
    .unwrap()
    .unwrap();

    assert_eq!(adaptation.physical_connection_limit().await.unwrap(), 4);
    adaptation
        .update_physical_connection_limit(1)
        .await
        .unwrap();
    assert_eq!(adaptation.physical_connection_limit().await.unwrap(), 1);
    adaptation
        .update_physical_connection_limit(1)
        .await
        .unwrap();
    assert_eq!(adaptation.physical_connection_limit().await.unwrap(), 1);
}

#[tokio::test]
async fn icap_pool_generation_replacement_closes_every_idle_transport() {
    struct TrackedConnection {
        extensions: Extensions,
        live: Arc<AtomicUsize>,
    }

    impl rama::extensions::ExtensionsRef for TrackedConnection {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl Drop for TrackedConnection {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    let live = Arc::new(AtomicUsize::new(0));
    let raw = service_fn({
        let live = live.clone();
        move |input: ConnectRequest| {
            let live = live.clone();
            async move {
                live.fetch_add(1, Ordering::SeqCst);
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: TrackedConnection {
                        extensions: Extensions::new(),
                        live,
                    },
                })
            }
        }
    });
    let make_pool = |limit| {
        let pool = LruDropPool::try_new(limit, limit)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let connector = PooledConnector::new(raw.clone(), pool.clone(), BasicConnIdentifier::new());
        (connector, pool)
    };
    let (connector, pool) = make_pool(4);
    let generation = ConnectorGeneration::new(4, connector, pool);
    let request = ConnectRequest::new("icap.test:1344".parse().unwrap())
        .with_application_protocol(Protocol::ICAP);

    let mut leased = Vec::new();
    for _ in 0..4 {
        leased.push(generation.serve(request.clone()).await.unwrap().conn);
    }
    assert_eq!(live.load(Ordering::SeqCst), 4);
    drop(leased);
    assert_eq!(
        live.load(Ordering::SeqCst),
        4,
        "connections are idle in the pool"
    );

    let (connector, pool) = make_pool(1);
    generation.replace(1, connector, pool).await;
    assert_eq!(generation.limit().await, 1);
    assert_eq!(
        live.load(Ordering::SeqCst),
        0,
        "replacing the pool must close all idle transports"
    );

    let leased = generation.serve(request).await.unwrap().conn;
    assert_eq!(live.load(Ordering::SeqCst), 1);
    drop(leased);
    assert_eq!(live.load(Ordering::SeqCst), 1);
    drop(generation);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn icap_pool_retirement_is_not_held_open_by_a_pending_connect() {
    struct TrackedConnection {
        extensions: Extensions,
        live: Arc<AtomicUsize>,
    }

    impl rama::extensions::ExtensionsRef for TrackedConnection {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl Drop for TrackedConnection {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    let live = Arc::new(AtomicUsize::new(0));
    let connect_started = Arc::new(tokio::sync::Notify::new());
    let release_connect = Arc::new(tokio::sync::Notify::new());
    let raw = service_fn({
        let live = live.clone();
        let connect_started = connect_started.clone();
        let release_connect = release_connect.clone();
        move |input: ConnectRequest| {
            let live = live.clone();
            let connect_started = connect_started.clone();
            let release_connect = release_connect.clone();
            async move {
                if input
                    .authority
                    .host
                    .try_as_domain()
                    .is_ok_and(|domain| domain.as_str() == "pending.test")
                {
                    connect_started.notify_one();
                    release_connect.notified().await;
                }
                live.fetch_add(1, Ordering::SeqCst);
                Ok::<_, Infallible>(EstablishedClientConnection {
                    input,
                    conn: TrackedConnection {
                        extensions: Extensions::new(),
                        live,
                    },
                })
            }
        }
    });
    let make_pool = |limit| {
        let pool = LruDropPool::try_new(limit, limit)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let connector = PooledConnector::new(raw.clone(), pool.clone(), BasicConnIdentifier::new());
        (connector, pool)
    };
    let (connector, pool) = make_pool(2);
    let generation = ConnectorGeneration::new(2, connector, pool);
    let request = |authority: &str| {
        ConnectRequest::new(authority.parse().unwrap()).with_application_protocol(Protocol::ICAP)
    };

    let idle = generation
        .serve(request("idle.test:1344"))
        .await
        .unwrap()
        .conn;
    drop(idle);
    assert_eq!(live.load(Ordering::SeqCst), 1);

    let pending = tokio::spawn({
        let generation = generation.clone();
        let request = request("pending.test:1344");
        async move { generation.serve(request).await.unwrap().conn }
    });
    connect_started.notified().await;

    let (connector, pool) = make_pool(1);
    generation.replace(1, connector, pool).await;
    assert_eq!(
        live.load(Ordering::SeqCst),
        0,
        "retirement must close idle sockets while an old connect is pending"
    );

    release_connect.notify_one();
    let old_lease = pending.await.unwrap();
    assert_eq!(live.load(Ordering::SeqCst), 1);
    drop(old_lease);
    assert_eq!(
        live.load(Ordering::SeqCst),
        0,
        "a retired generation must reject returned connections"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_client_applies_icap_reqmod_and_respmod() {
    let (icap_address, icap_task, _icap_state) = spawn_proxy_test_icap().await;
    let origin_listener =
        TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
            .await
            .unwrap();
    let origin_address = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(origin_listener.serve(
        HttpServer::auto(Executor::default()).service(service_fn(|request: Request| async move {
            assert_eq!(request.headers()["x-rama-icap-reqmod"], "yes");
            assert_eq!(
                request.into_body().collect().await.unwrap().to_bytes(),
                "request body"
            );
            Ok::<_, Infallible>(Response::new(Body::from("response body")))
        })),
    ));
    let cli = TestCli::parse_from(vec![
        "test".to_owned(),
        "--icap".to_owned(),
        format!("icap://{icap_address}/adapt"),
    ]);
    let tcp_options = Arc::new(SocketOptions::default_tcp());
    let icap = build_icap_adaptation(
        &cli.proxy,
        tcp_options.clone(),
        Some(Duration::from_secs(2)),
    )
    .unwrap();
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options,
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(None, false, &[]).unwrap(),
        icap,
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{origin_address}/adapt"))
        .body(Body::from("request body"))
        .unwrap();
    let request_future = client.serve(request);
    assert!(
        std::mem::size_of_val(&request_future) <= kib(24),
        "ICAP inflated the proxy request future to {} bytes",
        std::mem::size_of_val(&request_future),
    );
    let response = timeout(Duration::from_secs(5), request_future)
        .await
        .expect("ICAP-adapted proxy request timed out")
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-rama-icap-respmod"], "yes");
    assert!(
        !response
            .headers()
            .contains_key(rama::http::header::PROXY_AUTHENTICATE)
    );
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "response body"
    );
    origin_task.abort();
    icap_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_client_consumes_proxy_auth_without_icap() {
    let origin_listener =
        TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
            .await
            .unwrap();
    let origin_address = origin_listener.local_addr().unwrap();
    let origin_task = tokio::spawn(origin_listener.serve(
        HttpServer::auto(Executor::default()).service(service_fn(|request: Request| async move {
            assert!(
                !request
                    .headers()
                    .contains_key(rama::http::header::PROXY_AUTHORIZATION)
            );
            Ok::<_, Infallible>(
                Response::builder()
                    .header(rama::http::header::PROXY_AUTHENTICATE, "Basic")
                    .header(
                        rama::http::header::PROXY_AUTHENTICATION_INFO,
                        "nextnonce=deadbeef",
                    )
                    .body(Body::from("proxy auth consumed"))
                    .unwrap(),
            )
        })),
    ));
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(None, false, &[]).unwrap(),
        icap: None,
    });
    let response = client
        .serve(
            Request::builder()
                .uri(format!("http://{origin_address}/proxy-auth"))
                .header(
                    rama::http::header::PROXY_AUTHORIZATION,
                    "Basic downstream-secret",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        !response
            .headers()
            .contains_key(rama::http::header::PROXY_AUTHENTICATE)
    );
    assert!(
        !response
            .headers()
            .contains_key(rama::http::header::PROXY_AUTHENTICATION_INFO)
    );
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "proxy auth consumed"
    );

    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_icap_directions_follow_single_method_capabilities() {
    let state = Arc::new(ProxyTestIcapState {
        methods: Some(vec![IcapMethod::Reqmod]),
        ..Default::default()
    });
    let (icap_address, icap_task) = spawn_proxy_test_icap_with_state(state.clone()).await;
    let (origin, origin_task) = spawn_plain_origin("single-method-ok").await;
    let cli = TestCli::parse_from(vec![
        "test".to_owned(),
        "--icap".to_owned(),
        format!("icap://{icap_address}/adapt"),
    ]);
    let tcp_options = Arc::new(SocketOptions::default_tcp());
    let icap = build_icap_adaptation(
        &cli.proxy,
        tcp_options.clone(),
        Some(Duration::from_secs(2)),
    )
    .unwrap();
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options,
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(None, false, &[]).unwrap(),
        icap,
    });

    let response = timeout(
        Duration::from_secs(5),
        client.serve(
            Request::builder()
                .uri(format!("http://{origin}/single-method"))
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("single-method ICAP request timed out")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "single-method-ok"
    );
    assert_eq!(state.reqmod_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.respmod_calls.load(Ordering::SeqCst), 0);

    origin_task.abort();
    icap_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_icap_options_is_bounded_for_all_waiters() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let icap_address = listener.local_addr().unwrap();
    let icap_task = tokio::spawn(async move {
        let (_connection, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let cli = TestCli::parse_from(vec![
        "test".to_owned(),
        "--icap".to_owned(),
        format!("icap://{icap_address}/adapt"),
        "--icap-timeout".to_owned(),
        "1".to_owned(),
    ]);
    let tcp_options = Arc::new(SocketOptions::default_tcp());
    let icap = build_icap_adaptation(
        &cli.proxy,
        tcp_options.clone(),
        Some(Duration::from_secs(2)),
    )
    .unwrap();
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options,
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(None, false, &[]).unwrap(),
        icap,
    });
    let request = || {
        Request::builder()
            .uri("http://origin.test/bounded-options")
            .body(Body::empty())
            .unwrap()
    };

    let (first, second) = Box::pin(timeout(Duration::from_secs(3), async {
        tokio::join!(client.serve(request()), client.serve(request()))
    }))
    .await
    .expect("stalled OPTIONS waiters exceeded the ICAP timeout");
    for response in [first.unwrap(), second.unwrap()] {
        assert!(response.status().is_server_error());
    }

    icap_task.abort();
}
