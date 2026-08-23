use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::Parser;
use rama::{
    extensions::{Extensions, ExtensionsRef as _},
    http::ws::{
        AsyncWebSocket, Message,
        handshake::{
            client::HttpClientWebSocketExt as _,
            mitm::{
                WebSocketRelayDirection, WebSocketRelayEvent, WebSocketRelayEventInput,
                WebSocketRelayEventService,
            },
            server::WebSocketAcceptor,
        },
        protocol::Role,
    },
    http::{Body, body::util::BodyExt as _},
    io::BridgeIo,
    net::{client::ProxyRoute, test_utils::client::MockSocket},
    tls::client::{ServerVerifyMode, TlsClientConfig},
    tls::{
        ProtocolVersion,
        client::{ClientHello, ClientHelloExtension},
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{io::duplex, time::timeout};

use super::*;

#[derive(Debug, Parser)]
struct TestCli {
    #[command(flatten)]
    proxy: CliCommandProxy,
}

#[test]
fn default_is_plain_http_on_loopback_8080() {
    let cli = TestCli::parse_from(["test"]);
    let listeners = resolve_listeners(&cli.proxy);
    assert_eq!(
        listeners
            .iter()
            .find(|(address, _)| *address == default_bind())
            .map(|(_, protocols)| protocols),
        Some(&BTreeSet::from([ProxyProtocol::Http]))
    );
    assert!(!cli.proxy.lazy_connect);
    assert!(cli.proxy.mitm.is_none());
}

#[test]
fn ephemeral_mitm_ca_has_an_inspector_identity() {
    let config = mitm_ca_config();
    assert_eq!(
        config.subject.organisation_name.as_deref(),
        Some("Rama Proxy Inspector")
    );
    assert_eq!(
        config.subject.common_name.as_deref(),
        Some("Rama ephemeral MITM CA")
    );
}

#[test]
fn protocols_can_share_or_split_ports() {
    let cli = TestCli::parse_from([
        "test",
        "--bind",
        "127.0.0.1:9000",
        "--protocol",
        "http,https,socks5",
        "--socks5-bind",
        "127.0.0.1:9001",
    ]);
    let listeners = resolve_listeners(&cli.proxy);
    assert_eq!(listeners.len(), 2);
    let protocols = |address: SocketAddress| {
        listeners
            .iter()
            .find(|(current, _)| *current == address)
            .map(|(_, protocols)| protocols)
            .unwrap()
    };
    assert_eq!(protocols("127.0.0.1:9000".parse().unwrap()).len(), 3);
    assert_eq!(
        protocols("127.0.0.1:9001".parse().unwrap()),
        &BTreeSet::from([ProxyProtocol::Socks5])
    );

    let specific_only = TestCli::parse_from([
        "test",
        "--http-bind",
        "127.0.0.1:9100",
        "--https-bind",
        "127.0.0.1:9100",
    ]);
    let listeners = resolve_listeners(&specific_only.proxy);
    assert_eq!(listeners.len(), 1);
    assert_eq!(
        listeners[0].1,
        BTreeSet::from([ProxyProtocol::Http, ProxyProtocol::Https])
    );
    assert_ne!(listeners[0].0, default_bind());
}

#[test]
fn wildcard_listener_can_share_its_port_with_the_loopback_dashboard() {
    assert!(bind_addresses_overlap(
        "0.0.0.0:8080".parse().unwrap(),
        "127.0.0.1:8080".parse().unwrap()
    ));
    assert!(!bind_addresses_overlap(
        "0.0.0.0:8080".parse().unwrap(),
        "127.0.0.1:8081".parse().unwrap()
    ));
    assert!(!bind_addresses_overlap(
        "0.0.0.0:8080".parse().unwrap(),
        "[::1]:8080".parse().unwrap()
    ));
}

#[test]
fn dashboard_routing_accepts_its_absolute_uri_but_not_proxy_targets() {
    let dashboard: SocketAddress = "127.0.0.1:8081".parse().unwrap();
    let origin_form = Request::builder()
        .uri("/assets/style.css")
        .header("host", "127.0.0.1:8081")
        .body(Body::empty())
        .unwrap();
    assert!(request_targets_dashboard(&origin_form, dashboard));
    let absolute = Request::builder()
        .uri("http://127.0.0.1:8081/events")
        .body(Body::empty())
        .unwrap();
    assert!(request_targets_dashboard(&absolute, dashboard));
    let origin_form_proxy_target = Request::builder()
        .uri("/proxied")
        .header("host", "example.test:8081")
        .body(Body::empty())
        .unwrap();
    assert!(!request_targets_dashboard(
        &origin_form_proxy_target,
        dashboard
    ));
    let proxied = Request::builder()
        .uri("http://example.test:8081/")
        .body(Body::empty())
        .unwrap();
    assert!(!request_targets_dashboard(&proxied, dashboard));
    let connect = Request::builder()
        .method(rama::http::Method::CONNECT)
        .uri("https://127.0.0.1:8081/")
        .body(Body::empty())
        .unwrap();
    assert!(!request_targets_dashboard(&connect, dashboard));
    let remote_authority = Authority::try_from("192.0.2.1:8081").unwrap();
    assert!(!authority_targets_socket(
        remote_authority.view(),
        "0.0.0.0:8081".parse().unwrap()
    ));
}

#[test]
fn mitm_flag_accepts_default_or_explicit_ui_address() {
    let default = TestCli::parse_from(["test", "--mitm"]);
    assert_eq!(default.proxy.mitm, Some(MitmBindAddress::Inherit));
    assert_eq!(
        resolve_mitm_address(&default.proxy, &resolve_listeners(&default.proxy)),
        Some(default_bind())
    );
    let inherited = TestCli::parse_from(["test", "--mitm", "--bind", "127.0.0.1:9090"]);
    assert_eq!(
        resolve_mitm_address(&inherited.proxy, &resolve_listeners(&inherited.proxy)),
        Some("127.0.0.1:9090".parse().unwrap())
    );
    let one_specific = TestCli::parse_from(["test", "--mitm", "--http-bind", "127.0.0.1:9091"]);
    assert_eq!(
        resolve_mitm_address(&one_specific.proxy, &resolve_listeners(&one_specific.proxy)),
        Some("127.0.0.1:9091".parse().unwrap())
    );
    let multiple_specific = TestCli::parse_from([
        "test",
        "--mitm",
        "--http-bind",
        "127.0.0.1:9091",
        "--socks5-bind",
        "127.0.0.1:9092",
    ]);
    assert_eq!(
        resolve_mitm_address(
            &multiple_specific.proxy,
            &resolve_listeners(&multiple_specific.proxy)
        ),
        Some(default_bind())
    );
    let explicit = TestCli::parse_from(["test", "--mitm=0.0.0.0:9090"]);
    assert_eq!(
        explicit.proxy.mitm,
        Some(MitmBindAddress::Explicit("0.0.0.0:9090".parse().unwrap()))
    );
    assert_eq!(
        resolve_mitm_address(&explicit.proxy, &resolve_listeners(&explicit.proxy)),
        Some("0.0.0.0:9090".parse().unwrap())
    );
}

#[test]
fn lazy_connect_remains_available_as_an_opt_in() {
    let cli = TestCli::parse_from(["test", "--lazy-connect"]);
    assert!(cli.proxy.lazy_connect);
}

#[test]
fn mitm_bypass_plain_domains_include_only_dns_label_descendants() {
    let bypass = MitmBypass::try_new(&["example.test".to_owned()]).unwrap();
    assert!(bypass.matches_host(&Host::try_from("example.test").unwrap()));
    assert!(bypass.matches_host(&Host::try_from("api.example.test").unwrap()));
    assert!(!bypass.matches_host(&Host::try_from("notexample.test").unwrap()));
    MitmBypass::try_new(&["  ".to_owned()]).unwrap_err();
    let ip = MitmBypass::try_new(&["127.0.0.1".to_owned()]).unwrap();
    assert!(ip.matches_host(&Host::try_from("127.0.0.1").unwrap()));
    assert!(!ip.matches_host(&Host::try_from("127.0.0.2").unwrap()));
}

#[tokio::test]
async fn mitm_bypass_uses_tls_sni_when_the_connect_target_is_an_ip() {
    let inspected = Arc::new(AtomicUsize::new(0));
    let passed = Arc::new(AtomicUsize::new(0));
    let inspect = service_fn({
        let inspected = inspected.clone();
        move |_input: InputWithClientHello<()>| {
            inspected.fetch_add(1, Ordering::Relaxed);
            async { Ok::<_, Infallible>(()) }
        }
    });
    let passthrough = service_fn({
        let passed = passed.clone();
        move |()| {
            passed.fetch_add(1, Ordering::Relaxed);
            async { Ok::<_, Infallible>(()) }
        }
    });
    let service = TlsHelloMitmBypassService {
        inspect,
        passthrough,
        bypass: MitmBypass::try_new(&["example.test".to_owned()]).unwrap(),
    };
    let hello = |domain| InputWithClientHello {
        input: (),
        client_hello: ClientHello::new(
            ProtocolVersion::TLSv1_2,
            Vec::new(),
            Vec::new(),
            vec![ClientHelloExtension::ServerName(Some(
                rama::net::address::Domain::try_from(domain).unwrap(),
            ))],
        ),
    };

    service.serve(hello("api.example.test")).await.unwrap();
    service.serve(hello("other.test")).await.unwrap();
    assert_eq!(passed.load(Ordering::Relaxed), 1);
    assert_eq!(inspected.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn mitm_bypass_uses_connect_target_before_protocol_peeking() {
    let inspected = Arc::new(AtomicUsize::new(0));
    let passed = Arc::new(AtomicUsize::new(0));
    let inspect = service_fn({
        let inspected = inspected.clone();
        move |_input: rama::extensions::Extensions| {
            inspected.fetch_add(1, Ordering::Relaxed);
            async { Ok::<_, Infallible>(()) }
        }
    });
    let passthrough = service_fn({
        let passed = passed.clone();
        move |_input: rama::extensions::Extensions| {
            passed.fetch_add(1, Ordering::Relaxed);
            async { Ok::<_, Infallible>(()) }
        }
    });
    let service = MitmTargetBypassService {
        inspect,
        passthrough,
        bypass: MitmBypass::try_new(&["example.test".to_owned()]).unwrap(),
    };
    let input = |target: &str| {
        let extensions = rama::extensions::Extensions::new();
        extensions.insert(ConnectorTarget(target.parse().unwrap()));
        extensions
    };

    service.serve(input("api.example.test:443")).await.unwrap();
    service.serve(input("other.test:443")).await.unwrap();
    assert_eq!(passed.load(Ordering::Relaxed), 1);
    assert_eq!(inspected.load(Ordering::Relaxed), 1);
}

#[test]
fn l4_socket_defaults_match_the_terminating_proxy_policy() {
    let cli = TestCli::parse_from(["test"]);
    let options = tcp_socket_options(&cli.proxy);
    assert_eq!(options.tcp_no_delay, Some(true));
    assert_eq!(options.keep_alive, Some(true));
    let keep_alive = options.tcp_keep_alive.as_ref().unwrap();
    assert_eq!(
        keep_alive.time,
        Some(Duration::from_secs(DEFAULT_TCP_KEEPALIVE_IDLE_SECS))
    );
    assert_eq!(options.recv_buffer_size, None);
    assert_eq!(options.send_buffer_size, None);

    let opted_out = TestCli::parse_from(["test", "--tcp-no-delay=false", "--tcp-keepalive=false"]);
    let options = tcp_socket_options(&opted_out.proxy);
    assert_eq!(options.tcp_no_delay, Some(false));
    assert_eq!(options.keep_alive, Some(false));
    assert!(options.tcp_keep_alive.is_none());

    let tuned = TestCli::parse_from([
        "test",
        "--tcp-keepalive-idle",
        "41",
        "--tcp-keepalive-interval",
        "7",
        "--tcp-keepalive-probes",
        "9",
        "--tcp-recv-buffer",
        "4096",
        "--tcp-send-buffer",
        "8192",
    ]);
    let options = tcp_socket_options(&tuned.proxy);
    let keep_alive = options.tcp_keep_alive.as_ref().unwrap();
    assert_eq!(keep_alive.time, Some(Duration::from_secs(41)));
    assert_eq!(options.recv_buffer_size, Some(4096));
    assert_eq!(options.send_buffer_size, Some(8192));
}

fn reserve_loopback_address() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

async fn spawn_plain_origin(
    response_body: &'static str,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_address(
        SocketAddress::from(reserve_loopback_address()),
        Executor::default(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(
        listener.serve(HttpServer::auto(Executor::default()).service(service_fn(
            move |_request: Request| async move {
                Ok::<_, Infallible>(Response::new(Body::from(response_body)))
            },
        ))),
    );
    (address, task)
}

async fn spawn_websocket_origin() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_address(
        SocketAddress::from(reserve_loopback_address()),
        Executor::default(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(
        listener.serve(
            HttpServer::new_http1(Executor::default()).service(
                ConsumeErrLayer::trace_as_debug()
                    .into_layer(WebSocketAcceptor::new().into_echo_service()),
            ),
        ),
    );
    (address, task)
}

async fn get_via_proxy(
    origin: std::net::SocketAddr,
    proxy: &str,
) -> (StatusCode, rama::bytes::Bytes) {
    let insecure = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl_config(insecure.clone())
        .with_proxy_support()
        .with_tls_support_using_boringssl(insecure)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let request = Request::builder()
        .uri(format!("http://{origin}/proxy-e2e"))
        .extension(ProxyRoute::Proxy(proxy.parse().unwrap()))
        .body(Body::empty())
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), client.serve(request))
        .await
        .expect("proxy request timed out")
        .expect("proxy request failed");
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

fn dashboard_session_id(html: &str) -> &str {
    let attribute = html
        .split_once("data-signals:session=\"")
        .expect("dashboard has a session signal")
        .1
        .split_once('"')
        .unwrap()
        .0;
    attribute
        .split(|character: char| !character.is_ascii_hexdigit())
        .find(|candidate| candidate.len() == 32)
        .expect("dashboard carries a 128-bit session id")
}

async fn shutdown_proxy(
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    shutdown: rama::graceful::Shutdown,
) {
    _ = shutdown_tx.send(());
    shutdown
        .shutdown_with_limit(Duration::from_secs(5))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_http_and_socks5_listener_forwards_end_to_end() {
    let (origin, origin_task) = spawn_plain_origin("shared-proxy-ok").await;
    let proxy_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let cli = TestCli::parse_from([
        "test",
        "--bind",
        proxy_arg.as_str(),
        "--protocol",
        "http,socks5",
    ]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    for scheme in ["http", "socks5h"] {
        let proxy = format!("{scheme}://{proxy_address}");
        let (status, body) = get_via_proxy(origin, &proxy).await;
        assert_eq!(status, StatusCode::OK, "proxy scheme {scheme}");
        assert_eq!(body, "shared-proxy-ok", "proxy scheme {scheme}");
    }

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_proxy_listener_forwards_end_to_end() {
    let (origin, origin_task) = spawn_plain_origin("https-proxy-ok").await;
    let proxy_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let cli = TestCli::parse_from(["test", "--bind", proxy_arg.as_str(), "--protocol", "https"]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    let proxy = format!("https://{proxy_address}");
    let (status, body) = get_via_proxy(origin, &proxy).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "https-proxy-ok");

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_dashboard_and_http_proxy_share_a_listener_end_to_end() {
    let (origin, origin_task) = spawn_plain_origin("shared-dashboard-ok").await;
    let proxy_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let mitm_arg = format!("--mitm={proxy_address}");
    let cli = TestCli::parse_from(["test", "--bind", proxy_arg.as_str(), mitm_arg.as_str()]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    let (status, body) = get_via_proxy(origin, &format!("http://{proxy_address}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "shared-dashboard-ok");

    let client = EasyHttpWebClient::default();
    let response = client
        .serve(
            Request::builder()
                .uri(format!("http://{proxy_address}/"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("'unsafe-eval'")
    );
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("Rama Proxy Inspector"));
    let session = dashboard_session_id(&html);
    let response = client
        .serve(
            Request::builder()
                .uri(format!(
                    "http://{proxy_address}/events?datastar=%7B%22session%22%3A%22{session}%22%7D"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = timeout(Duration::from_secs(2), events.frame())
        .await
        .expect("initial shared-port inspector event timed out")
        .expect("shared-port inspector event stream ended")
        .unwrap()
        .into_data()
        .unwrap();
    let event = String::from_utf8_lossy(&event);
    assert!(event.contains(&origin.to_string()));
    assert!(event.contains("1 req ·"));
    assert!(!event.contains("0 req ·"));
    drop(events);
    drop(client);

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test]
async fn shared_dashboard_request_discards_its_provisional_connection() {
    let ua_db = Arc::new(UserAgentDatabase::try_embedded().unwrap());
    let capture = CaptureStore::new(8, 8, 1024, ua_db.clone()).unwrap();
    let connection_id = capture.begin_connection(None, "http");
    let dashboard = dashboard::service(DashboardState::new(
        capture.clone(),
        HarController::default(),
        Vec::new(),
        Arc::new(SocketOptions::default_tcp()),
        UpstreamProxyConfig::new(None, false, &[]).unwrap(),
    ));
    let dispatcher = proxy_request_dispatcher(
        service_fn(async |_request: Request| Ok::<_, Infallible>(Response::new(Body::empty()))),
        Some(dashboard),
        Some("127.0.0.1:8080".parse().unwrap()),
        true,
    );
    let dispatcher = classify_http_connection(
        dispatcher,
        Some("127.0.0.1:8080".parse().unwrap()),
        true,
        Some(capture.clone()),
    );
    let request = Request::builder()
        .uri("/assets/style.css")
        .header("host", "127.0.0.1:8080")
        .body(Body::empty())
        .unwrap();
    request.extensions().insert(ConnectionId(connection_id));

    let response = dispatcher.serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot = capture
        .snapshot_limited_for_connections(
            &capture::CaptureFilter::default(),
            &BTreeSet::new(),
            usize::MAX,
            usize::MAX,
        )
        .await;
    assert_eq!(snapshot.total_connections, 0);
}

#[tokio::test]
async fn websocket_inspector_records_and_relays_messages() {
    let store = CaptureStore::new(
        8,
        8,
        4,
        Arc::new(UserAgentDatabase::try_embedded().unwrap()),
    )
    .unwrap();
    let capture_service = CaptureHttpLayer::new(Some(store.clone())).into_layer(service_fn(
        async |_request: Request| Ok::<_, Infallible>(Response::new(Body::empty())),
    ));
    capture_service
        .serve(Request::new(Body::empty()))
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let extensions = rama::extensions::Extensions::new();
    extensions.insert(ExchangeId(1));
    let output = inspect_websocket_event(
        Some(store.clone()),
        WebSocketRelayEventInput {
            direction: WebSocketRelayDirection::Ingress,
            event: WebSocketRelayEvent::Data(WebSocketRelayMessage::Text(
                "websocket-payload".into(),
            )),
            extensions,
        },
    )
    .await
    .unwrap();

    assert!(matches!(
        output.messages.as_slice(),
        [WebSocketRelayMessage::Text(message)] if message.as_str() == "websocket-payload"
    ));
    let extensions = rama::extensions::Extensions::new();
    extensions.insert(ExchangeId(1));
    let ping = inspect_websocket_event(
        Some(store.clone()),
        WebSocketRelayEventInput {
            direction: WebSocketRelayDirection::Egress,
            event: WebSocketRelayEvent::Ping(rama::bytes::Bytes::from_static(b"heartbeat")),
            extensions,
        },
    )
    .await
    .unwrap();
    assert!(
        ping.messages.is_empty(),
        "control events are observation-only"
    );
    let details = store.details(1).await.unwrap();
    assert!(details.records.iter().any(|record| matches!(
        record,
        capture::StoredRecord::WebSocketMessage {
            direction,
            kind,
            data,
            ..
        }
            if direction == "Ingress"
                && kind == "text"
                && BASE64.decode(data).unwrap() == b"webs"
    )));
    assert!(details.records.iter().any(|record| matches!(
        record,
        capture::StoredRecord::WebSocketMessage { direction, kind, data, .. }
            if direction == "Egress"
                && kind == "ping"
                && BASE64.decode(data).unwrap() == b"hear"
    )));
    assert_eq!(details.summary.request_bytes, 17);
    assert_eq!(details.summary.response_bytes, 9);
    assert!(details.summary.request_truncated);
    assert!(details.summary.response_truncated);
    assert!(matches!(
        store.replay_websocket_message(1, 0).await,
        Err(capture::WebSocketReplayError::Truncated)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_proxy_inspector_exposes_and_replays_live_websocket_messages() {
    let (origin, origin_task) = spawn_websocket_origin().await;
    let proxy_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let mitm_arg = format!("--mitm={proxy_address}");
    let cli = TestCli::parse_from(["test", "--bind", proxy_arg.as_str(), mitm_arg.as_str()]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    let insecure = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl_config(insecure.clone())
        .with_proxy_support()
        .with_tls_support_using_boringssl(insecure)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let extensions = Extensions::new();
    extensions.insert(ProxyRoute::Proxy(
        format!("http://{proxy_address}").parse().unwrap(),
    ));
    let mut websocket = client
        .websocket(format!("ws://{origin}/echo"))
        .handshake(extensions)
        .await
        .unwrap();

    websocket
        .send_message(Message::text("captured websocket request"))
        .await
        .unwrap();
    assert_eq!(
        websocket.recv_message().await.unwrap(),
        Message::text("captured websocket request")
    );

    let dashboard = EasyHttpWebClient::default();
    let replay_dashboard = EasyHttpWebClient::default();
    let response = dashboard
        .serve(
            Request::builder()
                .uri(format!("http://{proxy_address}/"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    let session = dashboard_session_id(&html);
    let signals = format!("datastar=%7B%22session%22%3A%22{session}%22%7D");
    let signal_body = format!(r#"{{"session":"{session}"}}"#);
    let response = replay_dashboard
        .serve(
            Request::builder()
                .method(rama::http::Method::POST)
                .uri(format!("http://{proxy_address}/api/details/1"))
                .body(Body::from(signal_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = dashboard
        .serve(
            Request::builder()
                .uri(format!("http://{proxy_address}/events?{signals}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = timeout(Duration::from_secs(2), events.frame())
        .await
        .expect("initial WebSocket inspector event timed out")
        .expect("WebSocket inspector event stream ended")
        .unwrap()
        .into_data()
        .unwrap();
    let event = String::from_utf8_lossy(&event);
    assert!(event.contains("WebSocket traffic"), "{event}");
    assert!(event.contains("captured websocket request"));
    assert!(event.contains("Client → Server"));
    assert!(event.contains("Server → Client"));
    assert!(event.contains("Replay to server"));
    assert!(event.contains("connection-state alive"));
    drop(events);

    let response = replay_dashboard
        .serve(
            Request::builder()
                .method(rama::http::Method::POST)
                .uri(format!("http://{proxy_address}/api/websocket/1/replay/0"))
                .body(Body::from(signal_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        timeout(Duration::from_secs(2), websocket.recv_message())
            .await
            .expect("replayed WebSocket message was not echoed")
            .unwrap(),
        Message::text("captured websocket request")
    );

    let closure_dashboard = EasyHttpWebClient::default();
    let response = closure_dashboard
        .serve(
            Request::builder()
                .uri(format!("http://{proxy_address}/events?{signals}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut closure_events = response.into_body();
    _ = closure_events.frame().await;
    drop(websocket);
    let closed_event = timeout(Duration::from_secs(2), async {
        loop {
            let frame = closure_events
                .frame()
                .await
                .expect("WebSocket closure event stream ended")
                .unwrap();
            let Ok(data) = frame.into_data() else {
                continue;
            };
            let event = String::from_utf8_lossy(&data);
            if event.contains("connection-state closed") {
                break event.into_owned();
            }
        }
    })
    .await
    .expect("closed WebSocket remained marked alive");
    assert!(closed_event.contains("connection closed · replay unavailable"));
    drop(closure_events);
    drop(closure_dashboard);
    drop(replay_dashboard);
    drop(dashboard);
    drop(client);
    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_http_summary_includes_ingress_and_egress_socket_addresses() {
    let (origin, origin_task) = spawn_plain_origin("socket-summary").await;
    let store = CaptureStore::new(
        8,
        8,
        mib_u64(1),
        Arc::new(UserAgentDatabase::try_embedded().unwrap()),
    )
    .unwrap();
    let ingress_local: SocketAddress = "127.0.0.1:8080".parse().unwrap();
    let ingress_peer: SocketAddress = "127.0.0.1:54321".parse().unwrap();
    let connection_id = store.begin_connection(
        Some(rama::net::stream::SocketInfo::new(
            Some(ingress_local),
            ingress_peer,
        )),
        "http",
    );
    store.confirm_connection(connection_id);
    let client = new_proxy_client(
        Executor::default(),
        Some(store.clone()),
        HarController::default(),
        Arc::new(SocketOptions::default_tcp()),
        &UpstreamProxyConfig::new(None, false, &[]).unwrap(),
    );
    let request = Request::builder()
        .uri(format!("http://{origin}/socket-summary"))
        .extension(ConnectionId(connection_id))
        .body(Body::empty())
        .unwrap();
    let response = client.serve(request).await.unwrap();
    response.into_body().collect().await.unwrap();

    let summary = store.details(1).await.unwrap().summary;
    assert_eq!(
        summary.ingress_local_address.as_deref(),
        Some("127.0.0.1:8080")
    );
    assert_eq!(
        summary.ingress_peer_address.as_deref(),
        Some("127.0.0.1:54321")
    );
    assert!(summary.egress_local_address.is_some());
    assert_eq!(summary.egress_peer_address, Some(origin.to_string()));
    origin_task.abort();
}

#[tokio::test]
async fn websocket_inspector_replays_live_text_and_binary_in_original_direction() {
    let store = CaptureStore::new(
        8,
        8,
        4096,
        Arc::new(UserAgentDatabase::try_embedded().unwrap()),
    )
    .unwrap();
    let capture_service = CaptureHttpLayer::new(Some(store.clone())).into_layer(service_fn(
        async |_request: Request| Ok::<_, Infallible>(Response::new(Body::empty())),
    ));
    capture_service
        .serve(
            Request::builder()
                .uri("http://example.test/socket")
                .header("upgrade", "websocket")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    let (relay_ingress_io, peer_ingress_io) = duplex(rama::utils::octets::kib(16));
    let (relay_egress_io, peer_egress_io) = duplex(rama::utils::octets::kib(16));
    let relay_ingress = MockSocket::new(relay_ingress_io);
    let relay_egress = MockSocket::new(relay_egress_io);
    relay_ingress.extensions().insert(ExchangeId(1));
    relay_egress.extensions().insert(ExchangeId(1));
    let relay_store = store.clone();
    let relay_service = WebSocketRelayEventService::new(service_fn(move |input| {
        inspect_websocket_event(Some(relay_store.clone()), input)
    }))
    .with_message_injection(true);
    let relay = tokio::spawn(async move {
        relay_service
            .serve(BridgeIo(relay_ingress, relay_egress))
            .await
    });
    let mut peer_ingress =
        AsyncWebSocket::from_raw_socket(MockSocket::new(peer_ingress_io), Role::Client, None).await;
    let mut peer_egress =
        AsyncWebSocket::from_raw_socket(MockSocket::new(peer_egress_io), Role::Server, None).await;

    peer_ingress
        .send_message(Message::text("client text"))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_egress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("client text")
    );
    store.replay_websocket_message(1, 0).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_egress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("client text")
    );

    peer_egress
        .send_message(Message::binary(rama::bytes::Bytes::from_static(
            b"server binary",
        )))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_ingress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::binary(rama::bytes::Bytes::from_static(b"server binary"))
    );
    store.replay_websocket_message(1, 2).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_ingress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::binary(rama::bytes::Bytes::from_static(b"server binary"))
    );

    store
        .record_websocket_message(
            1,
            "Ingress".to_owned(),
            "ping".to_owned(),
            b"control".to_vec(),
            None,
        )
        .await;
    assert!(matches!(
        store.replay_websocket_message(1, 4).await,
        Err(capture::WebSocketReplayError::ControlFrame)
    ));
    let details = store.inspector_details(1, 0, 100).await.unwrap();
    assert!(details.websocket_replay_active);
    assert_eq!(
        details
            .records
            .iter()
            .filter(|record| matches!(
                record,
                capture::StoredRecord::WebSocketMessage { replayed: true, .. }
            ))
            .count(),
        2
    );

    drop(peer_ingress);
    drop(peer_egress);
    relay.await.unwrap().unwrap();
    assert!(matches!(
        store.replay_websocket_message(1, 0).await,
        Err(capture::WebSocketReplayError::ConnectionClosed)
    ));
    assert!(
        !store
            .inspector_details(1, 0, 100)
            .await
            .unwrap()
            .websocket_replay_active
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_har_controller_records_proxy_traffic_end_to_end() {
    let (origin, origin_task) = spawn_plain_origin("har-proxy-ok").await;
    let directory = rama::utils::fs::tempdir().unwrap();
    let path = directory.path().join("proxy.har");
    let har = HarController::default();
    har.start(path.clone()).await.unwrap();
    let upstream = UpstreamProxyConfig::new(None, false, &[]).unwrap();
    let client = new_proxy_client(
        Executor::default(),
        None,
        har.clone(),
        Arc::new(SocketOptions::default_tcp()),
        &upstream,
    );
    let response = client
        .serve(
            Request::builder()
                .uri(format!("http://{origin}/har-e2e"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "har-proxy-ok"
    );
    har.stop().await;

    let document: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
    let entries = document["log"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]["request"]["url"],
        format!("http://{origin}/har-e2e")
    );
    assert_eq!(entries[0]["response"]["status"], 200);
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_connect_is_mitm_relayed_end_to_end() {
    let origin_listener = TcpListener::bind_address(
        SocketAddress::from(reserve_loopback_address()),
        Executor::default(),
    )
    .await
    .unwrap();
    let origin_address = origin_listener.local_addr().unwrap();
    let origin_tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .unwrap()
        .with_alpn_http_auto();
    let origin_http =
        HttpServer::auto(Executor::default()).service(service_fn(|_request: Request| async move {
            Ok::<_, Infallible>(Response::new(Body::from("mitm-roundtrip-ok")))
        }));
    let origin_task = tokio::spawn(origin_listener.serve(TlsAcceptorService::new(
        origin_tls,
        origin_http,
        false,
    )));

    let proxy_address = reserve_loopback_address();
    let ui_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let mitm_arg = format!("--mitm={ui_address}");
    let cli = TestCli::parse_from(["test", "--bind", proxy_arg.as_str(), mitm_arg.as_str()]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    let tls_config = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls_config)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let request = Request::builder()
        .uri(format!("https://{origin_address}/ping"))
        .extension(ProxyRoute::Proxy(
            format!("http://{proxy_address}").parse().unwrap(),
        ))
        .body(Body::empty())
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), client.serve(request))
        .await
        .expect("MITM request timed out")
        .expect("MITM request failed");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "mitm-roundtrip-ok"
    );

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}
