use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::Parser;
use rama::{
    crypto::pki_types::{CertificateDer, pem::PemObject as _},
    extensions::Extensions,
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
    icap::{
        codec::{Header, HeaderSlot, ResponseLine},
        http::IncomingRequest as IcapHttpIncomingRequest,
        proto::{
            Method as IcapMethod, MethodKind as IcapMethodKind, ServiceTag,
            StatusCode as IcapStatusCode, header as icap_header,
        },
        server::{
            IncomingRequest as IcapIncomingRequest, OptionsResponse as IcapOptionsResponse,
            OutgoingResponse as IcapOutgoingResponse, Server as IcapServer,
        },
    },
    io::BridgeIo,
    net::{
        client::{ConnectorTarget, ProxyRoute},
        test_utils::client::MockSocket,
    },
    tls::client::{ServerVerifyMode, TlsClientConfig},
    tls::{
        ProtocolVersion,
        client::{ClientHello, ClientHelloExtension},
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, duplex},
    time::timeout,
};

use super::*;

const TEST_ICAP_SERVICE_TAG: ServiceTag = ServiceTag::from_static("rama-proxy-test");

#[derive(Debug, Parser)]
struct TestCli {
    #[command(flatten)]
    proxy: CliCommandProxy,
}

fn with_local_address(request: Request, local_address: &str) -> Request {
    request
        .extensions()
        .insert(rama::net::stream::SocketInfo::new(
            Some(local_address.parse().unwrap()),
            "198.51.100.10:54321".parse().unwrap(),
        ));
    request
}

#[test]
fn default_is_shared_http_and_socks5_on_loopback_8080() {
    let cli = TestCli::parse_from(["test"]);
    let listeners = resolve_listeners(&cli.proxy);
    assert_eq!(
        listeners
            .iter()
            .find(|(address, _)| *address == default_bind())
            .map(|(_, protocols)| protocols),
        Some(&BTreeSet::from([
            ProxyProtocol::Http,
            ProxyProtocol::Socks5,
        ]))
    );
    assert!(!cli.proxy.lazy_connect);
    assert!(!cli.proxy.no_upstream_proxy_forward_auth);
    assert!(!cli.proxy.upstream_proxy_tunnel);
    assert!(cli.proxy.mitm.is_none());
    assert_eq!(cli.proxy.body_limit, 0);
    assert_eq!(cli.proxy.capture_total_limit, DEFAULT_CAPTURE_TOTAL_LIMIT);
    assert_eq!(cli.proxy.capture_websocket_messages, 10_000);
    assert!(cli.proxy.icap.is_none());
    assert!(cli.proxy.icap_reqmod);
    assert!(cli.proxy.icap_respmod);
    assert_eq!(cli.proxy.icap_preview, DEFAULT_ICAP_PREVIEW_BYTES);
    assert!(!cli.proxy.icap_allow_204);
    assert!(!cli.proxy.icap_allow_206);
    assert_eq!(cli.proxy.icap_connections, DEFAULT_ICAP_CONNECTIONS);
    assert_eq!(cli.proxy.icap_timeout.get(), DEFAULT_ICAP_TIMEOUT_SECS);
    assert_eq!(cli.proxy.icap_idle_timeout, DEFAULT_ICAP_IDLE_TIMEOUT_SECS);
    assert!(!cli.proxy.icap_insecure);
}

#[test]
fn upstream_forward_proxy_options_are_explicit() {
    let cli = TestCli::parse_from([
        "test",
        "--upstream-proxy",
        "http://pu:pp@proxy.example:8080",
        "--no-upstream-proxy-forward-auth",
        "--upstream-proxy-tunnel",
    ]);
    assert!(cli.proxy.no_upstream_proxy_forward_auth);
    assert!(cli.proxy.upstream_proxy_tunnel);
    assert!(cli.proxy.upstream_proxy.is_some());
}

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
    assert_eq!(request.service_protocol(), &rama::net::Protocol::ICAPS);
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
        .with_application_protocol(rama::net::Protocol::ICAP);

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
        ConnectRequest::new(authority.parse().unwrap())
            .with_application_protocol(rama::net::Protocol::ICAP)
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
    let origin_form = with_local_address(
        Request::builder()
            .uri("/assets/style.css")
            .header("host", "127.0.0.1:8081")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:8081",
    );
    assert!(request_targets_dashboard(&origin_form, dashboard));
    let absolute = with_local_address(
        Request::builder()
            .uri("http://127.0.0.1:8081/events")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:8081",
    );
    assert!(request_targets_dashboard(&absolute, dashboard));
    let origin_form_proxy_target = with_local_address(
        Request::builder()
            .uri("/proxied")
            .header("host", "example.test:8081")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:8081",
    );
    assert!(!request_targets_dashboard(
        &origin_form_proxy_target,
        dashboard
    ));
    let proxied = with_local_address(
        Request::builder()
            .uri("http://example.test:8081/")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:8081",
    );
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
fn explicit_loopback_dashboard_is_not_routed_on_a_wildcard_external_interface() {
    let dashboard: SocketAddress = "127.0.0.1:8081".parse().unwrap();
    let missing_socket_info = Request::builder()
        .uri("/")
        .header("host", "localhost:8081")
        .body(Body::empty())
        .unwrap();
    assert!(!request_targets_dashboard(&missing_socket_info, dashboard));

    for authority in ["localhost:8081", "192.0.2.10:8081"] {
        let request = with_local_address(
            Request::builder()
                .uri("/")
                .header("host", authority)
                .body(Body::empty())
                .unwrap(),
            "192.0.2.10:8081",
        );
        assert!(
            !request_targets_dashboard(&request, dashboard),
            "{authority}"
        );
    }

    let loopback = with_local_address(
        Request::builder()
            .uri("/")
            .header("host", "localhost:8081")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:8081",
    );
    assert!(request_targets_dashboard(&loopback, dashboard));

    let wildcard = with_local_address(
        Request::builder()
            .uri("/")
            .header("host", "192.0.2.10:8081")
            .body(Body::empty())
            .unwrap(),
        "192.0.2.10:8081",
    );
    assert!(request_targets_dashboard(
        &wildcard,
        "0.0.0.0:8081".parse().unwrap()
    ));
}

#[test]
fn mitm_portal_routing_matches_only_the_reserved_host() {
    for uri in ["http://mitm.ramaproxy.org/", "https://mitm.ramaproxy.org/"] {
        let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        assert!(request_targets_mitm_portal(&request), "{uri}");
    }
    let connect = Request::builder()
        .method(rama::http::Method::CONNECT)
        .uri(rama::net::uri::Uri::parse_authority_form("mitm.ramaproxy.org:443").unwrap())
        .body(Body::empty())
        .unwrap();
    assert!(request_targets_mitm_portal(&connect));
    let origin_form = Request::builder()
        .uri("/")
        .header("host", "MITM.RAMAPROXY.ORG:443")
        .body(Body::empty())
        .unwrap();
    assert!(request_targets_mitm_portal(&origin_form));
    let lookalike = Request::builder()
        .uri("http://not-mitm.ramaproxy.org/")
        .body(Body::empty())
        .unwrap();
    assert!(!request_targets_mitm_portal(&lookalike));
}

#[tokio::test]
async fn mitm_portal_remains_available_while_recording_is_paused() {
    let inspection = InspectionState::default();
    let policy = MitmPolicy::try_new(&[], &[]).unwrap();
    let http = MitmPortalMatcher::http(inspection.clone(), policy.clone());
    let connect = MitmPortalMatcher::connect(inspection.clone(), policy);
    let get = Request::builder()
        .uri("http://mitm.ramaproxy.org/")
        .body(Body::empty())
        .unwrap();
    let tunnel = Request::builder()
        .method(rama::http::Method::CONNECT)
        .uri(rama::net::uri::Uri::parse_authority_form("mitm.ramaproxy.org:443").unwrap())
        .body(Body::empty())
        .unwrap();

    assert!(rama::matcher::Matcher::matches(&http, None, &get));
    assert!(!rama::matcher::Matcher::matches(&connect, None, &get));
    assert!(rama::matcher::Matcher::matches(&connect, None, &tunnel));
    inspection.pause().await;
    assert!(rama::matcher::Matcher::matches(&http, None, &get));
    assert!(rama::matcher::Matcher::matches(&connect, None, &tunnel));
    inspection.resume().await;
    assert!(rama::matcher::Matcher::matches(&http, None, &get));

    let denied = MitmPolicy::try_new(&[], &["mitm.ramaproxy.org".to_owned()]).unwrap();
    assert!(!rama::matcher::Matcher::matches(
        &MitmPortalMatcher::http(inspection.clone(), denied.clone()),
        None,
        &get
    ));
    assert!(!rama::matcher::Matcher::matches(
        &MitmPortalMatcher::connect(inspection, denied),
        None,
        &tunnel
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
fn inherited_mitm_uses_the_effective_proxy_address_when_binding_port_zero() {
    let cli = TestCli::parse_from(["test", "--bind", "127.0.0.1:0", "--mitm"]);
    let listeners = resolve_listeners(&cli.proxy);
    let requested = resolve_mitm_address(&cli.proxy, &listeners);
    let inherited = inherited_mitm_listener_index(&cli.proxy, &listeners, requested);
    assert_eq!(inherited, Some(0));

    let bound_address = "127.0.0.1:43123".parse().unwrap();
    let effective = resolve_bound_mitm_address(requested, inherited, &[bound_address]);
    assert_eq!(effective, Some(bound_address.into()));
    assert!(bind_addresses_overlap(
        bound_address,
        effective.unwrap().into()
    ));
}

#[test]
fn lazy_connect_remains_available_as_an_opt_in() {
    let cli = TestCli::parse_from(["test", "--lazy-connect"]);
    assert!(cli.proxy.lazy_connect);
}

#[test]
fn mitm_allow_and_deny_are_explicit_cli_arguments() {
    let cli = TestCli::parse_from([
        "test",
        "--mitm",
        "--mitm-allow",
        "example.test,internal.test",
        "--mitm-deny",
        "accounts.example.test",
    ]);
    assert_eq!(cli.proxy.mitm_allow.len(), 2);
    assert_eq!(cli.proxy.mitm_deny, ["accounts.example.test"]);
    TestCli::try_parse_from(["test", "--mitm", "--mitm-bypass", "example.test"]).unwrap_err();
    TestCli::try_parse_from(["test", "--mitm-allow", "example.test"]).unwrap_err();
    TestCli::try_parse_from(["test", "--mitm-deny", "example.test"]).unwrap_err();
}

#[tokio::test]
async fn mitm_policy_composes_connect_target_and_tls_sni() {
    let inspected = Arc::new(AtomicUsize::new(0));
    let passed = Arc::new(AtomicUsize::new(0));
    let inspect = service_fn({
        let inspected = inspected.clone();
        move |_input: InputWithClientHello<Extensions>| {
            inspected.fetch_add(1, Ordering::Relaxed);
            async { Ok::<_, Infallible>(()) }
        }
    });
    let passthrough = service_fn({
        let passed = passed.clone();
        move |_input: Extensions| {
            passed.fetch_add(1, Ordering::Relaxed);
            async { Ok::<_, Infallible>(()) }
        }
    });
    let service = TlsHelloMitmPolicyService {
        inspection: InspectionState::default(),
        inspect,
        passthrough,
        policy: MitmPolicy::try_new(
            &["example.test".to_owned()],
            &["blocked.example.test".to_owned()],
        )
        .unwrap(),
        control: None,
    };
    let hello = |target: &str, domain: &str| {
        let input = Extensions::new();
        input.insert(ConnectorTarget(target.parse().unwrap()));
        InputWithClientHello {
            input,
            client_hello: ClientHello::new(
                ProtocolVersion::TLSv1_2,
                Vec::new(),
                Vec::new(),
                vec![ClientHelloExtension::ServerName(Some(
                    rama::net::address::Domain::try_from(domain).unwrap(),
                ))],
            ),
        }
    };

    service
        .serve(hello("api.example.test:443", "other.test"))
        .await
        .unwrap();
    service
        .serve(hello("other.test:443", "api.example.test"))
        .await
        .unwrap();
    service
        .serve(hello("blocked.example.test:443", "api.example.test"))
        .await
        .unwrap();
    service
        .serve(hello("api.example.test:443", "blocked.example.test"))
        .await
        .unwrap();
    assert_eq!(passed.load(Ordering::Relaxed), 2);
    assert_eq!(inspected.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn mitm_prepeek_gate_defers_unmatched_targets_but_rejects_denied_targets() {
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
    let service = MitmTargetPolicyService {
        inspection: InspectionState::default(),
        inspect,
        passthrough,
        policy: MitmPolicy::try_new(
            &["example.test".to_owned()],
            &["blocked.example.test".to_owned()],
        )
        .unwrap(),
        control: None,
        defer_ip_target: true,
    };
    let input = |target: &str| {
        let extensions = rama::extensions::Extensions::new();
        extensions.insert(ConnectorTarget(target.parse().unwrap()));
        extensions
    };

    service.serve(input("api.example.test:443")).await.unwrap();
    service.serve(input("other.test:443")).await.unwrap();
    service
        .serve(input("blocked.example.test:443"))
        .await
        .unwrap();
    assert_eq!(passed.load(Ordering::Relaxed), 1);
    assert_eq!(inspected.load(Ordering::Relaxed), 2);
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
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
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

async fn read_raw_http_head(stream: &mut tokio::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.unwrap();
        assert_ne!(read, 0, "HTTP request ended before its headers");
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes).unwrap()
}

#[derive(Default)]
struct ProxyTestIcapState {
    active: AtomicUsize,
    max_active: AtomicUsize,
    proxy_authorization_seen: AtomicUsize,
    reqmod_calls: AtomicUsize,
    respmod_calls: AtomicUsize,
    peer_max_connections: Option<u64>,
    methods: Option<Vec<IcapMethod<'static>>>,
    delay: Option<Duration>,
}

struct ActiveIcapAdaptation(Arc<ProxyTestIcapState>);

impl Drop for ActiveIcapAdaptation {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn proxy_test_icap_service(
    request: IcapIncomingRequest,
    state: Arc<ProxyTestIcapState>,
) -> Result<IcapOutgoingResponse, BoxError> {
    let method = request.request().method();
    if method == IcapMethodKind::Options {
        const DEFAULT_METHODS: &[IcapMethod<'static>] = &[IcapMethod::Reqmod, IcapMethod::Respmod];
        let response = IcapOptionsResponse::new(
            TEST_ICAP_SERVICE_TAG,
            state.methods.as_deref().unwrap_or(DEFAULT_METHODS),
        )
        .with_preview(Preview::new(DEFAULT_ICAP_PREVIEW_BYTES))
        .with_transfer_preview_all(true);
        let response = match state.peer_max_connections {
            Some(limit) => response.with_max_connections(limit),
            None => response,
        };
        return Ok(response.build()?);
    }

    let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
    state.max_active.fetch_max(active, Ordering::SeqCst);
    let _active = ActiveIcapAdaptation(state.clone());
    match method {
        IcapMethodKind::Reqmod => {
            state.reqmod_calls.fetch_add(1, Ordering::SeqCst);
        }
        IcapMethodKind::Respmod => {
            state.respmod_calls.fetch_add(1, Ordering::SeqCst);
        }
        IcapMethodKind::Options | IcapMethodKind::Extension => {}
    }
    if let Some(delay) = state.delay {
        tokio::time::sleep(delay).await;
    }
    let mut slots = [HeaderSlot::EMPTY; 16];
    let head = request.request().parse_head(&mut slots)?;
    let saw_proxy_authorization = head
        .header(icap_header::PROXY_AUTHORIZATION)
        .is_some_and(|value| value.as_bytes().is_some());
    if saw_proxy_authorization {
        state
            .proxy_authorization_seen
            .fetch_add(1, Ordering::SeqCst);
    }
    let request = IcapHttpIncomingRequest::from_icap(request)?;
    let line = ResponseLine::new(IcapStatusCode::OK, b"OK")?;
    let tag = TEST_ICAP_SERVICE_TAG.to_wire();
    let fields = [Header::new(icap_header::ISTAG, tag.as_bytes())?];
    // This echo response depends on every input byte. Finish the bounded
    // request before returning instead of advertising a dependent response
    // while the client is still transmitting its Preview.
    match method {
        IcapMethodKind::Reqmod => {
            let (parts, body) = request.into_request()?.into_parts();
            let mut request = Request::from_parts(parts, Body::new(body.collect().await?));
            request.headers_mut().insert(
                "x-rama-icap-reqmod",
                rama::http::HeaderValue::from_static("yes"),
            );
            if saw_proxy_authorization {
                request.headers_mut().insert(
                    "x-rama-icap-saw-proxy-authorization",
                    rama::http::HeaderValue::from_static("yes"),
                );
            }
            Ok(IcapOutgoingResponse::from_http_request(
                line, &fields, request,
            )?)
        }
        IcapMethodKind::Respmod => {
            let (parts, body) = request.into_response()?.into_parts();
            let mut response = Response::from_parts(parts, Body::new(body.collect().await?));
            response.headers_mut().insert(
                "x-rama-icap-respmod",
                rama::http::HeaderValue::from_static("yes"),
            );
            response.headers_mut().insert(
                rama::http::header::PROXY_AUTHENTICATE,
                rama::http::HeaderValue::from_static("Basic realm=icap-test"),
            );
            Ok(IcapOutgoingResponse::from_http_response(
                IcapMethodKind::Respmod,
                line,
                &fields,
                response,
            )?)
        }
        IcapMethodKind::Options | IcapMethodKind::Extension => Err(BoxError::from_static_str(
            "unexpected ICAP method in adaptation test service",
        )),
    }
}

async fn spawn_proxy_test_icap_with_state(
    state: Arc<ProxyTestIcapState>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = IcapServer::new(
        service_fn(move |request| proxy_test_icap_service(request, state.clone())),
        TEST_ICAP_SERVICE_TAG,
    )
    .unwrap();
    let task = tokio::spawn(listener.serve(server));
    (address, task)
}

async fn spawn_proxy_test_icap() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    Arc<ProxyTestIcapState>,
) {
    let state = Arc::new(ProxyTestIcapState::default());
    let (address, task) = spawn_proxy_test_icap_with_state(state.clone()).await;
    (address, task, state)
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
        std::mem::size_of_val(&request_future) <= 24 * 1024,
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
async fn forward_client_isolates_upstream_proxy_407() {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(
        listener.serve(HttpServer::auto(Executor::default()).service(service_fn(
            |request: Request| async move {
                assert_eq!(
                    request.uri().to_string(),
                    "http://origin.example/upstream-challenge"
                );
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                        .header("proxy-authenticate", "Basic realm=upstream-secret")
                        .header("proxy-authentication-info", "nextnonce=upstream-secret")
                        .body(Body::from("upstream-secret-body"))
                        .unwrap(),
                )
            },
        ))),
    );
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(
            Some(format!("http://{proxy_address}").parse().unwrap()),
            false,
            &[],
        )
        .unwrap(),
        icap: None,
    });

    let response = client
        .serve(
            Request::builder()
                .uri("http://origin.example/upstream-challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(!response.headers().contains_key("proxy-authenticate"));
    assert!(!response.headers().contains_key("proxy-authentication-info"));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        !body
            .windows(b"upstream-secret".len())
            .any(|w| w == b"upstream-secret")
    );

    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_client_can_disable_automatic_upstream_proxy_auth() {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(
        listener.serve(HttpServer::auto(Executor::default()).service(service_fn(
            |request: Request| async move {
                assert_eq!(
                    request.uri().to_string(),
                    "http://origin.example/no-upstream-auth"
                );
                assert!(
                    !request
                        .headers()
                        .contains_key(rama::http::header::PROXY_AUTHORIZATION)
                );
                Ok::<_, Infallible>(Response::new(Body::from("ok")))
            },
        ))),
    );
    let mut proxy: ProxyAddress = format!("http://{proxy_address}").parse().unwrap();
    proxy.credential = Some(rama::net::user::ProxyCredential::Basic(
        rama::net::user::Basic::try_from("pu:pp").unwrap(),
    ));
    let upstream = UpstreamProxyConfig::new(Some(proxy), false, &[])
        .unwrap()
        .with_forward_proxy_auth(false);
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream,
        icap: None,
    });

    let response = client
        .serve(
            Request::builder()
                .uri("http://origin.example/no-upstream-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_client_authenticates_plaintext_upstream_proxy_by_default() {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(
        listener.serve(HttpServer::auto(Executor::default()).service(service_fn(
            |request: Request| async move {
                assert_eq!(
                    request.uri().to_string(),
                    "http://origin.example/upstream-auth"
                );
                assert_eq!(
                    request.headers()[rama::http::header::PROXY_AUTHORIZATION],
                    "Basic cHU6cHA="
                );
                Ok::<_, Infallible>(Response::new(Body::from("ok")))
            },
        ))),
    );
    let mut proxy: ProxyAddress = format!("http://{proxy_address}").parse().unwrap();
    proxy.credential = Some(rama::net::user::ProxyCredential::Basic(
        rama::net::user::Basic::try_from("pu:pp").unwrap(),
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
        upstream: UpstreamProxyConfig::new(Some(proxy), false, &[]).unwrap(),
        icap: None,
    });

    let response = client
        .serve(
            Request::builder()
                .uri("http://origin.example/upstream-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_client_can_tunnel_plaintext_without_leaking_proxy_auth() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket_address = listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let connect = read_raw_http_head(&mut stream).await;
        assert!(connect.starts_with("CONNECT origin.example:80 HTTP/1.1\r\n"));
        assert!(
            connect
                .to_ascii_lowercase()
                .contains("proxy-authorization: basic chu6cha=")
        );
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();

        let origin = read_raw_http_head(&mut stream).await;
        assert!(origin.starts_with("GET /inside HTTP/1.1\r\n"));
        assert!(!origin.to_ascii_lowercase().contains("proxy-authorization:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    let mut proxy: ProxyAddress = format!("http://{socket_address}").parse().unwrap();
    proxy.credential = Some(rama::net::user::ProxyCredential::Basic(
        rama::net::user::Basic::try_from("pu:pp").unwrap(),
    ));
    let upstream = UpstreamProxyConfig::new(Some(proxy), false, &[])
        .unwrap()
        .with_tunnel_plaintext_http(true);
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: Some(Duration::from_secs(2)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream,
        icap: None,
    });

    let response = client
        .serve(
            Request::builder()
                .uri("http://origin.example/inside")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    timeout(Duration::from_secs(5), proxy_task)
        .await
        .expect("proxy task timed out")
        .expect("proxy task failed");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_max_connections_clamps_concurrent_icap_transactions() {
    let icap_state = Arc::new(ProxyTestIcapState {
        peer_max_connections: Some(1),
        delay: Some(Duration::from_millis(30)),
        ..Default::default()
    });
    let (icap_address, icap_task) = spawn_proxy_test_icap_with_state(icap_state.clone()).await;
    let (origin, origin_task) = spawn_plain_origin("connection-limit-ok").await;
    let cli = TestCli::parse_from(vec![
        "test".to_owned(),
        "--icap".to_owned(),
        format!("icap://{icap_address}/adapt"),
        "--icap-connections".to_owned(),
        "4".to_owned(),
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
            .uri(format!("http://{origin}/limited"))
            .body(Body::empty())
            .unwrap()
    };

    let exchange = || async {
        let response = client.serve(request()).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, body)
    };
    let (first, second) = Box::pin(timeout(Duration::from_secs(5), async {
        tokio::join!(exchange(), exchange())
    }))
    .await
    .expect("requests queued by Max-Connections did not make progress");
    for (status, body) in [first, second] {
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "connection-limit-ok");
    }
    assert_eq!(icap_state.max_active.load(Ordering::SeqCst), 1);

    origin_task.abort();
    icap_task.abort();
}

async fn spawn_websocket_origin() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let websocket = WebSocketAcceptor::new().into_echo_service();
    let websocket = service_fn(move |request: Request| {
        let websocket = websocket.clone();
        async move {
            assert!(
                !request
                    .headers()
                    .contains_key(rama::http::header::PROXY_AUTHORIZATION)
            );
            websocket.serve(request).await
        }
    });
    let task = tokio::spawn(
        listener.serve(
            HttpServer::new_http1(Executor::default())
                .service(ConsumeErrLayer::trace_as_debug().into_layer(websocket)),
        ),
    );
    (address, task)
}

async fn spawn_tls_websocket_origin() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .unwrap()
        .with_alpn_http_auto();
    let websocket = WebSocketAcceptor::new().into_echo_service();
    let websocket = service_fn(move |request: Request| {
        let websocket = websocket.clone();
        async move {
            assert!(
                !request
                    .headers()
                    .contains_key(rama::http::header::PROXY_AUTHORIZATION)
            );
            websocket.serve(request).await
        }
    });
    let websocket = HttpServer::new_http1(Executor::default())
        .service(ConsumeErrLayer::trace_as_debug().into_layer(websocket));
    let task = tokio::spawn(listener.serve(TlsAcceptorService::new(tls, websocket, false)));
    (address, task)
}

fn proxy_websocket_client()
-> impl Service<Request, Output = Response, Error: Into<BoxError>> + Clone {
    let insecure = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl_config(insecure.clone())
        .with_proxy_support()
        .with_tls_support_using_boringssl(insecure)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_handshakes_support_each_icap_direction() {
    let (icap_address, icap_task, icap_state) = spawn_proxy_test_icap().await;
    let (origin, origin_task) = spawn_websocket_origin().await;

    for (reqmod, respmod) in [(true, false), (false, true), (true, true)] {
        let proxy_address = reserve_loopback_address();
        let proxy_arg = proxy_address.to_string();
        let icap_uri = format!("icap://{icap_address}/adapt");
        let reqmod_arg = format!("--icap-reqmod={reqmod}");
        let respmod_arg = format!("--icap-respmod={respmod}");
        let cli = TestCli::parse_from([
            "test",
            "--bind",
            proxy_arg.as_str(),
            "--icap",
            icap_uri.as_str(),
            reqmod_arg.as_str(),
            respmod_arg.as_str(),
        ]);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown = rama::graceful::Shutdown::new(async move {
            _ = shutdown_rx.await;
        });
        run(shutdown.guard(), cli.proxy).await.unwrap();

        let reqmod_before = icap_state.reqmod_calls.load(Ordering::SeqCst);
        let respmod_before = icap_state.respmod_calls.load(Ordering::SeqCst);
        let client = proxy_websocket_client();
        let extensions = Extensions::new();
        extensions.insert(ProxyRoute::Proxy(
            format!("http://{proxy_address}").parse().unwrap(),
        ));
        let mut websocket = client
            .websocket(format!("ws://{origin}/echo"))
            .with_header(
                rama::http::header::PROXY_AUTHORIZATION,
                "Basic downstream-secret",
            )
            .handshake(extensions)
            .await
            .unwrap();

        assert_eq!(
            websocket
                .response()
                .headers
                .contains_key("x-rama-icap-respmod"),
            respmod,
        );
        assert!(
            !websocket
                .response()
                .headers
                .contains_key(rama::http::header::PROXY_AUTHENTICATE)
        );
        websocket
            .send_message(Message::text("ICAP WebSocket round trip"))
            .await
            .unwrap();
        assert_eq!(
            websocket.recv_message().await.unwrap(),
            Message::text("ICAP WebSocket round trip")
        );
        assert_eq!(
            icap_state.reqmod_calls.load(Ordering::SeqCst) > reqmod_before,
            reqmod,
        );
        assert_eq!(
            icap_state.respmod_calls.load(Ordering::SeqCst) > respmod_before,
            respmod,
        );
        assert!(icap_state.proxy_authorization_seen.load(Ordering::SeqCst) > 0);

        drop(websocket);
        drop(client);
        shutdown_proxy(shutdown_tx, shutdown).await;
    }

    origin_task.abort();
    icap_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_mitm_websocket_handshake_supports_icap() {
    let (icap_address, icap_task, icap_state) = spawn_proxy_test_icap().await;
    let (origin, origin_task) = spawn_tls_websocket_origin().await;
    let proxy_address = reserve_loopback_address();
    let ui_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let mitm_arg = format!("--mitm={ui_address}");
    let icap_uri = format!("icap://{icap_address}/adapt");
    let cli = TestCli::parse_from([
        "test",
        "--bind",
        proxy_arg.as_str(),
        mitm_arg.as_str(),
        "--icap",
        icap_uri.as_str(),
    ]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    let client = proxy_websocket_client();
    let extensions = Extensions::new();
    extensions.insert(ProxyRoute::Proxy(
        format!("socks5h://{proxy_address}").parse().unwrap(),
    ));
    let mut websocket = client
        .websocket(format!("wss://{origin}/echo"))
        .handshake(extensions)
        .await
        .unwrap();

    assert_eq!(websocket.response().headers["x-rama-icap-respmod"], "yes");
    assert!(
        !websocket
            .response()
            .headers
            .contains_key(rama::http::header::PROXY_AUTHENTICATE)
    );
    websocket
        .send_message(Message::text("ICAP WSS over SOCKS5"))
        .await
        .unwrap();
    assert_eq!(
        websocket.recv_message().await.unwrap(),
        Message::text("ICAP WSS over SOCKS5")
    );
    assert!(icap_state.reqmod_calls.load(Ordering::SeqCst) > 0);
    assert!(icap_state.respmod_calls.load(Ordering::SeqCst) > 0);

    drop(websocket);
    drop(client);
    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
    icap_task.abort();
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

fn authorize_dashboard(request: &mut Request) {
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {TEST_DASHBOARD_TOKEN}")
            .parse()
            .expect("test dashboard token is a valid header value"),
    );
}

fn dashboard_request(mut request: Request) -> Request {
    authorize_dashboard(&mut request);
    request
}

async fn next_sse_event(body: &mut Body) -> String {
    let bytes = timeout(Duration::from_secs(2), async {
        let mut bytes = Vec::new();
        loop {
            let frame = body
                .frame()
                .await
                .expect("inspector event stream ended")
                .unwrap();
            let Ok(data) = frame.into_data() else {
                continue;
            };
            bytes.extend_from_slice(&data);
            if bytes.windows(2).any(|window| window == b"\n\n") {
                return bytes;
            }
        }
    })
    .await
    .expect("inspector event timed out");
    String::from_utf8(bytes).expect("inspector event is UTF-8")
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
    let cli = TestCli::parse_from(["test", "--bind", proxy_arg.as_str()]);
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
async fn default_mitm_dashboard_http_and_socks5_share_a_listener_end_to_end() {
    let (origin, origin_task) = spawn_plain_origin("shared-dashboard-ok").await;
    let proxy_address = reserve_loopback_address();
    let proxy_arg = proxy_address.to_string();
    let cli = TestCli::parse_from(["test", "--bind", proxy_arg.as_str(), "--mitm"]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    for scheme in ["http", "socks5h"] {
        let (status, body) = get_via_proxy(origin, &format!("{scheme}://{proxy_address}")).await;
        assert_eq!(status, StatusCode::OK, "proxy scheme {scheme}");
        assert_eq!(body, "shared-dashboard-ok", "proxy scheme {scheme}");
    }

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
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    response.into_body().collect().await.unwrap();
    let response = client
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{proxy_address}/"))
                .body(Body::empty())
                .unwrap(),
        ))
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
        .serve(dashboard_request(
            Request::builder()
                .uri(format!(
                    "http://{proxy_address}/events?datastar=%7B%22session%22%3A%22{session}%22%7D"
                ))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = next_sse_event(&mut events).await;
    assert!(event.contains(&origin.to_string()));
    assert!(event.contains("1 req ·"));
    assert!(!event.contains("0 req ·"));
    drop(events);
    drop(client);

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_certificate_portal_is_hijacked_over_http_and_https() {
    let proxy_address = reserve_loopback_address();
    let ui_address = reserve_loopback_address();
    let directory = rama::utils::fs::tempdir().unwrap();
    let ca_path = directory.path().join("proxy-ca.pem");
    let proxy_arg = proxy_address.to_string();
    let mitm_arg = format!("--mitm={ui_address}");
    let ca_arg = ca_path.to_string_lossy().into_owned();
    let cli = TestCli::parse_from([
        "test",
        "--bind",
        proxy_arg.as_str(),
        mitm_arg.as_str(),
        "--mitm-ca-cert",
        ca_arg.as_str(),
    ]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    let ca_pem = tokio::fs::read(&ca_path).await.unwrap();
    let trust_anchor = CertificateDer::from_pem_slice(&ca_pem).unwrap();
    let tls_config = TlsClientConfig::new()
        .try_with_server_trust_anchors([trust_anchor])
        .unwrap();
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls_config)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let proxy_route = || ProxyRoute::Proxy(format!("http://{proxy_address}").parse().unwrap());

    for uri in ["http://mitm.ramaproxy.org/", "https://mitm.ramaproxy.org/"] {
        let response = timeout(
            Duration::from_secs(10),
            client.serve(
                Request::builder()
                    .uri(uri)
                    .extension(proxy_route())
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("MITM portal request timed out")
        .expect("MITM portal request failed");
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert!(response.headers().contains_key("content-security-policy"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Rama Proxy Inspector"), "{uri}: {body}");
        assert!(body.contains("/rama-proxy-ca.crt"), "{uri}: {body}");
    }

    let certificate = client
        .serve(
            Request::builder()
                .uri("http://mitm.ramaproxy.org/rama-proxy-ca.crt")
                .extension(proxy_route())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        certificate.headers()["content-type"],
        "application/x-x509-ca-cert"
    );
    assert_eq!(
        certificate.into_body().collect().await.unwrap().to_bytes(),
        ca_pem
    );

    shutdown_proxy(shutdown_tx, shutdown).await;
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
        MitmPolicy::try_new(&[], &[]).unwrap(),
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
    let request = with_local_address(
        Request::builder()
            .uri("/assets/style.css")
            .header("host", "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:8080",
    );
    request.extensions().insert(ConnectionId(connection_id));

    let response = dispatcher.serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot = capture
        .snapshot_limited_for_connections(
            &capture::CaptureFilter::default(),
            &BTreeSet::new(),
            0,
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
    assert!(
        !details
            .records
            .iter()
            .any(|record| matches!(record, capture::StoredRecord::WebSocketMessage { .. })),
        "oversized WebSocket messages must not be persisted as partial messages"
    );
    assert_eq!(details.summary.request_bytes, 17);
    assert_eq!(details.summary.response_bytes, 9);
    assert!(details.summary.request_truncated);
    assert!(details.summary.response_truncated);
    assert!(matches!(
        store.replay_websocket_message(1, 0).await,
        Err(capture::WebSocketReplayError::MessageNotFound)
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
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{proxy_address}/"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    let session = dashboard_session_id(&html);
    let signals = format!("datastar=%7B%22session%22%3A%22{session}%22%7D");
    let signal_body = format!(r#"{{"session":"{session}"}}"#);
    let response = replay_dashboard
        .serve(dashboard_request(
            Request::builder()
                .method(rama::http::Method::POST)
                .uri(format!("http://{proxy_address}/api/focus/request/1"))
                .body(Body::from(signal_body.clone()))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{proxy_address}/events?{signals}"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = next_sse_event(&mut events).await;
    assert!(event.contains("WebSocket traffic"), "{event}");
    assert!(event.contains("captured websocket request"), "{event}");
    assert!(event.contains("Client → Server"));
    assert!(event.contains("Server → Client"));
    assert!(event.contains("Replay to server"));
    assert!(event.contains("connection-state alive"));
    drop(events);

    let response = replay_dashboard
        .serve(dashboard_request(
            Request::builder()
                .method(rama::http::Method::POST)
                .uri(format!("http://{proxy_address}/api/websocket/1/replay/0"))
                .body(Body::from(signal_body))
                .unwrap(),
        ))
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
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{proxy_address}/events?{signals}"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut closure_events = response.into_body();
    _ = next_sse_event(&mut closure_events).await;
    drop(websocket);
    let closed_event = timeout(Duration::from_secs(2), async {
        loop {
            let event = next_sse_event(&mut closure_events).await;
            if event.contains("connection-state closed") {
                break event;
            }
        }
    })
    .await
    .expect("closed WebSocket remained marked alive");
    assert_eq!(closed_event.matches("Replay off").count(), 1);
    assert!(!closed_event.contains("connection closed · replay unavailable"));
    drop(closure_events);
    drop(closure_dashboard);
    drop(replay_dashboard);
    drop(dashboard);
    drop(client);
    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_wss_inspector_captures_first_message_in_both_directions() {
    let (origin, origin_task) = spawn_tls_websocket_origin().await;
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
        .websocket(format!("wss://{origin}/echo"))
        .handshake(extensions)
        .await
        .unwrap();

    websocket
        .send_message(Message::text("first client message"))
        .await
        .unwrap();
    assert_eq!(
        websocket.recv_message().await.unwrap(),
        Message::text("first client message")
    );

    let dashboard = EasyHttpWebClient::default();
    let response = dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{ui_address}/"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    let session = dashboard_session_id(&html);
    let signal_body = format!(r#"{{"session":"{session}"}}"#);
    let response = dashboard
        .serve(dashboard_request(
            Request::builder()
                .method(rama::http::Method::POST)
                .uri(format!("http://{ui_address}/api/focus/request/1"))
                .body(Body::from(signal_body))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let signals = format!("datastar=%7B%22session%22%3A%22{session}%22%7D");
    let response = dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{ui_address}/events?{signals}"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = next_sse_event(&mut events).await;
    assert!(event.contains("WSS exchange #1"), "{event}");
    assert!(event.contains("messages 1–2 of 2"), "{event}");
    assert!(event.contains("Client → Server"), "{event}");
    assert!(event.contains("Server → Client"), "{event}");
    assert!(event.contains("first client message"), "{event}");
    assert!(!event.contains("Client hello"), "{event}");
    assert!(!event.contains("Client ↔ inspector"), "{event}");
    assert!(!event.contains("Inspector ↔ server"), "{event}");

    drop(events);
    let connection_dashboard = EasyHttpWebClient::default();
    let response = connection_dashboard
        .serve(dashboard_request(
            Request::builder()
                .method(rama::http::Method::POST)
                .uri(format!("http://{ui_address}/api/focus/connection/1"))
                .body(Body::from(format!(r#"{{"session":"{session}"}}"#)))
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = connection_dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{ui_address}/events?{signals}"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut connection_events = response.into_body();
    let connection_event = next_sse_event(&mut connection_events).await;
    assert!(
        connection_event.contains("connection-focus"),
        "{connection_event}"
    );
    assert!(
        connection_event.contains("connection-state alive focus-state"),
        "{connection_event}"
    );
    assert!(!connection_event.contains("detail-overview-label\">Ended"));
    assert!(
        connection_event.contains("Client hello"),
        "{connection_event}"
    );
    assert!(
        connection_event.contains("Client ↔ inspector"),
        "{connection_event}"
    );
    assert!(
        connection_event.contains("Inspector ↔ server"),
        "{connection_event}"
    );
    drop(connection_events);
    drop(connection_dashboard);
    drop(websocket);
    drop(dashboard);
    drop(client);
    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_http_client_applies_connect_timeout_to_tls_handshake() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let listener_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        _ = accepted_tx.send(());
        std::future::pending::<()>().await;
        drop(socket);
    });
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: Some(Duration::from_millis(50)),
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(None, false, &[]).unwrap(),
        icap: None,
    });
    let started = tokio::time::Instant::now();
    let response = timeout(
        Duration::from_secs(2),
        client.serve(
            Request::builder()
                .uri(format!("https://{address}/"))
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("forward HTTP client ignored its connect timeout")
    .unwrap();
    assert!(response.status().is_server_error());
    assert!(started.elapsed() >= Duration::from_millis(25));
    timeout(Duration::from_secs(1), accepted_rx)
        .await
        .expect("client did not reach the stalled TLS peer")
        .unwrap();
    listener_task.abort();
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
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: Some(store.clone()),
        inspection: store.inspection_state(),
        har: HarController::default(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: None,
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream: UpstreamProxyConfig::new(None, false, &[]).unwrap(),
        icap: None,
    });
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
        Box::pin(relay_service.serve(BridgeIo(relay_ingress, relay_egress))).await
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

    store
        .send_websocket_message(1, "ingress", "text", "custom to server")
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_egress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("custom to server")
    );
    store
        .send_websocket_message(1, "egress", "binary", &BASE64.encode(b"custom to client"))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), peer_ingress.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::binary(rama::bytes::Bytes::from_static(b"custom to client"))
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
        store.replay_websocket_message(1, 6).await,
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
    assert_eq!(
        details
            .records
            .iter()
            .filter(|record| matches!(
                record,
                capture::StoredRecord::WebSocketMessage { injected: true, .. }
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
    let client = new_proxy_client(ProxyClientConfig {
        exec: Executor::default(),
        capture: None,
        inspection: InspectionState::default(),
        har: har.clone(),
        portal: None,
        tcp_options: Arc::new(SocketOptions::default_tcp()),
        connect_timeout: None,
        mitm_policy: MitmPolicy::try_new(&[], &[]).unwrap(),
        upstream,
        icap: None,
    });
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
    let origin_listener =
        TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_http_and_socks5_mitm_apply_icap_reqmod_and_respmod() {
    let (icap_address, icap_task, _icap_state) = spawn_proxy_test_icap().await;
    let origin_listener =
        TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
            .await
            .unwrap();
    let origin_address = origin_listener.local_addr().unwrap();
    let origin_tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .unwrap()
        .with_alpn_http_auto();
    let origin_http =
        HttpServer::auto(Executor::default()).service(service_fn(|request: Request| async move {
            assert_eq!(request.headers()["x-rama-icap-reqmod"], "yes");
            assert!(
                !request
                    .headers()
                    .contains_key(rama::http::header::PROXY_AUTHORIZATION)
            );
            Ok::<_, Infallible>(Response::new(Body::from("mitm-icap-ok")))
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
    let icap_uri = format!("icap://{icap_address}/adapt");
    let cli = TestCli::parse_from([
        "test",
        "--bind",
        proxy_arg.as_str(),
        mitm_arg.as_str(),
        "--icap",
        icap_uri.as_str(),
    ]);
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
    for scheme in ["http", "socks5h"] {
        let response = timeout(
            Duration::from_secs(10),
            client.serve(
                Request::builder()
                    .uri(format!("https://{origin_address}/icap"))
                    .extension(ProxyRoute::Proxy(
                        format!("{scheme}://{proxy_address}").parse().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("ICAP-adapted {scheme} MITM request timed out"))
        .unwrap_or_else(|error| panic!("ICAP-adapted {scheme} MITM request failed: {error}"));
        assert_eq!(response.status(), StatusCode::OK, "proxy scheme {scheme}");
        assert_eq!(
            response.headers()["x-rama-icap-respmod"],
            "yes",
            "proxy scheme {scheme}",
        );
        assert!(
            !response
                .headers()
                .contains_key(rama::http::header::PROXY_AUTHENTICATE),
            "proxy scheme {scheme}",
        );
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "mitm-icap-ok",
            "proxy scheme {scheme}",
        );
    }
    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
    icap_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pausing_inspector_tunnels_origin_tls_without_capturing_until_resumed() {
    let origin_listener =
        TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default())
            .await
            .unwrap();
    let origin_address = origin_listener.local_addr().unwrap();
    let origin_tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .unwrap()
        .with_alpn_http_auto();
    let origin_http =
        HttpServer::auto(Executor::default()).service(service_fn(|_request: Request| async move {
            Ok::<_, Infallible>(Response::new(Body::from("pause-roundtrip-ok")))
        }));
    let origin_task = tokio::spawn(origin_listener.serve(TlsAcceptorService::new(
        origin_tls,
        origin_http,
        false,
    )));

    let proxy_address = reserve_loopback_address();
    let ui_address = reserve_loopback_address();
    let directory = rama::utils::fs::tempdir().unwrap();
    let ca_path = directory.path().join("pause-proxy-ca.pem");
    let proxy_arg = proxy_address.to_string();
    let mitm_arg = format!("--mitm={ui_address}");
    let ca_arg = ca_path.to_string_lossy().into_owned();
    let cli = TestCli::parse_from([
        "test",
        "--bind",
        proxy_arg.as_str(),
        mitm_arg.as_str(),
        "--mitm-ca-cert",
        ca_arg.as_str(),
    ]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();

    let dashboard_client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(TlsClientConfig::default_http())
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let dashboard = dashboard_client
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{ui_address}/"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let dashboard = dashboard.into_body().collect().await.unwrap().to_bytes();
    let dashboard = String::from_utf8(dashboard.to_vec()).unwrap();
    let session = dashboard_session_id(&dashboard).to_owned();

    let ca_pem = tokio::fs::read(&ca_path).await.unwrap();
    let trust_anchor = CertificateDer::from_pem_slice(&ca_pem).unwrap();
    let trusted_tls = TlsClientConfig::new()
        .try_with_server_trust_anchors([trust_anchor])
        .unwrap();
    let trusted_client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(trusted_tls)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    let insecure_tls = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    let insecure_client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(insecure_tls)
        .with_default_http_connector(Executor::default())
        .without_connection_pool()
        .build_client();
    // Use a DNS identity so the generated MITM leaf can be verified against
    // the exported proxy CA. The origin still resolves to this loopback test
    // listener and presents its independently generated self-signed leaf.
    let target = format!("https://localhost:{}/pause", origin_address.port());
    let proxy_route = || ProxyRoute::Proxy(format!("http://{proxy_address}").parse().unwrap());
    let request = || {
        Request::builder()
            .uri(target.as_str())
            .extension(proxy_route())
            .body(Body::empty())
            .unwrap()
    };

    let response = trusted_client.serve(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await.unwrap();

    let control = |path: &str| {
        dashboard_request(
            Request::builder()
                .method(rama::http::Method::POST)
                .uri(format!("http://{ui_address}{path}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "session": session }).to_string(),
                ))
                .unwrap(),
        )
    };
    let paused = dashboard_client
        .serve(control("/api/inspection/pause"))
        .await
        .unwrap();
    assert_eq!(paused.status(), StatusCode::NO_CONTENT);

    // The origin certificate is no longer replaced by the inspector CA.
    timeout(Duration::from_secs(10), trusted_client.serve(request()))
        .await
        .unwrap()
        .unwrap_err();
    let response = insecure_client.serve(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "pause-roundtrip-ok"
    );

    let response = dashboard_client
        .serve(dashboard_request(
            Request::builder()
                .uri(format!(
                    "http://{ui_address}/events?datastar=%7B%22session%22%3A%22{session}%22%7D"
                ))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = next_sse_event(&mut events).await;
    assert!(event.contains("data-inspection-paused=\"true\""));
    assert!(event.contains("<span>Requests</span><strong>1</strong>"));
    drop(events);

    let resumed = dashboard_client
        .serve(control("/api/inspection/resume"))
        .await
        .unwrap();
    assert_eq!(resumed.status(), StatusCode::NO_CONTENT);
    let response = trusted_client.serve(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await.unwrap();

    let response = dashboard_client
        .serve(dashboard_request(
            Request::builder()
                .uri(format!(
                    "http://{ui_address}/events?datastar=%7B%22session%22%3A%22{session}%22%7D"
                ))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let mut events = response.into_body();
    let event = next_sse_event(&mut events).await;
    assert!(event.contains("data-inspection-paused=\"false\""));
    assert!(event.contains("<span>Requests</span><strong>2</strong>"));
    drop(events);

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

async fn interception_api(
    address: std::net::SocketAddr,
    session: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> serde_json::Value {
    let client = EasyHttpWebClient::default();
    let (method, url, body) = match body {
        Some(mut value) => {
            value["session"] = session.into();
            (
                rama::http::Method::POST,
                format!("http://{address}{path}"),
                Body::from(serde_json::to_vec(&value).unwrap()),
            )
        }
        None => (
            rama::http::Method::GET,
            format!("http://{address}{path}?session={session}"),
            Body::empty(),
        ),
    };
    let response = client
        .serve(dashboard_request(
            Request::builder()
                .method(method)
                .uri(url)
                .header("content-type", "application/json")
                .body(body)
                .unwrap(),
        ))
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        status.is_success(),
        "{status}: {}",
        String::from_utf8_lossy(&body)
    );
    if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    }
}

async fn wait_interception(
    address: std::net::SocketAddr,
    session: &str,
    count: usize,
) -> serde_json::Value {
    timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = interception_api(address, session, "/api/control", None).await;
            if snapshot["control"]["pending"].as_array().unwrap().len() == count {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("interception queue did not reach expected size")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_interception_holds_upgrade_and_websocket_data_but_not_control_frames() {
    use serde_json::json;
    let (origin, origin_task) = spawn_websocket_origin().await;
    let address = reserve_loopback_address();
    let cli = TestCli::parse_from([
        "test",
        "--bind",
        &address.to_string(),
        &format!("--mitm={address}"),
        "--intercept",
    ]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    run(shutdown.guard(), cli.proxy).await.unwrap();
    let dashboard = EasyHttpWebClient::default();
    let response = dashboard
        .serve(dashboard_request(
            Request::builder()
                .uri(format!("http://{address}/"))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let session = dashboard_session_id(&String::from_utf8_lossy(&html)).to_owned();
    let client = proxy_websocket_client();
    let extensions = Extensions::new();
    extensions.insert(ProxyRoute::Proxy(
        format!("http://{address}").parse().unwrap(),
    ));
    let handshake = tokio::spawn(async move {
        client
            .websocket(format!("ws://{origin}/echo"))
            .handshake(extensions)
            .await
            .unwrap()
    });
    for direction in ["request", "response"] {
        let state = wait_interception(address, &session, 1).await;
        let pending = &state["control"]["pending"][0];
        assert_eq!(pending["direction"], direction);
        assert!(!handshake.is_finished());
        let results = interception_api(
            address,
            &session,
            "/api/control/decision",
            Some(json!({"ids": [pending["id"]], "decision": {"action": "forward"}})),
        )
        .await;
        assert!(results[0]["error"].is_null(), "{results}");
    }
    let mut socket = timeout(Duration::from_secs(2), handshake)
        .await
        .unwrap()
        .unwrap();
    socket
        .send_message(Message::text("original"))
        .await
        .unwrap();
    let state = wait_interception(address, &session, 1).await;
    let pending = &state["control"]["pending"][0];
    assert_eq!(pending["protocol"], "ws");
    assert_eq!(pending["direction"], "ingress");
    socket
        .send_message(Message::Ping(rama::bytes::Bytes::from_static(b"alive")))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::Pong(rama::bytes::Bytes::from_static(b"alive"))
    );
    interception_api(address, &session, "/api/control/decision", Some(json!({"ids": [pending["id"]], "decision": {"action": "forward", "payload": "edited upstream"}}))).await;
    let state = wait_interception(address, &session, 1).await;
    let pending = &state["control"]["pending"][0];
    assert_eq!(pending["direction"], "egress");
    let message = interception_api(
        address,
        &session,
        &format!("/api/control/pending/{}", pending["id"]),
        None,
    )
    .await;
    assert_eq!(message["payload"], "edited upstream");
    interception_api(address, &session, "/api/control/decision", Some(json!({"ids": [pending["id"]], "decision": {"action": "forward", "payload": "edited downstream"}}))).await;
    assert_eq!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("edited downstream")
    );

    socket
        .send_message(Message::binary(vec![0, 255, 3]))
        .await
        .unwrap();
    let state = wait_interception(address, &session, 1).await;
    let pending = &state["control"]["pending"][0];
    interception_api(
        address,
        &session,
        "/api/control/decision",
        Some(json!({"ids": [pending["id"]], "decision": {"action": "drop"}})),
    )
    .await;
    wait_interception(address, &session, 0).await;
    socket
        .send_message(Message::text("release connection"))
        .await
        .unwrap();
    let state = wait_interception(address, &session, 1).await;
    let pending = &state["control"]["pending"][0];
    let connection = pending["connection"].clone();
    interception_api(
        address,
        &session,
        "/api/control/decision",
        Some(json!({"ids": [pending["id"]], "decision": {"action": "connection"}})),
    )
    .await;
    assert_eq!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("release connection")
    );
    socket
        .send_message(Message::text("future messages also pass"))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("future messages also pass")
    );
    interception_api(
        address,
        &session,
        &format!("/api/control/resume/{connection}"),
        Some(json!({})),
    )
    .await;
    socket
        .send_message(Message::text("cancel this pending message"))
        .await
        .unwrap();
    wait_interception(address, &session, 1).await;
    socket.send_message(Message::Close(None)).await.unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::Close(_)
    ));
    wait_interception(address, &session, 0).await;
    drop(socket);
    // Pause ends an already inspected idle WebSocket, then new upgraded
    // connections relay raw bytes without recording or approval rules.
    interception_api(
        address,
        &session,
        "/api/control/forward-all",
        Some(json!({})),
    )
    .await;
    let connect = || async {
        let extensions = Extensions::new();
        extensions.insert(ProxyRoute::Proxy(
            format!("http://{address}").parse().unwrap(),
        ));
        proxy_websocket_client()
            .websocket(format!("ws://{origin}/echo"))
            .handshake(extensions)
            .await
            .unwrap()
    };
    let mut socket = connect().await;
    socket
        .send_message(Message::text("before pause"))
        .await
        .unwrap();
    assert_eq!(
        socket.recv_message().await.unwrap(),
        Message::text("before pause")
    );
    interception_api(address, &session, "/api/inspection/pause", Some(json!({}))).await;
    let closed = timeout(Duration::from_secs(2), socket.recv_message())
        .await
        .unwrap();
    assert!(closed.is_err() || matches!(closed, Ok(Message::Close(_))));
    let paused = interception_api(address, &session, "/api/control", None).await;
    assert_eq!(paused["control"]["recording"], false);
    let mut socket = connect().await;
    socket
        .send_message(Message::text("raw while paused"))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), socket.recv_message())
            .await
            .unwrap()
            .unwrap(),
        Message::text("raw while paused")
    );
    let after = wait_interception(address, &session, 0).await;
    assert_eq!(after["control"]["hosts"], paused["control"]["hosts"]);
    drop(socket);
    _ = shutdown_tx.send(());
    shutdown
        .shutdown_with_limit(Duration::from_secs(2))
        .await
        .unwrap();
    origin_task.abort();
}
