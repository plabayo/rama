use rama::{http::Method, net::Protocol};

use super::*;

#[test]
fn inspector_export_concurrency_is_opt_in() {
    assert_eq!(
        TestCli::parse_from(["test"])
            .proxy
            .inspect_export_concurrency,
        0
    );
    let cli = TestCli::parse_from(["test", "--inspect-export-concurrency", "3"]);
    assert_eq!(cli.proxy.inspect_export_concurrency, 3);
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
        .method(Method::CONNECT)
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
        .method(Method::CONNECT)
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
        .method(Method::CONNECT)
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
    assert_eq!(options.recv_buffer_size, Some(kib(4)));
    assert_eq!(options.send_buffer_size, Some(8192));
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
    let capture =
        crate::cmd::serve::proxy::capture::test_store(8, 8, kib_u64(1), ua_db.clone()).unwrap();
    let connection_id = capture
        .begin_connection_if_enabled(None, Protocol::HTTP, None)
        .unwrap();
    let dashboard = dashboard::service(
        DashboardState::new(
            capture.clone(),
            HarController::default(),
            Vec::new(),
            Arc::new(SocketOptions::default_tcp()),
            &UpstreamProxyConfig::new(None, false, &[]).unwrap(),
            MitmPolicy::try_new(&[], &[]).unwrap(),
        )
        .unwrap(),
    );
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
