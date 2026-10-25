use super::utils;
use parking_lot::Mutex;
use rama::{
    Layer, Service,
    crypto::pem::PemEncode as _,
    error::{BoxError, error_chain, extra::OpaqueError},
    extensions::{Egress, Extensions, ExtensionsRef as _},
    http::{
        Body, Method, Request, Response, StatusCode, Version,
        body::util::BodyExt as _,
        client::{
            EasyHttpWebClient, Http3Connector,
            proxy::layer::{HttpProxyConnectorLayer, HttpProxyError},
        },
        conn::TargetHttpVersion,
        headers::SecWebSocketProtocol,
        layer::error_handling::ErrorHandlerLayer,
        proto::ext::Protocol as ConnectProtocol,
        server::HttpServer,
        service::client::HttpClientExt as _,
        ws::{
            Message,
            handshake::{
                client::{HandshakeError, HttpClientWebSocketExt as _, ResponseValidateError},
                matcher::is_http_req_websocket_handshake,
                server::{ECHO_SERVICE_SUB_PROTOCOL_DEFAULT, WebSocketAcceptor},
            },
        },
    },
    layer::MapInputLayer,
    net::{
        Protocol,
        address::{HostWithPort, ProxyAddress},
        client::ProxyRoute,
        process::ProcessSocket,
        transport::TransportProtocol,
        user::{Basic, Bearer},
    },
    quic::tls::BoringTlsProvider,
    rt::Executor,
    service::{BoxService, service_fn},
    tcp::server::TcpListener,
    tls::{
        boring::server::TlsAcceptorLayer,
        client::{NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig},
        server::{ServerAuthData, TlsServerConfig},
    },
    utils::fs::tempdir,
};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

type Certificates = Arc<Mutex<Vec<Vec<u8>>>>;

fn client(outer: Version) -> (BoxService<Request, Response, OpaqueError>, Certificates) {
    let tls = TlsClientConfig::default_http()
        .with_server_verify(ServerVerifyMode::Disable)
        .with_store_server_cert_chain(true);
    let h3 = Http3Connector::builder(Executor::new())
        .with_tls_config(tls.clone())
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .build_lazy()
        .unwrap();
    let certificates = Certificates::default();
    let observed = certificates.clone();
    let web = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_custom_proxy_connector(
            HttpProxyConnectorLayer::optional()
                .with_version(outer)
                .with_tls_proxy_support(false),
        )
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector(Executor::new())
        .with_http3_support(h3)
        .with_default_connection_pool()
        .build_client()
        .with_jit_layer(MapInputLayer::new(move |req: Request| {
            let egress = req.extensions().get_ref::<Egress<Extensions>>().unwrap();
            let tls = egress.0.get_ref::<NegotiatedTlsParameters>().unwrap();
            observed.lock().push(
                tls.peer_certificate_chain.as_ref().unwrap()[0]
                    .as_ref()
                    .to_vec(),
            );
            req
        }));

    (web.boxed(), certificates)
}

fn route(address: std::net::SocketAddr, username: Option<&str>) -> ProxyRoute {
    ProxyRoute::Proxy(ProxyAddress {
        protocol: Some(Protocol::HTTP),
        address: address.into(),
        credential: username
            .map(|name| Basic::new(name.parse().unwrap(), "secret".parse().unwrap()).into()),
    })
}

fn assert_proxy_status(error: &BoxError, expected: StatusCode) {
    let status = error_chain(error.as_ref()).find_map(|cause| {
        match cause.downcast_ref::<HttpProxyError>() {
            Some(HttpProxyError::Rejected(status) | HttpProxyError::UpstreamFailure(status)) => {
                Some(*status)
            }
            _ => None,
        }
    });
    assert_eq!(status, Some(expected), "{error:?}");
}

async fn websocket_exchange(
    web: &BoxService<Request, Response, OpaqueError>,
    target: &str,
    version: Version,
    route: ProxyRoute,
    compressed: bool,
) {
    let url = format!("wss://{target}/ws");
    let builder = match version {
        Version::HTTP_11 => web.websocket(url),
        Version::HTTP_2 => web.websocket_h2(url),
        Version::HTTP_3 => web.websocket_h3(url),
        _ => unreachable!(),
    };
    let builder = if compressed {
        builder.with_per_message_deflate_overwrite_extensions()
    } else {
        builder
    };
    let builder =
        builder.with_protocols(SecWebSocketProtocol::new(ECHO_SERVICE_SUB_PROTOCOL_DEFAULT));
    let extensions = Extensions::new();
    extensions.insert(route);
    let mut socket = builder
        .handshake(extensions.clone())
        .await
        .unwrap_or_else(|error| {
            panic!("{version:?}, compressed={compressed}, target={target}: {error:?}")
        });
    assert_eq!(socket.accepted_protocol(), Some("echo"));
    assert_eq!(
        socket
            .response()
            .headers
            .contains_key("sec-websocket-extensions"),
        compressed
    );
    assert_eq!(socket.response().version, version);
    assert_eq!(
        socket.response().status,
        if version == Version::HTTP_11 {
            StatusCode::SWITCHING_PROTOCOLS
        } else {
            StatusCode::OK
        }
    );
    for message in [
        Message::text("hello through the proxy"),
        Message::binary(vec![42; 65536]),
    ] {
        socket.send_message(message.clone()).await.unwrap();
        assert_eq!(socket.recv_message().await.unwrap(), message);
    }
    socket
        .send_message(Message::Ping(b"ping".as_slice().into()))
        .await
        .unwrap();
    assert_eq!(
        socket.recv_message().await.unwrap(),
        Message::Pong(b"ping".as_slice().into())
    );
    socket.close(None).await.unwrap();
    assert_eq!(socket.recv_message().await.unwrap(), Message::Close(None));

    let url = format!("wss://{target}/ws-denied");
    let builder = match version {
        Version::HTTP_11 => web.websocket(url),
        Version::HTTP_2 => web.websocket_h2(url),
        Version::HTTP_3 => web.websocket_h3(url),
        _ => unreachable!(),
    };
    let error = builder.handshake(extensions).await.err().unwrap();
    assert!(
        matches!(
            error,
            HandshakeError::ValidationError(ResponseValidateError::UnexpectedStatusCode(
                StatusCode::FORBIDDEN
            ))
        ),
        "{error:?}"
    );
}

#[tokio::test]
#[ignore = "runs example processes"]
async fn test_http_version_proxy() {
    utils::init_tracing();
    let directory = tempdir().unwrap();
    let auth = ServerAuthData::new_self_signed_leaf(Default::default()).unwrap();
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    tokio::fs::write(&cert, auth.cert_chain[0].to_pem())
        .await
        .unwrap();
    tokio::fs::write(&key, auth.private_key.to_pem())
        .await
        .unwrap();

    let listener = TcpListener::bind_address("127.0.0.1:0", Executor::new())
        .await
        .unwrap();
    let origin = listener.local_addr().unwrap().to_string();
    let origin_host = origin.clone();
    let origin_requests = Arc::new(AtomicUsize::new(0));
    let received = origin_requests.clone();
    let service =
        HttpServer::new_http1(Executor::new()).service(service_fn(move |req: Request| {
            received.fetch_add(1, Ordering::Relaxed);
            let origin_host = origin_host.clone();
            async move {
                assert_eq!(req.version(), Version::HTTP_11);
                if is_http_req_websocket_handshake(&req) {
                    if req.uri().path_or_root() == "/ws-denied" {
                        let mut response = Response::new(Body::empty());
                        *response.status_mut() = StatusCode::FORBIDDEN;
                        return Ok(response);
                    }
                    return ErrorHandlerLayer::new()
                        .into_layer(
                            WebSocketAcceptor::new()
                                .with_per_message_deflate()
                                .into_echo_service(),
                        )
                        .serve(req)
                        .await;
                }
                assert_eq!(req.headers()["host"], origin_host);
                for name in [
                    "proxy-authorization",
                    "x-remove",
                    "keep-alive",
                    "proxy-connection",
                ] {
                    assert!(
                        !req.headers().contains_key(name),
                        "unexpected forwarded {name}"
                    );
                }
                let path = req.uri().path_or_root().to_string();
                let query = req.uri().query_or_empty().to_string();
                assert!(!req.headers().contains_key("forwarded"));
                assert!(!req.headers().contains_key("x-forwarded-for"));
                assert_eq!(req.headers()["x-forwarded-proto"], "https");
                let via = req.headers()["via"].clone();
                let host = req.headers().get("x-forwarded-host").cloned().unwrap();
                // This origin waits for the entire upload before sending headers.
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let mut response = Response::new(Body::from(body));
                response
                    .headers_mut()
                    .insert("x-seen-path", path.parse().unwrap());
                response
                    .headers_mut()
                    .insert("x-seen-query", query.parse().unwrap());
                response.headers_mut().insert("x-seen-host", host);
                response.headers_mut().insert("x-seen-via", via);
                Ok::<_, Infallible>(response)
            }
        }));
    let origin_task = tokio::spawn(async move {
        listener.serve(service).await;
    });

    // A separate TLS origin tests MITM independently of ingress.
    let tls_listener = TcpListener::bind_address("127.0.0.1:0", Executor::new())
        .await
        .unwrap();
    let tls_target = HostWithPort::new(
        "localhost".parse().unwrap(),
        tls_listener.local_addr().unwrap().port(),
    );
    let tls_requests = Arc::new(AtomicUsize::new(0));
    let received = tls_requests.clone();
    let mut tls_http = HttpServer::auto(Executor::new());
    tls_http.h2_mut().set_enable_connect_protocol();
    let tls_service = TlsAcceptorLayer::new(
        TlsServerConfig::new()
            .with_server_auth(auth)
            .with_alpn_http_auto(),
    )
    .into_layer(tls_http.service(service_fn(move |req: Request| {
        received.fetch_add(1, Ordering::Relaxed);
        async move {
            if req.uri().path_or_root() == "/credentials" {
                assert!(!req.headers().contains_key("proxy-authorization"));
                return Ok(Response::new(Body::from(format!("{:?}", req.version()))));
            }
            if req.uri().path_or_root() == "/ws-denied" {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::FORBIDDEN;
                return Ok(response);
            }
            ErrorHandlerLayer::new()
                .into_layer(
                    WebSocketAcceptor::new()
                        .with_per_message_deflate()
                        .into_echo_service(),
                )
                .serve(req)
                .await
        }
    })));
    let tls_origin_task = tokio::spawn(async move {
        tls_listener.serve(tls_service).await;
    });

    let mut ingress = utils::ExampleRunner::capturing(
        utils::example!("http_version_proxy"),
        [
            "ingress",
            "--listen",
            "127.0.0.1:0",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--upstream",
            &format!("http://{origin}"),
        ],
    );
    let ingress_address = ingress.tcp_listener_addr().await;
    utils::wait_for_socket(
        &mut ingress.server_process,
        ProcessSocket {
            protocol: TransportProtocol::Udp,
            local_addr: ingress_address,
        },
    )
    .await
    .unwrap();
    let target = HostWithPort::new("localhost".parse().unwrap(), ingress_address.port());
    let mut mitm = utils::ExampleRunner::capturing(
        utils::example!("http_version_proxy"),
        [
            "mitm",
            "--listen",
            "127.0.0.1:0",
            "--upstream-ca",
            cert.to_str().unwrap(),
        ],
    );
    let proxy = mitm.tcp_listener_addr().await;

    timeout(LIMIT, async {
        // Unsupported upgrade protocols are rejected before reaching either origin.
        for (outer, proxy_route, upgrade_target) in [
            (Version::HTTP_11, ProxyRoute::Direct, &target),
            (Version::HTTP_11, route(proxy, None), &tls_target),
            (Version::HTTP_11, route(proxy, Some("john-h1")), &tls_target),
            (Version::HTTP_2, route(proxy, None), &tls_target),
            (Version::HTTP_2, route(proxy, Some("john-h1")), &tls_target),
        ] {
            let (web, _) = client(outer);
            let response = web
                .get(format!("https://{upgrade_target}/upgrade"))
                .version(Version::HTTP_11)
                .extension(TargetHttpVersion(Version::HTTP_11))
                .extension(proxy_route)
                .header("connection", "upgrade")
                .header("upgrade", "unsupported-example")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
            assert!(!response.headers().contains_key("upgrade"));
            response.into_body().collect().await.unwrap();
        }
        for outer in [Version::HTTP_11, Version::HTTP_2] {
            let (web, _) = client(outer);
            for (connect_target, proxy_route, versions) in [
                (
                    &target,
                    ProxyRoute::Direct,
                    &[Version::HTTP_11, Version::HTTP_2, Version::HTTP_3][..],
                ),
                (
                    &tls_target,
                    route(proxy, None),
                    &[Version::HTTP_11, Version::HTTP_2][..],
                ),
            ] {
                for &version in versions {
                    for extended in [false, true] {
                        if extended && version == Version::HTTP_11 {
                            continue;
                        }
                        let req = Request::builder()
                            .method(Method::CONNECT)
                            .uri(format!("https://{connect_target}/"))
                            .version(version)
                            .body(Body::empty())
                            .unwrap();
                        req.extensions().insert(TargetHttpVersion(version));
                        req.extensions().insert(proxy_route.clone());
                        if extended {
                            req.extensions()
                                .insert(ConnectProtocol::from_static("unsupported-example"));
                        }
                        let response = web.serve(req).await.unwrap();
                        assert_eq!(
                            response.status(),
                            StatusCode::NOT_IMPLEMENTED,
                            "{outer:?}/{version:?}, extended={extended}"
                        );
                        response.into_body().collect().await.unwrap();
                    }
                }
            }
        }
        assert_eq!(origin_requests.load(Ordering::Relaxed), 0);
        assert_eq!(tls_requests.load(Ordering::Relaxed), 0);

        // Exercise the executable's listeners and routing labels with real frames.
        let (web, _) = client(Version::HTTP_11);
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            for compressed in [false, true] {
                websocket_exchange(
                    &web,
                    &target.to_string(),
                    version,
                    ProxyRoute::Direct,
                    compressed,
                )
                .await;
            }
        }
        for outer in [Version::HTTP_11, Version::HTTP_2] {
            let (web, _) = client(outer);
            for inner in [Version::HTTP_11, Version::HTTP_2] {
                for username in [None, Some("john-h1"), Some("john-h2"), Some("john-h3")] {
                    for compressed in [false, true] {
                        websocket_exchange(
                            &web,
                            &target.to_string(),
                            inner,
                            route(proxy, username),
                            compressed,
                        )
                        .await;
                    }
                    if username != Some("john-h3") {
                        websocket_exchange(
                            &web,
                            &tls_target.to_string(),
                            inner,
                            route(proxy, username),
                            false,
                        )
                        .await;
                    }
                }
            }
        }

        let mut previous_cert = None;
        for outer in [Version::HTTP_11, Version::HTTP_2] {
            let (web, certificates) = client(outer);
            for inner in [Version::HTTP_11, Version::HTTP_2] {
                for username in [
                    None,
                    Some("john-region"),
                    Some("john-region-h1"),
                    Some("john-h2"),
                    Some("john-h3"),
                    Some("john-H2"),
                ] {
                    let expected_version = match username {
                        Some("john-region-h1") => "1.1 rama",
                        Some("john-h2" | "john-H2") => "2 rama",
                        Some("john-h3") => "3 rama",
                        _ if inner == Version::HTTP_2 => "2 rama",
                        _ => "1.1 rama",
                    };
                    for (method, payload) in [
                        (Method::GET, ""),
                        (Method::HEAD, ""),
                        (Method::POST, "payload"),
                    ] {
                        let response = web
                            .request(method, format!("https://{target}/a%2Fb?x=%26&empty="))
                            .version(inner)
                            .extension(TargetHttpVersion(inner))
                            .extension(route(proxy, username))
                            .header("x-forwarded-host", "untrusted.example")
                            .header("x-forwarded-proto", "http")
                            .header("x-forwarded-for", "192.0.2.1")
                            .header("forwarded", "for=192.0.2.1;proto=http")
                            .header("via", "0.9 untrusted")
                            .header("proxy-authorization", "must-not-reach-origin")
                            .body(payload)
                            .send()
                            .await
                            .unwrap();
                        assert_eq!(response.status(), StatusCode::OK);
                        assert_eq!(response.headers()["x-seen-via"], expected_version);
                        assert_eq!(response.headers()["x-seen-path"], "/a%2Fb");
                        assert_eq!(response.headers()["x-seen-query"], "x=%26&empty=");
                        assert_eq!(response.headers()["x-seen-host"], target.to_string());
                        assert_eq!(
                            response.into_body().collect().await.unwrap().to_bytes(),
                            payload
                        );
                    }
                }
            }
            for certificate in certificates.lock().drain(..) {
                if let Some(previous) = &previous_cert {
                    assert_eq!(&certificate, previous, "issuer/cache shared across tunnels");
                }
                previous_cert = Some(certificate);
            }

            for username in ["john-h1-h3", "john-h2-h2", "john-h4", "john-H0"] {
                let error = web
                    .get(format!("https://{target}/"))
                    .extension(route(proxy, Some(username)))
                    .send()
                    .await
                    .unwrap_err();
                assert_proxy_status(&error, StatusCode::BAD_REQUEST);
            }
            let mut bearer_proxy = ProxyAddress {
                protocol: Some(Protocol::HTTP),
                address: proxy.into(),
                credential: None,
            };
            bearer_proxy.credential = Some(Bearer::try_from("token").unwrap().into());
            let error = web
                .get(format!("https://{target}/"))
                .extension(ProxyRoute::Proxy(bearer_proxy))
                .send()
                .await
                .unwrap_err();
            assert_proxy_status(&error, StatusCode::BAD_REQUEST);

            let error = web
                .get(format!("https://{origin}/"))
                .extension(route(proxy, Some("john-h2")))
                .send()
                .await
                .unwrap_err();
            assert_proxy_status(&error, StatusCode::BAD_GATEWAY);
        }

        // Direct ingress exercises every listener without a proxy route.
        let (web, _) = client(Version::HTTP_11);
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let response = web
                .get(format!("https://{target}/direct?x=1"))
                .header(
                    "connection",
                    "via, x-forwarded-host, x-forwarded-proto, x-remove",
                )
                .header("x-remove", "must-not-reach-origin")
                .header("keep-alive", "timeout=5")
                .header("proxy-connection", "keep-alive")
                .header("via", "untrusted")
                .header("x-forwarded-host", "untrusted.example")
                .header("x-forwarded-proto", "http")
                .version(version)
                .extension(TargetHttpVersion(version))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["x-seen-host"], target.to_string());
            assert!(
                response.headers()["alt-svc"]
                    .to_str()
                    .unwrap()
                    .contains(&format!("h3=\":{}\"", ingress_address.port()))
            );
            response.into_body().collect().await.unwrap();
        }
    })
    .await
    .expect("executable exchange deadline");

    for outer in [Version::HTTP_11, Version::HTTP_2] {
        timeout(Duration::from_secs(20), async {
            let (web, _) = client(outer);
            let before = tls_requests.load(Ordering::SeqCst);
            let error = web
                .get(format!("https://{tls_target}/"))
                .extension(route(proxy, Some("john-h3")))
                .send()
                .await
                .unwrap_err();
            // With no QUIC listener, platforms may report refusal or wait for
            // the connection deadline. Neither may fall back to the TCP origin.
            assert!(
                error_chain(error.as_ref()).any(|cause| matches!(
                    cause.downcast_ref::<HttpProxyError>(),
                    Some(HttpProxyError::UpstreamFailure(
                        StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT
                    ))
                )),
                "{error:?}"
            );
            assert_eq!(tls_requests.load(Ordering::SeqCst), before);
        })
        .await
        .expect("strict H3 rejection deadline");
    }

    timeout(LIMIT, async {
        for outer in [Version::HTTP_11, Version::HTTP_2] {
            for (username, egress) in [("john-h1", Version::HTTP_11), ("john-h2", Version::HTTP_2)]
            {
                let (web, _) = client(outer);
                let response = web
                    .get(format!("https://{tls_target}/credentials"))
                    .version(Version::HTTP_2)
                    .extension(TargetHttpVersion(Version::HTTP_2))
                    .extension(route(proxy, Some(username)))
                    .header("proxy-authorization", "Basic must-not-reach-origin")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    response
                        .into_body()
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes()
                        .as_ref(),
                    format!("{egress:?}").as_bytes()
                );
            }
        }
    })
    .await
    .expect("isolated MITM credential deadline");

    let stalled_listener = TcpListener::bind_address("127.0.0.1:0", Executor::new())
        .await
        .unwrap();
    let stalled_target = stalled_listener.local_addr().unwrap();
    let stalled_peer = tokio::spawn(async move {
        stalled_listener
            .serve(service_fn(async |stream| {
                let _held = stream;
                std::future::pending::<Result<(), Infallible>>().await
            }))
            .await;
    });
    for outer in [Version::HTTP_11, Version::HTTP_2] {
        for username in [Some("john-h1"), None] {
            timeout(Duration::from_secs(20), async {
                let (web, _) = client(outer);
                let result = web
                    .get(format!("https://{stalled_target}/"))
                    .version(Version::HTTP_11)
                    .extension(TargetHttpVersion(Version::HTTP_11))
                    .extension(route(proxy, username))
                    .send()
                    .await;
                if username.is_some() {
                    assert_proxy_status(&result.unwrap_err(), StatusCode::GATEWAY_TIMEOUT);
                } else {
                    let response = result.unwrap();
                    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
                    response.into_body().collect().await.unwrap();
                }
            })
            .await
            .expect("executable connection timeout deadline");
        }
    }
    stalled_peer.abort();

    assert!(
        mitm.interrupt_within(LIMIT).await.success(),
        "{}",
        mitm.said()
    );
    assert!(
        ingress.interrupt_within(LIMIT).await.success(),
        "{}",
        ingress.said()
    );
    origin_task.abort();
    tls_origin_task.abort();

    // Invalid origins are rejected before opening certificate files or listeners.
    for upstream in [
        "https://localhost",
        "http://localhost/path",
        "http://localhost?x=1",
    ] {
        let output = utils::ExampleRunner::command(utils::example!("http_version_proxy"))
            .args([
                "ingress",
                "--cert",
                "missing-cert",
                "--key",
                "missing-key",
                "--upstream",
                upstream,
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("plaintext http origin"));
    }
}
