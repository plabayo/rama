use super::utils;
use parking_lot::Mutex;
use rama::{
    Service,
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
        server::HttpServer,
        service::client::HttpClientExt as _,
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
        client::{NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig},
        server::ServerAuthData,
    },
    utils::fs::tempdir,
};
use std::{convert::Infallible, sync::Arc, time::Duration};
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
    let service =
        HttpServer::new_http1(Executor::new()).service(service_fn(move |req: Request| {
            let origin_host = origin_host.clone();
            async move {
                assert_eq!(req.version(), Version::HTTP_11);
                assert_eq!(req.headers()["host"], origin_host);
                assert!(!req.headers().contains_key("proxy-authorization"));
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

    let mut ingress = utils::ExampleRunner::capturing(
        "http_version_proxy",
        Some("boring"),
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
        "http_version_proxy",
        Some("boring"),
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

    // Invalid origins are rejected before opening certificate files or listeners.
    for upstream in [
        "https://localhost",
        "http://localhost/path",
        "http://localhost?x=1",
    ] {
        let output = utils::ExampleRunner::command("http_version_proxy", Some("boring"))
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
