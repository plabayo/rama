//! Real TCP/TLS and UDP/QUIC version-conversion and CONNECT integration tests.
//! These construct Rama service stacks directly; they do not load an example.

use rama::{
    Layer, Service,
    error::{BoxError, error_chain},
    extensions::ExtensionsRef as _,
    http::{
        Body, Request, Response, StatusCode, Version,
        client::{EasyHttpWebClient, Http3Connector},
        conn::TargetHttpVersion,
        layer::{
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            upgrade::{UpgradeLayer, UpgradeOutput, UpgradeResponse},
            version_adapter::ResponseVersionAdapter,
        },
        matcher::MethodMatcher,
        server::HttpServer,
    },
    layer::timeout::{Elapsed, Timeout},
    net::{
        address::SocketAddress, client::ConnectorService as _, tls::ApplicationProtocol, uri::Uri,
    },
    quic::{
        Endpoint, ServerConfig, TransportConfig,
        tls::{BoringTlsProvider, TlsOptions},
    },
    rt::Executor,
    service::{BoxService, service_fn},
    tcp::server::TcpListener,
    tls::{
        boring::server::{BoringServerConfigExt as _, ServerCertIssuerData, TlsAcceptorLayer},
        client::TlsClientConfig,
        server::{ServerAuthData, TlsServerConfig},
    },
};
use rama::{
    ServiceInput,
    http::{
        HeaderValue,
        body::util::BodyExt as _,
        client::{HttpClientService, http_connect},
        io::upgrade::handle_upgrade,
    },
    net::address::Host,
    tls::{
        boring::client::{TlsConnectorData, handshake::PreparedClient},
        client::ServerVerifyMode,
        server::GeneratedServerAuthConfig,
    },
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

type Web = Arc<BoxService<Request, Response, BoxError>>;
type Preflight = Arc<BoxService<Request, (), BoxError>>;

fn client(exec: Executor, tls: TlsClientConfig) -> Result<(Web, Preflight), BoxError> {
    let h3 = Http3Connector::builder(exec.clone())
        .with_tls_config(tls.clone())
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .build_lazy()?;
    let connector = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl_and_default_http_version(tls, Version::HTTP_11)
        .with_default_http_connector(exec)
        .with_http3_support(h3)
        .with_default_connection_pool()
        .build_connector();
    // Limit connection establishment, not uploads or the wait for response headers.
    let connector = Arc::new(Timeout::new(connector, CONNECT_TIMEOUT));
    let probe = connector.clone();
    let preflight = Arc::new(
        service_fn(move |req: Request| {
            let probe = probe.clone();
            async move { probe.connect(req).await.map(drop).map_err(Into::into) }
        })
        .boxed(),
    );
    let web = EasyHttpWebClient::new(connector);
    let web = ResponseVersionAdapter::new(
        (
            RemoveRequestHeaderLayer::hop_by_hop(),
            RemoveResponseHeaderLayer::hop_by_hop(),
        )
            .into_layer(web),
    );
    Ok((Arc::new(web.boxed()), preflight))
}

fn error_response(status: StatusCode, message: impl Into<Body>) -> Response {
    let mut response = Response::new(message.into());
    *response.status_mut() = status;
    response
}

fn target_uri(base: &str, req: &Request) -> Result<Uri, BoxError> {
    let query = req.uri().query_or_empty();
    let suffix = if req.uri().query().is_none() {
        String::new()
    } else {
        format!("?{query}")
    };
    Ok(format!("{base}{}{suffix}", req.uri().path_or_root()).parse()?)
}

async fn forward(web: &Web, mut req: Request, base: &str, version: Option<Version>) -> Response {
    match target_uri(base, &req) {
        Ok(uri) => *req.uri_mut() = uri,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid target URI"),
    }
    req.headers_mut().remove("host");
    req.headers_mut().remove("proxy-authorization");
    let version =
        version.or_else(|| (req.version() <= Version::HTTP_11).then_some(Version::HTTP_11));
    if let Some(version) = version {
        req.extensions().insert(TargetHttpVersion(version));
    }
    match web.serve(req).await {
        Ok(response) => response,
        Err(error) if error_chain(error.as_ref()).any(|cause| cause.is::<Elapsed>()) => {
            error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream HTTP connection timed out",
            )
        }
        Err(error) => error_response(
            StatusCode::BAD_GATEWAY,
            format!("upstream HTTP connection failed: {error}"),
        ),
    }
}

fn forwarding_service(
    web: Web,
    base: String,
    version: Option<Version>,
) -> Arc<BoxService<Request, Response, Infallible>> {
    Arc::new(
        service_fn(move |req: Request| {
            let web = web.clone();
            let base = base.clone();
            async move { Ok::<_, Infallible>(forward(&web, req, &base, version).await) }
        })
        .boxed(),
    )
}

fn mitm(
    exec: Executor,
    web: Web,
    preflight: Preflight,
    selected: Option<Version>,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    // Clones share the CA and issued-certificate cache across tunnels.
    let tls = TlsAcceptorLayer::new(
        TlsServerConfig::new()
            .with_cert_issuer(ServerCertIssuerData::default())
            .with_alpn_http_auto(),
    );
    let http = HttpServer::auto(exec.clone());
    let connect = service_fn(move |req: Request| {
        let tls = tls.clone();
        let http = http.clone();
        let web = web.clone();
        let preflight = preflight.clone();
        async move {
            let authority = req.uri().to_string();
            let authority: rama::net::address::HostWithPort =
                authority.parse().map_err(|_error| {
                    error_response(StatusCode::BAD_REQUEST, "CONNECT requires host:port")
                })?;
            let base = format!("https://{authority}");
            let probe = Request::builder()
                .uri(format!("{base}/"))
                .body(Body::empty())
                .map_err(|_error| {
                    error_response(StatusCode::BAD_REQUEST, "invalid CONNECT authority")
                })?;
            if let Some(version) = selected {
                probe.extensions().insert(TargetHttpVersion(version));
                match preflight.serve(probe).await {
                    Ok(()) => (),
                    Err(error)
                        if error_chain(error.as_ref()).any(|cause| cause.is::<Elapsed>()) =>
                    {
                        return Err(error_response(
                            StatusCode::GATEWAY_TIMEOUT,
                            format!("requested {version:?} connection timed out"),
                        ));
                    }
                    Err(error) => {
                        return Err(error_response(
                            StatusCode::BAD_GATEWAY,
                            format!("requested {version:?} unavailable: {error}"),
                        ));
                    }
                }
            }
            let inner = forwarding_service(web, base, selected);
            let tunnel = tls.into_layer(http.service(inner));
            Ok::<UpgradeOutput<Request, Response>, Response>(
                UpgradeResponse::new(req, Response::new(Body::empty()))
                    .with_handler(move |io| async move { tunnel.serve(io).await }),
            )
        }
    });
    UpgradeLayer::new(exec, MethodMatcher::CONNECT, connect).into_layer(service_fn(
        async |_: Request| {
            Ok::<_, Infallible>(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "use CONNECT",
            ))
        },
    ))
}

struct Fixture {
    address: String,
    tasks: Vec<JoinHandle<()>>,
    endpoint: Option<Endpoint>,
    upload_end: Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<bool>>>>,
    connections: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn origin() -> Fixture {
    origin_with_upload_wait(false).await
}

async fn origin_with_upload_wait(wait_for_upload: bool) -> Fixture {
    let listener = TcpListener::bind_address("127.0.0.1:0", Executor::new())
        .await
        .unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let service = HttpServer::new_http1(Executor::new()).service(service_fn(
        move |req: Request| async move {
            assert_eq!(req.version(), Version::HTTP_11);
            assert_eq!(req.uri().path_or_root(), "/echo");
            assert_eq!(req.uri().query_or_empty(), "test=1");
            assert!(!req.headers().contains_key("proxy-authorization"));
            let trailers = req.headers().get("trailer").cloned();
            let body = if wait_for_upload {
                Body::from(req.into_body().collect().await.unwrap().to_bytes())
            } else {
                req.into_body()
            };
            let mut response = Response::new(body);
            if let Some(trailers) = trailers {
                response.headers_mut().insert("trailer", trailers);
            }
            response
                .headers_mut()
                .insert("x-origin-version", HeaderValue::from_static("h1"));
            Ok::<_, Infallible>(response)
        },
    ));
    let task = tokio::spawn(async move {
        listener.serve(service).await;
    });
    Fixture {
        address,
        tasks: vec![task],
        endpoint: None,
        upload_end: Default::default(),
        connections: Default::default(),
    }
}

async fn ingress(upstream: &str, versions: &[ApplicationProtocol]) -> Fixture {
    let route = (!upstream.is_empty()).then(|| (format!("http://{upstream}"), Version::HTTP_11));
    endpoint(route, versions).await
}

async fn endpoint(route: Option<(String, Version)>, versions: &[ApplicationProtocol]) -> Fixture {
    let exec = Executor::new();
    let listener = TcpListener::bind_address("127.0.0.1:0", exec.clone())
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
    let (web, _) = client(
        exec.clone(),
        TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable),
    )
    .unwrap();
    let upload_end = Arc::new(parking_lot::Mutex::new(
        None::<tokio::sync::oneshot::Sender<bool>>,
    ));
    let observer = upload_end.clone();
    let service = Arc::new(
        service_fn(move |req: Request| {
            let observer = observer.clone();
            let web = web.clone();
            let route = route.clone();
            async move {
                let version = req.version();
                let mut response = if let Some((base, version)) = route {
                    forward(&web, req, &base, Some(version)).await
                } else {
                    let trailers = req.headers().get("trailer").cloned();
                    let head = req.method() == rama::http::Method::HEAD;
                    let no_content = req.headers().contains_key("x-no-content");
                    let observe = req.headers().contains_key("x-observe-upload");
                    let mut body = req.into_body();
                    if observe {
                        let sender = observer.lock().take();
                        body = Body::from_frame_stream(rama::futures::stream::unfold(
                            (body, sender),
                            |(mut body, mut sender)| async move {
                                let Some(frame) = body.frame().await else {
                                    if let Some(sender) = sender {
                                        _ = sender.send(true);
                                    }
                                    return None;
                                };
                                if frame.is_err()
                                    && let Some(sender) = sender.take()
                                {
                                    _ = sender.send(false);
                                }
                                Some((frame, (body, sender)))
                            },
                        ));
                    }
                    let mut response = Response::new(body);
                    if head {
                        *response.body_mut() = Body::from("HEAD representation");
                    }
                    if no_content {
                        *response.status_mut() = StatusCode::NO_CONTENT;
                        *response.body_mut() = Body::empty();
                    }
                    if let Some(trailers) = trailers {
                        response.headers_mut().insert("trailer", trailers);
                    }
                    response.headers_mut().insert(
                        "x-origin-version",
                        HeaderValue::from_str(&format!("{version:?}")).unwrap(),
                    );
                    response
                };
                response.headers_mut().insert(
                    "x-ingress-version",
                    HeaderValue::from_str(&format!("{version:?}")).unwrap(),
                );
                Ok::<_, Infallible>(response)
            }
        })
        .boxed(),
    );
    let tls = TlsServerConfig::new()
        .with_server_auth(auth.clone())
        .with_alpn(versions.iter().cloned().collect());
    let tcp = TlsAcceptorLayer::new(tls)
        .into_layer(HttpServer::auto(exec.clone()).service(service.clone()));
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = connections.clone();
    let tcp_task = tokio::spawn(async move {
        listener
            .serve(
                rama::layer::MapInputLayer::new(move |io| {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    io
                })
                .into_layer(tcp),
            )
            .await;
    });
    let http = HttpServer::new_http3(exec.clone());
    let tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut transport = TransportConfig::default();
    http.http3().configure_transport(&mut transport).unwrap();
    let mut config = ServerConfig::try_from_rama_tls_with_provider(
        &tls,
        TlsOptions::default(),
        &BoringTlsProvider,
    )
    .unwrap();
    config.set_transport_config(Arc::new(transport));
    let endpoint = Endpoint::build(exec)
        .with_server_config(config)
        .bind_address(SocketAddress::local_ipv4(port))
        .await
        .unwrap();
    let service = http.service(service);
    let quic_task = tokio::spawn(endpoint.clone().serve(Executor::new(), service));
    Fixture {
        address: format!("localhost:{port}"),
        tasks: vec![tcp_task, quic_task],
        endpoint: Some(endpoint),
        upload_end,
        connections,
    }
}

async fn proxy(selected: Option<Version>) -> Fixture {
    let exec = Executor::new();
    let (web, preflight) = client(
        exec.clone(),
        TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable),
    )
    .unwrap();
    let listener = TcpListener::bind_address("127.0.0.1:0", exec.clone())
        .await
        .unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let service = HttpServer::auto(exec.clone()).service(mitm(exec, web, preflight, selected));
    let task = tokio::spawn(async move {
        listener.serve(service).await;
    });
    Fixture {
        address,
        tasks: vec![task],
        endpoint: None,
        upload_end: Default::default(),
        connections: Default::default(),
    }
}

async fn connect(proxy: &str, target: &str, outer: Version) -> Response {
    let io = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let handshake = Request::builder()
        .version(outer)
        .uri(format!("http://{proxy}/"))
        .body(Body::empty())
        .unwrap();
    let client: HttpClientService<Body> =
        http_connect(ServiceInput::new(io), handshake, Executor::new())
            .await
            .unwrap()
            .conn;
    let request = Request::builder()
        .method("CONNECT")
        .version(outer)
        .uri(Uri::parse_authority_form(target).unwrap())
        .body(Body::empty())
        .unwrap();
    client.serve(request).await.unwrap()
}

async fn tunnel(response: Response, target: &str, version: Version) -> HttpClientService<Body> {
    assert_eq!(response.status(), StatusCode::OK);
    let io = handle_upgrade(&response).await.unwrap();
    let tls = TlsClientConfig::new()
        .with_server_verify(ServerVerifyMode::Disable)
        .with_server_name(Host::from_static("localhost"))
        .with_alpn(
            [if version == Version::HTTP_2 {
                ApplicationProtocol::HTTP_2
            } else {
                ApplicationProtocol::HTTP_11
            }]
            .into_iter()
            .collect(),
        );
    let io = PreparedClient::try_from(TlsConnectorData::try_from(&tls).unwrap())
        .unwrap()
        .connect(io)
        .await
        .unwrap();
    // PreparedClient is deliberately low-level: publish the inner protocol
    // instead of retaining the outer CONNECT connection metadata.
    io.extensions().insert(TargetHttpVersion(version));
    let request = Request::builder()
        .version(version)
        .uri(format!("https://{target}/echo?test=1"))
        .body(Body::empty())
        .unwrap();
    http_connect(io, request, Executor::new())
        .await
        .unwrap()
        .conn
}

async fn exchange(
    web: &impl Service<Request, Output = Response, Error = BoxError>,
    target: &str,
    version: Version,
    payload: usize,
) -> Response {
    let body = match payload {
        0 => Body::empty(),
        1 => Body::from("hello world"),
        _ => Body::from_stream(rama::futures::stream::iter([
            Ok::<_, Infallible>("hello "),
            Ok("world"),
        ])),
    };
    let request = Request::builder()
        .method("POST")
        .version(version)
        .uri(format!("https://{target}/echo?test=1"))
        .body(body)
        .unwrap();
    let response = web.serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), version);
    response
}

#[tokio::test]
async fn ingress_and_mitm_version_matrix() {
    timeout(Duration::from_secs(60), async {
        let origin = origin().await;
        let standalone = ingress(
            "",
            &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
        )
        .await;
        let ingress = ingress(
            &origin.address,
            &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
        )
        .await;
        // Each direct ingress protocol, independently of CONNECT.
        let (web, _) = client(
            Executor::new(),
            TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable),
        )
        .unwrap();
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let req = Request::builder()
                .version(version)
                .method("POST")
                .uri(format!("https://{}/echo?test=1", ingress.address))
                .body(Body::from("direct"))
                .unwrap();
            req.extensions().insert(TargetHttpVersion(version));
            let response = web.serve(req).await.unwrap();
            assert_eq!(
                response.headers()["x-ingress-version"],
                format!("{version:?}")
            );
            assert_eq!(
                response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .as_ref(),
                b"direct"
            );
        }
        for target in [&standalone, &ingress] {
            for outer in [Version::HTTP_11, Version::HTTP_2] {
                for inner in [Version::HTTP_11, Version::HTTP_2] {
                    for selected in [
                        None,
                        Some(Version::HTTP_11),
                        Some(Version::HTTP_2),
                        Some(Version::HTTP_3),
                    ] {
                        let expected = selected.unwrap_or(inner);
                        let proxy = proxy(selected).await;
                        let response = connect(&proxy.address, &target.address, outer).await;
                        let web = tunnel(response, &target.address, inner).await;
                        for payload in 0..3 {
                            let response = exchange(&web, &target.address, inner, payload).await;
                            assert_eq!(
                                response.headers()["x-ingress-version"],
                                format!("{expected:?}"),
                                "outer={outer:?} inner={inner:?} selected={selected:?}"
                            );
                            assert_eq!(
                                response.headers()["x-origin-version"],
                                if target.address == ingress.address {
                                    "h1".to_owned()
                                } else {
                                    format!("{expected:?}")
                                }
                            );
                            assert_eq!(
                                response
                                    .into_body()
                                    .collect()
                                    .await
                                    .unwrap()
                                    .to_bytes()
                                    .as_ref(),
                                if payload == 0 {
                                    b"".as_slice()
                                } else {
                                    b"hello world"
                                }
                            );
                        }
                    }
                }
            }
        }
        standalone.endpoint.as_ref().unwrap().shutdown().await;
        ingress.endpoint.as_ref().unwrap().shutdown().await;
    })
    .await
    .expect("proxy matrix deadline");
}

#[tokio::test]
async fn strict_override_fails_during_connect() {
    let origin = origin().await;
    let h1 = ingress(&origin.address, &[ApplicationProtocol::HTTP_11]).await;
    let h2_proxy = proxy(Some(Version::HTTP_2)).await;
    let h3_proxy = proxy(Some(Version::HTTP_3)).await;
    for outer in [Version::HTTP_11, Version::HTTP_2] {
        let response = timeout(
            Duration::from_secs(15),
            connect(&h2_proxy.address, &h1.address, outer),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("requested HTTP/2.0 unavailable"));
        // Plaintext origin has no QUIC listener. An explicit h3 target cannot
        // succeed by falling back to its working TCP listener.
        let response = timeout(
            Duration::from_secs(15),
            connect(&h3_proxy.address, &origin.address, outer),
        )
        .await
        .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT
        ));
    }
    h1.endpoint.as_ref().unwrap().shutdown().await;
}

#[tokio::test]
async fn default_version_can_fall_back_but_explicit_version_cannot() {
    timeout(Duration::from_secs(20), async {
        let origin = origin().await;
        let default_proxy = proxy(None).await;
        let strict_proxy = proxy(Some(Version::HTTP_2)).await;
        for alpns in [vec![ApplicationProtocol::HTTP_11], vec![]] {
            let h1 = ingress(&origin.address, &alpns).await;
            let response = connect(&default_proxy.address, &h1.address, Version::HTTP_11).await;
            let web = tunnel(response, &h1.address, Version::HTTP_2).await;
            let response = exchange(&web, &h1.address, Version::HTTP_2, 2).await;
            assert_eq!(response.headers()["x-ingress-version"], "HTTP/1.1");
            assert_eq!(
                response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .as_ref(),
                b"hello world"
            );
            let response = connect(&strict_proxy.address, &h1.address, Version::HTTP_11).await;
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            h1.endpoint.as_ref().unwrap().shutdown().await;
        }
    })
    .await
    .expect("fallback test deadline");
}

#[tokio::test]
async fn default_connection_failure_is_reported_inside_the_tunnel() {
    timeout(Duration::from_secs(15), async {
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = reservation.local_addr().unwrap().to_string();
        // Keep the port reserved and reject accepted streams deterministically.
        let reject = tokio::spawn(async move {
            while let Ok((stream, _)) = reservation.accept().await {
                drop(stream);
            }
        });
        let proxy = proxy(None).await;
        for outer in [Version::HTTP_11, Version::HTTP_2] {
            let response = connect(&proxy.address, &target, outer).await;
            let web = tunnel(response, &target, Version::HTTP_2).await;
            let req = Request::builder()
                .version(Version::HTTP_2)
                .uri(format!("https://{target}/"))
                .body(Body::empty())
                .unwrap();
            let response = web.serve(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            assert!(
                String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
                    .contains("upstream HTTP connection failed")
            );
        }
        reject.abort();
    })
    .await
    .expect("failure response deadline");
}

#[tokio::test]
async fn combined_proxy_streams_data_and_trailers_before_upload_finishes() {
    use rama::http::{HeaderMap, body::Frame};
    timeout(Duration::from_secs(20), async {
        let origin = origin().await;
        let ingress = ingress(
            &origin.address,
            &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
        )
        .await;
        for inner in [Version::HTTP_11, Version::HTTP_2] {
            for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
                let proxy = proxy(Some(version)).await;
                let response = connect(&proxy.address, &ingress.address, Version::HTTP_2).await;
                let web = tunnel(response, &ingress.address, inner).await;
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                let body = Body::from_frame_stream(rama::futures::stream::unfold(
                    rx,
                    |mut rx| async move {
                        rx.recv()
                            .await
                            .map(|frame| (Ok::<_, Infallible>(frame), rx))
                    },
                ));
                let request = Request::builder()
                    .method("POST")
                    .version(inner)
                    .uri(format!("https://{}/echo?test=1", ingress.address))
                    .header("te", "trailers")
                    .header("trailer", "x-checksum")
                    .body(body)
                    .unwrap();
                tx.send(Frame::data("first".into())).await.unwrap();
                let mut body = web.serve(request).await.unwrap().into_body();
                let frame = body.frame().await.unwrap().unwrap();
                assert_eq!(frame.data_ref().unwrap().as_ref(), b"first");
                tx.send(Frame::data("second".into())).await.unwrap();
                let mut trailers = HeaderMap::new();
                trailers.insert("x-checksum", HeaderValue::from_static("done"));
                tx.send(Frame::trailers(trailers)).await.unwrap();
                drop(tx);
                let rest = body.collect().await.unwrap();
                assert_eq!(rest.trailers().unwrap()["x-checksum"], "done");
                assert_eq!(rest.to_bytes().as_ref(), b"second");
            }
        }
        ingress.endpoint.as_ref().unwrap().shutdown().await;
    })
    .await
    .expect("streaming proxy deadline");
}

/// All nine protocol pairs through real sockets and the normal DNS/TLS/QUIC
/// connectors, pooling and version adapters. No example-specific routing policy.
#[tokio::test]
async fn all_network_version_pairs_preserve_http_semantics() {
    use rama::{
        futures::stream,
        http::{HeaderMap, Method, body::Frame},
    };

    timeout(Duration::from_secs(60), async {
        let origin = endpoint(
            None,
            &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
        )
        .await;
        let (web, _) = client(
            Executor::new(),
            TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable),
        )
        .unwrap();

        for egress in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let relay = endpoint(
                Some((format!("https://{}", origin.address), egress)),
                &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
            )
            .await;

            for ingress in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
                let request = |body, method| {
                    let req = Request::builder()
                        .version(ingress)
                        .method(method)
                        .uri(format!("https://{}/echo?test=1", relay.address))
                        .header("te", "trailers")
                        .header("trailer", "x-checksum")
                        .body(body)
                        .unwrap();
                    req.extensions().insert(TargetHttpVersion(ingress));
                    req
                };

                for case in 0..6 {
                    let (body, expected) = match case {
                        0 | 4 | 5 => (Body::empty(), vec![]),
                        1 => (Body::from("known"), b"known".to_vec()),
                        2 => (
                            Body::from_stream(stream::iter([
                                Ok::<_, Infallible>("one"),
                                Ok("two"),
                            ])),
                            b"onetwo".to_vec(),
                        ),
                        _ => (Body::from(vec![b'x'; 256 * 1024]), vec![b'x'; 256 * 1024]),
                    };
                    let mut req = request(
                        body,
                        if case == 4 {
                            Method::HEAD
                        } else {
                            Method::POST
                        },
                    );
                    if case == 5 {
                        req.headers_mut()
                            .insert("x-no-content", HeaderValue::from_static("1"));
                    }
                    let response = web.serve(req).await.unwrap();
                    assert_eq!(
                        response.status(),
                        if case == 5 {
                            StatusCode::NO_CONTENT
                        } else {
                            StatusCode::OK
                        }
                    );
                    assert_eq!(response.version(), ingress);
                    assert_eq!(
                        response.headers()["x-ingress-version"],
                        format!("{ingress:?}")
                    );
                    assert_eq!(
                        response.headers()["x-origin-version"],
                        format!("{egress:?}")
                    );
                    assert_eq!(
                        response
                            .into_body()
                            .collect()
                            .await
                            .unwrap()
                            .to_bytes()
                            .as_ref(),
                        expected.as_slice(),
                        "{ingress:?} -> {egress:?}, case {case}"
                    );
                }

                for fail in [false, true] {
                    let (tx, rx) = tokio::sync::mpsc::channel(1);
                    let body = Body::from_frame_stream(stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|frame| (frame, rx))
                    }));
                    tx.send(Ok(Frame::data("first".into()))).await.unwrap();
                    let (sender, observed_end) = tokio::sync::oneshot::channel();
                    let mut req = request(body, Method::POST);
                    if fail {
                        *origin.upload_end.lock() = Some(sender);
                        req.headers_mut()
                            .insert("x-observe-upload", HeaderValue::from_static("1"));
                    }
                    let response = web.serve(req).await.unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    let mut body = response.into_body();
                    assert_eq!(
                        body.frame()
                            .await
                            .unwrap()
                            .unwrap()
                            .data_ref()
                            .unwrap()
                            .as_ref(),
                        b"first"
                    );

                    if fail {
                        tx.send(Err(std::io::Error::other("injected upload failure")))
                            .await
                            .unwrap();
                        drop(tx);
                        assert!(
                            body.collect().await.is_err(),
                            "{ingress:?} -> {egress:?}: silently truncated upload"
                        );
                        assert_ne!(
                            observed_end.await,
                            Ok(true),
                            "{ingress:?} -> {egress:?}: origin saw clean EOF after upload failure"
                        );
                    } else {
                        tx.send(Ok(Frame::data("second".into()))).await.unwrap();
                        let mut trailers = HeaderMap::new();
                        trailers.insert("x-checksum", HeaderValue::from_static("done"));
                        tx.send(Ok(Frame::trailers(trailers))).await.unwrap();
                        drop(tx);
                        let rest = body.collect().await.unwrap();
                        assert_eq!(rest.trailers().unwrap()["x-checksum"], "done");
                        assert_eq!(rest.to_bytes().as_ref(), b"second");
                    }
                }
            }

            relay.endpoint.as_ref().unwrap().shutdown().await;
        }

        origin.endpoint.as_ref().unwrap().shutdown().await;
    })
    .await
    .expect("real network matrix deadline");
}

/// A peer that accepts TCP but never finishes TLS exercises the connection-only
/// deadline, both before CONNECT and after an unlabelled tunnel is accepted.
#[tokio::test]
async fn connection_timeout_returns_gateway_timeout() {
    timeout(Duration::from_secs(15), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let peer = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        for selected in [Some(Version::HTTP_11), None] {
            let proxy = proxy(selected).await;
            let mut response = connect(&proxy.address, &target, Version::HTTP_11).await;
            if selected.is_none() {
                let web = tunnel(response, &target, Version::HTTP_11).await;
                let request = Request::builder()
                    .uri(format!("https://{target}/"))
                    .body(Body::empty())
                    .unwrap();
                response = web.serve(request).await.unwrap();
            }
            assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(String::from_utf8_lossy(&body).contains("connection timed out"));
        }
        peer.abort();
    })
    .await
    .expect("connection timeout response deadline");
}

/// Malformed CONNECT targets cannot be emitted through a normal proxy client.
#[tokio::test]
async fn malformed_connect_targets_are_rejected() {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    timeout(Duration::from_secs(10), async {
        let proxy = proxy(None).await;
        for target in ["localhost", "localhost:"] {
            let mut io = tokio::net::TcpStream::connect(&proxy.address)
                .await
                .unwrap();
            io.write_all(
                format!(
                    "CONNECT {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let mut line = String::new();
            tokio::io::BufReader::new(io)
                .read_line(&mut line)
                .await
                .unwrap();
            // A parser-level rejection may close before an HTTP response can be produced.
            assert!(
                line.is_empty() || line.starts_with("HTTP/1.1 400"),
                "{target}: {line}"
            );
        }
    })
    .await
    .expect("invalid CONNECT deadline");
}

#[tokio::test]
async fn preflight_and_requests_reuse_the_upstream_connection() {
    timeout(Duration::from_secs(10), async {
        let target = ingress("", &[ApplicationProtocol::HTTP_11]).await;
        let proxy = proxy(Some(Version::HTTP_11)).await;
        let response = connect(&proxy.address, &target.address, Version::HTTP_2).await;
        let web = tunnel(response, &target.address, Version::HTTP_11).await;
        for _ in 0..2 {
            let response = exchange(&web, &target.address, Version::HTTP_11, 1).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "hello world"
            );
            assert_eq!(
                target.connections.load(std::sync::atomic::Ordering::SeqCst),
                1
            );
        }
        target.endpoint.as_ref().unwrap().shutdown().await;
    })
    .await
    .expect("pool reuse deadline");
}

#[tokio::test]
async fn slow_upload_and_response_headers_outlive_the_connection_timeout() {
    use rama::http::body::Frame;
    timeout(Duration::from_secs(15), async {
        let origin = origin_with_upload_wait(true).await;
        let ingress = ingress(&origin.address, &[ApplicationProtocol::HTTP_11]).await;
        let proxy = proxy(Some(Version::HTTP_11)).await;
        let response = connect(&proxy.address, &ingress.address, Version::HTTP_11).await;
        let web = tunnel(response, &ingress.address, Version::HTTP_11).await;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let body =
            Body::from_frame_stream(rama::futures::stream::unfold(rx, |mut rx| async move {
                rx.recv()
                    .await
                    .map(|frame| (Ok::<_, Infallible>(frame), rx))
            }));
        tx.send(Frame::data("first".into())).await.unwrap();
        let upload = tokio::spawn(async move {
            tokio::time::sleep(CONNECT_TIMEOUT + Duration::from_secs(1)).await;
            tx.send(Frame::data("second".into())).await.unwrap();
        });
        let request = Request::builder()
            .method("POST")
            .version(Version::HTTP_11)
            .uri(format!("https://{}/echo?test=1", ingress.address))
            .body(body)
            .unwrap();
        let response = web.serve(request).await.unwrap();
        upload.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "firstsecond"
        );
        ingress.endpoint.as_ref().unwrap().shutdown().await;
    })
    .await
    .expect("slow upload deadline");
}
