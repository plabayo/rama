//! Real TCP/TLS and UDP/QUIC version-conversion and CONNECT integration tests.
//! These construct Rama service stacks directly; they do not load an example.

use rama::{
    Layer, Service, ServiceInput,
    error::{BoxError, error_chain, extra::OpaqueError},
    extensions::{Extensions, ExtensionsRef as _},
    futures::{StreamExt as _, stream},
    http::{
        Body, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version,
        body::{Frame, util::BodyExt as _},
        client::{
            EasyHttpWebClient, Http3Connector, HttpClientService, http_connect,
            proxy::layer::HttpProxyConnectorLayer,
        },
        conn::{H2ClientContextParams, TargetHttpVersion},
        header::{HOST, UPGRADE},
        headers::SecWebSocketProtocol,
        io::upgrade::handle_upgrade,
        layer::{
            error_handling::ErrorHandlerLayer,
            into_response::IntoResponseLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            rewrite_uri::RewriteUriLayer,
            upgrade::{
                UpgradeLayer, UpgradeOutput, UpgradeResponse, mitm::HttpUpgradeMitmRelayLayer,
            },
            version_adapter::ResponseVersionAdapter,
        },
        matcher::{HttpMatcher, MethodMatcher, VersionMatcher},
        proto::{
            ext::Protocol as ConnectProtocol,
            h1::ext::{OriginalResponseBodyFraming, informational::OnInformational},
        },
        server::HttpServer,
        ws::{
            Message,
            handshake::{
                client::{HandshakeError, HttpClientWebSocketExt as _, ResponseValidateError},
                matcher::{
                    HttpWebSocketRelayServiceRequestMatcher, WebSocketMatcher,
                    is_http_req_websocket_handshake,
                },
                server::{ECHO_SERVICE_SUB_PROTOCOL_DEFAULT, WebSocketAcceptor},
            },
        },
    },
    layer::{
        AddInputExtensionLayer, HijackLayer, MapInputLayer,
        timeout::{Elapsed, Timeout},
    },
    net::{
        Protocol,
        address::{Host, ProxyAddress, SocketAddress},
        client::{ConnectorService as _, ConnectorTarget, ProxyRoute},
        socket::SocketOptions,
        stream::{Socket as _, layer::TcpStreamOptionsLayer},
        tls::{AlpnPolicy, ApplicationProtocol},
        uri::{Uri, UriMatchReplaceOrigin},
    },
    quic::{
        Endpoint, ServerConfig, TransportConfig,
        tls::{BoringTlsProvider, TlsOptions},
    },
    rt::Executor,
    service::{BoxService, StaticOutput, service_fn},
    tcp::{client::service::TcpConnector, server::TcpListener},
    tls::{
        boring::{
            client::{TlsConnectorData, handshake::PreparedClient},
            server::{BoringServerConfigExt as _, ServerCertIssuerData, TlsAcceptorLayer},
        },
        client::{ServerVerifyMode, TlsClientConfig},
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    udp::{DatagramError, UdpSocketConfig, UdpSocketFactory},
};
use std::{
    convert::Infallible,
    io::ErrorKind,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

type Web = Arc<BoxService<Request, Response, BoxError>>;
type Preflight = Arc<BoxService<Request, (), BoxError>>;

// Keep the streaming assertions independent of OS TCP buffer autotuning.
fn tcp_socket_options() -> SocketOptions {
    SocketOptions {
        recv_buffer_size: Some(64 * 1024),
        send_buffer_size: Some(64 * 1024),
        ..SocketOptions::default_tcp()
    }
}

fn client(exec: Executor, tls: TlsClientConfig) -> Result<(Web, Preflight), BoxError> {
    let h3 = Http3Connector::builder(exec.clone())
        .with_tls_config(tls.clone())
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .build_lazy()?;
    let connector = EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(
            TcpConnector::new()
                .with_connector(Arc::new(tcp_socket_options()))
                .boxed(),
        )
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl_and_default_http_version(tls, Version::HTTP_11)
        .with_default_http_connector(exec.clone())
        .with_http3_support(h3)
        .with_default_connection_pool()
        // Version policy comes from the tunnel or label, not advertised alternatives.
        .without_alt_svc()
        .build_connector();
    // Limit connection establishment, not uploads or the wait for response headers.
    let connector = AddInputExtensionLayer::new(H2ClientContextParams {
        headers_pseudo_order: Some(Default::default()),
        ..Default::default()
    })
    .into_layer(connector);
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
    // Correlate upgrade headers only after translating the response back to ingress.
    let web = RemoveResponseHeaderLayer::hop_by_hop().into_layer(ResponseVersionAdapter::new(web));
    let web = HttpUpgradeMitmRelayLayer::new(
        exec.clone(),
        HttpWebSocketRelayServiceRequestMatcher::default_with_exec(exec),
    )
    .into_layer(web);

    Ok((Arc::new(web.boxed()), preflight))
}

fn error_response(status: StatusCode, message: impl Into<Body>) -> Response {
    let mut response = Response::new(message.into());
    *response.status_mut() = status;
    response
}

async fn forward(web: &Web, req: Request, base: &str, version: Option<Version>) -> Response {
    forwarding_service(web.clone(), base, version)
        .serve(req)
        .await
        .unwrap()
}

fn forwarding_service(
    web: Web,
    base: &str,
    version: Option<Version>,
) -> Arc<BoxService<Request, Response, Infallible>> {
    let base: Uri = base.parse().unwrap();
    let origin = UriMatchReplaceOrigin::new(
        base.scheme().unwrap().clone(),
        base.host_with_opt_port().unwrap(),
    );
    Arc::new(
        (
            HijackLayer::new(
                HttpMatcher::header_exists(UPGRADE)
                    .or(HttpMatcher::method_connect())
                    .and(HttpMatcher::custom(WebSocketMatcher::new()).negate()),
                IntoResponseLayer::new().into_layer(StaticOutput::new((
                    StatusCode::NOT_IMPLEMENTED,
                    "only WebSocket upgrades are supported by this proxy",
                ))),
            ),
            RemoveRequestHeaderLayer::hop_by_hop(),
            ErrorHandlerLayer::new().error_mapper(|error: BoxError| {
                if error_chain(error.as_ref()).any(|cause| cause.is::<Elapsed>()) {
                    error_response(
                        StatusCode::GATEWAY_TIMEOUT,
                        "upstream HTTP connection timed out",
                    )
                } else {
                    error_response(StatusCode::BAD_GATEWAY, "upstream HTTP connection failed")
                }
            }),
            RemoveRequestHeaderLayer::exact(HOST),
            RemoveRequestHeaderLayer::proxy_auth(),
            RewriteUriLayer::new(origin),
            version.map(|version| AddInputExtensionLayer::new(TargetHttpVersion(version))),
            HijackLayer::new(
                VersionMatcher::HTTP_09
                    .or(VersionMatcher::HTTP_10)
                    .or(VersionMatcher::HTTP_11),
                AddInputExtensionLayer::new(TargetHttpVersion(Version::HTTP_11))
                    .with_overwrite(false)
                    .into_layer(web.clone()),
            ),
        )
            .into_layer(web)
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
    let mut http = HttpServer::auto(exec.clone());
    http.h2_mut().set_enable_connect_protocol();
    let connect = service_fn(move |req: Request| {
        let tls = tls.clone();
        let http = http.clone();
        let web = web.clone();
        let preflight = preflight.clone();
        async move {
            let authority = req.uri().host_with_port().ok_or_else(|| {
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
            let inner = forwarding_service(web, &base, selected);
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

// Windows reserves port blocks per protocol, and its ephemeral ports are nearly sequential:
// alternate which protocol picks the port, and retain collisions so retries move on.
async fn bind_tcp_and_quic(
    exec: Executor,
    address: SocketAddress,
    config: ServerConfig,
) -> Result<(TcpListener, Endpoint), BoxError> {
    let factory = UdpSocketFactory::new(
        UdpSocketConfig::default().with_min_buffer_size(rama::quic::DEFAULT_SOCKET_BUFFER_SIZE),
    );
    let retryable = |error: &std::io::Error| {
        address.port == 0
            && matches!(
                error.kind(),
                ErrorKind::AddrInUse | ErrorKind::PermissionDenied
            )
    };
    let (mut udp_reservations, mut tcp_reservations) = (Vec::new(), Vec::new());
    for attempt in 1..=200 {
        let last = attempt == 200;
        let (udp, tcp) = if attempt % 2 == 1 {
            let udp = factory.bind(address).await?;
            match TcpListener::bind_address(udp.local_addr()?, exec.clone()).await {
                Ok(tcp) => (udp, tcp),
                Err(error)
                    if !last
                        && error
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(retryable) =>
                {
                    udp_reservations.push(udp);
                    continue;
                }
                Err(error) => return Err(error),
            }
        } else {
            let tcp = TcpListener::bind_address(address, exec.clone()).await?;
            match factory.bind(tcp.local_addr()?).await {
                Ok(udp) => (udp, tcp),
                Err(DatagramError::Io(error)) if !last && retryable(&error) => {
                    tcp_reservations.push(tcp);
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        };
        let quic = Endpoint::build(exec)
            .with_server_config(config)
            .with_packet_socket(udp)?;
        return Ok((tcp, quic));
    }
    unreachable!("the last attempt returns")
}

struct Fixture {
    address: String,
    tasks: Vec<JoinHandle<()>>,
    endpoint: Option<Endpoint>,
    response_end: Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    upload_started: Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    upload_end: Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<bool>>>>,
    requests: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32, b"test fixture dropped");
        }
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
            if is_http_req_websocket_handshake(&req) {
                return ErrorHandlerLayer::new()
                    .into_layer(
                        WebSocketAcceptor::new()
                            .with_per_message_deflate()
                            .into_echo_service(),
                    )
                    .serve(req)
                    .await;
            }
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
        response_end: Default::default(),
        upload_started: Default::default(),
        upload_end: Default::default(),
        requests: Default::default(),
        connections: Default::default(),
    }
}

async fn ingress(upstream: &str, versions: &[ApplicationProtocol]) -> Fixture {
    let route = (!upstream.is_empty()).then(|| (format!("http://{upstream}"), Version::HTTP_11));
    endpoint(route, versions).await
}

async fn endpoint(route: Option<(String, Version)>, versions: &[ApplicationProtocol]) -> Fixture {
    endpoint_at(route, versions, "127.0.0.1:0").await
}

async fn endpoint_at(
    route: Option<(String, Version)>,
    versions: &[ApplicationProtocol],
    bind: &str,
) -> Fixture {
    endpoint_with_connect_support(route, versions, bind, true).await
}

async fn endpoint_with_connect_support(
    route: Option<(String, Version)>,
    versions: &[ApplicationProtocol],
    bind: &str,
    extended_connect: bool,
) -> Fixture {
    let exec = Executor::new();
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
    let (web, _) = client(
        exec.clone(),
        TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable),
    )
    .unwrap();
    let upload_end = Arc::new(parking_lot::Mutex::new(
        None::<tokio::sync::oneshot::Sender<bool>>,
    ));
    let upload_started = Arc::new(parking_lot::Mutex::new(
        None::<tokio::sync::oneshot::Sender<()>>,
    ));
    let started = upload_started.clone();
    let response_end = Arc::new(parking_lot::Mutex::new(
        None::<tokio::sync::oneshot::Sender<()>>,
    ));
    let response_observer = response_end.clone();
    let requests = Arc::new(AtomicUsize::new(0));
    let received = requests.clone();
    let observer = upload_end.clone();
    let service = Arc::new(
        service_fn(move |req: Request| {
            received.fetch_add(1, Ordering::SeqCst);
            let response_observer = response_observer.clone();
            let observer = observer.clone();
            let started = started.clone();
            let web = web.clone();
            let route = route.clone();
            async move {
                let version = req.version();
                let authority = req
                    .uri()
                    .host_with_opt_port()
                    .map(|host| host.to_string())
                    .or_else(|| {
                        req.headers()
                            .get("host")
                            .map(|host| host.to_str().unwrap().to_owned())
                    })
                    .unwrap();
                let mut response = if let Some((base, version)) = route {
                    forward(&web, req, &base, Some(version)).await
                } else if is_http_req_websocket_handshake(&req) {
                    if req.uri().path_or_root() == "/ws-denied" {
                        error_response(StatusCode::FORBIDDEN, "WebSocket refused by origin")
                    } else if req.uri().path_or_root() == "/ws-not-switched"
                        && version == Version::HTTP_11
                    {
                        error_response(StatusCode::OK, "ordinary HTTP response")
                    } else {
                        let mut response = ErrorHandlerLayer::new()
                            .into_layer(
                                WebSocketAcceptor::new()
                                    .with_per_message_deflate()
                                    .into_echo_service(),
                            )
                            .serve(req)
                            .await
                            .unwrap();
                        response.headers_mut().insert(
                            "x-origin-version",
                            HeaderValue::from_str(&format!("{version:?}")).unwrap(),
                        );
                        response
                    }
                } else {
                    let request_length = req.headers().get("content-length").cloned();
                    let request_transfer = req.headers().get("transfer-encoding").cloned();
                    let not_modified = req.headers().contains_key("x-not-modified");
                    let trailers = req.headers().get("trailer").cloned();
                    let response_length = req.headers().get("x-response-length").cloned();
                    let head = req.method() == Method::HEAD;
                    let no_content = req.headers().contains_key("x-no-content");
                    let observe_response = req.headers().contains_key("x-observe-response");
                    let observe = req.headers().contains_key("x-observe-upload");
                    let wait_for_upload = req.headers().contains_key("x-wait-for-upload");
                    let mut body = req.into_body();
                    if observe {
                        if let Some(started) = started.lock().take() {
                            _ = started.send(());
                        }
                        let sender = observer.lock().take();
                        body = Body::from_frame_stream(stream::unfold(
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
                    if wait_for_upload {
                        body = match body.collect().await {
                            Ok(body) => Body::from(body.to_bytes()),
                            Err(_) => {
                                return Ok::<_, Infallible>(error_response(
                                    StatusCode::BAD_REQUEST,
                                    "upload interrupted",
                                ));
                            }
                        };
                    }
                    if observe_response {
                        let ended = response_observer.lock().take().unwrap();
                        body = Body::from_stream(stream::unfold(ended, |ended| async move {
                            Some((Ok::<_, Infallible>(vec![42; 64 * 1024]), ended))
                        }));
                    }
                    let mut response = Response::new(body);
                    response
                        .headers_mut()
                        .append("set-cookie", HeaderValue::from_static("a=1; Path=/"));
                    response
                        .headers_mut()
                        .append("set-cookie", HeaderValue::from_static("b=2; Path=/"));
                    if head {
                        *response.body_mut() = Body::from("HEAD representation");
                    }
                    if no_content {
                        *response.status_mut() = StatusCode::NO_CONTENT;
                        *response.body_mut() = Body::empty();
                    }
                    if not_modified {
                        *response.status_mut() = StatusCode::NOT_MODIFIED;
                        *response.body_mut() = Body::empty();
                        response
                            .headers_mut()
                            .insert("etag", HeaderValue::from_static("\"unchanged\""));
                    }
                    response.headers_mut().insert(
                        "x-request-length",
                        request_length.unwrap_or(HeaderValue::from_static("absent")),
                    );
                    response.headers_mut().insert(
                        "x-request-transfer",
                        request_transfer.unwrap_or(HeaderValue::from_static("absent")),
                    );
                    if let Some(trailers) = trailers {
                        response.headers_mut().insert("trailer", trailers);
                    }
                    if let Some(length) = response_length {
                        response.headers_mut().insert("content-length", length);
                    }
                    response.headers_mut().insert(
                        "x-origin-version",
                        HeaderValue::from_str(&format!("{version:?}")).unwrap(),
                    );
                    response
                };
                response
                    .headers_mut()
                    .insert("x-origin-authority", authority.parse().unwrap());
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
    let http = if versions.contains(&ApplicationProtocol::HTTP_2) {
        let mut http = HttpServer::auto(exec.clone());
        if extended_connect {
            http.h2_mut().set_enable_connect_protocol();
        }
        http.service(service.clone()).boxed()
    } else {
        HttpServer::new_http1(exec.clone())
            .service(service.clone())
            .boxed()
    };
    let tcp = TcpStreamOptionsLayer::new(tcp_socket_options())
        .into_layer(TlsAcceptorLayer::new(tls).into_layer(http));
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    let mut http = HttpServer::new_http3(exec.clone());
    http.http3_mut().extended_connect = extended_connect;
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
    let (listener, endpoint) = bind_tcp_and_quic(exec, bind.parse().unwrap(), config)
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let tcp_task = tokio::spawn(async move {
        listener
            .serve(
                MapInputLayer::new(move |io| {
                    count.fetch_add(1, Ordering::SeqCst);
                    io
                })
                .into_layer(tcp),
            )
            .await;
    });
    let service = http.service(service);
    let count = connections.clone();
    let service = MapInputLayer::new(move |connection| {
        count.fetch_add(1, Ordering::SeqCst);
        connection
    })
    .into_layer(service);
    let quic_task = tokio::spawn(endpoint.clone().serve(Executor::new(), service));
    Fixture {
        address: address.to_string(),
        tasks: vec![tcp_task, quic_task],
        endpoint: Some(endpoint),
        response_end,
        upload_started,
        upload_end,
        requests,
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
        response_end: Default::default(),
        upload_started: Default::default(),
        upload_end: Default::default(),
        requests: Default::default(),
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
    let response = client.serve(request).await.unwrap();
    assert_eq!(response.version(), outer);
    response
}

async fn tunnel(response: Response, target: &str, version: Version) -> HttpClientService<Body> {
    tunnel_with_alpn(response, target, version, true).await
}

async fn tunnel_with_alpn(
    response: Response,
    target: &str,
    version: Version,
    alpn: bool,
) -> HttpClientService<Body> {
    assert_eq!(response.status(), StatusCode::OK);
    let io = handle_upgrade(&response).await.unwrap();
    let mut tls = TlsClientConfig::new()
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
    if !alpn {
        tls.set_alpn(Default::default());
    }
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
        _ => Body::from_stream(stream::iter([Ok::<_, Infallible>("hello "), Ok("world")])),
    };
    let request = Request::builder()
        .method("POST")
        .version(version)
        .uri(format!("https://{target}/echo?test=1"))
        .header("proxy-authorization", "Basic must-not-reach-origin")
        .body(body)
        .unwrap();
    let response = web.serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), version);
    response
}

fn websocket_client(outer: Version) -> BoxService<Request, Response, OpaqueError> {
    let exec = Executor::new();
    let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
    let h3 = Http3Connector::builder(exec.clone())
        .with_tls_config(tls.clone())
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .build_lazy()
        .unwrap();
    EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_custom_proxy_connector(
            HttpProxyConnectorLayer::optional()
                .with_version(outer)
                .with_tls_proxy_support(false),
        )
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector(exec)
        .with_http3_support(h3)
        .with_default_connection_pool()
        .build_client()
        .boxed()
}

async fn websocket_exchange(
    web: &BoxService<Request, Response, OpaqueError>,
    target: &str,
    ingress_version: Version,
    egress_version: Version,
    route: ProxyRoute,
    compressed: bool,
) {
    let url = format!("wss://{target}/ws");
    let builder = match ingress_version {
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
            panic!("{ingress_version:?} -> {egress_version:?}, compressed={compressed}: {error:?}")
        });
    assert_eq!(socket.accepted_protocol(), Some("echo"));
    assert_eq!(
        socket
            .response()
            .headers
            .contains_key("sec-websocket-extensions"),
        compressed
    );
    assert_eq!(socket.response().version, ingress_version);
    assert_eq!(
        socket.response().headers["x-origin-version"],
        format!("{egress_version:?}")
    );
    assert_eq!(
        socket.response().status,
        if ingress_version == Version::HTTP_11 {
            StatusCode::SWITCHING_PROTOCOLS
        } else {
            StatusCode::OK
        }
    );
    for message in [
        Message::text("version-converting WebSocket relay"),
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
    let builder = match ingress_version {
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
async fn websockets_relay_across_versions_and_connect_tunnels() {
    timeout(Duration::from_secs(60), async {
        let protocols = [ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11];
        let origin = endpoint(None, &protocols).await;
        let web = websocket_client(Version::HTTP_11);
        for egress in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let ingress = endpoint(
                Some((format!("https://{}", origin.address), egress)),
                &protocols,
            )
            .await;
            for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
                for extended in [false, true] {
                    if extended && version == Version::HTTP_11 {
                        continue;
                    }
                    let req = Request::builder()
                        .method(Method::CONNECT)
                        .uri(format!("https://{}/", ingress.address))
                        .version(version)
                        .body(Body::empty())
                        .unwrap();
                    req.extensions().insert(TargetHttpVersion(version));
                    if extended {
                        req.extensions()
                            .insert(ConnectProtocol::from_static("unsupported-example"));
                    }
                    let response = web.serve(req).await.unwrap();
                    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
                    response.into_body().collect().await.unwrap();
                }
                for compressed in [false, true] {
                    websocket_exchange(
                        &web,
                        &ingress.address,
                        version,
                        egress,
                        ProxyRoute::Direct,
                        compressed,
                    )
                    .await;
                }
            }
        }
        for selected in [
            None,
            Some(Version::HTTP_11),
            Some(Version::HTTP_2),
            Some(Version::HTTP_3),
        ] {
            let proxy = proxy(selected).await;
            let route = ProxyRoute::Proxy(ProxyAddress {
                protocol: Some(Protocol::HTTP),
                address: proxy.address.parse().unwrap(),
                credential: None,
                template: None,
            });
            for outer in [Version::HTTP_11, Version::HTTP_2] {
                let web = websocket_client(outer);
                for inner in [Version::HTTP_11, Version::HTTP_2] {
                    for compressed in [false, true] {
                        websocket_exchange(
                            &web,
                            &origin.address,
                            inner,
                            selected.unwrap_or(inner),
                            route.clone(),
                            compressed,
                        )
                        .await;
                    }
                }
            }
        }
    })
    .await
    .expect("WebSocket matrix deadline");
}

#[tokio::test]
async fn websocket_failures_do_not_become_successful_tunnels() {
    timeout(Duration::from_secs(20), async {
        let protocols = [ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11];
        let origin = endpoint_with_connect_support(None, &protocols, "127.0.0.1:0", false).await;
        let http1 = endpoint(Some((format!("https://{}", origin.address), Version::HTTP_11)), &protocols).await;
        let web = websocket_client(Version::HTTP_11);
        for (egress, target, path) in [
            (Version::HTTP_2, &origin.address, "/ws"),
            (Version::HTTP_3, &origin.address, "/ws"),
            (Version::HTTP_11, &http1.address, "/ws-not-switched"),
        ] {
            let proxy = proxy(Some(egress)).await;
            for outer in [Version::HTTP_11, Version::HTTP_2] {
                let web = websocket_client(outer);
                for inner in [Version::HTTP_11, Version::HTTP_2] {
                    let url = format!("wss://{target}{path}");
                    let builder = if inner == Version::HTTP_11 { web.websocket(url) } else { web.websocket_h2(url) };
                    let extensions = Extensions::new();
                    extensions.insert(ProxyRoute::Proxy(ProxyAddress {
                        protocol: Some(Protocol::HTTP), address: proxy.address.parse().unwrap(), credential: None,
                        template: None,
                    }));
                    let before = origin.requests.load(Ordering::SeqCst);
                    let error = builder.handshake(extensions).await.err().unwrap();
                    if egress != Version::HTTP_11 {
                        assert_eq!(origin.requests.load(Ordering::SeqCst), before,
                            "missing Extended CONNECT setting must reject before sending a request");
                    }
                    let expected = if egress == Version::HTTP_11 && inner == Version::HTTP_11 {
                        StatusCode::OK
                    } else { StatusCode::BAD_GATEWAY };
                    assert!(matches!(error, HandshakeError::ValidationError(ResponseValidateError::UnexpectedStatusCode(status)) if status == expected), "{outer:?}/{inner:?} -> {egress:?}: {error:?}");
                }
            }
        }
        for (egress, path) in [
            (Version::HTTP_2, "/ws"),
            (Version::HTTP_3, "/ws"),
            (Version::HTTP_11, "/ws-not-switched"),
        ] {
            let relay = endpoint(Some((format!("https://{}", origin.address), egress)), &protocols).await;
            for ingress in [Version::HTTP_2, Version::HTTP_3] {
                let before = origin.requests.load(Ordering::SeqCst);
                let url = format!("wss://{}{path}", relay.address);
                let builder = if ingress == Version::HTTP_2 { web.websocket_h2(url) } else { web.websocket_h3(url) };
                let error = builder.handshake(Extensions::new()).await.err().unwrap();
                assert!(matches!(error, HandshakeError::ValidationError(ResponseValidateError::UnexpectedStatusCode(StatusCode::BAD_GATEWAY))), "{ingress:?} -> {egress:?}: {error:?}");
                if egress != Version::HTTP_11 {
                    assert_eq!(origin.requests.load(Ordering::SeqCst), before);
                }
            }
        }
        // The origin really does support HTTP/2; the missing setting is the failure.
        let request = Request::builder().uri(format!("https://{}/echo", origin.address)).version(Version::HTTP_2).body(Body::empty()).unwrap();
        request.extensions().insert(TargetHttpVersion(Version::HTTP_2));
        let response = web.serve(request).await.unwrap();
        assert_eq!(response.version(), Version::HTTP_2);
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await.unwrap();
    }).await.expect("WebSocket rejection deadline");
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
    timeout(Duration::from_secs(20), async {
        let origin = origin().await;
        let h1 = ingress(&origin.address, &[ApplicationProtocol::HTTP_11]).await;
        // Leave a working TLS/TCP origin but no accepting QUIC listener.
        h1.endpoint.as_ref().unwrap().shutdown().await;
        let h1_proxy = proxy(Some(Version::HTTP_11)).await;
        let response = connect(&h1_proxy.address, &h1.address, Version::HTTP_11).await;
        let web = tunnel(response, &h1.address, Version::HTTP_11).await;
        assert_eq!(
            exchange(&web, &h1.address, Version::HTTP_11, 1)
                .await
                .status(),
            StatusCode::OK
        );
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
            // A fallback to TCP would succeed, so also verify no TCP attempt occurs.
            let before = h1.connections.load(Ordering::SeqCst);
            let response = timeout(
                Duration::from_secs(15),
                connect(&h3_proxy.address, &h1.address, outer),
            )
            .await
            .unwrap();
            assert!(matches!(
                response.status(),
                StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT
            ));
            assert_eq!(h1.connections.load(Ordering::SeqCst), before);
        }
        h1.endpoint.as_ref().unwrap().shutdown().await;
    })
    .await
    .expect("strict override deadline");
}

#[tokio::test]
async fn default_version_can_fall_back_but_explicit_version_cannot() {
    timeout(Duration::from_secs(20), async {
        let origin = origin().await;
        let default_proxy = proxy(None).await;
        let strict_proxy = proxy(Some(Version::HTTP_2)).await;
        for alpns in [vec![ApplicationProtocol::HTTP_11], vec![]] {
            let h1 = ingress(&origin.address, &alpns).await;
            for outer in [Version::HTTP_11, Version::HTTP_2] {
                let response = connect(&default_proxy.address, &h1.address, outer).await;
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
                let response = connect(&strict_proxy.address, &h1.address, outer).await;
                assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            }
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
                let body = Body::from_frame_stream(stream::unfold(rx, |mut rx| async move {
                    rx.recv()
                        .await
                        .map(|frame| (Ok::<_, Infallible>(frame), rx))
                }));
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
    // The last step reached, for a deadline failure: CI keeps nothing else.
    let stage = parking_lot::Mutex::new(String::from("origin"));
    let mark = |step: String| *stage.lock() = step;
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
            mark(format!("relay -> {egress:?}"));
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

                for case in 0..7 {
                    mark(format!("{ingress:?} -> {egress:?}: case {case}"));
                    let (body, expected) = match case {
                        0 | 4 | 5 | 6 => (Body::empty(), vec![]),
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
                    if matches!(case, 1 | 3) {
                        req.headers_mut().remove("trailer");
                        req.headers_mut().insert(
                            "content-length",
                            expected.len().to_string().parse().unwrap(),
                        );
                        req.headers_mut().insert(
                            "x-response-length",
                            expected.len().to_string().parse().unwrap(),
                        );
                    }
                    if case == 5 {
                        req.headers_mut()
                            .insert("x-no-content", HeaderValue::from_static("1"));
                    }
                    if case == 6 {
                        req.headers_mut().insert("x-not-modified", HeaderValue::from_static("1"));
                    }
                    let response = web.serve(req).await.unwrap();
                    if case == 6 {
                        assert_eq!(response.headers()["etag"], "\"unchanged\"");
                        assert!(!response.headers().contains_key("transfer-encoding"));
                    }
                    if matches!(case, 1 | 3) {
                        assert_eq!(response.headers()["x-request-length"], expected.len().to_string());
                        assert_eq!(response.headers()["x-request-transfer"], "absent");
                    }
                    if case == 2 {
                        assert_eq!(response.headers()["x-request-length"], "absent");
                        assert_eq!(response.headers()["x-request-transfer"], if egress == Version::HTTP_11 { "chunked" } else { "absent" });
                    }
                    assert_eq!(
                        response.status(),
                        if case == 6 { StatusCode::NOT_MODIFIED } else if case == 5 {
                            StatusCode::NO_CONTENT
                        } else {
                            StatusCode::OK
                        }
                    );
                    assert_eq!(response.version(), ingress);
                    assert_eq!(
                        response
                            .headers()
                            .get_all("set-cookie")
                            .iter()
                            .collect::<Vec<_>>(),
                        ["a=1; Path=/", "b=2; Path=/"]
                    );
                    if case == 4 {
                        assert_eq!(response.headers()["content-length"], "HEAD representation".len().to_string());
                    }
                    if case == 5 {
                        assert!(!response.headers().contains_key("content-length"));
                        assert!(!response.headers().contains_key("transfer-encoding"));
                    }
                    if matches!(case, 1 | 3) {
                        assert_eq!(
                            response.headers()["content-length"],
                            expected.len().to_string()
                        );
                    }
                    if case == 2 && ingress == Version::HTTP_11 {
                        assert_eq!(
                            response
                                .extensions()
                                .get_ref::<OriginalResponseBodyFraming>(),
                            Some(&OriginalResponseBodyFraming::TransferEncoded)
                        );
                    } else if ingress >= Version::HTTP_2 {
                        assert!(!response.headers().contains_key("transfer-encoding"));
                    }
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

                // The ingress server emits 100 Continue to release the upload.
                // This does not claim forwarding of origin informational responses.
                if ingress == Version::HTTP_11 {
                    mark(format!("{ingress:?} -> {egress:?}: 100-continue"));
                    let allowed = Arc::new(tokio::sync::Notify::new());
                    let observed = Arc::new(AtomicUsize::new(0));
                    let gate = allowed.clone();
                    let body = Body::from_stream(stream::once(async move {
                        gate.notified().await;
                        Ok::<_, Infallible>("body after Continue")
                    }));
                    let mut req = request(body, Method::POST);
                    req.headers_mut()
                        .insert("x-wait-for-upload", HeaderValue::from_static("1"));
                    req.headers_mut()
                        .insert("expect", HeaderValue::from_static("100-continue"));
                    let count = observed.clone();
                    req.extensions()
                        .insert(OnInformational::new_fn(move |response| {
                            assert_eq!(response.status(), StatusCode::CONTINUE);
                            count.fetch_add(1, Ordering::SeqCst);
                            allowed.notify_one();
                        }));
                    let response = web.serve(req).await.unwrap();
                    assert_eq!(
                        response.into_body().collect().await.unwrap().to_bytes(),
                        "body after Continue"
                    );
                    assert_eq!(observed.load(Ordering::SeqCst), 1);
                }

                // Require a bounded plateau after observing data, then prove the
                // producer resumes when the response reader drains the stream.
                mark(format!("{ingress:?} -> {egress:?}: backpressure"));
                let produced = Arc::new(AtomicUsize::new(0));
                let counter = produced.clone();
                let body = Body::from_stream(stream::iter(0..256).map(move |_| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, Infallible>(vec![b'x'; 64 * 1024])
                }));
                let mut body = web.serve(request(body, Method::POST)).await.unwrap().into_body();
                assert!(!body.frame().await.unwrap().unwrap().data_ref().unwrap().is_empty());
                timeout(Duration::from_secs(5), async {
                    let mut previous = produced.load(Ordering::SeqCst);
                    let mut stable = 0;
                    while stable < 3 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let current = produced.load(Ordering::SeqCst);
                        assert!(current <= 128,
                            "{ingress:?} -> {egress:?}: stalled reader buffered more than 8 MiB ({current} chunks)");
                        stable = if current == previous { stable + 1 } else { 0 };
                        previous = current;
                    }
                }).await.expect("upload did not reach a bounded backpressure plateau");
                while let Some(frame) = body.frame().await {
                    frame.unwrap();
                }
                assert_eq!(produced.load(Ordering::SeqCst), 256);

                mark(format!("{ingress:?} -> {egress:?}: sibling stream"));
                let mut sibling = if ingress != Version::HTTP_11 && egress != Version::HTTP_11 {
                    let (tx, rx) = tokio::sync::mpsc::channel(1);
                    let body = Body::from_stream(stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|data| (Ok::<_, Infallible>(data), rx))
                    }));
                    tx.send("before cancellation").await.unwrap();
                    let mut body = web.serve(request(body, Method::POST)).await.unwrap().into_body();
                    assert_eq!(body.frame().await.unwrap().unwrap().data_ref().unwrap().as_ref(), b"before cancellation");
                    Some((tx, body))
                } else {
                    None
                };

                mark(format!("{ingress:?} -> {egress:?}: upload cancellation"));
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                let body = Body::from_stream(stream::unfold(rx, |mut rx| async move {
                    rx.recv().await.map(|data| (Ok::<_, Infallible>(data), rx))
                }));
                tx.send("active upload").await.unwrap();
                let (started, observed_start) = tokio::sync::oneshot::channel();
                let (ended, observed_end) = tokio::sync::oneshot::channel();
                *origin.upload_started.lock() = Some(started);
                *origin.upload_end.lock() = Some(ended);
                let mut req = request(body, Method::POST);
                req.headers_mut().insert("x-observe-upload", HeaderValue::from_static("1"));
                req.headers_mut().insert("x-wait-for-upload", HeaderValue::from_static("1"));
                let mut pending = Box::pin(web.serve(req));
                tokio::select! {
                    result = &mut pending => panic!("response before upload completed: {result:?}"),
                    result = observed_start => result.unwrap(),
                }
                let relay_before_cancel = relay.connections.load(Ordering::SeqCst);
                let origin_before_cancel = origin.connections.load(Ordering::SeqCst);
                drop(pending);
                timeout(Duration::from_secs(5), tx.closed()).await
                    .expect("cancelled request retained its upload producer");
                assert_ne!(timeout(Duration::from_secs(5), observed_end).await
                    .expect("origin did not observe cancellation"), Ok(true));

                let response = web.serve(request(Body::empty(), Method::GET)).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                response.into_body().collect().await.unwrap();
                if ingress != Version::HTTP_11 {
                    assert_eq!(relay.connections.load(Ordering::SeqCst), relay_before_cancel);
                }
                if egress != Version::HTTP_11 {
                    assert_eq!(origin.connections.load(Ordering::SeqCst), origin_before_cancel);
                }

                mark(format!("{ingress:?} -> {egress:?}: response cancellation"));
                let relay_connections = relay.connections.load(Ordering::SeqCst);
                let origin_connections = origin.connections.load(Ordering::SeqCst);
                let (ended, observed_end) = tokio::sync::oneshot::channel();
                *origin.response_end.lock() = Some(ended);
                let mut req = request(Body::empty(), Method::GET);
                req.headers_mut().insert("x-observe-response", HeaderValue::from_static("1"));
                let mut body = web.serve(req).await.unwrap().into_body();
                assert!(body.frame().await.unwrap().unwrap().is_data());
                drop(body);
                assert!(timeout(Duration::from_secs(5), observed_end).await
                    .expect("origin retained cancelled response stream").is_err());

                let response = web.serve(request(Body::empty(), Method::GET)).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                response.into_body().collect().await.unwrap();
                if ingress != Version::HTTP_11 {
                    assert_eq!(relay.connections.load(Ordering::SeqCst), relay_connections);
                }
                if egress != Version::HTTP_11 {
                    assert_eq!(origin.connections.load(Ordering::SeqCst), origin_connections);
                }

                if let Some((tx, mut body)) = sibling.take() {
                    tx.send("after cancellation").await.unwrap();
                    drop(tx);
                    assert_eq!(body.frame().await.unwrap().unwrap().data_ref().unwrap().as_ref(), b"after cancellation");
                    body.collect().await.unwrap();
                }

                for fail in [false, true] {
                    mark(format!("{ingress:?} -> {egress:?}: upload, fail={fail}"));
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
                            timeout(Duration::from_secs(5), observed_end).await
                                .expect("origin did not observe upload termination"),
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

            mark(format!("relay -> {egress:?}: shutdown"));
            relay.endpoint.as_ref().unwrap().shutdown().await;
        }

        origin.endpoint.as_ref().unwrap().shutdown().await;
    })
    .await
    .unwrap_or_else(|_| panic!("real network matrix deadline at {}", stage.lock()));
}

/// A peer that accepts TCP but never finishes TLS exercises the connection-only
/// deadline, both before CONNECT and after an unlabelled tunnel is accepted.
#[tokio::test]
async fn connection_timeout_returns_gateway_timeout() {
    timeout(Duration::from_secs(25), async {
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
        let relay = endpoint(
            Some((format!("https://{target}"), Version::HTTP_11)),
            &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
        )
        .await;
        let (web, _) = client(
            Executor::new(),
            TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable),
        )
        .unwrap();
        let request = Request::builder()
            .uri(format!("https://{}/", relay.address))
            .body(Body::empty())
            .unwrap();
        let response = web.serve(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        response.into_body().collect().await.unwrap();
        peer.abort();
    })
    .await
    .expect("connection timeout response deadline");
}

/// Malformed CONNECT targets cannot be emitted through a normal proxy client.
#[tokio::test]
async fn malformed_connect_targets_are_rejected() {
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
            assert!(
                proxy.tasks.iter().all(|task| !task.is_finished()),
                "proxy stopped after malformed target"
            );
            let response = connect(&proxy.address, "localhost:443", Version::HTTP_11).await;
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "proxy must still accept a valid CONNECT"
            );
        }
    })
    .await
    .expect("invalid CONNECT deadline");
}

#[tokio::test]
async fn preflight_and_requests_reuse_the_upstream_connection() {
    timeout(Duration::from_secs(10), async {
        for egress in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            for inner in [Version::HTTP_11, Version::HTTP_2] {
                let target = ingress(
                    "",
                    &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
                )
                .await;
                let proxy = proxy(Some(egress)).await;
                let response = connect(&proxy.address, &target.address, Version::HTTP_2).await;
                let web = tunnel(response, &target.address, inner).await;
                for _ in 0..2 {
                    let response = exchange(&web, &target.address, inner, 1).await;
                    assert_eq!(response.status(), StatusCode::OK);
                    assert_eq!(
                        response.into_body().collect().await.unwrap().to_bytes(),
                        "hello world"
                    );
                    assert_eq!(
                        target.connections.load(Ordering::SeqCst),
                        1,
                        "inner={inner:?}, egress={egress:?}"
                    );
                }
                target.endpoint.as_ref().unwrap().shutdown().await;
            }
        }
    })
    .await
    .expect("pool reuse deadline");
}

#[tokio::test]
async fn shared_mitm_pool_keeps_inner_versions_isolated_without_alpn() {
    timeout(Duration::from_secs(30), async {
        let target = endpoint(
            None,
            &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
        )
        .await;
        let proxy = proxy(None).await;
        for outer in [Version::HTTP_11, Version::HTTP_2] {
            for alpn in [true, false] {
                for inner in [Version::HTTP_2, Version::HTTP_11, Version::HTTP_2] {
                    let response = connect(&proxy.address, &target.address, outer).await;
                    let web = tunnel_with_alpn(response, &target.address, inner, alpn).await;
                    let response = exchange(&web, &target.address, inner, 1).await;
                    assert_eq!(response.status(), StatusCode::OK);
                    assert_eq!(response.headers()["x-origin-version"], format!("{inner:?}"));
                    response.into_body().collect().await.unwrap();
                }
            }
        }
    })
    .await
    .expect("shared MITM pool deadline");
}

#[tokio::test]
async fn silent_quic_peer_returns_gateway_timeout() {
    timeout(Duration::from_secs(15), async {
        // Keep UDP bound so the failure is a deadline, not an ICMP refusal.
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = socket.local_addr().unwrap().to_string();
        let proxy = proxy(Some(Version::HTTP_3)).await;
        for outer in [Version::HTTP_11, Version::HTTP_2] {
            let response = connect(&proxy.address, &target, outer).await;
            assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
            response.into_body().collect().await.unwrap();
        }
    })
    .await
    .expect("QUIC timeout deadline");
}

#[tokio::test]
async fn slow_upload_and_response_headers_outlive_the_connection_timeout() {
    timeout(Duration::from_secs(15), async {
        let origin = origin_with_upload_wait(true).await;
        let ingress = ingress(&origin.address, &[ApplicationProtocol::HTTP_11]).await;
        let proxy = proxy(Some(Version::HTTP_11)).await;
        let response = connect(&proxy.address, &ingress.address, Version::HTTP_11).await;
        let web = tunnel(response, &ingress.address, Version::HTTP_11).await;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let body = Body::from_frame_stream(stream::unfold(rx, |mut rx| async move {
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

#[tokio::test]
async fn rewritten_https_origin_omits_default_port_on_the_wire() {
    timeout(Duration::from_secs(10), async {
        let target = ingress(
            "",
            &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
        )
        .await;
        let (web, _) = client(
            Executor::new(),
            TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable),
        )
        .unwrap();
        let authority = Uri::parse_authority_form("localhost:443")
            .unwrap()
            .host_with_opt_port()
            .unwrap()
            .without_default_port_for(Some(&Protocol::HTTPS));
        let web = RewriteUriLayer::new(UriMatchReplaceOrigin::new(Protocol::HTTPS, authority))
            .into_layer(web);
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let req = Request::builder()
                .uri("https://localhost:443/echo?test=1")
                .version(version)
                .body(Body::empty())
                .unwrap();
            req.extensions().insert(TargetHttpVersion(version));
            req.extensions()
                .insert(ConnectorTarget(target.address.parse().unwrap()));
            let response = web.serve(req).await.unwrap();
            assert_eq!(response.headers()["x-origin-authority"], "localhost");
            response.into_body().collect().await.unwrap();
        }
        target.endpoint.as_ref().unwrap().shutdown().await;
    })
    .await
    .expect("default authority deadline");
}

#[tokio::test]
async fn http2_without_alpn_respects_policy_and_pool_reuse() {
    timeout(Duration::from_secs(30), async {
        let exec = Executor::new();
        let listener = TcpListener::bind_address("127.0.0.1:0", exec.clone())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let tls = TlsServerConfig::new()
            .with_server_auth(
                ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap(),
            )
            .with_alpn(Default::default());
        let service = TlsAcceptorLayer::new(tls).into_layer(
            HttpServer::new_h2(exec.clone()).service(service_fn(|req: Request| async move {
                assert_eq!(req.version(), Version::HTTP_2);
                Ok::<_, Infallible>(Response::new(Body::from("h2 without ALPN")))
            })),
        );
        let connections = Arc::new(AtomicUsize::new(0));
        let count = connections.clone();
        let service = MapInputLayer::new(move |io| {
            count.fetch_add(1, Ordering::SeqCst);
            io
        })
        .into_layer(service);
        let task = tokio::spawn(async move {
            listener.serve(service).await;
        });

        for rustls in [false, true] {
            if rustls
                && !cfg!(all(
                    feature = "rustls",
                    any(feature = "ring", feature = "aws-lc")
                ))
            {
                continue;
            }
            for base_policy in [
                None,
                Some(AlpnPolicy::Require),
                Some(AlpnPolicy::OutOfBandAgreement),
            ] {
                let mut tls =
                    TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
                if let Some(policy) = base_policy {
                    tls.set_alpn_policy(policy);
                }
                let builder = EasyHttpWebClient::connector_builder()
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .without_tls_proxy_support()
                    .without_proxy_support();
                let web: Arc<BoxService<Request, Response, OpaqueError>> = {
                    #[cfg(feature = "rustls")]
                    if rustls {
                        Arc::new(
                            EasyHttpWebClient::new(
                                builder
                                    .with_tls_support_using_rustls_and_default_http_version(
                                        tls,
                                        Version::HTTP_11,
                                    )
                                    .with_default_http_connector(exec.clone())
                                    .with_default_connection_pool()
                                    .without_alt_svc()
                                    .build_connector(),
                            )
                            .boxed(),
                        )
                    } else {
                        Arc::new(
                            EasyHttpWebClient::new(
                                builder
                                    .with_tls_support_using_boringssl_and_default_http_version(
                                        tls,
                                        Version::HTTP_11,
                                    )
                                    .with_default_http_connector(exec.clone())
                                    .with_default_connection_pool()
                                    .without_alt_svc()
                                    .build_connector(),
                            )
                            .boxed(),
                        )
                    }
                    #[cfg(not(feature = "rustls"))]
                    Arc::new(
                        EasyHttpWebClient::new(
                            builder
                                .with_tls_support_using_boringssl_and_default_http_version(
                                    tls,
                                    Version::HTTP_11,
                                )
                                .with_default_http_connector(exec.clone())
                                .with_default_connection_pool()
                                .without_alt_svc()
                                .build_connector(),
                        )
                        .boxed(),
                    )
                };
                let mut previous = None;
                // Revisit compatibility after a strict failure and vice versa.
                for request_policy in [
                    Some(AlpnPolicy::OutOfBandAgreement),
                    Some(AlpnPolicy::Require),
                    None,
                    Some(AlpnPolicy::OutOfBandAgreement),
                ]
                .into_iter()
                .flat_map(|policy| [policy; 2])
                {
                    let request = Request::builder()
                        .uri(format!("https://{address}/"))
                        .body(Body::empty())
                        .unwrap();
                    request
                        .extensions()
                        .insert(TargetHttpVersion(Version::HTTP_2));
                    if let Some(policy) = request_policy {
                        request.extensions().insert(policy);
                    }
                    let result = web.serve(request).await;
                    let reject = request_policy.or(base_policy) == Some(AlpnPolicy::Require);
                    assert_eq!(
                        result.is_err(),
                        reject,
                        "rustls={rustls}, base={base_policy:?}, request={request_policy:?}"
                    );
                    if let Err(error) = &result {
                        assert!(
                            error_chain(error).any(|cause| cause
                                .to_string()
                                .contains("requires TLS ALPN negotiation")),
                            "{error:?}"
                        );
                    }
                    if let Ok(response) = result {
                        assert_eq!(response.version(), Version::HTTP_2);
                        assert_eq!(
                            response.into_body().collect().await.unwrap().to_bytes(),
                            "h2 without ALPN"
                        );
                        let count = connections.load(Ordering::SeqCst);
                        if let Some((last_policy, last_count)) = previous
                            && last_policy == request_policy
                        {
                            assert_eq!(
                                count, last_count,
                                "identical policy should reuse the connection"
                            );
                        }
                        previous = Some((request_policy, count));
                    } else {
                        previous = None;
                    }
                }
            }
        }
        task.abort();
    })
    .await
    .expect("HTTP/2 no-ALPN matrix deadline");
}

#[tokio::test]
async fn missing_alpn_preflight_waits_for_http2_settings_with_a_deadline() {
    timeout(Duration::from_secs(10), async {
        let exec = Executor::new();
        let listener = TcpListener::bind_address("127.0.0.1:0", exec)
            .await
            .unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let tls = TlsServerConfig::new()
            .with_server_auth(
                ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap(),
            )
            .with_alpn(Default::default());
        let completed_handshakes = Arc::new(AtomicUsize::new(0));
        let completed = completed_handshakes.clone();
        let service = TlsAcceptorLayer::new(tls).into_layer(service_fn(move |io| {
            completed.fetch_add(1, Ordering::SeqCst);
            async move {
                // TLS succeeds, but the peer never proves that it speaks HTTP/2.
                std::future::pending::<()>().await;
                drop(io);
                Ok::<_, Infallible>(())
            }
        }));
        let peer = tokio::spawn(async move {
            listener.serve(service).await;
        });
        let proxy = proxy(Some(Version::HTTP_2)).await;
        let response = connect(&proxy.address, &target, Version::HTTP_11).await;
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(completed_handshakes.load(Ordering::SeqCst), 1);
        peer.abort();
    })
    .await
    .expect("SETTINGS preflight deadline");
}

#[tokio::test]
async fn ipv6_connect_targets_work_end_to_end() {
    timeout(Duration::from_secs(15), async {
        let target = endpoint_at(
            None,
            &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
            "[::1]:0",
        )
        .await;
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let proxy = proxy(Some(version)).await;
            let response = connect(&proxy.address, &target.address, Version::HTTP_11).await;
            assert_eq!(response.status(), StatusCode::OK);
            let web = tunnel(response, &target.address, Version::HTTP_11).await;
            let response = exchange(&web, &target.address, Version::HTTP_11, 1).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()["x-origin-version"],
                format!("{version:?}")
            );
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "hello world"
            );
        }
        target.endpoint.as_ref().unwrap().shutdown().await;
    })
    .await
    .expect("IPv6 CONNECT deadline");
}
