use std::sync::atomic::{AtomicUsize, Ordering};

use clap::Parser;
use rama::{
    bytes::Bytes,
    crypto::pki_types::{CertificateDer, pem::PemObject as _},
    extensions::Extensions,
    http::{
        Body, HeaderValue, Method,
        body::util::BodyExt as _,
        inspect::control::Direction,
        ws::{
            AsyncWebSocket, Message,
            handshake::{
                client::HttpClientWebSocketExt as _,
                mitm::{
                    WebSocketRelayDirection, WebSocketRelayEvent, WebSocketRelayEventInput,
                    WebSocketRelayEventService, WebSocketRelayMessage,
                },
                server::WebSocketAcceptor,
            },
            inspect::{
                CaptureWebSocketExt, CapturedWebSocketMessage, WebSocketMessageKind,
                WebSocketMessageOrigin,
            },
            protocol::Role,
        },
    },
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
        stream::SocketInfo,
        test_utils::client::MockSocket,
    },
    tls::{
        ProtocolVersion,
        client::{ClientHello, ClientHelloExtension, ServerVerifyMode, TlsClientConfig},
    },
    utils::octets::{kib, kib_u64},
};
use tokio::{
    io::{AsyncReadExt as _, duplex},
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
    request.extensions().insert(SocketInfo::new(
        Some(local_address.parse().unwrap()),
        "198.51.100.10:54321".parse().unwrap(),
    ));
    request
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
    let mut buffer = [0; kib(1)];
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
            request
                .headers_mut()
                .insert("x-rama-icap-reqmod", HeaderValue::from_static("yes"));
            if saw_proxy_authorization {
                request.headers_mut().insert(
                    "x-rama-icap-saw-proxy-authorization",
                    HeaderValue::from_static("yes"),
                );
            }
            Ok(IcapOutgoingResponse::from_http_request(
                line, &fields, request,
            )?)
        }
        IcapMethodKind::Respmod => {
            let (parts, body) = request.into_response()?.into_parts();
            let mut response = Response::from_parts(parts, Body::new(body.collect().await?));
            response
                .headers_mut()
                .insert("x-rama-icap-respmod", HeaderValue::from_static("yes"));
            response.headers_mut().insert(
                rama::http::header::PROXY_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=icap-test"),
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
                Method::POST,
                format!("http://{address}{path}"),
                Body::from(serde_json::to_vec(&value).unwrap()),
            )
        }
        None => (
            Method::GET,
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

async fn approval_id(store: &CaptureStore, direction: Direction) -> u64 {
    let control = store.control();
    let mut changes = control.subscribe_changes();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(message) = control
                .pending_summaries()
                .iter()
                .find(|message| message.direction == direction)
            {
                return message.id;
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .unwrap()
}

mod configuration;
mod icap;
mod icap_transport;
mod interception;
mod recording;
mod traffic;
mod upstream;
mod websocket;
