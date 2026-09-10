//! Handshake metadata must cross real HTTP upgrades only on its selected side.
#![expect(clippy::unwrap_used, reason = "test fixtures")]

use rama_core::{
    Service, ServiceInput,
    extensions::{Extension, Extensions, ExtensionsRef},
    io::BridgeIo,
    rt::Executor,
    service::service_fn,
};
use rama_http::{
    Body, Method, Request, Response, StatusCode, Version,
    headers::sec_websocket_protocol::AcceptedWebSocketProtocol,
    io::upgrade::{self, OnUpgrade, Upgraded},
    layer::upgrade::mitm::{HttpUpgradeMitmRelay, HttpUpgradeMitmRelayExtensions},
    proto::h2::ext::Protocol,
};
use rama_http_core::{client::conn, server, service::RamaHttpService};
use rama_ws::{
    handshake::matcher::{
        HttpWebSocketRelayHandshakeRequest, HttpWebSocketRelayHandshakeResponse,
        HttpWebSocketRelayServiceRequestMatcher, RelayWebSocketConfig,
    },
    protocol::WebSocketConfig,
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc},
};

const LIMIT: Duration = Duration::from_secs(10);
#[derive(Default)]
struct Tasks(Vec<tokio::task::JoinHandle<()>>);
impl Tasks {
    fn spawn(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        self.0.push(tokio::spawn(future));
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Http {
    H1,
    H2,
}
impl Http {
    fn version(self) -> Version {
        match self {
            Self::H1 => Version::HTTP_11,
            Self::H2 => Version::HTTP_2,
        }
    }
    fn status(self) -> StatusCode {
        match self {
            Self::H1 => StatusCode::SWITCHING_PROTOCOLS,
            Self::H2 => StatusCode::OK,
        }
    }
}
#[derive(Debug)]
struct RequestPrivate;
impl Extension for RequestPrivate {}
#[derive(Debug)]
struct ResponsePrivate;
impl Extension for ResponsePrivate {}
#[derive(Debug)]
struct Transport(&'static str);
impl Extension for Transport {}

enum Sender {
    H1(conn::http1::SendRequest<Body>),
    H2(conn::http2::SendRequest<Body>),
}
impl Sender {
    async fn send(&mut self, req: Request) -> Response {
        match self {
            Self::H1(sender) => {
                sender.ready().await.unwrap();
                sender.send_request(req).await.unwrap().map(Body::new)
            }
            Self::H2(sender) => {
                sender.ready().await.unwrap();
                sender.send_request(req).await.unwrap().map(Body::new)
            }
        }
    }
}

async fn connection<S>(
    http: Http,
    service: S,
    name: &'static str,
    tasks: &mut Tasks,
) -> (Sender, Extensions, Extensions)
where
    S: Service<Request, Output = Response, Error = Infallible> + Clone,
{
    let (client_io, server_io) = tokio::io::duplex(65536);
    let client_io = ServiceInput::new(client_io);
    let server_io = ServiceInput::new(server_io);
    client_io.extensions().insert(Transport(name));
    server_io.extensions().insert(Transport(name));
    let client_extensions = client_io.extensions().clone();
    let server_extensions = server_io.extensions().clone();
    tasks.spawn(async move {
        match http {
            Http::H1 => {
                _ = server::conn::http1::Builder::new()
                    .serve_connection(server_io, RamaHttpService::new(service))
                    .with_upgrades()
                    .await;
            }
            Http::H2 => {
                _ = server::conn::http2::Builder::new(Executor::new())
                    .with_enable_connect_protocol()
                    .serve_connection(server_io, RamaHttpService::new(service))
                    .await;
            }
        }
    });
    let sender = match http {
        Http::H1 => {
            let (sender, connection) = conn::http1::handshake(client_io).await.unwrap();
            tasks.spawn(async move {
                _ = connection.with_upgrades().await;
            });
            Sender::H1(sender)
        }
        Http::H2 => {
            let (sender, mut connection) = conn::http2::Builder::new(Executor::new())
                .handshake(client_io)
                .await
                .unwrap();
            // Drive receipt of SETTINGS before attempting extended CONNECT.
            tokio::time::timeout(
                LIMIT,
                std::future::poll_fn(|cx| {
                    assert!(std::pin::Pin::new(&mut connection).poll(cx).is_pending());
                    if connection.is_extended_connect_protocol_enabled() {
                        std::task::Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                }),
            )
            .await
            .unwrap();
            tasks.spawn(async move {
                _ = connection.await;
            });
            Sender::H2(sender)
        }
    };
    (sender, client_extensions, server_extensions)
}

fn request(http: Http, path: &str) -> Request {
    let mut request = Request::builder()
        .version(http.version())
        .uri(format!("https://metadata.test{path}"))
        .method(match http {
            Http::H1 => Method::GET,
            Http::H2 => Method::CONNECT,
        })
        .header("host", "metadata.test")
        .header("x-request-metadata", path)
        .body(Body::empty())
        .unwrap();
    match http {
        Http::H1 => {
            request
                .headers_mut()
                .insert("connection", "upgrade".parse().unwrap());
            request
                .headers_mut()
                .insert("upgrade", "websocket".parse().unwrap());
        }
        Http::H2 => {
            request
                .extensions()
                .insert(Protocol::from_static("websocket"));
        }
    }
    request
}

fn set_response_http(response: &mut Response, http: Http) {
    *response.version_mut() = http.version();
    *response.status_mut() = http.status();
    match http {
        Http::H1 => {
            response
                .headers_mut()
                .insert("connection", "upgrade".parse().unwrap());
            response
                .headers_mut()
                .insert("upgrade", "websocket".parse().unwrap());
        }
        Http::H2 => {
            response.headers_mut().remove("connection");
            response.headers_mut().remove("upgrade");
        }
    }
}

fn no_message_state(extensions: &Extensions) {
    assert!(
        !extensions.contains::<RequestPrivate>(),
        "request-private state escaped into the transport"
    );
    assert!(
        !extensions.contains::<ResponsePrivate>(),
        "response-private state escaped into the transport"
    );
    assert!(
        !extensions.contains::<OnUpgrade>(),
        "OnUpgrade escaped into upgraded IO"
    );
    assert!(
        !extensions.contains::<HttpUpgradeMitmRelayExtensions>(),
        "selection container escaped into upgraded IO"
    );
}
fn pristine_transport(extensions: &Extensions) {
    no_message_state(extensions);
    assert!(!extensions.contains::<HttpWebSocketRelayHandshakeRequest>());
    assert!(!extensions.contains::<HttpWebSocketRelayHandshakeResponse>());
    assert!(!extensions.contains::<RelayWebSocketConfig>());
    assert!(!extensions.contains::<AcceptedWebSocketProtocol>());
}
fn empty_snapshot(extensions: &Extensions) {
    assert_eq!(extensions.self_iter_all().count(), 0);
    assert!(extensions.parent().is_none());
}

#[expect(
    clippy::fn_params_excessive_bools,
    reason = "exercise independent metadata options in the transport matrix"
)]
async fn matrix_case(
    ingress: Http,
    egress: Http,
    store_request: bool,
    store_response: bool,
    configured: bool,
    negotiated_protocol: bool,
    repetitions: usize,
) {
    let mut tasks = Tasks::default();
    let (origin_tx, mut origin_rx) = mpsc::unbounded_channel();
    let origin = service_fn(move |request: Request| {
        let pending = upgrade::handle_upgrade(request.extensions().clone());
        let rejected = request.headers()["x-request-metadata"] == "/rejected";
        if !rejected {
            origin_tx.send(pending).unwrap();
        }
        async move {
            if rejected {
                return Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::empty())
                        .unwrap(),
                );
            }
            let mut response = Response::builder()
                .header(
                    "x-response-metadata",
                    request.headers()["x-request-metadata"].clone(),
                )
                .body(Body::empty())
                .unwrap();
            if negotiated_protocol {
                response
                    .headers_mut()
                    .insert("sec-websocket-protocol", "metadata.v1".parse().unwrap());
            }
            set_response_http(&mut response, egress);
            Ok::<_, Infallible>(response)
        }
    });
    let (origin_sender, egress_extensions, origin_extensions) =
        connection(egress, origin, "egress", &mut tasks).await;
    let origin_sender = Arc::new(Mutex::new(origin_sender));
    let forward = service_fn(move |request: Request| {
        let sender = origin_sender.clone();
        async move {
            assert!(request.extensions().contains::<RequestPrivate>());
            assert_eq!(
                request
                    .extensions()
                    .self_contains::<HttpWebSocketRelayHandshakeRequest>(),
                store_request
            );
            let path = request.headers()["x-request-metadata"].to_str().unwrap();
            let mut response = sender.lock().await.send(self::request(egress, path)).await;
            response.extensions().insert(ResponsePrivate);
            // A common middleware pattern: a response inherits request state.
            // This must never select the request payload for the egress stream.
            let response_extensions = response.extensions().with_base(request.extensions());
            response = response.with_extensions(response_extensions);
            assert!(
                !response
                    .extensions()
                    .self_contains::<HttpUpgradeMitmRelayExtensions>()
            );
            // Keep the original egress version until its response matcher snapshots it.
            *response.version_mut() = egress.version();
            Ok::<_, Infallible>(response)
        }
    });
    let (relay_tx, mut relay_rx) = mpsc::unbounded_channel();
    let relay = service_fn(move |bridge: BridgeIo<Upgraded, Upgraded>| {
        relay_tx.send(bridge).unwrap();
        async { Ok::<_, Infallible>(()) }
    });
    let matcher = HttpWebSocketRelayServiceRequestMatcher::new(relay)
        .with_store_handshake_request_header(store_request)
        .with_store_handshake_response_header(store_response)
        .maybe_with_websocket_config(
            configured.then(|| WebSocketConfig::default().with_max_message_size(12345)),
        );
    let proxy = HttpUpgradeMitmRelay::new(Executor::new(), matcher, forward);
    let proxy = Arc::new(proxy);
    let proxy_service = service_fn(move |request: Request| {
        let proxy = proxy.clone();
        request.extensions().insert(RequestPrivate);
        async move {
            let mut response = proxy.serve(request).await.unwrap();
            let upgraded = response.status() == egress.status();
            assert_eq!(
                response
                    .extensions()
                    .self_contains::<HttpWebSocketRelayHandshakeResponse>(),
                store_response && upgraded
            );
            if upgraded {
                set_response_http(&mut response, ingress);
            }
            Ok::<_, Infallible>(response)
        }
    });
    let (mut client, client_extensions, ingress_extensions) =
        connection(ingress, proxy_service, "ingress", &mut tasks).await;
    if repetitions > 1 {
        let rejected = client.send(request(ingress, "/rejected")).await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert!(
            relay_rx.try_recv().is_err(),
            "rejected handshake must not run the relay"
        );
        for ext in [
            &client_extensions,
            &ingress_extensions,
            &egress_extensions,
            &origin_extensions,
        ] {
            pristine_transport(ext);
        }
        drop(rejected);
    }
    let mut previous = Vec::new();
    for n in 0..repetitions {
        let path = format!("/socket/{n}?metadata=preserved");
        let response = client.send(request(ingress, &path)).await;
        assert_eq!(response.status(), ingress.status());
        let client_pending = upgrade::handle_upgrade(&response);
        let origin_pending = origin_rx.recv().await.unwrap();
        let (client_io, origin_io, bridge) =
            tokio::join!(client_pending, origin_pending, relay_rx.recv());
        let mut client_io = client_io.unwrap();
        let mut origin_io = origin_io.unwrap();
        let BridgeIo(mut incoming, mut outgoing) = bridge.unwrap();
        assert_eq!(
            incoming.extensions().get_ref::<Transport>().unwrap().0,
            "ingress"
        );
        assert_eq!(
            outgoing.extensions().get_ref::<Transport>().unwrap().0,
            "egress"
        );
        for ext in [incoming.extensions(), outgoing.extensions()] {
            no_message_state(ext);
        }
        assert!(
            !incoming
                .extensions()
                .contains::<HttpWebSocketRelayHandshakeResponse>()
        );
        assert!(!incoming.extensions().contains::<RelayWebSocketConfig>());
        assert!(
            !incoming
                .extensions()
                .contains::<AcceptedWebSocketProtocol>()
        );
        assert!(
            !outgoing
                .extensions()
                .contains::<HttpWebSocketRelayHandshakeRequest>()
        );
        let request_head = incoming
            .extensions()
            .self_get_ref::<HttpWebSocketRelayHandshakeRequest>();
        assert_eq!(request_head.is_some(), store_request);
        if let Some(head) = request_head {
            assert_eq!(head.0.version, ingress.version());
            assert_eq!(
                head.0.method,
                match ingress {
                    Http::H1 => Method::GET,
                    Http::H2 => Method::CONNECT,
                }
            );
            assert_eq!(
                head.0.uri.path_or_root().as_ref(),
                path.split('?').next().unwrap()
            );
            assert_eq!(head.0.uri.query_or_empty().as_ref(), "metadata=preserved");
            assert_eq!(head.0.headers["x-request-metadata"], path);
            empty_snapshot(&head.0.extensions);
        }
        let response_head = outgoing
            .extensions()
            .self_get_ref::<HttpWebSocketRelayHandshakeResponse>();
        assert_eq!(response_head.is_some(), store_response);
        if let Some(head) = response_head {
            assert_eq!(head.0.version, egress.version());
            assert_eq!(head.0.status, egress.status());
            assert_eq!(head.0.headers["x-response-metadata"], path);
            empty_snapshot(&head.0.extensions);
        }
        let config = outgoing.extensions().self_get_ref::<RelayWebSocketConfig>();
        assert_eq!(config.is_some(), configured);
        if let Some(config) = config {
            assert_eq!(config.0.max_message_size, Some(12345));
        }
        let protocol = outgoing
            .extensions()
            .self_get_ref::<AcceptedWebSocketProtocol>();
        assert_eq!(protocol.is_some(), negotiated_protocol);
        if let Some(protocol) = protocol {
            assert_eq!(protocol.0.as_ref(), "metadata.v1");
        }
        for ext in [
            &client_extensions,
            &ingress_extensions,
            &egress_extensions,
            &origin_extensions,
        ] {
            pristine_transport(ext);
        }
        // Retain earlier streams' metadata while another HTTP/2 stream upgrades.
        previous.push((
            incoming.extensions().clone(),
            outgoing.extensions().clone(),
            path.clone(),
        ));
        for (request_ext, response_ext, previous_path) in &previous {
            if store_request {
                assert_eq!(
                    request_ext
                        .get_ref::<HttpWebSocketRelayHandshakeRequest>()
                        .unwrap()
                        .0
                        .headers["x-request-metadata"],
                    previous_path
                );
            }
            if store_response {
                assert_eq!(
                    response_ext
                        .get_ref::<HttpWebSocketRelayHandshakeResponse>()
                        .unwrap()
                        .0
                        .headers["x-response-metadata"],
                    previous_path
                );
            }
        }
        let (client_result, origin_result, relay_result) = tokio::join!(
            async {
                client_io.write_all(b"ping").await?;
                client_io.flush().await?;
                let mut bytes = [0; 4];
                client_io.read_exact(&mut bytes).await?;
                assert_eq!(&bytes, b"pong");
                client_io.shutdown().await
            },
            async {
                let mut bytes = [0; 4];
                origin_io.read_exact(&mut bytes).await?;
                assert_eq!(&bytes, b"ping");
                origin_io.write_all(b"pong").await?;
                origin_io.flush().await?;
                origin_io.shutdown().await
            },
            tokio::io::copy_bidirectional(&mut incoming, &mut outgoing),
        );
        client_result.unwrap();
        origin_result.unwrap();
        relay_result.unwrap();
    }
}

#[tokio::test]
async fn real_http_upgrade_metadata_matrix() {
    for ingress in [Http::H1, Http::H2] {
        for egress in [Http::H1, Http::H2] {
            for (request, response) in [(true, true), (true, false), (false, true), (false, false)]
            {
                for (config, protocol) in
                    [(true, true), (true, false), (false, true), (false, false)]
                {
                    tokio::time::timeout(LIMIT, matrix_case(ingress, egress, request, response, config, protocol, 1)).await
                        .unwrap_or_else(|_| panic!("timed out: {ingress:?}/{egress:?} request={request} response={response} config={config} protocol={protocol}"));
                }
            }
        }
    }
}

#[tokio::test]
async fn real_h2_repeated_streams_keep_handshake_metadata_isolated() {
    tokio::time::timeout(
        LIMIT,
        matrix_case(Http::H2, Http::H2, true, true, true, true, 3),
    )
    .await
    .unwrap();
}

#[cfg(feature = "compression")]
mod compressed_frames {
    use super::*;
    use rama_core::{futures::SinkExt as _, service::MirrorService};
    use rama_ws::{
        AsyncWebSocket, Message,
        handshake::mitm::{WebSocketRelayIoService, WebSocketRelayService},
        protocol::{PerMessageDeflateConfig, Role},
    };
    use std::{
        io,
        pin::Pin,
        sync::atomic::{AtomicU8, Ordering},
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    // Observe the first actual frame header on each leg. Configuring an endpoint
    // for compression alone would not prove that compressed frames crossed IO.
    struct FrameHeaders {
        io: Upgraded,
        received: Arc<AtomicU8>,
        sent: Arc<AtomicU8>,
    }

    impl FrameHeaders {
        fn new(io: Upgraded) -> Self {
            Self {
                io,
                received: Arc::new(AtomicU8::new(0)),
                sent: Arc::new(AtomicU8::new(0)),
            }
        }
    }

    impl ExtensionsRef for FrameHeaders {
        fn extensions(&self) -> &Extensions {
            self.io.extensions()
        }
    }

    impl AsyncRead for FrameHeaders {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buffer.filled().len();
            let result = Pin::new(&mut self.io).poll_read(cx, buffer);
            if buffer.filled().len() > before {
                let _previous_header = self.received.compare_exchange(
                    0,
                    buffer.filled()[before],
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
            result
        }
    }

    impl AsyncWrite for FrameHeaders {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let result = Pin::new(&mut self.io).poll_write(cx, bytes);
            if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
                let _previous_header =
                    self.sent
                        .compare_exchange(0, bytes[0], Ordering::Relaxed, Ordering::Relaxed);
            }
            result
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    async fn compressed_relay(http: Http) {
        let mut tasks = Tasks::default();
        let (origin_tx, mut origin_rx) = mpsc::unbounded_channel();
        let origin = service_fn(move |request: Request| {
            assert_eq!(
                request.headers()["sec-websocket-extensions"],
                "permessage-deflate"
            );
            origin_tx
                .send(upgrade::handle_upgrade(request.extensions().clone()))
                .unwrap();
            async move {
                let mut response = Response::builder()
                    .header("sec-websocket-extensions", "permessage-deflate")
                    .body(Body::empty())
                    .unwrap();
                set_response_http(&mut response, http);
                Ok::<_, Infallible>(response)
            }
        });
        let (origin_sender, _, _) = connection(http, origin, "compressed-egress", &mut tasks).await;
        let origin_sender = Arc::new(Mutex::new(origin_sender));
        let forward = service_fn(move |incoming: Request| {
            let sender = origin_sender.clone();
            async move {
                let mut outgoing = request(http, "/compressed");
                outgoing.headers_mut().insert(
                    "sec-websocket-extensions",
                    incoming.headers()["sec-websocket-extensions"].clone(),
                );
                Ok::<_, Infallible>(sender.lock().await.send(outgoing).await)
            }
        });
        let (finished_tx, mut finished_rx) = mpsc::unbounded_channel();
        let relay = service_fn(move |bridge: BridgeIo<Upgraded, Upgraded>| {
            let finished_tx = finished_tx.clone();
            async move {
                WebSocketRelayIoService::new(
                    WebSocketRelayService::new(MirrorService::new())
                        .with_close_handshake_timeout(Duration::from_secs(3)),
                )
                .serve(bridge)
                .await
                .unwrap();
                finished_tx.send(()).unwrap();
                Ok::<_, Infallible>(())
            }
        });
        // No base config and no stored heads: PMD must come solely from the
        // response matcher and its explicit transfer onto the egress upgrade.
        let proxy = HttpUpgradeMitmRelay::new(
            Executor::new(),
            HttpWebSocketRelayServiceRequestMatcher::new(relay),
            forward,
        );
        let (mut sender, _, _) =
            connection(http, Arc::new(proxy), "compressed-ingress", &mut tasks).await;
        let mut outgoing = request(http, "/compressed");
        outgoing.headers_mut().insert(
            "sec-websocket-extensions",
            "permessage-deflate".parse().unwrap(),
        );
        let response = sender.send(outgoing).await;
        assert_eq!(response.status(), http.status());
        assert_eq!(
            response.headers()["sec-websocket-extensions"],
            "permessage-deflate"
        );
        let (client_io, origin_io) = tokio::join!(upgrade::handle_upgrade(&response), async {
            origin_rx.recv().await.unwrap().await
        },);
        let client_io = FrameHeaders::new(client_io.unwrap());
        let origin_io = FrameHeaders::new(origin_io.unwrap());
        let frame_headers = [
            client_io.sent.clone(),
            client_io.received.clone(),
            origin_io.sent.clone(),
            origin_io.received.clone(),
        ];
        let config =
            WebSocketConfig::default().with_per_message_deflate(PerMessageDeflateConfig::default());
        let mut client =
            AsyncWebSocket::from_raw_socket(client_io, Role::Client, Some(config)).await;
        let mut origin =
            AsyncWebSocket::from_raw_socket(origin_io, Role::Server, Some(config)).await;
        // Multiple messages exercise the compression contexts in both relay roles.
        for n in 0..3 {
            let text = Message::text(format!(
                "client-message-{n}:{}",
                "compress me! ".repeat(512)
            ));
            client.send_message(text.clone()).await.unwrap();
            assert_eq!(origin.recv_message().await.unwrap(), text);
            let binary = Message::binary(vec![b'A' + n; 8192]);
            origin.send_message(binary.clone()).await.unwrap();
            assert_eq!(client.recv_message().await.unwrap(), binary);
        }
        for first_header in frame_headers {
            assert_ne!(
                first_header.load(Ordering::Relaxed) & 0x40,
                0,
                "each endpoint and relay writer must emit RSV1-compressed frames"
            );
        }
        client.close(None).await.unwrap();
        assert_eq!(origin.recv_message().await.unwrap(), Message::Close(None));
        origin.flush().await.unwrap();
        assert_eq!(client.recv_message().await.unwrap(), Message::Close(None));
        tokio::time::timeout(Duration::from_secs(1), finished_rx.recv())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn negotiated_compression_survives_real_http_mitm_upgrades() {
        for http in [Http::H1, Http::H2] {
            tokio::time::timeout(LIMIT, compressed_relay(http))
                .await
                .unwrap_or_else(|_| panic!("compressed relay timed out over {http:?}"));
        }
    }
}
