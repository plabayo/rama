//! The WebSocket MITM relay between real HTTP/1.1, HTTP/2 and HTTP/3 engines, including
//! Extended CONNECT over QUIC (RFC 9220).
//!
//! HTTP/1.1 and HTTP/2 run over in-memory byte streams, HTTP/3 over in-memory QUIC. The
//! origin records the handshake fields it received, so the relay's header order,
//! duplicates and sensitivity are checked end to end.

#![expect(
    clippy::expect_used,
    reason = "integration tests use expectation messages to identify failed stages"
)]

use rama_core::{
    Layer, Service, ServiceInput,
    extensions::{Extensions, ExtensionsRef as _},
    layer::{ArcLayer, ConsumeErrLayer},
    rt::{Executor, spawn},
    service::service_fn,
};
use rama_http::{
    Body, HeaderName, HeaderValue, Method, Request, Response, Version,
    layer::{
        upgrade::mitm::HttpUpgradeMitmRelayLayer,
        version_adapter::{ResponseVersionAdapter, adapt_request_version},
    },
    proto::ext::Protocol,
};
use rama_http_backend::{
    client::{Http3Transport, HttpClientService, http_connect},
    server::HttpServer,
};
use rama_http_core::h3::connection::Config;
use rama_net::address::SocketAddress;
use rama_quic::{Connection, Endpoint, TransportConfig, tls::TlsOptions};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::test_utils::MemoryDatagramSocket;
use rama_ws::{
    Message,
    handshake::{
        client::HttpClientWebSocketExt as _,
        matcher::HttpWebSocketRelayServiceRequestMatcher,
        mitm::{
            WebSocketRelayDirection, WebSocketRelayInput, WebSocketRelayIoLayer,
            WebSocketRelayMessage, WebSocketRelayOutput, WebSocketRelayService,
        },
        server::WebSocketAcceptor,
    },
};
use std::{convert::Infallible, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{sync::mpsc, time::timeout};

const LIMIT: Duration = Duration::from_secs(20);
const URI: &str = "wss://localhost/socket";

/// The handshake fields the client adds, in order: an adjacent duplicate and a sensitive
/// value among them.
fn client_fields() -> Vec<(HeaderName, HeaderValue)> {
    let mut secret = HeaderValue::from_static("hunter2");
    secret.set_sensitive(true);
    vec![
        (
            HeaderName::from_static("x-first"),
            HeaderValue::from_static("1"),
        ),
        (
            HeaderName::from_static("x-dup"),
            HeaderValue::from_static("a"),
        ),
        (
            HeaderName::from_static("x-dup"),
            HeaderValue::from_static("b"),
        ),
        (HeaderName::from_static("x-secret"), secret),
        (
            HeaderName::from_static("x-last"),
            HeaderValue::from_static("z"),
        ),
    ]
}

/// A connected in-memory QUIC pair.
struct QuicPair {
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    client: Connection,
    server: Connection,
}

impl QuicPair {
    async fn new() -> Self {
        let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())
            .expect("server identity");
        let alpn = || [b"h3".as_slice().into()].into_iter().collect();
        let server_tls = TlsServerConfig::new()
            .with_alpn(alpn())
            .with_server_auth(identity.clone());
        let client_tls = TlsClientConfig::new()
            .with_alpn(alpn())
            .try_with_server_trust_anchors([identity
                .cert_chain
                .last()
                .expect("certificate")
                .clone()])
            .expect("trust anchors");
        let transport = || {
            let mut transport = TransportConfig::default();
            Config::default()
                .configure_transport(&mut transport)
                .expect("transport config");
            Arc::new(transport)
        };
        let mut server_config =
            rama_quic::ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())
                .expect("server config");
        server_config.set_transport_config(transport());
        let mut client_config =
            rama_quic::ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default())
                .expect("client config");
        client_config.set_transport_config(transport());
        let (server_socket, client_socket) = MemoryDatagramSocket::pair(
            SocketAddress::local_ipv4(443),
            SocketAddress::local_ipv4(444),
            NonZeroUsize::MIN,
        );
        let server_endpoint = Endpoint::build(Executor::new())
            .with_server_config(server_config)
            .with_datagram_socket(server_socket)
            .expect("server endpoint");
        let client_endpoint = Endpoint::build(Executor::new())
            .with_datagram_socket(client_socket)
            .expect("client endpoint");
        let accept = spawn({
            let endpoint = server_endpoint.clone();
            async move {
                endpoint
                    .accept()
                    .await
                    .expect("incoming")
                    .await
                    .expect("accepted")
            }
        });
        let client = client_endpoint
            .connect_with(
                client_config,
                server_endpoint.local_addr().expect("server address"),
                "localhost",
            )
            .expect("connect")
            .await
            .expect("connected");
        let server = accept.await.expect("accept task");
        Self {
            client_endpoint,
            server_endpoint,
            client,
            server,
        }
    }

    async fn close(self) {
        self.client.close(0u32, b"test complete");
        tokio::join!(
            self.client_endpoint.shutdown(),
            self.server_endpoint.shutdown()
        );
    }
}

/// A handshake request on `version`, as a client of that version starts one.
fn handshake_request(version: Version) -> Request {
    let mut request = Request::new(Body::empty());
    *request.version_mut() = version;
    if version >= Version::HTTP_2 {
        *request.method_mut() = Method::CONNECT;
        *request.uri_mut() = "https://localhost/socket".parse().expect("URI");
        request.extensions().insert(Protocol::WEBSOCKET);
    } else {
        *request.uri_mut() = "ws://localhost/socket".parse().expect("URI");
    }
    request
}

/// One HTTP hop: `service` behind a real server engine on `version`, and a client of it.
struct Hop {
    client: Arc<HttpClientService<Body>>,
    quic: Option<QuicPair>,
}

impl Hop {
    async fn start<S>(version: Version, service: S) -> Self
    where
        S: Service<rama_http::Request, Output = Response, Error = Infallible> + Clone,
    {
        let executor = Executor::default();
        if version == Version::HTTP_3 {
            let quic = QuicPair::new().await;
            let mut server = HttpServer::new_http3(executor.clone());
            server.http3_mut().extended_connect = true;
            let service = server.service(service);
            let connection = quic.server.clone();
            spawn(async move {
                _ = service.serve(connection).await;
            });
            let transport = Http3Transport {
                connection: quic.client.clone(),
                config: Config::default(),
            };
            let client = http_connect(transport, handshake_request(version), executor)
                .await
                .expect("HTTP/3 client")
                .conn;
            return Self {
                client: Arc::new(client),
                quic: Some(quic),
            };
        }
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        spawn({
            let executor = executor.clone();
            async move {
                if version == Version::HTTP_2 {
                    let mut server = HttpServer::new_h2(executor);
                    server.h2_mut().set_enable_connect_protocol();
                    _ = server.serve(ServiceInput::new(server_io), service).await;
                } else {
                    _ = HttpServer::new_http1(executor)
                        .serve(ServiceInput::new(server_io), service)
                        .await;
                }
            }
        });
        let client = http_connect(
            ServiceInput::new(client_io),
            handshake_request(version),
            executor,
        )
        .await
        .expect("stream client")
        .conn;
        Self {
            client: Arc::new(client),
            quic: None,
        }
    }

    async fn close(self) {
        drop(self.client);
        if let Some(quic) = self.quic {
            quic.close().await;
        }
    }
}

async fn tag_relay_message(input: WebSocketRelayInput) -> Result<WebSocketRelayOutput, Infallible> {
    let WebSocketRelayInput {
        direction,
        message,
        extensions,
    } = input;
    let message = match (direction, message) {
        (WebSocketRelayDirection::Ingress, WebSocketRelayMessage::Text(text)) => {
            WebSocketRelayMessage::Text(text.as_str().to_uppercase().into())
        }
        (WebSocketRelayDirection::Egress, WebSocketRelayMessage::Text(text)) => {
            WebSocketRelayMessage::Text(format!("relayed-{text}").into())
        }
        (_, message) => message,
    };
    Ok(WebSocketRelayOutput {
        messages: vec![message],
        extensions,
    })
}

/// An echoing origin that reports the `x-` fields of each handshake it accepts.
fn origin(
    seen: mpsc::UnboundedSender<Vec<(HeaderName, HeaderValue)>>,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let echo =
        ConsumeErrLayer::trace_as_debug().into_layer(WebSocketAcceptor::new().into_echo_service());
    let echo = Arc::new(echo);
    service_fn(move |request: Request| {
        let seen = seen.clone();
        let echo = echo.clone();
        async move {
            let fields = request
                .headers()
                .iter()
                .filter(|(name, _)| name.as_str().starts_with("x-"))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect();
            _ = seen.send(fields);
            echo.serve(request).await
        }
    })
}

async fn assert_relay(ingress: Version, egress: Version) {
    let cell = format!("{ingress:?} -> {egress:?}");
    let (seen, mut handshakes) = mpsc::unbounded_channel();
    let upstream = Hop::start(egress, origin(seen)).await;

    // The egress client adapts the relayed request to its version, as the connector's
    // `RequestVersionAdapter` does.
    let egress_client = upstream.client.clone();
    let forward = service_fn(move |mut request: Request| {
        let client = egress_client.clone();
        async move {
            adapt_request_version(&mut request, egress)?;
            client.serve(request).await
        }
    });
    let relay = WebSocketRelayIoLayer::new()
        .into_layer(WebSocketRelayService::new(service_fn(tag_relay_message)));
    let proxy = HttpUpgradeMitmRelayLayer::new(
        Executor::default(),
        HttpWebSocketRelayServiceRequestMatcher::new(relay),
    )
    .into_layer(ResponseVersionAdapter::new(forward));
    let proxy = ArcLayer::new().into_layer(ConsumeErrLayer::trace_as_debug().into_layer(proxy));
    let downstream = Hop::start(ingress, proxy).await;

    let builder = match ingress {
        Version::HTTP_3 => downstream.client.websocket_h3(URI),
        Version::HTTP_2 => downstream.client.websocket_h2(URI),
        _ => downstream.client.websocket(URI),
    };
    let builder = client_fields()
        .into_iter()
        .fold(builder, |builder, (name, value)| {
            builder.with_header(name, value)
        });
    let mut socket = timeout(LIMIT, builder.handshake(Extensions::new()))
        .await
        .expect("handshake in time")
        .map_err(|error| format!("{cell}: {error}"))
        .expect("handshake");

    let received = handshakes.recv().await.expect("origin handshake");
    let names = |fields: &[(HeaderName, HeaderValue)]| {
        fields
            .iter()
            .map(|(name, value)| format!("{name}: {}", value.to_str().expect("ascii")))
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&received), names(&client_fields()), "{cell}");
    // Only HTTP/2 and HTTP/3 carry sensitivity (never-indexed fields) on the wire.
    let carried = ingress >= Version::HTTP_2 && egress >= Version::HTTP_2;
    let secret = received
        .iter()
        .find(|(name, _)| name == "x-secret")
        .map(|(_, value)| value.is_sensitive());
    assert_eq!(secret, Some(carried), "{cell}: x-secret sensitivity");

    socket
        .send_message(Message::text("hello"))
        .await
        .map_err(|error| format!("{cell}: {error}"))
        .expect("send");
    let echo = timeout(LIMIT, socket.recv_message())
        .await
        .expect("echo in time")
        .map_err(|error| format!("{cell}: {error}"))
        .expect("receive");
    assert_eq!(echo, Message::text("relayed-HELLO"), "{cell}");

    // The close handshake completes through the relay.
    socket.close(None).await.expect("close");
    let reply = timeout(LIMIT, socket.recv_message())
        .await
        .expect("close reply in time");
    assert!(
        matches!(reply, Ok(Message::Close(_))),
        "{cell}: close reply {reply:?}"
    );
    drop(socket);
    downstream.close().await;
    upstream.close().await;
}

#[tokio::test]
async fn relays_bridge_http3_with_every_http_version_over_real_engines() {
    for (ingress, egress) in [
        (Version::HTTP_3, Version::HTTP_3),
        (Version::HTTP_3, Version::HTTP_2),
        (Version::HTTP_3, Version::HTTP_11),
        (Version::HTTP_2, Version::HTTP_3),
        (Version::HTTP_11, Version::HTTP_3),
        (Version::HTTP_2, Version::HTTP_2),
        (Version::HTTP_11, Version::HTTP_11),
    ] {
        assert_relay(ingress, egress).await;
    }
}
