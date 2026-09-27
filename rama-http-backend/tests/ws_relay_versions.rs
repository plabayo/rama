//! The WebSocket MITM relay between real HTTP/1.1, HTTP/2 and HTTP/3 engines, including
//! Extended CONNECT over QUIC (RFC 9220).
//!
//! HTTP/1.1 and HTTP/2 run over in-memory byte streams, HTTP/3 over in-memory QUIC. A raw
//! RFC 6455 origin records the relayed handshake and checks how the relay ends its stream;
//! the client checks the relayed response and the relay's end of its own stream.

#![expect(
    clippy::expect_used,
    reason = "integration tests use expectation messages to identify failed stages"
)]

use rama_core::{
    Layer, Service, ServiceInput,
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef as _},
    futures::SinkExt as _,
    layer::{ArcLayer, ConsumeErrLayer},
    rt::{Executor, spawn},
    service::service_fn,
};
use rama_http::{
    Body, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Version,
    io::upgrade::{Upgraded, handle_upgrade},
    layer::{
        upgrade::mitm::HttpUpgradeMitmRelayLayer,
        version_adapter::{ResponseVersionAdapter, adapt_request_version},
    },
    proto::{
        ext::Protocol,
        h2::{PseudoHeader, PseudoHeaderOrder},
    },
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
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::mpsc,
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(20);
const URI: &str = "wss://localhost/socket";

/// `prefix`-named fields in order: a duplicate both adjacent and interleaved, and a
/// sensitive value among them.
fn fields(prefix: &str) -> Vec<(HeaderName, HeaderValue)> {
    let name = |suffix: &str| HeaderName::try_from(format!("{prefix}-{suffix}")).expect("name");
    let mut secret = HeaderValue::from_static("hunter2");
    secret.set_sensitive(true);
    vec![
        (name("first"), HeaderValue::from_static("1")),
        (name("dup"), HeaderValue::from_static("a")),
        (name("dup"), HeaderValue::from_static("b")),
        (name("secret"), secret),
        (name("dup"), HeaderValue::from_static("c")),
        (name("last"), HeaderValue::from_static("z")),
    ]
}

/// The `prefix`-named fields of `headers`, in wire order.
fn observe(headers: &HeaderMap, prefix: &str) -> Vec<(HeaderName, HeaderValue)> {
    headers
        .ordered_iter()
        .filter(|(name, _)| name.as_str().starts_with(prefix))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn render(fields: &[(HeaderName, HeaderValue)]) -> Vec<String> {
    fields
        .iter()
        .map(|(name, value)| format!("{name}: {}", value.to_str().expect("ascii")))
        .collect()
}

fn secret_is_sensitive(fields: &[(HeaderName, HeaderValue)]) -> Option<bool> {
    fields
        .iter()
        .find(|(name, _)| name.as_str().ends_with("-secret"))
        .map(|(_, value)| value.is_sensitive())
}

/// A pseudo-header order no encoder uses by default.
fn client_pseudo_order() -> PseudoHeaderOrder {
    [
        PseudoHeader::Protocol,
        PseudoHeader::Authority,
        PseudoHeader::Scheme,
        PseudoHeader::Path,
        PseudoHeader::Method,
    ]
    .into_iter()
    .collect()
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

/// Which peer starts the close handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Closer {
    Client,
    Origin,
}

/// What the origin saw of a relayed handshake request.
struct Handshake {
    fields: Vec<(HeaderName, HeaderValue)>,
    method: Method,
    uri: String,
    protocol: Option<Protocol>,
    pseudo: Option<Vec<PseudoHeader>>,
}

/// Read one masked client frame with a short payload.
async fn read_client_frame(io: &mut Upgraded) -> Result<(u8, Vec<u8>), BoxError> {
    let first = io.read_u8().await?;
    let second = io.read_u8().await?;
    if second & 0x80 == 0 || second & 0x7f >= 126 {
        return Err(BoxError::from_static_str(
            "expected a short masked client frame",
        ));
    }
    let mut mask = [0; 4];
    io.read_exact(&mut mask).await?;
    let mut payload = vec![0; usize::from(second & 0x7f)];
    io.read_exact(&mut payload).await?;
    for (byte, mask) in payload.iter_mut().zip(mask.iter().cycle()) {
        *byte ^= mask;
    }
    Ok((first, payload))
}

/// Echo `HELLO`, complete the close handshake started by `closer`, end the stream and
/// require the relay to end its side cleanly too (FIN or END_STREAM, not a reset).
async fn raw_origin_session(mut io: Upgraded, closer: Closer) -> Result<(), BoxError> {
    let (first, payload) = read_client_frame(&mut io).await?;
    if first != 0x81 || payload != b"HELLO" {
        return Err(BoxError::from_static_str("expected the relayed text"));
    }
    io.write_all(&[0x81, 5]).await?;
    io.write_all(&payload).await?;
    if closer == Closer::Origin {
        io.write_all(&[0x88, 2, 0x03, 0xe8]).await?;
    }
    io.flush().await?;
    let (first, payload) = read_client_frame(&mut io).await?;
    if first != 0x88 {
        return Err(BoxError::from_static_str("expected a close frame"));
    }
    if closer == Closer::Client {
        io.write_all(&[0x88, u8::try_from(payload.len())?]).await?;
        io.write_all(&payload).await?;
    }
    io.shutdown().await?;
    let mut rest = Vec::new();
    io.read_to_end(&mut rest).await?;
    if rest.is_empty() {
        Ok(())
    } else {
        Err(BoxError::from_static_str("bytes after the close handshake"))
    }
}

/// A raw RFC 6455 origin: it reports each handshake it accepts, answers with its own
/// fields, and reports how the relayed WebSocket ended.
fn origin(
    seen: mpsc::UnboundedSender<Handshake>,
    ended: mpsc::UnboundedSender<Result<(), String>>,
    closer: Closer,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(move |request: Request| {
        let seen = seen.clone();
        let ended = ended.clone();
        async move {
            _ = seen.send(Handshake {
                fields: observe(request.headers(), "x-"),
                method: request.method().clone(),
                uri: request.uri().to_string(),
                protocol: request.extensions().get_ref::<Protocol>().cloned(),
                pseudo: request
                    .extensions()
                    .get_ref::<PseudoHeaderOrder>()
                    .map(|order| order.iter().collect()),
            });
            let mut accepted = match WebSocketAcceptor::new().serve(request).await {
                Ok(accepted) => accepted,
                Err(response) => return Ok(response),
            };
            for (name, value) in fields("x-resp") {
                accepted.response.headers_mut().append(name, value);
            }
            let request = accepted.request;
            spawn(async move {
                let outcome = match handle_upgrade(&request).await {
                    Ok(io) => raw_origin_session(io, closer).await,
                    Err(error) => Err(error),
                };
                _ = ended.send(outcome.map_err(|error| error.to_string()));
            });
            Ok(accepted.response)
        }
    })
}

async fn assert_relay(ingress: Version, egress: Version, closer: Closer) {
    let cell = format!("{ingress:?} -> {egress:?}, {closer:?} closes");
    let (seen, mut handshakes) = mpsc::unbounded_channel();
    let (ended, mut origin_end) = mpsc::unbounded_channel();
    let upstream = Hop::start(egress, origin(seen, ended, closer)).await;

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
    let builder = fields("x-req")
        .into_iter()
        .fold(builder, |builder, (name, value)| {
            builder.with_header(name, value)
        });
    let extensions = Extensions::new();
    extensions.insert(client_pseudo_order());
    let mut socket = timeout(LIMIT, builder.handshake(extensions))
        .await
        .expect("handshake in time")
        .map_err(|error| format!("{cell}: {error}"))
        .expect("handshake");

    // Only HTTP/2 and HTTP/3 carry sensitivity (never-indexed fields) and pseudo-headers.
    let framed = ingress >= Version::HTTP_2 && egress >= Version::HTTP_2;
    let handshake = handshakes.recv().await.expect("origin handshake");
    assert_eq!(
        render(&handshake.fields),
        render(&fields("x-req")),
        "{cell}"
    );
    assert_eq!(
        secret_is_sensitive(&handshake.fields),
        Some(framed),
        "{cell}"
    );
    let response = observe(&socket.response().headers, "x-resp");
    assert_eq!(render(&response), render(&fields("x-resp")), "{cell}");
    assert_eq!(secret_is_sensitive(&response), Some(framed), "{cell}");
    if egress >= Version::HTTP_2 {
        assert_eq!(handshake.method, Method::CONNECT, "{cell}");
        assert_eq!(handshake.protocol, Some(Protocol::WEBSOCKET), "{cell}");
        // An HTTP/1.1 ingress arrives over a plain byte stream here: nothing makes it secure.
        let scheme = if ingress >= Version::HTTP_2 {
            "https"
        } else {
            "http"
        };
        assert_eq!(
            handshake.uri,
            format!("{scheme}://localhost/socket"),
            "{cell}"
        );
    } else {
        assert_eq!(handshake.method, Method::GET, "{cell}");
        assert_eq!(handshake.uri, "/socket", "{cell}");
    }
    if framed {
        let order: Vec<_> = client_pseudo_order().iter().collect();
        assert_eq!(handshake.pseudo, Some(order), "{cell}: pseudo-header order");
    }

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

    if closer == Closer::Client {
        socket.close(None).await.expect("close");
    }
    let close = timeout(LIMIT, socket.recv_message())
        .await
        .expect("close in time");
    assert!(matches!(close, Ok(Message::Close(_))), "{cell}: {close:?}");
    // Sends our reply when the origin closed first.
    socket.flush().await.expect("flush");
    let origin_end = timeout(LIMIT, origin_end.recv())
        .await
        .expect("origin end in time")
        .expect("origin report");
    assert_eq!(origin_end, Ok(()), "{cell}: the relay's upstream end");
    // The relay ends the downstream stream cleanly as well.
    let mut io = socket.into_inner().into_inner();
    let mut rest = Vec::new();
    timeout(LIMIT, io.read_to_end(&mut rest))
        .await
        .expect("downstream end in time")
        .map_err(|error| format!("{cell}: {error}"))
        .expect("the relay's downstream end");
    assert!(rest.is_empty(), "{cell}");
    drop(io);
    downstream.close().await;
    upstream.close().await;
}

#[tokio::test]
async fn relays_bridge_every_http_version_pair_over_real_engines() {
    let versions = [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3];
    for (ingress, egress) in versions
        .into_iter()
        .flat_map(|ingress| versions.map(|egress| (ingress, egress)))
    {
        for closer in [Closer::Client, Closer::Origin] {
            assert_relay(ingress, egress, closer).await;
        }
    }
}
