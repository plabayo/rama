//! WebSockets over HTTP/3 (RFC 9220) through the rama-ws handshake over real QUIC connections.

#![expect(clippy::unwrap_used, reason = "test fixtures")]

use rama_core::{
    Service,
    bytes::Bytes,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    futures::{SinkExt, poll},
    rt::{Executor, spawn},
    service::service_fn,
};
use rama_http::{
    Body, Method, Request, Response, StatusCode, Version,
    conn::TargetHttpVersion,
    io::upgrade::{Upgraded, handle_upgrade},
    proto::ext::Protocol,
};
use rama_http_core::{
    body::Incoming,
    h3::{Error as H3Error, client, connection::Config, server},
};
use rama_net::address::SocketAddress;
use rama_quic::{Endpoint, TransportConfig, tls::TlsOptions};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::test_utils::MemoryDatagramSocket;
use rama_ws::{
    Message,
    handshake::{
        client::HttpClientWebSocketExt as _,
        server::{ServerWebSocket, WebSocketAcceptor},
    },
};
use std::{convert::Infallible, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::{Notify, mpsc},
};

#[cfg(feature = "compression")]
use flate2::{Decompress, FlushDecompress};

const LIMIT: Duration = Duration::from_secs(20);
const URI: &str = "wss://localhost/ws";

/// A connected in-memory QUIC client/server pair.
struct Pair {
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    client: rama_quic::Connection,
    server: rama_quic::Connection,
}

impl Pair {
    async fn new() -> Self {
        let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        let alpn = || [b"h3".as_slice().into()].into_iter().collect();
        let server_tls = TlsServerConfig::new()
            .with_alpn(alpn())
            .with_server_auth(identity.clone());
        let client_tls = TlsClientConfig::new()
            .with_alpn(alpn())
            .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
            .unwrap();
        let transport = || {
            let mut transport = TransportConfig::default();
            Config::default()
                .configure_transport(&mut transport)
                .unwrap();
            Arc::new(transport)
        };
        let mut server_config =
            rama_quic::ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap();
        server_config.set_transport_config(transport());
        let mut client_config =
            rama_quic::ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default()).unwrap();
        client_config.set_transport_config(transport());
        let (server_socket, client_socket) = MemoryDatagramSocket::pair(
            SocketAddress::local_ipv4(443),
            SocketAddress::local_ipv4(444),
            NonZeroUsize::MIN,
        );
        let server_endpoint = Endpoint::build(Executor::new())
            .with_server_config(server_config)
            .with_datagram_socket(server_socket)
            .unwrap();
        let client_endpoint = Endpoint::build(Executor::new())
            .with_datagram_socket(client_socket)
            .unwrap();
        let accept = spawn({
            let endpoint = server_endpoint.clone();
            async move { endpoint.accept().await.unwrap().await.unwrap() }
        });
        let client = client_endpoint
            .connect_with(
                client_config,
                server_endpoint.local_addr().unwrap(),
                "localhost",
            )
            .unwrap()
            .await
            .unwrap();
        let server = accept.await.unwrap();
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

/// The HTTP/3 request sender as a Rama client service.
#[derive(Clone)]
struct H3Client(client::SendRequest<Body>);

impl Service<Request> for H3Client {
    type Output = Response<Incoming>;
    type Error = H3Error;

    async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
        // A version hint for connection layers must keep the request on HTTP/3.
        if let Some(target) = request.extensions().get_ref::<TargetHttpVersion>() {
            assert_eq!(target.0, Version::HTTP_3);
        }
        self.0.clone().send_request(request).await
    }
}

/// Start both HTTP/3 engines; every request stream is served by `service`.
async fn start<S>(pair: &Pair, extended_connect: bool, service: S) -> H3Client
where
    S: Service<Request<Incoming>, Output = Response, Error: Into<BoxError>> + Clone,
{
    let (sender, client_driver) =
        client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new()).unwrap();
    let config = Config {
        extended_connect,
        ..Config::default()
    };
    let (mut connection, server_driver) = server::handshake(pair.server.clone(), config).unwrap();
    spawn(client_driver.run());
    spawn(server_driver.run());
    spawn(async move {
        while let Ok(stream) = connection.accept().await {
            let service = service.clone();
            spawn(async move {
                let Ok((request, respond)) = stream.resolve().await else {
                    return;
                };
                let response = service.serve(request).await.unwrap_or_else(|_| {
                    let mut response = Response::new(Body::empty());
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    response
                });
                _ = respond.send_response(response).await;
            });
        }
    });
    H3Client(sender)
}

fn echo_server() -> impl Service<Request<Incoming>, Output = Response, Error: Into<BoxError>> + Clone
{
    service_fn(|request: Request<Incoming>| async move {
        // RFC 8441 §5 via RFC 9220: Extended CONNECT carries no key/accept exchange.
        assert!(!request.headers().contains_key("sec-websocket-key"));
        WebSocketAcceptor::new()
            .into_echo_service()
            .serve(request)
            .await
    })
}

/// How each server-side socket ended: `Ok` after a close handshake, `Err` otherwise.
fn recording_server(
    ends: mpsc::UnboundedSender<Result<(), String>>,
) -> impl Service<Request<Incoming>, Output = Response, Error: Into<BoxError>> + Clone {
    WebSocketAcceptor::new().into_service(service_fn(move |mut socket: ServerWebSocket| {
        let ends = ends.clone();
        async move {
            let end = loop {
                match socket.recv_message().await {
                    // Flushing drives the queued close reply and the orderly end of stream.
                    Ok(Message::Close(_)) => {
                        break socket.flush().await.map_err(|error| format!("{error:?}"));
                    }
                    Ok(message) if message.is_text() || message.is_binary() => {
                        if socket.send_message(message).await.is_err() {
                            break Err("send failed".to_owned());
                        }
                    }
                    Ok(_) => (),
                    Err(error) => break Err(format!("{error:?}")),
                }
            };
            _ = ends.send(end);
            Ok::<_, Infallible>(())
        }
    }))
}

/// A message larger than the stream receive window.
const LARGE: usize = 1024 * 1024;

/// Stops reading `/stall` sockets inside a large client frame; other paths echo.
#[derive(Clone)]
struct Staller {
    /// Signalled once a frame header was read: the sender is then out of credit.
    stalled: mpsc::UnboundedSender<()>,
    /// Lets the stalled reader take the payload.
    release: Arc<Notify>,
    /// The payload length read, or why reading it failed.
    received: mpsc::UnboundedSender<Result<usize, String>>,
}

impl Service<Request<Incoming>> for Staller {
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, request: Request<Incoming>) -> Result<Self::Output, Self::Error> {
        if request.uri().path_or_root().as_ref() != "/stall" {
            return echo_server().serve(request).await.map_err(Into::into);
        }
        let accepted = match WebSocketAcceptor::new().serve(request).await {
            Ok(accepted) => accepted,
            Err(response) => return Ok(response),
        };
        let request = accepted.request;
        let this = self.clone();
        spawn(async move {
            let mut io = handle_upgrade(&request).await.unwrap();
            // A masked binary frame with a 64-bit length: 2 + 8 + 4 mask bytes.
            let mut header = [0; 14];
            io.read_exact(&mut header).await.unwrap();
            assert_eq!(header[..2], [0x82, 0xff]);
            let len =
                usize::try_from(u64::from_be_bytes(header[2..10].try_into().unwrap())).unwrap();
            _ = this.stalled.send(());
            this.release.notified().await;
            let mut payload = vec![0; len];
            let outcome = match io.read_exact(&mut payload).await {
                Ok(_) => {
                    io.write_all(&[0x81, 2, b'o', b'k']).await.unwrap();
                    io.shutdown().await.unwrap();
                    Ok(len)
                }
                Err(error) => Err(format!("{error:?}")),
            };
            _ = this.received.send(outcome);
        });
        Ok(accepted.response)
    }
}

impl Staller {
    fn new() -> (
        Self,
        mpsc::UnboundedReceiver<()>,
        mpsc::UnboundedReceiver<Result<usize, String>>,
    ) {
        let (stalled, stalled_rx) = mpsc::unbounded_channel();
        let (received, received_rx) = mpsc::unbounded_channel();
        let this = Self {
            stalled,
            release: Arc::default(),
            received,
        };
        (this, stalled_rx, received_rx)
    }
}

/// A full round trip on a fresh socket of the same connection.
async fn round_trip(client: &H3Client, text: &'static str) {
    let mut socket = client
        .websocket_h3(URI)
        .handshake(Extensions::new())
        .await
        .unwrap();
    socket.send_message(Message::text(text)).await.unwrap();
    assert_eq!(socket.recv_message().await.unwrap(), Message::text(text));
    socket.close(None).await.unwrap();
    assert!(matches!(
        socket.recv_message().await.unwrap(),
        Message::Close(_)
    ));
}

#[tokio::test]
async fn messages_pings_and_close_round_trip_over_h3() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new().await;
        let client = start(&pair, true, echo_server()).await;
        let mut socket = client
            .websocket_h3(URI)
            .handshake(Extensions::new())
            .await
            .expect("handshake");
        socket.send_message(Message::text("hello")).await.unwrap();
        assert_eq!(socket.recv_message().await.unwrap(), Message::text("hello"));
        // Larger than the QUIC stream receive window: flow control carries it through.
        let big = Bytes::from(vec![0x5a; 1024 * 1024]);
        socket
            .send_message(Message::binary(big.clone()))
            .await
            .unwrap();
        assert_eq!(socket.recv_message().await.unwrap(), Message::binary(big));
        socket
            .send_message(Message::Ping(Bytes::from_static(b"ping")))
            .await
            .unwrap();
        assert_eq!(
            socket.recv_message().await.unwrap(),
            Message::Pong(Bytes::from_static(b"ping"))
        );
        socket.close(None).await.unwrap();
        // The close handshake completes and the stream ends in order, not by reset.
        // The peer's close reply may be delivered, then the stream ends without a reset.
        let mut end = socket.recv_message().await;
        if let Ok(Message::Close(_)) = end {
            end = socket.recv_message().await;
        }
        match end {
            Err(error) if error.is_connection_error() => (),
            other => panic!("expected an orderly close, got {other:?}"),
        }
        pair.close().await;
    })
    .await
    .unwrap();
}

/// A raw Extended CONNECT WebSocket tunnel, for exact wire checks.
async fn raw_tunnel(client: &H3Client) -> Upgraded {
    let request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_3)
        .uri("https://localhost/ws")
        .header("sec-websocket-version", "13")
        .body(Body::empty())
        .unwrap();
    request.extensions().insert(Protocol::WEBSOCKET);
    let response = client.serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // RFC 8441 §5 via RFC 9220: no key/accept exchange on Extended CONNECT.
    assert!(!response.headers().contains_key("sec-websocket-accept"));
    handle_upgrade(&response).await.unwrap()
}

/// A raw tunnel offering `extensions`; returns the accepted extensions too.
async fn raw_tunnel_offering(client: &H3Client, extensions: &str) -> (Option<String>, Upgraded) {
    let request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_3)
        .uri("https://localhost/ws")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-extensions", extensions)
        .body(Body::empty())
        .unwrap();
    request.extensions().insert(Protocol::WEBSOCKET);
    let response = client.serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let accepted = response
        .headers()
        .get("sec-websocket-extensions")
        .map(|value| value.to_str().unwrap().to_owned());
    (accepted, handle_upgrade(&response).await.unwrap())
}

/// A client frame (masked, RFC 6455 §5.3) with a short payload.
fn masked(first: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0x37, 0xfa, 0x21, 0x3d];
    let mut frame = vec![first, 0x80 | u8::try_from(payload.len()).unwrap()];
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));
    frame
}

async fn read_frame(io: &mut Upgraded) -> (u8, u8, Vec<u8>) {
    let first = io.read_u8().await.unwrap();
    let second = io.read_u8().await.unwrap();
    assert!(second & 0x7f < 126, "short test frames only");
    let mut payload = vec![0; usize::from(second & 0x7f)];
    io.read_exact(&mut payload).await.unwrap();
    (first, second, payload)
}

#[tokio::test]
async fn frames_are_masked_fragmented_and_validated_on_the_wire() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new().await;
        let client = start(&pair, true, echo_server()).await;

        // A fragmented text message: first frame without FIN, then a continuation.
        let mut io = raw_tunnel(&client).await;
        io.write_all(&masked(0x01, b"hel")).await.unwrap();
        io.write_all(&masked(0x80, b"lo")).await.unwrap();
        io.flush().await.unwrap();
        let (first, second, payload) = read_frame(&mut io).await;
        assert_eq!(first, 0x81, "one final text frame echoed");
        assert_eq!(second & 0x80, 0, "server frames are never masked");
        assert_eq!(payload, b"hello");

        // An orderly close: the server replies with a close frame and then ends the stream
        // with FIN (RFC 9220 §3), not a reset.
        let mut io = raw_tunnel(&client).await;
        io.write_all(&masked(0x88, &1000u16.to_be_bytes()))
            .await
            .unwrap();
        io.flush().await.unwrap();
        let (first, _, payload) = read_frame(&mut io).await;
        assert_eq!(first, 0x88, "close reply");
        assert_eq!(&payload[..2], &1000u16.to_be_bytes());
        let mut rest = Vec::new();
        io.read_to_end(&mut rest)
            .await
            .expect("the server ends the stream with FIN");
        assert!(rest.is_empty(), "{rest:?}");

        // RFC 6455 §5.1: an unmasked client frame closes the connection (a 1002 close frame is
        // optional); nothing is echoed, and other requests keep working.
        let mut io = raw_tunnel(&client).await;
        io.write_all(&[0x81, 0x02, b'h', b'i']).await.unwrap();
        io.flush().await.unwrap();
        let mut rest = Vec::new();
        _ = io.read_to_end(&mut rest).await;
        assert!(
            rest.is_empty() || rest[0] == 0x88,
            "only a close frame may follow: {rest:?}"
        );
        let mut io = raw_tunnel(&client).await;
        io.write_all(&masked(0x81, b"ok")).await.unwrap();
        io.flush().await.unwrap();
        assert_eq!(read_frame(&mut io).await.2, b"ok");
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unsuccessful_and_unavailable_negotiation_leave_the_connection_usable() {
    tokio::time::timeout(LIMIT, async {
        // A server without SETTINGS_ENABLE_CONNECT_PROTOCOL: the client fails locally.
        let pair = Pair::new().await;
        let client = start(&pair, false, echo_server()).await;
        client
            .websocket_h3(URI)
            .handshake(Extensions::new())
            .await
            .expect_err("extended CONNECT is not enabled");
        let ordinary = Request::builder()
            .version(Version::HTTP_3)
            .uri("https://localhost/")
            .body(Body::empty())
            .unwrap();
        // The request still reaches the server, which refuses a non-WebSocket request.
        assert!(!client.serve(ordinary).await.unwrap().status().is_success());
        pair.close().await;

        // A refusing server: the handshake fails, and later handshakes still work.
        let pair = Pair::new().await;
        let refusing = service_fn(|request: Request<Incoming>| async move {
            if request.uri().path_or_root().as_ref() == "/refused" {
                let mut response = Response::new(Body::from("no"));
                *response.status_mut() = StatusCode::FORBIDDEN;
                return Ok::<_, BoxError>(response);
            }
            echo_server().serve(request).await.map_err(Into::into)
        });
        let client = start(&pair, true, refusing).await;
        client
            .websocket_h3("wss://localhost/refused")
            .handshake(Extensions::new())
            .await
            .expect_err("403 is not a WebSocket");
        let mut socket = client
            .websocket_h3(URI)
            .handshake(Extensions::new())
            .await
            .expect("later handshake");
        socket.send_message(Message::text("again")).await.unwrap();
        assert_eq!(socket.recv_message().await.unwrap(), Message::text("again"));
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn concurrent_websockets_share_one_connection() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new().await;
        let client = start(&pair, true, echo_server()).await;
        let mut tasks = Vec::new();
        for index in 0..16 {
            let client = client.clone();
            tasks.push(spawn(async move {
                let mut socket = client
                    .websocket_h3(URI)
                    .handshake(Extensions::new())
                    .await
                    .expect("handshake");
                for round in 0..8 {
                    let text = format!("{index}:{round}");
                    socket
                        .send_message(Message::text(text.clone()))
                        .await
                        .unwrap();
                    assert_eq!(socket.recv_message().await.unwrap(), Message::text(text));
                }
                socket.close(None).await.unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn orderly_close_ends_cleanly_and_abandoning_resets() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new().await;
        let (ends, mut ended) = mpsc::unbounded_channel();
        let client = start(&pair, true, recording_server(ends)).await;

        // RFC 9220 §3: an orderly close is a close handshake followed by FIN.
        let mut socket = client
            .websocket_h3(URI)
            .handshake(Extensions::new())
            .await
            .expect("handshake");
        socket.send_message(Message::text("hi")).await.unwrap();
        assert_eq!(socket.recv_message().await.unwrap(), Message::text("hi"));
        socket.close(None).await.unwrap();
        assert_eq!(ended.recv().await.unwrap(), Ok(()));

        // Dropping a socket without a close aborts: the server sees a reset, not a close.
        let mut socket = client
            .websocket_h3(URI)
            .handshake(Extensions::new())
            .await
            .expect("handshake");
        socket.send_message(Message::text("before")).await.unwrap();
        assert_eq!(
            socket.recv_message().await.unwrap(),
            Message::text("before")
        );
        drop(socket);
        let end = ended.recv().await.unwrap();
        assert!(end.is_err(), "abandoned socket ended as {end:?}");

        // The connection keeps serving new sockets.
        let mut socket = client
            .websocket_h3(URI)
            .handshake(Extensions::new())
            .await
            .expect("handshake after abort");
        socket.send_message(Message::text("after")).await.unwrap();
        assert_eq!(socket.recv_message().await.unwrap(), Message::text("after"));
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn flushing_after_a_received_close_replies_and_finishes() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new().await;
        let service = WebSocketAcceptor::new().into_service(service_fn(
            |mut socket: ServerWebSocket| async move {
                assert!(matches!(
                    socket.recv_message().await.unwrap(),
                    Message::Close(_)
                ));
                socket.flush().await.unwrap();
                // The socket is dropped right away: the flush already ended the stream.
                Ok::<_, Infallible>(())
            },
        ));
        let client = start(&pair, true, service).await;
        let mut io = raw_tunnel(&client).await;
        io.write_all(&masked(0x88, &1000u16.to_be_bytes()))
            .await
            .unwrap();
        io.flush().await.unwrap();
        let mut bytes = Vec::new();
        io.read_to_end(&mut bytes)
            .await
            .expect("the close reply ends with FIN, not a reset");
        assert_eq!(bytes, [0x88, 2, 0x03, 0xe8]);
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_reported_clean_close_is_a_reply_and_fin_on_the_wire() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new().await;
        let (ends, mut ended) = mpsc::unbounded_channel();
        let client = start(&pair, true, recording_server(ends)).await;
        let mut io = raw_tunnel(&client).await;
        io.write_all(&masked(0x88, &1000u16.to_be_bytes()))
            .await
            .unwrap();
        io.flush().await.unwrap();
        assert_eq!(ended.recv().await.unwrap(), Ok(()));
        let mut bytes = Vec::new();
        io.read_to_end(&mut bytes)
            .await
            .expect("the fixture's clean close must be a FIN");
        assert_eq!(bytes, [0x88, 2, 0x03, 0xe8]);
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_cancelled_blocked_send_resumes_and_stalls_no_other_stream() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new().await;
        let (staller, mut stalled, mut received) = Staller::new();
        let release = staller.release.clone();
        let client = start(&pair, true, staller).await;
        let mut stuck = client
            .websocket_h3("wss://localhost/stall")
            .handshake(Extensions::new())
            .await
            .expect("handshake");
        {
            let send = stuck.send_message(Message::binary(vec![0x5a; LARGE]));
            tokio::pin!(send);
            tokio::select! {
                _ = &mut send => panic!("sent beyond the stalled reader's window"),
                _ = stalled.recv() => (),
            }
            // The reader stopped inside the frame, so the send is out of credit.
            assert!(poll!(&mut send).is_pending());
            // Other streams on the connection keep flowing meanwhile.
            round_trip(&client, "second").await;
            assert!(poll!(&mut send).is_pending());
        }
        // The cancelled send keeps its queued frame: a flush completes it once released.
        release.notify_one();
        stuck.flush().await.unwrap();
        assert_eq!(received.recv().await.unwrap(), Ok(LARGE));
        assert_eq!(stuck.recv_message().await.unwrap(), Message::text("ok"));
        round_trip(&client, "third").await;
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropping_a_blocked_send_resets_only_its_stream() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new().await;
        let (staller, mut stalled, mut received) = Staller::new();
        let release = staller.release.clone();
        let client = start(&pair, true, staller).await;
        let mut stuck = client
            .websocket_h3("wss://localhost/stall")
            .handshake(Extensions::new())
            .await
            .expect("handshake");
        {
            let send = stuck.send_message(Message::binary(vec![0x5a; LARGE]));
            tokio::pin!(send);
            tokio::select! {
                _ = &mut send => panic!("sent beyond the stalled reader's window"),
                _ = stalled.recv() => (),
            }
            assert!(poll!(&mut send).is_pending());
        }
        drop(stuck);
        release.notify_one();
        let outcome = received.recv().await.unwrap();
        assert!(
            outcome.is_err(),
            "an abandoned message arrived: {outcome:?}"
        );
        round_trip(&client, "second").await;
        round_trip(&client, "third").await;
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn closing_a_client_after_the_close_exchange_finishes_its_stream() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new().await;
        let (ended, mut end) = mpsc::unbounded_channel();
        // Answers the close but never ends its own side first.
        let service = service_fn(move |request: Request<Incoming>| {
            let ended = ended.clone();
            async move {
                let accepted = match WebSocketAcceptor::new().serve(request).await {
                    Ok(accepted) => accepted,
                    Err(response) => return Ok::<_, BoxError>(response),
                };
                let request = accepted.request;
                spawn(async move {
                    let mut io = handle_upgrade(&request).await.unwrap();
                    // A masked, empty client close: 0x88 0x80 and the mask.
                    let mut close = [0; 6];
                    io.read_exact(&mut close).await.unwrap();
                    assert_eq!(close[..2], [0x88, 0x80]);
                    io.write_all(&[0x88, 0]).await.unwrap();
                    io.flush().await.unwrap();
                    let mut rest = Vec::new();
                    _ = ended.send(io.read_to_end(&mut rest).await.map(|_| rest));
                });
                Ok(accepted.response)
            }
        });
        let client = start(&pair, true, service).await;
        let mut socket = client
            .websocket_h3(URI)
            .handshake(Extensions::new())
            .await
            .expect("handshake");
        socket.close(None).await.unwrap();
        assert!(matches!(
            socket.recv_message().await.unwrap(),
            Message::Close(_)
        ));
        socket.flush().await.unwrap();
        // The exchange is complete: closing the sink ends the transport, before the server's.
        SinkExt::close(&mut socket).await.unwrap();
        let rest = end.recv().await.unwrap().expect("FIN, not a reset");
        assert!(rest.is_empty());
        pair.close().await;
    })
    .await
    .unwrap();
}

/// Inflate one permessage-deflate message (RFC 7692 §7.2.2), keeping the peer's context.
#[cfg(feature = "compression")]
fn inflate(context: &mut Decompress, payload: &[u8]) -> Vec<u8> {
    let mut input = payload.to_vec();
    input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
    let mut output = Vec::with_capacity(1024);
    context
        .decompress_vec(&input, &mut output, FlushDecompress::Sync)
        .unwrap();
    output
}

#[cfg(feature = "compression")]
#[tokio::test]
async fn per_message_deflate_over_h3_carries_fragments_controls_and_close() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new().await;
        let deflating = service_fn(|request: Request<Incoming>| async move {
            WebSocketAcceptor::new()
                .with_per_message_deflate()
                .into_echo_service()
                .serve(request)
                .await
        });
        let client = start(&pair, true, deflating).await;
        let (accepted, mut io) = raw_tunnel_offering(&client, "permessage-deflate").await;
        assert!(
            accepted
                .as_deref()
                .is_some_and(|value| value.starts_with("permessage-deflate")),
            "{accepted:?}"
        );
        let mut server_context = Decompress::new(false);

        // RFC 7692 §7.2.3.1: "Hello" compressed and fragmented, with a ping in between.
        io.write_all(&masked(0x41, &[0xf2, 0x48, 0xcd]))
            .await
            .unwrap();
        io.write_all(&masked(0x89, b"ping")).await.unwrap();
        io.write_all(&masked(0x80, &[0xc9, 0xc9, 0x07, 0x00]))
            .await
            .unwrap();
        io.flush().await.unwrap();
        let mut pong = false;
        let mut echo = None;
        while !pong || echo.is_none() {
            let (first, _, payload) = read_frame(&mut io).await;
            match first {
                // Control frames are never compressed (RFC 7692 §6.1).
                0x8a => {
                    assert_eq!(payload, b"ping");
                    pong = true;
                }
                // FIN, RSV1 and text: the echo is compressed.
                0xc1 => echo = Some(inflate(&mut server_context, &payload)),
                other => panic!("unexpected frame {other:#x}"),
            }
        }
        assert_eq!(echo.unwrap(), b"Hello");

        // An uncompressed message is valid too; the echo may come back compressed.
        io.write_all(&masked(0x81, b"plain")).await.unwrap();
        io.flush().await.unwrap();
        let (first, _, payload) = read_frame(&mut io).await;
        let echoed = match first {
            0xc1 => inflate(&mut server_context, &payload),
            0x81 => payload,
            other => panic!("unexpected frame {other:#x}"),
        };
        assert_eq!(echoed, b"plain");

        // The close is uncompressed and ends with FIN.
        io.write_all(&masked(0x88, &1000u16.to_be_bytes()))
            .await
            .unwrap();
        io.flush().await.unwrap();
        let mut bytes = Vec::new();
        io.read_to_end(&mut bytes).await.expect("FIN, not a reset");
        assert_eq!(bytes, [0x88, 2, 0x03, 0xe8]);
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn an_unaccepted_per_message_deflate_offer_falls_back_to_plain_frames() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new().await;
        let client = start(&pair, true, echo_server()).await;
        let (accepted, mut io) = raw_tunnel_offering(&client, "permessage-deflate").await;
        assert_eq!(accepted, None);
        io.write_all(&masked(0x81, b"plain")).await.unwrap();
        io.flush().await.unwrap();
        let (first, _, payload) = read_frame(&mut io).await;
        assert_eq!((first, payload.as_slice()), (0x81, b"plain".as_slice()));
        // Without the extension RSV1 is a protocol error: the server stops the connection.
        io.write_all(&masked(0xc1, &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]))
            .await
            .unwrap();
        io.flush().await.unwrap();
        let mut rest = Vec::new();
        _ = io.read_to_end(&mut rest).await;
        assert!(
            rest.is_empty() || rest[0] == 0x88,
            "only a close may follow: {rest:?}"
        );
        pair.close().await;
    })
    .await
    .unwrap();
}
