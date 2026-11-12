//! One limit on interim (1xx) responses, set through the client connector, the input or the
//! transport, reaches the HTTP/1, HTTP/2 and HTTP/3 connection that gets established, and so
//! does the budget of requests an HTTP/2 or HTTP/3 connection refuses for it.
#![cfg(feature = "quic")]
#![expect(clippy::expect_used, reason = "test assertions identify failed stages")]

use parking_lot::Mutex;
use rama_core::{
    Service as _, ServiceInput, bytes::Bytes, extensions::ExtensionsRef as _, graceful::WeakScope,
    rt::spawn, service::service_fn,
};
use rama_http::{Body, Request, Response, StatusCode, Version};
use rama_http_backend::client::{
    Http3Transport, HttpClientService, HttpConnector, MaxInformationalResponses,
    RefusedStreamBudget, http_connect, http2_eager_handshake,
};
use rama_http_core::{
    h2::{RateBudget, server as h2_server},
    h3::{connection::Config, server as h3_server, transport::BoxedConnection},
};
use rama_net::{
    address::SocketAddress,
    client::{ConnectionError, EstablishedClientConnection},
};
use rama_quic::{
    ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig, tls::TlsOptions,
};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::test_utils::MemoryDatagramSocket;
use std::{iter::repeat_n, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    time::timeout,
};

const ALLOWED: usize = 3;
const LIMIT: Duration = Duration::from_secs(20);
const INTERIM: &[u8] = b"HTTP/1.1 103 Early Hints\r\nlink: </style.css>\r\n\r\n";
const FINAL: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";

/// Where the limit is configured.
#[derive(Debug, Clone, Copy)]
enum Source {
    /// On the input that opens the connection.
    Input,
    /// On the transport the connection is established on.
    Transport,
}

fn request(version: Version) -> Request {
    Request::builder()
        .version(version)
        .uri("https://localhost/")
        .body(Body::empty())
        .expect("request")
}

/// The input that opens a connection, carrying the limit if that is its `source`.
fn opening_request(version: Version, source: Source) -> Request {
    let request = request(version);
    if matches!(source, Source::Input) {
        request
            .extensions()
            .insert(MaxInformationalResponses(ALLOWED));
    }
    request
}

/// The client side of a byte stream, carrying the limit if that is its `source`.
fn stream(io: DuplexStream, source: Source) -> ServiceInput<DuplexStream> {
    let io = ServiceInput::new(io);
    if matches!(source, Source::Transport) {
        io.extensions().insert(MaxInformationalResponses(ALLOWED));
    }
    io
}

fn interim() -> Response<()> {
    Response::builder().status(103).body(()).expect("interim")
}

/// Answer one HTTP/1 request with `count` interim responses and a final one.
async fn h1_exchange(
    client: &HttpClientService<Body>,
    origin: &mut DuplexStream,
    count: usize,
) -> Option<StatusCode> {
    let (response, ()) = tokio::join!(client.serve(request(Version::HTTP_11)), async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(origin.read_u8().await.expect("request head"));
        }
        let mut bytes = INTERIM.repeat(count);
        bytes.extend_from_slice(FINAL);
        // The client closes once the limit is passed.
        _ = origin.write_all(&bytes).await;
    });
    response.ok().map(|response| response.status())
}

async fn h1_status(source: Source, count: usize) -> Option<StatusCode> {
    let (client_io, mut origin) = tokio::io::duplex(64 * 1024);
    let client = http_connect::<_, _, Body>(
        stream(client_io, source),
        opening_request(Version::HTTP_11, source),
        WeakScope::detached(),
    )
    .await
    .expect("HTTP/1 client")
    .conn;
    h1_exchange(&client, &mut origin, count).await
}

type H2Origin = h2_server::Connection<ServiceInput<DuplexStream>, Bytes>;

/// Answer one HTTP/2 request with `count` interim responses and a final one.
async fn h2_exchange(
    client: HttpClientService<Body>,
    mut origin: H2Origin,
    count: usize,
) -> Option<StatusCode> {
    let response = spawn(async move { client.serve(request(Version::HTTP_2)).await });
    let (_request, mut respond) = origin
        .accept()
        .await
        .expect("request")
        .expect("request stream");
    for _ in 0..count {
        // The client resets the stream once the limit is passed.
        if respond.send_informational(interim()).is_err() {
            break;
        }
    }
    _ = respond.send_response(Response::new(()), true);
    let serve = spawn(async move { while origin.accept().await.is_some() {} });
    let status = response
        .await
        .expect("request task")
        .ok()
        .map(|response| response.status());
    serve.abort();
    status
}

/// An HTTP/2 connection opened by a request (`eager` unset) or ahead of any request.
async fn h2_status(source: Source, eager: bool, count: usize) -> Option<StatusCode> {
    let (client_io, origin_io) = tokio::io::duplex(64 * 1024);
    let origin = spawn(h2_server::Builder::new().handshake(ServiceInput::new(origin_io)));
    let io = stream(client_io, source);
    let client = if eager {
        http2_eager_handshake::<_, Body>(io, WeakScope::detached())
            .await
            .expect("eager HTTP/2 client")
            .0
    } else {
        http_connect::<_, _, Body>(
            io,
            opening_request(Version::HTTP_2, source),
            WeakScope::detached(),
        )
        .await
        .expect("HTTP/2 client")
        .conn
    };
    let origin = origin.await.expect("origin task").expect("HTTP/2 origin");
    h2_exchange(client, origin, count).await
}

/// Where the budget of refused requests is configured.
#[derive(Debug, Clone, Copy)]
enum BudgetSource {
    /// Nowhere: the connection keeps its default.
    Unset,
    /// On the input that opens the connection.
    Input,
    /// On the transport, with the connection opened by a request (`eager` unset) or ahead
    /// of any request.
    Transport { eager: bool },
    /// On the connector.
    Connector,
    /// On the connector, with the input asking for no budget at all.
    ConnectorAndNoneOnInput,
}

/// Whether an HTTP/2 connection whose budget of refused requests is `budget`, configured
/// at `source`, still serves a request after its client refused `refused` of them.
async fn h2_survives_refusals(source: BudgetSource, budget: RateBudget, refused: usize) -> bool {
    let budget = RefusedStreamBudget(Some(budget));
    let (client_io, origin_io) = tokio::io::duplex(64 * 1024);
    let origin = spawn(h2_server::Builder::new().handshake(ServiceInput::new(origin_io)));
    let io = stream(client_io, Source::Transport);
    let input = request(Version::HTTP_2);
    match source {
        BudgetSource::Unset | BudgetSource::Connector => (),
        BudgetSource::Input => _ = input.extensions().insert(budget),
        BudgetSource::Transport { .. } => _ = io.extensions().insert(budget),
        BudgetSource::ConnectorAndNoneOnInput => {
            input.extensions().insert(RefusedStreamBudget(None));
        }
    }
    let client = match source {
        BudgetSource::Transport { eager: true } => {
            http2_eager_handshake::<_, Body>(io, WeakScope::detached())
                .await
                .expect("eager HTTP/2 client")
                .0
        }
        BudgetSource::Connector | BudgetSource::ConnectorAndNoneOnInput => {
            let io = Mutex::new(Some(io));
            let streams = service_fn(move |input: Request| {
                let conn = io.lock().take();
                async move {
                    Ok::<_, ConnectionError>(EstablishedClientConnection {
                        input,
                        conn: conn.expect("one connection"),
                    })
                }
            });
            HttpConnector::<_, Body>::new(streams, WeakScope::detached())
                .with_refused_stream_budget(budget)
                .serve(input)
                .await
                .expect("HTTP/2 client of a connector")
                .conn
        }
        BudgetSource::Unset | BudgetSource::Input | BudgetSource::Transport { eager: false } => {
            http_connect::<_, _, Body>(io, input, WeakScope::detached())
                .await
                .expect("HTTP/2 client")
                .conn
        }
    };
    let client = Arc::new(client);
    let mut origin: H2Origin = origin.await.expect("origin task").expect("HTTP/2 origin");

    for count in repeat_n(ALLOWED + 1, refused).chain([0]) {
        let client = client.clone();
        let response = spawn(async move { client.serve(request(Version::HTTP_2)).await });
        let Some(Ok((_request, mut respond))) = origin.accept().await else {
            return false;
        };
        for _ in 0..count {
            // The client resets the stream once the limit is passed.
            if respond.send_informational(interim()).is_err() {
                break;
            }
        }
        _ = respond.send_response(Response::new(()), true);
        let status = tokio::select! {
            response = response => response.expect("request task").ok().map(|response| response.status()),
            // The origin's frames leave while it is polled, and it ends with its connection.
            () = async { while origin.accept().await.is_some_and(|accepted| accepted.is_ok()) {} } => {
                return false;
            }
        };
        if count == 0 {
            return status == Some(StatusCode::OK);
        }
    }
    false
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
        let mut server_config = ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())
            .expect("server config");
        server_config.set_transport_config(transport());
        let mut client_config = ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default())
            .expect("client config");
        client_config.set_transport_config(transport());
        let (server_socket, client_socket) = MemoryDatagramSocket::pair(
            SocketAddress::local_ipv4(443),
            SocketAddress::local_ipv4(444),
            NonZeroUsize::MIN,
        );
        let server_endpoint = Endpoint::build(WeakScope::detached())
            .with_server_config(server_config)
            .with_datagram_socket(server_socket)
            .expect("server endpoint");
        let client_endpoint = Endpoint::build(WeakScope::detached())
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

async fn h3_status(source: Source, count: usize) -> Option<StatusCode> {
    let quic = QuicPair::new().await;
    let (mut origin, origin_driver) =
        h3_server::handshake(quic.server.clone(), Config::default()).expect("HTTP/3 origin");
    let origin_driver = spawn(origin_driver.run());
    let serve = spawn(async move {
        let (_request, mut response) = origin
            .accept()
            .await
            .expect("request stream")
            .resolve()
            .await
            .expect("request");
        for _ in 0..count {
            // The client refuses the stream once the limit is passed.
            if response.send_informational(interim()).await.is_err() {
                return;
            }
        }
        _ = response.send_response(Response::new(Body::empty())).await;
    });
    let connection = BoxedConnection::new(quic.client.clone());
    if matches!(source, Source::Transport) {
        connection
            .extensions()
            .insert(MaxInformationalResponses(ALLOWED));
    }
    let transport = Http3Transport {
        connection,
        config: Arc::new(Config::default()),
    };
    let client = http_connect::<_, _, Body>(
        transport,
        opening_request(Version::HTTP_3, source),
        WeakScope::detached(),
    )
    .await
    .expect("HTTP/3 client")
    .conn;
    let status = client
        .serve(request(Version::HTTP_3))
        .await
        .ok()
        .map(|response| response.status());
    _ = serve.await;
    drop(client);
    quic.close().await;
    origin_driver.abort();
    status
}

#[tokio::test(start_paused = true)]
async fn the_configured_limit_reaches_an_http1_connection() {
    timeout(LIMIT, async {
        for source in [Source::Input, Source::Transport] {
            assert_eq!(
                h1_status(source, ALLOWED).await,
                Some(StatusCode::OK),
                "{source:?}"
            );
            assert_eq!(h1_status(source, ALLOWED + 1).await, None, "{source:?}");
        }
    })
    .await
    .expect("HTTP/1 exchanges");
}

#[tokio::test(start_paused = true)]
async fn the_configured_limit_reaches_an_http2_connection() {
    timeout(LIMIT, async {
        for (source, eager) in [
            (Source::Input, false),
            (Source::Transport, false),
            (Source::Transport, true),
        ] {
            assert_eq!(
                h2_status(source, eager, ALLOWED).await,
                Some(StatusCode::OK),
                "{source:?}, eager={eager}"
            );
            assert_eq!(
                h2_status(source, eager, ALLOWED + 1).await,
                None,
                "{source:?}, eager={eager}"
            );
        }
    })
    .await
    .expect("HTTP/2 exchanges");
}

#[tokio::test(start_paused = true)]
async fn the_configured_limit_reaches_an_http3_connection() {
    timeout(LIMIT, async {
        for source in [Source::Input, Source::Transport] {
            assert_eq!(
                h3_status(source, ALLOWED).await,
                Some(StatusCode::OK),
                "{source:?}"
            );
            assert_eq!(h3_status(source, ALLOWED + 1).await, None, "{source:?}");
        }
    })
    .await
    .expect("HTTP/3 exchanges");
}

/// A connector over one prepared byte stream, with the limit set on the connector itself.
async fn connector_status(on_input: Option<usize>, count: usize) -> Option<StatusCode> {
    let (client_io, mut origin) = tokio::io::duplex(64 * 1024);
    let client_io = Mutex::new(Some(ServiceInput::new(client_io)));
    let streams = service_fn(move |input: Request| {
        let conn = client_io.lock().take();
        async move {
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: conn.expect("one connection"),
            })
        }
    });
    let connector = HttpConnector::<_, Body>::new(streams, WeakScope::detached())
        .with_max_informational_responses(ALLOWED);
    let input = request(Version::HTTP_11);
    if let Some(max) = on_input {
        input.extensions().insert(MaxInformationalResponses(max));
    }
    let client = connector.serve(input).await.expect("HTTP/1 client").conn;
    h1_exchange(&client, &mut origin, count).await
}

#[tokio::test(start_paused = true)]
async fn a_connector_limit_applies_unless_the_input_carries_its_own() {
    timeout(LIMIT, async {
        assert_eq!(connector_status(None, ALLOWED).await, Some(StatusCode::OK));
        assert_eq!(connector_status(None, ALLOWED + 1).await, None);
        assert_eq!(
            connector_status(Some(ALLOWED + 1), ALLOWED + 1).await,
            Some(StatusCode::OK)
        );
    })
    .await
    .expect("connector exchanges");
}

/// Whether an HTTP/3 connection whose budget of refused requests is `budget`, configured
/// at `source`, still serves a request after its client refused `refused` of them.
async fn h3_survives_refusals(source: BudgetSource, budget: RateBudget, refused: usize) -> bool {
    let budget = RefusedStreamBudget(Some(budget));
    let quic = QuicPair::new().await;
    let (mut origin, origin_driver) =
        h3_server::handshake(quic.server.clone(), Config::default()).expect("HTTP/3 origin");
    let origin_driver = spawn(origin_driver.run());
    let connection = BoxedConnection::new(quic.client.clone());
    connection
        .extensions()
        .insert(MaxInformationalResponses(ALLOWED));
    let input = request(Version::HTTP_3);
    match source {
        BudgetSource::Unset | BudgetSource::Connector => (),
        BudgetSource::Input => _ = input.extensions().insert(budget),
        BudgetSource::Transport { .. } => _ = connection.extensions().insert(budget),
        BudgetSource::ConnectorAndNoneOnInput => {
            input.extensions().insert(RefusedStreamBudget(None));
        }
    }
    let transport = Http3Transport {
        connection,
        config: Arc::new(Config::default()),
    };
    let client = match source {
        BudgetSource::Connector | BudgetSource::ConnectorAndNoneOnInput => {
            let transport = Mutex::new(Some(transport));
            let streams = service_fn(move |input: Request| {
                let conn = transport.lock().take();
                async move {
                    Ok::<_, ConnectionError>(EstablishedClientConnection {
                        input,
                        conn: conn.expect("one connection"),
                    })
                }
            });
            HttpConnector::<_, Body>::new(streams, WeakScope::detached())
                .with_refused_stream_budget(budget)
                .serve(input)
                .await
                .expect("HTTP/3 client of a connector")
                .conn
        }
        BudgetSource::Unset | BudgetSource::Input | BudgetSource::Transport { .. } => {
            http_connect::<_, _, Body>(transport, input, WeakScope::detached())
                .await
                .expect("HTTP/3 client")
                .conn
        }
    };
    let client = Arc::new(client);

    let mut survived = false;
    for count in repeat_n(ALLOWED + 1, refused).chain([0]) {
        let client = client.clone();
        let response = spawn(async move { client.serve(request(Version::HTTP_3)).await });
        let Ok(stream) = origin.accept().await else {
            break;
        };
        let Ok((_request, mut respond)) = stream.resolve().await else {
            break;
        };
        for _ in 0..count {
            // The client refuses the stream once the limit is passed.
            if respond.send_informational(interim()).await.is_err() {
                break;
            }
        }
        _ = respond.send_response(Response::new(Body::empty())).await;
        let status = response
            .await
            .expect("request task")
            .ok()
            .map(|response| response.status());
        survived = count == 0 && status == Some(StatusCode::OK);
    }
    drop(client);
    quic.close().await;
    origin_driver.abort();
    survived
}

#[tokio::test(start_paused = true)]
async fn the_configured_refused_stream_budget_reaches_an_http3_connection() {
    timeout(LIMIT, async {
        let budget = RateBudget::lifetime(1);
        for source in [
            BudgetSource::Input,
            BudgetSource::Transport { eager: false },
            BudgetSource::Connector,
        ] {
            assert!(h3_survives_refusals(source, budget, 1).await, "{source:?}");
            assert!(!h3_survives_refusals(source, budget, 2).await, "{source:?}");
        }
        for source in [BudgetSource::Unset, BudgetSource::ConnectorAndNoneOnInput] {
            assert!(h3_survives_refusals(source, budget, 2).await, "{source:?}");
        }
    })
    .await
    .expect("HTTP/3 exchanges");
}

#[tokio::test(start_paused = true)]
async fn the_configured_refused_stream_budget_reaches_an_http2_connection() {
    timeout(LIMIT, async {
        let budget = RateBudget::lifetime(1);
        for source in [
            BudgetSource::Input,
            BudgetSource::Transport { eager: false },
            BudgetSource::Transport { eager: true },
            BudgetSource::Connector,
        ] {
            assert!(h2_survives_refusals(source, budget, 1).await, "{source:?}");
            assert!(!h2_survives_refusals(source, budget, 2).await, "{source:?}");
        }
        for source in [BudgetSource::Unset, BudgetSource::ConnectorAndNoneOnInput] {
            assert!(h2_survives_refusals(source, budget, 2).await, "{source:?}");
        }
    })
    .await
    .expect("HTTP/2 exchanges");
}
