//! Rama's HTTP/3 over a Quinn connection, through rama's h3 transport trait, against rama's own
//! QUIC stack on the other end.
//!
//! The adapter is test-only. Quinn does not expose everything the trait asks for, so it fills
//! the gaps from what the test configures ([`Limits`]) and approximates the rest:
//! - the handshake counts as confirmed once the connection is established, and no early data
//!   is sent;
//! - the peer's bidirectional stream limit is unknown, so client priorities are not checked
//!   against it;
//! - queued datagrams are not counted and the datagram send queue reports room at once, so a
//!   closing connection does not drain datagrams and senders do not wait for room;
//! - a graceful endpoint shutdown is not held off for tunnels, and there is no h3 qlog;
//! - QPACK gets no send credit, so it encodes literals only;
//! - a stream handle sends plain connection datagrams, without the atomic check that the stream
//!   is still open;
//! - connection errors other than application closes map onto a generic transport error.

mod common;

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use parking_lot::Mutex;
use rama::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
    http::{
        Body, Request, Response,
        body::util::BodyExt,
        core::h3::{
            client,
            connection::Config,
            server,
            transport::{
                self, ClosedStream, ReadError, SendDatagramError, StoppedError, WriteError,
            },
        },
    },
    net::{address::Domain, stream::SocketInfo, tls::ApplicationProtocol},
    quic::{
        self as rq,
        proto::{Dir, Side, StreamId, TransportError, VarInt, frame::ApplicationClose},
        qlog::ConnectionQlogControl,
    },
    rt::{Executor, spawn},
    tls::{
        ProtocolVersion,
        client::{NegotiatedTlsAlgorithms, NegotiatedTlsParameters},
    },
};

use common::{identity, localhost, step};
use interop_common::scenario::SERVER_NAME;

const H3: &[u8] = b"h3";

/// Rama serves, Quinn sends the requests.
#[tokio::test]
async fn rama_h3_server_answers_h3_over_quinn() {
    let identity = identity();
    let server = rama::quic::Endpoint::bind_server(
        Executor::new(),
        h3_rama_server_config(&identity),
        localhost(),
    )
    .await
    .expect("the rama endpoint binds");
    let address = server.local_addr().expect("a local address");
    let quinn_client = quinn::Endpoint::client(localhost()).expect("the quinn endpoint binds");
    let (served, sending) = step("connect", async {
        tokio::join!(
            async {
                server
                    .accept()
                    .await
                    .expect("an attempt")
                    .await
                    .expect("accepted")
            },
            async {
                quinn_client
                    .connect_with(
                        h3_quinn_client_config(anchor(&identity)),
                        address,
                        SERVER_NAME,
                    )
                    .expect("the attempt starts")
                    .await
                    .expect("connected")
            },
        )
    })
    .await;
    round_trip(served, Quinn::new(sending, Limits::DEFAULTS)).await;
}

/// Quinn serves, rama sends the requests.
#[tokio::test]
async fn h3_over_quinn_answers_a_rama_h3_client() {
    let identity = identity();
    let quinn_server = quinn::Endpoint::server(h3_quinn_server_config(&identity), localhost())
        .expect("the quinn endpoint binds");
    let address = quinn_server.local_addr().expect("a local address");
    let client = rama::quic::Endpoint::bind_client(Executor::new(), localhost())
        .await
        .expect("the rama endpoint binds");
    let (served, sending) = step("connect", async {
        tokio::join!(
            async {
                quinn_server
                    .accept()
                    .await
                    .expect("an attempt")
                    .await
                    .expect("accepted")
            },
            async {
                client
                    .connect_with(
                        h3_rama_client_config(anchor(&identity)),
                        address,
                        SERVER_NAME,
                    )
                    .expect("the attempt starts")
                    .await
                    .expect("connected")
            },
        )
    })
    .await;
    round_trip(Quinn::new(served, Limits::DEFAULTS), sending).await;
}

async fn round_trip(served: impl transport::Connection, sending: impl transport::Connection) {
    let (mut server, server_driver) =
        server::handshake(served, Config::default()).expect("the server handshake starts");
    let (mut client, client_driver) =
        client::handshake::<Body, _>(sending, Config::default(), Executor::new())
            .expect("the client handshake starts");
    let server_driver = spawn(server_driver.run());
    let client_driver = spawn(client_driver.run());
    let serve = spawn(async move {
        for _ in 0..2 {
            let (request, response) = server
                .accept()
                .await
                .expect("a request")
                .resolve()
                .await
                .expect("its head");
            let mut reply = request.uri().request_target().to_string().into_bytes();
            reply.extend_from_slice(
                &request
                    .into_body()
                    .collect()
                    .await
                    .expect("a body")
                    .to_bytes(),
            );
            response
                .send_response(Response::new(Body::from(reply)))
                .await
                .expect("the response is sent");
        }
    });
    for path in ["/first", "/second"] {
        let response = step(
            "request",
            client.send_request(
                Request::builder()
                    .method("POST")
                    .uri(format!("https://localhost{path}"))
                    .body(Body::from(" across stacks"))
                    .expect("a request"),
            ),
        )
        .await
        .expect("a response");
        let body = step("body", response.into_body().collect())
            .await
            .expect("a body")
            .to_bytes();
        assert_eq!(body, format!("{path} across stacks"));
    }
    step("serve", serve).await.expect("the server task");
    drop(client);
    _ = step("client driver", client_driver).await;
    _ = step("server driver", server_driver).await;
}

fn anchor(
    identity: &rama::tls::server::ServerAuthData,
) -> rama::crypto::pki_types::CertificateDer<'static> {
    identity.cert_chain.last().expect("a chain").clone()
}

fn h3_rama_server_config(identity: &rama::tls::server::ServerAuthData) -> rq::ServerConfig {
    common::rama_server_config_with_alpn(identity, H3)
}

fn h3_rama_client_config(
    anchor: rama::crypto::pki_types::CertificateDer<'static>,
) -> rq::ClientConfig {
    common::rama_client_config_with_alpn(anchor, H3)
}

fn h3_quinn_server_config(identity: &rama::tls::server::ServerAuthData) -> quinn::ServerConfig {
    common::quinn_server_config_with_alpn(identity, H3)
}

fn h3_quinn_client_config(
    anchor: rama::crypto::pki_types::CertificateDer<'static>,
) -> quinn::ClientConfig {
    common::quinn_client_config_with_alpn(anchor, H3)
}

/// What the Quinn side allows and what its peer allows: Quinn has setters for these but no
/// getters, and never reports the peer's stream credit.
#[derive(Debug, Clone, Copy)]
struct Limits {
    local_bi: u64,
    local_uni: u64,
    peer_uni: u64,
    datagrams: bool,
}

impl Limits {
    /// Quinn's and rama's default transport configurations: 100 streams each way, datagrams on.
    const DEFAULTS: Self = Self {
        local_bi: 100,
        local_uni: 100,
        peer_uni: 100,
        datagrams: true,
    };
}

#[derive(Debug, Clone)]
struct Quinn {
    connection: quinn::Connection,
    extensions: Extensions,
    limits: Limits,
    accepted_bi: Arc<AtomicU64>,
    accepted_uni: Arc<AtomicU64>,
}

impl Quinn {
    fn new(connection: quinn::Connection, limits: Limits) -> Self {
        let extensions = Extensions::new();
        extensions.insert(SocketInfo::new(None, connection.remote_address().into()));
        let handshake = connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok());
        extensions.insert(NegotiatedTlsParameters {
            protocol_version: ProtocolVersion::TLSv1_3,
            application_layer_protocol: handshake
                .as_ref()
                .and_then(|data| data.protocol.as_deref())
                .map(ApplicationProtocol::from),
            peer_certificate_chain: None,
            server_name: handshake
                .as_ref()
                .and_then(|data| data.server_name.as_deref())
                .and_then(|name| Domain::try_from(name).ok()),
            resumed: None,
            algorithms: NegotiatedTlsAlgorithms::default(),
            server_hello: None,
        });
        Self {
            connection,
            extensions,
            limits,
            accepted_bi: Arc::new(AtomicU64::new(0)),
            accepted_uni: Arc::new(AtomicU64::new(0)),
        }
    }

    fn bi(&self, (send, recv): (quinn::SendStream, quinn::RecvStream)) -> (QuinnSend, QuinnRecv) {
        let recv = Arc::new(Mutex::new(recv));
        (
            QuinnSend {
                stream: Arc::new(Mutex::new(send)),
                recv: Some(recv.clone()),
                connection: self.connection.clone(),
            },
            QuinnRecv(recv),
        )
    }

    fn uni_send(&self, send: quinn::SendStream) -> QuinnSend {
        QuinnSend {
            stream: Arc::new(Mutex::new(send)),
            recv: None,
            connection: self.connection.clone(),
        }
    }
}

impl ExtensionsRef for Quinn {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl transport::Connection for Quinn {
    type SendStream = QuinnSend;
    type RecvStream = QuinnRecv;
    type CloseLease = ();

    async fn open_bi(&self) -> Result<(QuinnSend, QuinnRecv), rq::ConnectionError> {
        let pair = self.connection.open_bi().await.map_err(connection_error)?;
        Ok(self.bi(pair))
    }

    async fn open_uni(&self) -> Result<QuinnSend, rq::ConnectionError> {
        let send = self.connection.open_uni().await.map_err(connection_error)?;
        Ok(self.uni_send(send))
    }

    async fn accept_bi(&self) -> Result<(QuinnSend, QuinnRecv), rq::ConnectionError> {
        let pair = self
            .connection
            .accept_bi()
            .await
            .map_err(connection_error)?;
        self.accepted_bi.fetch_add(1, Ordering::Relaxed);
        Ok(self.bi(pair))
    }

    async fn accept_uni(&self) -> Result<QuinnRecv, rq::ConnectionError> {
        let recv = self
            .connection
            .accept_uni()
            .await
            .map_err(connection_error)?;
        self.accepted_uni.fetch_add(1, Ordering::Relaxed);
        Ok(QuinnRecv(Arc::new(Mutex::new(recv))))
    }

    fn side(&self) -> Side {
        match self.connection.side() {
            quinn::Side::Client => Side::Client,
            quinn::Side::Server => Side::Server,
        }
    }

    async fn handshake_confirmed(&self) -> Result<(), rq::ConnectionError> {
        self.connection
            .close_reason()
            .map_or(Ok(()), |error| Err(connection_error(error)))
    }

    fn is_handshake_confirmed(&self) -> bool {
        true
    }

    fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.connection.close(quinn_varint(error_code), reason);
    }

    async fn closed(&self) -> rq::ConnectionError {
        connection_error(self.connection.closed().await)
    }

    fn close_reason(&self) -> Option<rq::ConnectionError> {
        self.connection.close_reason().map(connection_error)
    }

    fn available_streams(&self, dir: Dir) -> u64 {
        match dir {
            Dir::Uni => self.limits.peer_uni,
            Dir::Bi => u64::MAX,
        }
    }

    fn max_concurrent_streams(&self, dir: Dir) -> u64 {
        match dir {
            Dir::Uni => self.limits.local_uni,
            Dir::Bi => self.limits.local_bi,
        }
    }

    fn remote_stream_limit(&self, dir: Dir) -> u64 {
        match dir {
            Dir::Uni => self.limits.local_uni + self.accepted_uni.load(Ordering::Relaxed),
            Dir::Bi => self.limits.local_bi + self.accepted_bi.load(Ordering::Relaxed),
        }
    }

    fn local_stream_limit(&self, _dir: Dir) -> u64 {
        u64::MAX
    }

    fn early_data(&self) -> transport::EarlyData {
        transport::EarlyData::Unavailable
    }

    fn qlog_control(&self) -> Option<ConnectionQlogControl> {
        None
    }

    async fn read_datagram(&self) -> Result<Bytes, rq::ConnectionError> {
        self.connection
            .read_datagram()
            .await
            .map_err(connection_error)
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    fn datagram_receive_enabled(&self) -> bool {
        self.limits.datagrams
    }

    fn received_datagrams(&self) -> usize {
        0
    }

    fn datagram_send_ready(&self) -> impl Future<Output = ()> + Send + 'static + use<> {
        std::future::ready(())
    }

    fn close_lease(&self) {}

    fn rtt(&self) -> Duration {
        self.connection.rtt()
    }
}

struct QuinnSend {
    stream: Arc<Mutex<quinn::SendStream>>,
    recv: Option<Arc<Mutex<quinn::RecvStream>>>,
    connection: quinn::Connection,
}

impl transport::SendStream for QuinnSend {
    type Handle = QuinnHandle;

    fn id(&self) -> StreamId {
        stream_id(self.stream.lock().id())
    }

    fn poll_write_chunks(
        &mut self,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
        _reserve: u64,
    ) -> Poll<Result<(), WriteError>> {
        let Some(chunk) = chunks.iter_mut().find(|chunk| !chunk.is_empty()) else {
            return Poll::Ready(Ok(()));
        };
        let mut stream = self.stream.lock();
        let written = ready!(Pin::new(&mut *stream).poll_write(cx, chunk)).map_err(write_error)?;
        _ = chunk.split_to(written);
        Poll::Ready(Ok(()))
    }

    fn try_write_generated(
        &mut self,
        _reserve: u64,
        generate: impl FnOnce(usize) -> Bytes,
    ) -> Result<(), WriteError> {
        if generate(0).is_empty() {
            Ok(())
        } else {
            Err(WriteError::Closed)
        }
    }

    fn finish(&mut self) -> Result<(), ClosedStream> {
        self.stream.lock().finish().map_err(|_| ClosedStream)
    }

    fn reset(&mut self, error_code: VarInt) -> Result<(), ClosedStream> {
        self.stream
            .lock()
            .reset(quinn_varint(error_code))
            .map_err(|_| ClosedStream)
    }

    fn set_priority(&self, priority: i32) -> Result<(), ClosedStream> {
        self.stream
            .lock()
            .set_priority(priority)
            .map_err(|_| ClosedStream)
    }

    fn stopped(
        &self,
    ) -> impl Future<Output = Result<Option<VarInt>, StoppedError>> + Send + Sync + 'static + use<>
    {
        let stopped = self.stream.lock().stopped();
        async move {
            match stopped.await {
                Ok(code) => Ok(code.map(rama_varint)),
                Err(quinn::StoppedError::ConnectionLost(error)) => {
                    Err(StoppedError::ConnectionLost(connection_error(error)))
                }
                Err(_) => Err(StoppedError::ZeroRttRejected),
            }
        }
    }

    fn handle(&self) -> QuinnHandle {
        QuinnHandle {
            send: self.stream.clone(),
            recv: self.recv.clone(),
            connection: self.connection.clone(),
        }
    }
}

struct QuinnRecv(Arc<Mutex<quinn::RecvStream>>);

impl transport::RecvStream for QuinnRecv {
    fn id(&self) -> StreamId {
        stream_id(self.0.lock().id())
    }

    fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max_length: usize,
    ) -> Poll<Result<Option<Bytes>, ReadError>> {
        let mut buf = vec![0; max_length];
        let read = ready!(self.0.lock().poll_read(cx, &mut buf)).map_err(read_error)?;
        if read == 0 {
            return Poll::Ready(Ok(None));
        }
        buf.truncate(read);
        Poll::Ready(Ok(Some(Bytes::from(buf))))
    }

    fn stop(&mut self, error_code: VarInt) -> Result<(), ClosedStream> {
        self.0
            .lock()
            .stop(quinn_varint(error_code))
            .map_err(|_| ClosedStream)
    }

    fn is_0rtt(&self) -> bool {
        self.0.lock().is_0rtt()
    }
}

struct QuinnHandle {
    send: Arc<Mutex<quinn::SendStream>>,
    recv: Option<Arc<Mutex<quinn::RecvStream>>>,
    connection: quinn::Connection,
}

impl transport::StreamHandle for QuinnHandle {
    fn abort(&self, error_code: VarInt) {
        _ = self.send.lock().reset(quinn_varint(error_code));
        if let Some(recv) = &self.recv {
            _ = recv.lock().stop(quinn_varint(error_code));
        }
    }

    fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError> {
        self.connection.send_datagram(data).map_err(datagram_error)
    }

    fn try_send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError> {
        self.send_datagram(data)
    }
}

fn quinn_varint(value: VarInt) -> quinn::VarInt {
    quinn::VarInt::from_u64(value.into_inner()).expect("a QUIC varint fits a QUIC varint")
}

fn rama_varint(value: quinn::VarInt) -> VarInt {
    VarInt::from_u64(value.into_inner()).expect("a QUIC varint fits a QUIC varint")
}

fn stream_id(id: quinn::StreamId) -> StreamId {
    StreamId::from(rama_varint(quinn::VarInt::from(id)))
}

fn connection_error(error: quinn::ConnectionError) -> rq::ConnectionError {
    match error {
        quinn::ConnectionError::ApplicationClosed(close) => {
            rq::ConnectionError::ApplicationClosed(ApplicationClose {
                error_code: rama_varint(close.error_code),
                reason: close.reason,
            })
        }
        quinn::ConnectionError::Reset => rq::ConnectionError::Reset,
        quinn::ConnectionError::TimedOut => rq::ConnectionError::TimedOut,
        quinn::ConnectionError::LocallyClosed => rq::ConnectionError::LocallyClosed,
        quinn::ConnectionError::CidsExhausted => rq::ConnectionError::CidsExhausted,
        other => rq::ConnectionError::TransportError(TransportError::PROTOCOL_VIOLATION(
            other.to_string(),
        )),
    }
}

fn write_error(error: quinn::WriteError) -> WriteError {
    match error {
        quinn::WriteError::Stopped(code) => WriteError::Stopped(rama_varint(code)),
        quinn::WriteError::ConnectionLost(error) => {
            WriteError::ConnectionLost(connection_error(error))
        }
        _ => WriteError::Closed,
    }
}

fn read_error(error: quinn::ReadError) -> ReadError {
    match error {
        quinn::ReadError::Reset(code) => ReadError::Reset(rama_varint(code)),
        quinn::ReadError::ConnectionLost(error) => {
            ReadError::ConnectionLost(connection_error(error))
        }
        _ => ReadError::Closed,
    }
}

fn datagram_error(error: quinn::SendDatagramError) -> SendDatagramError {
    match error {
        quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled => {
            SendDatagramError::Unavailable
        }
        quinn::SendDatagramError::TooLarge => SendDatagramError::TooLarge,
        quinn::SendDatagramError::ConnectionLost(_) => SendDatagramError::Closed,
    }
}
