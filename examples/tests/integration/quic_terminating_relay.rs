//! End-to-end tests for the `quic_terminating_relay` example.
//!
//! The example runs as its own process. A real QUIC client connects to it and a real QUIC
//! origin answers upstream, so every assertion is a network outcome or the process's own
//! lifecycle. Nothing here calls into the example's code.

use super::utils;

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rama::{
    crypto::{
        pem::PemEncode as _,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    },
    error::BoxError,
    net::tls::ApplicationProtocol,
    quic::{
        ClientConfig, Connection, ConnectionError, Endpoint, ReadError, ReadToEndError, RecvStream,
        SendStream, ServerConfig, TransportConfig, WriteError, proto::VarInt, tls::TlsOptions,
    },
    rt::{Executor, spawn},
    tls::{
        client::TlsClientConfig,
        server::{ServerAuthData, TlsServerConfig},
    },
    utils::{collections::smallvec::smallvec, fs::TempDir, fs::tempdir, octets},
};

/// The protocol the example speaks.
const ALPN: &[u8] = b"rama-quic/relay";
/// Every wait is bounded; a relay that never answers fails a test rather than hanging it.
const LIMIT: Duration = Duration::from_secs(20);
/// What a prompt end is allowed to take. Far above what cancellation needs and well inside
/// `IDLE`, so an idle timeout cannot stand in for it.
const PROMPTLY: Duration = Duration::from_secs(2);
/// Long enough that nothing here ends by timing out.
const IDLE: Duration = Duration::from_secs(60);
/// How long the example is given to report the address it bound.
const STARTUP: Duration = Duration::from_secs(30);
const READ_CAP: usize = octets::kib(64);
/// The code the example gives either peer when it ends a stream for them.
const RELAY_CANCELLED: u32 = 1;
/// The codes the client and the origin use when they give up on a direction.
const RELAY_STOPPING: u32 = 4;
const CLIENT_STOPPED: u32 = 9;
const ORIGIN_STOPPED: u32 = 11;
/// The codes the example closes a client connection with when its upstream fails it.
const UPSTREAM_UNAVAILABLE: u32 = 2;
const UPSTREAM_GONE: u32 = 3;
/// The window the origin advertises in the blocked-write case, small enough that the relay's
/// upstream write stops almost at once.
const SMALL_WINDOW: u32 = octets::kib_u32(16);
/// More than the relay's own default receive window, so once the relay stops reading the
/// client's write stalls too. That stall is what shows the relay is inside its write.
const TOO_MUCH: usize = octets::mib(8);

/// One self-signed identity, on disk for the example to read and in memory for this side.
struct Identity {
    certificate: PathBuf,
    key: PathBuf,
    anchor: CertificateDer<'static>,
}

impl Identity {
    fn generate(directory: &TempDir, name: &str) -> Self {
        let generated =
            ServerAuthData::new_self_signed_leaf(rama::tls::server::LeafCertRequest::default())
                .expect("an identity is generated");
        let certificate = directory.path().join(format!("{name}-cert.pem"));
        let key = directory.path().join(format!("{name}-key.pem"));
        fs::write(&certificate, generated.cert_chain[0].to_pem())
            .expect("the certificate is written");
        fs::write(&key, generated.private_key.to_pem()).expect("the key is written");
        let anchor = CertificateDer::from_pem_file(&certificate).expect("it reads back");
        Self {
            certificate,
            key,
            anchor,
        }
    }
}

fn transport(window: Option<u32>, bidi: Option<u32>) -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.set_max_idle_timeout(IDLE.try_into().expect("a usable idle timeout"));
    if let Some(window) = window {
        transport.set_stream_receive_window(VarInt::from(window));
        transport.set_receive_window(VarInt::from(window));
    }
    if let Some(bidi) = bidi {
        transport.set_max_concurrent_bidi_streams(VarInt::from(bidi));
    }
    Arc::new(transport)
}

fn serving(identity: &Identity, window: Option<u32>, bidi: Option<u32>) -> ServerConfig {
    let auth = ServerAuthData {
        cert_chain: vec![CertificateDer::from_pem_file(&identity.certificate).expect("a chain")],
        private_key: PrivateKeyDer::from_pem_file(&identity.key).expect("a key"),
        ocsp: None,
    };
    let tls = TlsServerConfig::new()
        .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
        .with_server_auth(auth);
    let mut config =
        ServerConfig::try_from_rama_tls(&tls, TlsOptions::default()).expect("a server config");
    config.set_transport_config(transport(window, bidi));
    config
}

fn connecting(anchor: CertificateDer<'static>) -> ClientConfig {
    let tls = TlsClientConfig::new()
        .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
        .try_with_server_trust_anchors([anchor])
        .expect("the anchor is accepted");
    let mut config =
        ClientConfig::try_from_rama_tls(&tls, TlsOptions::default()).expect("a client config");
    config.set_transport_config(transport(None, None));
    config
}

fn localhost() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)
}

/// A loopback socket held for the test's lifetime, so nothing else takes its address. Used as
/// an upstream that never answers.
fn reserved() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind(localhost()).expect("a reserved socket");
    let address = socket.local_addr().expect("its address");
    (socket, address)
}

/// The example process, a client that trusts it, and the origin it relays to.
struct Relay {
    _directory: TempDir,
    /// Held for the test's lifetime where the upstream is meant to be unreachable, so its
    /// address cannot be taken by something else mid-test.
    _unreachable: Option<UdpSocket>,
    process: utils::ExampleRunner,
    client: Endpoint,
    client_config: ClientConfig,
    address: SocketAddr,
    origin: Option<Endpoint>,
    gate: Option<PacketGate>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("{}", self.process.said());
        }
    }
}

impl Relay {
    /// Start an origin, then the example pointed at it.
    async fn new(streams: usize, origin_window: Option<u32>) -> Self {
        Self::start(streams, origin_window, true, None, false).await
    }

    /// Start the example pointed at an address nothing is listening on.
    async fn without_an_origin() -> Self {
        Self::start(1, None, false, None, false).await
    }

    /// The same, with an origin that grants no stream credit, so the relay's upstream open
    /// stays pending however long a client waits.
    async fn without_stream_credit() -> Self {
        Self::start(1, None, true, Some(0), false).await
    }

    async fn start(
        streams: usize,
        origin_window: Option<u32>,
        with_origin: bool,
        origin_streams: Option<u32>,
        gate_packets: bool,
    ) -> Self {
        let directory = tempdir().expect("a directory for the identities");
        let relay_identity = Identity::generate(&directory, "relay");
        let origin_identity = Identity::generate(&directory, "origin");

        let (origin, origin_address, unreachable) = if with_origin {
            let origin = Endpoint::build(Executor::new())
                .with_server_config(serving(&origin_identity, origin_window, origin_streams))
                .bind_address(localhost())
                .await
                .expect("the origin binds");
            let address = origin.local_addr().expect("its address");
            (Some(origin), address, None)
        } else {
            let (held, address) = reserved();
            (None, address, Some(held))
        };

        let gate = if gate_packets {
            Some(PacketGate::new(origin_address).await)
        } else {
            None
        };
        let origin_address = gate.as_ref().map_or(origin_address, |gate| gate.address);

        // Port 0: the example binds and reports what it got, so no address is chosen here and
        // released for something else to take.
        let mut process = utils::ExampleRunner::capturing(
            "quic_terminating_relay",
            None,
            [
                "--listen".to_owned(),
                localhost().to_string(),
                "--upstream".to_owned(),
                origin_address.to_string(),
                "--upstream-ca".to_owned(),
                origin_identity.certificate.display().to_string(),
                "--cert".to_owned(),
                relay_identity.certificate.display().to_string(),
                "--key".to_owned(),
                relay_identity.key.display().to_string(),
                "--max-streams".to_owned(),
                streams.to_string(),
            ],
        );

        let announced = process.wait_for_line("relay: listening on", STARTUP).await;
        let address = listening_address(&announced);

        let client = Endpoint::build(Executor::new())
            .bind_address(localhost())
            .await
            .expect("the client binds");
        let client_config = connecting(relay_identity.anchor.clone());
        Self {
            _directory: directory,
            _unreachable: unreachable,
            process,
            client,
            client_config,
            address,
            origin,
            gate,
        }
    }

    async fn connect_once(&self) -> Result<Connection, BoxError> {
        self.connect_once_with(self.client_config.clone()).await
    }

    async fn connect_once_with(&self, config: ClientConfig) -> Result<Connection, BoxError> {
        Ok(self
            .client
            .connect_with(config, self.address, "localhost")?
            .await?)
    }

    /// The same, with this side advertising `window`, so a writer towards it blocks.
    async fn connect_with_window(&self, window: Option<u32>) -> Connection {
        let mut config = self.client_config.clone();
        config.set_transport_config(transport(window, None));
        tokio::time::timeout(LIMIT, self.connect_once_with(config))
            .await
            .unwrap_or_else(|_| panic!("the relay did not answer on {}", self.address))
            .expect("the handshake completed")
    }

    /// The scenario's client connection. The relay has already reported its address, so one
    /// attempt is enough and a failure is reported rather than retried over.
    async fn connect(&self) -> Connection {
        tokio::time::timeout(LIMIT, self.connect_once())
            .await
            .unwrap_or_else(|_| panic!("the relay did not answer on {}", self.address))
            .expect("the handshake completed")
    }

    /// The upstream connection the relay opens for a client connection.
    async fn upstream(&self) -> Connection {
        let origin = self.origin.as_ref().expect("this relay has an origin");
        tokio::time::timeout(LIMIT, async {
            origin
                .accept()
                .await
                .expect("the relay opened an upstream connection")
                .await
                .expect("its handshake completed")
        })
        .await
        .expect("the relay reached the origin")
    }
}

/// Accept the stream the relay opens upstream for a client stream.
async fn upstream_stream(upstream: &Connection) -> (SendStream, RecvStream) {
    tokio::time::timeout(LIMIT, upstream.accept_bi())
        .await
        .expect("the relay opened an upstream stream")
        .expect("it arrived")
}

/// A request the client finishes, the answer the origin sends back, and the exact bytes both
/// ways.
#[tokio::test]
#[ignore]
async fn a_relayed_request_is_answered_over_a_half_closed_stream() {
    utils::init_tracing();
    let relay = Relay::new(1, None).await;
    let connection = relay.connect().await;
    let upstream = relay.upstream().await;

    let (mut send, mut recv) = connection.open_bi().await.expect("a bi stream");
    send.write_all(b"how are you").await.expect("it is written");
    send.finish().expect("the request ends");

    let (mut answering, mut asked) = upstream_stream(&upstream).await;
    let question = tokio::time::timeout(LIMIT, asked.read_to_end(READ_CAP))
        .await
        .expect("the request reached the origin")
        .expect("it completed");
    assert_eq!(
        question, b"how are you",
        "the origin got the request whole, ended by the client"
    );
    answering
        .write_all(b"i am quite well")
        .await
        .expect("the answer is written");
    answering.finish().expect("the answer ends");

    let answer = tokio::time::timeout(LIMIT, recv.read_to_end(READ_CAP))
        .await
        .expect("the answer came back")
        .expect("it completed");
    assert_eq!(answer, b"i am quite well", "and the client got those bytes");
    connection.close(0u32, b"done");
}

/// The client resets its request. The origin sees its own stream ended rather than left open.
#[tokio::test]
#[ignore]
async fn a_client_reset_reaches_the_origin() {
    utils::init_tracing();
    let relay = Relay::new(1, None).await;
    let connection = relay.connect().await;
    let upstream = relay.upstream().await;

    let (mut send, _recv) = connection.open_bi().await.expect("a bi stream");
    send.write_all(b"begin").await.expect("it is written");
    let (_answering, mut asked) = upstream_stream(&upstream).await;
    let mut taken = [0u8; 8];
    tokio::time::timeout(LIMIT, asked.read(&mut taken))
        .await
        .expect("the start reached the origin")
        .expect("it read");

    send.reset(VarInt::from(7u32)).expect("the client resets");
    let ended = tokio::time::timeout(PROMPTLY, asked.read_to_end(READ_CAP))
        .await
        .expect("the origin was told promptly")
        .expect_err("a reset stream does not complete");
    assert!(
        matches!(
            ended,
            ReadToEndError::Read(ReadError::Reset(code)) if code == VarInt::from(RELAY_CANCELLED)
        ),
        "the origin's end was reset with the relay's own code: {ended:?}"
    );
    connection.close(0u32, b"done");
}

/// The client stops reading while the origin sends nothing, so the relay's copy towards the
/// client is waiting on an idle source. The origin must still be told.
#[tokio::test]
#[ignore]
async fn a_client_stop_reaches_the_origin_with_an_idle_source() {
    utils::init_tracing();
    let relay = Relay::new(1, None).await;
    let connection = relay.connect().await;
    let upstream = relay.upstream().await;

    let (mut send, mut recv) = connection.open_bi().await.expect("a bi stream");
    send.write_all(b"begin").await.expect("it is written");
    let (answering, mut asked) = upstream_stream(&upstream).await;
    let mut taken = [0u8; 8];
    tokio::time::timeout(LIMIT, asked.read(&mut taken))
        .await
        .expect("the start reached the origin")
        .expect("it read");

    // The origin has sent nothing, so the relay is parked on it.
    recv.stop(VarInt::from(9u32)).expect("the client stops");
    let told = tokio::time::timeout(PROMPTLY, answering.stopped())
        .await
        .expect("the origin was told promptly")
        .expect("the stream ended cleanly enough to say so");
    assert_eq!(
        told,
        Some(VarInt::from(RELAY_CANCELLED)),
        "the origin's send was stopped with the relay's own code"
    );
    connection.close(0u32, b"done");
}

/// The relay's upstream write is blocked by the origin's flow control when the client fails
/// the other direction. The blocked direction itself must be cancelled.
///
/// Nothing reads the origin's receiver here: reading it would return flow-control credit and
/// let the blocked write continue. What is observed instead is the client's own send, which
/// the relay stops only if it noticed the cancellation from inside its write.
#[tokio::test]
#[ignore]
async fn a_blocked_upstream_write_is_cancelled() {
    utils::init_tracing();
    let relay = Relay::new(1, Some(SMALL_WINDOW)).await;
    let connection = relay.connect().await;
    let upstream = relay.upstream().await;

    let (mut send, mut recv) = connection.open_bi().await.expect("a bi stream");
    send.write_all(b"begin").await.expect("it is written");
    // Accepted and held, never read, so the origin's window fills and stays full.
    let held = upstream_stream(&upstream).await;

    let mut writing = spawn(async move {
        let big = vec![0x5au8; TOO_MUCH];
        send.write_all(&big).await
    });
    assert!(
        tokio::time::timeout(PROMPTLY, &mut writing).await.is_err(),
        "the client's write stalled, so the relay is not reading from it"
    );

    // The other direction fails while this one is stuck writing.
    recv.stop(VarInt::from(CLIENT_STOPPED))
        .expect("the client stops reading");

    // The blocked direction, observed without touching the origin's receiver: the relay stops
    // the client's send with its own code.
    let cancelled = tokio::time::timeout(PROMPTLY, writing)
        .await
        .expect("the blocked direction was given up promptly")
        .expect("the writing task did not panic")
        .expect_err("a cancelled write does not complete");
    assert!(
        matches!(cancelled, WriteError::Stopped(code) if code == VarInt::from(RELAY_CANCELLED)),
        "the relay stopped the client's send with its own code: {cancelled:?}"
    );

    // Only now is the origin's end looked at, and the permit is reusable.
    drop(held);
    carries_another_stream(&connection, &upstream).await;
    connection.close(0u32, b"done");
}

/// The mirror: the client stops reading, so the relay's downstream write blocks, and the
/// origin then fails the other direction. The origin's own send is stopped by the relay.
#[tokio::test]
#[ignore]
async fn a_blocked_downstream_write_is_cancelled() {
    utils::init_tracing();
    // The client is the one advertising the small window this time.
    let relay = Relay::new(1, None).await;
    let connection = relay.connect_with_window(Some(SMALL_WINDOW)).await;
    let upstream = relay.upstream().await;

    let (mut send, held_recv) = connection.open_bi().await.expect("a bi stream");
    send.write_all(b"begin").await.expect("it is written");
    let (mut answering, mut asked) = upstream_stream(&upstream).await;
    let mut taken = [0u8; 8];
    tokio::time::timeout(LIMIT, asked.read(&mut taken))
        .await
        .expect("the start reached the origin")
        .expect("it read");

    // The origin floods towards a client that never reads, so the relay's downstream write
    // blocks. Nothing reads `held_recv`.
    let mut answering_all = spawn(async move {
        let big = vec![0x5au8; TOO_MUCH];
        answering.write_all(&big).await
    });
    assert!(
        tokio::time::timeout(PROMPTLY, &mut answering_all)
            .await
            .is_err(),
        "the origin's write stalled, so the relay is not reading from it"
    );

    // The origin gives up on the other direction while this one is stuck writing.
    asked
        .stop(VarInt::from(ORIGIN_STOPPED))
        .expect("the origin stops reading");

    let cancelled = tokio::time::timeout(PROMPTLY, answering_all)
        .await
        .expect("the blocked direction was given up promptly")
        .expect("the writing task did not panic")
        .expect_err("a cancelled write does not complete");
    assert!(
        matches!(cancelled, WriteError::Stopped(code) if code == VarInt::from(RELAY_CANCELLED)),
        "the relay stopped the origin's send with its own code: {cancelled:?}"
    );
    drop(held_recv);
    connection.close(0u32, b"done");
}

/// One more stream over the same pair, carried end to end. With a limit of one relayed stream,
/// this only works if the previous stream released its permit.
async fn carries_another_stream(connection: &Connection, upstream: &Connection) {
    let (mut again, mut answer) = connection.open_bi().await.expect("another bi stream");
    again.write_all(b"again").await.expect("it is written");
    again.finish().expect("the request ends");
    let (mut serving, mut got) = upstream_stream(upstream).await;
    let question = tokio::time::timeout(LIMIT, got.read_to_end(READ_CAP))
        .await
        .expect("the next stream was carried, so the permit came back")
        .expect("it completed");
    assert_eq!(question, b"again");
    serving.write_all(b"second").await.expect("written");
    serving.finish().expect("the answer ends");
    let back = tokio::time::timeout(LIMIT, answer.read_to_end(READ_CAP))
        .await
        .expect("the answer came back")
        .expect("it completed");
    assert_eq!(back, b"second", "the connection is still healthy");
}

/// A relay whose origin is unreachable closes the client connection rather than accepting
/// streams it cannot serve, and says so with its own code and reason.
#[tokio::test]
#[ignore]
async fn an_unreachable_origin_ends_the_client_connection() {
    utils::init_tracing();
    let relay = Relay::without_an_origin().await;
    let connection = relay.connect().await;
    let ended = tokio::time::timeout(LIMIT, connection.closed())
        .await
        .expect("the client was told rather than left waiting");
    let ConnectionError::ApplicationClosed(close) = &ended else {
        panic!("the relay closed the connection itself, rather than it failing: {ended:?}");
    };
    assert_eq!(
        close.error_code(),
        VarInt::from(UPSTREAM_UNAVAILABLE),
        "with the code for an upstream it could not reach"
    );
    assert_eq!(
        close.reason(),
        &b"upstream unavailable"[..],
        "and that reason"
    );
}

/// An origin that goes away ends the client connection it was carrying, with the relay's own
/// code and reason rather than a timeout or a transport failure.
#[tokio::test]
#[ignore]
async fn an_origin_that_closes_ends_the_client_connection() {
    utils::init_tracing();
    let relay = Relay::new(1, None).await;
    let connection = relay.connect().await;
    let upstream = relay.upstream().await;

    upstream.close(0u32, b"origin going away");
    let ended = tokio::time::timeout(LIMIT, connection.closed())
        .await
        .expect("the client connection ended with its upstream");
    let ConnectionError::ApplicationClosed(close) = &ended else {
        panic!("the relay closed the connection itself: {ended:?}");
    };
    assert_eq!(
        close.error_code(),
        VarInt::from(UPSTREAM_GONE),
        "with the code for an upstream that went away"
    );
    assert_eq!(close.reason(), &b"upstream closed"[..], "and that reason");
}

/// An origin that grants no stream credit leaves the relay waiting inside its upstream open.
/// The client then leaves, and the relay has to notice from there: it releases the upstream
/// promptly and keeps serving.
#[tokio::test]
#[ignore]
async fn a_client_that_leaves_releases_a_stream_waiting_on_upstream_credit() {
    utils::init_tracing();
    let relay = Relay::without_stream_credit().await;
    let connection = relay.connect().await;
    let upstream = relay.upstream().await;

    // The relay opens a stream upstream for this one and waits: there is no credit for it.
    let (mut send, _recv) = connection.open_bi().await.expect("a bi stream");
    send.write_all(b"waiting").await.expect("it is written");
    assert!(
        tokio::time::timeout(PROMPTLY, upstream.accept_bi())
            .await
            .is_err(),
        "the origin granted no stream credit, so no upstream stream arrives"
    );

    // The client leaves while that open is still pending.
    connection.close(0u32, b"leaving");

    let ended = tokio::time::timeout(PROMPTLY, upstream.closed())
        .await
        .expect("the relay released the upstream promptly");
    assert!(
        matches!(&ended, ConnectionError::ApplicationClosed(close) if close.error_code() == VarInt::from(0u32)),
        "the relay closed the upstream itself: {ended:?}"
    );

    // And it is still serving: another client gets its own upstream connection.
    let again = relay.connect().await;
    let upstream_again = relay.upstream().await;
    again.close(0u32, b"done");
    tokio::time::timeout(PROMPTLY, upstream_again.closed())
        .await
        .expect("the second upstream was released too");
}

/// Asking the relay to stop, the way a person would, while a connection and a stream are live.
/// Its peers are told, and the process exits on its own.
#[tokio::test]
#[ignore]
async fn an_interrupted_relay_stops_its_peers_and_exits() {
    utils::init_tracing();
    let mut relay = Relay::new(1, None).await;
    let connection = relay.connect().await;
    let upstream = relay.upstream().await;

    // A stream in flight, carried both ways, so nothing below is about an idle relay.
    let (mut send, mut recv) = connection.open_bi().await.expect("a bi stream");
    send.write_all(b"live").await.expect("it is written");
    let (mut answering, mut asked) = upstream_stream(&upstream).await;
    let mut taken = [0u8; 8];
    tokio::time::timeout(LIMIT, asked.read(&mut taken))
        .await
        .expect("the stream reached the origin")
        .expect("it read");
    answering.write_all(b"back").await.expect("written");
    tokio::time::timeout(LIMIT, recv.read(&mut taken))
        .await
        .expect("the answer reached the client")
        .expect("it read");

    // Asked to stop, and reaped within the bound.
    let status = relay
        .process
        .interrupt_within(Duration::from_secs(20))
        .await;
    assert!(
        status.success(),
        "the relay exited on its own after being asked to stop: {status}"
    );

    // Both peers are told, rather than left to time out: a stopping endpoint closes its
    // connections itself, so each peer reads an application close and not a transport failure.
    let told = tokio::time::timeout(LIMIT, connection.closed())
        .await
        .expect("the client connection ended with the relay");
    assert!(
        matches!(&told, ConnectionError::ApplicationClosed(close) if close.error_code() == VarInt::from(RELAY_STOPPING)),
        "the client was told the relay closed: {told:?}"
    );
    let told = tokio::time::timeout(LIMIT, upstream.closed())
        .await
        .expect("the upstream connection ended with the relay");
    assert!(
        matches!(&told, ConnectionError::ApplicationClosed(close) if close.error_code() == VarInt::from(RELAY_STOPPING)),
        "the origin was told the relay closed: {told:?}"
    );
}

/// A stream permit is released when its stream ends, so the next stream is carried even with
/// a limit of one.
#[tokio::test]
#[ignore]
async fn a_stream_permit_is_released_after_a_cancelled_stream() {
    utils::init_tracing();
    let relay = Relay::new(1, None).await;
    let connection = relay.connect().await;
    let upstream = relay.upstream().await;

    let (mut send, _recv) = connection.open_bi().await.expect("a bi stream");
    send.write_all(b"begin").await.expect("it is written");
    let (_answering, mut asked) = upstream_stream(&upstream).await;
    let mut taken = [0u8; 8];
    tokio::time::timeout(LIMIT, asked.read(&mut taken))
        .await
        .expect("the start reached the origin")
        .expect("it read");
    send.reset(VarInt::from(7u32)).expect("the client resets");
    let ended = tokio::time::timeout(PROMPTLY, asked.read_to_end(READ_CAP))
        .await
        .expect("the origin was told")
        .expect_err("a reset stream does not complete");
    assert!(
        matches!(
            ended,
            ReadToEndError::Read(ReadError::Reset(code)) if code == VarInt::from(RELAY_CANCELLED)
        ),
        "the origin's end was reset with the relay's own code: {ended:?}"
    );

    carries_another_stream(&connection, &upstream).await;
    connection.close(0u32, b"done");
}

/// The address out of the example's own listening line.
fn listening_address(line: &str) -> SocketAddr {
    let after = line
        .split("relay: listening on ")
        .nth(1)
        .unwrap_or_else(|| panic!("a listening line with an address: {line}"));
    after
        .split(',')
        .next()
        .and_then(|address| address.trim().parse().ok())
        .unwrap_or_else(|| panic!("an address in: {line}"))
}

/// A UDP hop that can withhold relay-to-origin packets while continuing to carry the
/// origin's STOP_SENDING back. It never alters a packet or relies on its encrypted contents.
struct PacketGate {
    address: SocketAddr,
    paused: Arc<AtomicBool>,
    withheld: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl PacketGate {
    async fn new(origin: SocketAddr) -> Self {
        let socket = tokio::net::UdpSocket::bind(localhost()).await.unwrap();
        let address = socket.local_addr().unwrap();
        let paused = Arc::new(AtomicBool::new(false));
        let withheld = Arc::new(tokio::sync::Notify::new());
        let task = spawn({
            let paused = paused.clone();
            let withheld = withheld.clone();
            async move {
                let mut relay = None;
                let mut buffer = vec![0; 65536];
                loop {
                    let (len, from) = socket.recv_from(&mut buffer).await.unwrap();
                    let destination = if from == origin {
                        relay.expect("the relay sent the first packet")
                    } else {
                        relay = Some(from);
                        if paused.load(Ordering::Acquire) {
                            withheld.notify_one();
                            continue;
                        }
                        origin
                    };
                    socket.send_to(&buffer[..len], destination).await.unwrap();
                }
            }
        });
        Self {
            address,
            paused,
            withheld,
            task,
        }
    }
}

impl Drop for PacketGate {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
#[ignore]
async fn a_reset_cancels_a_request_waiting_on_upstream_credit() {
    cancelled_while_waiting_for_credit(true).await;
}

#[tokio::test]
#[ignore]
async fn a_stop_cancels_a_request_waiting_on_upstream_credit() {
    cancelled_while_waiting_for_credit(false).await;
}

async fn cancelled_while_waiting_for_credit(reset: bool) {
    utils::init_tracing();
    let relay = Relay::without_stream_credit().await;
    let connection = relay.connect().await;
    let upstream = relay.upstream().await;
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(b"abandoned").await.unwrap();
    tokio::time::timeout(Duration::from_millis(100), upstream.accept_bi())
        .await
        .expect_err("the relay must wait for upstream stream credit");
    if reset {
        send.reset(7u32).unwrap();
        let error = tokio::time::timeout(PROMPTLY, recv.read_to_end(READ_CAP))
            .await
            .expect("a queued request reset is noticed promptly")
            .unwrap_err();
        assert!(
            matches!(error, ReadToEndError::Read(ReadError::Reset(code)) if code == VarInt::from(RELAY_CANCELLED))
        );
    } else {
        recv.stop(CLIENT_STOPPED).unwrap();
        assert_eq!(
            tokio::time::timeout(PROMPTLY, send.stopped())
                .await
                .expect("a queued response stop is noticed promptly")
                .unwrap(),
            Some(RELAY_CANCELLED.into())
        );
    }
    // Grant exactly one stream: a stale open for the abandoned request would consume it.
    upstream.set_max_concurrent_bi_streams(1u32);
    carries_another_stream(&connection, &upstream).await;
    connection.close(0u32, b"done");
}

/// The request FIN has left the relay but is withheld before the origin. A stop at this
/// point is meaningful: the FIN cannot have been acknowledged. The idle response must be
/// cancelled too, and its permit must become available again.
#[tokio::test]
#[ignore]
async fn a_stop_after_forwarding_fin_cancels_the_idle_response() {
    utils::init_tracing();
    let relay = Relay::start(1, None, true, None, true).await;
    let connection = relay.connect().await;
    let upstream = relay.upstream().await;
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(b"begin").await.unwrap();
    let (_answering, mut asked) = upstream_stream(&upstream).await;
    let mut prefix = [0; 5];
    tokio::time::timeout(LIMIT, asked.read_exact(&mut prefix))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&prefix, b"begin");
    // Let the prefix and handshake ACKs settle before closing the gate. Once closed, the
    // only new application work is FIN, and the origin cannot acknowledge that packet.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let gate = relay.gate.as_ref().unwrap();
    gate.paused.store(true, Ordering::Release);
    send.finish().unwrap();
    tokio::time::timeout(PROMPTLY, gate.withheld.notified())
        .await
        .expect("the relay tried to forward the request FIN");
    asked.stop(ORIGIN_STOPPED).unwrap();
    let error = tokio::time::timeout(PROMPTLY, recv.read_to_end(READ_CAP))
        .await
        .expect("the unacknowledged FIN still observes a stop")
        .unwrap_err();
    assert!(
        matches!(error, ReadToEndError::Read(ReadError::Reset(code)) if code == VarInt::from(RELAY_CANCELLED))
    );
    gate.paused.store(false, Ordering::Release);
    carries_another_stream(&connection, &upstream).await;
    connection.close(0u32, b"done");
}
