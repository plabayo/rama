//! What the quiche interoperability tests need: identities on disk for a peer that reads PEM
//! files, the two stacks' configurations, and a hand-driven loop for a library that owns neither
//! sockets nor timers.
//!
//! Two limits of the driver, both fine for the scenarios here and both to lift before the MTU,
//! pacing and loss matrix: datagrams are read and written through a 1350-byte buffer, so a peer
//! that raises its MTU needs that raised with it; and `SendInfo::at`, the moment quiche asks a
//! datagram to leave, is ignored, so nothing here is paced.

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use rama::{
    crypto::{dep::rcgen, pki_types::PrivatePkcs8KeyDer},
    net::tls::ApplicationProtocol,
    quic::{ClientConfig, Connection, Endpoint, ServerConfig, tls::TlsOptions},
    tls::{
        client::TlsClientConfig,
        server::{ServerAuthData, TlsServerConfig},
    },
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{net::UdpSocket, time::Instant};

pub const ALPN: &[u8] = b"rama-quiche-interop";
/// How long a whole scenario may take. Every await inside one shares this deadline, so a stall
/// anywhere fails the test instead of extending it.
pub const LIMIT: Duration = Duration::from_secs(20);
/// Scratch for one datagram. Larger than the path MTU these tests use; a scenario that raises
/// the MTU has to raise this with it.
const DATAGRAM: usize = 1350;

/// The moment a scenario must be finished by. Passed to every operation that waits.
#[derive(Clone, Copy)]
pub struct Deadline(Instant);

impl Deadline {
    pub fn new() -> Self {
        Self(Instant::now() + LIMIT)
    }

    /// A deadline of the caller's own length, for a scenario that is about waiting.
    pub fn of(limit: Duration) -> Self {
        Self(Instant::now() + limit)
    }

    /// Wait for one future, or fail saying what was being waited for.
    pub async fn wait<F: Future>(&self, what: &str, future: F) -> F::Output {
        match tokio::time::timeout_at(self.0, future).await {
            Ok(value) => value,
            Err(_) => panic!("{what}: the scenario's {LIMIT:?} ran out"),
        }
    }

    fn passed(&self) -> bool {
        Instant::now() >= self.0
    }

    /// The soonest of this deadline and a timer the connection asked for.
    fn next_wake(&self, timer: Option<Duration>) -> Instant {
        match timer {
            Some(timer) => self
                .0
                .min(Instant::now() + timer.max(Duration::from_millis(1))),
            None => self.0.min(Instant::now() + Duration::from_millis(5)),
        }
    }

    fn expect(&self, what: &str) {
        assert!(!self.passed(), "{what}: the scenario's {LIMIT:?} ran out");
    }
}

impl Default for Deadline {
    fn default() -> Self {
        Self::new()
    }
}

/// A spawned peer. The guard owns its handle for as long as it exists, including while a wait on
/// it is in progress, so a wait that is itself cancelled leaves the task with the guard. Dropping
/// the guard aborts the task; it does not wait for the task to unwind.
pub struct Peer(Option<tokio::task::JoinHandle<()>>);

impl Peer {
    pub fn spawn(task: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(Some(tokio::spawn(task)))
    }

    /// Whether the guard still owns the task, which is what keeps a cancelled wait from
    /// leaving it detached.
    pub fn owns_it(&self) -> bool {
        self.0.is_some()
    }

    pub async fn join(mut self, what: &str, deadline: Deadline) {
        if let Err(reason) = self.try_join(deadline).await {
            panic!("{what}: {reason}");
        }
    }

    /// Wait for the task, with the handle staying in the guard throughout. Awaiting it by value
    /// would drop it on a timeout, leaving the task detached; taking it out first would do the
    /// same if this wait were cancelled.
    pub async fn try_join(&mut self, deadline: Deadline) -> Result<(), String> {
        let handle = self.0.as_mut().expect("waited on once");
        let outcome = match tokio::time::timeout_at(deadline.0, handle).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.is_panic() => Err(format!("panicked: {error}")),
            Ok(Err(error)) => Err(format!("ended: {error}")),
            Err(_) => {
                let handle = self.0.as_mut().expect("still here");
                handle.abort();
                let _ = handle.await;
                Err("the deadline ran out".to_owned())
            }
        };
        self.0 = None;
        outcome
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

pub fn localhost() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)
}

pub fn digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

pub fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8) ^ seed).collect()
}

/// An identity both stacks can use: Rama takes it in memory, quiche reads it from files. The
/// directory is created exclusively by `tempfile` and owned from that moment, so a failure part
/// way through writing leaves nothing behind.
pub struct Identity {
    /// Held so the files live as long as the identity does.
    #[expect(dead_code)]
    directory: TempDir,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub auth: ServerAuthData,
}

impl Identity {
    pub fn generate(name: &str) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("rama-quiche-interop-")
            .tempdir()
            .expect("a directory of our own");
        let generated = rcgen::generate_simple_self_signed(vec![name.to_owned()])
            .expect("an identity is generated");
        let certificate = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&certificate, generated.cert.pem()).expect("the certificate is written");
        std::fs::write(&key, generated.signing_key.serialize_pem()).expect("the key is written");
        // rcgen serialises the key as PKCS#8, so it is named as such rather than guessed at.
        let auth = ServerAuthData::new(
            vec![generated.cert.der().clone()],
            PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()).into(),
        );
        Self {
            directory,
            certificate,
            key,
            auth,
        }
    }

    fn path(path: &Path) -> &str {
        path.to_str().expect("a printable path")
    }
}

pub fn alpn() -> impl IntoIterator<Item = ApplicationProtocol> {
    [ApplicationProtocol::from(ALPN)]
}

pub fn rama_server_config(identity: &Identity) -> ServerConfig {
    let tls = TlsServerConfig::new()
        .with_alpn(alpn().into_iter().collect())
        .with_server_auth(identity.auth.clone());
    ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .expect("the server config is built")
}

pub fn rama_client_config(identity: &Identity) -> ClientConfig {
    let anchor = identity.auth.cert_chain.last().expect("a chain").clone();
    let tls = TlsClientConfig::new()
        .with_alpn(alpn().into_iter().collect())
        .try_with_server_trust_anchors([anchor])
        .expect("the trust anchor is accepted");
    ClientConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .expect("the client config is built")
}

fn quiche_config() -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("a quiche configuration");
    config
        .set_application_protos(&[ALPN])
        .expect("the protocol list is accepted");
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(200_000);
    config.set_initial_max_stream_data_bidi_remote(200_000);
    config.set_initial_max_stream_data_uni(200_000);
    config.set_initial_max_streams_bidi(16);
    config.set_initial_max_streams_uni(16);
    config.set_max_idle_timeout(20_000);
    config
}

pub fn quiche_server_config(identity: &Identity) -> quiche::Config {
    let mut config = quiche_config();
    config
        .load_cert_chain_from_pem_file(Identity::path(&identity.certificate))
        .expect("the certificate is loaded");
    config
        .load_priv_key_from_pem_file(Identity::path(&identity.key))
        .expect("the key is loaded");
    config
}

/// A client configuration that trusts `identity` and nothing else.
pub fn quiche_client_config(identity: &Identity) -> quiche::Config {
    let mut config = quiche_config();
    config
        .load_verify_locations_from_file(Identity::path(&identity.certificate))
        .expect("the trust anchor is loaded");
    config.verify_peer(true);
    config
}

/// Why a driven connection stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum Stopped {
    /// The connection is closed, by either side.
    Closed,
    /// A datagram could not be taken, with the error the connection gave.
    Rejected(quiche::Error),
}

/// A quiche connection with the socket and the clock it does not own itself.
pub struct Quiche {
    connection: quiche::Connection,
    socket: UdpSocket,
    local: SocketAddr,
}

impl Quiche {
    /// Start a client and send its first flight.
    pub async fn connect(
        server: SocketAddr,
        name: &str,
        mut config: quiche::Config,
        deadline: Deadline,
    ) -> Self {
        let socket = UdpSocket::bind(localhost())
            .await
            .expect("the socket binds");
        let local = socket.local_addr().expect("its address");
        let scid = quiche::ConnectionId::from_ref(&[0x5a; quiche::MAX_CONN_ID_LEN]);
        let connection = quiche::connect(Some(name), &scid, local, server, &mut config)
            .expect("the attempt starts");
        let mut peer = Self {
            connection,
            socket,
            local,
        };
        peer.flush(deadline).await;
        peer
    }

    /// Bind a server socket, and hand back the work of accepting on it.
    pub async fn bind_server(
        config: quiche::Config,
        deadline: Deadline,
    ) -> (SocketAddr, impl Future<Output = Self>) {
        let socket = UdpSocket::bind(localhost())
            .await
            .expect("the socket binds");
        let local = socket.local_addr().expect("its address");
        let accepting = async move { Self::accept_on(socket, config, deadline).await };
        (local, accepting)
    }

    /// Accept one connection on a socket that is already bound, so a server can take a further
    /// attempt after an earlier one has ended.
    pub async fn accept_on(
        socket: UdpSocket,
        mut config: quiche::Config,
        deadline: Deadline,
    ) -> Self {
        let local = socket.local_addr().expect("its address");
        let mut buffer = [0u8; DATAGRAM];
        // A socket that served an earlier attempt can still hold that attempt's trailing
        // datagrams, so the accept starts at the next Initial.
        let (len, from, header) = loop {
            let (len, from) = deadline
                .wait(
                    "the quiche server waits for a first datagram",
                    socket.recv_from(&mut buffer),
                )
                .await
                .expect("a first datagram");
            let header = quiche::Header::from_slice(&mut buffer[..len], quiche::MAX_CONN_ID_LEN)
                .expect("a QUIC header");
            if header.ty == quiche::Type::Initial {
                break (len, from, header);
            }
        };
        let mut connection = quiche::accept(&header.dcid, None, local, from, &mut config)
            .expect("the attempt is accepted");
        connection
            .recv(&mut buffer[..len], quiche::RecvInfo { from, to: local })
            .expect("the first datagram is taken");
        let mut peer = Self {
            connection,
            socket,
            local,
        };
        peer.flush(deadline).await;
        peer
    }

    /// Give up the connection and keep the socket, for a server that takes another attempt.
    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }

    /// Send everything the connection has to send. A datagram the socket refuses fails the test:
    /// a lost send would otherwise look like a peer that never answered.
    async fn flush(&mut self, deadline: Deadline) {
        let mut out = [0u8; DATAGRAM];
        loop {
            let (written, info) = match self.connection.send(&mut out) {
                Ok(sent) => sent,
                Err(quiche::Error::Done) => return,
                Err(error) => panic!("quiche send: {error}"),
            };
            deadline
                .wait(
                    "the quiche side writes a datagram",
                    self.socket.send_to(&out[..written], info.to),
                )
                .await
                .expect("the datagram is written");
        }
    }

    /// One turn: send what is pending, then take one datagram or let a timer fire. `Rejected`
    /// means the connection refused a datagram, which its own error explains.
    pub async fn turn(&mut self, deadline: Deadline) -> Option<Stopped> {
        self.flush(deadline).await;
        if self.connection.is_closed() {
            return Some(Stopped::Closed);
        }
        let mut buffer = [0u8; DATAGRAM];
        let wake = deadline.next_wake(self.connection.timeout());
        match tokio::time::timeout_at(wake, self.socket.recv_from(&mut buffer)).await {
            Ok(Ok((len, from))) => {
                let info = quiche::RecvInfo {
                    from,
                    to: self.local,
                };
                match self.connection.recv(&mut buffer[..len], info) {
                    Ok(_) | Err(quiche::Error::Done) => {}
                    Err(error) => {
                        self.flush(deadline).await;
                        return Some(Stopped::Rejected(error));
                    }
                }
            }
            Ok(Err(error)) => panic!("the quiche side's socket: {error}"),
            Err(_) => {
                deadline.expect("the quiche side waits");
                self.connection.on_timeout();
            }
        }
        self.flush(deadline).await;
        None
    }

    /// Turn until `ready` says so. Answers what stopped it, if something did first.
    pub async fn drive_or_stop(
        &mut self,
        what: &str,
        deadline: Deadline,
        mut ready: impl FnMut(&mut quiche::Connection) -> bool,
    ) -> Option<Stopped> {
        while !ready(&mut self.connection) {
            deadline.expect(what);
            if let Some(stopped) = self.turn(deadline).await {
                return Some(stopped);
            }
        }
        None
    }

    /// Turn until `ready` says so, requiring it: a connection that stops first fails the test,
    /// so a caller that asks for a state gets that state or a failure.
    pub async fn drive_until(
        &mut self,
        what: &str,
        deadline: Deadline,
        ready: impl FnMut(&mut quiche::Connection) -> bool,
    ) {
        if let Some(stopped) = self.drive_or_stop(what, deadline, ready).await {
            panic!("{what}: the connection stopped first ({stopped:?})");
        }
    }

    /// Read one stream to its end, driving the connection while it arrives. A stream that
    /// carries more than `limit` is a fault, not a larger test.
    pub async fn read_stream(&mut self, stream: u64, limit: usize, deadline: Deadline) -> Vec<u8> {
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            // Asking whether the stream is readable first keeps the not-yet-created case out of
            // the error path, so anything the read does report is a real fault.
            while self.connection.stream_readable(stream) {
                match self.connection.stream_recv(stream, &mut chunk) {
                    Ok((read, fin)) => {
                        received.extend_from_slice(&chunk[..read]);
                        assert!(
                            received.len() <= limit,
                            "stream {stream} carried more than {limit} bytes"
                        );
                        if fin {
                            return received;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(error) => panic!("reading stream {stream}: {error}"),
                }
            }
            deadline.expect(&format!("reading stream {stream}"));
            if let Some(stopped) = self.turn(deadline).await {
                panic!("reading stream {stream}: the connection stopped ({stopped:?})");
            }
        }
    }

    /// Write a whole payload and finish the stream.
    pub async fn write_stream(&mut self, stream: u64, payload: &[u8], deadline: Deadline) {
        let mut offset = 0;
        while offset < payload.len() {
            match self
                .connection
                .stream_send(stream, &payload[offset..], false)
            {
                Ok(written) => offset += written,
                Err(quiche::Error::Done) => {}
                Err(error) => panic!("quiche stream send: {error}"),
            }
            deadline.expect(&format!("writing stream {stream}"));
            if let Some(stopped) = self.turn(deadline).await {
                panic!("writing stream {stream}: the connection stopped ({stopped:?})");
            }
        }
        self.connection
            .stream_send(stream, b"", true)
            .expect("the stream ends");
        self.turn(deadline).await;
    }

    pub fn connection(&mut self) -> &mut quiche::Connection {
        &mut self.connection
    }

    /// Whether this connection ended for the reason a rejected certificate gives: a TLS alert,
    /// which QUIC carries as an error code in the crypto range (RFC 9001 §4.8).
    pub fn ended_on_a_tls_alert(&self) -> Option<u64> {
        if self.connection.is_timed_out() {
            return None;
        }
        self.connection
            .local_error()
            .or_else(|| self.connection.peer_error())
            .filter(|error| !error.is_app && (0x100..0x200).contains(&error.error_code))
            .map(|error| error.error_code)
    }

    /// Close, and drive until the close has been seen through.
    pub async fn close(&mut self, deadline: Deadline) {
        let _ = self.connection.close(true, 0, b"done");
        self.drive_until("the quiche side closes", deadline, |connection| {
            connection.is_closed()
        })
        .await;
        assert!(
            self.connection.is_closed(),
            "the close finished rather than running out of time"
        );
    }
}

/// Take one attempt on a Rama server and require it to reach a connection. An attempt that
/// never arrives, is refused by the endpoint, or fails its handshake fails the caller.
pub async fn accept_one(what: &str, server: &Endpoint, deadline: Deadline) -> Connection {
    let incoming = deadline
        .wait(&format!("{what} takes an attempt"), server.accept())
        .await
        .unwrap_or_else(|| panic!("{what}: no attempt arrived before the endpoint closed"));
    deadline
        .wait(
            &format!("{what} completes the handshake"),
            incoming
                .accept()
                .unwrap_or_else(|reason| panic!("{what}: the attempt was refused: {reason}")),
        )
        .await
        .unwrap_or_else(|reason| panic!("{what}: the handshake failed: {reason}"))
}

/// Take one attempt on a Rama server and require its handshake to fail, answering why.
pub async fn refuse_one(what: &str, server: &Endpoint, deadline: Deadline) -> String {
    let incoming = deadline
        .wait(&format!("{what} takes an attempt"), server.accept())
        .await
        .unwrap_or_else(|| panic!("{what}: no attempt arrived before the endpoint closed"));
    let outcome = deadline
        .wait(
            &format!("{what} sees the attempt end"),
            incoming
                .accept()
                .unwrap_or_else(|reason| panic!("{what}: the attempt was refused: {reason}")),
        )
        .await;
    match outcome {
        Ok(_) => panic!("{what}: the handshake completed where it had to fail"),
        Err(reason) => format!("{reason:?}"),
    }
}

/// Whether a UDP port on loopback can be bound, which is how these tests see that a socket is
/// gone rather than merely unreferenced.
pub fn port_is_free(port: u16) -> bool {
    std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

/// Wait for a condition to hold, within a bound of its own. Answers whether it did.
pub async fn within(limit: Duration, mut holds: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if holds() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    holds()
}
