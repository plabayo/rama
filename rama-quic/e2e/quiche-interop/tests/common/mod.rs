//! What the quiche interoperability tests need: identities on disk for a peer that reads PEM
//! files, the two stacks' configurations, and a hand-driven loop for a library that owns neither
//! sockets nor timers.
//!
//! Two limits of the driver, both fine for the scenarios here and both to lift before the MTU,
//! pacing and loss matrix: datagrams are read and written through a 1350-byte buffer, so a peer
//! that raises its MTU needs that raised with it; and `SendInfo::at`, the moment quiche asks a
//! datagram to leave, is ignored, so nothing here is paced.
#![allow(
    dead_code,
    reason = "shared support for several integration test binaries, each using part of it"
)]

use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use rama::{
    crypto::{
        dep::rcgen,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
    quic::{ClientConfig, Connection, Endpoint, ServerConfig, tls::TlsOptions},
    tls::{
        client::TlsClientConfig,
        server::{ServerAuthData, TlsServerConfig},
    },
    utils::{collections::smallvec::smallvec, fs::TempDir},
};
use tokio::{net::UdpSocket, time::Instant};

/// The protocol, deadline, task guard and payloads every peer project shares. Each test binary
/// uses part of this.
#[allow(
    unused_imports,
    reason = "shared surface, used in part by each test binary"
)]
pub use interop_common::{
    ALPN, Deadline, Peer, digest, identity::alpn as shared_alpn, localhost, payload,
};

/// The largest datagram this driver reads or writes at once. quiche owns no socket, so the
/// buffer is the harness's.
const DATAGRAM: usize = 1350;

pub fn localhost_v6() -> SocketAddr {
    SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0)
}

/// An identity both stacks can use: Rama takes it in memory, quiche reads it from files. The
/// directory is created exclusively and owned from that moment, so a failure part way through
/// writing leaves nothing behind.
pub struct Identity {
    /// Held so the files live as long as the identity does.
    #[expect(dead_code)]
    directory: TempDir,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub auth: ServerAuthData,
}

impl Identity {
    /// Self-signed identity for `name` with a distinct issuer name, so a client trusting
    /// another anchor finds no issuer for it.
    pub fn generate_from_a_stranger(name: &str, issuer: &str) -> Self {
        let mut params = rcgen::CertificateParams::new([name.to_owned()])
            .expect("the name is usable in a certificate");
        let mut distinguished = rcgen::DistinguishedName::new();
        distinguished.push(rcgen::DnType::OrganizationName, issuer.to_owned());
        params.distinguished_name = distinguished;
        let key = rcgen::KeyPair::generate().expect("a key pair");
        let certificate = params.self_signed(&key).expect("an identity is generated");
        Self::written(
            &certificate.pem(),
            &key.serialize_pem(),
            certificate.der().clone(),
            &key,
        )
    }

    /// The identity a name case needs: one for the name the client will ask for, or one
    /// carrying the loopback address when it will send no name at all.
    pub fn generate_for(name: Option<&str>) -> Self {
        match name {
            Some(name) => Self::generate(name),
            None => Self::generate_for_loopback(),
        }
    }

    /// An identity valid for the loopback address, for a client that names an address rather
    /// than a host. The address goes in the subject alternative name as an address, not as a
    /// DNS name, which is what a verifier looks for when the client named an address.
    pub fn generate_for_loopback() -> Self {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::IpAddress(Ipv4Addr::LOCALHOST.into())];
        let key = rcgen::KeyPair::generate().expect("a key pair");
        let certificate = params.self_signed(&key).expect("an identity is generated");
        Self::written(
            &certificate.pem(),
            &key.serialize_pem(),
            certificate.der().clone(),
            &key,
        )
    }

    pub fn generate(name: &str) -> Self {
        let generated = rcgen::generate_simple_self_signed(vec![name.to_owned()])
            .expect("an identity is generated");
        Self::written(
            &generated.cert.pem(),
            &generated.signing_key.serialize_pem(),
            generated.cert.der().clone(),
            &generated.signing_key,
        )
    }

    /// Put an identity on disk for a peer that reads PEM files, and keep it in Rama's own types
    /// for this side.
    fn written(
        certificate_pem: &str,
        key_pem: &str,
        der: CertificateDer<'static>,
        key: &rcgen::KeyPair,
    ) -> Self {
        let directory =
            TempDir::with_prefix("rama-quiche-interop-").expect("a directory of our own");
        let certificate = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&certificate, certificate_pem).expect("the certificate is written");
        std::fs::write(&key_path, key_pem).expect("the key is written");
        // rcgen serialises the key as PKCS#8, so it is named as such rather than guessed at.
        let auth = ServerAuthData::new(
            vec![der],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        );
        Self {
            directory,
            certificate,
            key: key_path,
            auth,
        }
    }

    fn path(path: &Path) -> &str {
        path.to_str().expect("a printable path")
    }
}

pub fn rama_server_config(identity: &Identity) -> ServerConfig {
    let tls = TlsServerConfig::new()
        .with_alpn(smallvec![shared_alpn()])
        .with_server_auth(identity.auth.clone());
    ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .expect("the server config is built")
}

/// A client that trusts `identity` and may offer early application data. Early data is opt-in
/// in this crate: `TlsOptions::early_data` is off by default, so a test about 0-RTT asks for it.
pub fn rama_client_config_with_early_data(identity: &Identity) -> ClientConfig {
    let anchor = identity.auth.cert_chain.last().expect("a chain").clone();
    let tls = TlsClientConfig::new()
        .with_alpn(smallvec![shared_alpn()])
        .try_with_server_trust_anchors([anchor])
        .expect("the trust anchor is accepted");
    ClientConfig::try_from_rama_tls(&tls, TlsOptions::default().with_early_data(true))
        .expect("the client config is built")
}

pub fn rama_client_config(identity: &Identity) -> ClientConfig {
    let anchor = identity.auth.cert_chain.last().expect("a chain").clone();
    let tls = TlsClientConfig::new()
        .with_alpn(smallvec![shared_alpn()])
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

/// How many datagrams each direction of a quiche connection will hold.
pub const DGRAM_QUEUE: usize = 64;

/// quiche advertises 65536 as its `max_datagram_frame_size` whenever datagrams are enabled,
/// following draft-ietf-quic-datagram-01; RFC 9221 recommends 65535. Either way the value is
/// far above the path budget, so what limits a datagram towards a quiche peer is the path. That
/// is the complement of the aioquic project, where the peer's advertised size is set small
/// enough to be the binding one.
pub fn with_datagrams(mut config: quiche::Config) -> quiche::Config {
    config.enable_dgram(true, DGRAM_QUEUE, DGRAM_QUEUE);
    config
}

/// The ticket key these tests pin, so a later server can be the same resumption authority as
/// the first, or deliberately not be.
pub const TICKET_KEY: [u8; 48] = [0x5a; 48];
/// A different one, for refusing a resumption outright.
pub const OTHER_TICKET_KEY: [u8; 48] = [0xa5; 48];

/// BoringSSL's `ssl_early_data_reason_t`, as the vendored header in the pinned quiche defines
/// it. quiche reports it through `Connection::early_data_reason`.
pub mod early_data {
    pub const ACCEPTED: u32 = 2;
    pub const PEER_DECLINED: u32 = 4;
    pub const SESSION_NOT_RESUMED: u32 = 6;
    pub const UNSUPPORTED_FOR_SESSION: u32 = 7;
}

/// A server that issues resumption tickets under `key`. Whether it also accepts early data is
/// what separates a server that resumes and takes 0-RTT from one that resumes and refuses it.
pub fn quiche_resuming_server_config(
    identity: &Identity,
    key: &[u8; 48],
    early_data: bool,
) -> quiche::Config {
    let mut config = quiche_server_config(identity);
    config
        .set_ticket_key(key)
        .expect("the ticket key is accepted");
    if early_data {
        config.enable_early_data();
    }
    config
}

/// A server that tells the client not to migrate. RFC 9000 §9 forbids active migration when
/// the peer set this, so the client keeps its socket however many identifiers it holds.
pub fn quiche_server_config_without_migration(identity: &Identity) -> quiche::Config {
    let mut config = quiche_server_config(identity);
    config.set_disable_active_migration(true);
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

/// A client that will move: it asks for room for more connection identifiers than the default
/// two, so both sides have a spare when the move comes.
pub fn quiche_client_config_that_moves(identity: &Identity) -> quiche::Config {
    let mut config = quiche_client_config(identity);
    config.set_active_connection_id_limit(4);
    config
}

/// A client configuration that trusts `identity` and nothing else.
pub fn quiche_client_config(identity: &Identity) -> quiche::Config {
    quiche_client_config_trusting(&identity.certificate)
}

/// A client configuration that trusts whatever is in `anchor`, for identities issued by an
/// authority rather than signed by themselves.
pub fn quiche_client_config_trusting(anchor: &Path) -> quiche::Config {
    let mut config = quiche_config();
    config
        .load_verify_locations_from_file(Identity::path(anchor))
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
    last_from: Option<SocketAddr>,
}

impl Quiche {
    /// Start a client that asks for no name. RFC 6066 §3 has no SNI for an address literal, and
    /// this is how that looks on the wire.
    pub async fn connect_without_a_name(
        server: SocketAddr,
        config: quiche::Config,
        deadline: Deadline,
    ) -> Self {
        Self::start(server, None, config, None, deadline).await
    }

    /// Start a client that offers a session it was given, so a server that recognises it can
    /// resume rather than start again.
    pub async fn connect_resuming(
        server: SocketAddr,
        name: &str,
        config: quiche::Config,
        session: &[u8],
        deadline: Deadline,
    ) -> Self {
        Self::start(server, Some(name), config, Some(session), deadline).await
    }

    /// Start a client and send its first flight.
    pub async fn connect(
        server: SocketAddr,
        name: &str,
        config: quiche::Config,
        deadline: Deadline,
    ) -> Self {
        Self::start(server, Some(name), config, None, deadline).await
    }

    async fn start(
        server: SocketAddr,
        name: Option<&str>,
        mut config: quiche::Config,
        session: Option<&[u8]>,
        deadline: Deadline,
    ) -> Self {
        // The client's own socket follows the family of the address it is dialling.
        let here = if server.is_ipv6() {
            localhost_v6()
        } else {
            localhost()
        };
        let socket = UdpSocket::bind(here).await.expect("the socket binds");
        let local = socket.local_addr().expect("its address");
        let scid = quiche::ConnectionId::from_ref(&[0x5a; quiche::MAX_CONN_ID_LEN]);
        let connection =
            quiche::connect(name, &scid, local, server, &mut config).expect("the attempt starts");
        let mut peer = Self {
            connection,
            socket,
            local,
            last_from: None,
        };
        // Offered before the first flight leaves, so the offer is in it.
        if let Some(session) = session {
            peer.connection
                .set_session(session)
                .expect("the session is offered");
        }
        peer.flush(deadline).await;
        peer
    }

    /// Bind a server socket on loopback, and hand back the work of accepting on it.
    pub async fn bind_server(
        config: quiche::Config,
        deadline: Deadline,
    ) -> (SocketAddr, impl Future<Output = Self>) {
        Self::bind_server_on(localhost(), config, deadline).await
    }

    /// The same, on an address of the caller's choosing, so a test can pick the family.
    pub async fn bind_server_on(
        where_to: SocketAddr,
        config: quiche::Config,
        deadline: Deadline,
    ) -> (SocketAddr, impl Future<Output = Self>) {
        let socket = UdpSocket::bind(where_to).await.expect("the socket binds");
        let local = socket.local_addr().expect("its address");
        let accepting = async move { Self::accept_on(socket, config, deadline).await };
        (local, accepting)
    }

    /// Accept one connection on a socket that is already bound, so a server can take a further
    /// attempt after an earlier one has ended.
    pub async fn accept_on(socket: UdpSocket, config: quiche::Config, deadline: Deadline) -> Self {
        let mut peer = Self::accept_on_silently(socket, config, deadline).await;
        peer.flush(deadline).await;
        peer
    }

    /// The same, but without answering. A server that has not answered cannot have finished a
    /// handshake, so anything readable on it arrived on the early keys.
    pub async fn accept_on_silently(
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
        Self {
            connection,
            socket,
            local,
            last_from: None,
        }
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
                self.last_from = Some(from);
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

    /// Take one datagram, or let a timer fire, without answering. Used to watch what a peer
    /// sends while this side stays silent.
    pub async fn receive(&mut self, deadline: Deadline) {
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
                    Err(error) => panic!("the quiche side refused a datagram: {error}"),
                }
            }
            Ok(Err(error)) => panic!("the quiche side's socket: {error}"),
            Err(_) => {
                deadline.expect("the quiche side waits");
                self.connection.on_timeout();
            }
        }
    }

    /// Take datagrams without answering until `ready` says so.
    pub async fn receive_until(
        &mut self,
        what: &str,
        deadline: Deadline,
        mut ready: impl FnMut(&mut quiche::Connection) -> bool,
    ) {
        while !ready(&mut self.connection) {
            deadline.expect(what);
            self.receive(deadline).await;
        }
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

    /// Send one datagram and put it on the wire.
    pub async fn send_datagram(&mut self, payload: &[u8], deadline: Deadline) {
        self.connection
            .dgram_send(payload)
            .expect("the datagram is queued");
        self.flush(deadline).await;
    }

    /// Take one datagram, driving the connection while it arrives. A datagram larger than
    /// `limit` is a fault, not a larger test.
    pub async fn read_datagram(&mut self, limit: usize, deadline: Deadline) -> Vec<u8> {
        let mut buffer = vec![0u8; limit];
        loop {
            match self.connection.dgram_recv(&mut buffer) {
                Ok(read) => {
                    buffer.truncate(read);
                    return buffer;
                }
                Err(quiche::Error::Done) => {}
                Err(quiche::Error::BufferTooShort) => {
                    panic!("a datagram carried more than {limit} bytes")
                }
                Err(error) => panic!("reading a datagram: {error}"),
            }
            deadline.expect("reading a datagram");
            if let Some(stopped) = self.turn(deadline).await {
                panic!("reading a datagram: the connection stopped ({stopped:?})");
            }
        }
    }

    /// Offer the peer one more connection identifier to move to. quiche leaves this to the
    /// application, so without it the peer has no spare identifier and cannot migrate.
    pub async fn offer_another_identifier(&mut self, tag: u8, deadline: Deadline) {
        let bytes = [tag; quiche::MAX_CONN_ID_LEN];
        let scid = quiche::ConnectionId::from_ref(&bytes);
        self.connection
            .new_scid(&scid, u128::from(tag), false)
            .expect("the identifier is accepted");
        self.flush(deadline).await;
    }

    /// Move this side to a socket of its own choosing, the way a client whose network changed
    /// would. Answers the address it moved to. Only a client may do this.
    pub async fn move_to_a_new_socket(&mut self, deadline: Deadline) -> SocketAddr {
        let socket = UdpSocket::bind(if self.local.is_ipv6() {
            localhost_v6()
        } else {
            localhost()
        })
        .await
        .expect("the socket binds");
        let local = socket.local_addr().expect("its address");
        self.connection
            .migrate_source(local)
            .expect("the move is accepted");
        self.socket = socket;
        self.local = local;
        self.flush(deadline).await;
        local
    }

    /// The address this side is sending from.
    pub fn local_address(&self) -> SocketAddr {
        self.local
    }

    /// Where the last datagram came from, which is how a peer's move shows up here.
    pub fn last_seen_from(&self) -> Option<SocketAddr> {
        self.last_from
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

    /// Close with an application code and reason of the caller's choosing, and drive until the
    /// close has been seen through.
    pub async fn close_with(&mut self, code: u64, reason: &[u8], deadline: Deadline) {
        let _ = self.connection.close(true, code, reason);
        self.drive_until("the quiche side closes", deadline, |connection| {
            connection.is_closed()
        })
        .await;
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
