use std::{
    cmp,
    collections::VecDeque,
    env,
    io::{self, Write},
    mem,
    net::{Ipv6Addr, SocketAddr, UdpSocket},
    ops::RangeFrom,
    str,
    sync::{Arc, LazyLock},
};

use ahash::{HashMap, HashSet};
use parking_lot::Mutex;
use rama_core::bytes::BytesMut;
use rama_core::telemetry::tracing::{info_span, trace};
use rama_tls_rustls::dep::rustls::{
    KeyLogFile,
    client::WebPkiServerVerifier,
    pki_types::{CertificateDer, PrivateKeyDer},
};

use super::crypto::rustls::{QuicClientConfig, QuicServerConfig, configured_provider};
use super::*;
use crate::proto::{Duration, Instant};

pub(super) const DEFAULT_MTU: usize = 1452;

pub(super) struct Pair {
    pub(super) server: TestEndpoint,
    pub(super) client: TestEndpoint,
    /// Start time
    epoch: Instant,
    /// Current time
    pub(super) time: Instant,
    /// Simulates the maximum size allowed for UDP payloads by the link (packets exceeding this size will be dropped)
    pub(super) mtu: usize,
    /// Simulates explicit congestion notification
    pub(super) congestion_experienced: bool,
    // One-way
    pub(super) latency: Duration,
    /// Number of spin bit flips
    pub(super) spins: u64,
    /// Every address the client sent a datagram to, in order.
    /// Every datagram the client put on the wire, as the engine emitted it.
    pub(super) client_sent: Vec<Sent>,
    /// What the server put on the wire, recorded as it is drained. Every drive empties the
    /// queue, so an assertion made on the queue afterwards would inspect nothing.
    pub(super) server_sent: Vec<Sent>,
    last_spin: bool,
}

impl Pair {
    pub(super) fn default_with_deterministic_pns() -> Self {
        let mut cfg = server_config();
        let mut transport = TransportConfig::default();
        transport.deterministic_packet_numbers(true);
        cfg.transport = Arc::new(transport);
        Self::new(Default::default(), cfg)
    }

    pub(super) fn new(endpoint_config: Arc<EndpointConfig>, server_config: ServerConfig) -> Self {
        let server = Endpoint::new(
            endpoint_config.clone(),
            Some(Arc::new(server_config)),
            true,
            None,
        );
        let client = Endpoint::new(endpoint_config, None, true, None);

        Self::new_from_endpoint(client, server)
    }

    pub(super) fn new_from_endpoint(client: Endpoint, server: Endpoint) -> Self {
        let server_addr = SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            SERVER_PORTS.lock().next().unwrap(),
        );
        let client_addr = SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            CLIENT_PORTS.lock().next().unwrap(),
        );
        let now = Instant::now();
        Self {
            server: TestEndpoint::new(server, server_addr),
            client: TestEndpoint::new(client, client_addr),
            epoch: now,
            time: now,
            mtu: DEFAULT_MTU,
            latency: Duration::ZERO,
            spins: 0,
            client_sent: Vec::new(),
            server_sent: Vec::new(),
            last_spin: false,
            congestion_experienced: false,
        }
    }

    /// Returns whether the connection is not idle
    pub(super) fn step(&mut self) -> bool {
        self.drive_client();
        self.drive_server();
        if self.client.is_idle() && self.server.is_idle() {
            return false;
        }

        let client_t = self.client.next_wakeup();
        let server_t = self.server.next_wakeup();
        match min_opt(client_t, server_t) {
            Some(t) if Some(t) == client_t => {
                if t != self.time {
                    self.time = self.time.max(t);
                    trace!("advancing to {:?} for client", self.time - self.epoch);
                }
                true
            }
            Some(t) if Some(t) == server_t => {
                if t != self.time {
                    self.time = self.time.max(t);
                    trace!("advancing to {:?} for server", self.time - self.epoch);
                }
                true
            }
            Some(_) => {
                panic!("the simulator only advances time to the next client or server timeout")
            }
            None => false,
        }
    }

    /// Advance time until both connections are idle
    pub(super) fn drive(&mut self) {
        while self.step() {}
    }

    /// Advance time until both connections are idle, or after 100 steps have been executed
    ///
    /// Returns true if the amount of steps exceeds the bounds, because the connections never became
    /// idle
    pub(super) fn drive_bounded(&mut self) -> bool {
        for _ in 0..100 {
            if !self.step() {
                return false;
            }
        }

        true
    }

    pub(super) fn drive_client(&mut self) {
        let span = info_span!("client");
        let _guard = span.enter();
        self.client.drive(self.time, self.server.addr);
        for (packet, buffer) in self.client.outbound.drain(..) {
            self.client_sent.push(Sent {
                local: packet.local,
                to: packet.destination,
                cid: packet.cid_used,
            });
            let packet_size = packet_size(&packet, &buffer);
            if packet_size > self.mtu {
                info!(packet_size, "dropping packet (max size exceeded)");
                continue;
            }
            if buffer[0] & packet::LONG_HEADER_FORM == 0 {
                let spin = buffer[0] & packet::SPIN_BIT != 0;
                self.spins += (spin == self.last_spin) as u64;
                self.last_spin = spin;
            }
            if let Some(ref socket) = self.client.socket {
                socket.send_to(&buffer, packet.destination).unwrap();
            }
            if self.server.accepts(packet.destination) {
                let ecn = set_congestion_experienced(packet.ecn, self.congestion_experienced);
                let to = (!self.server.hide_local).then_some(packet.destination);
                self.server.inbound.push_back(Inbound {
                    at: self.time + self.latency,
                    ecn,
                    packet: buffer.as_ref().into(),
                    from: packet.local,
                    to,
                });
            }
        }
    }

    pub(super) fn drive_server(&mut self) {
        let span = info_span!("server");
        let _guard = span.enter();
        self.server.drive(self.time, self.client.addr);
        for (packet, buffer) in self.server.outbound.drain(..) {
            self.server_sent.push(Sent {
                local: packet.local,
                to: packet.destination,
                cid: packet.cid_used,
            });
            let packet_size = packet_size(&packet, &buffer);
            if packet_size > self.mtu {
                info!(packet_size, "dropping packet (max size exceeded)");
                continue;
            }
            if let Some(ref socket) = self.server.socket {
                socket.send_to(&buffer, packet.destination).unwrap();
            }
            if self.client.accepts(packet.destination) {
                let ecn = set_congestion_experienced(packet.ecn, self.congestion_experienced);
                let to = (!self.client.hide_local).then_some(packet.destination);
                self.client.inbound.push_back(Inbound {
                    at: self.time + self.latency,
                    ecn,
                    packet: buffer.as_ref().into(),
                    from: packet.local,
                    to,
                });
            }
        }
    }

    pub(super) fn connect(&mut self) -> (ConnectionHandle, ConnectionHandle) {
        self.connect_with(client_config())
    }

    pub(super) fn connect_with(
        &mut self,
        config: ClientConfig,
    ) -> (ConnectionHandle, ConnectionHandle) {
        info!("connecting");
        let client_ch = self.begin_connect(config);
        self.drive();
        let server_ch = self.server.assert_accept();
        self.finish_connect(client_ch, server_ch);
        (client_ch, server_ch)
    }

    /// Just start connecting the client
    pub(super) fn begin_connect(&mut self, config: ClientConfig) -> ConnectionHandle {
        let span = info_span!("client");
        let _guard = span.enter();
        let (client_ch, client_conn) = self
            .client
            .connect(self.time, config, self.server.addr, "localhost")
            .unwrap();
        self.client.connections.insert(client_ch, client_conn);
        client_ch
    }

    fn finish_connect(&mut self, client_ch: ConnectionHandle, server_ch: ConnectionHandle) {
        match self.client_conn_mut(client_ch).poll() {
            Some(Event::HandshakeDataReady) => {}
            other => panic!(
                "assertion failed: `{other:?}` does not match `Some(Event::HandshakeDataReady)`"
            ),
        }
        match self.client_conn_mut(client_ch).poll() {
            Some(Event::Connected) => {}
            other => {
                panic!("assertion failed: `{other:?}` does not match `Some(Event::Connected)`")
            }
        }
        match self.server_conn_mut(server_ch).poll() {
            Some(Event::HandshakeDataReady) => {}
            other => panic!(
                "assertion failed: `{other:?}` does not match `Some(Event::HandshakeDataReady)`"
            ),
        }
        match self.server_conn_mut(server_ch).poll() {
            Some(Event::HandshakeConfirmed) => {}
            other => panic!(
                "assertion failed: `{other:?}` does not match `Some(Event::HandshakeConfirmed)`"
            ),
        }
        match self.server_conn_mut(server_ch).poll() {
            Some(Event::Connected) => {}
            other => {
                panic!("assertion failed: `{other:?}` does not match `Some(Event::Connected)`")
            }
        }
        match self.client_conn_mut(client_ch).poll() {
            Some(Event::HandshakeConfirmed) => {}
            other => panic!(
                "assertion failed: `{other:?}` does not match `Some(Event::HandshakeConfirmed)`"
            ),
        }
    }

    pub(super) fn client_conn_mut(&mut self, ch: ConnectionHandle) -> &mut Connection {
        self.client.connections.get_mut(&ch).unwrap()
    }

    pub(super) fn client_streams(&mut self, ch: ConnectionHandle) -> Streams<'_> {
        self.client_conn_mut(ch).streams()
    }

    pub(super) fn client_send(&mut self, ch: ConnectionHandle, s: StreamId) -> SendStream<'_> {
        self.client_conn_mut(ch).send_stream(s)
    }

    pub(super) fn client_recv(&mut self, ch: ConnectionHandle, s: StreamId) -> RecvStream<'_> {
        self.client_conn_mut(ch).recv_stream(s)
    }

    pub(super) fn client_datagrams(&mut self, ch: ConnectionHandle) -> Datagrams<'_> {
        self.client_conn_mut(ch).datagrams()
    }

    pub(super) fn server_conn_mut(&mut self, ch: ConnectionHandle) -> &mut Connection {
        self.server.connections.get_mut(&ch).unwrap()
    }

    pub(super) fn server_streams(&mut self, ch: ConnectionHandle) -> Streams<'_> {
        self.server_conn_mut(ch).streams()
    }

    pub(super) fn server_send(&mut self, ch: ConnectionHandle, s: StreamId) -> SendStream<'_> {
        self.server_conn_mut(ch).send_stream(s)
    }

    pub(super) fn server_recv(&mut self, ch: ConnectionHandle, s: StreamId) -> RecvStream<'_> {
        self.server_conn_mut(ch).recv_stream(s)
    }

    pub(super) fn server_datagrams(&mut self, ch: ConnectionHandle) -> Datagrams<'_> {
        self.server_conn_mut(ch).datagrams()
    }
}

impl Default for Pair {
    fn default() -> Self {
        Self::new(Default::default(), server_config())
    }
}

/// One datagram an endpoint put on the wire: the local address it belongs to, where it went, and
/// the sequence number of the destination connection ID it carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Sent {
    pub(super) local: Option<SocketAddr>,
    pub(super) to: SocketAddr,
    pub(super) cid: Option<u64>,
}

pub(super) struct TestEndpoint {
    pub(super) endpoint: Endpoint,
    pub(super) addr: SocketAddr,
    socket: Option<UdpSocket>,
    timeout: Option<Instant>,
    pub(super) outbound: VecDeque<(Transmit, Bytes)>,
    delayed: VecDeque<(Transmit, Bytes)>,
    pub(super) inbound: VecDeque<Inbound>,
    /// A second address this endpoint receives at, such as a server's preferred one.
    pub(super) alt_addr: Option<SocketAddr>,
    /// While set, datagrams reach this endpoint without local provenance, as they do on a host
    /// whose socket cannot report which address received them.
    pub(super) hide_local: bool,
    accepted: Option<Result<ConnectionHandle, ConnectionError>>,
    pub(super) connections: HashMap<ConnectionHandle, Connection>,
    conn_events: HashMap<ConnectionHandle, VecDeque<ConnectionEvent>>,
    /// Drives that ended with a datagram waiting for a route and nothing left to install, since
    /// the last datagram actually left. A route that is never installed would otherwise be
    /// invisible. The count is endpoint-wide, which suffices while these tests run one
    /// connection each. Per-connection ownership is required for the multi-connection case and is
    /// not implemented.
    waiting_drives: u32,
    /// A datagram that was built but may not be sent yet because the endpoint has not confirmed
    /// the route its identifier needs. It is kept exactly as it is, as the driver keeps its
    /// buffered transmit, so nothing is rebuilt and no protocol counter advances twice.
    pending_transmit: HashMap<ConnectionHandle, (Transmit, Vec<u8>)>,
    pub(super) captured_packets: Vec<Vec<u8>>,
    pub(super) capture_inbound_packets: bool,
    pub(super) handle_incoming: Box<dyn FnMut(&Incoming) -> IncomingConnectionBehavior>,
    pub(super) waiting_incoming: Vec<Incoming>,
    /// While set, connection IDs the endpoint issues are kept from the connection (the peer sees
    /// no NEW_CONNECTION_ID) until `release_held_identifiers`: a peer slow to issue.
    pub(super) hold_identifiers: bool,
    held_identifiers: Vec<(ConnectionHandle, ConnectionEvent)>,
}

/// A datagram waiting for an endpoint's receive path.
#[derive(Debug)]
pub(super) struct Inbound {
    pub(super) at: Instant,
    pub(super) ecn: Option<EcnCodepoint>,
    pub(super) packet: BytesMut,
    /// Source address to hand the endpoint; the peer's primary address when unset.
    pub(super) from: Option<SocketAddr>,
    /// The local address the datagram was addressed to.
    pub(super) to: Option<SocketAddr>,
}

impl Inbound {
    /// A datagram from the peer's primary address, addressed to this endpoint's own.
    pub(super) fn plain(at: Instant, ecn: Option<EcnCodepoint>, packet: BytesMut) -> Self {
        Self {
            at,
            ecn,
            packet,
            from: None,
            to: None,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub(super) enum IncomingConnectionBehavior {
    Accept,
    Reject,
    Retry,
    Wait,
}

pub(super) fn validate_incoming(incoming: &Incoming) -> IncomingConnectionBehavior {
    if incoming.remote_address_validated() {
        IncomingConnectionBehavior::Accept
    } else {
        IncomingConnectionBehavior::Retry
    }
}

impl TestEndpoint {
    fn new(endpoint: Endpoint, addr: SocketAddr) -> Self {
        let socket = if env::var_os("SSLKEYLOGFILE").is_some() {
            let socket = UdpSocket::bind(addr).expect("failed to bind UDP socket");
            socket
                .set_read_timeout(Some(Duration::from_millis(10)))
                .unwrap();
            Some(socket)
        } else {
            None
        };
        Self {
            endpoint,
            addr,
            socket,
            timeout: None,
            outbound: VecDeque::new(),
            delayed: VecDeque::new(),
            inbound: VecDeque::new(),
            alt_addr: None,
            hide_local: false,
            accepted: None,
            connections: HashMap::default(),
            conn_events: HashMap::default(),
            pending_transmit: HashMap::default(),
            waiting_drives: 0,
            captured_packets: Vec::new(),
            capture_inbound_packets: false,
            handle_incoming: Box::new(|_| IncomingConnectionBehavior::Accept),
            waiting_incoming: Vec::new(),
            hold_identifiers: false,
            held_identifiers: Vec::new(),
        }
    }

    pub(super) fn drive(&mut self, now: Instant, remote: SocketAddr) {
        self.drive_incoming(now, remote);
        self.drive_outgoing(now);
    }

    /// Whether a datagram addressed to `destination` reaches this endpoint.
    pub(super) fn accepts(&self, destination: SocketAddr) -> bool {
        self.addr == destination || self.alt_addr == Some(destination)
    }

    pub(super) fn drive_incoming(&mut self, now: Instant, remote: SocketAddr) {
        if let Some(ref socket) = self.socket {
            loop {
                let mut buf = [0; 8192];
                if socket.recv_from(&mut buf).is_err() {
                    break;
                }
            }
        }
        let buffer_size = self.endpoint.config().get_max_udp_payload_size() as usize;
        let mut buf = Vec::with_capacity(buffer_size);

        while self.inbound.front().is_some_and(|x| x.at <= now) {
            let Some(datagram) = self.inbound.pop_front() else {
                break;
            };
            let source = datagram.from.unwrap_or(remote);
            if let Some(event) = self.endpoint.handle(
                datagram.at,
                source,
                datagram.to,
                datagram.ecn,
                datagram.packet,
                &mut buf,
            ) {
                match event {
                    DatagramEvent::NewConnection(incoming) => {
                        match (self.handle_incoming)(&incoming) {
                            IncomingConnectionBehavior::Accept => {
                                let _ = self.try_accept(incoming, now);
                            }
                            IncomingConnectionBehavior::Reject => {
                                self.reject(incoming);
                            }
                            IncomingConnectionBehavior::Retry => {
                                self.retry(incoming);
                            }
                            IncomingConnectionBehavior::Wait => {
                                self.waiting_incoming.push(incoming);
                            }
                        }
                    }
                    DatagramEvent::ConnectionEvent(ch, event) => {
                        if self.capture_inbound_packets {
                            let packet = self.connections[&ch].decode_packet(&event);
                            self.captured_packets.extend(packet);
                        }

                        self.conn_events.entry(ch).or_default().push_back(event);
                    }
                    DatagramEvent::Response(transmit) => {
                        let size = transmit.size;
                        self.outbound.extend(split_transmit(transmit, &buf[..size]));
                        buf.clear();
                    }
                }
            }
        }
    }

    /// How many drives in a row a datagram may wait for a route that nothing is installing.
    const WAITING_DRIVES: u32 = 8;

    pub(super) fn drive_outgoing(&mut self, now: Instant) {
        let buffer_size = self.endpoint.config().get_max_udp_payload_size() as usize;
        let mut buf = Vec::with_capacity(buffer_size);

        loop {
            // Arrivals and timers, then the wire, then everything the connections asked the
            // endpoint for — in the order they asked. Nothing is applied early: a datagram that
            // needs a route is *kept*, so the next pass sends it once the route is in, and the
            // release of a displaced route can never be reordered behind the installation that
            // displaced it.
            let mut endpoint_events: Vec<(ConnectionHandle, EndpointEvent)> = vec![];
            for (ch, conn) in self.connections.iter_mut() {
                if self.timeout.is_some_and(|x| x <= now) {
                    self.timeout = None;
                    conn.handle_timeout(now);
                }
                // Only this connection's events: draining every handle's here would hand one
                // connection another's packets.
                if let Some(events) = self.conn_events.get_mut(ch) {
                    for event in events.drain(..) {
                        conn.handle_event(event);
                    }
                }
                while let Some(event) = conn.poll_endpoint_events() {
                    endpoint_events.push((*ch, event));
                }
            }
            // Now the wire.
            let mut waiting = false;
            for (ch, conn) in self.connections.iter_mut() {
                // Whatever was waiting for a route goes first, and is offered as it was built.
                if let Some((transmit, bytes)) = self.pending_transmit.remove(ch) {
                    match transmit.cid_used.map_or(SendPermit::Sendable, |seq| {
                        conn.may_send_cid(seq, transmit.destination)
                    }) {
                        SendPermit::Sendable => {
                            let (cid_used, destination) = (transmit.cid_used, transmit.destination);
                            self.outbound.extend(split_transmit(transmit, &bytes));
                            if let Some(seq) = cid_used {
                                conn.cid_sent(seq, destination);
                            }
                        }
                        SendPermit::AwaitingInstallation => {
                            self.pending_transmit.insert(*ch, (transmit, bytes));
                            waiting = true;
                            continue;
                        }
                        // Never sendable again: only this datagram is given up.
                        SendPermit::Obsolete => {}
                    }
                }
                let mut transmits = 0;
                while let Some(transmit) = conn.poll_transmit(now, MAX_DATAGRAMS, &mut buf) {
                    transmits += 1;
                    assert!(
                        transmits < 100_000,
                        "a connection produced packets without end: something announces frames \
                         to send that it never writes"
                    );
                    let size = transmit.size;
                    let cid_used = transmit.cid_used;
                    let destination = transmit.destination;
                    // The driver holds a datagram whose route the endpoint has not confirmed and
                    // drops one whose identifier may never be sent again (RFC 9000 §9.5); so does
                    // this. A held one is kept as it is and offered again once the route is in.
                    match cid_used.map_or(SendPermit::Sendable, |seq| {
                        conn.may_send_cid(seq, destination)
                    }) {
                        SendPermit::Sendable => {}
                        SendPermit::AwaitingInstallation => {
                            self.pending_transmit
                                .insert(*ch, (transmit, buf[..size].to_vec()));
                            buf.clear();
                            waiting = true;
                            break;
                        }
                        SendPermit::Obsolete => {
                            buf.clear();
                            continue;
                        }
                    }
                    self.outbound.extend(split_transmit(transmit, &buf[..size]));
                    buf.clear();
                    // Something left, so nothing is stuck: this is the progress the waiting
                    // count below is measured against.
                    self.waiting_drives = 0;
                    // The datagram is on its way, which is the boundary the driver reports.
                    if let Some(seq) = cid_used {
                        conn.cid_sent(seq, destination);
                    }
                }
                self.timeout = conn.poll_timeout();
                while let Some(event) = conn.poll_endpoint_events() {
                    endpoint_events.push((*ch, event));
                }
            }
            let more = !endpoint_events.is_empty();
            self.apply_endpoint_events(endpoint_events);
            if !more {
                // Nothing was asked of the endpoint, so nothing can change for a datagram that is
                // waiting: another pass would only rebuild the same state. A held datagram stays
                // held for the next drive, which is what the driver does when it returns to the
                // scheduler. How long it may stay held is counted across drives, below.
                if waiting {
                    self.waiting_drives += 1;
                    assert!(
                        self.waiting_drives <= Self::WAITING_DRIVES,
                        "a datagram has waited for a route across {} drives with nothing left \
                         to install: its installation was refused or never asked for",
                        self.waiting_drives
                    );
                } else {
                    self.waiting_drives = 0;
                }
                break;
            }
        }
    }

    /// Hand each event to the endpoint and give the connection back whatever it answers.
    fn apply_endpoint_events(&mut self, events: Vec<(ConnectionHandle, EndpointEvent)>) {
        for (ch, event) in events {
            if let Some(event) = self.handle_event(ch, event) {
                // Only identifier issuance is held by that seam, however it was asked for; a
                // route acknowledgement withheld here would stop the connection sending at all.
                if self.hold_identifiers && event.is_new_identifiers() {
                    self.held_identifiers.push((ch, event));
                } else if let Some(conn) = self.connections.get_mut(&ch) {
                    conn.handle_event(event);
                }
            }
        }
    }

    /// Hand the connection the identifiers held back so far; the next drive sends them.
    pub(super) fn release_held_identifiers(&mut self) {
        self.hold_identifiers = false;
        for (ch, event) in std::mem::take(&mut self.held_identifiers) {
            if let Some(conn) = self.connections.get_mut(&ch) {
                conn.handle_event(event);
            }
        }
    }

    pub(super) fn next_wakeup(&self) -> Option<Instant> {
        let next_inbound = self.inbound.front().map(|x| x.at);
        min_opt(self.timeout, next_inbound)
    }

    pub(super) fn is_idle(&self) -> bool {
        self.connections.values().all(|x| x.is_idle())
    }

    pub(super) fn delay_outbound(&mut self) {
        assert!(self.delayed.is_empty());
        mem::swap(&mut self.delayed, &mut self.outbound);
    }

    pub(super) fn finish_delay(&mut self) {
        self.outbound.extend(self.delayed.drain(..));
    }

    pub(super) fn try_accept(
        &mut self,
        incoming: Incoming,
        now: Instant,
    ) -> Result<ConnectionHandle, ConnectionError> {
        let mut buf = Vec::new();
        match self.endpoint.accept(incoming, now, &mut buf, None) {
            Ok((ch, conn)) => {
                self.connections.insert(ch, conn);
                self.accepted = Some(Ok(ch));
                Ok(ch)
            }
            Err(error) => {
                if let Some(transmit) = error.response {
                    let size = transmit.size;
                    self.outbound.extend(split_transmit(transmit, &buf[..size]));
                }
                self.accepted = Some(Err(error.cause.clone()));
                Err(error.cause)
            }
        }
    }

    pub(super) fn retry(&mut self, incoming: Incoming) {
        let mut buf = Vec::new();
        let transmit = self.endpoint.retry(incoming, &mut buf).unwrap();
        let size = transmit.size;
        self.outbound.extend(split_transmit(transmit, &buf[..size]));
    }

    pub(super) fn reject(&mut self, incoming: Incoming) {
        let mut buf = Vec::new();
        let transmit = self.endpoint.refuse(incoming, &mut buf);
        let size = transmit.size;
        self.outbound.extend(split_transmit(transmit, &buf[..size]));
    }

    pub(super) fn assert_accept(&mut self) -> ConnectionHandle {
        self.accepted
            .take()
            .expect("server didn't try connecting")
            .expect("server experienced error connecting")
    }

    pub(super) fn assert_accept_error(&mut self) -> ConnectionError {
        self.accepted
            .take()
            .expect("server didn't try connecting")
            .expect_err("server did unexpectedly connect without error")
    }

    pub(super) fn assert_no_accept(&self) {
        assert!(self.accepted.is_none(), "server did unexpectedly connect")
    }
}

impl ::std::ops::Deref for TestEndpoint {
    type Target = Endpoint;
    fn deref(&self) -> &Endpoint {
        &self.endpoint
    }
}

impl ::std::ops::DerefMut for TestEndpoint {
    fn deref_mut(&mut self) -> &mut Endpoint {
        &mut self.endpoint
    }
}

pub(super) fn subscribe() -> rama_core::telemetry::tracing::subscriber::DefaultGuard {
    let builder = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(rama_core::telemetry::tracing::Level::TRACE)
        .with_writer(|| TestWriter);
    // tracing uses std::time to trace time, which panics in wasm.
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    let builder = builder.without_time();
    rama_core::telemetry::tracing::subscriber::set_default(builder.finish())
}

struct TestWriter;

impl Write for TestWriter {
    #[expect(clippy::print_stdout, reason = "test log output")]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        print!(
            "{}",
            str::from_utf8(buf).expect("tried to log invalid UTF-8")
        );
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

pub(super) fn server_config() -> ServerConfig {
    ServerConfig::with_crypto(Arc::new(server_crypto()))
}

pub(super) fn server_config_with_cert(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> ServerConfig {
    let mut config = ServerConfig::with_crypto(Arc::new(server_crypto_with_cert(cert, key)));
    config
        .validation_token
        .sent(2)
        .log(Arc::new(SimpleTokenLog::default()));
    config
}

pub(super) fn server_crypto() -> QuicServerConfig {
    server_crypto_inner(None, None)
}

pub(super) fn server_crypto_with_alpn(alpn: Vec<Vec<u8>>) -> QuicServerConfig {
    server_crypto_inner(None, Some(alpn))
}

pub(super) fn server_crypto_with_cert(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> QuicServerConfig {
    server_crypto_inner(Some((cert, key)), None)
}

fn server_crypto_inner(
    identity: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
    alpn: Option<Vec<Vec<u8>>>,
) -> QuicServerConfig {
    server_crypto_with_provider(test_provider(), identity, alpn)
}

pub(super) fn server_crypto_with_provider(
    provider: Arc<rama_tls_rustls::dep::rustls::crypto::CryptoProvider>,
    identity: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
    alpn: Option<Vec<Vec<u8>>>,
) -> QuicServerConfig {
    let (cert, key) = identity.unwrap_or_else(|| {
        (
            CERTIFIED_KEY.cert.der().clone(),
            PrivateKeyDer::Pkcs8(CERTIFIED_KEY.signing_key.serialize_der().into()),
        )
    });

    let mut config = rama_tls_rustls::dep::rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rama_tls_rustls::dep::rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.max_early_data_size = u32::MAX;
    if let Some(alpn) = alpn {
        config.alpn_protocols = alpn;
    }

    config.try_into().unwrap()
}

/// The configured provider restricted to a classic X25519 key exchange
///
/// The simulator tests assert exact packet/event sequences, which depend on handshake flight
/// sizes; post-quantum key shares (preferred by the `aws-lc` provider) roughly double the
/// ClientHello and would make those sequences provider dependent.
pub(super) fn test_provider() -> Arc<rama_tls_rustls::dep::rustls::crypto::CryptoProvider> {
    let mut provider = Arc::unwrap_or_clone(configured_provider());
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    let x25519 = rama_tls_rustls::dep::rustls::crypto::aws_lc_rs::kx_group::X25519;
    #[cfg(feature = "ring")]
    let x25519 = rama_tls_rustls::dep::rustls::crypto::ring::kx_group::X25519;
    provider.kx_groups = vec![x25519];
    Arc::new(provider)
}

pub(super) fn client_config() -> ClientConfig {
    ClientConfig::new(Arc::new(client_crypto()))
}

pub(super) fn client_config_with_deterministic_pns() -> ClientConfig {
    let mut cfg = ClientConfig::new(Arc::new(client_crypto()));
    let mut transport = TransportConfig::default();
    transport.deterministic_packet_numbers(true);
    cfg.transport = Arc::new(transport);
    cfg
}

pub(super) fn client_config_with_certs(certs: Vec<CertificateDer<'static>>) -> ClientConfig {
    ClientConfig::new(Arc::new(client_crypto_inner(Some(certs), None)))
}

pub(super) fn client_crypto() -> QuicClientConfig {
    client_crypto_inner(None, None)
}

pub(super) fn client_crypto_with_alpn(protocols: Vec<Vec<u8>>) -> QuicClientConfig {
    client_crypto_inner(None, Some(protocols))
}

fn client_crypto_inner(
    certs: Option<Vec<CertificateDer<'static>>>,
    alpn: Option<Vec<Vec<u8>>>,
) -> QuicClientConfig {
    client_crypto_with_provider(test_provider(), certs, alpn)
}

pub(super) fn client_crypto_with_provider(
    provider: Arc<rama_tls_rustls::dep::rustls::crypto::CryptoProvider>,
    certs: Option<Vec<CertificateDer<'static>>>,
    alpn: Option<Vec<Vec<u8>>>,
) -> QuicClientConfig {
    let mut roots = rama_tls_rustls::dep::rustls::RootCertStore::empty();
    for cert in certs.unwrap_or_else(|| vec![CERTIFIED_KEY.cert.der().clone()]) {
        roots.add(cert).unwrap();
    }

    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let mut inner = rama_tls_rustls::dep::rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rama_tls_rustls::dep::rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    inner.enable_early_data = true;
    inner.key_log = Arc::new(KeyLogFile::new());
    if let Some(alpn) = alpn {
        inner.alpn_protocols = alpn;
    }

    inner.try_into().unwrap()
}

pub(super) fn min_opt<T: Ord>(x: Option<T>, y: Option<T>) -> Option<T> {
    match (x, y) {
        (Some(x), Some(y)) => Some(cmp::min(x, y)),
        (Some(x), _) => Some(x),
        (_, Some(y)) => Some(y),
        _ => None,
    }
}

/// The maximum of datagrams TestEndpoint will produce via `poll_transmit`
const MAX_DATAGRAMS: usize = 10;

fn split_transmit(transmit: Transmit, buffer: &[u8]) -> Vec<(Transmit, Bytes)> {
    let mut buffer = Bytes::copy_from_slice(buffer);
    let segment_size = match transmit.segment_size {
        Some(segment_size) => segment_size,
        _ => return vec![(transmit, buffer)],
    };

    let mut transmits = Vec::new();
    while !buffer.is_empty() {
        let end = segment_size.min(buffer.len());

        let contents = buffer.split_to(end);
        transmits.push((
            Transmit {
                destination: transmit.destination,
                size: contents.len(),
                ecn: transmit.ecn,
                segment_size: None,
                local: transmit.local,
                cid_used: transmit.cid_used,
            },
            contents,
        ));
    }

    transmits
}

fn packet_size(transmit: &Transmit, buffer: &Bytes) -> usize {
    if transmit.segment_size.is_some() {
        panic!("This transmit is meant to be split into multiple packets!");
    }

    buffer.len()
}

fn set_congestion_experienced(
    x: Option<EcnCodepoint>,
    congestion_experienced: bool,
) -> Option<EcnCodepoint> {
    x.map(|codepoint| match congestion_experienced {
        true => EcnCodepoint::Ce,
        false => codepoint,
    })
}

#[derive(Default)]
struct SimpleTokenLog(Mutex<HashSet<u128>>);

impl TokenLog for SimpleTokenLog {
    fn check_and_insert(
        &self,
        nonce: u128,
        _issued: SystemTime,
        _lifetime: Duration,
    ) -> Result<(), TokenReuseError> {
        if self.0.lock().insert(nonce) {
            Ok(())
        } else {
            Err(TokenReuseError)
        }
    }
}

pub(crate) static SERVER_PORTS: LazyLock<Mutex<RangeFrom<u16>>> =
    LazyLock::new(|| Mutex::new(4433..));
pub(crate) static CLIENT_PORTS: LazyLock<Mutex<RangeFrom<u16>>> =
    LazyLock::new(|| Mutex::new(44433..));
pub(crate) static CERTIFIED_KEY: LazyLock<
    rama_crypto::dep::rcgen::CertifiedKey<rama_crypto::dep::rcgen::KeyPair>,
> = LazyLock::new(|| {
    rama_crypto::dep::rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap()
});
