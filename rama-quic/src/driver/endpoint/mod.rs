use rama_utils::octets;
use std::{
    fmt,
    future::Future,
    io,
    io::IoSliceMut,
    net::SocketAddr,
    pin::Pin,
    str,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use crate::driver::{
    Duration, QueuedPacket,
    connection::{ConnectionDriver, ConnectionInner, Control, EndpointLink},
    lifecycle::{Lifecycle, ShutdownOutcome},
    queue::{
        BoundedDeque, BoundedSender, INCOMING_OVERHEAD, PACKET_OVERHEAD, PacketBudget,
        PacketPermit, PacketQueueStats, Refusal, bounded_queue,
    },
    sockets::{Lease, RebindRefused, SocketId, SocketRegistry, Sockets},
    timer::{Deadline, DeadlineTimer},
};
use crate::driver::{
    Instant, now,
    udp::{Sender, Socket, proto_ecn},
};
use crate::proto::{
    self as proto, ClientConfig, ConnectError, ConnectionError, ConnectionHandle, DatagramEvent,
    EndpointEvent, ReceiveQueueLimits, ServerConfig,
};
use parking_lot::Mutex;
use pin_project_lite::pin_project;
use rama_core::bytes::{Bytes, BytesMut};
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{Instrument, Span};
use rama_net::address::{SocketAddress, ip::IntoCanonicalIpAddr as _};
#[cfg(any(feature = "aws-lc", feature = "ring"))]
use rama_net::socket::core::{Domain, Protocol, Socket as CoreSocket, Type};
use rama_udp::{
    DatagramError, DatagramMetadata, UdpPacketSocket, UdpSocketConfig, UdpSocketFactory,
};
use rustc_hash::FxHashMap;
use tokio::sync::{Notify, futures::Notified};

const BATCH_SIZE: usize = 32;

use crate::driver::{
    EndpointConfig, IO_LOOP_BOUND, RECV_TIME_BOUND, VarInt,
    connection::Connecting,
    incoming::Incoming,
    work_limiter::{WorkCycle, WorkLimiter},
};

/// A QUIC endpoint.
///
/// An endpoint corresponds to a single UDP socket, may host many connections, and may act as both
/// client and server for different connections.
///
/// May be cloned to obtain another handle to the same endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub(crate) inner: EndpointRef,
    pub(crate) default_client_config: Option<ClientConfig>,
}

impl Endpoint {
    /// Helper to construct an endpoint for use with outgoing connections only
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually be a wildcard
    /// address like `0.0.0.0:0` or `[::]:0`, which allow communication with any reachable IPv4 or
    /// IPv6 address respectively from an OS-assigned port.
    ///
    /// If an IPv6 address is provided, attempts to make the socket dual-stack so as to allow
    /// communication with both IPv4 and IPv6 addresses. As such, calling `Endpoint::client` with
    /// the address `[::]:0` is a reasonable default to maximize the ability to connect to other
    /// address. For example:
    ///
    /// ```
    /// Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into());
    /// ```
    ///
    /// Some environments may not allow creation of dual-stack sockets, in which case an IPv6
    /// client will only be able to connect to IPv6 servers. An IPv4 client is never dual-stack.
    #[cfg(any(feature = "aws-lc", feature = "ring"))] // `EndpointConfig::default()` is only available with these
    pub async fn client(address: impl Into<SocketAddress>) -> Result<Self, DatagramError> {
        let address = address.into();
        Self::bind(
            EndpointConfig::default(),
            None,
            address,
            client_socket_config(address),
        )
        .await
    }

    /// Bind an endpoint through Rama's shared UDP construction.
    ///
    /// `socket` carries the socket options to bind with and the packet features this endpoint
    /// requires; a feature the platform does not provide fails the call.
    pub async fn bind(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        address: impl Into<SocketAddress>,
        socket: UdpSocketConfig,
    ) -> Result<Self, DatagramError> {
        let factory = UdpSocketFactory::new(socket);
        let listener = factory.bind(address.into()).await?;
        // The addresses this server advertises as preferred are bound first, so the engine
        // advertises the addresses the sockets actually have, ports the platform assigned
        // included.
        let (server_config, advertised) = bind_advertised(&factory, server_config).await?;
        let advertised = advertised
            .into_iter()
            .map(Socket::new)
            .collect::<io::Result<Vec<_>>>()?;
        Self::new_with_advertised(
            config,
            server_config,
            Socket::new(listener)?,
            advertised,
            Executor::new(),
            Duration::from_secs(5),
        )
        .map_err(DatagramError::from)
    }

    /// Take ownership of a packet socket the caller prepared, bound to an address this endpoint
    /// advertises as its preferred one (RFC 9000 §9.6). Datagrams for a connection that moved
    /// there leave from this socket.
    pub fn advertise_socket(&self, socket: UdpPacketSocket) -> Result<(), DatagramError> {
        self.advertise_abstract(Socket::new(socket).map_err(DatagramError::from)?)
    }

    /// Take ownership of one socket bound to an address this endpoint advertises, given as our
    /// own abstraction: a socket with state of its own, or a test socket.
    pub(crate) fn advertise_abstract(&self, socket: Socket) -> Result<(), DatagramError> {
        let mut state = self.inner.state.lock();
        let Some(registry) = state.sockets.live_mut() else {
            drop(state);
            drop(socket);
            return Err(DatagramError::Io(io::ErrorKind::NotConnected.into()));
        };
        match registry.advertise(socket) {
            Ok(_) => {
                // A driver that has already parked has never polled this socket, so traffic
                // arriving only there would wake nothing.
                state.wake_driver();
                Ok(())
            }
            Err(refused) => {
                // The refused socket is dropped outside the endpoint lock.
                drop(state);
                drop(refused.socket);
                Err(DatagramError::Io(refused.error))
            }
        }
    }

    /// Construct an endpoint on a packet socket the caller prepared, for example through
    /// [`UdpSocketConfig::wrap_std`](rama_udp::UdpSocketConfig::wrap_std), which is where the
    /// packet metadata is set up and the required features are validated.
    pub fn with_packet_socket(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: UdpPacketSocket,
    ) -> io::Result<Self> {
        Self::new_with_abstract_socket(config, server_config, Socket::new(socket)?)
    }

    /// Tests: the addresses this endpoint still advertises as preferred.
    #[cfg(test)]
    pub(crate) fn advertised_preferred(&self) -> Vec<SocketAddr> {
        self.inner.state.lock().inner.advertised_preferred()
    }

    /// Returns relevant stats from this Endpoint
    pub fn stats(&self) -> EndpointStats {
        let state = self.inner.state.lock();
        EndpointStats {
            received_datagrams: state.recv_state.received_datagrams,
            truncated_receive_entries: state.recv_state.truncated_receive_entries,
            ignored_receive_errors: state.recv_state.ignored_receive_errors,
            dropped_responses: state.sockets.dropped_responses(),
            failed_responses: state.sockets.failed_responses(),
            dropped_packets: state.recv_state.dropped_packets,
            receive_queue: state.packet_budget.stats(),
            incoming_queue_capacity: state.recv_state.incoming.capacity(),
            retained_sockets: state.sockets.retained_sockets(),
            retired_sockets: state.sockets.retired_sockets(),
            ..state.stats
        }
    }

    /// Helper to construct an endpoint for use with both incoming and outgoing connections
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    #[cfg(any(feature = "aws-lc", feature = "ring"))] // `EndpointConfig::default()` is only available with these
    pub async fn server(
        config: ServerConfig,
        address: impl Into<SocketAddress>,
    ) -> Result<Self, DatagramError> {
        // The platform's own defaults: no dual-stack option is requested for a server, so an IPv6
        // wildcard reaches IPv4 peers only where the platform says it does.
        Self::bind(
            EndpointConfig::default(),
            Some(config),
            address,
            UdpSocketConfig::default(),
        )
        .await
    }

    /// Construct an endpoint on a bound standard socket.
    ///
    /// The packet metadata a [`UdpSocketConfig`](rama_udp::UdpSocketConfig) describes is not set
    /// up here; a caller that needs it wraps the socket with that configuration first and uses
    /// [`with_packet_socket`](Self::with_packet_socket).
    pub fn with_std_socket(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: std::net::UdpSocket,
    ) -> io::Result<Self> {
        Self::new_with_abstract_socket(config, server_config, Socket::from_std(socket)?)
    }

    /// Construct an endpoint with arbitrary configuration and pre-constructed abstract socket
    ///
    /// Useful when `socket` has additional state (e.g. sidechannels) attached for which shared
    /// ownership is needed.
    pub(crate) fn new_with_abstract_socket(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: Socket,
    ) -> io::Result<Self> {
        Self::new_with_executor(
            config,
            server_config,
            socket,
            Executor::new(),
            Duration::from_secs(5),
        )
    }

    /// Construct an endpoint whose drivers and lifecycle supervisor run on the current Tokio
    /// runtime through Rama's shared spawn utilities.
    ///
    /// Fails outside a Tokio runtime context.
    pub(crate) fn new_with_executor(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: Socket,
        executor: Executor,
        shutdown_budget: Duration,
    ) -> io::Result<Self> {
        Self::new_with_advertised(
            config,
            server_config,
            socket,
            Vec::new(),
            executor,
            shutdown_budget,
        )
    }

    /// The same, with sockets bound to the addresses this endpoint advertises as preferred. They
    /// are in the registry before the driver is spawned, so its first poll covers them and
    /// traffic that arrives only there needs no wake to be seen.
    pub(crate) fn new_with_advertised(
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        socket: Socket,
        advertised: Vec<Socket>,
        executor: Executor,
        shutdown_budget: Duration,
    ) -> io::Result<Self> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(io::Error::other("no async runtime found"));
        }
        if config.handshake_timeout.is_zero()
            || now().checked_add(config.handshake_timeout).is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid QUIC handshake timeout",
            ));
        }
        let largest_payload =
            usize::try_from(config.get_max_udp_payload_size()).unwrap_or(usize::MAX);
        let connection = config.connection_receive_queue;
        let endpoint = config.endpoint_receive_queue;
        if connection.bytes() < largest_payload.saturating_add(PACKET_OVERHEAD)
            || endpoint.bytes() < connection.bytes()
            || endpoint.bytes() < largest_payload.saturating_add(INCOMING_OVERHEAD)
            || endpoint.datagrams() < connection.datagrams()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC receive queue limits must hold one maximum-size datagram per connection and one incoming attempt",
            ));
        }
        let addr = socket.local_addr();
        let allow_mtud = !socket.capabilities().may_fragment;
        let rc = EndpointRef::new(
            socket,
            crate::proto::Endpoint::new(
                Arc::new(config),
                server_config.map(Arc::new),
                allow_mtud,
                None,
            ),
            addr.is_ipv6(),
        );
        {
            let mut state = rc.0.state.lock();
            let mut refused = Vec::new();
            let mut error = None;
            match state.sockets.live_mut() {
                Some(registry) => {
                    for socket in advertised {
                        match registry.advertise(socket) {
                            Ok(_) => {}
                            Err(rejected) => {
                                refused.push(rejected.socket);
                                error = Some(rejected.error);
                            }
                        }
                    }
                }
                None => {
                    refused.extend(advertised);
                    error = Some(io::Error::from(io::ErrorKind::NotConnected));
                }
            }
            drop(state);
            // A refused socket is dropped outside the endpoint lock, and the endpoint is not
            // built: it would otherwise advertise an address it does not own.
            drop(refused);
            if let Some(error) = error {
                return Err(error);
            }
        }
        let driver = EndpointDriver(rc.0.clone());
        let driver_lifecycle = rc.shared.lifecycle.clone();
        rc.shared.lifecycle.spawn(Box::pin(
            async move {
                if let Err(e) = driver.await {
                    driver_lifecycle.failed();
                    rama_core::telemetry::tracing::error!("I/O error: {}", e);
                }
            }
            .instrument(Span::current()),
        ));
        let lifecycle = rc.shared.lifecycle.clone();
        let inner = rc.0.clone();
        let cancellation = executor.guard().map(|guard| guard.clone_weak());
        executor.into_spawn_task(async move {
            let cancel = async {
                match cancellation {
                    Some(guard) => guard.cancelled().await,
                    None => std::future::pending().await,
                }
            };
            let stop = tokio::select! {
                _ = lifecycle.join() => false,
                _ = lifecycle.requested() => true,
                _ = cancel => true,
            };
            let mut forced = false;
            if stop {
                {
                    let mut state = inner.state.lock();
                    state.shutdown = true;
                    state.close(VarInt::from_u32(0), Bytes::new(), &inner.shared);
                }
                if tokio::time::timeout(shutdown_budget, lifecycle.join())
                    .await
                    .is_err()
                {
                    forced = true;
                    lifecycle.abort();
                    lifecycle.join().await;
                }
            }
            // Drivers deliver their Drained events synchronously, so every engine connection
            // is already retired once all drivers have joined.
            loop {
                {
                    let mut state = inner.state.lock();
                    let before = state.inner.pending_incoming();
                    state.inner.discard_incoming(IO_LOOP_BOUND);
                    let after = state.inner.pending_incoming();
                    if after == 0 {
                        break;
                    }
                    if after >= before {
                        // The deadline index lost track of live admissions: release everything
                        // that is left in one pass and report the failure instead of spinning.
                        state.inner.discard_all_incoming();
                        lifecycle.failed();
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
            lifecycle.finish(forced);
        });
        Ok(Self {
            inner: rc,
            default_client_config: None,
        })
    }

    /// Get the next incoming connection attempt from a client
    ///
    /// Yields [`Incoming`]s, or `None` if the endpoint is [`close`](Self::close)d. [`Incoming`]
    /// can be `await`ed to obtain the final [`Connection`](crate::driver::Connection), or used to e.g.
    /// filter connection attempts or force address validation, or converted into an intermediate
    /// `Connecting` future which can be used to e.g. send 0.5-RTT data.
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            endpoint: self,
            notify: self.inner.shared.incoming.notified(),
        }
    }

    /// Set the client configuration used by `connect`
    pub fn set_default_client_config(&mut self, config: ClientConfig) {
        self.default_client_config = Some(config);
    }

    /// Connect to a remote endpoint
    ///
    /// `server_name` must be covered by the certificate presented by the server. This prevents a
    /// connection from being intercepted by an attacker with a valid certificate for some other
    /// server.
    ///
    /// May fail immediately due to configuration errors, or in the future if the connection could
    /// not be established.
    pub fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Connecting, ConnectError> {
        let config = match &self.default_client_config {
            Some(config) => config.clone(),
            None => return Err(ConnectError::NoDefaultClientConfig),
        };

        self.connect_with(config, addr, server_name)
    }

    /// Connect to a remote endpoint using a custom configuration.
    ///
    /// See [`connect()`] for details.
    ///
    /// [`connect()`]: Endpoint::connect
    pub fn connect_with(
        &self,
        config: ClientConfig,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connecting, ConnectError> {
        let mut endpoint = self.inner.state.lock();
        if endpoint.driver_lost || endpoint.recv_state.connections.close.is_some() {
            return Err(ConnectError::EndpointStopping);
        }
        let addr: SocketAddr = SocketAddress::from(addr).into_canonical_ip_addr().into();
        if addr.is_ipv6() && !endpoint.ipv6 {
            return Err(ConnectError::InvalidRemoteAddress(addr));
        }

        // New connections send from the active socket; the sender registers its dependence.
        let socket = endpoint
            .sockets
            .live_mut()
            .and_then(|sockets| {
                let id = sockets.active_id();
                sockets.sender(id)
            })
            .ok_or(ConnectError::EndpointStopping)?;
        let now = now();
        let (ch, conn) = match endpoint.inner.connect(now, config, addr, server_name) {
            Ok(registered) => registered,
            Err(error) => {
                // The unused send handle and any socket it retired are dropped after unlocking.
                let mut socket = socket;
                let retired = socket
                    .take_lease()
                    .and_then(|lease| endpoint.sockets.release(lease, now));
                drop(endpoint);
                drop(retired);
                drop(socket);
                return Err(error);
            }
        };

        endpoint.stats.outgoing_handshakes += 1;
        let (connecting, driver) = endpoint.recv_state.connections.insert(
            ch,
            conn,
            socket,
            EndpointLink::new(Arc::downgrade(&self.inner.0), ch),
        );
        // Supervision is reserved before the registration lock is released, and the driver
        // is submitted with no lock held (see `ConnectionDriver::spawn`).
        let slot = self.inner.shared.lifecycle.reserve();
        drop(endpoint);
        driver.spawn(slot);
        Ok(connecting)
    }

    /// Bind a new socket through Rama's shared UDP construction and switch to it.
    ///
    /// See [`Endpoint::rebind_abstract()`] for what the switch means for existing connections. On
    /// error nothing changes and the previous socket stays active.
    pub async fn rebind(
        &self,
        address: impl Into<SocketAddress>,
        socket: UdpSocketConfig,
    ) -> Result<(), DatagramError> {
        let socket = UdpSocketFactory::new(socket).bind(address.into()).await?;
        self.rebind_packet_socket(socket)
            .map_err(DatagramError::from)
    }

    /// Switch to a packet socket the caller prepared.
    pub fn rebind_packet_socket(&self, socket: UdpPacketSocket) -> io::Result<()> {
        self.rebind_abstract(Socket::new(socket)?)
    }

    /// Switch to a bound standard socket.
    pub fn rebind_std_socket(&self, socket: std::net::UdpSocket) -> io::Result<()> {
        self.rebind_abstract(Socket::from_std(socket)?)
    }

    /// Switch to a new UDP socket
    ///
    /// New connections and attempts use the new socket at once. Each existing connection moves
    /// to it only when QUIC allows the address change (RFC 9000 §9): a socket bound to the same
    /// address is adopted right away; a client whose handshake is confirmed, whose peer allows
    /// active migration and that holds an unused destination connection ID migrates after
    /// finishing any partially sent transmit; a client still handshaking or without an unused
    /// connection ID migrates once it has both; server connections and clients whose peer
    /// disabled active migration keep sending from their current socket.
    /// A replaced socket stays open while connections, queued attempts, queued responses or a
    /// recent Retry depend on it, up to a bounded number of retained sockets.
    ///
    /// On error, nothing changes and the previous socket stays active.
    pub(crate) fn rebind_abstract(&self, socket: Socket) -> io::Result<()> {
        let addr = socket.local_addr();
        let mut inner = self.inner.state.lock();
        let now = now();
        // A refused socket is dropped only after the lock is released (see below).
        if inner.driver_lost || inner.shutdown {
            drop(inner);
            drop(socket);
            return Err(io::ErrorKind::NotConnected.into());
        }
        let State {
            sockets,
            recv_state,
            ..
        } = &mut *inner;
        let Some(sockets) = sockets.live_mut() else {
            drop(inner);
            drop(socket);
            return Err(io::ErrorKind::NotConnected.into());
        };
        // The previous socket stays registered while connections, queued attempts, queued
        // responses or a Retry route depend on it; a rebind beyond the retained bound fails
        // without any change.
        let (id, retired) = match sockets.activate(socket, now) {
            Ok(activated) => activated,
            Err(RebindRefused { error, socket }) => {
                drop(inner);
                drop(socket);
                return Err(error);
            }
        };
        let mut senders = Vec::with_capacity(recv_state.connections.channels.len());
        for handle in recv_state.connections.channels.keys() {
            if let Some(sender) = sockets.sender(id) {
                senders.push((*handle, sender));
            }
        }
        // Each connection completes its in-flight transmit on its current sender before it
        // switches, and releases the old socket once it has switched.
        for (handle, sender) in senders {
            if let Some(channel) = inner.recv_state.connections.channels.get(&handle) {
                channel.inner.control(Control::Rebind(sender));
            }
        }
        inner.ipv6 = addr.is_ipv6();
        if let Some(driver) = inner.driver.take() {
            // Ensure the driver can register for wake-ups from the new socket
            driver.wake();
        }
        drop(inner);
        // A previous socket nothing depended on is dropped here, outside the endpoint lock.
        drop(retired);
        Ok(())
    }

    /// Replace the server configuration, affecting new incoming connections only
    ///
    /// Useful for e.g. refreshing TLS certificates without disrupting existing connections.
    pub fn set_server_config(&self, server_config: Option<ServerConfig>) {
        self.inner
            .state
            .lock()
            .inner
            .set_server_config(server_config.map(Arc::new))
    }

    /// Get the local `SocketAddr` the underlying socket is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner
            .state
            .lock()
            .sockets
            .live()
            .map(|sockets| sockets.active().local_addr())
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }

    /// Local addresses of every retained socket, the active one first.
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        let state = self.inner.state.lock();
        state
            .sockets
            .live()
            .map(|sockets| {
                sockets
                    .ids()
                    .filter_map(|id| sockets.local_addr(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the number of connections that are currently open
    pub fn open_connections(&self) -> usize {
        self.inner.state.lock().inner.open_connections()
    }

    /// Close all of this endpoint's connections immediately and cease accepting new connections.
    ///
    /// See [`Connection::close()`] for details.
    ///
    /// [`Connection::close()`]: crate::driver::Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.inner.state.lock().close(
            error_code,
            Bytes::copy_from_slice(reason),
            &self.inner.shared,
        );
    }

    /// Stop the endpoint and join all drivers, releasing sockets even with retained handles.
    pub async fn shutdown(&self) -> ShutdownOutcome {
        self.inner.shared.lifecycle.request();
        self.inner.shared.lifecycle.completed().await
    }

    /// Wait for all connections on the endpoint to be cleanly shut down
    ///
    /// Waiting for this condition before exiting ensures that a good-faith effort is made to notify
    /// peers of recent connection closes, whereas exiting immediately could force them to wait out
    /// the idle timeout period.
    ///
    /// Does not proactively close existing connections or cause incoming connections to be
    /// rejected. Consider calling [`close()`] if that is desired.
    ///
    /// [`close()`]: Endpoint::close
    pub async fn wait_idle(&self) {
        loop {
            {
                let endpoint = &mut *self.inner.state.lock();
                if endpoint.recv_state.connections.is_empty() {
                    break;
                }
                // Construct future while lock is held to avoid race
                self.inner.shared.idle.notified()
            }
            .await;
        }
    }
}

/// Statistics on [Endpoint] activity
#[non_exhaustive]
#[derive(Debug, Default, Copy, Clone)]
pub struct EndpointStats {
    /// Cumulative number of Quic handshakes accepted by this [Endpoint]
    pub accepted_handshakes: u64,
    /// Cumulative number of Quic handshakees sent from this [Endpoint]
    pub outgoing_handshakes: u64,
    /// Cumulative number of Quic handshakes refused on this [Endpoint]
    pub refused_handshakes: u64,
    /// Cumulative number of Quic handshakes ignored on this [Endpoint]
    pub ignored_handshakes: u64,
    /// UDP datagrams passed to the protocol engine, including malformed QUIC packets.
    pub received_datagrams: u64,
    /// Entire receive entries discarded because at least one datagram was truncated.
    pub truncated_receive_entries: u64,
    /// Receive attempts that failed with a connection-reset error, ignored as attacker-injectable
    /// noise; counted apart from received datagrams.
    pub ignored_receive_errors: u64,
    /// Stateless responses dropped at the bounded outgoing queue.
    pub dropped_responses: u64,
    /// Stateless responses the socket refused for their destination.
    pub failed_responses: u64,
    /// Pending incoming handshakes expired before application acceptance.
    pub expired_incoming: u64,
    /// Received datagrams dropped because a receive queue was saturated.
    pub dropped_packets: u64,
    /// Occupancy and drop counters of the endpoint-wide receive queue budget.
    pub receive_queue: PacketQueueStats,
    /// Entries the queued-incoming container currently retains storage for.
    pub incoming_queue_capacity: usize,
    /// Sockets currently owned: the active one plus those still serving earlier work.
    pub retained_sockets: usize,
    /// Sockets retired so far after their last dependent went away.
    pub retired_sockets: u64,
}

/// A future that drives IO on an endpoint
///
/// This task functions as the switch point between the UDP socket object and the
/// `Endpoint` responsible for routing datagrams to their owning `Connection`.
/// In order to do so, it also facilitates the exchange of different types of events
/// flowing between the `Endpoint` and the tasks managing `Connection`s. As such,
/// running this task is necessary to keep the endpoint's connections running.
///
/// `EndpointDriver` futures terminate when all clones of the `Endpoint` have been dropped, or when
/// an I/O error occurs.
#[must_use = "endpoint drivers must be spawned for I/O to occur"]
#[derive(Debug)]
pub(crate) struct EndpointDriver(pub(crate) Arc<EndpointInner>);

impl Future for EndpointDriver {
    type Output = Result<(), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        // Sockets retired during this poll outlive the lock: they are dropped here, after the
        // locked part returned, on the success and the error path alike.
        let mut retired = Vec::new();
        let outcome = self.poll_locked(cx, &mut retired);
        drop(retired);
        match outcome {
            Ok(Some(keep_going)) => {
                // If there is more work to do schedule the endpoint task again.
                // `wake_by_ref()` is called outside the lock to minimize
                // lock contention on a multithreaded runtime.
                if keep_going {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Ok(None) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl EndpointDriver {
    /// One poll under the endpoint lock. `Ok(Some(keep_going))` keeps the driver alive,
    /// `Ok(None)` finishes it. Retired sockets are pushed to `retired` for the caller to drop
    /// outside the lock, which this method never holds when it returns.
    fn poll_locked(&self, cx: &mut Context, retired: &mut Vec<Socket>) -> io::Result<Option<bool>> {
        let mut endpoint = self.0.state.lock();
        if endpoint.driver.is_none() {
            endpoint.driver = Some(cx.waker().clone());
        }

        let now = now();
        let mut keep_going = false;
        keep_going |= endpoint.drive_recv(cx, now, retired)?;
        keep_going |= endpoint.drive_incoming_timeout(cx, now, retired);
        keep_going |= endpoint.drive_route_expiry(cx, now, retired);
        if let Some(sockets) = endpoint.sockets.live_mut() {
            let driven = sockets.drive_responses(cx, now)?;
            keep_going |= driven.keep_going;
            retired.extend(driven.retired);
        }
        endpoint.leave_failed_sockets(now, retired);

        if !endpoint.recv_state.incoming.is_empty() {
            self.0.shared.incoming.notify_waiters();
        }

        let finished = (self.0.shared.ref_count.load(Ordering::Relaxed) == 0 || endpoint.shutdown)
            && endpoint.recv_state.connections.is_empty();
        Ok((!finished).then_some(keep_going))
    }
}

impl Drop for EndpointDriver {
    fn drop(&mut self) {
        let mut endpoint = self.0.state.lock();
        endpoint.driver_lost = true;
        endpoint.incoming_timer.clear();
        endpoint.route_timer.clear();
        // Every socket is released here regardless of retained handles: nothing may keep a
        // bound port alive after the driver is gone.
        let sockets = endpoint.sockets.release_all();
        while let Some(queued) = endpoint.recv_state.incoming.pop_front() {
            endpoint.inner.ignore(queued.incoming);
        }
        self.0.shared.idle.notify_waiters();
        self.0.shared.incoming.notify_waiters();
        // Closing the packet channels tells every connection driver that the endpoint is gone.
        // Connection state is released outside the endpoint lock (lock order).
        let channels = std::mem::take(&mut endpoint.recv_state.connections.channels);
        drop(endpoint);
        drop(channels);
        drop(sockets);
    }
}

/// The address a bound packet socket has.
fn bound_address(socket: &UdpPacketSocket) -> Result<SocketAddr, DatagramError> {
    rama_net::stream::Socket::local_addr(socket)
        .map(SocketAddr::from)
        .map_err(DatagramError::Io)
}

/// Bind a socket for each preferred address this server configuration advertises, and return the
/// configuration with those addresses replaced by the ones the sockets are bound to.
///
/// A configured address that cannot be bound fails: it is an explicit option, and advertising an
/// address this endpoint does not own would send clients somewhere nothing answers.
async fn bind_advertised(
    factory: &UdpSocketFactory,
    server_config: Option<ServerConfig>,
) -> Result<(Option<ServerConfig>, Vec<UdpPacketSocket>), DatagramError> {
    let Some(mut server_config) = server_config else {
        return Ok((None, Vec::new()));
    };
    let mut sockets = Vec::new();
    if let Some(address) = server_config.preferred_address_v4 {
        // A wildcard address is not a destination a client can be sent to: resolving the port
        // leaves the address unspecified, so it is refused rather than advertised.
        if address.ip().is_unspecified() {
            return Err(DatagramError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a preferred address must be a concrete address a peer can reach, not a wildcard",
            )));
        }
        let socket = factory.bind(SocketAddr::from(address)).await?;
        match bound_address(&socket)? {
            SocketAddr::V4(bound) if !bound.ip().is_unspecified() => {
                server_config.preferred_address_v4 = Some(bound);
            }
            SocketAddr::V4(bound) => {
                return Err(DatagramError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("the preferred IPv4 address bound as the unspecified {bound}"),
                )));
            }
            SocketAddr::V6(bound) => {
                return Err(DatagramError::Io(io::Error::other(format!(
                    "the preferred IPv4 address bound as {bound}"
                ))));
            }
        }
        sockets.push(socket);
    }
    if let Some(address) = server_config.preferred_address_v6 {
        if address.ip().is_unspecified() {
            return Err(DatagramError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a preferred address must be a concrete address a peer can reach, not a wildcard",
            )));
        }
        let socket = factory.bind(SocketAddr::from(address)).await?;
        match bound_address(&socket)? {
            SocketAddr::V6(bound) if !bound.ip().is_unspecified() => {
                server_config.preferred_address_v6 = Some(bound);
            }
            SocketAddr::V6(bound) => {
                return Err(DatagramError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("the preferred IPv6 address bound as the unspecified {bound}"),
                )));
            }
            SocketAddr::V4(bound) => {
                return Err(DatagramError::Io(io::Error::other(format!(
                    "the preferred IPv6 address bound as {bound}"
                ))));
            }
        }
        sockets.push(socket);
    }
    Ok((Some(server_config), sockets))
}

/// The socket configuration a client binds with: Rama's UDP defaults, plus a request for a
/// dual-stack socket on an IPv6 address that the platform may refuse. A refusal leaves the
/// platform's own `IPV6_V6ONLY` default in place and the socket bound.
fn client_socket_config(address: SocketAddress) -> UdpSocketConfig {
    let mut config = UdpSocketConfig::default();
    if address.ip_addr.is_ipv6() {
        let mut options = config.socket_options().clone();
        options.only_v6_best_effort = Some(false);
        config.set_socket_options(options);
    }
    config
}

#[derive(Debug)]
pub(crate) struct EndpointInner {
    pub(crate) state: Mutex<State>,
    pub(crate) shared: Shared,
}

impl EndpointInner {
    /// Apply events a connection driver produced, after that driver released its own lock.
    ///
    /// Nothing is queued: identifiers issued in response reach the connection through
    /// [`ConnectionInner::control`] before this returns, and Drained retires the connection
    /// from the table exactly once.
    pub(crate) fn connection_events(&self, handle: ConnectionHandle, events: Vec<EndpointEvent>) {
        let mut state = self.state.lock();
        let mut retired = None;
        for event in events {
            #[cfg(test)]
            if state.hold_route_installs && event.is_reset_route() {
                state.held_route_installs.push((handle, event));
                continue;
            }
            if event.is_drained() {
                retired = state.recv_state.connections.channels.remove(&handle);
                if state.recv_state.connections.is_empty() {
                    self.shared.idle.notify_waiters();
                    if let Some(driver) = state.driver.take() {
                        driver.wake();
                    }
                }
            }
            if let Some(control) = state.inner.handle_event(handle, event)
                && let Some(channel) = state.recv_state.connections.channels.get(&handle)
            {
                channel.inner.control(Control::Proto(control));
            }
        }
        drop(state);
        // The retired connection's state is released outside the endpoint lock (lock order).
        drop(retired);
    }
}

/// What this endpoint can offer a connection whose path has moved to a local address.
#[derive(Debug)]
pub(crate) enum LocalSocket {
    /// A socket bound to exactly that address; the handle owns a lease on it.
    Owned(crate::driver::udp::Sender),
    /// No socket is bound to that address, but the one the connection already sends from is
    /// bound to a wildcard of that port and family and can select a source address per datagram,
    /// so it can carry that path.
    Covered,
    /// This endpoint owns no socket that can send from that address.
    Unowned,
}

impl EndpointInner {
    /// What this endpoint can offer for sending from `local`, given that the connection currently
    /// sends from the socket named `current`.
    pub(crate) fn socket_for_local(&self, local: SocketAddr, current: SocketId) -> LocalSocket {
        let mut state = self.state.lock();
        let Some(registry) = state.sockets.live_mut() else {
            return LocalSocket::Unowned;
        };
        if let Some(id) = registry.id_for_local(local)
            && let Some(sender) = registry.sender(id)
        {
            return LocalSocket::Owned(sender);
        }
        // The socket in use may already cover the address, in which case nothing changes. A
        // delayed datagram for a path this connection has left names an address another retained
        // socket covers instead, and that socket is the one it must leave from.
        if registry.covers_local(current, local) {
            return LocalSocket::Covered;
        }
        if let Some(id) = registry.only_cover_for(local)
            && let Some(sender) = registry.sender(id)
        {
            return LocalSocket::Owned(sender);
        }
        LocalSocket::Unowned
    }
}

impl EndpointRef {
    /// Tests: stop applying route installations, so a datagram that needs one can be observed
    /// waiting instead of leaving.
    #[cfg(test)]
    pub(crate) fn hold_route_installs(&self) {
        self.0.state.lock().hold_route_installs = true;
    }

    /// Tests: answer the route installations put aside with a refusal, as a full routing table
    /// does, so the connection fails rather than waiting for a route that cannot exist.
    #[cfg(test)]
    pub(crate) fn refuse_route_installs(&self) {
        let mut state = self.0.state.lock();
        state.hold_route_installs = false;
        let held = std::mem::take(&mut state.held_route_installs);
        for (handle, event) in held {
            let Some(refusal) = event.route_refusal() else {
                continue;
            };
            if let Some(channel) = state.recv_state.connections.channels.get(&handle) {
                channel.inner.control(Control::Proto(refusal));
            }
        }
    }

    /// Tests: apply the route installations put aside, and hand each connection the
    /// acknowledgement the endpoint answers with, as it would have received it otherwise.
    #[cfg(test)]
    pub(crate) fn release_route_installs(&self) {
        let mut state = self.0.state.lock();
        state.hold_route_installs = false;
        let held = std::mem::take(&mut state.held_route_installs);
        for (handle, event) in held {
            if let Some(control) = state.inner.handle_event(handle, event)
                && let Some(channel) = state.recv_state.connections.channels.get(&handle)
            {
                channel.inner.control(Control::Proto(control));
            }
        }
    }

    /// Accept an attempt that arrived on socket `received_on`: the connection sends from that
    /// socket, and a refusal response leaves from it too. The attempt's socket dependence is
    /// released here on every path.
    pub(crate) fn accept(
        &self,
        incoming: crate::proto::Incoming,
        lease: Lease,
        server_config: Option<Arc<ServerConfig>>,
    ) -> Result<Connecting, ConnectionError> {
        let received_on = lease.id();
        let mut state = self.state.lock();
        let now = now();
        if state.driver_lost || state.shutdown || state.recv_state.connections.close.is_some() {
            state.inner.ignore(incoming);
            let retired = state.sockets.release(lease, now);
            drop(state);
            drop(retired);
            return Err(ConnectionError::LocallyClosed);
        }
        let Some(mut socket) = state
            .sockets
            .live_mut()
            .and_then(|sockets| sockets.sender(received_on))
        else {
            // The receiving socket is gone or unusable: the attempt cannot be answered on it.
            state.inner.ignore(incoming);
            let retired = state.sockets.release(lease, now);
            drop(state);
            drop(retired);
            return Err(ConnectionError::LocallyClosed);
        };
        let mut response_buffer = Vec::new();
        let mut retired = Vec::new();
        // An unused send handle is dropped after unlocking, like the sockets it retires.
        let mut unused_sender = None;
        let registered =
            match state
                .inner
                .accept(incoming, now, &mut response_buffer, server_config)
            {
                Ok((handle, conn)) => {
                    state.stats.accepted_handshakes += 1;
                    Ok(state.recv_state.connections.insert(
                        handle,
                        conn,
                        socket,
                        EndpointLink::new(Arc::downgrade(&self.0), handle),
                    ))
                }
                Err(error) => {
                    if let Some(sender_lease) = socket.take_lease() {
                        retired.extend(state.sockets.release(sender_lease, now));
                    }
                    unused_sender = Some(socket);
                    if let Some(transmit) = error.response {
                        state
                            .sockets
                            .respond(received_on, transmit, &response_buffer);
                    }
                    Err(error.cause)
                }
            };
        retired.extend(state.sockets.release(lease, now));
        // Supervision is reserved before the registration lock is released, and the driver
        // is submitted with no lock held (see `ConnectionDriver::spawn`).
        let slot = registered
            .as_ref()
            .ok()
            .map(|_| self.shared.lifecycle.reserve());
        drop(state);
        drop(retired);
        drop(unused_sender);
        registered.map(|(connecting, driver)| {
            if let Some(slot) = slot {
                driver.spawn(slot);
            }
            connecting
        })
    }
}

impl EndpointInner {
    pub(crate) fn refuse(&self, incoming: crate::proto::Incoming, lease: Lease) {
        let received_on = lease.id();
        let mut state = self.state.lock();
        if incoming.is_expired() {
            state.inner.ignore(incoming);
        } else {
            state.stats.refused_handshakes += 1;
            let mut response_buffer = Vec::new();
            let transmit = state.inner.refuse(incoming, &mut response_buffer);
            state
                .sockets
                .respond(received_on, transmit, &response_buffer);
        }
        let retired = state.sockets.release(lease, now());
        state.wake_driver();
        drop(state);
        drop(retired);
    }

    /// Send a Retry on the attempt's receiving socket. The peer is told to come back to that
    /// socket's address, so the socket keeps receiving even when it has been replaced meanwhile.
    ///
    /// The hold lasts the configured Retry token lifetime, measured on the driver's monotonic
    /// clock from the moment the Retry is issued under the lock, and ends at that instant (the
    /// endpoint's timer is scheduled for it). It is a bounded retention policy, not the token's
    /// validity: the token is checked, inclusively, against the configured wall-clock time source
    /// with a whole-second issue time, so the two can differ by up to a second plus any
    /// wall-clock adjustment. A lifetime the monotonic clock cannot represent is refused before
    /// any Retry is issued (`RetryRefused::LifetimeUnrepresentable`). On error the attempt and
    /// its lease stay with the caller.
    pub(crate) fn retry(
        &self,
        incoming: crate::proto::Incoming,
        lease: Lease,
    ) -> Result<(), (crate::proto::RetryError, Lease)> {
        let received_on = lease.id();
        let mut state = self.state.lock();
        let now = now();
        let hold_until = match state.inner.retry_token_lifetime() {
            Some(lifetime) => match now.checked_add(lifetime) {
                Some(until) => Some(until),
                None => {
                    return Err((
                        crate::proto::RetryError::new(
                            incoming,
                            crate::proto::RetryRefused::LifetimeUnrepresentable,
                        ),
                        lease,
                    ));
                }
            },
            None => None,
        };
        let mut response_buffer = Vec::new();
        let transmit = match state.inner.retry(incoming, &mut response_buffer) {
            Ok(transmit) => transmit,
            Err(error) => return Err((error, lease)),
        };
        if let Some(until) = hold_until
            && let Some(sockets) = state.sockets.live_mut()
        {
            sockets.hold_route(received_on, until);
        }
        state
            .sockets
            .respond(received_on, transmit, &response_buffer);
        let retired = state.sockets.release(lease, now);
        state.wake_driver();
        drop(state);
        drop(retired);
        Ok(())
    }

    pub(crate) fn ignore(&self, incoming: crate::proto::Incoming, lease: Lease) {
        let mut state = self.state.lock();
        state.stats.ignored_handshakes += 1;
        state.inner.ignore(incoming);
        let retired = state.sockets.release(lease, now());
        drop(state);
        drop(retired);
    }

    /// Connection drivers hand back the send handles they gave up, after dropping their own
    /// lock. Their socket leases are released here; the handles and any socket retired as a
    /// result are dropped outside the endpoint lock.
    pub(crate) fn release_senders(&self, mut senders: Vec<Sender>) {
        let mut state = self.state.lock();
        let now = now();
        let retired: Vec<Socket> = senders
            .iter_mut()
            .filter_map(Sender::take_lease)
            .filter_map(|lease| state.sockets.release(lease, now))
            .collect();
        drop(state);
        drop(retired);
        drop(senders);
    }
}

#[derive(Debug)]
pub(crate) struct State {
    /// The sockets this endpoint owns: the active one and earlier ones that connections, queued
    /// attempts or queued responses still depend on (see [`SocketRegistry`]).
    sockets: Sockets,
    inner: crate::proto::Endpoint,
    recv_state: RecvState,
    driver: Option<Waker>,
    ipv6: bool,
    driver_lost: bool,
    shutdown: bool,
    incoming_timer: DeadlineTimer,
    /// Fires when a replaced socket's Retry route hold expires (see [`SocketRegistry::hold_route`]).
    route_timer: DeadlineTimer,
    stats: EndpointStats,
    /// Endpoint-wide budget shared by every queued packet and queued incoming attempt.
    packet_budget: PacketBudget,
    /// Tests: while set, a route installation is put aside instead of applied, so a test can
    /// attempt a send in the window before the connection learns its route exists.
    #[cfg(test)]
    hold_route_installs: bool,
    #[cfg(test)]
    held_route_installs: Vec<(ConnectionHandle, EndpointEvent)>,
}

#[derive(Debug)]
pub(crate) struct Shared {
    incoming: Notify,
    idle: Notify,
    lifecycle: Lifecycle,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: AtomicUsize,
}

impl State {
    fn close(&mut self, error_code: VarInt, reason: Bytes, shared: &Shared) {
        if self.recv_state.connections.close.is_none() {
            self.recv_state.connections.close = Some((error_code, reason.clone()));
            for channel in self.recv_state.connections.channels.values() {
                channel.inner.control(Control::Close {
                    error_code,
                    reason: reason.clone(),
                });
            }
        }
        shared.incoming.notify_waiters();
        if let Some(driver) = self.driver.take() {
            driver.wake();
        }
    }

    fn drive_incoming_timeout(
        &mut self,
        cx: &mut Context<'_>,
        now: Instant,
        retired: &mut Vec<Socket>,
    ) -> bool {
        let expired = self.inner.expire_incoming(now, IO_LOOP_BOUND);
        self.stats.expired_incoming = self.stats.expired_incoming.saturating_add(expired as u64);
        // Arrival order and a fixed endpoint timeout make expired queued handles a prefix.
        for _ in 0..IO_LOOP_BOUND {
            if !self
                .recv_state
                .incoming
                .front()
                .is_some_and(|queued| queued.incoming.is_expired())
            {
                break;
            }
            if let Some(queued) = self.recv_state.incoming.pop_front() {
                self.inner.ignore(queued.incoming);
                retired.extend(self.sockets.release(queued.lease, now));
            }
        }
        let Some(deadline) = self.inner.poll_incoming_timeout() else {
            self.incoming_timer.clear();
            return self
                .recv_state
                .incoming
                .front()
                .is_some_and(|queued| queued.incoming.is_expired());
        };
        self.incoming_timer.poll(deadline, now, cx) == Deadline::Elapsed
    }

    /// Retire replaced sockets whose Retry route hold has expired, and arm the timer for the
    /// next hold so an unanswered Retry never keeps a socket for good. Returns whether the
    /// driver must poll again: the timer may fire after `now` was read, and that hold is only
    /// judged against a fresh clock on the next poll, which also re-arms the next deadline.
    fn drive_route_expiry(
        &mut self,
        cx: &mut Context<'_>,
        now: Instant,
        retired: &mut Vec<Socket>,
    ) -> bool {
        let Some(sockets) = self.sockets.live_mut() else {
            self.route_timer.clear();
            return false;
        };
        retired.extend(sockets.expire_routes(now));
        match sockets.next_route_expiry() {
            Some(deadline) => self.route_timer.poll(deadline, now, cx) == Deadline::Elapsed,
            None => {
                self.route_timer.clear();
                false
            }
        }
    }

    /// A socket failed: its dependents are told once. Each connection still sending from it
    /// moves to a path it may use or is terminated with a local path error (see
    /// [`ConnectionInner::path_failed`]). Attempts still queued on it can no longer be answered
    /// and are released here (engine state cleaned, lease returned); an attempt the application
    /// already holds is refused with `LocallyClosed` when it is accepted, its responses dropped.
    fn leave_failed_sockets(&mut self, now: Instant, retired: &mut Vec<Socket>) {
        let State {
            sockets,
            recv_state,
            inner,
            ..
        } = self;
        let Some(sockets) = sockets.live_mut() else {
            return;
        };
        // An address this endpoint advertised as preferred but no longer has a usable socket for
        // is not offered to connections that have yet to handshake. Recorded when the failure was
        // marked, so it holds whether or not the entry has been retired since.
        for address in sockets.take_withdrawn() {
            inner.stop_advertising(address);
        }
        let failed = sockets.take_failed_to_announce();
        if failed.iter().next().is_none() {
            return;
        }
        for id in failed.iter() {
            for channel in recv_state.connections.channels.values() {
                channel.inner.path_failed(id);
            }
        }
        for _ in 0..recv_state.incoming.len() {
            let Some(queued) = recv_state.incoming.pop_front() else {
                break;
            };
            if failed.iter().any(|id| id == queued.lease.id()) {
                inner.ignore(queued.incoming);
                retired.extend(sockets.release(queued.lease, now));
            } else if let Err(refused) = recv_state.incoming.push_back(queued) {
                // Re-queueing what was just popped cannot exceed the bound; refusal is treated
                // like any other refused admission.
                recv_state.dropped_packets += 1;
                inner.ignore(refused.incoming);
                retired.extend(sockets.release(refused.lease, now));
            }
        }
    }

    /// Queue a stateless response on the active socket (tests).
    #[cfg(test)]
    fn respond_active(&mut self, transmit: proto::Transmit, response_buffer: &[u8]) {
        let Some(id) = self.sockets.live().map(SocketRegistry::active_id) else {
            return;
        };
        self.respond(id, transmit, response_buffer);
    }

    /// Queue a stateless response on socket `on` and wake the driver to send it.
    fn respond(&mut self, on: SocketId, transmit: proto::Transmit, response_buffer: &[u8]) {
        self.sockets.respond(on, transmit, response_buffer);
        self.wake_driver();
    }

    fn wake_driver(&self) {
        if let Some(waker) = &self.driver {
            waker.wake_by_ref();
        }
    }

    /// Receive from every usable socket in rotation order under one work budget. A failing
    /// active socket is fatal; a failing retiring socket is marked and skipped from then on.
    fn drive_recv(
        &mut self,
        cx: &mut Context,
        now: Instant,
        retired: &mut Vec<Socket>,
    ) -> Result<bool, io::Error> {
        let State {
            sockets,
            recv_state,
            inner,
            packet_budget,
            ..
        } = self;
        let Some(sockets) = sockets.live_mut() else {
            return Ok(false);
        };
        let mut cycle = recv_state.start_recv_cycle();
        let mut keep_going = false;
        let mut outcome = Ok(());
        let mut visited = false;
        for id in sockets.receive_order().iter() {
            // One allowance covers every socket: the ones not reached this poll are served first
            // by the next one, which the continuation wake requests. The first socket of a pass
            // is always polled, so a budget already spent by the time the pass starts (the task
            // was preempted) still yields one batch of progress instead of an idle spin.
            if visited && !cycle.allow_work(crate::driver::now) {
                sockets.continue_receive_from(id);
                keep_going = true;
                break;
            }
            let Some(socket) = sockets.socket_mut(id) else {
                continue;
            };
            visited = true;
            let progress =
                recv_state.poll_socket(cx, inner, socket, now, packet_budget, &mut cycle);
            keep_going |= progress.keep_going;
            // Attempts admitted from this socket are queued now that the socket borrow is over:
            // each takes a lease on it, or is ignored when no room is left or the socket failed.
            let failed = progress.error.is_some();
            for (incoming, permit) in progress.admitted {
                let lease = (!failed).then(|| sockets.acquire_attempt(id)).flatten();
                let Some(lease) = lease else {
                    inner.ignore(incoming);
                    continue;
                };
                if let Err(refused) = recv_state.incoming.push_back(QueuedIncoming {
                    incoming,
                    lease,
                    _permit: permit,
                }) {
                    recv_state.dropped_packets += 1;
                    inner.ignore(refused.incoming);
                    retired.extend(sockets.release(refused.lease, now));
                }
            }
            if let Some(error) = progress.error {
                match sockets.receive_failed(id, error, now) {
                    Ok(retired_socket) => retired.extend(retired_socket),
                    Err(fatal) => {
                        outcome = Err(fatal);
                        break;
                    }
                }
            }
        }
        recv_state
            .recv_limiter
            .finish_cycle(cycle, crate::driver::now);
        outcome?;
        Ok(keep_going)
    }
}

impl Drop for State {
    fn drop(&mut self) {
        for queued in self.recv_state.incoming.drain_all() {
            self.inner.ignore(queued.incoming);
        }
    }
}

fn respond(transmit: crate::proto::Transmit, response_buffer: &[u8], socket: &mut Socket) {
    socket.queue_response(transmit, response_buffer);
}

/// An incoming connection attempt awaiting the application, charged to the endpoint budget.
#[derive(Debug)]
pub(crate) struct QueuedIncoming {
    incoming: crate::proto::Incoming,
    /// The attempt's hold on the socket the Initial arrived on; responses and the accepted
    /// connection use that socket.
    lease: Lease,
    _permit: PacketPermit,
}

/// The endpoint's side of one live connection.
#[derive(Debug)]
struct ConnectionChannel {
    /// Received packets, each holding a permit from `budget` and the endpoint budget. Storage
    /// follows use within the connection's datagram limit.
    packets: BoundedSender<QueuedPacket>,
    budget: PacketBudget,
    /// Kept until Drained so control can be applied directly; the connection never
    /// references the endpoint strongly, so there is no cycle.
    inner: Arc<ConnectionInner>,
}

#[derive(Debug)]
struct ConnectionSet {
    channels: FxHashMap<ConnectionHandle, ConnectionChannel>,
    connection_limits: ReceiveQueueLimits,
    /// Set if the endpoint has been manually closed
    close: Option<(VarInt, Bytes)>,
}

impl ConnectionSet {
    /// Register a connection. The returned driver must be spawned by the caller after the
    /// endpoint lock is released.
    fn insert(
        &mut self,
        handle: ConnectionHandle,
        conn: crate::proto::Connection,
        socket: Sender,
        link: EndpointLink,
    ) -> (Connecting, ConnectionDriver) {
        let (packets, receiver) = bounded_queue(self.connection_limits.datagrams());
        let budget = PacketBudget::new(self.connection_limits);
        let (connecting, driver) =
            Connecting::new(handle, conn, link, receiver, socket, budget.clone());
        let inner = connecting.inner();
        if let Some((error_code, ref reason)) = self.close {
            inner.control(Control::Close {
                error_code,
                reason: reason.clone(),
            });
        }
        self.channels.insert(
            handle,
            ConnectionChannel {
                packets,
                budget,
                inner,
            },
        );
        (connecting, driver)
    }

    fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }
}

pin_project! {
    /// Future produced by [`Endpoint::accept`]
    pub struct Accept<'a> {
        endpoint: &'a Endpoint,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for Accept<'_> {
    type Output = Option<Incoming>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut endpoint = this.endpoint.inner.state.lock();
        if endpoint.driver_lost {
            return Poll::Ready(None);
        }
        if let Some(QueuedIncoming {
            incoming,
            lease,
            _permit,
        }) = endpoint.recv_state.incoming.pop_front()
        {
            // Release the mutex lock on endpoint so cloning it doesn't deadlock
            drop(endpoint);
            // The attempt now belongs to the application; its queue charge ends here, its
            // socket lease travels with the handle.
            drop(_permit);
            let incoming = Incoming::new(incoming, this.endpoint.inner.clone(), lease);
            return Poll::Ready(Some(incoming));
        }
        if endpoint.recv_state.connections.close.is_some() {
            return Poll::Ready(None);
        }
        loop {
            match this.notify.as_mut().poll(ctx) {
                // `state` lock ensures we didn't race with readiness
                Poll::Pending => return Poll::Pending,
                // Spurious wakeup, get a new future
                Poll::Ready(()) => this
                    .notify
                    .set(this.endpoint.inner.shared.incoming.notified()),
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct EndpointRef(Arc<EndpointInner>);

impl EndpointRef {
    pub(crate) fn new(socket: Socket, inner: crate::proto::Endpoint, ipv6: bool) -> Self {
        let packet_budget = PacketBudget::new(inner.config().endpoint_receive_queue);
        let recv_state = RecvState::new(
            socket.capabilities().max_receive_segments.clamp(1, 64),
            &inner,
        );
        Self(Arc::new(EndpointInner {
            shared: Shared {
                incoming: Notify::new(),
                idle: Notify::new(),
                lifecycle: Lifecycle::default(),
                ref_count: AtomicUsize::new(1),
            },
            state: Mutex::new(State {
                sockets: Sockets::Live(SocketRegistry::new(socket)),
                inner,
                ipv6,
                driver: None,
                driver_lost: false,
                shutdown: false,
                incoming_timer: DeadlineTimer::default(),
                route_timer: DeadlineTimer::default(),
                recv_state,
                stats: EndpointStats::default(),
                packet_budget,
                #[cfg(test)]
                hold_route_installs: false,
                #[cfg(test)]
                held_route_installs: Vec::new(),
            }),
        }))
    }
}

impl Clone for EndpointRef {
    fn clone(&self) -> Self {
        self.0.shared.ref_count.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}

impl Drop for EndpointRef {
    fn drop(&mut self) {
        if self.shared.ref_count.fetch_sub(1, Ordering::Relaxed) > 1 {
            return;
        }

        let endpoint = &mut *self.0.state.lock();
        // If the driver is about to be on its own, ensure it can shut down if the last
        // connection is gone.
        if let Some(task) = endpoint.driver.take() {
            task.wake();
        }
    }
}

impl std::ops::Deref for EndpointRef {
    type Target = EndpointInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// State directly involved in handling incoming packets
struct RecvState {
    /// Attempts awaiting `accept`; storage follows use within the endpoint datagram limit.
    incoming: BoundedDeque<QueuedIncoming>,
    connections: ConnectionSet,
    recv_buf: Box<[u8]>,
    recv_limiter: WorkLimiter,
    received_datagrams: u64,
    truncated_receive_entries: u64,
    /// Ignored connection-reset receive errors (work, not datagrams).
    ignored_receive_errors: u64,
    /// Datagrams refused by a saturated endpoint or connection budget before any engine work.
    dropped_packets: u64,
    /// Tests: a fixed per-poll receive allowance in place of the measured one.
    #[cfg(test)]
    forced_recv_allowance: Option<usize>,
}

impl RecvState {
    fn start_recv_cycle(&self) -> WorkCycle {
        #[cfg(test)]
        if let Some(allowed) = self.forced_recv_allowance {
            return WorkCycle::with_allowance(allowed);
        }
        self.recv_limiter.start_cycle(crate::driver::now)
    }

    fn new(max_receive_segments: usize, endpoint: &crate::proto::Endpoint) -> Self {
        let recv_buf = vec![
            0;
            endpoint
                .config()
                .get_max_udp_payload_size()
                .min(octets::kib_u64(64)) as usize
                * max_receive_segments
                * BATCH_SIZE
        ];
        Self {
            connections: ConnectionSet {
                channels: FxHashMap::default(),
                connection_limits: endpoint.config().connection_receive_queue,
                close: None,
            },
            incoming: BoundedDeque::new(endpoint.config().endpoint_receive_queue.datagrams()),
            recv_buf: recv_buf.into(),
            recv_limiter: WorkLimiter::new(RECV_TIME_BOUND),
            received_datagrams: 0,
            truncated_receive_entries: 0,
            ignored_receive_errors: 0,
            dropped_packets: 0,
            #[cfg(test)]
            forced_recv_allowance: None,
        }
    }

    /// Receive from one socket until it is pending, the allowance is spent or it fails. Packets
    /// received before a failure are delivered; the failure travels in the result so the
    /// caller queues the attempts admitted first and then judges the socket.
    fn poll_socket(
        &mut self,
        cx: &mut Context,
        endpoint: &mut crate::proto::Endpoint,
        socket: &mut Socket,
        now: Instant,
        budget: &PacketBudget,
        cycle: &mut WorkCycle,
    ) -> PollProgress {
        let mut progress = PollProgress::default();
        let mut metas = [DatagramMetadata::empty(); BATCH_SIZE];
        #[expect(
            clippy::expect_used,
            reason = "recv_buf is allocated as BATCH_SIZE equal chunks, and from_fn consumes exactly that many"
        )]
        let mut iovs: [IoSliceMut; BATCH_SIZE] = {
            let mut bufs = self
                .recv_buf
                .chunks_mut(self.recv_buf.len() / BATCH_SIZE)
                .map(IoSliceMut::new);

            // expect() safe as self.recv_buf is chunked into BATCH_SIZE items
            // and iovs will be of size BATCH_SIZE, thus from_fn is called
            // exactly BATCH_SIZE times.
            std::array::from_fn(|_| bufs.next().expect("BATCH_SIZE elements"))
        };
        loop {
            match socket.poll_recv(cx, &mut iovs, &mut metas) {
                Poll::Ready(Ok(msgs)) => {
                    if msgs == 0 || msgs > iovs.len() {
                        progress.error = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid UDP receive entry count",
                        ));
                        return progress;
                    }
                    cycle.record_work(msgs);
                    for (meta, buf) in metas.iter().zip(iovs.iter()).take(msgs) {
                        if meta.truncated || meta.original_len > meta.len {
                            self.truncated_receive_entries += 1;
                            continue;
                        }
                        let Some(data) = buf.get(..meta.len) else {
                            progress.error = Some(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "UDP receive length exceeds buffer",
                            ));
                            return progress;
                        };
                        if data.is_empty() {
                            continue;
                        }
                        for segment in
                            data.chunks(meta.segment_size.map_or(data.len(), |size| size.get()))
                        {
                            self.received_datagrams += 1;
                            // Charge the packet before parsing: a refused packet costs no engine
                            // work. Each admitted packet owns its backing bytes, so retaining one
                            // small packet never retains a whole coalesced receive allocation.
                            let Some(mut permit) = budget.reserve(segment.len()) else {
                                self.dropped_packets += 1;
                                continue;
                            };
                            let buf = BytesMut::from(segment);
                            let mut response_buffer = Vec::new();
                            // The receiving socket identifies the path's local side: its bound
                            // port, and the datagram's destination ip when the platform reports
                            // one (a wildcard bind without that metadata keeps an unspecified ip).
                            let local = SocketAddr::new(
                                SocketAddress::from((meta.local.ip_addr, 0))
                                    .into_canonical_ip_addr()
                                    .ip_addr,
                                socket.local_addr().port(),
                            );
                            match endpoint.handle(
                                now,
                                meta.peer.into_canonical_ip_addr().into(),
                                Some(local),
                                meta.ecn.and_then(proto_ecn),
                                buf,
                                &mut response_buffer,
                            ) {
                                Some(DatagramEvent::NewConnection(incoming)) => {
                                    if self.connections.close.is_some() {
                                        let transmit =
                                            endpoint.refuse(incoming, &mut response_buffer);
                                        respond(transmit, &response_buffer, socket);
                                    } else if permit.widen(INCOMING_OVERHEAD - PACKET_OVERHEAD) {
                                        // Charged until the application takes the attempt; it is
                                        // queued by the caller once this socket is released.
                                        progress.admitted.push((incoming, permit));
                                    } else {
                                        // No room to hold the attempt; the peer retries.
                                        self.dropped_packets += 1;
                                        endpoint.ignore(incoming);
                                    }
                                }
                                Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                                    progress.received_connection_packet = true;
                                    // A connection that already drained has no channel; a
                                    // saturated connection budget drops the packet here.
                                    if let Some(channel) = self.connections.channels.get(&handle) {
                                        match permit.for_connection(&channel.budget) {
                                            Ok(permit) => {
                                                match channel.packets.send(QueuedPacket {
                                                    event,
                                                    _permit: permit,
                                                }) {
                                                    Ok(()) => {}
                                                    // The driver closed its queue on the way
                                                    // out: the packet is for a connection that
                                                    // is gone, not a receive drop.
                                                    Err((_packet, Refusal::Closed)) => {}
                                                    // Storage was refused although the budget
                                                    // accepted the packet: a real receive drop,
                                                    // counted once here and on the connection.
                                                    Err((_packet, Refusal::Full)) => {
                                                        self.dropped_packets += 1;
                                                        channel.budget.count_drop();
                                                    }
                                                }
                                            }
                                            Err(_permit) => self.dropped_packets += 1,
                                        }
                                    }
                                }
                                Some(DatagramEvent::Response(transmit)) => {
                                    respond(transmit, &response_buffer, socket);
                                }
                                None => {}
                            }
                        }
                    }
                }
                Poll::Pending => return progress,
                // Ignore ECONNRESET as it's undefined in QUIC and may be injected by an
                // attacker. Each ignored error is still work under the shared allowance, so a
                // stream of them cannot hold the pass; it is counted apart from received data.
                Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionReset => {
                    self.ignored_receive_errors += 1;
                    cycle.record_work(1);
                    if !cycle.allow_work(crate::driver::now) {
                        progress.keep_going = true;
                        return progress;
                    }
                    continue;
                }
                Poll::Ready(Err(e)) => {
                    progress.error = Some(e);
                    return progress;
                }
            }
            if !cycle.allow_work(crate::driver::now) {
                progress.keep_going = true;
                return progress;
            }
        }
    }
}

impl fmt::Debug for RecvState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RecvState")
            .field("incoming", &self.incoming.len())
            .field("connections", &self.connections)
            // recv_buf too large
            .field("recv_limiter", &self.recv_limiter)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct PollProgress {
    /// Whether a datagram was routed to an existing connection
    received_connection_packet: bool,
    /// Whether datagram handling was interrupted early by the work limiter for fairness
    keep_going: bool,
    /// Attempts admitted during this poll, still to be queued with a lease on the socket.
    admitted: Vec<(crate::proto::Incoming, PacketPermit)>,
    /// The receive error that ended this poll, after everything received before it.
    error: Option<io::Error>,
}

#[cfg(test)]
impl PollProgress {
    /// Tests: the poll as a result, discarding progress when the socket failed.
    fn into_result(self) -> io::Result<Self> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self),
        }
    }
}

#[cfg(test)]
#[cfg(any(feature = "ring", feature = "aws-lc"))]
mod tests;
