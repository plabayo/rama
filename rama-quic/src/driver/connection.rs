use std::{
    any::Any,
    fmt,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker, ready},
};

use parking_lot::Mutex;
use pin_project_lite::pin_project;
use rama_core::bytes::Bytes;
use rama_core::telemetry::tracing::{Instrument, Span, debug_span};
use rama_udp::SendFailure;
use rustc_hash::FxHashMap;
use tokio::sync::{Notify, futures::Notified, oneshot};

use crate::driver::{
    Duration, IO_LOOP_BOUND, QueuedPacket, VarInt,
    endpoint::{EndpointInner, LocalSocket},
    now,
    queue::{BoundedReceiver, PacketBudget, PacketQueueStats},
    recv_stream::RecvStream,
    send_stream::SendStream,
    sockets::SocketId,
    timer::{Deadline, DeadlineTimer},
    udp::{FailureLog, Sender},
};
use crate::proto::{
    ConnectionError, ConnectionHandle, ConnectionStats, Dir, EndpointEvent, SendPermit, Side,
    StreamEvent, StreamId, congestion::Controller,
};

/// Tests: one descriptor this connection offered to its sender, and what became of it.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub(crate) id: u64,
    pub(crate) size: usize,
    /// The bytes offered, so a test can compare what reached the socket with what was built.
    pub(crate) bytes: Vec<u8>,
    pub(crate) segment_size: Option<usize>,
    pub(crate) destination: SocketAddr,
    pub(crate) cid_used: Option<u64>,
    pub(crate) outcome: Outcome,
    /// Whether the connection was actually told this offer's identifier reached the network. It
    /// is observed from the connection's own report count across this offer's processing, not
    /// copied from the condition that should cause the call.
    pub(crate) reported: bool,
}

/// Tests: what became of a descriptor that was offered.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Taken in full.
    Sent,
    /// The sender was not ready. The same descriptor is retained and offered again.
    Pending,
    /// Held because the route its identifier needs is not installed.
    Awaiting,
    /// Given up: its identifier may never be sent again.
    Obsolete,
    /// The sender refused it.
    Failed,
}

/// Tests: how many descriptor records are kept.
#[cfg(test)]
const DESCRIPTORS: usize = 64;

/// In-progress connection attempt future
#[derive(Debug)]
pub(crate) struct Connecting {
    conn: Option<ConnectionRef>,
    connected: oneshot::Receiver<Result<bool, ConnectionError>>,
    handshake_data_ready: Option<oneshot::Receiver<()>>,
}

impl Connecting {
    /// Tests: hold or release this (server-side) connection's HANDSHAKE_DONE before the
    /// handshake completes, so the peer can be observed complete but unconfirmed.
    #[cfg(test)]
    pub(crate) fn hold_handshake_done(&self, hold: bool) {
        if let Some(conn) = &self.conn {
            let conn = &mut *conn.state.lock();
            conn.inner.hold_handshake_done(hold);
            conn.wake();
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "the connection is removed only after this future yields Ready or is consumed into early data"
    )]
    fn connection_ref(&self) -> &ConnectionRef {
        self.conn
            .as_ref()
            .expect("Connecting used after completion")
    }

    #[expect(
        clippy::expect_used,
        reason = "a connection is taken once; repolling a completed future violates its contract"
    )]
    fn take_connection(&mut self) -> ConnectionRef {
        self.conn.take().expect("Connecting used after completion")
    }

    /// Build the connection state and its driver. The driver is returned unspawned so the
    /// caller can register the connection first and submit the driver with no lock held
    /// (see [`ConnectionDriver::spawn`]).
    pub(crate) fn new(
        handle: ConnectionHandle,
        conn: crate::proto::Connection,
        endpoint: EndpointLink,
        packets: BoundedReceiver<QueuedPacket>,
        socket: Sender,
        receive_queue: PacketBudget,
    ) -> (Self, ConnectionDriver) {
        let (on_handshake_data_send, on_handshake_data_recv) = oneshot::channel();
        let (on_connected_send, on_connected_recv) = oneshot::channel();
        let conn = ConnectionRef::new(
            handle,
            conn,
            endpoint,
            packets,
            on_handshake_data_send,
            on_connected_send,
            socket,
            receive_queue,
        );
        let driver = ConnectionDriver::new(conn.0.clone());
        (
            Self {
                conn: Some(conn),
                connected: on_connected_recv,
                handshake_data_ready: Some(on_handshake_data_recv),
            },
            driver,
        )
    }

    /// Shared state for the endpoint's connection table; not an application reference.
    pub(crate) fn inner(&self) -> Arc<ConnectionInner> {
        self.connection_ref().0.clone()
    }

    /// Convert into a 0-RTT or 0.5-RTT connection at the cost of weakened security
    ///
    /// Returns `Ok` immediately if the local endpoint is able to attempt sending 0/0.5-RTT data.
    /// If so, the returned [`Connection`] can be used to send application data without waiting for
    /// the rest of the handshake to complete, at the cost of weakened cryptographic security
    /// guarantees. The returned [`ZeroRttAccepted`] future resolves when the handshake does
    /// complete, at which point subsequently opened streams and written data will have full
    /// cryptographic protection.
    ///
    /// ## Outgoing
    ///
    /// For outgoing connections, the initial attempt to convert to a [`Connection`] which sends
    /// 0-RTT data will proceed if the [`crypto::ClientConfig`][crate::driver::crypto::ClientConfig]
    /// attempts to resume a previous TLS session. However, **the remote endpoint may not actually
    /// _accept_ the 0-RTT data**--yet still accept the connection attempt in general. This
    /// possibility is conveyed through the [`ZeroRttAccepted`] future--when the handshake
    /// completes, it resolves to `Ok(true)` if the 0-RTT data was accepted and `Ok(false)`
    /// if it was rejected. A failed handshake returns `Err` with the connection error.
    /// If it was rejected, the existence of streams opened and other application data sent prior
    /// to the handshake completing will not be conveyed to the remote application, and local
    /// operations on them will return `ZeroRttRejected` errors.
    ///
    /// A server may reject 0-RTT data at its discretion, but accepting 0-RTT data requires the
    /// relevant resumption state to be stored in the server, which servers may limit or lose for
    /// various reasons including not persisting resumption state across server restarts.
    ///
    /// If manually providing a [`crypto::ClientConfig`][crate::driver::crypto::ClientConfig], check your
    /// implementation's docs for 0-RTT pitfalls.
    ///
    /// ## Incoming
    ///
    /// Incoming connections permit a 0.5-RTT handle. The [`ZeroRttAccepted`] future resolves
    /// to `Ok(true)` after a successful handshake or `Err` if authentication or the connection fails.
    ///
    /// If manually providing a [`crypto::ServerConfig`][crate::driver::crypto::ServerConfig], check your
    /// implementation's docs for 0-RTT pitfalls.
    ///
    /// ## Security
    ///
    /// On outgoing connections, this enables transmission of 0-RTT data, which is vulnerable to
    /// replay attacks, and should therefore never invoke non-idempotent operations.
    ///
    /// On incoming connections, this enables transmission of 0.5-RTT data, which may be sent
    /// before TLS client authentication has occurred, and should therefore not be used to send
    /// data for which client authentication is being used.
    pub(crate) fn into_0rtt(mut self) -> Result<(Connection, ZeroRttAccepted), Self> {
        // This lock borrows `self` and would normally be dropped at the end of this scope, so we'll
        // have to release it explicitly before returning `self` by value.
        let conn = self.connection_ref().state.lock();

        let is_ok = conn.inner.has_0rtt() || conn.inner.side().is_server();
        drop(conn);

        if is_ok {
            let conn = self.take_connection();
            Ok((Connection(conn), ZeroRttAccepted(self.connected)))
        } else {
            Err(self)
        }
    }

    /// Parameters negotiated during the handshake
    ///
    /// The dynamic type returned is determined by the configured
    /// [`Session`](crate::proto::crypto::Session). For the default `rustls` session, the return value can
    /// be [`downcast`](Box::downcast) to a
    /// [`crypto::rustls::HandshakeData`](crate::driver::crypto::rustls::HandshakeData).
    pub(crate) async fn handshake_data(&mut self) -> Result<Box<dyn Any>, ConnectionError> {
        // Taking &mut self allows us to use a single oneshot channel rather than dealing with
        // potentially many tasks waiting on the same event. It's a bit of a hack, but keeps things
        // simple.
        if let Some(x) = self.handshake_data_ready.take() {
            let _ = x.await;
        }
        let conn = self.connection_ref();
        let inner = conn.state.lock();
        inner
            .inner
            .crypto_session()
            .handshake_data()
            .ok_or_else(|| {
                inner.error.clone().unwrap_or_else(|| {
                    crate::proto::TransportError::INTERNAL_ERROR(
                        "TLS session did not provide handshake metadata",
                    )
                    .into()
                })
            })
    }

    /// The local IP address which was used when the peer established
    /// the connection
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// This will return `None` for clients, or when the platform does not expose this
    /// information. See `rama_udp::DatagramCapabilities::receive_local_ip` for platform
    /// support.
    ///
    /// Will panic if called after `poll` has returned `Ready`.
    pub(crate) fn local_ip(&self) -> Option<IpAddr> {
        let conn = self.connection_ref();
        let inner = conn.state.lock();

        inner.inner.local_ip()
    }

    /// The peer's UDP address
    ///
    /// Will panic if called after `poll` has returned `Ready`.
    pub(crate) fn remote_address(&self) -> SocketAddr {
        let conn_ref: &ConnectionRef = self.connection_ref();
        conn_ref.state.lock().inner.remote_address()
    }
}

impl Future for Connecting {
    type Output = Result<Connection, ConnectionError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        Pin::new(&mut self.connected).poll(cx).map(|result| {
            let conn = self.take_connection();
            match result {
                Ok(Ok(_)) => Ok(Connection(conn)),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(conn
                    .state
                    .lock()
                    .error
                    .clone()
                    .unwrap_or_else(handshake_driver_stopped)),
            }
        })
    }
}

/// Future that completes when a connection is fully established
///
/// On success, clients receive whether 0-RTT was accepted and servers receive `true`.
/// A handshake failure returns the connection error, preserving its source.
pub(crate) struct ZeroRttAccepted(oneshot::Receiver<Result<bool, ConnectionError>>);

impl Future for ZeroRttAccepted {
    type Output = Result<bool, ConnectionError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|result| result.unwrap_or_else(|_| Err(handshake_driver_stopped())))
    }
}

fn handshake_driver_stopped() -> ConnectionError {
    crate::proto::TransportError::INTERNAL_ERROR("QUIC handshake driver stopped without a result")
        .into()
}

/// The endpoint side of a connection's control path.
///
/// Control is never queued. Lock order is endpoint state, then connection state: the
/// endpoint applies [`Control`] to a connection while holding both locks, and a connection
/// reaches its endpoint only after releasing its own lock. [`ConnectionDriver`] therefore
/// hands engine events to the endpoint outside the [`State`] lock.
#[derive(Debug, Clone)]
pub(crate) struct EndpointLink {
    endpoint: Weak<EndpointInner>,
    handle: ConnectionHandle,
}

impl EndpointLink {
    pub(crate) fn new(endpoint: Weak<EndpointInner>, handle: ConnectionHandle) -> Self {
        Self { endpoint, handle }
    }

    /// A link to no endpoint, for driving a connection in isolation.
    #[cfg(test)]
    pub(crate) fn detached(handle: ConnectionHandle) -> Self {
        Self {
            endpoint: Weak::new(),
            handle,
        }
    }

    fn deliver(&self, events: Vec<EndpointEvent>) {
        if let Some(endpoint) = self.endpoint.upgrade() {
            endpoint.connection_events(self.handle, events);
        }
    }

    /// What the endpoint can offer for sending from `local`, given the socket in use.
    fn socket_for_local(&self, local: SocketAddr, current: SocketId) -> LocalSocket {
        match self.endpoint.upgrade() {
            Some(endpoint) => endpoint.socket_for_local(local, current),
            None => LocalSocket::Unowned,
        }
    }

    /// Hand back send handles this connection no longer uses: the endpoint releases their socket
    /// leases and drops the handles outside every lock. Without an endpoint they are dropped here,
    /// outside the connection lock.
    fn release_senders(&self, senders: Vec<Sender>) {
        if senders.is_empty() {
            return;
        }
        match self.endpoint.upgrade() {
            Some(endpoint) => endpoint.release_senders(senders),
            None => drop(senders),
        }
    }
}

/// Control the endpoint applies directly to a connection's engine.
#[derive(Debug)]
pub(crate) enum Control {
    Proto(crate::proto::ConnectionEvent),
    Close { error_code: VarInt, reason: Bytes },
    Rebind(Sender),
}

/// What happened to a connection when the endpoint reported a failed socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathFailure {
    /// The connection did not use that socket.
    Unaffected,
    /// The connection left the socket for a path it may use.
    Switched,
    /// The connection had no path it may use and was terminated with a local path error.
    Terminated,
}

/// Whether a connection may start sending from a given local address (RFC 9000 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Switch {
    /// The same local address: a socket replacement, not a migration; always allowed.
    SameAddress,
    /// A client whose handshake is confirmed, whose peer allows active migration and that has an
    /// unused destination connection ID (or a zero-length one) for the new address.
    Now,
    /// A client that may migrate but not yet: its handshake is not confirmed, or it has no unused
    /// destination connection ID (RFC 9000 §9.5) until the peer issues one.
    Later,
    /// Never: servers cannot change address (the preferred-address mechanism aside), and a
    /// peer may disable active migration.
    Never,
}

/// Counters kept by the asynchronous driver around the protocol engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DriverStats {
    /// Datagrams the socket refused for their destination; recovered like any packet loss.
    pub(crate) send_failures: u64,
    /// Datagrams the network stack rejected as too large; recovered by loss detection and
    /// MTU discovery.
    pub(crate) oversized_sends: u64,
    /// Occupancy and drops of this connection's received-packet queue.
    pub(crate) receive_queue: PacketQueueStats,
    /// Entries the packet queue currently retains storage for (at most the configured limit).
    pub(crate) receive_queue_capacity: usize,
}

/// A future that drives protocol logic for a connection
///
/// This future handles the protocol logic for a single connection, routing events from the
/// `Connection` API object to the `Endpoint` task and the related stream-related interfaces.
/// It also keeps track of outstanding timeouts for the `Connection`.
///
/// If the connection encounters an error condition, this future will yield an error. It will
/// terminate (yielding `Ok(())`) if the connection was closed without error. Unlike other
/// connection-related futures, this waits for the draining period to complete to ensure that
/// packets still in flight from the peer are handled gracefully.
#[must_use = "connection drivers must be spawned for their connections to function"]
#[derive(Debug)]
pub(crate) struct ConnectionDriver {
    conn: Arc<ConnectionInner>,
    span: Span,
}

impl ConnectionDriver {
    fn new(conn: Arc<ConnectionInner>) -> Self {
        let span = {
            let conn = &mut conn.state.lock();
            debug_span!("drive", id = conn.handle.0)
        };

        Self { conn, span }
    }

    /// Submit the driver to the runtime through a slot reserved while the connection was
    /// registered.
    ///
    /// Must be called with no endpoint or connection lock held: a runtime that discards the
    /// future inline (for example while shutting down) runs this driver's `Drop`, which
    /// delivers Drained to the endpoint and therefore takes the endpoint lock.
    pub(crate) fn spawn(self, slot: crate::driver::lifecycle::SpawnSlot) {
        slot.submit(Box::pin(
            async {
                if let Err(e) = self.await {
                    rama_core::telemetry::tracing::error!("I/O error: {e}");
                }
            }
            .instrument(Span::current()),
        ));
    }
}

/// Test observation: whether a connection driver ever polled inside an enabled dial9 session.
#[cfg(all(test, feature = "dial9"))]
pub(crate) static DRIVER_POLLED_WITH_DIAL9: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

impl Future for ConnectionDriver {
    type Output = Result<(), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        #[cfg(all(test, feature = "dial9"))]
        if rama_core::telemetry::dial9::Dial9Handle::current().is_enabled() {
            DRIVER_POLLED_WITH_DIAL9.store(true, Ordering::Relaxed);
        }
        let (outcome, endpoint_work, wanted_local) = {
            let conn = &mut *self.conn.state.lock();
            let _guard = self.span.enter();
            let outcome = conn.drive(&self.conn.shared, cx);
            (
                outcome,
                !conn.pending_endpoint_events.is_empty() || !conn.released_senders.is_empty(),
                conn.wanted_local.take(),
            )
        };
        if endpoint_work {
            // Our lock is released, so the endpoint may lock this connection back (lock order).
            self.conn.deliver_endpoint_events();
        }
        if let Some((local, descriptor)) = wanted_local {
            // Asked with our lock released, in endpoint-then-connection order.
            self.conn.follow_local_address(local, descriptor);
        }
        outcome
    }
}

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        let (link, events, released) = {
            let conn = &mut *self.conn.state.lock();
            // Discarding queued packets releases their budget charges.
            conn.packets.close();
            if conn.error.is_none() {
                conn.terminate(
                    crate::proto::TransportError::INTERNAL_ERROR("QUIC driver stopped").into(),
                    &self.conn.shared,
                );
            }
            // The send handles go away with the driver; they are handed back below, outside
            // this lock, so their socket leases are released and they are dropped there.
            let mut released = std::mem::take(&mut conn.released_senders);
            released.extend(conn.socket.take());
            released.extend(conn.pending_rebind.take());
            conn.buffered_transmit = None;
            conn.send_buffer = Vec::new();
            (
                conn.endpoint.clone(),
                conn.take_endpoint_events_with_drained(),
                released,
            )
        };
        link.deliver(events);
        link.release_senders(released);
    }
}

/// A QUIC connection.
///
/// If all references to a connection (including every clone of the `Connection` handle, streams of
/// incoming streams, and the various stream types) have been dropped, then the connection will be
/// automatically closed with an `error_code` of 0 and an empty `reason`. You can also close the
/// connection explicitly by calling [`Connection::close()`].
///
/// Closing the connection immediately abandons efforts to deliver data to the peer.  Upon
/// receiving CONNECTION_CLOSE the peer *may* drop any stream data not yet delivered to the
/// application. [`Connection::close()`] describes in more detail how to gracefully close a
/// connection without losing application data.
///
/// May be cloned to obtain another handle to the same connection.
///
/// [`Connection::close()`]: Connection::close
#[derive(Debug, Clone)]
pub(crate) struct Connection(ConnectionRef);

impl Connection {
    /// Initiate a new outgoing unidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the stream is
    /// actually used.
    pub(crate) fn open_uni(&self) -> OpenUni<'_> {
        OpenUni {
            conn: &self.0,
            notify: self.0.shared.stream_budget_available[Dir::Uni as usize].notified(),
        }
    }

    /// Initiate a new outgoing bidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the stream is
    /// actually used. Calling [`open_bi()`] then waiting on the [`RecvStream`] without writing
    /// anything to [`SendStream`] will never succeed.
    ///
    /// [`open_bi()`]: crate::driver::Connection::open_bi
    /// [`SendStream`]: crate::driver::SendStream
    /// [`RecvStream`]: crate::driver::RecvStream
    pub(crate) fn open_bi(&self) -> OpenBi<'_> {
        OpenBi {
            conn: &self.0,
            notify: self.0.shared.stream_budget_available[Dir::Bi as usize].notified(),
        }
    }

    /// Accept the next incoming uni-directional stream
    pub(crate) fn accept_uni(&self) -> AcceptUni<'_> {
        AcceptUni {
            conn: &self.0,
            notify: self.0.shared.stream_incoming[Dir::Uni as usize].notified(),
        }
    }

    /// Accept the next incoming bidirectional stream
    ///
    /// **Important Note**: The `Connection` that calls [`open_bi()`] must write to its [`SendStream`]
    /// before the other `Connection` is able to `accept_bi()`. Calling [`open_bi()`] then
    /// waiting on the [`RecvStream`] without writing anything to [`SendStream`] will never succeed.
    ///
    /// [`accept_bi()`]: crate::driver::Connection::accept_bi
    /// [`open_bi()`]: crate::driver::Connection::open_bi
    /// [`SendStream`]: crate::driver::SendStream
    /// [`RecvStream`]: crate::driver::RecvStream
    pub(crate) fn accept_bi(&self) -> AcceptBi<'_> {
        AcceptBi {
            conn: &self.0,
            notify: self.0.shared.stream_incoming[Dir::Bi as usize].notified(),
        }
    }

    /// Receive an application datagram
    pub(crate) fn read_datagram(&self) -> ReadDatagram<'_> {
        ReadDatagram {
            conn: &self.0,
            notify: self.0.shared.datagram_received.notified(),
        }
    }

    /// Wait for the connection to be closed for any reason
    ///
    /// Despite the return type's name, closed connections are often not an error condition at the
    /// application layer. Cases that might be routine include [`ConnectionError::LocallyClosed`]
    /// and [`ConnectionError::ApplicationClosed`].
    pub(crate) async fn closed(&self) -> ConnectionError {
        loop {
            {
                let conn = self.0.state.lock();
                if let Some(error) = &conn.error {
                    return error.clone();
                }
                self.0.shared.closed.notified()
            }
            .await;
        }
    }

    /// If the connection is closed, the reason why.
    ///
    /// Returns `None` if the connection is still open.
    pub(crate) fn close_reason(&self) -> Option<ConnectionError> {
        self.0.state.lock().error.clone()
    }

    /// Close the connection immediately.
    ///
    /// Pending operations will fail immediately with [`ConnectionError::LocallyClosed`]. No
    /// more data is sent to the peer and the peer may drop buffered data upon receiving
    /// the CONNECTION_CLOSE frame.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds that it
    /// is preserved in full, it should be kept under 1KiB.
    ///
    /// # Gracefully closing a connection
    ///
    /// Only the peer last receiving application data can be certain that all data is
    /// delivered. The only reliable action it can then take is to close the connection,
    /// potentially with a custom error code. The delivery of the final CONNECTION_CLOSE
    /// frame is very likely if both endpoints stay online long enough, and
    /// [`Endpoint::wait_idle()`] can be used to provide sufficient time. Otherwise, the
    /// remote peer will time out the connection, provided that the idle timeout is not
    /// disabled.
    ///
    /// The sending side can not guarantee all stream data is delivered to the remote
    /// application. It only knows the data is delivered to the QUIC stack of the remote
    /// endpoint. Once the local side sends a CONNECTION_CLOSE frame in response to calling
    /// [`close()`] the remote endpoint may drop any data it received but is as yet
    /// undelivered to the application, including data that was acknowledged as received to
    /// the local endpoint.
    ///
    /// [`ConnectionError::LocallyClosed`]: crate::driver::ConnectionError::LocallyClosed
    /// [`Endpoint::wait_idle()`]: crate::driver::Endpoint::wait_idle
    /// [`close()`]: Connection::close
    pub(crate) fn close(&self, error_code: VarInt, reason: &[u8]) {
        let conn = &mut *self.0.state.lock();
        conn.close(error_code, Bytes::copy_from_slice(reason), &self.0.shared);
    }

    /// Wait for the handshake to be confirmed.
    ///
    /// As a server, who must be authenticated by clients,
    /// this happens when the handshake completes
    /// upon receiving a TLS Finished message from the client.
    /// In return, the server send a HANDSHAKE_DONE frame.
    ///
    /// As a client, this happens when receiving a HANDSHAKE_DONE frame.
    /// At this point, the server has either accepted our authentication,
    /// or, if client authentication is not required, accepted our lack of authentication.
    pub(crate) async fn handshake_confirmed(&self) -> Result<(), ConnectionError> {
        self.handshake_confirmed_inner().await
    }

    /// Tests: hold or release the server's HANDSHAKE_DONE (see the engine seam).
    #[cfg(test)]
    pub(crate) fn hold_handshake_done(&self, hold: bool) {
        let conn = &mut *self.0.state.lock();
        conn.inner.hold_handshake_done(hold);
        conn.wake();
    }

    /// The destination connection ID this connection currently puts on the wire (tests).
    #[cfg(test)]
    pub(crate) fn active_dcid(&self) -> Vec<u8> {
        self.0.state.lock().inner.active_rem_cid().to_vec()
    }

    /// Tests: whether a datagram carrying the active connection ID has gone out since the last
    /// switch, which is what makes that identifier one this connection has used.
    #[cfg(test)]
    pub(crate) fn active_cid_confirmed(&self) -> bool {
        self.0.state.lock().inner.active_cid_confirmed()
    }

    /// Tests: whether a datagram carrying the identifier numbered `seq` has gone out.
    #[cfg(test)]
    pub(crate) fn cid_confirmed(&self, seq: u64) -> bool {
        self.0.state.lock().inner.cid_confirmed(seq)
    }

    /// Tests: the datagram this connection has buffered: its exact bytes, its destination and
    /// the identifier it carries.
    ///
    /// A descriptor is buffered either because the socket was not ready for it or because the
    /// route its identifier needs is not installed; this does not distinguish the two. A test
    /// that needs to know which must arrange one of them, as the route tests do by holding
    /// installation on a socket that is otherwise writable.
    #[cfg(test)]
    pub(crate) fn held_transmit(&self) -> Option<(Vec<u8>, std::net::SocketAddr, Option<u64>)> {
        let state = self.0.state.lock();
        let (_, transmit) = state.buffered_transmit.as_ref()?;
        let bytes = state.send_buffer.get(..transmit.size)?.to_vec();
        Some((bytes, transmit.destination, transmit.cid_used))
    }

    /// Tests: the descriptors this connection offered to its sender, oldest first.
    #[cfg(test)]
    pub(crate) fn descriptors(&self) -> Vec<Descriptor> {
        self.0.state.lock().descriptors.iter().cloned().collect()
    }

    /// Tests: how many times this connection has been told a datagram reached the network.
    #[cfg(test)]
    pub(crate) fn cid_sent_calls(&self) -> u64 {
        self.0.state.lock().inner.cid_sent_calls()
    }

    /// Tests: whether the identifier numbered `seq` may be sent to `remote` — that is, whether
    /// its route is installed, which is a different question from whether anything has been sent
    /// with it.
    #[cfg(test)]
    pub(crate) fn send_permit(&self, seq: u64, remote: std::net::SocketAddr) -> SendPermit {
        self.0.state.lock().inner.may_send_cid(seq, remote)
    }

    /// Tests: whether a datagram carrying the identifier numbered `seq` has gone out towards
    /// `remote`, which is what RFC 9000 §10.3.1 ties recognition to.
    #[cfg(test)]
    pub(crate) fn cid_confirmed_to(&self, seq: u64, remote: std::net::SocketAddr) -> bool {
        self.0.state.lock().inner.cid_confirmed_to(seq, remote)
    }

    /// Tests: how many datagrams were given up because their identifier may never be sent again.
    /// A datagram merely waiting for its route is not one of them.
    #[cfg(test)]
    pub(crate) fn stale_transmits(&self) -> u64 {
        self.0.state.lock().stale_transmits
    }

    /// Tests: how many datagrams were given up because this endpoint owns no socket that could
    /// send from the local address their path names.
    #[cfg(test)]
    pub(crate) fn unowned_paths(&self) -> u64 {
        self.0.state.lock().unowned_paths
    }

    /// Tests: the local address this connection sends from, as its send handle reports it.
    #[cfg(test)]
    pub(crate) fn sending_from(&self) -> Option<std::net::SocketAddr> {
        self.0.state.lock().socket.as_ref().map(Sender::local_addr)
    }

    /// Tests: the sequence number of the connection ID this side is addressing its peer with.
    #[cfg(test)]
    pub(crate) fn active_dcid_seq(&self) -> u64 {
        self.0.state.lock().inner.active_rem_cid_seq()
    }

    /// Tests: have the peer retire every connection ID we issued below `v`, issuing replacements.
    #[cfg(test)]
    pub(crate) fn rotate_local_cid(&self, v: u64) {
        let conn = &mut *self.0.state.lock();
        conn.inner
            .rotate_local_cid(v, crate::driver::Instant::now());
        conn.wake();
    }

    /// The destination connection ID set aside for a candidate path, if any (tests).
    #[cfg(test)]
    pub(crate) fn reserved_dcid(&self) -> Option<Vec<u8>> {
        self.0
            .state
            .lock()
            .inner
            .reserved_rem_cid()
            .map(|cid| cid.to_vec())
    }

    async fn handshake_confirmed_inner(&self) -> Result<(), ConnectionError> {
        {
            let conn = self.0.state.lock();
            if let Some(error) = conn.error.as_ref() {
                return Err(error.clone());
            }
            if conn.handshake_confirmed {
                return Ok(());
            }
            // Construct the future while the lock is held to ensure we can't miss a wakeup if
            // the `Notify` is signaled immediately after we release the lock. `await` it after
            // the lock guard is out of scope.
            self.0.shared.handshake_confirmed.notified()
        }
        .await;
        if let Some(error) = self.0.state.lock().error.as_ref() {
            Err(error.clone())
        } else {
            Ok(())
        }
    }

    /// Transmit `data` as an unreliable, unordered application datagram
    ///
    /// Application datagrams are a low-level primitive. They may be lost or delivered out of order,
    /// and `data` must both fit inside a single QUIC packet and be smaller than the maximum
    /// dictated by the peer.
    ///
    /// Previously queued datagrams which are still unsent may be discarded to make space for this
    /// datagram, in order of oldest to newest.
    #[expect(
        clippy::unreachable,
        reason = "the engine never returns Blocked when its drop-oldest send policy is enabled"
    )]
    pub(crate) fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError> {
        let conn = &mut *self.0.state.lock();
        if let Some(ref x) = conn.error {
            return Err(SendDatagramError::ConnectionLost(x.clone()));
        }
        use crate::proto::SendDatagramError::*;
        match conn.inner.datagrams().send(data, true) {
            Ok(()) => {
                conn.wake();
                Ok(())
            }
            Err(e) => Err(match e {
                Blocked(..) => unreachable!(),
                UnsupportedByPeer => SendDatagramError::UnsupportedByPeer,
                Disabled => SendDatagramError::Disabled,
                TooLarge => SendDatagramError::TooLarge,
            }),
        }
    }

    /// Transmit `data` as an unreliable, unordered application datagram
    ///
    /// Unlike [`send_datagram()`], this method will wait for buffer space during congestion
    /// conditions, which effectively prioritizes old datagrams over new datagrams.
    ///
    /// See [`send_datagram()`] for details.
    ///
    /// [`send_datagram()`]: Connection::send_datagram
    pub(crate) fn send_datagram_wait(&self, data: Bytes) -> SendDatagram<'_> {
        SendDatagram {
            conn: &self.0,
            data: Some(data),
            notify: self.0.shared.datagrams_unblocked.notified(),
        }
    }

    /// Compute the maximum size of datagrams that may be passed to [`send_datagram()`].
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// [`send_datagram()`]: Connection::send_datagram
    pub(crate) fn max_datagram_size(&self) -> Option<usize> {
        self.0.state.lock().inner.datagrams().max_size()
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, calling [`send_datagram()`](Self::send_datagram) with a datagram of
    /// at most this size is guaranteed not to cause older datagrams to be dropped.
    pub(crate) fn datagram_send_buffer_space(&self) -> usize {
        self.0.state.lock().inner.datagrams().send_buffer_space()
    }

    /// The side of the connection (client or server)
    pub(crate) fn side(&self) -> Side {
        self.0.state.lock().inner.side()
    }

    /// The peer's UDP address
    ///
    /// If `ServerConfig::migration` is `true`, clients may change addresses at will, e.g. when
    /// switching to a cellular internet connection.
    pub(crate) fn remote_address(&self) -> SocketAddr {
        self.0.state.lock().inner.remote_address()
    }

    /// The local IP address which was used when the peer established
    /// the connection
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// This will return `None` for clients, or when the platform does not expose this
    /// information. See `rama_udp::DatagramCapabilities::receive_local_ip` for platform
    /// support.
    pub(crate) fn local_ip(&self) -> Option<IpAddr> {
        self.0.state.lock().inner.local_ip()
    }

    /// Current best estimate of this connection's latency (round-trip-time)
    pub(crate) fn rtt(&self) -> Duration {
        self.0.state.lock().inner.rtt()
    }

    /// Minimum RTT seen on this path, ignoring ack delay
    pub(crate) fn min_rtt(&self) -> Duration {
        self.0.state.lock().inner.min_rtt()
    }

    /// Returns connection statistics
    pub(crate) fn stats(&self) -> ConnectionStats {
        self.0.state.lock().inner.stats()
    }

    /// Current state of the congestion control algorithm, for debugging purposes
    pub(crate) fn congestion_state(&self) -> Box<dyn Controller> {
        self.0.state.lock().inner.congestion_state().clone_box()
    }

    /// Parameters negotiated during the handshake
    ///
    /// Guaranteed to return `Some` on fully established connections or after
    /// [`Connecting::handshake_data()`] succeeds. See that method's documentations for details on
    /// the returned value.
    ///
    /// [`Connection::handshake_data()`]: crate::driver::Connecting::handshake_data
    pub(crate) fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.0.state.lock().inner.crypto_session().handshake_data()
    }

    /// Cryptographic identity of the peer
    ///
    /// The dynamic type returned is determined by the configured
    /// [`Session`](crate::proto::crypto::Session). For the default `rustls` session, the return value can
    /// be [`downcast`](Box::downcast) to a <code>Vec<[rama_crypto::pki_types::CertificateDer]></code>
    pub(crate) fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.0.state.lock().inner.crypto_session().peer_identity()
    }

    /// A stable identifier for this connection
    ///
    /// Peer addresses and connection IDs can change, but this value will remain
    /// fixed for the lifetime of the connection.
    pub(crate) fn stable_id(&self) -> usize {
        self.0.stable_id()
    }

    /// Update traffic keys spontaneously
    ///
    /// This primarily exists for testing purposes.
    pub(crate) fn force_key_update(&self) {
        self.0.state.lock().inner.force_key_update()
    }

    /// Derive keying material from this connection's TLS session secrets.
    ///
    /// When both peers call this method with the same `label` and `context`
    /// arguments and `output` buffers of equal length, they will get the
    /// same sequence of bytes in `output`. These bytes are cryptographically
    /// strong and pseudorandom, and are suitable for use as keying material.
    ///
    /// See [RFC5705](https://tools.ietf.org/html/rfc5705) for more information.
    pub(crate) fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crate::proto::crypto::ExportKeyingMaterialError> {
        self.0
            .state
            .lock()
            .inner
            .crypto_session()
            .export_keying_material(output, label, context)
    }

    /// Counters kept by the driver that the protocol engine does not see.
    pub(crate) fn driver_stats(&self) -> DriverStats {
        let conn = self.0.state.lock();
        DriverStats {
            send_failures: conn.send_failures,
            oversized_sends: conn.oversized_sends,
            receive_queue: conn.receive_queue.stats(),
            receive_queue_capacity: conn.packets.capacity(),
        }
    }

    /// Modify the number of remotely initiated unidirectional streams that may be concurrently open
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already open. Large
    /// `count`s increase both minimum and worst-case memory consumption.
    pub(crate) fn set_max_concurrent_uni_streams(&self, count: VarInt) {
        let mut conn = self.0.state.lock();
        conn.inner.set_max_concurrent_streams(Dir::Uni, count);
        // May need to send MAX_STREAMS to make progress
        conn.wake();
    }

    /// See [`crate::proto::TransportConfig::send_window()`]
    pub(crate) fn set_send_window(&self, send_window: u64) {
        let mut conn = self.0.state.lock();
        conn.inner.set_send_window(send_window);
        conn.wake();
    }

    /// See [`crate::proto::TransportConfig::receive_window()`]
    pub(crate) fn set_receive_window(&self, receive_window: VarInt) {
        let mut conn = self.0.state.lock();
        conn.inner.set_receive_window(receive_window);
        conn.wake();
    }

    /// Modify the number of remotely initiated bidirectional streams that may be concurrently open
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already open. Large
    /// `count`s increase both minimum and worst-case memory consumption.
    pub(crate) fn set_max_concurrent_bi_streams(&self, count: VarInt) {
        let mut conn = self.0.state.lock();
        conn.inner.set_max_concurrent_streams(Dir::Bi, count);
        // May need to send MAX_STREAMS to make progress
        conn.wake();
    }
}

pin_project! {
    /// Future produced by [`Connection::open_uni`]
    pub(crate) struct OpenUni<'a> {
        conn: &'a ConnectionRef,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for OpenUni<'_> {
    type Output = Result<SendStream, ConnectionError>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let (conn, id, is_0rtt) = ready!(poll_open(ctx, this.conn, this.notify, Dir::Uni))?;
        Poll::Ready(Ok(SendStream::new(conn, id, is_0rtt)))
    }
}

pin_project! {
    /// Future produced by [`Connection::open_bi`]
    pub(crate) struct OpenBi<'a> {
        conn: &'a ConnectionRef,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for OpenBi<'_> {
    type Output = Result<(SendStream, RecvStream), ConnectionError>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let (conn, id, is_0rtt) = ready!(poll_open(ctx, this.conn, this.notify, Dir::Bi))?;

        Poll::Ready(Ok((
            SendStream::new(conn.clone(), id, is_0rtt),
            RecvStream::new(conn, id, is_0rtt),
        )))
    }
}

fn poll_open<'a>(
    ctx: &mut Context<'_>,
    conn: &'a ConnectionRef,
    mut notify: Pin<&mut Notified<'a>>,
    dir: Dir,
) -> Poll<Result<(ConnectionRef, StreamId, bool), ConnectionError>> {
    let mut state = conn.state.lock();
    if let Some(ref e) = state.error {
        return Poll::Ready(Err(e.clone()));
    } else if let Some(id) = state.inner.streams().open(dir) {
        let is_0rtt = state.inner.side().is_client() && state.inner.is_handshaking();
        drop(state); // Release the lock so clone can take it
        return Poll::Ready(Ok((conn.clone(), id, is_0rtt)));
    }
    // A failed open schedules STREAMS_BLOCKED even when the application has no other data.
    state.wake();
    loop {
        match notify.as_mut().poll(ctx) {
            // `state` lock ensures we didn't race with readiness
            Poll::Pending => return Poll::Pending,
            // Spurious wakeup, get a new future
            Poll::Ready(()) => {
                notify.set(conn.shared.stream_budget_available[dir as usize].notified())
            }
        }
    }
}

pin_project! {
    /// Future produced by [`Connection::accept_uni`]
    pub(crate) struct AcceptUni<'a> {
        conn: &'a ConnectionRef,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for AcceptUni<'_> {
    type Output = Result<RecvStream, ConnectionError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let (conn, id, is_0rtt) = ready!(poll_accept(ctx, this.conn, this.notify, Dir::Uni))?;
        Poll::Ready(Ok(RecvStream::new(conn, id, is_0rtt)))
    }
}

pin_project! {
    /// Future produced by [`Connection::accept_bi`]
    pub(crate) struct AcceptBi<'a> {
        conn: &'a ConnectionRef,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for AcceptBi<'_> {
    type Output = Result<(SendStream, RecvStream), ConnectionError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let (conn, id, is_0rtt) = ready!(poll_accept(ctx, this.conn, this.notify, Dir::Bi))?;
        Poll::Ready(Ok((
            SendStream::new(conn.clone(), id, is_0rtt),
            RecvStream::new(conn, id, is_0rtt),
        )))
    }
}

fn poll_accept<'a>(
    ctx: &mut Context<'_>,
    conn: &'a ConnectionRef,
    mut notify: Pin<&mut Notified<'a>>,
    dir: Dir,
) -> Poll<Result<(ConnectionRef, StreamId, bool), ConnectionError>> {
    let mut state = conn.state.lock();
    // Check for incoming streams before checking `state.error` so that already-received streams,
    // which are necessarily finite, can be drained from a closed connection.
    if let Some(id) = state.inner.streams().accept(dir) {
        let is_0rtt = state.inner.is_handshaking();
        state.wake(); // To send additional stream ID credit
        drop(state); // Release the lock so clone can take it
        return Poll::Ready(Ok((conn.clone(), id, is_0rtt)));
    } else if let Some(ref e) = state.error {
        return Poll::Ready(Err(e.clone()));
    }
    loop {
        match notify.as_mut().poll(ctx) {
            // `state` lock ensures we didn't race with readiness
            Poll::Pending => return Poll::Pending,
            // Spurious wakeup, get a new future
            Poll::Ready(()) => notify.set(conn.shared.stream_incoming[dir as usize].notified()),
        }
    }
}

pin_project! {
    /// Future produced by [`Connection::read_datagram`]
    pub(crate) struct ReadDatagram<'a> {
        conn: &'a ConnectionRef,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for ReadDatagram<'_> {
    type Output = Result<Bytes, ConnectionError>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut state = this.conn.state.lock();
        // Check for buffered datagrams before checking `state.error` so that already-received
        // datagrams, which are necessarily finite, can be drained from a closed connection.
        if let Some(x) = state.inner.datagrams().recv() {
            return Poll::Ready(Ok(x));
        } else if let Some(ref e) = state.error {
            return Poll::Ready(Err(e.clone()));
        }
        loop {
            match this.notify.as_mut().poll(ctx) {
                // `state` lock ensures we didn't race with readiness
                Poll::Pending => return Poll::Pending,
                // Spurious wakeup, get a new future
                Poll::Ready(()) => this
                    .notify
                    .set(this.conn.shared.datagram_received.notified()),
            }
        }
    }
}

pin_project! {
    /// Future produced by [`Connection::send_datagram_wait`]
    pub(crate) struct SendDatagram<'a> {
        conn: &'a ConnectionRef,
        data: Option<Bytes>,
        #[pin]
        notify: Notified<'a>,
    }
}

impl Future for SendDatagram<'_> {
    type Output = Result<(), SendDatagramError>;
    #[expect(
        clippy::unwrap_used,
        reason = "payload is present until the future completes; repolling after Ready violates the Future contract"
    )]
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut state = this.conn.state.lock();
        if let Some(ref e) = state.error {
            return Poll::Ready(Err(SendDatagramError::ConnectionLost(e.clone())));
        }
        use crate::proto::SendDatagramError::*;
        match state
            .inner
            .datagrams()
            .send(this.data.take().unwrap(), false)
        {
            Ok(()) => {
                state.wake();
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(match e {
                Blocked(data) => {
                    this.data.replace(data);
                    loop {
                        match this.notify.as_mut().poll(ctx) {
                            Poll::Pending => return Poll::Pending,
                            // Spurious wakeup, get a new future
                            Poll::Ready(()) => this
                                .notify
                                .set(this.conn.shared.datagrams_unblocked.notified()),
                        }
                    }
                }
                UnsupportedByPeer => SendDatagramError::UnsupportedByPeer,
                Disabled => SendDatagramError::Disabled,
                TooLarge => SendDatagramError::TooLarge,
            })),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionRef(Arc<ConnectionInner>);

impl ConnectionRef {
    #[expect(
        clippy::too_many_arguments,
        reason = "constructor wires every shared handle of a new connection"
    )]
    fn new(
        handle: ConnectionHandle,
        conn: crate::proto::Connection,
        endpoint: EndpointLink,
        packets: BoundedReceiver<QueuedPacket>,
        on_handshake_data: oneshot::Sender<()>,
        on_connected: oneshot::Sender<Result<bool, ConnectionError>>,
        socket: Sender,
        receive_queue: PacketBudget,
    ) -> Self {
        Self(Arc::new(ConnectionInner {
            state: Mutex::new(State {
                inner: conn,
                driver: None,
                handle,
                on_handshake_data: Some(on_handshake_data),
                on_connected: Some(on_connected),
                connected: false,
                handshake_confirmed: false,
                timer: DeadlineTimer::default(),
                packets,
                endpoint,
                pending_endpoint_events: Vec::new(),
                blocked_writers: FxHashMap::default(),
                blocked_readers: FxHashMap::default(),
                stopped: FxHashMap::default(),
                error: None,
                socket: Some(socket),
                send_buffer: Vec::new(),
                buffered_transmit: None,
                transmits_offered: 0,
                #[cfg(test)]
                descriptors: std::collections::VecDeque::new(),
                endpoint_drained: false,
                pending_rebind: None,
                wanted_local: None,
                covered_local: None,
                unowned_paths: 0,
                released_senders: Vec::new(),
                stale_transmits: 0,
                receive_queue,
                failure_log: FailureLog::default(),
                send_failures: 0,
                oversized_sends: 0,
            }),
            shared: Shared {
                ref_count: AtomicUsize::new(1),
                ..Shared::default()
            },
        }))
    }

    fn stable_id(&self) -> usize {
        &*self.0 as *const _ as usize
    }
}

impl Clone for ConnectionRef {
    fn clone(&self) -> Self {
        self.shared.ref_count.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}

impl Drop for ConnectionRef {
    fn drop(&mut self) {
        if self.shared.ref_count.fetch_sub(1, Ordering::Relaxed) > 1 {
            return;
        }

        let conn = &mut *self.state.lock();

        if !conn.inner.is_closed() {
            // If the driver is alive, it's just it and us, so we'd better shut it down. If it's
            // not, we can't do any harm. If there were any streams being opened, then either
            // the connection will be closed for an unrelated reason or a fresh reference will
            // be constructed for the newly opened stream.
            conn.implicit_close(&self.shared);
        }
    }
}

impl std::ops::Deref for ConnectionRef {
    type Target = ConnectionInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionInner {
    pub(crate) state: Mutex<State>,
    pub(crate) shared: Shared,
}

impl ConnectionInner {
    /// Apply endpoint control; the caller holds the endpoint lock (see [`EndpointLink`]).
    pub(crate) fn control(&self, message: Control) {
        let conn = &mut *self.state.lock();
        match message {
            Control::Proto(event) => conn.inner.handle_event(event),
            Control::Close { error_code, reason } => conn.close(error_code, reason, &self.shared),
            Control::Rebind(socket) => {
                // A connection that may never send from the new address (a server, or a client
                // whose peer disabled migration) keeps its socket and hands the offer back at
                // once. Otherwise the offer waits until any partially accepted transmit finished
                // on the current sender and the connection may migrate; a rebind that supersedes
                // a still-pending offer hands the superseded sender back.
                if conn.switch_to(&socket) == Switch::Never {
                    conn.released_senders.push(socket);
                } else if let Some(superseded) = conn.pending_rebind.replace(socket) {
                    conn.released_senders.push(superseded);
                }
            }
        }
        conn.wake();
    }

    /// The endpoint marked socket `failed` unusable: leave it now. A transmit still pending on
    /// it is lost like any dropped datagram (loss recovery resends). The pending replacement
    /// takes over when this connection may send from its address now (a same-address
    /// replacement, or a confirmed client whose peer allows migration and that has an unused
    /// destination connection ID); otherwise there is no path it may use at this moment, and
    /// waiting on a dead socket is not an option, so it is terminated with a local path error,
    /// waking everything blocked on it.
    /// The caller holds the endpoint lock (lock order endpoint → connection).
    pub(crate) fn path_failed(&self, failed: SocketId) -> PathFailure {
        let conn = &mut *self.state.lock();
        let mut outcome = PathFailure::Unaffected;
        if conn
            .pending_rebind
            .as_ref()
            .is_some_and(|s| s.socket_id() == failed)
            && let Some(pending) = conn.pending_rebind.take()
        {
            conn.released_senders.push(pending);
        }
        if conn
            .socket
            .as_ref()
            .is_some_and(|s| s.socket_id() == failed)
            && let Some(dead) = conn.socket.take()
        {
            let dead_addr = dead.local_addr();
            conn.released_senders.push(dead);
            conn.buffered_transmit = None;
            outcome = match conn.pending_rebind.take() {
                Some(replacement) => match conn.switch_from(dead_addr, &replacement) {
                    Switch::SameAddress => {
                        conn.socket = Some(replacement);
                        PathFailure::Switched
                    }
                    Switch::Now if conn.inner.migrate_local_address() => {
                        conn.socket = Some(replacement);
                        PathFailure::Switched
                    }
                    Switch::Now | Switch::Later | Switch::Never => {
                        conn.released_senders.push(replacement);
                        conn.lose_path(&self.shared);
                        PathFailure::Terminated
                    }
                },
                None => {
                    conn.lose_path(&self.shared);
                    PathFailure::Terminated
                }
            };
        }
        conn.wake();
        outcome
    }

    /// Follow this connection's path to `local`: take a send handle for that address from the
    /// endpoint, note that the current one already covers it, or, when neither is possible, give
    /// up the datagram that named it rather than send it from another address. Called with no
    /// connection lock held, so the endpoint's lock comes first.
    fn follow_local_address(&self, local: SocketAddr, descriptor: crate::driver::udp::TransmitId) {
        let (link, current) = {
            let conn = &*self.state.lock();
            (
                conn.endpoint.clone(),
                conn.socket.as_ref().map(Sender::socket_id),
            )
        };
        let Some(current) = current else {
            return;
        };
        let offered = link.socket_for_local(local, current);
        let released = {
            let conn = &mut *self.state.lock();
            // The question was asked with this lock released, so what it was asked about may be
            // gone: a concurrent path failure, rebind or shutdown changes the socket in use or
            // ends the connection. An answer about a socket this connection no longer sends from
            // is not applied, and a handle offered for it goes back the way any released handle
            // does.
            let stale = conn.error.is_some()
                || conn.socket.as_ref().map(Sender::socket_id) != Some(current)
                || conn.buffered_transmit.as_ref().map(|(id, _)| *id) != Some(descriptor);
            if stale {
                let offered = match offered {
                    LocalSocket::Owned(sender) => Some(sender),
                    LocalSocket::Covered | LocalSocket::Unowned => None,
                };
                conn.wake();
                offered
            } else {
                let released = match offered {
                    LocalSocket::Owned(sender) => {
                        // The descriptor waiting for this address was offered to the socket this
                        // connection is leaving. Whatever prefix that sender accepted has left from
                        // the old address and is reported there; a descriptor nothing was taken from
                        // is kept whole for the new sender.
                        conn.release_buffered();
                        conn.covered_local = None;
                        conn.socket.replace(sender)
                    }
                    LocalSocket::Covered => {
                        conn.covered_local = conn
                            .socket
                            .as_ref()
                            .map(|socket| (socket.socket_id(), local));
                        None
                    }
                    LocalSocket::Unowned => {
                        // The path identity of that datagram cannot be honoured: sending it from
                        // another address would put a different source on the path the peer is
                        // validating. It is given up like any lost datagram, with the accounting its
                        // sender needs, and loss recovery decides what follows.
                        conn.give_up_buffered();
                        conn.unowned_paths = conn.unowned_paths.saturating_add(1);
                        None
                    }
                };
                conn.wake();
                released
            }
        };
        if let Some(previous) = released {
            link.release_senders(vec![previous]);
        }
    }

    fn deliver_endpoint_events(&self) {
        let (link, events, released) = {
            let conn = &mut *self.state.lock();
            (
                conn.endpoint.clone(),
                std::mem::take(&mut conn.pending_endpoint_events),
                std::mem::take(&mut conn.released_senders),
            )
        };
        if !events.is_empty() {
            link.deliver(events);
        }
        link.release_senders(released);
    }
}

#[derive(Debug, Default)]
pub(crate) struct Shared {
    handshake_confirmed: Notify,
    /// Notified when new streams may be locally initiated due to an increase in stream ID flow
    /// control budget
    stream_budget_available: [Notify; 2],
    /// Notified when the peer has initiated a new stream
    stream_incoming: [Notify; 2],
    datagram_received: Notify,
    datagrams_unblocked: Notify,
    closed: Notify,
    /// Number of live handles that can used to initiate or handle I/O; excludes the driver
    ref_count: AtomicUsize,
}

pub(crate) struct State {
    pub(crate) inner: crate::proto::Connection,
    driver: Option<Waker>,
    handle: ConnectionHandle,
    on_handshake_data: Option<oneshot::Sender<()>>,
    on_connected: Option<oneshot::Sender<Result<bool, ConnectionError>>>,
    connected: bool,
    handshake_confirmed: bool,
    timer: DeadlineTimer,
    packets: BoundedReceiver<QueuedPacket>,
    endpoint: EndpointLink,
    /// Engine events for the endpoint, delivered once the connection lock is released.
    pending_endpoint_events: Vec<EndpointEvent>,
    pub(crate) blocked_writers: FxHashMap<StreamId, Waker>,
    pub(crate) blocked_readers: FxHashMap<StreamId, Waker>,
    pub(crate) stopped: FxHashMap<StreamId, Arc<Notify>>,
    /// Always set to Some before the connection becomes drained
    pub(crate) error: Option<ConnectionError>,
    socket: Option<Sender>,
    /// A local address the engine has moved this connection to, with the descriptor that named
    /// it, for which a send handle has been asked of the endpoint. The datagram waits until the
    /// answer arrives, so it leaves from that address rather than from the one this connection was
    /// sending from. The descriptor is part of the request: an answer is applied only while the
    /// work that motivated it is still the work in hand.
    wanted_local: Option<(SocketAddr, crate::driver::udp::TransmitId)>,
    /// A local address the socket this connection sends from can carry, with the identity of that
    /// socket: a wildcard-bound listener reports the address a datagram arrived on and can put it
    /// on the wire as the source. The socket's identity is part of the record, so a replacement
    /// that cannot carry the same path is asked about again.
    covered_local: Option<(SocketId, SocketAddr)>,
    pending_rebind: Option<Sender>,
    /// Send handles this connection gave up; handed to the endpoint after the connection lock is
    /// released (lock order), which releases their socket leases and drops them outside its own.
    released_senders: Vec<Sender>,
    /// Datagrams dropped because the identifier they carried may no longer be sent.
    stale_transmits: u64,
    send_buffer: Vec<u8>,
    /// We buffer a transmit when the underlying I/O would block, with the name of the attempt it
    /// belongs to, so the sender cannot apply what it accepted to a different descriptor.
    buffered_transmit: Option<(crate::driver::udp::TransmitId, crate::proto::Transmit)>,
    /// Datagrams given up because this endpoint owns no socket that could send from the local
    /// address their path names.
    unowned_paths: u64,
    /// Names each descriptor handed to the sender.
    transmits_offered: u64,
    /// Tests: the last [`DESCRIPTORS`] descriptors offered, oldest first.
    #[cfg(test)]
    descriptors: std::collections::VecDeque<Descriptor>,
    endpoint_drained: bool,
    receive_queue: PacketBudget,
    failure_log: FailureLog,
    send_failures: u64,
    oversized_sends: u64,
}

impl State {
    fn drive(&mut self, shared: &Shared, cx: &mut Context) -> Poll<io::Result<()>> {
        self.inner.expire_handshake(now());

        let mut keep_going = match self.process_packets(cx) {
            Ok(more) => more,
            Err(e) => {
                self.terminate(e, shared);
                return Poll::Ready(Ok(()));
            }
        };
        keep_going |= match self.drive_transmit(cx) {
            Ok(keep_going) => keep_going,
            Err(error) => {
                let reason = crate::proto::TransportError::INTERNAL_ERROR("QUIC UDP send failed")
                    .with_cause(error);
                self.terminate(reason.into(), shared);
                return Poll::Ready(Ok(()));
            }
        };
        // If a timer expires, there might be more to transmit. When we transmit something, we
        // might need to reset a timer. Hence, we must loop until neither happens.
        keep_going |= self.drive_timer(cx);
        self.forward_endpoint_events();
        self.forward_app_events(shared);

        if !self.inner.is_drained() {
            if keep_going {
                // If the connection hasn't processed all tasks, schedule it again
                cx.waker().wake_by_ref();
            } else {
                self.driver = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        if self.error.is_none() {
            self.terminate(
                crate::proto::TransportError::INTERNAL_ERROR(
                    "QUIC engine drained without a close reason",
                )
                .into(),
                shared,
            );
        }
        Poll::Ready(Ok(()))
    }

    /// Tests: record what became of a descriptor that was offered.
    #[cfg(test)]
    fn note_descriptor(
        &mut self,
        id: crate::driver::udp::TransmitId,
        transmit: &crate::proto::Transmit,
        outcome: Outcome,
        reported: bool,
    ) {
        while self.descriptors.len() >= DESCRIPTORS {
            self.descriptors.pop_front();
        }
        self.descriptors.push_back(Descriptor {
            id: id.0,
            size: transmit.size,
            bytes: self
                .send_buffer
                .get(..transmit.size)
                .expect("a descriptor's size is within the buffer it was written to")
                .to_vec(),
            segment_size: transmit.segment_size,
            destination: transmit.destination,
            cid_used: transmit.cid_used,
            outcome,
            reported,
        });
    }

    /// Release the descriptor waiting on this connection's sender before that sender changes or
    /// goes away.
    ///
    /// The sender's record of the descriptor is cancelled either way. A descriptor the sender had
    /// already taken a prefix of cannot move: those bytes left from that socket's address, so the
    /// identifier they carried is reported as used towards its destination (RFC 9000 §10.3.1) and
    /// the unsent remainder is given up like any dropped datagram. One nothing was taken from is
    /// kept, whole, for whichever sender comes next.
    fn release_buffered(&mut self) {
        let Some((id, transmit)) = self.buffered_transmit.take() else {
            return;
        };
        let Some(socket) = self.socket.as_mut() else {
            return;
        };
        let started = socket.accepted_any(id);
        socket.abandon(id);
        if !started {
            self.buffered_transmit = Some((id, transmit));
            return;
        }
        #[cfg(test)]
        let reports_before = self.inner.cid_sent_calls();
        if let Some(seq) = transmit.cid_used {
            self.inner.cid_sent(seq, transmit.destination);
        }
        #[cfg(test)]
        self.note_descriptor(
            id,
            &transmit,
            Outcome::Obsolete,
            self.inner.cid_sent_calls() > reports_before,
        );
        self.stale_transmits += 1;
    }

    /// Give up the descriptor waiting on this connection's sender: there is no socket it may
    /// leave from, so it is released and, if it was kept whole by the release, dropped.
    fn give_up_buffered(&mut self) {
        self.release_buffered();
        if let Some((id, transmit)) = self.buffered_transmit.take() {
            #[cfg(test)]
            self.note_descriptor(id, &transmit, Outcome::Obsolete, false);
            let _ = (id, transmit);
            self.stale_transmits += 1;
        }
    }

    fn drive_transmit(&mut self, cx: &mut Context) -> io::Result<bool> {
        let now = now();
        // A failure raised where it could not be returned closes the connection here, before
        // anything is retried: a datagram held for a route that will never exist must not keep
        // the cause from reaching the application.
        self.inner.settle_deferred_error(now);
        let mut transmits = 0;

        loop {
            if self.buffered_transmit.is_none()
                && let Some(pending) = self.pending_rebind.as_ref()
            {
                // The in-flight transmit finished on the old sender: switch when this connection
                // may send from the offered address, keep waiting while the handshake is not
                // confirmed, and hand the offer back once it is known to be unusable.
                match self.switch_to(pending) {
                    // The connection ID switch is committed first; the address follows only
                    // once it succeeded, so no CID is ever sent from two addresses.
                    Switch::Now if !self.inner.migrate_local_address() => {}
                    Switch::SameAddress | Switch::Now => {
                        if let Some(socket) = self.pending_rebind.take()
                            && let Some(old) = self.socket.replace(socket)
                        {
                            self.released_senders.push(old);
                        }
                    }
                    Switch::Later => {}
                    Switch::Never => {
                        self.released_senders.extend(self.pending_rebind.take());
                    }
                }
            }
            let Some(socket) = self.socket.as_mut() else {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "QUIC send handle released",
                ));
            };
            let max_datagrams = socket.max_transmit_segments().min(MAX_TRANSMIT_SEGMENTS);
            // Retry the last transmit, or get a new one.
            let (id, t) = match self.buffered_transmit.take() {
                Some(pair) => pair,
                None => {
                    self.send_buffer.clear();
                    self.send_buffer.reserve(self.inner.current_mtu() as usize);
                    match self
                        .inner
                        .poll_transmit(now, max_datagrams, &mut self.send_buffer)
                    {
                        Some(t) => {
                            transmits += match t.segment_size {
                                None => 1,
                                Some(s) => t.size.div_ceil(s), // round up
                            };
                            self.transmits_offered = self.transmits_offered.wrapping_add(1);
                            (crate::driver::udp::TransmitId(self.transmits_offered), t)
                        }
                        None => break,
                    }
                }
            };

            // The engine may have moved this connection to another of the endpoint's addresses
            // (a client that took the server's preferred address makes the server's path local
            // address that one, RFC 9000 §9.6). The datagram has to leave from there, so a send
            // handle for it is asked of the endpoint and this datagram waits for the answer. An
            // address the endpoint owns no socket for is answered once and not asked for again:
            // a wildcard-bound listener reports the address a datagram arrived on.
            if let Some(local) = t.local
                && socket.local_addr() != local
                && self.covered_local != Some((socket.socket_id(), local))
            {
                self.wanted_local = Some((local, id));
                self.buffered_transmit = Some((id, t));
                return Ok(false);
            }

            if let Some(seq) = t.cid_used {
                match self.inner.may_send_cid(seq, t.destination) {
                    SendPermit::Sendable => {}
                    // The route a reset would arrive by is not installed yet. The descriptor is
                    // retained with its socket state and any accepted prefix, and the endpoint's
                    // confirmation wakes this connection, so no polling loop is needed. Receiving,
                    // timers and shutdown continue meanwhile.
                    SendPermit::AwaitingInstallation => {
                        #[cfg(test)]
                        self.note_descriptor(id, &t, Outcome::Awaiting, false);
                        self.buffered_transmit = Some((id, t));
                        return Ok(false);
                    }
                    // The identifier may never be sent again. Only the unsent remainder goes: a
                    // prefix the sender already took has left, so it counts and is never offered
                    // again (RFC 9000 §9.5).
                    SendPermit::Obsolete => {
                        socket.abandon(id);
                        #[cfg(test)]
                        let reports_before = self.inner.cid_sent_calls();
                        if socket.accepted_any(id) {
                            self.inner.cid_sent(seq, t.destination);
                        }
                        #[cfg(test)]
                        self.note_descriptor(
                            id,
                            &t,
                            Outcome::Obsolete,
                            self.inner.cid_sent_calls() > reports_before,
                        );
                        self.stale_transmits += 1;
                        if transmits >= MAX_TRANSMIT_DATAGRAMS {
                            return Ok(true);
                        }
                        continue;
                    }
                }
            }

            // Observed before and after this offer's processing, so the record says whether the
            // connection was told, not whether it should have been. No other connection can move
            // this count while this state is locked.
            #[cfg(test)]
            let reports_before = self.inner.cid_sent_calls();
            let outcome = socket.poll_transmit(cx, id, &t, &self.send_buffer);
            // An identifier is used from the first byte the sender accepted, whatever becomes of
            // the rest: a prefix that left cannot be recalled, so its reset token is ours.
            if let Some(seq) = t.cid_used
                && socket.accepted_any(id)
            {
                self.inner.cid_sent(seq, t.destination);
            }
            #[cfg(test)]
            let reported = self.inner.cid_sent_calls() > reports_before;
            match outcome {
                Poll::Pending => {
                    #[cfg(test)]
                    self.note_descriptor(id, &t, Outcome::Pending, reported);
                    self.buffered_transmit = Some((id, t));
                    return Ok(false);
                }
                Poll::Ready(Ok(())) => {
                    #[cfg(test)]
                    self.note_descriptor(id, &t, Outcome::Sent, reported);
                }
                Poll::Ready(Err(error)) => match error.class {
                    // The engine already counts this datagram as in flight, so loss detection
                    // and MTU discovery recover from it like from any dropped packet.
                    SendFailure::Datagram | SendFailure::TooLarge => {
                        if error.class == SendFailure::TooLarge {
                            self.oversized_sends += 1;
                        } else {
                            self.send_failures += 1;
                        }
                        self.failure_log.record(now, "QUIC transmit", &error);
                        #[cfg(test)]
                        self.note_descriptor(id, &t, Outcome::Failed, reported);
                    }
                    // An invalid descriptor or an unusable socket cannot be retried.
                    SendFailure::Descriptor | SendFailure::Socket => {
                        #[cfg(test)]
                        self.note_descriptor(id, &t, Outcome::Failed, reported);
                        return Err(error.error);
                    }
                },
            }

            if transmits >= MAX_TRANSMIT_DATAGRAMS {
                // TODO: What isn't ideal here yet is that if we don't poll all
                // datagrams that could be sent we don't go into the `app_limited`
                // state and CWND continues to grow until we get here the next time.
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn forward_endpoint_events(&mut self) {
        while let Some(event) = self.inner.poll_endpoint_events() {
            if event.is_drained() {
                self.endpoint_drained = true;
            }
            self.pending_endpoint_events.push(event);
        }
    }

    /// Pending engine events plus exactly one Drained, if none was emitted yet.
    fn take_endpoint_events_with_drained(&mut self) -> Vec<EndpointEvent> {
        let mut events = std::mem::take(&mut self.pending_endpoint_events);
        if !self.endpoint_drained {
            self.endpoint_drained = true;
            events.push(EndpointEvent::drained());
        }
        events
    }

    /// Feed queued packets to the engine, bounded per poll. Each packet releases its budget
    /// charge here. `Err` means the endpoint driver is gone and this driver must exit.
    fn process_packets(&mut self, cx: &mut Context) -> Result<bool, ConnectionError> {
        for _ in 0..IO_LOOP_BOUND {
            match self.packets.poll_recv(cx) {
                Poll::Ready(Some(QueuedPacket { event, _permit })) => {
                    self.inner.handle_event(event);
                }
                Poll::Ready(None) => {
                    return Err(ConnectionError::TransportError(
                        crate::proto::TransportError::new(
                            crate::proto::TransportErrorCode::INTERNAL_ERROR,
                            "endpoint driver future was dropped".to_string(),
                        ),
                    ));
                }
                Poll::Pending => return Ok(false),
            }
        }
        Ok(true)
    }

    fn forward_app_events(&mut self, shared: &Shared) {
        while let Some(event) = self.inner.poll() {
            use crate::proto::Event::*;
            match event {
                HandshakeDataReady => {
                    if let Some(x) = self.on_handshake_data.take() {
                        let _ = x.send(());
                    }
                }
                Connected => {
                    self.connected = true;
                    if let Some(x) = self.on_connected.take() {
                        // We don't care if the on-connected future was dropped
                        let _ = x.send(Ok(
                            self.inner.side().is_server() || self.inner.accepted_0rtt()
                        ));
                    }
                    if self.inner.side().is_client() && !self.inner.accepted_0rtt() {
                        // Wake up rejected 0-RTT streams so they can fail immediately with
                        // `ZeroRttRejected` errors.
                        wake_all(&mut self.blocked_writers);
                        wake_all(&mut self.blocked_readers);
                        wake_all_notify(&mut self.stopped);
                    }
                }
                HandshakeConfirmed => {
                    self.handshake_confirmed = true;
                    shared.handshake_confirmed.notify_waiters();
                }
                ConnectionLost { reason } => {
                    self.terminate(reason, shared);
                }
                Stream(StreamEvent::Writable { id }) => wake_stream(id, &mut self.blocked_writers),
                Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
                    shared.stream_incoming[Dir::Uni as usize].notify_waiters();
                }
                Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                    shared.stream_incoming[Dir::Bi as usize].notify_waiters();
                }
                DatagramReceived => {
                    shared.datagram_received.notify_waiters();
                }
                DatagramsUnblocked => {
                    shared.datagrams_unblocked.notify_waiters();
                }
                Stream(StreamEvent::Readable { id }) => wake_stream(id, &mut self.blocked_readers),
                Stream(StreamEvent::Available { dir }) => {
                    // Might mean any number of streams are ready, so we wake up everyone
                    shared.stream_budget_available[dir as usize].notify_waiters();
                }
                Stream(StreamEvent::Finished { id }) => wake_stream_notify(id, &mut self.stopped),
                Stream(StreamEvent::Stopped { id, .. }) => {
                    wake_stream_notify(id, &mut self.stopped);
                    wake_stream(id, &mut self.blocked_writers);
                }
            }
        }
    }

    fn drive_timer(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(deadline) = self.inner.poll_timeout() else {
            self.timer.clear();
            return false;
        };
        match self.timer.poll(deadline, now(), cx) {
            Deadline::Elapsed => {
                self.inner.handle_timeout(now());
                true
            }
            Deadline::Pending => false,
        }
    }

    /// Wake up a blocked `Driver` task to process I/O
    pub(crate) fn wake(&mut self) {
        if let Some(x) = self.driver.take() {
            x.wake();
        }
    }

    /// Whether this connection may start sending from `candidate` instead of its current sender.
    fn switch_to(&self, candidate: &Sender) -> Switch {
        match self.socket.as_ref().map(Sender::local_addr) {
            Some(current) => self.switch_from(current, candidate),
            // Without a sender there is no address to keep; only the migration rules apply.
            None => self.migration_switch(),
        }
    }

    /// Whether this connection, currently sending from `current`, may send from `candidate`.
    fn switch_from(&self, current: SocketAddr, candidate: &Sender) -> Switch {
        if candidate.local_addr() == current {
            return Switch::SameAddress;
        }
        self.migration_switch()
    }

    /// The active-migration rules of RFC 9000 §9 for this connection's role and state.
    fn migration_switch(&self) -> Switch {
        if self.inner.side().is_server() {
            return Switch::Never;
        }
        if !self.inner.handshake_confirmed() {
            return Switch::Later;
        }
        if !self.inner.may_migrate_actively() {
            return Switch::Never;
        }
        if self.inner.can_migrate_locally() {
            Switch::Now
        } else {
            Switch::Later
        }
    }

    /// The local socket failed and this connection has no address it may send from any more.
    fn lose_path(&mut self, shared: &Shared) {
        let reason = crate::proto::TransportError::INTERNAL_ERROR(
            "QUIC local socket failed and this connection may not migrate now",
        )
        .with_cause(io::Error::new(
            io::ErrorKind::NotConnected,
            "the socket this connection sends from is unusable",
        ));
        self.terminate(reason.into(), shared);
    }

    /// Used to wake up all blocked futures when the connection becomes closed for any reason
    fn terminate(&mut self, reason: ConnectionError, shared: &Shared) {
        let reason = self.error.get_or_insert(reason).clone();
        // Whatever was waiting to be sent is never going out, and holding it would pin the
        // sender's state for a descriptor nobody will offer again.
        self.buffered_transmit = None;
        if let Some(x) = self.on_handshake_data.take() {
            let _ = x.send(());
        }
        wake_all(&mut self.blocked_writers);
        wake_all(&mut self.blocked_readers);
        shared.stream_budget_available[Dir::Uni as usize].notify_waiters();
        shared.stream_budget_available[Dir::Bi as usize].notify_waiters();
        shared.stream_incoming[Dir::Uni as usize].notify_waiters();
        shared.stream_incoming[Dir::Bi as usize].notify_waiters();
        shared.datagram_received.notify_waiters();
        shared.datagrams_unblocked.notify_waiters();
        if let Some(x) = self.on_connected.take() {
            let _ = x.send(Err(reason));
        }
        shared.handshake_confirmed.notify_waiters();
        wake_all_notify(&mut self.stopped);
        shared.closed.notify_waiters();
    }

    fn close(&mut self, error_code: VarInt, reason: Bytes, shared: &Shared) {
        self.inner.close(now(), error_code, reason);
        self.terminate(ConnectionError::LocallyClosed, shared);
        self.wake();
    }

    /// Close for a reason other than the application's explicit request
    pub(crate) fn implicit_close(&mut self, shared: &Shared) {
        self.close(0u32.into(), Bytes::new(), shared);
    }

    pub(crate) fn check_0rtt(&self) -> Result<(), ()> {
        if self.inner.is_handshaking()
            || self.inner.accepted_0rtt()
            || self.inner.side().is_server()
        {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        // The driver's Drop already delivered Drained; this only covers a state that was never
        // driven. No lock is held here, so delivering to the endpoint is safe.
        if !self.endpoint_drained {
            let link = self.endpoint.clone();
            link.deliver(self.take_endpoint_events_with_drained());
        }
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("State").field("inner", &self.inner).finish()
    }
}

fn wake_stream(stream_id: StreamId, wakers: &mut FxHashMap<StreamId, Waker>) {
    if let Some(waker) = wakers.remove(&stream_id) {
        waker.wake();
    }
}

fn wake_all(wakers: &mut FxHashMap<StreamId, Waker>) {
    wakers.drain().for_each(|(_, waker)| waker.wake())
}

fn wake_stream_notify(stream_id: StreamId, wakers: &mut FxHashMap<StreamId, Arc<Notify>>) {
    if let Some(notify) = wakers.remove(&stream_id) {
        notify.notify_waiters()
    }
}

fn wake_all_notify(wakers: &mut FxHashMap<StreamId, Arc<Notify>>) {
    wakers
        .drain()
        .for_each(|(_, notify)| notify.notify_waiters())
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    TooLarge,
    /// The connection was lost
    ConnectionLost(ConnectionError),
}

impl core::fmt::Display for SendDatagramError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedByPeer => f.write_str("datagrams not supported by peer"),
            Self::Disabled => f.write_str("datagram support disabled"),
            Self::TooLarge => f.write_str("datagram too large"),
            Self::ConnectionLost(_) => f.write_str("connection lost"),
        }
    }
}

impl std::error::Error for SendDatagramError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConnectionLost(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<ConnectionError> for SendDatagramError {
    fn from(value: ConnectionError) -> Self {
        Self::ConnectionLost(value)
    }
}

/// The maximum amount of datagrams which will be produced in a single `drive_transmit` call
///
/// This limits the amount of CPU resources consumed by datagram generation,
/// and allows other tasks (like receiving ACKs) to run in between.
pub(crate) const MAX_TRANSMIT_DATAGRAMS: usize = 20;

/// The maximum amount of datagrams that are sent in a single transmit
///
/// This can be lower than the maximum platform capabilities, to avoid excessive
/// memory allocations when calling `poll_transmit()`. Benchmarks have shown
/// that numbers around 10 are a good compromise.
const MAX_TRANSMIT_SEGMENTS: usize = 10;

#[cfg(test)]
#[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
mod tests {
    use super::*;
    use crate::driver::Instant;
    use crate::proto::ReceiveQueueLimits;
    use rama_net::address::SocketAddress;
    use rama_tls_rustls::dep::rustls::RootCertStore;
    use rama_udp::{
        DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSender, DatagramSocket,
    };
    use rama_utils::octets;
    use std::{error::Error as _, io::IoSliceMut};

    #[derive(Debug, Clone, Copy)]
    enum Failure {
        /// A destination-local refusal; the connection must keep running.
        Datagram,
        /// An invalid descriptor; the connection must terminate.
        Descriptor,
    }

    #[derive(Debug)]
    struct FailingSocket(Arc<AtomicUsize>, Failure);
    impl rama_net::stream::Socket for FailingSocket {
        fn local_addr(&self) -> io::Result<SocketAddress> {
            Ok(([127, 0, 0, 1], 1234).into())
        }
        fn peer_addr(&self) -> io::Result<SocketAddress> {
            Err(io::ErrorKind::NotConnected.into())
        }
    }
    impl DatagramSocket for FailingSocket {
        type Sender = FailingSender;
        fn create_sender(&self) -> Self::Sender {
            self.0.fetch_add(1, Ordering::Relaxed);
            FailingSender(self.0.clone(), self.1)
        }
        fn poll_recv(
            &mut self,
            _: &mut Context<'_>,
            _: &mut [IoSliceMut<'_>],
            _: &mut [DatagramMetadata],
        ) -> Poll<Result<usize, DatagramError>> {
            Poll::Pending
        }
        fn capabilities(&self) -> DatagramCapabilities {
            DatagramCapabilities::portable()
        }
    }
    #[derive(Debug)]
    struct FailingSender(Arc<AtomicUsize>, Failure);
    impl Drop for FailingSender {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }
    impl DatagramSender for FailingSender {
        fn poll_send(
            &mut self,
            _: &mut Context<'_>,
            _: &rama_udp::SendDatagram<'_>,
        ) -> Poll<Result<(), DatagramError>> {
            Poll::Ready(Err(match self.1 {
                Failure::Datagram => {
                    io::Error::new(io::ErrorKind::PermissionDenied, "injected UDP failure").into()
                }
                Failure::Descriptor => DatagramError::TooManySegments { count: 2, max: 1 },
            }))
        }
        fn capabilities(&self) -> DatagramCapabilities {
            DatagramCapabilities::portable()
        }
    }

    /// The packet sender is returned too: dropping it tells the driver the endpoint is gone.
    fn isolated_connection(
        failure: Failure,
    ) -> (
        Connecting,
        Connection,
        Arc<AtomicUsize>,
        crate::driver::queue::BoundedSender<QueuedPacket>,
    ) {
        let cert =
            rama_crypto::dep::rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.into()).unwrap();
        let config = crate::proto::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        let mut endpoint = crate::proto::Endpoint::new(
            Arc::new(crate::proto::EndpointConfig::default()),
            None,
            false,
            None,
        );
        let (handle, engine) = endpoint
            .connect(
                Instant::now(),
                config,
                ([127, 0, 0, 2], 443).into(),
                "localhost",
            )
            .unwrap();
        let alive = Arc::new(AtomicUsize::new(0));
        let sender = crate::driver::udp::Socket::new(FailingSocket(alive.clone(), failure))
            .unwrap()
            .create_sender();
        let (packets, receiver) = crate::driver::queue::bounded_queue(4);
        let (connecting, driver) = Connecting::new(
            handle,
            engine,
            EndpointLink::detached(handle),
            receiver,
            sender,
            PacketBudget::new(ReceiveQueueLimits::new(4, octets::kib(64)).unwrap()),
        );
        driver.spawn(crate::driver::lifecycle::Lifecycle::default().reserve());
        let connection = Connection(connecting.conn.as_ref().unwrap().clone());
        (connecting, connection, alive, packets)
    }

    #[tokio::test]
    async fn descriptor_failures_terminate_wake_retained_handles_and_release_the_sender() {
        let (connecting, connection, alive, _packets) = isolated_connection(Failure::Descriptor);
        let streams = connection.clone();
        let datagrams = connection.clone();
        let (connected, closed, accepted, datagram) =
            tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(
                    connecting,
                    connection.closed(),
                    streams.accept_uni(),
                    datagrams.read_datagram()
                )
            })
            .await
            .expect("all waiters must wake after a fatal send failure");
        connected.unwrap_err();
        accepted.unwrap_err();
        datagram.unwrap_err();
        let source = closed
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(
            source.to_string(),
            DatagramError::TooManySegments { count: 2, max: 1 }.to_string()
        );
        assert_eq!(
            alive.load(Ordering::Relaxed),
            0,
            "retained connection handles must not retain the send socket"
        );
        assert!(connection.close_reason().is_some());
        assert_eq!(connection.0.shared.ref_count.load(Ordering::Relaxed), 3);
        let clone = connection.clone();
        drop(clone);
        assert_eq!(connection.0.shared.ref_count.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn destination_failures_are_counted_and_the_connection_keeps_running() {
        let (connecting, connection, alive, _packets) = isolated_connection(Failure::Datagram);
        tokio::time::timeout(Duration::from_secs(3), async {
            while connection.driver_stats().send_failures < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("retransmissions keep hitting the refusing socket");
        assert!(
            connection.close_reason().is_none(),
            "a destination-local refusal must not terminate the connection"
        );
        assert_eq!(
            alive.load(Ordering::Relaxed),
            1,
            "the sender stays owned by the driver"
        );
        assert_eq!(connection.driver_stats().oversized_sends, 0);
        connection.close(0u32.into(), b"done");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), connecting)
                .await
                .unwrap(),
            Err(ConnectionError::LocallyClosed)
        ));
    }
}
