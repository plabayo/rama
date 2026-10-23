use std::{
    fmt,
    future::Future as _,
    io,
    io::IoSliceMut,
    num::NonZeroUsize,
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use parking_lot::Mutex;
use rama_core::{
    bytes::{Bytes, BytesMut},
    extensions::ExtensionsRef,
    rt::Executor,
};
use rama_http::{
    datagram::{
        HttpDatagramSession, NativeDatagrams, NativeSendError, NativeSendPolicy, SessionConfig,
        SessionError, SessionEvent, SessionReceiver, SessionSender,
        capsule::MAX_OVERSIZED_DATAGRAM_PREFIX,
    },
    io::upgrade::Upgraded,
};
use rama_net::{
    address::{SocketAddress, ip::IntoCanonicalIpAddr as _},
    stream::Socket,
};
use rama_udp::{
    DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSender, DatagramSocket,
    SendDatagram,
};
use rama_utils::macros::generate_set_and_with;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Notify, futures::OwnedNotified, mpsc},
    time::Instant,
};

use super::{ContextId, ContextPayloadError, MAX_UDP_PAYLOAD, decode_context_payload};

/// How long a closing tunnel may take to finish its direction before the carrier is dropped.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// Bytes of the Context ID prefix this socket sends: Context ID 0 encodes in one byte.
const CONTEXT_PREFIX: usize = 1;

/// The [`SessionConfig`] a CONNECT-UDP tunnel's [`HttpDatagramSession`] needs.
///
/// Native sends report a full queue instead of dropping older payloads, so the socket can
/// apply backpressure, and oversized DATAGRAM capsules report their Context ID so a
/// context-0 payload above the UDP limit aborts the stream (RFC 9298 §5).
#[must_use]
pub fn session_config() -> SessionConfig {
    let mut config = SessionConfig {
        native_send: NativeSendPolicy::RejectWhenFull,
        ..Default::default()
    };
    config.capsules.oversized_datagram_prefix = MAX_OVERSIZED_DATAGRAM_PREFIX;
    config
}

/// Limits of a [`ConnectUdpSocket`].
#[derive(Debug, Clone, Copy)]
pub struct ConnectUdpSocketConfig {
    /// UDP payloads accepted for sending but not yet handed to the HTTP carrier.
    queue: NonZeroUsize,
    /// How long the tunnel may forward nothing in either direction before it closes.
    idle_timeout: Duration,
}

impl Default for ConnectUdpSocketConfig {
    fn default() -> Self {
        Self {
            queue: NonZeroUsize::new(256).unwrap_or(NonZeroUsize::MIN),
            // RFC 9298 §3.1: idle closes SHOULD NOT use less than two minutes.
            idle_timeout: Duration::from_mins(2),
        }
    }
}

impl ConnectUdpSocketConfig {
    generate_set_and_with! {
        /// UDP payloads accepted for sending but not yet handed to the HTTP carrier.
        pub fn queue(mut self, queue: NonZeroUsize) -> Self {
            self.queue = queue;
            self
        }
    }

    generate_set_and_with! {
        /// How long the tunnel may forward nothing before it closes ([`ConnectUdpStats`]
        /// drops never count as progress).
        pub fn idle_timeout(mut self, timeout: Duration) -> Self {
            self.idle_timeout = timeout;
            self
        }
    }
}

/// Counters and outcome of a [`ConnectUdpSocket`], readable after the socket is gone.
#[derive(Debug, Default)]
pub struct ConnectUdpStats {
    sent: AtomicU64,
    received: AtomicU64,
    dropped_too_large: AtomicU64,
    dropped_unknown_context: AtomicU64,
    close: Mutex<Option<ConnectUdpClose>>,
}

impl ConnectUdpStats {
    /// Why the tunnel stopped, once it did.
    #[must_use]
    pub fn close_reason(&self) -> Option<ConnectUdpClose> {
        *self.close.lock()
    }

    /// UDP payloads handed to the HTTP carrier.
    #[must_use]
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// UDP payloads received from the HTTP carrier.
    #[must_use]
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    /// Payloads dropped as too large for the native carrier (never sent as capsules).
    #[must_use]
    pub fn dropped_too_large(&self) -> u64 {
        self.dropped_too_large.load(Ordering::Relaxed)
    }

    /// Received datagrams dropped for a Context ID other than 0 or a truncated one.
    #[must_use]
    pub fn dropped_unknown_context(&self) -> u64 {
        self.dropped_unknown_context.load(Ordering::Relaxed)
    }
}

/// Why a [`ConnectUdpSocket`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectUdpClose {
    /// The peer finished the tunnel or it was closed locally.
    Closed,
    /// Nothing was forwarded for the [idle timeout](ConnectUdpSocketConfig::with_idle_timeout).
    Idle,
    /// The HTTP carrier failed or the peer broke the protocol.
    Failed,
}

struct Shared {
    native: Option<NativeDatagrams>,
    stats: Arc<ConnectUdpStats>,
    closed: AtomicBool,
    recv_waker: Mutex<Option<Waker>>,
    // Notified whenever the pump takes a payload from the queue, and on close.
    space: Arc<Notify>,
    // Notified on close, so the pump stops whatever it waits for.
    stopped: Notify,
    progress: Mutex<Instant>,
    peer: SocketAddress,
}

impl Shared {
    fn progressed(&self) {
        *self.progress.lock() = Instant::now();
    }

    /// End the tunnel from any side: every waiter (receiver, senders, pump) is woken.
    fn close(&self, reason: ConnectUdpClose) {
        self.stats.close.lock().get_or_insert(reason);
        self.closed.store(true, Ordering::Release);
        if let Some(waker) = self.recv_waker.lock().take() {
            waker.wake();
        }
        self.space.notify_waiters();
        self.stopped.notify_waiters();
    }

    /// Resolves once the tunnel is closed.
    async fn wait_closed(&self) {
        loop {
            let mut notified = pin!(self.stopped.notified());
            // Registered before the check, so a close in between is not missed.
            notified.as_mut().enable();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }

    fn idle_deadline(&self, idle_timeout: Duration) -> Instant {
        *self.progress.lock() + idle_timeout
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn max_payload(&self) -> usize {
        self.native
            .as_ref()
            .and_then(|native| native.channel().max_payload_size())
            .map_or(MAX_UDP_PAYLOAD, |max| {
                max.saturating_sub(CONTEXT_PREFIX).min(MAX_UDP_PAYLOAD)
            })
    }
}

/// A [`DatagramSocket`] carrying UDP payloads through a CONNECT-UDP tunnel ([RFC 9298]).
///
/// Wraps the [`HttpDatagramSession`] of an accepted tunnel on any HTTP version, so a QUIC
/// endpoint, a relay or a proxy can use the tunnel as a UDP socket fixed to one peer.
/// Payloads travel with Context ID 0; datagrams for other contexts are dropped and
/// counted. Sending never waits for delivery, but a full queue applies backpressure
/// (`Pending`) instead of dropping older payloads. Native HTTP/3 payloads above the
/// current limit are dropped and counted, never re-sent as capsules (RFC 9298 §6.1).
///
/// [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
pub struct ConnectUdpSocket<T = Upgraded> {
    receiver: SessionReceiver<T>,
    shared: Arc<Shared>,
    tx: mpsc::Sender<Bytes>,
    local: SocketAddress,
}

impl<T> fmt::Debug for ConnectUdpSocket<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectUdpSocket")
            .field("local", &self.local)
            .field("peer", &self.shared.peer)
            .field("stats", &self.shared.stats)
            .finish_non_exhaustive()
    }
}

impl<T> ConnectUdpSocket<T>
where
    T: AsyncRead + AsyncWrite + ExtensionsRef + Send + 'static,
{
    /// Turn an established tunnel's session into a socket fixed to `peer`.
    ///
    /// Build the session with [`session_config`].
    ///
    /// `local` and `peer` are what [`Socket`] reports: the target's address on the
    /// client side, the client's or a documented placeholder on the proxy side.
    /// IPv4-mapped IPv6 addresses are reported as IPv4.
    pub fn new(
        exec: &Executor,
        session: HttpDatagramSession<T>,
        local: SocketAddress,
        peer: SocketAddress,
        config: ConnectUdpSocketConfig,
    ) -> Self {
        let (local, peer) = (
            local.into_canonical_ip_addr(),
            peer.into_canonical_ip_addr(),
        );
        let native = session.native().cloned();
        let (sender, receiver) = session.split();
        let shared = Arc::new(Shared {
            native,
            stats: Arc::default(),
            closed: AtomicBool::new(false),
            recv_waker: Mutex::new(None),
            space: Arc::new(Notify::new()),
            stopped: Notify::new(),
            progress: Mutex::new(Instant::now()),
            peer,
        });
        let (tx, rx) = mpsc::channel(config.queue.get());
        exec.spawn_task(pump(sender, rx, shared.clone(), config.idle_timeout));
        Self {
            receiver,
            shared,
            tx,
            local,
        }
    }
}

impl<T> ConnectUdpSocket<T> {
    /// The tunnel's counters, shared with every sender.
    #[must_use]
    pub fn stats(&self) -> Arc<ConnectUdpStats> {
        self.shared.stats.clone()
    }

    /// Why the tunnel stopped, once it did.
    #[must_use]
    pub fn close_reason(&self) -> Option<ConnectUdpClose> {
        self.shared.stats.close_reason()
    }

    /// The largest UDP payload that can be sent now: the native datagram limit minus the
    /// Context ID, or the RFC 9298 maximum on capsule carriers.
    #[must_use]
    pub fn max_payload(&self) -> usize {
        self.shared.max_payload()
    }
}

/// Send handle of a [`ConnectUdpSocket`], with its own readiness registration.
///
/// A send waiting for room reserves nothing, so cancelling it holds no queue slot.
pub struct ConnectUdpSender {
    tx: mpsc::Sender<Bytes>,
    space: Option<Pin<Box<OwnedNotified>>>,
    shared: Arc<Shared>,
}

impl fmt::Debug for ConnectUdpSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectUdpSender")
            .field("peer", &self.shared.peer)
            .finish_non_exhaustive()
    }
}

fn capabilities(shared: &Shared) -> DatagramCapabilities {
    let max = shared.max_payload();
    let mut capabilities = DatagramCapabilities::portable();
    capabilities.max_payload_ipv4 = max;
    capabilities.max_payload_ipv6 = max;
    // No MTU discovery through the tunnel: the inner sender sizes its packets itself.
    capabilities.may_fragment = true;
    capabilities.receive_truncation = true;
    capabilities
}

impl DatagramSender for ConnectUdpSender {
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        if self.shared.is_closed() {
            return Poll::Ready(Err(DatagramError::Closed));
        }
        if datagram.destination() != self.shared.peer {
            return Poll::Ready(Err(DatagramError::ForeignDestination(
                datagram.destination(),
            )));
        }
        if datagram.segment_size().is_some() {
            return Poll::Ready(Err(DatagramError::TooManySegments { count: 2, max: 1 }));
        }
        let payload = datagram.payload();
        let max = self.shared.max_payload();
        if payload.len() > max {
            return Poll::Ready(Err(DatagramError::PayloadTooLarge {
                len: payload.len(),
                max,
            }));
        }
        let mut encoded = BytesMut::with_capacity(CONTEXT_PREFIX + payload.len());
        encoded.extend_from_slice(&[0x00]);
        encoded.extend_from_slice(payload);
        let mut encoded = encoded.freeze();
        loop {
            // Registered before the attempt: room made in between wakes this registration.
            let space = self
                .space
                .get_or_insert_with(|| Box::pin(self.shared.space.clone().notified_owned()));
            match self.tx.try_send(encoded) {
                Ok(()) => {
                    self.space = None;
                    return Poll::Ready(Ok(()));
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(DatagramError::Closed));
                }
                Err(mpsc::error::TrySendError::Full(returned)) => encoded = returned,
            }
            if space.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.space = None;
            if self.shared.is_closed() {
                return Poll::Ready(Err(DatagramError::Closed));
            }
        }
    }

    fn capabilities(&self) -> DatagramCapabilities {
        capabilities(&self.shared)
    }
}

impl<T> Socket for ConnectUdpSocket<T>
where
    T: Send + 'static,
{
    fn local_addr(&self) -> io::Result<SocketAddress> {
        Ok(self.local)
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        Ok(self.shared.peer)
    }
}

impl<T> DatagramSocket for ConnectUdpSocket<T>
where
    T: AsyncRead + Send + 'static,
{
    type Sender = ConnectUdpSender;

    fn create_sender(&self) -> Self::Sender {
        ConnectUdpSender {
            tx: self.tx.clone(),
            space: None,
            shared: self.shared.clone(),
        }
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>> {
        let (Some(buffer), Some(meta)) = (buffers.first_mut(), metadata.first_mut()) else {
            return Poll::Ready(Err(DatagramError::EmptyReceiveBatch));
        };
        loop {
            if self.shared.is_closed() {
                return Poll::Ready(Err(DatagramError::Closed));
            }
            let event = match self.receiver.poll_recv(cx) {
                Poll::Pending => {
                    *self.shared.recv_waker.lock() = Some(cx.waker().clone());
                    // A close between the check above and this registration must not be missed.
                    if self.shared.is_closed() {
                        return Poll::Ready(Err(DatagramError::Closed));
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Ok(Some(event))) => event,
                Poll::Ready(Ok(None)) => {
                    self.shared.close(ConnectUdpClose::Closed);
                    return Poll::Ready(Err(DatagramError::Closed));
                }
                Poll::Ready(Err(error)) => {
                    self.shared.close(ConnectUdpClose::Failed);
                    return Poll::Ready(Err(session_error(error)));
                }
            };
            match event {
                SessionEvent::Datagram { payload, .. } => match decode_context_payload(&payload) {
                    Ok((ContextId::UDP, udp)) => {
                        let copied = udp.len().min(buffer.len());
                        buffer[..copied].copy_from_slice(&udp[..copied]);
                        let mut received = DatagramMetadata::empty();
                        received.len = copied;
                        received.original_len = udp.len();
                        received.peer = self.shared.peer;
                        received.local = self.local;
                        received.truncated = copied < udp.len();
                        *meta = received;
                        self.shared.stats.received.fetch_add(1, Ordering::Relaxed);
                        self.shared.progressed();
                        return Poll::Ready(Ok(1));
                    }
                    Ok(_) | Err(ContextPayloadError::Truncated) => {
                        self.shared
                            .stats
                            .dropped_unknown_context
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(ContextPayloadError::UdpPayloadTooLarge) => {
                        return Poll::Ready(Err(self.abort()));
                    }
                },
                SessionEvent::OversizedDatagram { prefix, length } => {
                    // RFC 9298 §5: a context-0 payload above the UDP limit aborts the stream.
                    if let Ok((ContextId::UDP, rest)) = decode_context_payload(&prefix) {
                        let id_len = (prefix.len() - rest.len()) as u64;
                        if length.saturating_sub(id_len) > MAX_UDP_PAYLOAD as u64 {
                            return Poll::Ready(Err(self.abort()));
                        }
                    }
                    self.shared
                        .stats
                        .dropped_too_large
                        .fetch_add(1, Ordering::Relaxed);
                }
                // Control and unknown capsules carry nothing for this tunnel.
                SessionEvent::Capsule { .. }
                | SessionEvent::UnknownCapsule(_)
                | SessionEvent::UnknownCapsuleData(_) => {}
            }
        }
    }

    fn capabilities(&self) -> DatagramCapabilities {
        capabilities(&self.shared)
    }
}

impl<T> ConnectUdpSocket<T> {
    fn abort(&self) -> DatagramError {
        self.receiver.abort_malformed();
        self.shared.close(ConnectUdpClose::Failed);
        DatagramError::Io(io::ErrorKind::InvalidData.into())
    }
}

fn session_error(error: SessionError) -> DatagramError {
    match error {
        SessionError::Io(error) => DatagramError::Io(error),
        _ => DatagramError::Closed,
    }
}

/// Hand queued payloads to the carrier in order, and end the tunnel when idle or closed.
async fn pump<T: AsyncWrite + Send>(
    mut sender: SessionSender<T>,
    mut rx: mpsc::Receiver<Bytes>,
    shared: Arc<Shared>,
    idle_timeout: Duration,
) {
    let reason = forward(&mut sender, &mut rx, &shared, idle_timeout).await;
    shared.close(reason);
    // Queued payloads are released; blocked senders were woken by the close.
    drop(rx);
    // A graceful end of our direction within a short grace, else the carrier is dropped:
    // a peer that stopped reading must not hold the stream.
    if !matches!(
        tokio::time::timeout(CLOSE_GRACE, sender.close()).await,
        Ok(Ok(()))
    ) {
        sender.abort();
    }
}

/// Forward queued payloads until the tunnel closes or idles out; every wait, including a
/// carrier send blocked by the peer, is bounded by the idle deadline and a close.
async fn forward<T: AsyncWrite>(
    sender: &mut SessionSender<T>,
    rx: &mut mpsc::Receiver<Bytes>,
    shared: &Shared,
    idle_timeout: Duration,
) -> ConnectUdpClose {
    let mut closed = pin!(shared.wait_closed());
    loop {
        let payload = tokio::select! {
            () = &mut closed => return ConnectUdpClose::Closed,
            payload = rx.recv() => payload,
            () = tokio::time::sleep_until(shared.idle_deadline(idle_timeout)) => {
                if shared.idle_deadline(idle_timeout) <= Instant::now() {
                    return ConnectUdpClose::Idle;
                }
                continue;
            }
        };
        let Some(payload) = payload else {
            // Every socket and sender handle is gone: finish our side of the tunnel.
            return ConnectUdpClose::Closed;
        };
        shared.space.notify_waiters();
        // One send future for the whole wait: restarting it could repeat the payload.
        let mut sending = pin!(send(sender, shared, payload));
        loop {
            tokio::select! {
                () = &mut closed => return ConnectUdpClose::Closed,
                sent = &mut sending => match sent {
                    Ok(()) => break,
                    Err(reason) => return reason,
                },
                () = tokio::time::sleep_until(shared.idle_deadline(idle_timeout)) => {
                    if shared.idle_deadline(idle_timeout) <= Instant::now() {
                        return ConnectUdpClose::Idle;
                    }
                }
            }
        }
    }
}

async fn send<T: AsyncWrite>(
    sender: &mut SessionSender<T>,
    shared: &Shared,
    payload: Bytes,
) -> Result<(), ConnectUdpClose> {
    loop {
        // Registered before the attempt, so room made in between is not missed.
        let ready = shared
            .native
            .as_ref()
            .map(|native| native.channel().send_ready());
        match sender.send_datagram(payload.clone()).await {
            Ok(_) => {
                shared.stats.sent.fetch_add(1, Ordering::Relaxed);
                shared.progressed();
                return Ok(());
            }
            Err(SessionError::Native(NativeSendError::TooLarge { .. })) => {
                shared
                    .stats
                    .dropped_too_large
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Err(SessionError::Native(NativeSendError::Full)) => match ready {
                Some(ready) => ready.await,
                None => return Ok(()),
            },
            Err(SessionError::Native(NativeSendError::Closed)) => {
                return Err(ConnectUdpClose::Closed);
            }
            Err(_) => return Err(ConnectUdpClose::Failed),
        }
        if shared.is_closed() {
            return Err(ConnectUdpClose::Closed);
        }
    }
}

#[cfg(test)]
mod tests;
