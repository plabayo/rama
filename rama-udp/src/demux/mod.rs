//! One listening socket's datagrams, split into an association per client.

use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::IpAddr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, atomic::AtomicUsize},
    task::{Context, Poll, ready},
    time::Duration,
};

use ahash::HashMap;
use parking_lot::Mutex;
use rama_core::{
    Service,
    bytes::Bytes,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef},
    layer::IntoErr,
    rt::Executor,
    service::BoxService,
    telemetry::tracing,
};
use rama_net::{
    address::{
        HostWithPort, SocketAddress,
        ip::{IntoCanonicalIpAddr, IpScopes},
    },
    client::ConnectorTarget,
    socket::local_addresses,
    stream::Socket,
};
use tokio::{
    sync::mpsc,
    time::{Instant, Sleep, sleep},
};

use crate::{
    DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSender, DatagramSocket,
    DatagramSocketExt as _, RetainedDatagram, SendDatagram,
};

mod budget;
use budget::Charge;
pub use budget::SharedQueueBudget;

mod reply;
use reply::{Reader, ReplyLease, ReplySockets};

/// Bounds of a [`DatagramDemux`].
#[derive(Debug, Clone, Copy)]
pub struct DemuxConfig {
    /// Associations open at once; datagrams that would open another are dropped.
    pub associations: NonZeroUsize,
    /// Datagrams queued per association; later ones are dropped until it catches up.
    pub queue: NonZeroUsize,
    /// An association that receives nothing for this long is closed.
    pub idle_timeout: Duration,
    /// Receive buffer of the listening socket, including a coalesced group.
    pub receive_bytes: NonZeroUsize,
    /// Payload bytes queued across all associations; a datagram beyond it is dropped as if its
    /// queue were full. Each association holds at most an equal share of it, or one datagram,
    /// so a stalled one cannot keep the others from queueing.
    pub queued_bytes: NonZeroUsize,
}

/// A queued datagram, charged against [`DemuxConfig::queued_bytes`] until it is read or dropped.
#[derive(Debug)]
struct Queued {
    datagram: RetainedDatagram,
    charge: Charge,
}

/// How long the host's own addresses are trusted before they are enumerated again.
const HOST_ADDRESSES_TTL: Duration = Duration::from_secs(5);

/// The host's own addresses, enumerated only when a new association may be addressed to a
/// wildcard listener itself.
struct HostAddresses {
    source: fn() -> io::Result<Vec<IpAddr>>,
    /// `None` addresses: enumeration failed, and every address counts as the host's own.
    cached: Option<(Instant, Option<Vec<IpAddr>>)>,
}

impl HostAddresses {
    fn new() -> Self {
        Self {
            source: || local_addresses(IpScopes::all()),
            cached: None,
        }
    }

    fn contains(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let stale = self
            .cached
            .as_ref()
            .is_none_or(|(at, _)| now.duration_since(*at) >= HOST_ADDRESSES_TTL);
        if stale {
            // A short blocking call, at most once per TTL and only for a new association.
            let addresses = match (self.source)() {
                Ok(addresses) => Some(
                    addresses
                        .into_iter()
                        .map(IntoCanonicalIpAddr::into_canonical_ip_addr)
                        .collect(),
                ),
                Err(error) => {
                    tracing::debug!(%error, "host addresses unavailable: treating all as own");
                    None
                }
            };
            self.cached = Some((now, addresses));
        }
        self.cached
            .as_ref()
            .is_none_or(|(_, addresses)| addresses.as_ref().is_none_or(|all| all.contains(&ip)))
    }

    /// Whether `destination` is `listening` itself, so that a bridge to it would loop back.
    fn is_listener(&mut self, destination: SocketAddress, listening: SocketAddress) -> bool {
        if destination.port != listening.port {
            return false;
        }
        let ip = destination.ip_addr.into_canonical_ip_addr();
        ip.is_unspecified()
            || ip == listening.ip_addr.into_canonical_ip_addr()
            || (listening.ip_addr.is_unspecified() && self.is_host(ip))
    }

    /// Whether `ip` is this host itself, on any port.
    fn is_host(&mut self, ip: IpAddr) -> bool {
        let ip = ip.into_canonical_ip_addr();
        ip.is_unspecified() || ip.is_loopback() || self.contains(ip)
    }
}

/// The addresses an association is fixed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Addresses {
    local: SocketAddress,
    peer: SocketAddress,
    /// The zone a link-local address is only meaningful with: the same address on
    /// two links is two associations.
    interface: Option<u32>,
}

impl Addresses {
    fn new(local: SocketAddress, peer: SocketAddress, interface: Option<u32>) -> Self {
        let local = local.into_canonical_ip_addr();
        let peer = peer.into_canonical_ip_addr();
        // Elsewhere the arrival interface is routing, not identity.
        let interface = interface.filter(|_| needs_zone(local.ip_addr) || needs_zone(peer.ip_addr));
        Self {
            local,
            peer,
            interface,
        }
    }
}

/// IPv6 link-local unicast (fe80::/10), or multicast scoped to one interface or one
/// link (ffx1::/16, ffx2::/16), whose zone is that interface. Wider scopes can span
/// interfaces, so arrival over one does not name their zone (RFC 4007 §6).
fn needs_zone(ip: IpAddr) -> bool {
    let IpAddr::V6(ip) = ip else { return false };
    let first = ip.segments()[0];
    first & 0xffc0 == 0xfe80 || matches!(first & 0xff0f, 0xff01 | 0xff02)
}

#[derive(Debug)]
struct Entry {
    queue: mpsc::Sender<Queued>,
    generation: u64,
    /// Bytes this association holds queued.
    queued: Arc<AtomicUsize>,
}

#[derive(Debug, Default)]
struct Registry {
    associations: HashMap<Addresses, Entry>,
    next_generation: u64,
}

/// Splits the datagrams of one listening socket into an association per `(local, peer)`
/// address pair, each served by its own service as a [`DemuxedSocket`]: the datagram
/// counterpart of accepting connections.
///
/// Every association is bounded: by [`DemuxConfig::associations`], by its queue, and by its
/// idle timeout, and all end when the demux stops serving. A reply leaves the listening socket
/// for the association's peer only, from the address the client sent to. A transparently
/// redirected datagram, whose original destination is not the listening address, cannot be
/// answered from there; it is dropped rather than answered from the wrong address, unless the
/// socket selects a reply's whole source ([`DatagramCapabilities::send_source_port`] with
/// `send_source_ip`), as a transparent proxy flow does, or the demux can bind a socket at that
/// destination ([`DatagramDemux::with_reply_sockets`]): then every original destination is an
/// association of its own, answered from that destination. A redirected association carries
/// its original destination as its [`ConnectorTarget`], which one addressed to this listener
/// itself never has (its port and its IP, or for a wildcard listener also loopback or any of
/// the host's addresses), so a bridge cannot loop it back. Admission and inspection limits
/// belong to the association's service.
pub struct DatagramDemux<S> {
    socket: S,
    config: DemuxConfig,
    registry: Arc<Mutex<Registry>>,
    /// Payload bytes queued across all associations.
    queued: Arc<AtomicUsize>,
    host: HostAddresses,
    reply_sockets: Option<BoxService<SocketAddress, S, BoxError>>,
    shared_budget: Option<SharedQueueBudget>,
}

impl<S: fmt::Debug> fmt::Debug for DatagramDemux<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramDemux")
            .field("socket", &self.socket)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// A demux that stops serving ends its associations too: nothing more arrives for them.
impl<S> Drop for DatagramDemux<S> {
    fn drop(&mut self) {
        self.registry.lock().associations.clear();
    }
}

impl<S: DatagramSocket> DatagramDemux<S> {
    pub fn new(socket: S, config: DemuxConfig) -> Self {
        Self {
            socket,
            config,
            registry: Arc::default(),
            queued: Arc::default(),
            host: HostAddresses::new(),
            reply_sockets: None,
            shared_budget: None,
        }
    }

    /// Hold what this demux queues within `budget` too, which other demuxes may share.
    #[must_use]
    pub fn with_shared_budget(mut self, budget: SharedQueueBudget) -> Self {
        self.shared_budget = Some(budget);
        self
    }

    /// Answer a redirected datagram the listening socket cannot from a socket that `bind`
    /// binds at its original destination, as a transparent proxy must for a client that
    /// accepts replies only from where it sent to.
    ///
    /// Associations addressed to one destination share its socket, which closes with the
    /// last of them and is read too, since redirection may deliver to it. On Linux, a
    /// [`UdpSocketFactory`](crate::UdpSocketFactory) binds such sockets when its
    /// [`SocketOptions`](rama_net::socket::SocketOptions) set `ip_transparent`,
    /// `ip_transparent_v6` and `reuse_address`.
    #[must_use]
    pub fn with_reply_sockets<B>(mut self, bind: B) -> Self
    where
        B: Service<SocketAddress, Output = S, Error: Into<BoxError>>,
    {
        self.reply_sockets = Some(IntoErr::<_, BoxError>::new(bind).boxed());
        self
    }

    /// Serve every new association with `service`, spawned on `exec`, until the listening
    /// socket fails or `exec`'s graceful shutdown begins.
    pub async fn serve<Svc>(mut self, exec: Executor, service: Svc) -> Result<(), DatagramError>
    where
        S: Send + 'static,
        S::Sender: Clone,
        Svc: Service<DemuxedSocket<S::Sender>, Error: Into<BoxError>> + Clone,
    {
        let listening = self.socket.local_addr().map_err(DatagramError::Io)?;
        let capabilities = self.socket.capabilities();
        let mut buffer = vec![0; self.config.receive_bytes.get()];
        let share = self.config.queued_bytes.get() / self.config.associations;
        let (incoming, mut from_reply_sockets) = mpsc::channel(self.config.queue.get());
        let reply = self.reply_sockets.take().map(|bind| {
            let reader = Reader {
                incoming,
                queued: self.queued.clone(),
                shared: self.shared_budget.clone(),
                queued_bytes: self.config.queued_bytes.get(),
                receive_bytes: self.config.receive_bytes.get(),
            };
            ReplySockets::new(bind, reader)
        });
        let cancelled = async {
            match exec.guard() {
                Some(guard) => guard.cancelled().await,
                None => std::future::pending().await,
            }
        };
        let mut cancelled = std::pin::pin!(cancelled);
        loop {
            let (mut datagram, local, via_reply_socket) = tokio::select! {
                received = self.socket.recv(&mut buffer) => {
                    let metadata = received?;
                    if let Err(error) = metadata.validate(buffer.len()) {
                        tracing::trace!(
                            %error,
                            peer = %metadata.peer,
                            "dropped invalid datagram"
                        );
                        continue;
                    }
                    // A reply must leave from where the client sent to: the listening port, and
                    // its IP or, for a wildcard listener that can choose its source, the IP sent to.
                    let local = match metadata.original_destination {
                        Some(destination) => destination,
                        None if metadata.local.ip_addr.is_unspecified() => listening,
                        None => metadata.local,
                    };
                    // A socket that selects a reply's whole source answers every original
                    // destination; otherwise a redirected one needs a socket bound there.
                    let from_listener = full_source(capabilities)
                        || (local.port == listening.port
                            && (local.ip_addr.into_canonical_ip_addr()
                                == listening.ip_addr.into_canonical_ip_addr()
                                || (listening.ip_addr.is_unspecified()
                                    && capabilities.send_source_ip)));
                    if !from_listener {
                        let Some(destination) =
                            metadata.original_destination.filter(|_| reply.is_some())
                        else {
                            tracing::trace!(
                                peer = %metadata.peer,
                                %local,
                                "dropped redirected datagram: cannot reply from its destination"
                            );
                            continue;
                        };
                        // The proxy's own forward to this host would reach a reply socket there.
                        if self.host.is_host(destination.ip_addr) {
                            tracing::trace!(
                                peer = %metadata.peer,
                                %destination,
                                "dropped datagram redirected from this host"
                            );
                            continue;
                        }
                    }
                    let Some(charge) = Charge::try_new(
                        &self.queued,
                        self.shared_budget.as_ref(),
                        metadata.len,
                        self.config.queued_bytes.get(),
                    ) else {
                        tracing::trace!(
                            peer = %metadata.peer,
                            len = metadata.len,
                            "dropped datagram: queued bytes budget full"
                        );
                        continue;
                    };
                    let datagram = Queued {
                        datagram: RetainedDatagram {
                            payload: Bytes::copy_from_slice(&buffer[..metadata.len]),
                            metadata,
                        },
                        charge,
                    };
                    (datagram, local, !from_listener)
                }
                Some(datagram) = from_reply_sockets.recv(), if reply.is_some() => {
                    let local = datagram.datagram.metadata.local;
                    (datagram, local, true)
                }
                () = &mut cancelled => return Ok(()),
            };
            let addresses = Addresses::new(
                local,
                datagram.datagram.metadata.peer,
                datagram.datagram.metadata.interface_index,
            );
            let original_destination = datagram.datagram.metadata.original_destination;
            {
                let registry = self.registry.lock();
                if let Some(entry) = registry.associations.get(&addresses) {
                    if !datagram.charge.try_assign(&entry.queued, share)
                        || entry.queue.try_send(datagram).is_err()
                    {
                        tracing::trace!(
                            peer = %addresses.peer,
                            "dropped datagram: association queue full"
                        );
                    }
                    continue;
                }
                if registry.associations.len() >= self.config.associations.get() {
                    tracing::trace!(
                        peer = %addresses.peer,
                        "dropped datagram: association limit reached"
                    );
                    continue;
                }
            }
            let (sender, reply_lease) = match &reply {
                Some(reply) if via_reply_socket => match reply.lease(local, &exec).await {
                    Ok((sender, lease)) => (sender, Some(lease)),
                    Err(error) => {
                        tracing::debug!(%error, %local, "no datagram reply socket at destination");
                        continue;
                    }
                },
                _ => (self.socket.create_sender(), None),
            };
            let (queue, receiver) = mpsc::channel(self.config.queue.get());
            let queued = Arc::new(AtomicUsize::new(0));
            // An association's first datagram always fits its share.
            let _assigned = datagram.charge.try_assign(&queued, share);
            let _first = queue.try_send(datagram);
            let mut registry = self.registry.lock();
            let generation = registry.next_generation;
            registry.next_generation += 1;
            registry.associations.insert(
                addresses,
                Entry {
                    queue,
                    generation,
                    queued,
                },
            );
            drop(registry);
            let socket = DemuxedSocket {
                receiver,
                sender: Mutex::new(sender),
                capabilities,
                addresses,
                listening,
                idle: Box::pin(sleep(self.config.idle_timeout)),
                idle_timeout: self.config.idle_timeout,
                release: Release {
                    registry: self.registry.clone(),
                    addresses,
                    generation,
                },
                reply: reply_lease,
                extensions: Extensions::new(),
            };
            // Only a redirected datagram names a destination beyond this proxy.
            if let Some(destination) = original_destination {
                if self.host.is_listener(destination, listening) {
                    tracing::debug!(
                        peer = %addresses.peer,
                        %destination,
                        "datagram association addressed to the listener itself: no target"
                    );
                } else {
                    socket.extensions.insert(ConnectorTarget(HostWithPort::from(
                        destination.into_canonical_ip_addr(),
                    )));
                }
            }
            let service = service.clone();
            exec.spawn_task(async move {
                if let Err(error) = service.serve(socket).await {
                    let error: BoxError = error.into();
                    tracing::debug!(%error, "datagram association ended with an error");
                }
            });
        }
    }
}

/// Removes an association from its demux once its socket is gone or idle, so the next
/// datagram from its peer opens a new one.
#[derive(Debug)]
struct Release {
    registry: Arc<Mutex<Registry>>,
    addresses: Addresses,
    generation: u64,
}

impl Release {
    fn release(&self) {
        let mut registry = self.registry.lock();
        if registry
            .associations
            .get(&self.addresses)
            .is_some_and(|entry| entry.generation == self.generation)
        {
            registry.associations.remove(&self.addresses);
        }
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        self.release();
    }
}

/// One association of a [`DatagramDemux`]: the datagrams one peer sent to one local
/// address, and replies to that peer only.
pub struct DemuxedSocket<T> {
    receiver: mpsc::Receiver<Queued>,
    /// Cloned for each send handle; never sends itself.
    sender: Mutex<T>,
    capabilities: DatagramCapabilities,
    addresses: Addresses,
    listening: SocketAddress,
    idle: Pin<Box<Sleep>>,
    idle_timeout: Duration,
    release: Release,
    /// The socket bound at this association's destination, when replies leave from there.
    reply: Option<ReplyLease<T>>,
    extensions: Extensions,
}

impl<T: fmt::Debug> fmt::Debug for DemuxedSocket<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DemuxedSocket")
            .field("local", &self.addresses.local)
            .field("peer", &self.addresses.peer)
            .finish_non_exhaustive()
    }
}

impl<T> ExtensionsRef for DemuxedSocket<T> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<T> DemuxedSocket<T> {
    /// The zone of this association's link-local address, if it has one: what an egress
    /// to its destination must scope it with.
    #[must_use]
    pub fn interface_index(&self) -> Option<u32> {
        self.addresses.interface
    }
}

impl<T: Send + 'static> Socket for DemuxedSocket<T> {
    fn local_addr(&self) -> io::Result<SocketAddress> {
        Ok(self.addresses.local)
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        Ok(self.addresses.peer)
    }
}

impl<T: DatagramSender + Clone> DatagramSocket for DemuxedSocket<T> {
    type Sender = DemuxedSender<T>;

    fn create_sender(&self) -> Self::Sender {
        // A socket bound at the destination already sends from it.
        let listener = self.reply.is_none();
        let full_source = listener && full_source(self.capabilities);
        DemuxedSender {
            inner: self.sender.lock().clone(),
            peer: self.addresses.peer,
            source: (full_source || (listener && self.listening.ip_addr.is_unspecified()))
                .then_some(self.addresses.local.ip_addr),
            source_port: full_source.then_some(self.addresses.local.port),
            source_interface: self.addresses.interface,
        }
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>> {
        if buffers.len() != metadata.len() {
            return Poll::Ready(Err(DatagramError::ReceiveSlotMismatch {
                buffers: buffers.len(),
                metadata: metadata.len(),
            }));
        }
        let Some(buffer) = buffers.first_mut() else {
            return Poll::Ready(Err(DatagramError::EmptyReceiveBatch));
        };
        if self.idle.as_mut().poll(cx).is_ready() {
            self.release.release();
            self.receiver.close();
            return Poll::Ready(Err(DatagramError::Closed));
        }
        // A queued datagram is never cut: too small a buffer discards this packet.
        let Some(Queued { datagram, .. }) = ready!(self.receiver.poll_recv(cx)) else {
            return Poll::Ready(Err(DatagramError::Closed));
        };
        if datagram.payload.len() > buffer.len() {
            return Poll::Ready(Err(DatagramError::PayloadTooLarge {
                len: datagram.payload.len(),
                max: buffer.len(),
            }));
        }
        buffer[..datagram.payload.len()].copy_from_slice(&datagram.payload);
        metadata[0] = datagram.metadata;
        self.idle.as_mut().reset(Instant::now() + self.idle_timeout);
        Poll::Ready(Ok(1))
    }

    fn capabilities(&self) -> DatagramCapabilities {
        self.capabilities
    }
}

/// Whether `capabilities` let a reply leave from any address, port included.
const fn full_source(capabilities: DatagramCapabilities) -> bool {
    capabilities.send_source_ip && capabilities.send_source_port
}

/// Sends a [`DemuxedSocket`]'s replies through its listening socket, to its peer only.
#[derive(Debug, Clone)]
pub struct DemuxedSender<T> {
    inner: T,
    peer: SocketAddress,
    source: Option<IpAddr>,
    source_port: Option<u16>,
    source_interface: Option<u32>,
}

impl<T: DatagramSender> DatagramSender for DemuxedSender<T> {
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        if datagram.destination().into_canonical_ip_addr() != self.peer {
            return Poll::Ready(Err(DatagramError::ForeignDestination(
                datagram.destination(),
            )));
        }
        let mut datagram = *datagram;
        if let (None, Some(source)) = (datagram.source_ip(), self.source) {
            datagram = datagram.with_source_ip(source);
        }
        if let (None, Some(port)) = (datagram.source_port(), self.source_port) {
            datagram = datagram.with_source_port(port);
        }
        // Replies on a link travel back over that link.
        if let (None, Some(interface)) = (datagram.source_interface(), self.source_interface) {
            datagram = datagram.with_source_interface(interface);
        }
        self.inner.poll_send(cx, &datagram)
    }

    fn capabilities(&self) -> DatagramCapabilities {
        self.inner.capabilities()
    }
}

#[cfg(test)]
mod tests;
