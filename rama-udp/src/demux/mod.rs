//! One listening socket's datagrams, split into an association per client.

use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::IpAddr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
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
    rt::Executor,
    telemetry::tracing,
};
use rama_net::{
    address::{SocketAddress, ip::IntoCanonicalIpAddr as _},
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
}

/// What a [`DatagramDemux`] dropped or refused since it started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DemuxStats {
    /// Datagrams dropped because their association's queue was full.
    pub dropped_queue_full: u64,
    /// Datagrams dropped because they would open an association beyond the limit.
    pub dropped_association_limit: u64,
    /// Datagrams dropped because a reply could not leave from where they were sent to.
    pub dropped_reply_source: u64,
    /// Datagrams dropped as invalid receives (see [`DatagramMetadata::validate`]).
    pub dropped_invalid: u64,
}

#[derive(Debug, Default)]
struct Counters {
    queue_full: AtomicU64,
    association_limit: AtomicU64,
    reply_source: AtomicU64,
    invalid: AtomicU64,
}

/// The addresses an association is fixed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Addresses {
    local: SocketAddress,
    peer: SocketAddress,
}

#[derive(Debug)]
struct Entry {
    queue: mpsc::Sender<RetainedDatagram>,
    generation: u64,
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
/// idle timeout, and all end when the demux stops serving. A reply leaves the listening socket for the association's peer only, from
/// the address the client sent to. A transparently redirected datagram, whose original
/// destination is not the listening address, cannot be answered from there; it is dropped
/// and counted rather than answered from the wrong address. Admission and inspection
/// limits belong to the association's service.
pub struct DatagramDemux<S> {
    socket: S,
    config: DemuxConfig,
    registry: Arc<Mutex<Registry>>,
    counters: Arc<Counters>,
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

/// A handle to read a running [`DatagramDemux`]'s counters.
#[derive(Debug, Clone)]
pub struct DemuxStatsHandle(Arc<Counters>);

impl DemuxStatsHandle {
    #[must_use]
    pub fn get(&self) -> DemuxStats {
        DemuxStats {
            dropped_queue_full: self.0.queue_full.load(Ordering::Relaxed),
            dropped_association_limit: self.0.association_limit.load(Ordering::Relaxed),
            dropped_reply_source: self.0.reply_source.load(Ordering::Relaxed),
            dropped_invalid: self.0.invalid.load(Ordering::Relaxed),
        }
    }
}

impl<S: DatagramSocket> DatagramDemux<S> {
    pub fn new(socket: S, config: DemuxConfig) -> Self {
        Self {
            socket,
            config,
            registry: Arc::default(),
            counters: Arc::default(),
        }
    }

    /// Read this demux's counters, also while it serves.
    #[must_use]
    pub fn stats(&self) -> DemuxStatsHandle {
        DemuxStatsHandle(self.counters.clone())
    }

    /// Serve every new association with `service`, spawned on `exec`, until the listening
    /// socket fails or `exec`'s graceful shutdown begins.
    pub async fn serve<Svc>(mut self, exec: Executor, service: Svc) -> Result<(), DatagramError>
    where
        Svc: Service<DemuxedSocket<S::Sender>, Error: Into<BoxError>> + Clone,
    {
        let listening = self.socket.local_addr().map_err(DatagramError::Io)?;
        let capabilities = self.socket.capabilities();
        let mut buffer = vec![0; self.config.receive_bytes.get()];
        let cancelled = async {
            match exec.guard() {
                Some(guard) => guard.cancelled().await,
                None => std::future::pending().await,
            }
        };
        let mut cancelled = std::pin::pin!(cancelled);
        loop {
            let metadata = tokio::select! {
                received = self.socket.recv(&mut buffer) => received?,
                () = &mut cancelled => return Ok(()),
            };
            if metadata.validate(buffer.len()).is_err() {
                self.counters.invalid.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            // A reply must leave from where the client sent to: the listening port, and its IP
            // or, for a wildcard listener that can choose its source, the IP sent to.
            let local = match metadata.original_destination {
                Some(destination) => destination,
                None if metadata.local.ip_addr.is_unspecified() => listening,
                None => metadata.local,
            };
            let answerable = local.port == listening.port
                && (local.ip_addr.into_canonical_ip_addr()
                    == listening.ip_addr.into_canonical_ip_addr()
                    || (listening.ip_addr.is_unspecified() && capabilities.send_source_ip));
            if !answerable {
                self.counters.reply_source.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let addresses = Addresses {
                local: local.into_canonical_ip_addr(),
                peer: metadata.peer.into_canonical_ip_addr(),
            };
            let datagram = RetainedDatagram {
                payload: Bytes::copy_from_slice(&buffer[..metadata.len]),
                metadata,
            };
            let mut registry = self.registry.lock();
            if let Some(entry) = registry.associations.get(&addresses) {
                if entry.queue.try_send(datagram).is_err() {
                    self.counters.queue_full.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
            if registry.associations.len() >= self.config.associations.get() {
                self.counters
                    .association_limit
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let (queue, receiver) = mpsc::channel(self.config.queue.get());
            let _first = queue.try_send(datagram);
            let generation = registry.next_generation;
            registry.next_generation += 1;
            registry
                .associations
                .insert(addresses, Entry { queue, generation });
            drop(registry);
            let socket = DemuxedSocket {
                receiver,
                sender: Mutex::new(self.socket.create_sender()),
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
                extensions: Extensions::new(),
            };
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
    receiver: mpsc::Receiver<RetainedDatagram>,
    /// Cloned for each send handle; never sends itself.
    sender: Mutex<T>,
    capabilities: DatagramCapabilities,
    addresses: Addresses,
    listening: SocketAddress,
    idle: Pin<Box<Sleep>>,
    idle_timeout: Duration,
    release: Release,
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
        DemuxedSender {
            inner: self.sender.lock().clone(),
            peer: self.addresses.peer,
            source: self
                .listening
                .ip_addr
                .is_unspecified()
                .then_some(self.addresses.local.ip_addr),
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
        // A queued datagram is never cut: too small a buffer leaves it queued.
        let Some(datagram) = ready!(self.receiver.poll_recv(cx)) else {
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

/// Sends a [`DemuxedSocket`]'s replies through its listening socket, to its peer only.
#[derive(Debug, Clone)]
pub struct DemuxedSender<T> {
    inner: T,
    peer: SocketAddress,
    source: Option<IpAddr>,
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
        let datagram = match (datagram.source_ip(), self.source) {
            (None, Some(source)) => datagram.with_source_ip(source),
            _ => *datagram,
        };
        self.inner.poll_send(cx, &datagram)
    }

    fn capabilities(&self) -> DatagramCapabilities {
        self.inner.capabilities()
    }
}

#[cfg(test)]
mod tests;
