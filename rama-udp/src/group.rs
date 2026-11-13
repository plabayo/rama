//! Multiplex association readiness into one socket, without queuing or copying payloads.
//!
//! Attach sockets with distinct concrete peers, then keep each attachment's `run` future alive.
//! The consuming endpoint polls directly into its own receive buffers. Paths track readiness
//! independently so silent peers are not repeatedly polled. Native capabilities, including
//! fragmentation policy, ECN and segmentation, are retained by an explicit transport profile.
//! Each receive briefly locks its transport; registry locks are used for membership changes.
//! Protocol authentication and path validation remain the endpoint's responsibility.

use crate::{
    DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSender, DatagramSocket,
    SendDatagram,
};
use ahash::HashMap;
use parking_lot::Mutex;
use rama_core::futures::task::AtomicWaker;
use rama_net::{
    address::{SocketAddress, ip::IntoCanonicalIpAddr as _},
    stream::Socket,
};
use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
use tokio::sync::{Notify, futures::OwnedNotified};

/// Bounds for a group of independently owned datagram paths.
#[derive(Debug, Clone, Copy)]
pub struct DatagramSocketGroupConfig {
    /// Maximum simultaneously attached peers. There is no intermediate payload queue.
    pub max_paths: NonZeroUsize,
    /// Required transport profile. Use the first socket's capabilities to retain native MTU,
    /// ECN and offload support, or a conservative profile when mixing transport providers.
    /// Later paths must support the advertised payload/metadata/fragmentation guarantees.
    pub capabilities: DatagramCapabilities,
}

/// A socket fed directly by independent associations to one local address.
///
/// Attachments preserve their transport's receive buffers: this adapter allocates no payload
/// storage and performs no payload copy. Dropping an attachment removes only its return path.
/// Consumers must honor the current `min_receive_buffer_size` capability to replay prefixes.
#[derive(Debug)]
pub struct DatagramSocketGroup {
    shared: Arc<Shared>,
    paths: Vec<(Arc<Path>, Waker)>,
    generation: usize,
    next: usize,
}

/// Attachment point for a [`DatagramSocketGroup`]. Clones share its path bound.
#[derive(Debug, Clone)]
pub struct DatagramGroup {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    local: SocketAddress,
    max_paths: usize,
    capabilities: DatagramCapabilities,
    retained_size: AtomicUsize,
    changed: Arc<Notify>,
    receiver: Arc<AtomicWaker>,
    generation: AtomicUsize,
    closed: AtomicBool,
    paths: Mutex<HashMap<SocketAddress, Arc<Path>>>,
}

type Receive = dyn Fn(
        &mut Context<'_>,
        &mut [IoSliceMut<'_>],
        &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>>
    + Send
    + Sync;

struct Path {
    peer: SocketAddress,
    sender: Box<dyn Fn() -> Box<dyn DatagramSender> + Send + Sync>,
    receive: Box<Receive>,
    close: Box<dyn Fn() + Send + Sync>,
    retained_size: Arc<AtomicUsize>,
    receive_local_ip: bool,
    ready: AtomicBool,
    closed: AtomicBool,
    stopped: Notify,
    error: Mutex<Option<DatagramError>>,
    receiver: Arc<AtomicWaker>,
}

impl fmt::Debug for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramGroupPath")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl Wake for Path {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.store(true, Ordering::Release);
        self.receiver.wake();
    }
}

impl Shared {
    fn remove(&self, path: &Arc<Path>) {
        path.closed.store(true, Ordering::Release);
        let mut paths = self.paths.lock();
        if paths.get(&path.peer).is_some_and(|p| Arc::ptr_eq(p, path)) {
            paths.remove(&path.peer);
            self.retained_size.store(
                paths
                    .values()
                    .map(|path| path.retained_size.load(Ordering::Acquire))
                    .max()
                    .unwrap_or(0),
                Ordering::Release,
            );
            self.generation.fetch_add(1, Ordering::Release);
        }
        drop(paths);

        // Destroy transports and wake consumers outside the membership lock.
        (path.close)();
        path.stopped.notify_waiters();
        self.receiver.wake();
        self.changed.notify_waiters();
    }
}

impl DatagramSocketGroup {
    pub fn new(local: SocketAddress, config: DatagramSocketGroupConfig) -> (Self, DatagramGroup) {
        let shared = Arc::new(Shared {
            local: local.into_canonical_ip_addr(),
            max_paths: config.max_paths.get(),
            capabilities: group_capabilities(config.capabilities),
            retained_size: AtomicUsize::new(config.capabilities.min_receive_buffer_size),
            changed: Arc::new(Notify::new()),
            receiver: Arc::new(AtomicWaker::new()),
            generation: AtomicUsize::new(1),
            closed: AtomicBool::new(false),
            paths: Mutex::new(HashMap::default()),
        });

        (
            Self {
                shared: shared.clone(),
                paths: Vec::new(),
                generation: 0,
                next: 0,
            },
            DatagramGroup { shared },
        )
    }
}

impl Drop for DatagramSocketGroup {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        let paths: Vec<_> = self.shared.paths.lock().values().cloned().collect();
        for path in paths {
            self.shared.remove(&path);
        }
    }
}

impl DatagramGroup {
    /// Register a concrete peer. No receive task or payload queue is created.
    /// Transport destruction can run on the endpoint driver when a path closes or is
    /// evicted. Implementations must keep Drop nonblocking to avoid stalling that endpoint.
    pub fn attach<S: DatagramSocket>(
        &self,
        socket: S,
    ) -> Result<DatagramGroupAttachment<S>, DatagramError> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(DatagramError::Closed);
        }

        // Reject incompatible transports before allocating a registration.
        let capabilities = socket.capabilities();
        if !supports_profile(capabilities, self.shared.capabilities) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram path cannot honor the group's transport capabilities",
            )
            .into());
        }

        let local = socket.local_addr()?.into_canonical_ip_addr();
        let peer = socket.peer_addr()?.into_canonical_ip_addr();
        if local != self.shared.local
            || local.ip_addr.is_unspecified()
            || local.port == 0
            || peer.ip_addr.is_unspecified()
            || peer.port == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram group requires its local address and an unambiguous peer",
            )
            .into());
        }

        let socket = Arc::new(Mutex::new(Some(socket)));
        let send = Arc::downgrade(&socket);
        // The receiver owns the slot directly: no weak upgrade/refcount pair per packet.
        // remove() takes the transport out before releasing a path, also breaking a waker
        // retained by that transport back to this Path.
        let receive = socket.clone();
        let close = Arc::downgrade(&socket);
        let retained_size = Arc::new(AtomicUsize::new(capabilities.min_receive_buffer_size));
        let received_size = retained_size.clone();
        let path = Arc::new(Path {
            peer,
            sender: Box::new(move || match send.upgrade() {
                Some(socket) => match socket.lock().as_ref() {
                    Some(socket) => Box::new(socket.create_sender()),
                    None => Box::new(ClosedSender),
                },
                None => Box::new(ClosedSender),
            }),
            receive: Box::new(move |cx, buffers, metadata| {
                let mut owned = receive.lock();
                let Some(socket) = owned.as_mut() else {
                    return Poll::Ready(Err(DatagramError::Closed));
                };

                let result = socket.poll_recv(cx, buffers, metadata);
                if received_size.load(Ordering::Relaxed) != 0 {
                    received_size.store(
                        socket.capabilities().min_receive_buffer_size,
                        Ordering::Release,
                    );
                }
                result
            }),
            close: Box::new(move || {
                if let Some(socket) = close.upgrade() {
                    let removed = socket.lock().take();
                    drop(removed);
                }
            }),
            retained_size,
            receive_local_ip: capabilities.receive_local_ip,
            ready: AtomicBool::new(true),
            closed: AtomicBool::new(false),
            stopped: Notify::new(),
            error: Mutex::new(None),
            receiver: self.shared.receiver.clone(),
        });

        let mut paths = self.shared.paths.lock();
        // Recheck closure while serialized with path registration.
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(DatagramError::Closed);
        }
        if paths.contains_key(&peer) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "datagram group peer already attached",
            )
            .into());
        }
        if paths.len() >= self.shared.max_paths {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "datagram group path limit reached",
            )
            .into());
        }

        // Publish the path and its buffer requirement before waking the receiver.
        self.shared.retained_size.fetch_max(
            path.retained_size.load(Ordering::Acquire),
            Ordering::Release,
        );
        paths.insert(peer, path.clone());
        self.shared.generation.fetch_add(1, Ordering::Release);
        drop(paths);

        self.shared.receiver.wake();
        self.shared.changed.notify_waiters();

        Ok(DatagramGroupAttachment {
            group: self.clone(),
            _socket: socket,
            path,
        })
    }

    /// Detach a peer without affecting other paths, waking its attachment and pending senders.
    /// A socket's owner can then drop its attachment; cached senders treat it as packet loss.
    pub fn detach(&self, peer: SocketAddress) -> bool {
        let path = self
            .shared
            .paths
            .lock()
            .get(&peer.into_canonical_ip_addr())
            .cloned();
        if let Some(path) = path {
            self.shared.remove(&path);
            true
        } else {
            false
        }
    }

    /// Whether a peer still has a registered path.
    pub fn contains_path(&self, peer: SocketAddress) -> bool {
        self.shared
            .paths
            .lock()
            .contains_key(&peer.into_canonical_ip_addr())
    }

    pub fn path_count(&self) -> usize {
        self.shared.paths.lock().len()
    }
}

/// Owns one registration. Cancellation removes it without closing other paths.
#[derive(Debug)]
pub struct DatagramGroupAttachment<S> {
    group: DatagramGroup,
    _socket: Arc<Mutex<Option<S>>>,
    path: Arc<Path>,
}

impl<S> DatagramGroupAttachment<S> {
    pub fn peer_addr(&self) -> SocketAddress {
        self.path.peer
    }

    /// Keep this path alive until its transport or group closes, or the caller cancels.
    /// Receive I/O is performed by the group's consumer, not by this future.
    pub async fn run(self) -> Result<(), DatagramError> {
        loop {
            let stopped = self.path.stopped.notified();
            tokio::pin!(stopped);
            stopped.as_mut().enable();

            if self.path.closed.load(Ordering::Acquire) {
                return self.path.error.lock().take().map_or(Ok(()), Err);
            }

            stopped.await;
        }
    }
}

impl<S> Drop for DatagramGroupAttachment<S> {
    fn drop(&mut self) {
        self.group.shared.remove(&self.path);
    }
}

impl Socket for DatagramSocketGroup {
    fn local_addr(&self) -> io::Result<SocketAddress> {
        Ok(self.shared.local)
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        Err(io::ErrorKind::NotConnected.into())
    }
}

impl DatagramSocket for DatagramSocketGroup {
    type Sender = DatagramGroupSender;

    fn create_sender(&self) -> Self::Sender {
        DatagramGroupSender {
            shared: self.shared.clone(),
            cached: None,
            changed: Box::pin(self.shared.changed.clone().notified_owned()),
        }
    }

    fn capabilities(&self) -> DatagramCapabilities {
        let mut capabilities = self.shared.capabilities;
        capabilities.min_receive_buffer_size = self.shared.retained_size.load(Ordering::Acquire);
        capabilities
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
        if buffers.is_empty() {
            return Poll::Ready(Err(DatagramError::EmptyReceiveBatch));
        }

        self.shared.receiver.register(cx.waker());
        let generation = self.shared.generation.load(Ordering::Acquire);
        if generation != self.generation {
            // Membership changes are rare. Cache paths so ordinary receives never lock the map.
            self.paths.clear();
            self.paths.extend(
                self.shared
                    .paths
                    .lock()
                    .values()
                    .map(|path| (path.clone(), Waker::from(path.clone()))),
            );
            self.generation = generation;
        }

        let count = self.paths.len();
        for _ in 0..count {
            let index = self.next % count;
            self.next = index + 1;
            let (path, waker) = &self.paths[index];
            if path.closed.load(Ordering::Acquire) || !path.ready.load(Ordering::Acquire) {
                continue;
            }

            // Avoid an atomic read-modify-write for silent paths. Clear readiness before
            // polling so a concurrent wake remains visible to the next receive attempt.
            if !path.ready.swap(false, Ordering::AcqRel) {
                continue;
            }

            let mut context = Context::from_waker(waker);
            let received = (path.receive)(&mut context, buffers, metadata);
            match received {
                Poll::Pending => {}
                Poll::Ready(Err(error @ DatagramError::PayloadTooLarge { .. })) => {
                    // An attachment can add a retained prefix after the consumer reads our
                    // capabilities. Keep the path and let it retry with the updated buffer size.
                    path.ready.store(true, Ordering::Release);
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Err(error)) => {
                    *path.error.lock() = Some(error);
                    self.shared.remove(path);
                }
                Poll::Ready(Ok(n)) => {
                    path.ready.store(true, Ordering::Release);
                    if n == 0 || n > metadata.len() {
                        self.shared.remove(path);
                        continue;
                    }

                    // Do not compact payloads: invalid slots become discarded datagrams.
                    for (meta, buffer) in metadata[..n].iter_mut().zip(buffers.iter()) {
                        meta.peer = meta.peer.into_canonical_ip_addr();
                        meta.local = if path.receive_local_ip {
                            meta.local.into_canonical_ip_addr()
                        } else {
                            self.shared.local
                        };
                        if meta.len > buffer.len()
                            || meta.original_len != meta.len
                            || meta.peer != path.peer
                            || meta.local != self.shared.local
                            || meta.segment_size.is_some_and(|segment| {
                                meta.original_len.div_ceil(segment.get())
                                    > self.shared.capabilities.max_receive_segments
                            })
                        {
                            meta.len = meta.len.min(buffer.len());
                            meta.truncated = true;
                        }
                    }

                    if self.shared.retained_size.load(Ordering::Acquire) != 0 {
                        // Retained prefixes are a setup cost only. Serialize with attach so
                        // consuming one prefix cannot hide a newly registered larger prefix.
                        let paths = self.shared.paths.lock();
                        let size = paths
                            .values()
                            .map(|path| path.retained_size.load(Ordering::Acquire))
                            .max()
                            .unwrap_or(0);
                        self.shared.retained_size.store(size, Ordering::Release);
                    }

                    return Poll::Ready(Ok(n));
                }
            }
        }
        Poll::Pending
    }
}

/// Each handle has its own underlying sender and therefore its own readiness registration.
#[derive(Debug)]
pub struct DatagramGroupSender {
    shared: Arc<Shared>,
    cached: Option<(Arc<Path>, Box<dyn DatagramSender>)>,
    changed: Pin<Box<OwnedNotified>>,
}

impl DatagramSender for DatagramGroupSender {
    fn capabilities(&self) -> DatagramCapabilities {
        let mut capabilities = self.shared.capabilities;
        if let Some((_, sender)) = &self.cached {
            capabilities.max_send_segments = capabilities
                .max_send_segments
                .min(sender.capabilities().max_send_segments);
        }
        capabilities
    }

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        if datagram
            .source_ip()
            .is_some_and(|ip| ip != self.shared.local.ip_addr)
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source address differs from datagram group",
            )
            .into()));
        }

        if let Err(error) = datagram
            .maybe_with_source_ip(None)
            .validate(self.capabilities())
        {
            return Poll::Ready(Err(error));
        }

        // Reuse the native sender while its path remains attached. The registry is
        // consulted only on a destination change or after the cached path closes.
        let destination = datagram.destination();
        if !self.cached.as_ref().is_some_and(|(path, _)| {
            path.peer == destination && !path.closed.load(Ordering::Acquire)
        }) {
            let path = self.shared.paths.lock().get(&destination).cloned();
            self.cached = path.map(|path| {
                let sender = (path.sender)();
                (path, sender)
            });
        }
        let Some((path, sender)) = &mut self.cached else {
            // A vanished path is packet loss, not failure of the other paths sharing the socket.
            return Poll::Ready(Ok(()));
        };

        let caps = sender.capabilities();
        let outgoing = datagram
            .maybe_with_source_ip(caps.send_source_ip.then_some(self.shared.local.ip_addr))
            .maybe_with_source_port(caps.send_source_port.then_some(self.shared.local.port));

        match sender.poll_send(cx, &outgoing) {
            Poll::Ready(Err(DatagramError::Closed)) => Poll::Ready(Ok(())),
            Poll::Pending => {
                // Membership notification is needed only while transport readiness is pending.
                // Register before checking closure so removal cannot strand this sender.
                while self.changed.as_mut().poll(cx).is_ready() {
                    self.changed = Box::pin(self.shared.changed.clone().notified_owned());
                }
                if path.closed.load(Ordering::Acquire) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
            result @ Poll::Ready(_) => result,
        }
    }
}

#[derive(Debug)]
struct ClosedSender;

impl DatagramSender for ClosedSender {
    fn capabilities(&self) -> DatagramCapabilities {
        DatagramCapabilities::portable()
    }

    fn poll_send(
        &mut self,
        _: &mut Context<'_>,
        _: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        Poll::Ready(Ok(()))
    }
}

fn group_capabilities(mut caps: DatagramCapabilities) -> DatagramCapabilities {
    // Source identity is fixed by registration. Batch send currently uses the trait fallback;
    // segmentation remains native and is forwarded atomically to the selected sender.
    caps.send_source_ip = true;
    caps.send_source_port = false;
    caps.receive_local_ip = true;
    caps.max_send_batch = 1;
    caps
}

fn supports_profile(actual: DatagramCapabilities, required: DatagramCapabilities) -> bool {
    // Registration-only checks: keep them short-circuiting, with no per-packet cost.
    // A path must accept the group's sends and fit its receive segmentation budget.
    (required.may_fragment || !actual.may_fragment)
        && actual.max_send_segments >= required.max_send_segments
        && actual.max_receive_segments <= required.max_receive_segments
        && actual.max_payload_ipv4 >= required.max_payload_ipv4
        && actual.max_payload_ipv6 >= required.max_payload_ipv6
        && actual.max_receive_payload.unwrap_or(usize::MAX)
            >= required.max_receive_payload.unwrap_or(usize::MAX)
        && (!required.send_ecn || actual.send_ecn)
        && (!required.receive_ecn || actual.receive_ecn)
        && (!required.receive_interface || actual.receive_interface)
        && (!required.receive_original_destination || actual.receive_original_destination)
        && (!required.receive_timestamp || actual.receive_timestamp)
        && (!required.receive_truncation || actual.receive_truncation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatagramSenderExt as _, DatagramSocketExt as _, test_utils::MemoryDatagramSocket};

    fn n(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    fn pair(port: u16) -> (MemoryDatagramSocket, MemoryDatagramSocket) {
        MemoryDatagramSocket::pair(([127, 0, 0, 1], 443), ([127, 0, 0, 1], port), n(2))
    }

    #[derive(Debug)]
    struct ProfileSocket {
        inner: MemoryDatagramSocket,
        profile: DatagramCapabilities,
        drops: Option<Arc<AtomicUsize>>,
    }

    impl Drop for ProfileSocket {
        fn drop(&mut self) {
            if let Some(count) = &self.drops {
                count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    impl Socket for ProfileSocket {
        fn local_addr(&self) -> io::Result<SocketAddress> {
            self.inner.local_addr()
        }

        fn peer_addr(&self) -> io::Result<SocketAddress> {
            self.inner.peer_addr()
        }
    }

    impl DatagramSocket for ProfileSocket {
        type Sender = <MemoryDatagramSocket as DatagramSocket>::Sender;

        fn create_sender(&self) -> Self::Sender {
            self.inner.create_sender()
        }

        fn capabilities(&self) -> DatagramCapabilities {
            self.profile
        }

        fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
            buffers: &mut [IoSliceMut<'_>],
            metadata: &mut [DatagramMetadata],
        ) -> Poll<Result<usize, DatagramError>> {
            let result = self.inner.poll_recv(cx, buffers, metadata);
            if !self.profile.receive_local_ip
                && let Poll::Ready(Ok(count)) = &result
            {
                for meta in &mut metadata[..*count] {
                    meta.local.ip_addr = std::net::Ipv4Addr::UNSPECIFIED.into();
                }
            }
            result
        }
    }

    #[tokio::test]
    async fn detaching_releases_transport_even_with_a_live_guard_and_cached_waker() {
        let (inner, _peer) = pair(1000);
        let profile = inner.capabilities();
        let drops = Arc::new(AtomicUsize::new(0));
        let (mut socket, group) = DatagramSocketGroup::new(
            inner.local_addr().unwrap(),
            DatagramSocketGroupConfig {
                max_paths: n(1),
                capabilities: profile,
            },
        );
        let attachment = group
            .attach(ProfileSocket {
                inner,
                profile,
                drops: Some(drops.clone()),
            })
            .unwrap();
        let mut bytes = [0; 32];
        let mut metadata = [DatagramMetadata::empty()];
        assert!(
            socket
                .poll_recv(
                    &mut Context::from_waker(Waker::noop()),
                    &mut [IoSliceMut::new(&mut bytes)],
                    &mut metadata
                )
                .is_pending()
        );
        assert!(group.detach(attachment.peer_addr()));
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        attachment.run().await.unwrap();
        drop(socket);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn attachment_rejects_incompatible_segment_limits() {
        for receive in [false, true] {
            let (inner, _client) = pair(1000);
            let profile = inner.capabilities();
            let (_socket, group) = DatagramSocketGroup::new(
                inner.local_addr().unwrap(),
                DatagramSocketGroupConfig {
                    max_paths: n(1),
                    capabilities: profile,
                },
            );
            let mut changed = profile;
            if receive {
                changed.max_receive_segments += 1;
            } else {
                changed.max_send_segments = 1;
                assert!(profile.max_send_segments > 1);
            }
            group
                .attach(ProfileSocket {
                    inner,
                    profile: changed,
                    drops: None,
                })
                .unwrap_err();
            assert_eq!(group.path_count(), 0);
        }
    }

    #[tokio::test]
    async fn bound_path_without_local_metadata_uses_registered_address() {
        let (inner, client) = pair(1000);
        let local = inner.local_addr().unwrap();
        let mut profile = inner.capabilities();
        profile.receive_local_ip = false;
        let (mut socket, group) = DatagramSocketGroup::new(
            local,
            DatagramSocketGroupConfig {
                max_paths: n(1),
                capabilities: profile,
            },
        );
        let _attachment = group
            .attach(ProfileSocket {
                inner,
                profile,
                drops: None,
            })
            .unwrap();
        client
            .create_sender()
            .send(SendDatagram::new(local, b"bound"))
            .await
            .unwrap();
        let mut buffer = [0; 32];
        let meta = socket.recv(&mut buffer).await.unwrap();
        assert_eq!(meta.local, local);
        assert!(!meta.truncated);
        assert_eq!(&buffer[..meta.len], b"bound");
    }

    #[tokio::test]
    async fn later_retained_prefix_updates_buffer_requirement_without_losing_path() {
        let (mut socket, group) = DatagramSocketGroup::new(
            ([127, 0, 0, 1], 443).into(),
            DatagramSocketGroupConfig {
                max_paths: n(2),
                capabilities: pair(9999).0.capabilities(),
            },
        );
        let (path, _client) = pair(1000);
        let payload = rama_core::bytes::Bytes::from(vec![7; 4096]);
        let mut meta = DatagramMetadata::empty();
        meta.peer = ([127, 0, 0, 1], 1000).into();
        meta.local = ([127, 0, 0, 1], 443).into();
        meta.len = payload.len();
        meta.original_len = payload.len();
        let attachment = group
            .attach(crate::PrefixedDatagramSocket::new(
                path,
                [crate::RetainedDatagram {
                    payload,
                    metadata: meta,
                }],
            ))
            .unwrap();
        assert_eq!(socket.capabilities().min_receive_buffer_size, 4096);
        let mut small = [0; 1200];
        let mut metadata = [DatagramMetadata::empty()];
        assert!(
            socket
                .poll_recv(
                    &mut Context::from_waker(Waker::noop()),
                    &mut [IoSliceMut::new(&mut small)],
                    &mut metadata,
                )
                .is_ready()
        );
        assert_eq!(group.path_count(), 1);
        let mut large = [0; 4096];
        let meta = socket.recv(&mut large).await.unwrap();
        assert_eq!(meta.len, 4096);
        assert!(large.iter().all(|byte| *byte == 7));
        assert_eq!(socket.capabilities().min_receive_buffer_size, 0);
        drop(attachment);
    }

    #[tokio::test]
    async fn multiple_paths_keep_boundaries_and_reply_to_the_right_peer() {
        let local = ([127, 0, 0, 1], 443).into();
        let (mut socket, group) = DatagramSocketGroup::new(
            local,
            DatagramSocketGroupConfig {
                max_paths: n(2),
                capabilities: pair(9999).0.capabilities(),
            },
        );
        let (a, mut client_a) = pair(1000);
        let (b, mut client_b) = pair(1001);
        let a = group.attach(a).unwrap();
        let b = group.attach(b).unwrap();
        let pump_a = tokio::spawn(a.run());
        let pump_b = tokio::spawn(b.run());
        client_a
            .create_sender()
            .send(SendDatagram::new(local, b"first"))
            .await
            .unwrap();
        let mut buf = [0; 1500];
        let meta = socket.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..meta.len], b"first");
        assert_eq!(meta.peer.port, 1000);
        let mut reply = socket.create_sender();
        reply
            .send(SendDatagram::new(meta.peer, b"reply-a"))
            .await
            .unwrap();
        let meta = client_a.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..meta.len], b"reply-a");
        pump_a.abort();
        assert!(pump_a.await.unwrap_err().is_cancelled());
        assert_eq!(group.path_count(), 1);
        client_b
            .create_sender()
            .send(SendDatagram::new(local, b"second"))
            .await
            .unwrap();
        let meta = socket.recv(&mut buf).await.unwrap();
        assert_eq!(meta.peer.port, 1001);
        reply
            .send(SendDatagram::new(meta.peer, b"reply-b"))
            .await
            .unwrap();
        let meta = client_b.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..meta.len], b"reply-b");
        drop(socket);
        pump_b.await.unwrap().unwrap();
        assert_eq!(group.path_count(), 0);
    }

    #[tokio::test]
    async fn duplicate_and_excess_paths_cannot_replace_existing_routes() {
        let (socket, group) = DatagramSocketGroup::new(
            ([127, 0, 0, 1], 443).into(),
            DatagramSocketGroupConfig {
                max_paths: n(1),
                capabilities: pair(9999).0.capabilities(),
            },
        );
        let (a, _client) = pair(1000);
        let a = group.attach(a).unwrap();
        group.attach(pair(1000).0).unwrap_err();
        group.attach(pair(1001).0).unwrap_err();
        assert_eq!(group.path_count(), 1);
        drop(a);
        group.attach(pair(1001).0).unwrap();
        drop(socket);
        group.attach(pair(1002).0).unwrap_err();
    }

    #[tokio::test]
    async fn closing_a_path_wakes_a_blocked_sender_without_closing_other_paths() {
        let local = ([127, 0, 0, 1], 443).into();
        let (socket, group) = DatagramSocketGroup::new(
            local,
            DatagramSocketGroupConfig {
                max_paths: n(1),
                capabilities: pair(9999).0.capabilities(),
            },
        );
        let (a, _client) = pair(1000);
        let attachment = group.attach(a).unwrap();
        let peer = attachment.peer_addr();
        let mut sender = socket.create_sender();
        for _ in 0..2 {
            sender.send(SendDatagram::new(peer, b"fill")).await.unwrap();
        }
        let task =
            tokio::spawn(async move { sender.send(SendDatagram::new(peer, b"blocked")).await });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        drop(attachment);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn receives_into_callers_buffer_and_only_repolls_ready_paths() {
        #[derive(Debug)]
        struct Counted {
            inner: MemoryDatagramSocket,
            polls: Arc<AtomicUsize>,
            address: Arc<AtomicUsize>,
        }

        impl Socket for Counted {
            fn local_addr(&self) -> io::Result<SocketAddress> {
                self.inner.local_addr()
            }

            fn peer_addr(&self) -> io::Result<SocketAddress> {
                self.inner.peer_addr()
            }
        }

        impl DatagramSocket for Counted {
            type Sender = <MemoryDatagramSocket as DatagramSocket>::Sender;
            fn create_sender(&self) -> Self::Sender {
                self.inner.create_sender()
            }

            fn capabilities(&self) -> DatagramCapabilities {
                self.inner.capabilities()
            }

            fn poll_recv(
                &mut self,
                cx: &mut Context<'_>,
                buffers: &mut [IoSliceMut<'_>],
                metadata: &mut [DatagramMetadata],
            ) -> Poll<Result<usize, DatagramError>> {
                self.polls.fetch_add(1, Ordering::Relaxed);
                self.address
                    .store(buffers[0].as_ptr() as usize, Ordering::Relaxed);
                self.inner.poll_recv(cx, buffers, metadata)
            }
        }

        let local = ([127, 0, 0, 1], 443).into();
        let (mut socket, group) = DatagramSocketGroup::new(
            local,
            DatagramSocketGroupConfig {
                max_paths: n(2),
                capabilities: pair(9999).0.capabilities(),
            },
        );
        let (inner, client) = pair(1000);
        let polls = Arc::new(AtomicUsize::new(0));
        let address = Arc::new(AtomicUsize::new(0));
        let attachment = group
            .attach(Counted {
                inner,
                polls: polls.clone(),
                address: address.clone(),
            })
            .unwrap();
        let (quiet, _quiet_client) = pair(1001);
        let _quiet_path = group.attach(quiet).unwrap();
        let mut buffer = [0; 1500];
        let pointer = buffer.as_ptr() as usize;
        let mut slots = [IoSliceMut::new(&mut buffer)];
        let mut metadata = [DatagramMetadata::empty()];
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            socket
                .poll_recv(&mut cx, &mut slots, &mut metadata)
                .is_pending()
        );
        assert_eq!(address.load(Ordering::Relaxed), pointer);
        assert!(
            socket
                .poll_recv(&mut cx, &mut slots, &mut metadata)
                .is_pending()
        );
        assert_eq!(
            polls.load(Ordering::Relaxed),
            1,
            "silent transport is not polled again"
        );
        client
            .create_sender()
            .send(SendDatagram::new(local, b"direct"))
            .await
            .unwrap();
        assert!(matches!(
            socket.poll_recv(&mut cx, &mut slots, &mut metadata),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(polls.load(Ordering::Relaxed), 2);
        assert_eq!(address.load(Ordering::Relaxed), pointer);
        assert_eq!(&buffer[..6], b"direct");
        drop(attachment);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attaching_and_removing_paths_wakes_a_pending_reader() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let local = ([127, 0, 0, 1], 443).into();
            let (mut socket, group) = DatagramSocketGroup::new(
                local,
                DatagramSocketGroupConfig {
                    max_paths: n(1),
                    capabilities: pair(9999).0.capabilities(),
                },
            );
            let (acknowledge, mut received) = tokio::sync::mpsc::channel(1);
            let reader = tokio::spawn(async move {
                let mut buffer = [0; 32];
                for value in 0..256u16 {
                    let metadata = socket.recv(&mut buffer).await.unwrap();
                    assert_eq!(&buffer[..metadata.len], value.to_be_bytes());
                    acknowledge.send(()).await.unwrap();
                }
            });
            for value in 0..256u16 {
                let (path, client) = pair(1000 + value);
                let attachment = group.attach(path).unwrap();
                tokio::task::yield_now().await;
                client
                    .create_sender()
                    .send(SendDatagram::new(local, &value.to_be_bytes()))
                    .await
                    .unwrap();
                received.recv().await.unwrap();
                drop(attachment);
            }
            reader.await.unwrap();
            assert_eq!(group.path_count(), 0);
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn single_and_multiple_path_transitions_preserve_wakeups() {
        struct Flag(AtomicBool);

        impl Wake for Flag {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Release);
            }
        }

        let local = ([127, 0, 0, 1], 443).into();
        let (mut socket, group) = DatagramSocketGroup::new(
            local,
            DatagramSocketGroupConfig {
                max_paths: n(2),
                capabilities: pair(9999).0.capabilities(),
            },
        );
        let (first, client) = pair(1000);
        let _first = group.attach(first).unwrap();
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());
        let mut cx = Context::from_waker(&waker);
        let mut buffer = [0; 32];
        let mut slots = [IoSliceMut::new(&mut buffer)];
        let mut metadata = [DatagramMetadata::empty()];
        assert!(
            socket
                .poll_recv(&mut cx, &mut slots, &mut metadata)
                .is_pending()
        );

        let (second, _quiet_client) = pair(1001);
        let second = group.attach(second).unwrap();
        assert!(
            socket
                .poll_recv(&mut cx, &mut slots, &mut metadata)
                .is_pending()
        );
        flag.0.store(false, Ordering::Release);
        client
            .create_sender()
            .send(SendDatagram::new(local, b"multiple"))
            .await
            .unwrap();
        assert!(flag.0.load(Ordering::Acquire));
        assert!(matches!(
            socket.poll_recv(&mut cx, &mut slots, &mut metadata),
            Poll::Ready(Ok(1))
        ));

        drop(second);
        assert!(
            socket
                .poll_recv(&mut cx, &mut slots, &mut metadata)
                .is_pending()
        );
        flag.0.store(false, Ordering::Release);
        client
            .create_sender()
            .send(SendDatagram::new(local, b"single"))
            .await
            .unwrap();
        assert!(flag.0.load(Ordering::Acquire));
        assert!(matches!(
            socket.poll_recv(&mut cx, &mut slots, &mut metadata),
            Poll::Ready(Ok(1))
        ));
    }
    #[tokio::test(start_paused = true)]
    async fn native_profile_preserves_fragmentation_ecn_and_atomic_segmentation() {
        let local = ([127, 0, 0, 1], 443).into();
        let (path, mut client) = pair(1000);
        let profile = path.capabilities();
        let (mut socket, group) = DatagramSocketGroup::new(
            local,
            DatagramSocketGroupConfig {
                max_paths: n(1),
                capabilities: profile,
            },
        );
        assert!(!socket.capabilities().may_fragment);
        assert!(socket.capabilities().send_ecn);
        assert_eq!(
            socket.capabilities().max_receive_batch,
            profile.max_receive_batch
        );
        assert_eq!(
            socket.capabilities().max_receive_segments,
            profile.max_receive_segments
        );
        let attachment = group.attach(path).unwrap();
        let peer = attachment.peer_addr();
        let mut sender = socket.create_sender();
        let segmented = SendDatagram::new(peer, b"abcdef")
            .with_segment_size(n(3))
            .with_ecn(crate::EcnCodepoint::Ce);
        sender.send(segmented).await.unwrap();
        let mut buffer = [0; 64];
        for expected in [b"abc", b"def"] {
            let metadata = client.recv(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..metadata.len], expected);
            assert_eq!(metadata.ecn, Some(crate::EcnCodepoint::Ce));
        }

        let mut client_sender = client.create_sender();
        client_sender
            .send(SendDatagram::new(local, b"one"))
            .await
            .unwrap();
        client_sender
            .send(SendDatagram::new(local, b"two"))
            .await
            .unwrap();
        let mut first = [0; 16];
        let mut second = [0; 16];
        let mut buffers = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        let mut metadata = [DatagramMetadata::empty(); 2];
        assert_eq!(
            socket
                .recv_batch(&mut buffers, &mut metadata)
                .await
                .unwrap(),
            2
        );
        assert_eq!(&first[..3], b"one");
        assert_eq!(&second[..3], b"two");

        client.set_max_send_segments(n(1));
        assert_eq!(sender.capabilities().max_send_segments, 1);
        sender.send(segmented).await.unwrap_err();
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            client.recv(&mut buffer),
        )
        .await
        .unwrap_err();
    }

    #[tokio::test]
    async fn attachment_rejects_a_weaker_transport_profile() {
        #[derive(Debug)]
        struct Weaker(MemoryDatagramSocket);

        impl Socket for Weaker {
            fn local_addr(&self) -> io::Result<SocketAddress> {
                self.0.local_addr()
            }

            fn peer_addr(&self) -> io::Result<SocketAddress> {
                self.0.peer_addr()
            }
        }

        impl DatagramSocket for Weaker {
            type Sender = <MemoryDatagramSocket as DatagramSocket>::Sender;

            fn create_sender(&self) -> Self::Sender {
                self.0.create_sender()
            }

            fn capabilities(&self) -> DatagramCapabilities {
                let mut caps = self.0.capabilities();
                caps.may_fragment = true;
                caps
            }

            fn poll_recv(
                &mut self,
                cx: &mut Context<'_>,
                buffers: &mut [IoSliceMut<'_>],
                metadata: &mut [DatagramMetadata],
            ) -> Poll<Result<usize, DatagramError>> {
                self.0.poll_recv(cx, buffers, metadata)
            }
        }

        let (path, _client) = pair(1000);
        // Keep the group receiver alive; rejecting this path must be a capability decision.
        let (socket, group) = DatagramSocketGroup::new(
            ([127, 0, 0, 1], 443).into(),
            DatagramSocketGroupConfig {
                max_paths: n(1),
                capabilities: path.capabilities(),
            },
        );
        let error = group.attach(Weaker(path)).unwrap_err();
        assert!(error.to_string().contains("transport capabilities"));
        assert_eq!(group.path_count(), 0);
        drop(socket);
    }
}
