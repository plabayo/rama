//! Deterministic in-memory datagram transport for protocol tests.

use std::{
    collections::VecDeque,
    io::{self, IoSliceMut},
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        Arc, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use parking_lot::{Mutex, MutexGuard};
use rama_net::{
    address::{SocketAddress, ip::IntoCanonicalIpAddr as _},
    stream::Socket,
};

use crate::{
    DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSender, DatagramSocket,
    EcnCodepoint, ReceiveTimestamp, SendDatagram,
};

/// One endpoint of an in-memory datagram pair used by protocol tests.
///
/// Sending from either endpoint queues a datagram for the other. The fixed
/// queue capacity models backpressure without using an operating-system socket.
pub struct MemoryDatagramSocket {
    shared: Arc<Shared>,
    side: usize,
}

impl MemoryDatagramSocket {
    /// Construct two connected endpoints with `capacity` datagrams per side.
    #[must_use]
    pub fn pair(
        first: impl Into<SocketAddress>,
        second: impl Into<SocketAddress>,
        capacity: NonZeroUsize,
    ) -> (Self, Self) {
        let first = first.into().into_canonical_ip_addr();
        let second = second.into().into_canonical_ip_addr();
        let shared = Arc::new(Shared {
            state: Mutex::new(PairState {
                endpoints: [EndpointState::new(), EndpointState::new()],
                sequence: NonZeroU64::MIN,
            }),
            addresses: [first, second],
            capacity: capacity.get(),
            max_send_segments: AtomicUsize::new(64),
        });
        (
            Self {
                shared: shared.clone(),
                side: 0,
            },
            Self { shared, side: 1 },
        )
    }

    /// Insert a datagram directly into this endpoint's receive queue.
    ///
    /// This is useful for deterministic tests of metadata that cannot be
    /// produced by the ordinary paired send path, such as original destination.
    pub fn inject_received(
        &self,
        payload: Vec<u8>,
        mut metadata: DatagramMetadata,
    ) -> Result<(), DatagramError> {
        if let Some(segment_size) = metadata.segment_size
            && (payload.is_empty()
                || segment_size.get() >= metadata.original_len.max(payload.len()))
        {
            return Err(DatagramError::InvalidSegmentSize {
                payload_len: metadata.original_len.max(payload.len()),
                segment_size: segment_size.get(),
            });
        }
        if let Some(segment_size) = metadata.segment_size {
            let count = metadata
                .original_len
                .max(payload.len())
                .div_ceil(segment_size.get());
            if count > 64 {
                return Err(DatagramError::TooManySegments { count, max: 64 });
            }
        }
        let mut state = self.lock();
        let endpoint = &mut state.endpoints[self.side];
        if endpoint.queue.len() >= self.shared.capacity {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "in-memory datagram receive queue is full",
            )
            .into());
        }
        metadata.len = payload.len();
        metadata.original_len = metadata.original_len.max(payload.len());
        endpoint
            .queue
            .push_back(OwnedDatagram { payload, metadata });
        let waker = endpoint.recv_waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }

    /// Change the segmented-send limit exposed by both endpoints.
    ///
    /// This deterministic hook lets protocol tests model a backend that lowers
    /// its offload limit after a runtime rejection. Already-created sender
    /// handles observe the new value through their next capability query.
    pub fn set_max_send_segments(&self, value: NonZeroUsize) {
        self.shared
            .max_send_segments
            .store(value.get().min(64), Ordering::Relaxed);
    }

    fn lock(&self) -> MutexGuard<'_, PairState> {
        self.shared.state.lock()
    }
}

impl std::fmt::Debug for MemoryDatagramSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryDatagramSocket")
            .field("local_addr", &self.shared.addresses[self.side])
            .field("peer_addr", &self.shared.addresses[other(self.side)])
            .field("capacity", &self.shared.capacity)
            .finish()
    }
}

impl Drop for MemoryDatagramSocket {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock();
        state.endpoints[self.side].receiver_alive = false;
        let peer = other(self.side);
        let recv_waker = if state.endpoints[self.side].senders == 0 {
            state.endpoints[peer].recv_waker.take()
        } else {
            None
        };
        let send_wakers = take_waiters(&mut state.endpoints[peer].send_waiters);
        drop(state);
        if let Some(waker) = recv_waker {
            waker.wake();
        }
        wake_all(send_wakers);
    }
}

impl Socket for MemoryDatagramSocket {
    fn local_addr(&self) -> io::Result<SocketAddress> {
        Ok(self.shared.addresses[self.side])
    }

    fn peer_addr(&self) -> io::Result<SocketAddress> {
        Ok(self.shared.addresses[other(self.side)])
    }
}

impl DatagramSocket for MemoryDatagramSocket {
    type Sender = MemoryDatagramSender;

    fn create_sender(&self) -> Self::Sender {
        self.shared.state.lock().endpoints[self.side].senders += 1;
        MemoryDatagramSender {
            shared: self.shared.clone(),
            side: self.side,
            waiter: Arc::new(SendWaiter::default()),
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
        if buffers.is_empty() {
            return Poll::Ready(Err(DatagramError::EmptyReceiveBatch));
        }

        let mut state = self.lock();
        let peer = other(self.side);
        let mut received = 0;
        while received < buffers.len() {
            let Some(packet) = state.endpoints[self.side].queue.pop_front() else {
                break;
            };
            let copied = packet.payload.len().min(buffers[received].len());
            buffers[received][..copied].copy_from_slice(&packet.payload[..copied]);
            metadata[received] = DatagramMetadata {
                len: copied,
                truncated: copied < packet.payload.len() || packet.metadata.truncated,
                ..packet.metadata
            };
            received += 1;
        }

        if received > 0 {
            let wakers = take_waiters(&mut state.endpoints[peer].send_waiters);
            drop(state);
            wake_all(wakers);
            return Poll::Ready(Ok(received));
        }
        if !state.endpoints[peer].receiver_alive && state.endpoints[peer].senders == 0 {
            return Poll::Ready(Err(DatagramError::Closed));
        }
        register(&mut state.endpoints[self.side].recv_waker, cx.waker());
        Poll::Pending
    }

    fn capabilities(&self) -> DatagramCapabilities {
        memory_capabilities(&self.shared)
    }
}

/// Send handle for a [`MemoryDatagramSocket`].
pub struct MemoryDatagramSender {
    shared: Arc<Shared>,
    side: usize,
    waiter: Arc<SendWaiter>,
}

impl MemoryDatagramSender {
    fn lock(&self) -> MutexGuard<'_, PairState> {
        self.shared.state.lock()
    }
}

impl std::fmt::Debug for MemoryDatagramSender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryDatagramSender")
            .field("local_addr", &self.shared.addresses[self.side])
            .finish()
    }
}

impl Drop for MemoryDatagramSender {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock();
        state.endpoints[self.side].senders = state.endpoints[self.side].senders.saturating_sub(1);
        state.endpoints[self.side]
            .send_waiters
            .retain(|waiter| waiter.as_ptr() != Arc::as_ptr(&self.waiter));
        let recv_waker = if state.endpoints[self.side].senders == 0
            && !state.endpoints[self.side].receiver_alive
        {
            let peer = other(self.side);
            state.endpoints[peer].recv_waker.take()
        } else {
            None
        };
        drop(state);
        if let Some(waker) = recv_waker {
            waker.wake();
        }
    }
}

impl DatagramSender for MemoryDatagramSender {
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        if let Err(error) = datagram.validate(memory_capabilities(&self.shared)) {
            return Poll::Ready(Err(error));
        }

        let peer = other(self.side);
        if datagram.destination() != self.shared.addresses[peer] {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "destination is not this in-memory socket's peer",
            )
            .into()));
        }
        let segment_size = datagram
            .segment_size()
            .map_or(datagram.payload().len(), NonZeroUsize::get);
        let segment_count = datagram.segment_count();
        let mut state = self.lock();
        if !state.endpoints[peer].receiver_alive {
            return Poll::Ready(Err(DatagramError::Closed));
        }
        if state.endpoints[peer].queue.len() + segment_count > self.shared.capacity {
            register_waiter(
                &mut state.endpoints[self.side].send_waiters,
                &self.waiter,
                cx.waker(),
            );
            return Poll::Pending;
        }

        let source = SocketAddress::new(
            datagram
                .source_ip()
                .unwrap_or(self.shared.addresses[self.side].ip_addr),
            self.shared.addresses[self.side].port,
        );
        let chunks: Box<dyn Iterator<Item = &[u8]> + '_> = if datagram.segment_size().is_some() {
            Box::new(datagram.payload().chunks(segment_size))
        } else {
            Box::new(std::iter::once(datagram.payload()))
        };
        for payload in chunks {
            let timestamp = state.sequence.get();
            state.sequence = state.sequence.checked_add(1).unwrap_or(NonZeroU64::MAX);
            state.endpoints[peer].queue.push_back(OwnedDatagram {
                payload: payload.to_vec(),
                metadata: DatagramMetadata {
                    len: payload.len(),
                    original_len: payload.len(),
                    segment_size: None,
                    peer: source,
                    local: datagram.destination(),
                    original_destination: None,
                    interface_index: Some((peer + 1) as u32),
                    ecn: Some(datagram.ecn().unwrap_or(EcnCodepoint::NotEct)),
                    timestamp: Some(ReceiveTimestamp::Monotonic(Duration::from_nanos(timestamp))),
                    truncated: false,
                },
            });
        }
        let waker = state.endpoints[peer].recv_waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }

    fn capabilities(&self) -> DatagramCapabilities {
        memory_capabilities(&self.shared)
    }
}

struct Shared {
    state: Mutex<PairState>,
    addresses: [SocketAddress; 2],
    capacity: usize,
    max_send_segments: AtomicUsize,
}

struct PairState {
    endpoints: [EndpointState; 2],
    sequence: NonZeroU64,
}

struct EndpointState {
    receiver_alive: bool,
    senders: usize,
    queue: VecDeque<OwnedDatagram>,
    recv_waker: Option<Waker>,
    send_waiters: Vec<Weak<SendWaiter>>,
}

#[derive(Default)]
struct SendWaiter {
    waker: Mutex<Option<Waker>>,
}

impl EndpointState {
    fn new() -> Self {
        Self {
            receiver_alive: true,
            senders: 0,
            queue: VecDeque::new(),
            recv_waker: None,
            send_waiters: Vec::new(),
        }
    }
}

struct OwnedDatagram {
    payload: Vec<u8>,
    metadata: DatagramMetadata,
}

const fn other(side: usize) -> usize {
    side ^ 1
}

fn register(slot: &mut Option<Waker>, waker: &Waker) {
    if slot
        .as_ref()
        .is_none_or(|current| !current.will_wake(waker))
    {
        *slot = Some(waker.clone());
    }
}

fn register_waiter(waiters: &mut Vec<Weak<SendWaiter>>, waiter: &Arc<SendWaiter>, waker: &Waker) {
    register(&mut waiter.waker.lock(), waker);
    waiters.retain(|registered| registered.strong_count() != 0);
    if !waiters
        .iter()
        .any(|registered| registered.as_ptr() == Arc::as_ptr(waiter))
    {
        waiters.push(Arc::downgrade(waiter));
    }
}

fn take_waiters(waiters: &mut Vec<Weak<SendWaiter>>) -> Vec<Waker> {
    waiters
        .drain(..)
        .filter_map(|waiter| waiter.upgrade())
        .filter_map(|waiter| waiter.waker.lock().take())
        .collect()
}

fn wake_all(waiters: Vec<Waker>) {
    for waker in waiters {
        waker.wake();
    }
}

fn memory_capabilities(shared: &Shared) -> DatagramCapabilities {
    let batch_limit = shared.capacity.min(64);
    let segment_limit = shared
        .max_send_segments
        .load(Ordering::Relaxed)
        .min(batch_limit);
    DatagramCapabilities {
        max_payload_ipv4: crate::MAX_UDP_PAYLOAD_IPV4,
        max_payload_ipv6: crate::MAX_UDP_PAYLOAD_IPV6,
        max_receive_batch: batch_limit,
        max_send_batch: batch_limit,
        max_send_segments: segment_limit,
        max_receive_segments: 64,
        may_fragment: false,
        send_ecn: true,
        receive_ecn: true,
        send_source_ip: true,
        receive_local_ip: true,
        receive_interface: true,
        receive_original_destination: true,
        receive_timestamp: true,
        receive_truncation: true,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::pin,
        sync::atomic::AtomicUsize,
        task::{Poll, Wake, Waker},
    };

    use super::*;
    use crate::{DatagramSenderExt as _, DatagramSocketExt as _};

    fn memory_pair(capacity: NonZeroUsize) -> (MemoryDatagramSocket, MemoryDatagramSocket) {
        MemoryDatagramSocket::pair(
            SocketAddress::local_ipv4(40_000),
            SocketAddress::local_ipv4(40_001),
            capacity,
        )
    }

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn preserves_boundaries_metadata_and_zero_length() {
        let (mut receiver, sender_socket) = memory_pair(NonZeroUsize::MIN);
        let destination = receiver.local_addr().unwrap();
        let mut sender = sender_socket.create_sender();

        sender
            .send(SendDatagram::new(destination, b"").with_ecn(EcnCodepoint::Ce))
            .await
            .unwrap();
        let mut buffer = [0; 8];
        let metadata = receiver.recv(&mut buffer).await.unwrap();

        assert_eq!(metadata.len, 0);
        assert_eq!(metadata.original_len, 0);
        assert_eq!(metadata.interface_index, Some(1));
        assert_eq!(metadata.ecn, Some(EcnCodepoint::Ce));
        assert!(!metadata.truncated);
    }

    #[test]
    fn pair_uses_the_supplied_endpoint_addresses() {
        let first = SocketAddress::local_ipv4(41_000);
        let second = SocketAddress::local_ipv6(41_001);
        let (first_socket, second_socket) =
            MemoryDatagramSocket::pair(first, second, NonZeroUsize::MIN);

        assert_eq!(first_socket.local_addr().unwrap(), first);
        assert_eq!(first_socket.peer_addr().unwrap(), second);
        assert_eq!(second_socket.local_addr().unwrap(), second);
        assert_eq!(second_socket.peer_addr().unwrap(), first);
    }

    #[tokio::test]
    async fn reports_truncation_without_consuming_the_next_datagram() {
        let (mut receiver, sender_socket) = memory_pair(NonZeroUsize::new(2).unwrap());
        let destination = receiver.local_addr().unwrap();
        let mut sender = sender_socket.create_sender();
        sender
            .send(SendDatagram::new(destination, b"large"))
            .await
            .unwrap();
        sender
            .send(SendDatagram::new(destination, b"ok"))
            .await
            .unwrap();

        let mut small = [0; 2];
        let first = receiver.recv(&mut small).await.unwrap();
        assert_eq!(first.len, 2);
        assert!(first.truncated);
        assert_eq!(first.original_len, 5);

        let mut next = [0; 2];
        let second = receiver.recv(&mut next).await.unwrap();
        assert_eq!(&next, b"ok");
        assert!(!second.truncated);
    }

    #[tokio::test]
    async fn shutdown_closes_both_directions() {
        let (mut socket, peer) = memory_pair(NonZeroUsize::MIN);
        let destination = peer.local_addr().unwrap();
        let mut sender = socket.create_sender();
        drop(peer);

        assert!(matches!(
            sender
                .send(SendDatagram::new(destination, b"after close"))
                .await,
            Err(DatagramError::Closed)
        ));

        let mut buffer = [0; 1];
        assert!(matches!(
            socket.recv(&mut buffer).await,
            Err(DatagramError::Closed)
        ));
    }

    #[test]
    fn receive_closes_after_the_last_sender_is_dropped() {
        let (mut receiver, sender_socket) = memory_pair(NonZeroUsize::MIN);
        let sender = sender_socket.create_sender();

        let wake_counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(wake_counter.clone());
        let mut context = Context::from_waker(&waker);
        let mut buffer = [0];
        let mut buffers = [IoSliceMut::new(&mut buffer)];
        let mut metadata = [DatagramMetadata::empty()];
        assert!(matches!(
            receiver.poll_recv(&mut context, &mut buffers, &mut metadata),
            Poll::Pending
        ));

        drop(sender_socket);
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 0);
        assert!(matches!(
            receiver.poll_recv(&mut context, &mut buffers, &mut metadata),
            Poll::Pending
        ));

        drop(sender);
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);
        assert!(matches!(
            receiver.poll_recv(&mut context, &mut buffers, &mut metadata),
            Poll::Ready(Err(DatagramError::Closed))
        ));
    }

    #[test]
    fn capability_changes_reach_existing_senders() {
        let (socket, peer) = memory_pair(NonZeroUsize::new(64).unwrap());
        let sender = peer.create_sender();
        assert_eq!(socket.capabilities(), sender.capabilities());
        assert!(socket.capabilities().receive_interface);
        assert_eq!(sender.capabilities().max_send_segments, 64);

        socket.set_max_send_segments(NonZeroUsize::MIN);
        assert_eq!(sender.capabilities().max_send_segments, 1);
    }

    #[test]
    fn full_queue_tracks_each_live_sender_once() {
        let (mut receiver, sender_socket) = memory_pair(NonZeroUsize::MIN);
        let destination = receiver.local_addr().unwrap();
        let mut first = sender_socket.create_sender();
        let mut second = sender_socket.create_sender();
        let mut cancelled = sender_socket.create_sender();
        let mut filler = sender_socket.create_sender();
        let old_first = Arc::new(WakeCounter::default());
        let new_first = Arc::new(WakeCounter::default());
        let live_second = Arc::new(WakeCounter::default());
        let dropped = Arc::new(WakeCounter::default());

        let mut filler_context = Context::from_waker(Waker::noop());
        assert!(matches!(
            filler.poll_send(
                &mut filler_context,
                &SendDatagram::new(destination, b"full")
            ),
            Poll::Ready(Ok(()))
        ));

        let old_first_waker = Waker::from(old_first.clone());
        let new_first_waker = Waker::from(new_first.clone());
        let live_second_waker = Waker::from(live_second.clone());
        let dropped_waker = Waker::from(dropped.clone());
        assert!(matches!(
            first.poll_send(
                &mut Context::from_waker(&old_first_waker),
                &SendDatagram::new(destination, b"a")
            ),
            Poll::Pending
        ));
        assert!(matches!(
            first.poll_send(
                &mut Context::from_waker(&new_first_waker),
                &SendDatagram::new(destination, b"a")
            ),
            Poll::Pending
        ));
        assert!(matches!(
            second.poll_send(
                &mut Context::from_waker(&live_second_waker),
                &SendDatagram::new(destination, b"b")
            ),
            Poll::Pending
        ));
        assert!(matches!(
            cancelled.poll_send(
                &mut Context::from_waker(&dropped_waker),
                &SendDatagram::new(destination, b"cancelled")
            ),
            Poll::Pending
        ));
        drop(cancelled);

        let mut receive_buffer = [0; 8];
        let mut receive = pin!(receiver.recv(&mut receive_buffer));
        assert!(matches!(
            receive
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(old_first.0.load(Ordering::Relaxed), 0);
        assert_eq!(new_first.0.load(Ordering::Relaxed), 1);
        assert_eq!(live_second.0.load(Ordering::Relaxed), 1);
        assert_eq!(dropped.0.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn injected_coalescing_preserves_normative_boundaries() {
        let (mut receiver, _peer) = memory_pair(NonZeroUsize::new(2).unwrap());
        let metadata = DatagramMetadata {
            original_len: 7,
            segment_size: NonZeroUsize::new(3),
            ..DatagramMetadata::empty()
        };
        receiver
            .inject_received(b"abcdefg".to_vec(), metadata)
            .unwrap();

        let mut buffer = [0; 7];
        let metadata = receiver.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"abcdefg");
        assert_eq!(metadata.segment_count(), 3);
        assert!(!metadata.truncated);

        let invalid = DatagramMetadata {
            original_len: 0,
            segment_size: NonZeroUsize::new(1),
            ..DatagramMetadata::empty()
        };
        assert!(matches!(
            receiver.inject_received(Vec::new(), invalid),
            Err(DatagramError::InvalidSegmentSize { .. })
        ));

        let invalid = DatagramMetadata {
            segment_size: NonZeroUsize::new(3),
            ..DatagramMetadata::empty()
        };
        assert!(matches!(
            receiver.inject_received(b"abc".to_vec(), invalid),
            Err(DatagramError::InvalidSegmentSize { .. })
        ));

        let valid = DatagramMetadata {
            segment_size: NonZeroUsize::MIN.into(),
            ..DatagramMetadata::empty()
        };
        receiver.inject_received(vec![0; 64], valid).unwrap();

        let invalid = DatagramMetadata {
            segment_size: NonZeroUsize::MIN.into(),
            ..DatagramMetadata::empty()
        };
        assert!(matches!(
            receiver.inject_received(vec![0; 65], invalid),
            Err(DatagramError::TooManySegments { count: 65, max: 64 })
        ));
    }
}
