//! A third-party native datagram carrier and an independent observer, composed with
//! [`HttpDatagramSession`] through the public contract only.

use parking_lot::Mutex;
use rama_core::{ServiceInput, bytes::Bytes, extensions::ExtensionsRef as _};
use rama_http::datagram::{
    DatagramTransport, HttpDatagramSession, NativeDatagramChannel, NativeDatagrams,
    NativeRecvError, NativeSendError, NativeSendPolicy, SessionEvent,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};
use tokio::io::{DuplexStream, duplex};

#[derive(Default)]
struct Inbox {
    queue: VecDeque<Bytes>,
    waker: Option<Waker>,
    released: bool,
}

/// One end of an in-process carrier: what it sends lands in the peer's inbox.
struct Loopback {
    inbox: Arc<Mutex<Inbox>>,
    peer: Arc<Mutex<Inbox>>,
    // 0: not negotiated.
    max: Arc<AtomicUsize>,
    dropped: AtomicU64,
}

impl Loopback {
    fn pair(max: &Arc<AtomicUsize>) -> (Self, Self) {
        let (a, b) = (Arc::default(), Arc::<Mutex<Inbox>>::default());
        let end = |inbox: &Arc<Mutex<Inbox>>, peer: &Arc<Mutex<Inbox>>| Self {
            inbox: inbox.clone(),
            peer: peer.clone(),
            max: max.clone(),
            dropped: AtomicU64::new(0),
        };
        (end(&a, &b), end(&b, &a))
    }
}

impl NativeDatagramChannel for Loopback {
    fn max_payload_size(&self) -> Option<usize> {
        Some(self.max.load(Ordering::Acquire)).filter(|max| *max > 0)
    }

    fn send(&self, payload: Bytes, _policy: NativeSendPolicy) -> Result<(), NativeSendError> {
        let Some(max) = self.max_payload_size() else {
            return Err(NativeSendError::Unavailable);
        };
        if payload.len() > max {
            return Err(NativeSendError::TooLarge { max });
        }
        let mut peer = self.peer.lock();
        if peer.released {
            return Ok(());
        }
        peer.queue.push_back(payload);
        if let Some(waker) = peer.waker.take() {
            waker.wake();
        }
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        let mut inbox = self.inbox.lock();
        if let Some(payload) = inbox.queue.pop_front() {
            return Poll::Ready(Ok(Some(payload)));
        }
        inbox.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Acquire)
    }

    fn release_recv(&self) {
        let mut inbox = self.inbox.lock();
        inbox.released = true;
        self.dropped
            .fetch_add(inbox.queue.len() as u64, Ordering::AcqRel);
        inbox.queue.clear();
    }
}

#[derive(Default)]
struct Counts {
    sent: AtomicU64,
    received: AtomicU64,
    released: AtomicU64,
}

/// Counts what any carrier sends and receives, knowing nothing of its implementation.
struct Observed<C> {
    inner: C,
    counts: Arc<Counts>,
}

impl<C: NativeDatagramChannel> NativeDatagramChannel for Observed<C> {
    fn max_payload_size(&self) -> Option<usize> {
        self.inner.max_payload_size()
    }

    fn send(&self, payload: Bytes, policy: NativeSendPolicy) -> Result<(), NativeSendError> {
        self.inner.send(payload, policy)?;
        self.counts.sent.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        let polled = self.inner.poll_recv(cx);
        if let Poll::Ready(Ok(Some(_))) = polled {
            self.counts.received.fetch_add(1, Ordering::AcqRel);
        }
        polled
    }

    fn dropped(&self) -> u64 {
        self.inner.dropped()
    }

    fn release_recv(&self) {
        self.counts.released.fetch_add(1, Ordering::AcqRel);
        self.inner.release_recv();
    }
}

/// Two sessions over one byte stream, each publishing its end of an observed carrier.
fn sessions(
    max: &Arc<AtomicUsize>,
) -> (
    HttpDatagramSession<ServiceInput<DuplexStream>>,
    HttpDatagramSession<ServiceInput<DuplexStream>>,
    Arc<Counts>,
) {
    let (left, right) = duplex(4096);
    let (left_carrier, right_carrier) = Loopback::pair(max);
    let counts = Arc::new(Counts::default());
    let publish = |io: DuplexStream, inner: Loopback| {
        let io = ServiceInput::new(io);
        io.extensions().insert(NativeDatagrams::new(Observed {
            inner,
            counts: counts.clone(),
        }));
        HttpDatagramSession::new(io)
    };
    (
        publish(left, left_carrier),
        publish(right, right_carrier),
        counts,
    )
}

fn datagram(payload: &'static [u8], transport: DatagramTransport) -> Option<SessionEvent> {
    Some(SessionEvent::Datagram {
        payload: Bytes::from_static(payload),
        transport,
    })
}

#[tokio::test]
async fn a_custom_carrier_and_observer_compose_with_the_session() {
    let max = Arc::new(AtomicUsize::new(0));
    let (mut left, mut right, counts) = sessions(&max);

    // Not negotiated yet: the session carries datagrams as capsules on the stream.
    assert_eq!(
        left.send_datagram(Bytes::from_static(b"early"))
            .await
            .unwrap(),
        DatagramTransport::Capsule
    );
    assert_eq!(
        right.recv().await.unwrap(),
        datagram(b"early", DatagramTransport::Capsule)
    );

    // Negotiated: the custom carrier takes over, both ways, observed on the way.
    max.store(16, Ordering::Release);
    assert_eq!(
        left.send_datagram(Bytes::from_static(b"native"))
            .await
            .unwrap(),
        DatagramTransport::Native
    );
    assert_eq!(
        right.recv().await.unwrap(),
        datagram(b"native", DatagramTransport::Native)
    );
    assert_eq!(
        right
            .send_datagram(Bytes::from_static(b"back"))
            .await
            .unwrap(),
        DatagramTransport::Native
    );
    assert_eq!(
        left.recv().await.unwrap(),
        datagram(b"back", DatagramTransport::Native)
    );
    assert_eq!(counts.sent.load(Ordering::Acquire), 2);
    assert_eq!(counts.received.load(Ordering::Acquire), 2);

    // The carrier's limit is its own, and the session reports it.
    let too_large = left
        .send_datagram(Bytes::from_static(b"larger than sixteen"))
        .await
        .unwrap_err();
    assert!(too_large.to_string().contains("16"), "{too_large}");

    // A clean close of the data stream ends the peer's session.
    left.close().await.unwrap();
    assert_eq!(right.recv().await.unwrap(), None);
    right.close().await.unwrap();
    assert_eq!(left.recv().await.unwrap(), None);
}

#[tokio::test]
async fn dropping_the_receiver_releases_the_custom_carrier_once() {
    let max = Arc::new(AtomicUsize::new(16));
    let (mut left, right, counts) = sessions(&max);
    let native = right.native().unwrap().clone();
    // Queued for a consumer that goes away before reading it.
    left.send_datagram(Bytes::from_static(b"unread"))
        .await
        .unwrap();
    let (_sender, receiver) = right.split();
    drop(receiver);
    assert_eq!(counts.released.load(Ordering::Acquire), 1);
    assert_eq!(native.channel().dropped(), 1);
}
