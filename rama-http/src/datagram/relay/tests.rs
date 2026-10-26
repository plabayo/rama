use parking_lot::Mutex;
use rama_core::{ServiceInput, bytes::Bytes, rt::spawn};
use std::{
    collections::VecDeque,
    future::Future as _,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncWriteExt as _, DuplexStream};

use super::*;
use crate::datagram::{
    NativeDatagramChannel, NativeDatagrams, NativeRecvError, NativeSendPolicy, NativeSendReady,
    capsule::encode_capsule,
};

#[derive(Default)]
struct NativeState {
    maximum: Option<usize>,
    received: VecDeque<Bytes>,
    sent: Vec<Bytes>,
    waker: Option<Waker>,
}

#[derive(Clone, Default)]
struct Native(Arc<Mutex<NativeState>>);

impl Native {
    fn push(&self, bytes: &'static [u8]) {
        let waker = {
            let mut state = self.0.lock();
            state.received.push_back(Bytes::from_static(bytes));
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl NativeDatagramChannel for Native {
    fn send_ready(&self) -> NativeSendReady {
        NativeSendReady::now()
    }

    fn max_payload_size(&self) -> Option<usize> {
        self.0.lock().maximum
    }
    fn send(&self, payload: Bytes, _: NativeSendPolicy) -> Result<(), NativeSendError> {
        self.0.lock().sent.push(payload);
        Ok(())
    }
    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        let mut state = self.0.lock();
        if let Some(bytes) = state.received.pop_front() {
            return Poll::Ready(Ok(Some(bytes)));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
    fn dropped(&self) -> u64 {
        0
    }
    fn release_recv(&self) {
        self.0.lock().received.clear();
    }
}

fn socket(native: &Native) -> (ServiceInput<DuplexStream>, ServiceInput<DuplexStream>) {
    let (relay, peer) = tokio::io::duplex(64);
    let relay = ServiceInput::new(relay);
    relay
        .extensions()
        .insert(NativeDatagrams::new(native.clone()));
    (relay, ServiceInput::new(peer))
}

#[tokio::test]
async fn relay_keeps_capsule_datagrams_reliable_with_native_egress() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let ingress = Native::default();
        let egress = Native::default();
        egress.0.lock().maximum = Some(64);
        let (left, client) = socket(&ingress);
        let (right, origin) = socket(&egress);
        let relay = spawn(async move {
            HttpDatagramRelay::default()
                .serve(BridgeIo(left, right))
                .await
        });
        let mut client = HttpDatagramSession::new(client);
        let mut origin = HttpDatagramSession::new(origin);
        client
            .send_capsule(CapsuleType::DATAGRAM, Bytes::from_static(b"reliable"))
            .await
            .unwrap();
        assert_eq!(
            origin.recv().await.unwrap(),
            Some(SessionEvent::Datagram {
                payload: Bytes::from_static(b"reliable"),
                transport: DatagramTransport::Capsule,
            })
        );
        assert!(egress.0.lock().sent.is_empty());
        client.close().await.unwrap();
        assert_eq!(origin.recv().await.unwrap(), None);
        origin
            .send_capsule(CapsuleType::DATAGRAM, Bytes::from_static(b"after FIN"))
            .await
            .unwrap();
        assert_eq!(
            client.recv().await.unwrap(),
            Some(SessionEvent::Datagram {
                payload: Bytes::from_static(b"after FIN"),
                transport: DatagramTransport::Capsule,
            })
        );
        origin.close().await.unwrap();
        let outcome = relay.await.unwrap().unwrap();
        assert_eq!(outcome.ingress_to_egress.datagrams, 1);
        assert_eq!(outcome.egress_to_ingress.datagrams, 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_finishes_unknown_capsule_before_native_fallback() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let ingress = Native::default();
        let (left, mut client) = socket(&ingress);
        let (right, origin) = socket(&Native::default());
        let mut relay = Box::pin(async move { HttpDatagramRelay::default().serve(BridgeIo(left, right)).await });
        let mut config = SessionConfig::default();
        config.capsules.unknown = UnknownCapsules::Forward;
        let mut origin = HttpDatagramSession::with_config(origin, config);
        let ty = CapsuleType::new(0x4242).unwrap();
        let wire = encode_capsule(ty, b"opaque value").unwrap();
        let header_len = wire.len() - b"opaque value".len();
        client.write_all(&wire[..header_len]).await.unwrap();
        assert!(std::future::poll_fn(|cx| Poll::Ready(relay.as_mut().poll(cx))).await.is_pending());
        assert!(matches!(origin.recv().await.unwrap(), Some(SessionEvent::UnknownCapsule(header)) if header.ty == ty));
        ingress.push(b"native fallback");
        assert!(std::future::poll_fn(|cx| Poll::Ready(relay.as_mut().poll(cx))).await.is_pending(), "native fallback must wait for the capsule boundary");
        let relay = spawn(relay);
        client.write_all(b"opaque value").await.unwrap();
        let mut opaque = Vec::new();
        while opaque.len() < b"opaque value".len() {
            let Some(SessionEvent::UnknownCapsuleData(chunk)) = origin.recv().await.unwrap() else { panic!("capsule value was interleaved") };
            opaque.extend_from_slice(&chunk);
        }
        assert_eq!(opaque, b"opaque value");
        assert_eq!(origin.recv().await.unwrap(), Some(SessionEvent::Datagram {
            payload: Bytes::from_static(b"native fallback"), transport: DatagramTransport::Capsule,
        }));
        client.shutdown().await.unwrap();
        origin.close().await.unwrap();
        let outcome = relay.await.unwrap().unwrap();
        assert_eq!(outcome.ingress_to_egress.capsules, 1);
        assert_eq!(outcome.ingress_to_egress.datagrams, 1);
    }).await.unwrap();
}

#[tokio::test]
async fn relay_drops_oversize_native_without_reliable_fallback() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let ingress = Native::default();
        let egress = Native::default();
        egress.0.lock().maximum = Some(2);
        let (left, mut client) = socket(&ingress);
        let (right, origin) = socket(&egress);
        ingress.push(b"too large");
        let relay = spawn(async move {
            HttpDatagramRelay::default()
                .serve(BridgeIo(left, right))
                .await
        });
        let mut origin = HttpDatagramSession::new(origin);
        client.shutdown().await.unwrap();
        assert_eq!(origin.recv().await.unwrap(), None);
        origin.close().await.unwrap();
        let outcome = relay.await.unwrap().unwrap();
        assert_eq!(outcome.ingress_to_egress.dropped, 1);
        assert_eq!(outcome.ingress_to_egress.datagrams, 0);
        assert!(egress.0.lock().sent.is_empty());
    })
    .await
    .unwrap();
}

#[test]
fn relay_cancellation_before_poll_aborts_both_owned_streams() {
    let aborted = Arc::new(AtomicUsize::new(0));
    let (left, _left_peer) = socket(&Native::default());
    let (right, _right_peer) = socket(&Native::default());
    for io in [&left, &right] {
        let aborted = aborted.clone();
        io.extensions().insert(AbortIo::new(move || {
            aborted.fetch_add(1, Ordering::SeqCst);
        }));
    }
    let relay = HttpDatagramRelay::default();
    drop(relay.serve(BridgeIo(left, right)));
    assert_eq!(aborted.load(Ordering::SeqCst), 2);
}
