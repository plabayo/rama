use super::*;
use crate::datagram::{NativeDatagramChannel, capsule::UnknownCapsules};
use parking_lot::Mutex;
use rama_core::ServiceInput;
use std::{
    collections::VecDeque,
    future::Future as _,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Waker,
};
use tokio::io::{AsyncWriteExt as _, DuplexStream};

const CONTROL: CapsuleType = match CapsuleType::new(0x2a) {
    Ok(ty) => ty,
    Err(_) => panic!("valid capsule type"),
};

fn config() -> SessionConfig {
    SessionConfig {
        capsules: CapsuleConfig {
            max_datagram_size: 64,
            max_capsule_size: 32,
            capsule_types: Box::new([CONTROL]),
            unknown: UnknownCapsules::Skip,
        },
        ..SessionConfig::default()
    }
}

fn pair() -> (
    HttpDatagramSession<ServiceInput<DuplexStream>>,
    HttpDatagramSession<ServiceInput<DuplexStream>>,
) {
    let (a, b) = tokio::io::duplex(256);
    (
        HttpDatagramSession::with_config(ServiceInput::new(a), config()),
        HttpDatagramSession::with_config(ServiceInput::new(b), config()),
    )
}

fn datagram(payload: &'static [u8], transport: DatagramTransport) -> SessionEvent {
    SessionEvent::Datagram {
        payload: Bytes::from_static(payload),
        transport,
    }
}

#[tokio::test]
async fn capsules_round_trip_over_a_reliable_stream() {
    let (mut client, mut server) = pair();
    assert!(client.native().is_none());
    for payload in [&b"first"[..], b"", &[9; 64]] {
        assert_eq!(
            client
                .send_datagram(Bytes::copy_from_slice(payload))
                .await
                .unwrap(),
            DatagramTransport::Capsule
        );
    }
    client
        .send_capsule(CONTROL, Bytes::from_static(b"control"))
        .await
        .unwrap();
    // Unknown types are skipped by endpoints.
    client
        .send_capsule(
            CapsuleType::new(0x17).unwrap(),
            Bytes::from_static(b"grease"),
        )
        .await
        .unwrap();
    client.close().await.unwrap();
    assert_eq!(
        server.recv().await.unwrap(),
        Some(datagram(b"first", DatagramTransport::Capsule))
    );
    assert_eq!(
        server.recv().await.unwrap(),
        Some(datagram(b"", DatagramTransport::Capsule))
    );
    let Some(SessionEvent::Datagram { payload, .. }) = server.recv().await.unwrap() else {
        panic!("expected datagram");
    };
    assert_eq!(&payload[..], &[9; 64]);
    assert_eq!(
        server.recv().await.unwrap(),
        Some(SessionEvent::Capsule {
            ty: CONTROL,
            value: Bytes::from_static(b"control")
        })
    );
    assert_eq!(server.recv().await.unwrap(), None);
    // The other direction remains usable after half-close.
    server
        .send_datagram(Bytes::from_static(b"reply"))
        .await
        .unwrap();
    server.close().await.unwrap();
    assert_eq!(
        client.recv().await.unwrap(),
        Some(datagram(b"reply", DatagramTransport::Capsule))
    );
    assert_eq!(client.recv().await.unwrap(), None);
}

#[tokio::test]
async fn intermediaries_can_forward_unknown_capsules() {
    let (a, b) = tokio::io::duplex(256);
    let mut client = HttpDatagramSession::with_config(ServiceInput::new(a), config());
    let mut forward = config();
    forward.capsules.unknown = UnknownCapsules::Forward;
    let mut proxy = HttpDatagramSession::with_config(ServiceInput::new(b), forward);
    let ty = CapsuleType::new(0x4242).unwrap();
    client
        .send_capsule(ty, Bytes::from_static(b"opaque"))
        .await
        .unwrap();
    client.close().await.unwrap();
    let Some(SessionEvent::UnknownCapsule(header)) = proxy.recv().await.unwrap() else {
        panic!("expected forwarded header");
    };
    assert_eq!((header.ty, header.length.into_inner()), (ty, 6));
    let mut value = Vec::new();
    while let Some(event) = proxy.recv().await.unwrap() {
        let SessionEvent::UnknownCapsuleData(chunk) = event else {
            panic!("unexpected {event:?}");
        };
        value.extend_from_slice(&chunk);
    }
    assert_eq!(value, b"opaque");
}

#[derive(Default)]
struct FakeNativeState {
    max: Option<usize>,
    sent: Vec<Bytes>,
    inbox: VecDeque<Bytes>,
    closed: bool,
    waker: Option<Waker>,
}

/// A third-party carrier built only from the public contract.
#[derive(Clone, Default)]
struct FakeNative(Arc<Mutex<FakeNativeState>>);

impl NativeDatagramChannel for FakeNative {
    fn max_payload_size(&self) -> Option<usize> {
        self.0.lock().max
    }

    fn send(&self, payload: Bytes, _policy: NativeSendPolicy) -> Result<(), NativeSendError> {
        self.0.lock().sent.push(payload);
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        let mut state = self.0.lock();
        if let Some(payload) = state.inbox.pop_front() {
            return Poll::Ready(Some(payload));
        }
        if state.closed {
            return Poll::Ready(None);
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn dropped(&self) -> u64 {
        0
    }
}

impl FakeNative {
    fn push(&self, payload: &'static [u8]) {
        let mut state = self.0.lock();
        state.inbox.push_back(Bytes::from_static(payload));
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}

fn native_pair(
    native: &FakeNative,
) -> (
    HttpDatagramSession<ServiceInput<DuplexStream>>,
    HttpDatagramSession<ServiceInput<DuplexStream>>,
) {
    let (a, b) = tokio::io::duplex(256);
    let a = ServiceInput::new(a);
    a.extensions().insert(NativeDatagrams::new(native.clone()));
    (
        HttpDatagramSession::with_config(a, config()),
        HttpDatagramSession::with_config(ServiceInput::new(b), config()),
    )
}

#[tokio::test]
async fn native_carrier_is_preferred_without_oversize_fallback() {
    let native = FakeNative::default();
    let (mut local, mut peer) = native_pair(&native);
    // Not negotiated: capsules carry the datagram.
    assert_eq!(
        local
            .send_datagram(Bytes::from_static(b"early"))
            .await
            .unwrap(),
        DatagramTransport::Capsule
    );
    native.0.lock().max = Some(8);
    assert_eq!(
        local
            .send_datagram(Bytes::from_static(b"native"))
            .await
            .unwrap(),
        DatagramTransport::Native
    );
    let error = local
        .send_datagram(Bytes::from_static(b"too large for it"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            SessionError::Native(NativeSendError::TooLarge { max: 8 })
        ),
        "{error:?}"
    );
    // Reliable control keeps using the data stream.
    local
        .send_capsule(CONTROL, Bytes::from_static(b"ctl"))
        .await
        .unwrap();
    local.close().await.unwrap();
    assert_eq!(native.0.lock().sent, [Bytes::from_static(b"native")]);
    assert_eq!(
        peer.recv().await.unwrap(),
        Some(datagram(b"early", DatagramTransport::Capsule))
    );
    assert!(matches!(
        peer.recv().await.unwrap(),
        Some(SessionEvent::Capsule { .. })
    ));
    assert_eq!(peer.recv().await.unwrap(), None);
}

#[tokio::test]
async fn native_and_capsule_sources_are_merged_fairly() {
    let native = FakeNative::default();
    let (mut local, mut peer) = native_pair(&native);
    for _ in 0..8 {
        native.push(b"n");
        peer.send_datagram(Bytes::from_static(b"c")).await.unwrap();
    }
    let mut order = String::new();
    for _ in 0..16 {
        match local.recv().await.unwrap() {
            Some(SessionEvent::Datagram {
                transport: DatagramTransport::Native,
                ..
            }) => order.push('n'),
            Some(SessionEvent::Datagram {
                transport: DatagramTransport::Capsule,
                ..
            }) => order.push('c'),
            other => panic!("unexpected {other:?}"),
        }
    }
    // Neither source may be starved while the other stays ready.
    assert!(!order.contains("nnn") && !order.contains("ccc"), "{order}");
    // A clean end of the data stream ends the session; later native datagrams are dropped.
    native.push(b"late");
    peer.close().await.unwrap();
    while let Some(event) = local.recv().await.unwrap() {
        assert!(
            matches!(
                event,
                SessionEvent::Datagram {
                    transport: DatagramTransport::Native,
                    ..
                }
            ),
            "{event:?}"
        );
    }
    assert_eq!(local.recv().await.unwrap(), None);
}

#[tokio::test]
async fn malformed_streams_abort_through_the_transport_hook() {
    for wire in [
        // Truncated DATAGRAM capsule at a clean end of stream.
        &b"\x00\x05ab"[..],
        // Partial type integer.
        b"\x40",
        // Registered control capsule above its limit.
        b"\x2a\x21",
    ] {
        let (a, mut raw) = tokio::io::duplex(256);
        let a = ServiceInput::new(a);
        let aborted = Arc::new(AtomicUsize::new(0));
        a.extensions().insert(OnMalformedMessage::new({
            let aborted = aborted.clone();
            move || {
                aborted.fetch_add(1, Ordering::Relaxed);
            }
        }));
        let mut session = HttpDatagramSession::with_config(a, config());
        raw.write_all(wire).await.unwrap();
        raw.shutdown().await.unwrap();
        for _ in 0..2 {
            let error = session.recv().await.unwrap_err();
            assert!(matches!(error, SessionError::Malformed(_)), "{error:?}");
        }
        assert_eq!(aborted.load(Ordering::Relaxed), 1, "{wire:?}");
    }
}

/// Accepts one byte per successful poll and alternates with `Pending`.
struct Trickle {
    inner: DuplexStream,
    pending: bool,
    extensions: rama_core::extensions::Extensions,
}

impl ExtensionsRef for Trickle {
    fn extensions(&self) -> &rama_core::extensions::Extensions {
        &self.extensions
    }
}

impl AsyncRead for Trickle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Trickle {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.pending = !self.pending;
        if self.pending {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, &buf[..buf.len().min(1)])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn cancelled_sends_never_truncate_a_capsule() {
    let (a, b) = tokio::io::duplex(256);
    let mut sender = HttpDatagramSession::with_config(
        Trickle {
            inner: a,
            pending: false,
            extensions: Default::default(),
        },
        config(),
    );
    let mut receiver = HttpDatagramSession::with_config(ServiceInput::new(b), config());
    let mut cx = Context::from_waker(Waker::noop());
    for polls in 1..8 {
        {
            let send = sender.send_capsule(CONTROL, Bytes::from_static(b"interrupted"));
            let mut send = std::pin::pin!(send);
            for _ in 0..polls {
                assert!(send.as_mut().poll(&mut cx).is_pending());
            }
        }
        // The next operation completes the abandoned capsule before its own.
        sender
            .send_datagram(Bytes::from_static(b"after"))
            .await
            .unwrap();
        assert_eq!(
            receiver.recv().await.unwrap(),
            Some(SessionEvent::Capsule {
                ty: CONTROL,
                value: Bytes::from_static(b"interrupted")
            })
        );
        assert_eq!(
            receiver.recv().await.unwrap(),
            Some(datagram(b"after", DatagramTransport::Capsule))
        );
    }
    sender.close().await.unwrap();
    assert_eq!(receiver.recv().await.unwrap(), None);
}

#[tokio::test]
async fn split_halves_relay_concurrently() {
    let (client, server) = pair();
    let (mut client_tx, mut client_rx) = client.split();
    let (mut server_tx, mut server_rx) = server.split();
    const COUNT: usize = 200;
    let echo = tokio::spawn(async move {
        while let Some(event) = server_rx.recv().await.unwrap() {
            let SessionEvent::Datagram { payload, .. } = event else {
                panic!("unexpected {event:?}");
            };
            server_tx.send_datagram(payload).await.unwrap();
        }
        server_tx.close().await.unwrap();
    });
    let send = tokio::spawn(async move {
        for i in 0..COUNT {
            client_tx
                .send_datagram(Bytes::from(i.to_be_bytes().to_vec()))
                .await
                .unwrap();
        }
        client_tx.close().await.unwrap();
    });
    let mut received: usize = 0;
    while let Some(SessionEvent::Datagram { payload, .. }) = client_rx.recv().await.unwrap() {
        assert_eq!(&payload[..], received.to_be_bytes());
        received += 1;
    }
    assert_eq!(received, COUNT);
    send.await.unwrap();
    echo.await.unwrap();
}

#[tokio::test]
async fn oversized_capsule_datagrams_are_counted_not_delivered() {
    let (mut client, mut server) = pair();
    client
        .send_datagram(Bytes::from(vec![1; 65]))
        .await
        .unwrap();
    client
        .send_datagram(Bytes::from_static(b"fits"))
        .await
        .unwrap();
    client.close().await.unwrap();
    assert_eq!(
        server.recv().await.unwrap(),
        Some(datagram(b"fits", DatagramTransport::Capsule))
    );
    assert_eq!(server.split().1.dropped_datagrams(), 1);
}
