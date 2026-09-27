use super::*;
use crate::datagram::{
    NativeDatagramChannel, NativeRecvError,
    capsule::{CapsuleError, UnknownCapsules, encode_capsule},
};
use parking_lot::Mutex;
use rama_core::{ServiceInput, extensions::Extensions};
use std::{
    collections::VecDeque,
    future::Future as _,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::Waker,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, ReadBuf};

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
    next_error: Option<NativeSendError>,
    released: usize,
    dropped: u64,
}

/// A third-party carrier built only from the public contract.
#[derive(Clone, Default)]
struct FakeNative(Arc<Mutex<FakeNativeState>>);

impl NativeDatagramChannel for FakeNative {
    fn max_payload_size(&self) -> Option<usize> {
        self.0.lock().max
    }

    fn send(&self, payload: Bytes, _policy: NativeSendPolicy) -> Result<(), NativeSendError> {
        let mut state = self.0.lock();
        if let Some(error) = state.next_error.take() {
            return Err(error);
        }
        state.sent.push(payload);
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        let mut state = self.0.lock();
        if let Some(payload) = state.inbox.pop_front() {
            return Poll::Ready(Ok(Some(payload)));
        }
        if state.closed {
            return Poll::Ready(Ok(None));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn dropped(&self) -> u64 {
        self.0.lock().dropped
    }

    fn release_recv(&self) {
        self.0.lock().released += 1;
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
    // The limit is read at every send: a shrunk one applies at once.
    native.0.lock().max = Some(4);
    let error = local
        .send_datagram(Bytes::from_static(b"native"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            SessionError::Native(NativeSendError::TooLarge { max: 4 })
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
    extensions: Extensions,
}

impl ExtensionsRef for Trickle {
    fn extensions(&self) -> &Extensions {
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

#[tokio::test]
async fn dropped_datagrams_add_the_native_carriers_drops() {
    let native = FakeNative::default();
    // Only the local session has the native carrier; the peer sends capsules.
    let (local, mut peer) = native_pair(&native);
    native.0.lock().dropped = 3;
    peer.send_datagram(Bytes::from(vec![1; 65])).await.unwrap();
    peer.close().await.unwrap();
    let (_, mut receiver) = local.split();
    assert_eq!(receiver.recv().await.unwrap(), None);
    assert_eq!(receiver.dropped_datagrams(), 3 + 1);
}

#[test]
fn only_sessions_over_a_carrier_expose_it() {
    let native = FakeNative::default();
    let (with, _) = native_pair(&native);
    assert!(with.native().is_some());
    let (without, _) = pair();
    assert!(without.native().is_none());
}

#[test]
fn session_errors_chain_their_cause() {
    let io = SessionError::Io(std::io::Error::other("wire"));
    let sources: [(SessionError, bool); 5] = [
        (SessionError::Malformed(CapsuleError::Truncated), true),
        (SessionError::Native(NativeSendError::Full), true),
        (SessionError::NativeRecv(NativeRecvError::Lost), true),
        (io, true),
        (SessionError::SendClosed, false),
    ];
    for (error, chained) in sources {
        assert_eq!(
            std::error::Error::source(&error).is_some(),
            chained,
            "{error:?}"
        );
    }
}

fn hooked(io: DuplexStream) -> (ServiceInput<DuplexStream>, Arc<AtomicUsize>) {
    let io = ServiceInput::new(io);
    let aborted = Arc::new(AtomicUsize::new(0));
    io.extensions().insert(OnMalformedMessage::new({
        let aborted = aborted.clone();
        move || {
            aborted.fetch_add(1, Ordering::Relaxed);
        }
    }));
    (io, aborted)
}

fn header(ty: u64, length: u64) -> CapsuleHeader {
    CapsuleHeader::new(CapsuleType::new(ty).unwrap(), length).unwrap()
}

#[tokio::test]
async fn streamed_capsules_reject_interleaving_and_overruns() {
    let native = FakeNative::default();
    native.0.lock().max = Some(64);
    let (mut local, mut peer) = native_pair(&native);
    assert!(matches!(
        local.send_capsule_data(Bytes::from_static(b"x")).await,
        Err(SessionError::CapsuleNotStarted)
    ));
    local.start_capsule(header(0x4242, 6)).await.unwrap();
    local
        .send_capsule_data(Bytes::from_static(b"ab"))
        .await
        .unwrap();
    for rejected in [
        local.send_capsule(CONTROL, Bytes::from_static(b"c")).await,
        local.start_capsule(header(0x4243, 1)).await,
        local.close().await,
    ] {
        assert!(
            matches!(rejected, Err(SessionError::CapsuleInProgress)),
            "{rejected:?}"
        );
    }
    assert!(matches!(
        local.send_capsule_data(Bytes::from_static(b"cdefg")).await,
        Err(SessionError::CapsuleLengthMismatch)
    ));
    // Native datagrams never wait for the reliable stream.
    assert_eq!(
        local
            .send_datagram(Bytes::from_static(b"native"))
            .await
            .unwrap(),
        DatagramTransport::Native
    );
    local
        .send_capsule_data(Bytes::from_static(b"cdef"))
        .await
        .unwrap();
    local
        .send_capsule(CONTROL, Bytes::from_static(b"next"))
        .await
        .unwrap();
    local.close().await.unwrap();
    assert_eq!(
        peer.recv().await.unwrap(),
        Some(SessionEvent::Capsule {
            ty: CONTROL,
            value: Bytes::from_static(b"next")
        })
    );
    assert_eq!(peer.recv().await.unwrap(), None);
}

#[tokio::test]
async fn relays_forward_capsules_larger_than_every_buffer() {
    let (client_io, relay_in) = tokio::io::duplex(64);
    let (relay_out, server_io) = tokio::io::duplex(64);
    let mut forward = config();
    forward.capsules.unknown = UnknownCapsules::Forward;
    forward.read_chunk_size = 16;
    let relay_in = HttpDatagramSession::with_config(ServiceInput::new(relay_in), forward.clone());
    let relay_out = HttpDatagramSession::with_config(ServiceInput::new(relay_out), config());
    let mut server = HttpDatagramSession::with_config(ServiceInput::new(server_io), forward);
    let big: Bytes = (0..4096u32).map(|i| i as u8).collect::<Vec<_>>().into();

    let client = tokio::spawn({
        let big = big.clone();
        async move {
            let mut client = client_io;
            // A non-minimal header: 8-byte type and length integers.
            let mut wire = vec![
                0xc0, 0, 0, 0, 0, 0, 0x42, 0x42, 0xc0, 0, 0, 0, 0, 0, 0x10, 0,
            ];
            wire.extend_from_slice(&big);
            wire.extend_from_slice(
                &encode_capsule(CapsuleType::new(0x4243).unwrap(), b"").unwrap(),
            );
            wire.extend_from_slice(&encode_capsule(CapsuleType::DATAGRAM, b"dgram").unwrap());
            client.write_all(&wire).await.unwrap();
            client.shutdown().await.unwrap();
            let mut rest = Vec::new();
            client.read_to_end(&mut rest).await.unwrap();
        }
    });
    // The relay uses only public API.
    let relay = tokio::spawn(async move {
        let (_, mut inbound) = relay_in.split();
        let (mut outbound, _) = relay_out.split();
        while let Some(event) = inbound.recv().await.unwrap() {
            match event {
                SessionEvent::UnknownCapsule(header) => outbound.start_capsule(header).await,
                SessionEvent::UnknownCapsuleData(chunk) => outbound.send_capsule_data(chunk).await,
                SessionEvent::Datagram { payload, .. } => {
                    outbound.send_datagram(payload).await.map(drop)
                }
                SessionEvent::Capsule { ty, value } => outbound.send_capsule(ty, value).await,
            }
            .unwrap();
        }
        outbound.close().await.unwrap();
    });

    let Some(SessionEvent::UnknownCapsule(first)) = server.recv().await.unwrap() else {
        panic!("expected the forwarded header");
    };
    assert_eq!(
        (first.ty.value(), first.length.into_inner()),
        (0x4242, 4096)
    );
    let mut value = Vec::new();
    let empty = loop {
        match server.recv().await.unwrap() {
            Some(SessionEvent::UnknownCapsuleData(chunk)) => {
                assert!(chunk.len() <= 64, "chunks stay bounded: {}", chunk.len());
                value.extend_from_slice(&chunk);
            }
            Some(SessionEvent::UnknownCapsule(header)) => break header,
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(value, big);
    assert_eq!((empty.ty.value(), empty.length.into_inner()), (0x4243, 0));
    assert_eq!(
        server.recv().await.unwrap(),
        Some(datagram(b"dgram", DatagramTransport::Capsule))
    );
    assert_eq!(server.recv().await.unwrap(), None);
    relay.await.unwrap();
    drop(server);
    client.await.unwrap();
}

#[tokio::test]
async fn sends_dropped_before_acceptance_send_nothing() {
    let (a, b) = tokio::io::duplex(256);
    let mut sender = HttpDatagramSession::with_config(
        Trickle {
            inner: a,
            pending: false,
            extensions: Extensions::new(),
        },
        config(),
    );
    let mut receiver = HttpDatagramSession::with_config(ServiceInput::new(b), config());
    let mut cx = Context::from_waker(Waker::noop());
    // Never polled.
    drop(sender.send_capsule(CONTROL, Bytes::from_static(b"never")));
    {
        // Accepted at its first poll and left partially written.
        let first = sender.send_capsule(CONTROL, Bytes::from_static(b"accepted"));
        let mut first = std::pin::pin!(first);
        assert!(first.as_mut().poll(&mut cx).is_pending());
    }
    {
        // Still draining the earlier write when dropped: not accepted.
        let second = sender.send_capsule(CONTROL, Bytes::from_static(b"dropped"));
        let mut second = std::pin::pin!(second);
        assert!(second.as_mut().poll(&mut cx).is_pending());
    }
    sender
        .send_capsule(CONTROL, Bytes::from_static(b"third"))
        .await
        .unwrap();
    sender.close().await.unwrap();
    let mut values = Vec::new();
    while let Some(SessionEvent::Capsule { value, .. }) = receiver.recv().await.unwrap() {
        values.push(value);
    }
    assert_eq!(values, [&b"accepted"[..], b"third"]);
}

#[tokio::test]
async fn close_commits_once_and_can_be_resumed() {
    let (a, b) = tokio::io::duplex(256);
    let mut sender = HttpDatagramSession::with_config(
        Trickle {
            inner: a,
            pending: false,
            extensions: Extensions::new(),
        },
        config(),
    );
    let mut receiver = HttpDatagramSession::with_config(ServiceInput::new(b), config());
    let mut cx = Context::from_waker(Waker::noop());
    {
        let send = sender.send_capsule(CONTROL, Bytes::from_static(b"body"));
        let mut send = std::pin::pin!(send);
        assert!(send.as_mut().poll(&mut cx).is_pending());
    }
    {
        // Cancelled while draining: nothing is committed.
        let close = sender.close();
        let mut close = std::pin::pin!(close);
        assert!(close.as_mut().poll(&mut cx).is_pending());
    }
    sender
        .send_capsule(CONTROL, Bytes::from_static(b"after"))
        .await
        .unwrap();
    sender.close().await.unwrap();
    for rejected in [
        sender
            .send_capsule(CONTROL, Bytes::from_static(b"late"))
            .await,
        sender
            .send_datagram(Bytes::from_static(b"late"))
            .await
            .map(drop),
        sender.start_capsule(header(0x4242, 1)).await,
    ] {
        assert!(
            matches!(rejected, Err(SessionError::SendClosed)),
            "{rejected:?}"
        );
    }
    sender.close().await.unwrap();
    let mut values = Vec::new();
    while let Some(SessionEvent::Capsule { value, .. }) = receiver.recv().await.unwrap() {
        values.push(value);
    }
    assert_eq!(values, [&b"body"[..], b"after"]);
}

#[tokio::test]
async fn dropping_the_sender_mid_capsule_aborts_the_stream() {
    // Header and part of the value on the wire.
    let (a, _b) = tokio::io::duplex(256);
    let (io, aborted) = hooked(a);
    let (mut sender, receiver) = HttpDatagramSession::with_config(io, config()).split();
    sender.start_capsule(header(0x4242, 10)).await.unwrap();
    sender
        .send_capsule_data(Bytes::from_static(b"part"))
        .await
        .unwrap();
    drop(sender);
    assert_eq!(aborted.load(Ordering::Relaxed), 1);
    drop(receiver);

    // At a capsule boundary, or with a header accepted but never written, nothing is aborted.
    let (a, _b) = tokio::io::duplex(256);
    let (io, aborted) = hooked(a);
    let mut session = HttpDatagramSession::with_config(io, config());
    session
        .send_capsule(CONTROL, Bytes::from_static(b"whole"))
        .await
        .unwrap();
    drop(session);
    assert_eq!(aborted.load(Ordering::Relaxed), 0);

    // A partially written header counts as on the wire.
    let (a, _b) = tokio::io::duplex(256);
    let io = Trickle {
        inner: a,
        pending: false,
        extensions: Extensions::new(),
    };
    let aborted = Arc::new(AtomicUsize::new(0));
    io.extensions.insert(OnMalformedMessage::new({
        let aborted = aborted.clone();
        move || {
            aborted.fetch_add(1, Ordering::Relaxed);
        }
    }));
    let mut sender = HttpDatagramSession::with_config(io, config());
    let mut cx = Context::from_waker(Waker::noop());
    {
        // Two polls move exactly one of the two header bytes.
        let send = sender.send_capsule(CONTROL, Bytes::from_static(b"value"));
        let mut send = std::pin::pin!(send);
        for _ in 0..2 {
            assert!(send.as_mut().poll(&mut cx).is_pending());
        }
    }
    drop(sender);
    assert_eq!(aborted.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn recoverable_rejections_leave_the_sender_usable() {
    let native = FakeNative::default();
    native.0.lock().max = Some(8);
    let (mut local, mut peer) = native_pair(&native);
    native.0.lock().next_error = Some(NativeSendError::Full);
    assert!(matches!(
        local.send_datagram(Bytes::from_static(b"full")).await,
        Err(SessionError::Native(NativeSendError::Full))
    ));
    assert!(matches!(
        local.send_datagram(Bytes::from(vec![0; 9])).await,
        Err(SessionError::Native(NativeSendError::TooLarge { max: 8 }))
    ));
    assert_eq!(
        local
            .send_datagram(Bytes::from_static(b"ok"))
            .await
            .unwrap(),
        DatagramTransport::Native
    );
    // Unavailable falls back to reliable delivery; Closed never does.
    native.0.lock().next_error = Some(NativeSendError::Unavailable);
    assert_eq!(
        local
            .send_datagram(Bytes::from_static(b"reliable"))
            .await
            .unwrap(),
        DatagramTransport::Capsule
    );
    native.0.lock().next_error = Some(NativeSendError::Closed);
    assert!(matches!(
        local.send_datagram(Bytes::from_static(b"closed")).await,
        Err(SessionError::Native(NativeSendError::Closed))
    ));
    // Terminal for sending (see `native_closed_is_terminal_for_sending`).
    drop(local);
    assert_eq!(native.0.lock().sent, [Bytes::from_static(b"ok")]);
    assert_eq!(
        peer.recv().await.unwrap(),
        Some(datagram(b"reliable", DatagramTransport::Capsule))
    );
    assert_eq!(peer.recv().await.unwrap(), None);
}

#[tokio::test]
async fn dropping_the_receiver_releases_native_receive_only() {
    let native = FakeNative::default();
    native.0.lock().max = Some(8);
    let (local, mut peer) = native_pair(&native);
    let (mut sender, receiver) = local.split();
    drop(receiver);
    assert_eq!(native.0.lock().released, 1);
    sender
        .send_datagram(Bytes::from_static(b"n"))
        .await
        .unwrap();
    sender
        .send_capsule(CONTROL, Bytes::from_static(b"still"))
        .await
        .unwrap();
    sender.close().await.unwrap();
    assert!(matches!(
        peer.recv().await.unwrap(),
        Some(SessionEvent::Capsule { .. })
    ));
}

/// An always-ready reader: one unknown capsule that never ends.
struct Endless {
    header_sent: bool,
    extensions: Extensions,
}

impl ExtensionsRef for Endless {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl AsyncRead for Endless {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.header_sent {
            self.header_sent = true;
            // Type 0x17, length 2^32.
            buf.put_slice(&[0x17, 0xc0, 0, 0, 0x01, 0, 0, 0, 0]);
        } else {
            let fill = buf.remaining();
            buf.put_slice(&vec![0; fill]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Endless {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn receive_polls_do_bounded_work_and_keep_native_flowing() {
    let native = FakeNative::default();
    let io = Endless {
        header_sent: false,
        extensions: Extensions::new(),
    };
    io.extensions.insert(NativeDatagrams::new(native.clone()));
    let mut session = HttpDatagramSession::with_config(io, config());
    let mut cx = Context::from_waker(Waker::noop());
    // Skipping the endless value must yield instead of looping forever.
    for _ in 0..4 {
        assert!(session.receiver.poll_recv(&mut cx).is_pending());
    }
    native.push(b"n");
    assert_eq!(
        session.recv().await.unwrap(),
        Some(datagram(b"n", DatagramTransport::Native))
    );
}

/// Fails the first read and write, then behaves like a healthy, empty stream.
struct FailsOnce {
    read_failed: bool,
    write_failed: bool,
    extensions: Extensions,
}

impl ExtensionsRef for FailsOnce {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl AsyncRead for FailsOnce {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if std::mem::replace(&mut self.read_failed, true) {
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
    }
}

impl AsyncWrite for FailsOnce {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if std::mem::replace(&mut self.write_failed, true) {
            return Poll::Ready(Ok(buf.len()));
        }
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn stream_failures_are_sticky_per_direction() {
    let io = FailsOnce {
        read_failed: false,
        write_failed: false,
        extensions: Extensions::new(),
    };
    let mut session = HttpDatagramSession::with_config(io, config());
    for _ in 0..2 {
        let error = session
            .send_capsule(CONTROL, Bytes::from_static(b"x"))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, SessionError::Io(error) if error.kind() == io::ErrorKind::BrokenPipe),
            "{error:?}"
        );
    }
    assert!(matches!(session.close().await, Err(SessionError::Io(_))));
    for _ in 0..2 {
        let error = session.recv().await.unwrap_err();
        assert!(
            matches!(&error, SessionError::Io(error) if error.kind() == io::ErrorKind::ConnectionReset),
            "{error:?}"
        );
    }
}

/// A custom carrier whose receive side has failed.
struct FailedNative(NativeRecvError);

impl NativeDatagramChannel for FailedNative {
    fn max_payload_size(&self) -> Option<usize> {
        Some(128)
    }

    fn send(&self, _: Bytes, _: NativeSendPolicy) -> Result<(), NativeSendError> {
        Ok(())
    }

    fn poll_recv(&self, _: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        Poll::Ready(Err(self.0))
    }

    fn dropped(&self) -> u64 {
        0
    }
}

#[tokio::test]
async fn native_receive_failures_end_receiving() {
    for error in [
        NativeRecvError::Lost,
        NativeRecvError::Reset(0x10e),
        NativeRecvError::Aborted(0x10e),
    ] {
        // The reliable stream stays open and idle.
        let (a, _b) = tokio::io::duplex(256);
        let io = ServiceInput::new(a);
        io.extensions()
            .insert(NativeDatagrams::new(FailedNative(error)));
        let (_, mut receiver) = HttpDatagramSession::with_config(io, config()).split();
        let mut cx = Context::from_waker(Waker::noop());
        for attempt in 0..2 {
            let result = receiver.poll_recv(&mut cx);
            assert!(
                matches!(result, Poll::Ready(Err(SessionError::NativeRecv(e))) if e == error),
                "{error:?} attempt {attempt}: {result:?}"
            );
        }
    }
}

#[tokio::test]
async fn native_closed_is_terminal_for_sending() {
    let native = FakeNative::default();
    native.0.lock().max = Some(8);
    let (mut local, mut peer) = native_pair(&native);
    native.0.lock().next_error = Some(NativeSendError::Closed);
    for _ in 0..2 {
        assert!(matches!(
            local.send_datagram(Bytes::from_static(b"closed")).await,
            Err(SessionError::Native(NativeSendError::Closed))
        ));
    }
    assert!(matches!(
        local
            .send_capsule(CONTROL, Bytes::from_static(b"after"))
            .await,
        Err(SessionError::Native(NativeSendError::Closed))
    ));
    // Nothing was written after the terminal result.
    let mut cx = Context::from_waker(Waker::noop());
    assert!(peer.receiver.poll_recv(&mut cx).is_pending());
}

#[tokio::test]
async fn dropping_a_partial_sender_closes_hookless_carriers() {
    for partial_header in [false, true] {
        let (local, mut peer) = pair();
        let (mut sender, mut receiver) = local.split();
        if partial_header {
            // Header bytes only, with the receiver half retained.
            drop(receiver);
            let (a, b) = tokio::io::duplex(256);
            let mut sender_session = HttpDatagramSession::with_config(
                Trickle {
                    inner: a,
                    pending: false,
                    extensions: Extensions::new(),
                },
                config(),
            );
            let mut peer = HttpDatagramSession::with_config(ServiceInput::new(b), config());
            {
                let send = sender_session.send_capsule(CONTROL, Bytes::from_static(b"value"));
                let mut send = std::pin::pin!(send);
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..2 {
                    assert!(send.as_mut().poll(&mut cx).is_pending());
                }
            }
            let (sender, _retained) = sender_session.split();
            drop(sender);
            assert!(matches!(
                peer.recv().await,
                Err(SessionError::Malformed(CapsuleError::Truncated))
            ));
            continue;
        }
        sender.start_capsule(header(0x4242, 4)).await.unwrap();
        sender
            .send_capsule_data(Bytes::from_static(b"x"))
            .await
            .unwrap();
        drop(sender);
        // The peer sees the truncation instead of waiting for the missing value.
        assert!(matches!(
            peer.recv().await,
            Err(SessionError::Malformed(CapsuleError::Truncated))
        ));
        // The retained half fails instead of hanging.
        assert!(matches!(receiver.recv().await, Err(SessionError::Io(_))));
    }
}

#[tokio::test]
async fn malformed_input_closes_hookless_carriers_for_both_halves() {
    let (a, mut raw) = tokio::io::duplex(256);
    let (mut sender, mut receiver) =
        HttpDatagramSession::with_config(ServiceInput::new(a), config()).split();
    // A registered control capsule above its limit.
    raw.write_all(b"\x2a\x21").await.unwrap();
    assert!(matches!(
        receiver.recv().await,
        Err(SessionError::Malformed(_))
    ));
    let mut rest = Vec::new();
    raw.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    assert!(matches!(
        sender.send_capsule(CONTROL, Bytes::from_static(b"x")).await,
        Err(SessionError::Io(_))
    ));
}

/// Shutdown stays pending until allowed, to cancel `close` after its commit.
struct PendingShutdown {
    inner: DuplexStream,
    extensions: Extensions,
    polled: Arc<AtomicUsize>,
    allowed: Arc<AtomicBool>,
}

impl ExtensionsRef for PendingShutdown {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl AsyncRead for PendingShutdown {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PendingShutdown {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.polled.fetch_add(1, Ordering::Relaxed);
        if !self.allowed.load(Ordering::Relaxed) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn close_cancelled_after_its_commit_resumes_shutdown() {
    let (a, b) = tokio::io::duplex(256);
    let polled = Arc::new(AtomicUsize::new(0));
    let allowed = Arc::new(AtomicBool::new(false));
    let io = PendingShutdown {
        inner: a,
        extensions: Extensions::new(),
        polled: polled.clone(),
        allowed: allowed.clone(),
    };
    let mut local = HttpDatagramSession::with_config(io, config());
    let mut peer = HttpDatagramSession::with_config(ServiceInput::new(b), config());
    local
        .send_capsule(CONTROL, Bytes::from_static(b"before"))
        .await
        .unwrap();
    {
        let close = local.close();
        let mut close = std::pin::pin!(close);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(close.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(polled.load(Ordering::Relaxed), 1);
    assert!(matches!(
        local
            .send_capsule(CONTROL, Bytes::from_static(b"after"))
            .await,
        Err(SessionError::SendClosed)
    ));
    allowed.store(true, Ordering::Relaxed);
    local.close().await.unwrap();
    assert_eq!(polled.load(Ordering::Relaxed), 2);
    assert_eq!(
        peer.recv().await.unwrap(),
        Some(SessionEvent::Capsule {
            ty: CONTROL,
            value: Bytes::from_static(b"before")
        })
    );
    assert_eq!(peer.recv().await.unwrap(), None);
}

/// Counts wakes to observe that an abort reaches a task already waiting.
#[derive(Default)]
struct CountWakes(AtomicUsize);

impl std::task::Wake for CountWakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn aborts_wake_a_receiver_already_waiting() {
    let (local, _peer) = pair();
    let (mut sender, mut receiver) = local.split();
    sender.start_capsule(header(0x4242, 4)).await.unwrap();
    let wakes = Arc::new(CountWakes::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(receiver.poll_recv(&mut cx).is_pending());
    let before = wakes.0.load(Ordering::SeqCst);
    drop(sender);
    assert!(wakes.0.load(Ordering::SeqCst) > before);
    assert!(matches!(
        receiver.poll_recv(&mut cx),
        Poll::Ready(Err(SessionError::Io(_)))
    ));
}

#[tokio::test]
async fn aborts_wake_a_sender_already_waiting() {
    let (a, mut raw) = tokio::io::duplex(4);
    let (mut sender, mut receiver) =
        HttpDatagramSession::with_config(ServiceInput::new(a), config()).split();
    let wakes = Arc::new(CountWakes::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let send = sender.send_capsule(CONTROL, Bytes::from_static(b"longer than buffer"));
    let mut send = std::pin::pin!(send);
    assert!(send.as_mut().poll(&mut cx).is_pending());
    // A registered control capsule above its limit: malformed input aborts both halves.
    raw.write_all(b"\x2a\x21").await.unwrap();
    assert!(matches!(
        receiver.recv().await,
        Err(SessionError::Malformed(_))
    ));
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        send.as_mut().poll(&mut cx),
        Poll::Ready(Err(SessionError::Io(_)))
    ));
}

#[tokio::test]
async fn aborts_discard_already_decoded_events() {
    let (local, mut peer) = pair();
    let (mut sender, mut receiver) = local.split();
    peer.send_datagram(Bytes::from_static(b"first"))
        .await
        .unwrap();
    peer.send_datagram(Bytes::from_static(b"buffered"))
        .await
        .unwrap();
    assert_eq!(
        receiver.recv().await.unwrap(),
        Some(datagram(b"first", DatagramTransport::Capsule))
    );
    sender.start_capsule(header(0x4242, 4)).await.unwrap();
    drop(sender);
    assert!(matches!(receiver.recv().await, Err(SessionError::Io(_))));
}

#[tokio::test]
async fn the_malformed_hook_runs_once_per_session() {
    let (a, mut raw) = tokio::io::duplex(256);
    let (io, aborted) = hooked(a);
    let (mut sender, mut receiver) = HttpDatagramSession::with_config(io, config()).split();
    sender.start_capsule(header(0x4242, 4)).await.unwrap();
    raw.write_all(b"\x2a\x21").await.unwrap();
    assert!(matches!(
        receiver.recv().await,
        Err(SessionError::Malformed(_))
    ));
    assert_eq!(aborted.load(Ordering::Relaxed), 1);
    // The partial sender is dropped after the carrier already aborted.
    drop(sender);
    assert_eq!(aborted.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn aborts_wake_the_latest_receiver_task() {
    let (local, _peer) = pair();
    let (mut sender, mut receiver) = local.split();
    sender.start_capsule(header(0x4242, 4)).await.unwrap();
    let first = Arc::new(CountWakes::default());
    let latest = Arc::new(CountWakes::default());
    let first_waker = Waker::from(first);
    let latest_waker = Waker::from(latest.clone());
    assert!(
        receiver
            .poll_recv(&mut Context::from_waker(&first_waker))
            .is_pending()
    );
    assert!(
        receiver
            .poll_recv(&mut Context::from_waker(&latest_waker))
            .is_pending()
    );
    drop(sender);
    assert!(latest.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        receiver.poll_recv(&mut Context::from_waker(&latest_waker)),
        Poll::Ready(Err(SessionError::Io(_)))
    ));
}

#[tokio::test]
async fn aborts_wake_a_pending_close() {
    let (a, mut raw) = tokio::io::duplex(256);
    let io = PendingShutdown {
        inner: a,
        extensions: Extensions::new(),
        polled: Arc::new(AtomicUsize::new(0)),
        allowed: Arc::new(AtomicBool::new(false)),
    };
    let (mut sender, mut receiver) = HttpDatagramSession::with_config(io, config()).split();
    let wakes = Arc::new(CountWakes::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let close = sender.close();
    let mut close = std::pin::pin!(close);
    assert!(close.as_mut().poll(&mut cx).is_pending());
    raw.write_all(b"\x2a\x21").await.unwrap();
    assert!(matches!(
        receiver.recv().await,
        Err(SessionError::Malformed(_))
    ));
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        close.as_mut().poll(&mut cx),
        Poll::Ready(Err(SessionError::Io(_)))
    ));
}

#[tokio::test]
async fn aborts_block_queued_native_events_and_native_sends() {
    let native = FakeNative::default();
    native.0.lock().max = Some(128);
    let (local, _peer) = native_pair(&native);
    let (mut sender, mut receiver) = local.split();
    sender.start_capsule(header(0x4242, 4)).await.unwrap();
    native.push(b"queued");
    drop(sender);
    assert!(matches!(receiver.recv().await, Err(SessionError::Io(_))));
    let (a, mut raw) = tokio::io::duplex(256);
    let io = ServiceInput::new(a);
    io.extensions().insert(NativeDatagrams::new(native.clone()));
    let (mut sender, mut receiver) = HttpDatagramSession::with_config(io, config()).split();
    raw.write_all(b"\x2a\x21").await.unwrap();
    assert!(matches!(
        receiver.recv().await,
        Err(SessionError::Malformed(_))
    ));
    assert!(matches!(
        sender.send_datagram(Bytes::from_static(b"after")).await,
        Err(SessionError::Io(_))
    ));
    assert!(native.0.lock().sent.is_empty());
}

#[tokio::test]
async fn buffers_stay_bounded_after_a_burst() {
    let (client, server) = pair();
    let (mut sender, _client_receiver) = client.split();
    let (_server_sender, mut receiver) = server.split();
    let burst = tokio::spawn(async move {
        for _ in 0..256 {
            sender
                .send_datagram(Bytes::from(vec![9; 64]))
                .await
                .unwrap();
        }
        sender.close().await.unwrap();
        sender.scratch.capacity()
    });
    let mut received = 0;
    while let Some(event) = receiver.recv().await.unwrap() {
        assert!(matches!(event, SessionEvent::Datagram { .. }));
        received += 1;
    }
    assert_eq!(received, 256);
    let scratch = burst.await.unwrap();
    let read = receiver.buf.capacity();
    eprintln!("after 256 capsules: sender scratch {scratch} B, receiver read buffer {read} B");
    assert!(scratch <= CapsuleHeader::MAX_SIZE, "{scratch}");
    // The stream ended: its read chunk is released.
    assert_eq!(read, 0);
}

#[test]
fn session_futures_stay_small() {
    let (mut session, _peer) = pair();
    let send = size_of_val(&session.send_datagram(Bytes::new()));
    let recv = size_of_val(&session.recv());
    let close = size_of_val(&session.close());
    eprintln!("future sizes: send_datagram {send} B, recv {recv} B, close {close} B");
    // Measured 288, 40 and 40 bytes: guards against accidental growth.
    assert!(send <= 384 && recv <= 64 && close <= 64);
}

#[tokio::test]
async fn ended_receivers_keep_no_share_of_delivered_payloads() {
    // A clean end, and a malformed one: the stream stops inside a capsule.
    for tail in [&[][..], &[0x00, 0x10][..]] {
        let (mut raw, io) = tokio::io::duplex(256);
        let mut session = HttpDatagramSession::with_config(ServiceInput::new(io), config());
        raw.write_all(&encode_capsule(CapsuleType::DATAGRAM, b"keep").unwrap())
            .await
            .unwrap();
        raw.write_all(tail).await.unwrap();
        raw.shutdown().await.unwrap();
        let Some(SessionEvent::Datagram { payload, .. }) = session.recv().await.unwrap() else {
            panic!("no datagram");
        };
        let end = session.recv().await;
        assert!(!matches!(end, Ok(Some(_))), "{end:?}");
        // Nothing more is read: neither the read buffer nor the decoder shares the payload.
        assert!(payload.is_unique(), "tail {tail:?}");
    }
}

/// Counts drops of a payload's storage.
struct Owned(Vec<u8>, Arc<AtomicUsize>);

impl AsRef<[u8]> for Owned {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        self.1.fetch_add(1, Ordering::AcqRel);
    }
}

fn owned(len: usize, dropped: &Arc<AtomicUsize>) -> Bytes {
    Bytes::from_owner(Owned(vec![7; len], dropped.clone()))
}

#[tokio::test]
async fn sent_payloads_are_released_once_written() {
    for mode in ["capsule", "streamed", "datagram"] {
        let (mut session, mut peer) = pair();
        let dropped = Arc::new(AtomicUsize::new(0));
        match mode {
            "capsule" => session.send_capsule(CONTROL, owned(32, &dropped)).await,
            "streamed" => {
                session
                    .start_capsule(CapsuleHeader::new(CONTROL, 32).unwrap())
                    .await
                    .unwrap();
                session.send_capsule_data(owned(32, &dropped)).await
            }
            _ => session.send_datagram(owned(32, &dropped)).await.map(drop),
        }
        .unwrap();
        assert_eq!(
            dropped.load(Ordering::Acquire),
            1,
            "{mode}: kept after writing"
        );
        session.close().await.unwrap();
        assert_eq!(dropped.load(Ordering::Acquire), 1, "{mode}");
        assert!(peer.recv().await.unwrap().is_some(), "{mode}");
        assert_eq!(peer.recv().await.unwrap(), None, "{mode}");
    }
}

#[tokio::test]
async fn failed_sends_release_accepted_payloads() {
    let io = FailsOnce {
        read_failed: false,
        write_failed: false,
        extensions: Extensions::new(),
    };
    let mut session = HttpDatagramSession::with_config(io, config());
    let dropped = Arc::new(AtomicUsize::new(0));
    let error = session
        .send_capsule(CONTROL, owned(32, &dropped))
        .await
        .unwrap_err();
    assert!(matches!(&error, SessionError::Io(error) if error.kind() == io::ErrorKind::BrokenPipe));
    // Sending is over for good: the accepted payload is gone while the session lives on.
    assert_eq!(dropped.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn cancelled_sends_keep_their_accepted_payload_until_written() {
    // Room for less than one capsule until the peer reads.
    let (a, mut b) = tokio::io::duplex(8);
    let mut session = HttpDatagramSession::with_config(ServiceInput::new(a), config());
    let dropped = Arc::new(AtomicUsize::new(0));
    {
        let send = session.send_capsule(CONTROL, owned(32, &dropped));
        tokio::pin!(send);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(send.as_mut().poll(&mut cx).is_pending());
    }
    // Accepted but unwritten: it is still owned, to be written by the next operation.
    assert_eq!(dropped.load(Ordering::Acquire), 0);
    let reader = tokio::spawn(async move {
        let mut wire = Vec::new();
        b.read_to_end(&mut wire).await.unwrap();
        wire
    });
    session.close().await.unwrap();
    drop(session);
    let wire = reader.await.unwrap();
    assert_eq!(wire, encode_capsule(CONTROL, &[7; 32]).unwrap());
    assert_eq!(dropped.load(Ordering::Acquire), 1);
}
