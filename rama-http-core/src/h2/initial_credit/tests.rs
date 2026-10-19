use super::*;
use crate::h2::{client, server};
use rama_core::{
    ServiceInput, bytes::Bytes, extensions::ExtensionsRef, rt::Executor, service::service_fn,
};
use rama_http::{Body, Response};
use rama_http_types::{Request, proto::h2::frame::Reason};
use std::{
    convert::Infallible,
    future::{Future as _, poll_fn},
    io,
    pin::Pin,
    sync::{
        Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Poll, Wake, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn bind_source(observer: &PeerInitialCredit) -> Source {
    let extensions = Extensions::new();
    extensions.insert(observer.clone());
    Bindings::bind(&extensions).unwrap().source.unwrap()
}

fn bind_target(observer: &PeerInitialCredit) -> Target {
    let extensions = Extensions::new();
    extensions.insert(observer.try_receive_target(MAX_WINDOW_SIZE).unwrap());
    Bindings::bind(&extensions).unwrap().target.unwrap()
}

#[tokio::test]
async fn initial_credit_wakes_idle_target_for_growth_completion_and_failure() {
    for fail in [false, true] {
        let observer = PeerInitialCredit::new();
        let mut source = bind_source(&observer);
        let mut target = bind_target(&observer);
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let cx = Context::from_waker(&waker);
        assert_eq!(target.pending(&cx).unwrap(), None);
        let notification = source.increment(1);
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            0,
            "publication must not wake under caller locks"
        );
        notification.dispatch();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert_eq!(target.pending(&cx).unwrap(), Some((65536, 1)));
        // Re-polling without committing must retain the exact same credit.
        assert_eq!(target.pending(&cx).unwrap(), Some((65536, 1)));
        target.committed(65536);
        assert_eq!(target.pending(&cx).unwrap(), None);
        if fail {
            source.data_committed(1);
            source.increment(2).dispatch();
            assert_eq!(
                observer.complete().await,
                Err(Failure::DataCreditBeforeInitialHeaders)
            );
            target.pending(&cx).unwrap_err();
        } else {
            source.data_committed(0);
            source.headers(true).dispatch();
            assert_eq!(observer.complete().await, Ok(65536));
            assert_eq!(target.pending(&cx).unwrap(), None);
        }
        assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
    }
    // A terminal update before interest registration must also be visible.
    let observer = PeerInitialCredit::new();
    let source = bind_source(&observer);
    let target = bind_target(&observer);
    source.fail(Failure::NativeError).dispatch();
    target
        .pending(&Context::from_waker(Waker::noop()))
        .unwrap_err();
}

#[tokio::test]
async fn initial_credit_owners_close_without_retaining_connections_or_rebinding() {
    let observer = PeerInitialCredit::new();
    let source = bind_source(&observer);
    let target = bind_target(&observer);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    assert_eq!(target.pending(&Context::from_waker(&waker)).unwrap(), None);
    drop(target);
    drop(source);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        observer.complete().await,
        Err(Failure::ClosedBeforeInitialHeaders)
    );
    let ext = Extensions::new();
    ext.insert(observer.clone());
    Bindings::bind(&ext).unwrap_err();
    let ext = Extensions::new();
    ext.insert(observer.try_receive_target(MAX_WINDOW_SIZE).unwrap());
    Bindings::bind(&ext).unwrap_err();
    let isolated = PeerInitialCredit::new();
    let source = bind_source(&isolated);
    source.headers(true).dispatch();
    drop(source);
    assert_eq!(isolated.complete().await, Ok(65535));
    assert_eq!(
        observer.complete().await,
        Err(Failure::ClosedBeforeInitialHeaders)
    );
}

async fn frame(io: &mut DuplexStream, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    let length = payload.len() as u32;
    let mut head = [0; 9];
    head[..3].copy_from_slice(&length.to_be_bytes()[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..].copy_from_slice(&stream.to_be_bytes());
    io.write_all(&head).await.unwrap();
    io.write_all(payload).await.unwrap();
}

async fn next_frame(io: &mut DuplexStream) -> (u8, u8, u32, Vec<u8>) {
    let mut head = [0; 9];
    io.read_exact(&mut head).await.unwrap();
    let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let stream = u32::from_be_bytes(head[5..].try_into().unwrap()) & 0x7fff_ffff;
    let mut body = vec![0; length];
    io.read_exact(&mut body).await.unwrap();
    (head[3], head[4], stream, body)
}

async fn client_preface(io: &mut DuplexStream) {
    let mut preface = [0; 24];
    io.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let first = next_frame(io).await;
    assert_eq!((first.0, first.1, first.2), (4, 0, 0));
    frame(io, 4, 0, 0, &[]).await;
    frame(io, 4, 1, 0, &[]).await;
}

async fn until(io: &mut DuplexStream, kind: u8, stream: u32) -> (u8, Vec<u8>) {
    loop {
        let next = next_frame(io).await;
        if next.0 == kind && next.2 == stream {
            return (next.1, next.3);
        }
    }
}

#[tokio::test]
async fn initial_credit_actual_peer_split_headers_freezes_before_later_update() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let observer = PeerInitialCredit::new();
        let (io, mut peer) = tokio::io::duplex(8192);
        let io = ServiceInput::new(io);
        io.extensions().insert(observer.clone());
        let (mut sender, connection) = client::Builder::new()
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let task = tokio::spawn(connection);
        let request = Request::builder()
            .uri("https://example.test/")
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        client_preface(&mut peer).await;
        until(&mut peer, 1, 1).await;
        frame(&mut peer, 8, 0, 0, &1_u32.to_be_bytes()).await;
        // The response status is valid HPACK static index8; CONTINUATION completes
        // its block. A WINDOW_UPDATE in the same write after it is outside prefix.
        frame(&mut peer, 1, 1, 1, &[0x88]).await;
        frame(&mut peer, 9, 4, 1, &[]).await;
        frame(&mut peer, 8, 0, 0, &7_u32.to_be_bytes()).await;
        assert_eq!(observer.complete().await, Ok(65536));
        assert_eq!(response.await.unwrap().status(), 200);
        assert_eq!(observer.snapshot(), Status::Complete { target: 65536 });
        task.abort();
        let _result = task.await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn initial_credit_post_first_ambiguity_does_not_fail_ordinary_source() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let observer = PeerInitialCredit::new();
        let (io, mut peer) = tokio::io::duplex(8192);
        let io = ServiceInput::new(io);
        io.extensions().insert(observer.clone());
        let (mut sender, connection) = client::Builder::new()
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let task = tokio::spawn(connection);
        let request = Request::builder()
            .method("POST")
            .uri("https://example.test/")
            .body(())
            .unwrap();
        let (response, mut body) = sender.send_request(request, false).unwrap();
        body.send_data(Bytes::from_static(b"x"), true).unwrap();
        client_preface(&mut peer).await;
        assert_eq!(until(&mut peer, 0, 1).await.1, b"x");
        let changed = observer.state.complete.notified();
        let mut changed = std::pin::pin!(changed);
        changed.as_mut().enable();
        frame(&mut peer, 8, 0, 0, &1_u32.to_be_bytes()).await;
        changed.await;
        assert_eq!(
            observer.snapshot(),
            Status::Failed {
                target: 65_535,
                reason: Failure::DataCreditBeforeInitialHeaders,
            },
            "actual emitted POST DATA must make the next validated credit ambiguous",
        );
        assert_eq!(
            observer.complete().await,
            Err(Failure::DataCreditBeforeInitialHeaders)
        );
        frame(&mut peer, 1, 5, 1, &[0x88]).await;
        assert_eq!(response.await.unwrap().status(), 200);
        assert!(
            !task.is_finished(),
            "observation ambiguity must not terminate ordinary source"
        );
        task.abort();
        let _result = task.await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn initial_credit_small_target_changes_real_receive_flow_not_only_wire_bytes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let observer = PeerInitialCredit::new();
        let source = bind_source(&observer);
        let (io, mut peer) = tokio::io::duplex(256 * 1024);
        let io = ServiceInput::new(io);
        io.extensions()
            .insert(observer.try_receive_target(MAX_WINDOW_SIZE).unwrap());
        let mut builder = client::Builder::new();
        builder.set_initial_connection_window_size(65535);
        builder.set_initial_window_size(200000);
        let (mut sender, connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
        let task = tokio::spawn(connection);
        let request = Request::builder()
            .uri("https://example.test/")
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        client_preface(&mut peer).await;
        until(&mut peer, 1, 1).await;
        source.increment(1).dispatch();
        source.headers(true).dispatch();
        let update = until(&mut peer, 8, 0).await;
        assert_eq!(update.1, 1_u32.to_be_bytes());
        frame(&mut peer, 1, 4, 1, &[0x88]).await;
        for _ in 0..4 {
            frame(&mut peer, 0, 0, 1, &vec![b'x'; 16384]).await;
        }
        // Capacity is intentionally not released: the next byte is over credit.
        let mut body = response.await.unwrap().into_body();
        let mut accepted = 0;
        while accepted < 65536 {
            accepted += body.data().await.unwrap().unwrap().len();
        }
        assert_eq!(accepted, 65536);
        frame(&mut peer, 0, 1, 1, b"x").await;
        let error = loop {
            match body.data().await {
                Some(Ok(bytes)) => accepted += bytes.len(),
                Some(Err(error)) => break error,
                None => panic!("over-credit DATA must fail native receive flow"),
            }
        };
        assert_eq!(accepted, 65536);
        assert_eq!(error.reason(), Some(Reason::FLOW_CONTROL_ERROR));
        let _result = task.await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn initial_credit_refused_headers_cannot_complete_and_source_still_answers_ping() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let observer = PeerInitialCredit::new();
        let (mut peer, io) = tokio::io::duplex(8192);
        let io = ServiceInput::new(io);
        io.extensions().insert(observer.clone());
        let mut builder = server::Builder::new();
        builder.set_max_concurrent_streams(0);
        let task = tokio::spawn(async move {
            let mut connection = builder.handshake::<_, Bytes>(io).await.unwrap();
            while let Some(request) = connection.accept().await {
                let _request = request.unwrap();
            }
        });
        peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        frame(&mut peer, 4, 0, 0, &[]).await;
        frame(&mut peer, 8, 0, 0, &1_u32.to_be_bytes()).await;
        // GET/http/"/"/authority=example.test; no Rama encoder participates.
        let mut fields = vec![0x82, 0x86, 0x84, 0x01, 12];
        fields.extend_from_slice(b"example.test");
        frame(&mut peer, 1, 5, 1, &fields).await;
        assert_eq!(
            observer.complete().await,
            Err(Failure::InitialHeadersNotAccepted)
        );
        frame(&mut peer, 6, 0, 0, b"12345678").await;
        assert_eq!(until(&mut peer, 6, 0).await, (1, b"12345678".to_vec()));
        assert_eq!(
            observer.snapshot(),
            Status::Failed {
                target: 65536,
                reason: Failure::InitialHeadersNotAccepted
            }
        );
        task.abort();
        let _result = task.await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn initial_credit_target_conflicts_fail_before_any_client_output() {
    for window in [65534, 65536] {
        let observer = PeerInitialCredit::new();
        let (io, mut peer) = tokio::io::duplex(8192);
        let io = ServiceInput::new(io);
        io.extensions()
            .insert(observer.try_receive_target(MAX_WINDOW_SIZE).unwrap());
        let mut builder = client::Builder::new();
        builder.set_initial_connection_window_size(window);
        builder.handshake::<_, Bytes>(io).await.unwrap_err();
        let mut first = [0];
        assert_eq!(peer.read(&mut first).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn initial_credit_cancelled_native_handshakes_publish_incomplete() {
    let observer = PeerInitialCredit::new();
    let (_peer, io) = tokio::io::duplex(8);
    let io = ServiceInput::new(io);
    io.extensions().insert(observer.clone());
    let handshake = server::Builder::new().handshake::<_, Bytes>(io);
    assert_eq!(observer.snapshot(), Status::Observing { target: 65535 });
    drop(handshake);
    assert_eq!(
        observer.complete().await,
        Err(Failure::ClosedBeforeInitialHeaders)
    );

    let observer = PeerInitialCredit::new();
    let (_peer, io) = tokio::io::duplex(8);
    let io = ServiceInput::new(io);
    io.extensions().insert(observer.clone());
    let builder = client::Builder::new();
    let mut handshake = Box::pin(builder.handshake::<_, Bytes>(io));
    poll_fn(|cx| {
        assert!(handshake.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(observer.snapshot(), Status::Observing { target: 65535 });
    drop(handshake);
    assert_eq!(
        observer.complete().await,
        Err(Failure::ClosedBeforeInitialHeaders)
    );
}

#[tokio::test]
async fn initial_credit_invalid_connection_updates_never_publish_credit() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for (increment, after_data) in [(0_u32, false), (0x7fff_ffff, false), (0x7fff_ffff, true)] {
            let observer = PeerInitialCredit::new();
            let (io, mut peer) = tokio::io::duplex(8192);
            let io = ServiceInput::new(io);
            io.extensions().insert(observer.clone());
            let (mut sender, connection) = client::Builder::new()
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let task = tokio::spawn(connection);
            let _held_response = if after_data {
                let request = Request::builder()
                    .method("POST")
                    .uri("https://example.test/")
                    .body(())
                    .unwrap();
                let (response, mut body) = sender.send_request(request, false).unwrap();
                body.send_data(Bytes::from_static(b"x"), true).unwrap();
                Some(response)
            } else {
                None
            };
            client_preface(&mut peer).await;
            if after_data {
                assert_eq!(until(&mut peer, 0, 1).await.1, b"x");
            }
            frame(&mut peer, 8, 0, 0, &increment.to_be_bytes()).await;
            assert_eq!(observer.complete().await, Err(Failure::NativeError));
            assert_eq!(
                observer.snapshot(),
                Status::Failed {
                    target: 65535,
                    reason: Failure::NativeError
                }
            );
            // Drain the local GOAWAY so driver shutdown is not backpressured.
            let _goaway = until(&mut peer, 7, 0).await;
            let error = task.await.unwrap().unwrap_err();
            assert_eq!(
                error.reason(),
                Some(if increment == 0 {
                    Reason::PROTOCOL_ERROR
                } else {
                    Reason::FLOW_CONTROL_ERROR
                })
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn initial_credit_rejected_first_headers_cannot_be_replaced_by_later_response() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let observer = PeerInitialCredit::new();
        let (io, mut peer) = tokio::io::duplex(8192);
        let io = ServiceInput::new(io);
        io.extensions().insert(observer.clone());
        let (mut sender, connection) = client::Builder::new()
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let task = tokio::spawn(connection);
        let request = Request::builder()
            .uri("https://example.test/")
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        client_preface(&mut peer).await;
        until(&mut peer, 1, 1).await;
        // A response must have :status, not the request pseudo :method GET.
        frame(&mut peer, 1, 5, 1, &[0x82]).await;
        response.await.unwrap_err();
        assert!(matches!(
            observer.complete().await,
            Err(Failure::InitialHeadersNotAccepted | Failure::NativeError)
        ));
        let request = Request::builder()
            .uri("https://example.test/next")
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        until(&mut peer, 1, 3).await;
        frame(&mut peer, 1, 5, 3, &[0x88]).await;
        assert_eq!(response.await.unwrap().status(), 200);
        assert!(matches!(observer.snapshot(), Status::Failed { .. }));
        task.abort();
        let _result = task.await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn initial_credit_server_target_changes_actual_receive_flow() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let observer = PeerInitialCredit::new();
        let source = bind_source(&observer);
        let (mut peer, io) = tokio::io::duplex(256 * 1024);
        let io = ServiceInput::new(io);
        io.extensions()
            .insert(observer.try_receive_target(MAX_WINDOW_SIZE).unwrap());
        let mut builder = server::Builder::new();
        builder.set_initial_connection_window_size(65535);
        builder.set_initial_window_size(200000);
        let (allowed_tx, allowed_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connection = builder.handshake::<_, Bytes>(io).await.unwrap();
            let (request, _response) = connection.accept().await.unwrap().unwrap();
            let receive = async move {
                let mut body = request.into_body();
                let mut accepted = 0;
                while accepted < 65536 {
                    accepted += body.data().await.unwrap().unwrap().len();
                }
                allowed_tx.send(accepted).unwrap();
                let error = body.data().await.unwrap().unwrap_err();
                assert_eq!(error.reason(), Some(Reason::FLOW_CONTROL_ERROR));
                accepted
            };
            let drive = poll_fn(|cx| connection.poll_closed(cx));
            let (accepted, result) = tokio::join!(receive, drive);
            assert_eq!(
                result.unwrap_err().reason(),
                Some(Reason::FLOW_CONTROL_ERROR)
            );
            accepted
        });
        peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        frame(&mut peer, 4, 0, 0, &[]).await;
        until(&mut peer, 4, 0).await;
        frame(&mut peer, 4, 1, 0, &[]).await;
        source.increment(1).dispatch();
        source.headers(true).dispatch();
        assert_eq!(until(&mut peer, 8, 0).await.1, 1_u32.to_be_bytes());
        let mut fields = vec![0x83, 0x86, 0x84, 0x01, 12];
        fields.extend_from_slice(b"example.test");
        frame(&mut peer, 1, 4, 1, &fields).await;
        for _ in 0..4 {
            frame(&mut peer, 0, 0, 1, &vec![b'x'; 16384]).await;
        }
        assert_eq!(allowed_rx.await.unwrap(), 65536);
        frame(&mut peer, 0, 1, 1, b"x").await;
        until(&mut peer, 7, 0).await;
        assert_eq!(task.await.unwrap(), 65536);
    })
    .await
    .unwrap();
}

#[test]
fn initial_credit_binding_and_conflicts_are_opt_in_and_connection_local() {
    let empty = Bindings::bind(&Extensions::new()).unwrap();
    assert!(empty.source.is_none() && empty.target.is_none());
    let observer = PeerInitialCredit::new();
    let ext = Extensions::new();
    ext.insert(observer.clone());
    ext.insert(observer.try_receive_target(MAX_WINDOW_SIZE).unwrap());
    Bindings::bind(&ext).unwrap_err();
    assert_eq!(observer.snapshot(), Status::Unbound);
    let target = Extensions::new();
    target.insert(observer.try_receive_target(MAX_WINDOW_SIZE).unwrap());
    validate_adaptive(&target, true).unwrap_err();
    validate_adaptive(&target, false).unwrap();
    validate_receive_config(&target, Some(65535), true).unwrap_err();
    validate_receive_config(&target, None, false).unwrap();
    validate_receive_config(&target, Some(65535), false).unwrap();
    validate_adaptive(&Extensions::new(), true).unwrap();
    validate_receive_config(&Extensions::new(), Some(1000000), true).unwrap();
}

#[derive(Default)]
struct Gate {
    blocked: AtomicBool,
    blocked_write: Notify,
    attempts: AtomicUsize,
    writer: Mutex<Option<Waker>>,
}

impl Gate {
    fn open(&self) {
        self.blocked.store(false, Ordering::SeqCst);
        let wake = self.writer.lock().take();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}

struct WriteGate {
    io: DuplexStream,
    gate: Arc<Gate>,
}

impl AsyncRead for WriteGate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for WriteGate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        {
            let mut wake = self.gate.writer.lock();
            if self.gate.blocked.load(Ordering::SeqCst) {
                *wake = Some(cx.waker().clone());
                drop(wake);
                self.gate.attempts.fetch_add(1, Ordering::SeqCst);
                self.gate.blocked_write.notify_one();
                return Poll::Pending;
            }
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn initial_credit_codec_backpressure_retries_once_and_terminal_failure_wakes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for outcome in 0..3 {
            let observer = PeerInitialCredit::new();
            let source = bind_source(&observer);
            let (io, mut peer) = tokio::io::duplex(64 * 1024);
            let gate = Arc::new(Gate::default());
            let io = ServiceInput::new(WriteGate {
                io,
                gate: gate.clone(),
            });
            io.extensions().insert(
                observer
                    .try_receive_target(if outcome == 2 {
                        65_536
                    } else {
                        MAX_WINDOW_SIZE
                    })
                    .unwrap(),
            );
            let (mut sender, connection) = client::Builder::new()
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let task = tokio::spawn(connection);
            let request = Request::builder()
                .method("POST")
                .uri("https://example.test/")
                .body(())
                .unwrap();
            let (_response, mut body) = sender.send_request(request, false).unwrap();
            client_preface(&mut peer).await;
            until(&mut peer, 1, 1).await;
            gate.blocked.store(true, Ordering::SeqCst);
            // Large DATA uses the codec's chained frame slot. A blocked write
            // therefore makes its next poll_ready genuinely Pending/CodecFull.
            body.send_data(Bytes::from(vec![b'x'; 16384]), true)
                .unwrap();
            gate.blocked_write.notified().await;
            let attempts = gate.attempts.load(Ordering::SeqCst);
            source.increment(1).dispatch();
            source.increment(2).dispatch();
            // Observe a new driver attempt after the credit publication; an old
            // Notify permit is not evidence of a current blocked-write retry.
            while outcome != 2 && gate.attempts.load(Ordering::SeqCst) == attempts {
                gate.blocked_write.notified().await;
            }
            if outcome != 0 {
                if outcome == 1 {
                    source.fail(Failure::NativeError).dispatch();
                }
                let error = task.await.unwrap().unwrap_err();
                assert!(error.to_string().contains(if outcome == 1 {
                    "initial connection credit source unavailable"
                } else {
                    "initial connection credit 65538 exceeds receive maximum 65536"
                }));
                assert!(observer.state.inner.lock().target_waker.is_none());
                if outcome == 2 {
                    source.headers(true).dispatch();
                    assert_eq!(observer.complete().await, Ok(65_538));
                }
                // The target must have failed before this test releases writes.
                gate.open();
            } else {
                gate.open();
                assert_eq!(until(&mut peer, 0, 1).await.1.len(), 16384);
                assert_eq!(until(&mut peer, 8, 0).await.1, 3_u32.to_be_bytes());
                frame(&mut peer, 6, 0, 0, b"creditOK").await;
                let mut additional_updates = 0;
                loop {
                    let next = next_frame(&mut peer).await;
                    if next.0 == 8 && next.2 == 0 {
                        additional_updates += 1;
                    }
                    if next.0 == 6 && next.1 == 1 {
                        assert_eq!(next.3, b"creditOK");
                        break;
                    }
                }
                assert_eq!(
                    additional_updates, 0,
                    "CodecFull retries must not duplicate target credit"
                );
                source.headers(true).dispatch();
                task.abort();
                let _result = task.await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn initial_credit_failed_opposite_setup_leaves_unbound_fact_and_cancels_native_target() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let downstream = PeerInitialCredit::new();
        let upstream = PeerInitialCredit::new();
        let (io, _peer) = tokio::io::duplex(8192);
        let io = ServiceInput::new(io);
        io.extensions().insert(upstream.clone());
        io.extensions()
            .insert(downstream.try_receive_target(MAX_WINDOW_SIZE).unwrap());
        let (_sender, connection) = client::Builder::new()
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let mut connection = Box::pin(connection);
        poll_fn(|cx| {
            assert!(connection.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(downstream.state.inner.lock().target_waker.is_some());
        assert_eq!(downstream.snapshot(), Status::Unbound);

        let (io, mut peer) = tokio::io::duplex(8192);
        let io = ServiceInput::new(io);
        io.extensions().insert(downstream.clone());
        io.extensions()
            .insert(upstream.try_receive_target(MAX_WINDOW_SIZE).unwrap());
        let service = service_fn(|_: Request<crate::body::Incoming>| {
            std::future::ready(Ok::<_, Infallible>(Response::new(Body::empty())))
        });
        // Adaptive=true must fail before claiming the second native source or
        // emitting SETTINGS. This exercises the actual high server adapter.
        let builder = crate::server::conn::http2::Builder::new(Executor::default())
            .with_adaptive_window(true);
        let mut setup = Box::pin(builder.serve_connection(io, service));
        poll_fn(|cx| {
            assert!(
                matches!(setup.as_mut().poll(cx), Poll::Ready(Err(_))),
                "adaptive receive policy must reject setup before waiting for peer I/O"
            );
            Poll::Ready(())
        })
        .await;
        drop(setup);
        let mut first = [0];
        assert_eq!(peer.read(&mut first).await.unwrap(), 0);
        assert_eq!(downstream.snapshot(), Status::Unbound);
        // Setup ownership cancels the already-built native leg. The API must
        // not fabricate a closed source fact for the never-bound opposite IO.
        drop(connection);
        assert_eq!(
            upstream.complete().await,
            Err(Failure::ClosedBeforeInitialHeaders)
        );
        assert!(downstream.state.inner.lock().target_waker.is_none());
        assert_eq!(downstream.snapshot(), Status::Unbound);
    })
    .await
    .unwrap();
}

struct CellProbeWake {
    state: Weak<State>,
    calls: AtomicUsize,
}

impl Wake for CellProbeWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let state = self.state.upgrade().unwrap();
        assert!(
            state.inner.try_lock().is_some(),
            "foreign initial-credit wake must run after releasing the credit-cell lock"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn initial_credit_target_and_observer_wakes_run_after_cell_unlock() {
    for complete in [false, true] {
        let observer = PeerInitialCredit::new();
        let source = bind_source(&observer);
        let mut target = bind_target(&observer);
        let probe = Arc::new(CellProbeWake {
            state: Arc::downgrade(&observer.state),
            calls: AtomicUsize::new(0),
        });
        let waker = Waker::from(probe.clone());
        let mut cx = Context::from_waker(&waker);
        let completion = observer.complete();
        let mut completion = std::pin::pin!(completion);
        assert!(completion.as_mut().poll(&mut cx).is_pending());
        assert_eq!(target.pending(&cx).unwrap(), None);
        let notification = source.increment(1);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        notification.dispatch();
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
        assert!(completion.as_mut().poll(&mut cx).is_pending());
        assert_eq!(target.pending(&cx).unwrap(), Some((65_536, 1)));
        target.committed(65_536);
        let notification = if complete {
            source.headers(true)
        } else {
            source.fail(Failure::NativeError)
        };
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
        notification.dispatch();
        assert_eq!(probe.calls.load(Ordering::SeqCst), 4);
        assert_eq!(
            completion.as_mut().poll(&mut cx),
            Poll::Ready(if complete {
                Ok(65_536)
            } else {
                Err(Failure::NativeError)
            })
        );
        drop(source);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 4);
    }
}

#[tokio::test]
async fn initial_credit_terminal_driver_clears_interest_while_future_is_retained() {
    let observer = PeerInitialCredit::new();
    let source = bind_source(&observer);
    let (io, peer) = tokio::io::duplex(8192);
    let io = ServiceInput::new(io);
    io.extensions()
        .insert(observer.try_receive_target(MAX_WINDOW_SIZE).unwrap());
    let (sender, connection) = client::Builder::new()
        .handshake::<_, Bytes>(io)
        .await
        .unwrap();
    let mut connection = Box::pin(connection);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes);
    let mut cx = Context::from_waker(&waker);
    assert!(connection.as_mut().poll(&mut cx).is_pending());
    assert!(observer.state.inner.lock().target_waker.is_some());
    // The paired source remains live/Observing. EOF belongs to this destination
    // connection and therefore cannot take the paired source's stored interest.
    drop(peer);
    assert!(connection.as_mut().poll(&mut cx).is_ready());
    assert_eq!(observer.snapshot(), Status::Observing { target: 65_535 });
    assert!(
        observer.state.inner.lock().target_waker.is_none(),
        "terminal driver must clear foreign interest before future/dispatcher disposal"
    );
    // Keep both the completed future and the cloned native stream owner alive
    // until after the assertion: Drop cannot mask missing terminal cleanup.
    drop(sender);
    drop(connection);
    drop(source);
}

#[test]
fn initial_credit_receive_limit_requires_an_explicit_valid_protocol_budget() {
    let observer = PeerInitialCredit::new();
    for maximum in [0, 65_534, MAX_WINDOW_SIZE + 1, u32::MAX] {
        let error = observer.try_receive_target(maximum).unwrap_err();
        assert_eq!(error.reason(), None);
        assert_eq!(observer.snapshot(), Status::Unbound);
    }
    // Lowest legal budget accepts the mandatory initial window, then refuses
    // genuine source growth rather than silently clamping its valid fact.
    let source = bind_source(&observer);
    let extensions = Extensions::new();
    extensions.insert(observer.try_receive_target(65_535).unwrap());
    let target = Bindings::bind(&extensions).unwrap().target.unwrap();
    let cx = Context::from_waker(Waker::noop());
    assert_eq!(target.pending(&cx).unwrap(), None);
    source.increment(1).dispatch();
    assert!(matches!(
        target.pending(&cx),
        Err(Error::User(UserError::InitialCreditLimitExceeded {
            target: 65_536,
            maximum: 65_535
        }))
    ));
    assert_eq!(target.applied, 65_535);
    source.headers(true).dispatch();
    assert_eq!(observer.snapshot(), Status::Complete { target: 65_536 });
}

#[tokio::test]
async fn initial_credit_actual_source_limit_rejects_before_native_target_output() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for prior_growth in [false, true] {
            let observer = PeerInitialCredit::new();
            let (io, mut source_peer) = tokio::io::duplex(8192);
            let io = ServiceInput::new(io);
            io.extensions().insert(observer.clone());
            let (mut source_sender, source_connection) = client::Builder::new()
                .handshake::<_, Bytes>(io)
                .await
                .unwrap();
            let source_driver = tokio::spawn(source_connection);
            let request = Request::builder()
                .uri("https://example.test/")
                .body(())
                .unwrap();
            let (source_response, _) = source_sender.send_request(request, true).unwrap();
            client_preface(&mut source_peer).await;
            until(&mut source_peer, 1, 1).await;

            let (io, mut target_peer) = tokio::io::duplex(8192);
            let io = ServiceInput::new(io);
            io.extensions()
                .insert(observer.try_receive_target(65_536).unwrap());
            let mut builder = client::Builder::new();
            builder.set_initial_connection_window_size(65_535);
            let (mut target_sender, target_connection) =
                builder.handshake::<_, Bytes>(io).await.unwrap();
            let mut target_connection = Box::pin(target_connection);
            let request = Request::builder()
                .uri("https://example.test/")
                .body(())
                .unwrap();
            let (_response, _) = target_sender.send_request(request, true).unwrap();
            let mut cx = Context::from_waker(Waker::noop());
            assert!(target_connection.as_mut().poll(&mut cx).is_pending());
            client_preface(&mut target_peer).await;
            assert!(target_connection.as_mut().poll(&mut cx).is_pending());
            until(&mut target_peer, 1, 1).await;

            if prior_growth {
                // Register before publishing, so no scheduler delay or saved
                // permit can masquerade as the actual source's first growth.
                let changed = observer.state.complete.notified();
                let mut changed = std::pin::pin!(changed);
                changed.as_mut().enable();
                frame(&mut source_peer, 8, 0, 0, &1_u32.to_be_bytes()).await;
                changed.await;
                assert_eq!(observer.snapshot(), Status::Observing { target: 65_536 });
                assert!(target_connection.as_mut().poll(&mut cx).is_pending());
                assert_eq!(until(&mut target_peer, 8, 0).await.1, 1_u32.to_be_bytes());
            }
            // Both source totals are protocol-valid: either2 at once, or1 after
            // an accepted1. The destination's separate explicit budget is65536.
            frame(
                &mut source_peer,
                8,
                0,
                0,
                &(if prior_growth { 1_u32 } else { 2_u32 }).to_be_bytes(),
            )
            .await;
            frame(&mut source_peer, 1, 5, 1, &[0x88]).await;
            assert_eq!(source_response.await.unwrap().status(), 200);
            assert_eq!(observer.complete().await, Ok(65_537));
            assert!(
                !source_driver.is_finished(),
                "local budget refusal must not fail its source"
            );
            // This is a manually polled real native driver, not a timeout-based
            // rejection oracle. Removing the budget check yields Pending here.
            let error = match target_connection.as_mut().poll(&mut cx) {
                Poll::Ready(Err(error)) => error,
                result => panic!("over-budget native target must fail immediately: {result:?}"),
            };
            assert_eq!(
                error.reason(),
                None,
                "this is local policy, not a remote protocol error"
            );
            assert!(
                error
                    .to_string()
                    .contains("initial connection credit 65537 exceeds receive maximum 65536")
            );
            assert!(observer.state.inner.lock().target_waker.is_none());
            drop(target_sender);
            drop(target_connection);
            let mut remaining = Vec::new();
            target_peer.read_to_end(&mut remaining).await.unwrap();
            let mut offset = 0;
            while offset < remaining.len() {
                assert!(remaining.len() - offset >= 9);
                let head = &remaining[offset..offset + 9];
                let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
                assert!(
                    head[3] != 8 || head[5..9] != [0, 0, 0, 0],
                    "over-budget target must not emit WINDOW_UPDATE, even a clamped one"
                );
                offset += 9 + length;
                assert!(offset <= remaining.len());
            }
            source_driver.abort();
            let _result = source_driver.await;
        }
    })
    .await
    .unwrap();
}
