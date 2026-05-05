use super::*;
use crate::tproxy::{TransparentProxyConfig, TransparentProxyFlowProtocol};
use parking_lot::Mutex;
use rama_core::{
    bytes::Bytes,
    error::BoxError,
    service::{BoxService, service_fn},
};
use rama_net::address::HostWithPort;
use std::time::{Duration, Instant};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

type TestTcpService = BoxService<BridgeIo<TcpFlow, NwTcpStream>, (), Infallible>;
type TestUdpService = BoxService<BridgeIo<UdpFlow, NwUdpSocket>, (), Infallible>;

#[derive(Clone)]
struct TestHandler {
    app_message_handler: Arc<dyn Fn(Vec<u8>) -> Option<Vec<u8>> + Send + Sync>,
    tcp_matcher: Arc<dyn Fn(TransparentProxyFlowMeta) -> FlowAction<TestTcpService> + Send + Sync>,
    udp_matcher: Arc<dyn Fn(TransparentProxyFlowMeta) -> FlowAction<TestUdpService> + Send + Sync>,
}

impl TestHandler {
    fn passthrough() -> Self {
        Self {
            app_message_handler: Arc::new(|_| None),
            tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
            udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        }
    }
}

impl TransparentProxyHandler for TestHandler {
    fn transparent_proxy_config(&self) -> crate::tproxy::TransparentProxyConfig {
        TransparentProxyConfig::new()
    }

    fn handle_app_message(
        &self,
        _exec: Executor,
        message: Bytes,
    ) -> impl Future<Output = Option<Bytes>> + Send + '_ {
        let reply = (self.app_message_handler)(message.to_vec()).map(Bytes::from);
        std::future::ready(reply)
    }

    fn match_tcp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<TcpFlow, NwTcpStream>, Output = (), Error = Infallible>,
        >,
    > + Send
    + '_ {
        std::future::ready((self.tcp_matcher)(meta))
    }

    fn match_udp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<UdpFlow, NwUdpSocket>, Output = (), Error = Infallible>,
        >,
    > + Send
    + '_ {
        std::future::ready((self.udp_matcher)(meta))
    }
}

#[derive(Clone)]
struct TestHandlerFactory(TestHandler);

impl TransparentProxyHandlerFactory for TestHandlerFactory {
    type Handler = TestHandler;
    type Error = BoxError;

    fn create_transparent_proxy_handler(
        &self,
        _ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        std::future::ready(Ok(self.0.clone()))
    }
}

#[derive(Clone, Copy, Default)]
struct TestRuntimeFactory;

impl TransparentProxyAsyncRuntimeFactory for TestRuntimeFactory {
    type Error = BoxError;

    fn create_async_runtime(
        self,
        _cfg: Option<&[u8]>,
    ) -> Result<tokio::runtime::Runtime, Self::Error> {
        Ok(tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()?)
    }
}

fn build_engine(handler: TestHandler) -> TransparentProxyEngine<TestHandler> {
    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .build()
        .expect("build engine")
}

fn build_engine_with_tcp_channel_capacity(
    handler: TestHandler,
    capacity: usize,
) -> TransparentProxyEngine<TestHandler> {
    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_tcp_channel_capacity(capacity)
        .build()
        .expect("build engine")
}

#[test]
fn engine_builds_live_and_stop_is_terminal() {
    let engine = build_engine(TestHandler::passthrough());
    engine.stop(0);
}

#[test]
fn tcp_session_passthrough_by_default() {
    let engine = build_engine(TestHandler::passthrough());
    let decision = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Passthrough));
}

#[test]
fn udp_session_passthrough_by_default() {
    let engine = build_engine(TestHandler::passthrough());
    let decision = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Passthrough));
}

#[test]
fn tcp_session_can_be_blocked() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Blocked),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    });
    let decision = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Blocked));
}

#[test]
fn udp_session_can_be_blocked() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|_| FlowAction::Blocked),
    });
    let decision = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Blocked));
}

#[test]
fn tcp_bridge_delivers_server_bytes() {
    let got = Arc::new(Mutex::new(Vec::<u8>::new()));
    let got_clone = got.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|bridge: BridgeIo<TcpFlow, NwTcpStream>| async move {
                let BridgeIo(mut ingress, _egress) = bridge;
                let _ = ingress.write_all(b"pong").await;
                Ok(())
            })
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        move |bytes| {
            let mut lock = got_clone.lock();
            lock.extend_from_slice(&bytes);
            let _ = notify_tx.send(());
            TcpDeliverStatus::Accepted
        },
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    // Phase 2: activate egress (no-op callbacks) so the service task starts.
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    let _ = session.on_client_bytes(b"ping");

    let _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert_eq!(got.lock().as_slice(), b"pong");
}

#[test]
fn udp_bridge_delivers_server_datagram() {
    let got = Arc::new(Mutex::new(Vec::<u8>::new()));
    let got_clone = got.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|bridge: BridgeIo<UdpFlow, NwUdpSocket>| async move {
                let BridgeIo(mut ingress, _egress) = bridge;
                if let Some(datagram) = ingress.recv().await {
                    ingress.send(datagram);
                }
                Ok(())
            })
            .boxed(),
        }),
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::local_ipv4(5353)),
        move |bytes| {
            let mut lock = got_clone.lock();
            lock.extend_from_slice(&bytes);
            let _ = notify_tx.send(());
        },
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    // Phase 2: activate egress so the service task starts.
    session.activate(|_| {});
    session.on_client_datagram(b"ping");

    let _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert_eq!(got.lock().as_slice(), b"ping");
}

#[test]
fn udp_session_requests_client_read_demand() {
    let demand_count = Arc::new(AtomicUsize::new(0));
    let demand_count_clone = demand_count.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|bridge: BridgeIo<UdpFlow, NwUdpSocket>| async move {
                let BridgeIo(mut ingress, _egress) = bridge;
                let _ = ingress.recv().await;
                Ok(())
            })
            .boxed(),
        }),
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        move || {
            demand_count_clone.fetch_add(1, Ordering::Relaxed);
            let _ = notify_tx.send(());
        },
        || {},
    ) else {
        panic!("expected intercept session");
    };

    // Phase 2: activate egress so the service task starts.
    session.activate(|_| {});
    session.on_client_datagram(b"x");

    let _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert!(demand_count.load(Ordering::Relaxed) >= 1);
}

#[test]
fn tcp_flow_exposes_meta_extension() {
    let seen = Arc::new(Mutex::new(None::<Arc<TransparentProxyFlowMeta>>));
    let seen_clone = seen.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let seen_clone = seen_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |bridge: BridgeIo<TcpFlow, NwTcpStream>| {
                    let seen_clone = seen_clone.clone();
                    let notify_tx = notify_tx.clone();
                    async move {
                        let BridgeIo(stream, _egress) = bridge;
                        *seen_clone.lock() =
                            stream.extensions().get_arc::<TransparentProxyFlowMeta>();
                        let _ = notify_tx.send(());
                        Ok(())
                    }
                })
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp).with_source_app_pid(777),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    // Phase 2: activate so the service task runs and reads extensions.
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    let _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert_eq!(
        seen.lock().clone().expect("tcp flow meta").source_app_pid,
        Some(777)
    );
}

#[test]
fn udp_flow_exposes_meta_extension() {
    let seen = Arc::new(Mutex::new(None::<Arc<TransparentProxyFlowMeta>>));
    let seen_clone = seen.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let seen_clone = seen_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |bridge: BridgeIo<UdpFlow, NwUdpSocket>| {
                    let seen_clone = seen_clone.clone();
                    let notify_tx = notify_tx.clone();
                    async move {
                        let BridgeIo(flow, _egress) = bridge;
                        *seen_clone.lock() =
                            flow.extensions().get_arc::<TransparentProxyFlowMeta>();
                        let _ = notify_tx.send(());
                        Ok(())
                    }
                })
                .boxed(),
            }
        }),
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp).with_source_app_pid(888),
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    // Phase 2: activate so the service task runs and reads extensions.
    session.activate(|_| {});
    let _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert_eq!(
        seen.lock().clone().expect("udp flow meta").source_app_pid,
        Some(888)
    );
}

#[test]
fn tcp_cancel_many_idle_sessions_suppresses_callbacks_and_stops_fast() {
    let closed_count = Arc::new(AtomicUsize::new(0));
    let bytes_count = Arc::new(AtomicUsize::new(0));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            // Sessions are cancelled before activate — the service body never runs.
            // The type must still match BridgeIo<TcpFlow, NwTcpStream>.
            service: service_fn(|_: BridgeIo<TcpFlow, NwTcpStream>| async move { Ok(()) }).boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine(handler);

    let mut sessions = Vec::new();
    for _ in 0..512 {
        let closed_count = closed_count.clone();
        let bytes_count = bytes_count.clone();
        let SessionFlowAction::Intercept(session) = engine.new_tcp_session(
            TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
                .with_remote_endpoint(HostWithPort::example_domain_with_port(443)),
            move |_bytes| {
                bytes_count.fetch_add(1, Ordering::Relaxed);
                TcpDeliverStatus::Accepted
            },
            || {},
            move || {
                closed_count.fetch_add(1, Ordering::Relaxed);
            },
        ) else {
            panic!("expected intercept session");
        };
        sessions.push(session);
    }

    for session in &mut sessions {
        session.cancel();
    }

    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(bytes_count.load(Ordering::Relaxed), 0);
    assert_eq!(closed_count.load(Ordering::Relaxed), 0);

    let start = Instant::now();
    engine.stop(0);
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn tcp_on_client_bytes_signals_paused_when_ingress_channel_full() {
    // Without `activate`, the bridge tasks never start, so the channel never
    // drains: any send beyond `tcp_channel_capacity` must come back as
    // `Paused`. This proves `on_client_bytes` is non-blocking and surfaces
    // fullness as a pause signal — the load-bearing property the Swift FFI
    // relies on.
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|_: BridgeIo<TcpFlow, NwTcpStream>| async move { Ok(()) }).boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine_with_tcp_channel_capacity(handler, 2);

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    let chunk = vec![0u8; 16];
    let mut accepted = 0usize;
    let mut paused = 0usize;
    for _ in 0..10 {
        match session.on_client_bytes(&chunk) {
            TcpDeliverStatus::Accepted => accepted += 1,
            TcpDeliverStatus::Paused => paused += 1,
            TcpDeliverStatus::Closed => panic!("unexpected Closed before teardown"),
        }
    }

    assert_eq!(accepted, 2, "channel capacity is 2");
    assert_eq!(paused, 8);

    engine.stop(0);
}

#[test]
fn tcp_demand_callback_fires_after_ingress_channel_drains() {
    // The bridge runs and the service drains the duplex, so the bounded
    // channel transitions from full → empty. After every successful `recv`
    // the bridge swaps `client_paused` and fires `on_client_read_demand`
    // exactly once per pause event. We expect at least one demand callback
    // by the time the service finishes draining.
    let demand_count = Arc::new(AtomicUsize::new(0));
    let demand_count_clone = demand_count.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|bridge: BridgeIo<TcpFlow, NwTcpStream>| async move {
                let BridgeIo(mut ingress, _egress) = bridge;
                let mut buf = vec![0u8; 4096];
                // Slow drain: forces the bounded channel + duplex to back up
                // while the test pumps bytes from another thread.
                loop {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    match ingress.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                Ok(())
            })
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine_with_tcp_channel_capacity(handler, 2);

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        |_| TcpDeliverStatus::Accepted,
        move || {
            demand_count_clone.fetch_add(1, Ordering::Relaxed);
            let _ = notify_tx.send(());
        },
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    // Pump until we hit backpressure. With a slow service and capacity=2 we
    // expect this within a handful of iterations.
    let chunk = vec![0u8; 4096];
    let mut got_paused = false;
    for _ in 0..1000 {
        if matches!(session.on_client_bytes(&chunk), TcpDeliverStatus::Paused) {
            got_paused = true;
            break;
        }
    }
    assert!(got_paused, "expected the bounded channel to fill up");

    // Give the bridge time to drain at least one chunk and fire demand.
    let _ = notify_rx.recv_timeout(Duration::from_secs(2));
    assert!(
        demand_count.load(Ordering::Relaxed) >= 1,
        "demand callback should fire when the bridge frees a slot"
    );

    engine.stop(0);
}

#[test]
fn tcp_bridge_write_failure_closes_ingress_channel() {
    // When the service finishes (and drops its half of the duplex) the
    // bridge's `write_all` fails and we close the receiver. From that point
    // on `on_client_bytes` MUST report `Closed` (not `Paused`) — Swift uses
    // that to terminate the read pump immediately rather than waiting on a
    // demand callback that will never come.
    let (closed_tx, closed_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            // Service exits immediately, dropping its end of the duplex.
            service: service_fn(|_: BridgeIo<TcpFlow, NwTcpStream>| async move { Ok(()) }).boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine_with_tcp_channel_capacity(handler, 2);

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        |_| TcpDeliverStatus::Accepted,
        || {},
        move || {
            let _ = closed_tx.send(());
        },
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    // The service has nothing to do and exits, dropping ingress; the bridge's
    // first `write_all` will fail and close the receiver. Pump bytes until
    // we observe the Closed status.
    let chunk = vec![0u8; 1024];
    let mut saw_closed = false;
    for _ in 0..200 {
        if matches!(session.on_client_bytes(&chunk), TcpDeliverStatus::Closed) {
            saw_closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        saw_closed,
        "on_client_bytes must report Closed after a bridge write failure"
    );

    let _ = closed_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);
}

#[test]
fn tcp_on_bytes_signals_closed_after_session_cancel() {
    // After `cancel()`, the FFI byte-delivery calls MUST surface
    // `Closed` (not `Paused`) so the Swift pumps terminate immediately.
    // Regression: the egress read pump previously dropped the chunk on
    // a nil-session and rescheduled another `connection.receive`, leaving
    // NWConnection traffic alive after the session was gone.
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|_: BridgeIo<TcpFlow, NwTcpStream>| async move { Ok(()) }).boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    session.cancel();

    let chunk = vec![0u8; 16];
    assert_eq!(
        session.on_client_bytes(&chunk),
        TcpDeliverStatus::Closed,
        "on_client_bytes must report Closed after cancel"
    );
    assert_eq!(
        session.on_egress_bytes(&chunk),
        TcpDeliverStatus::Closed,
        "on_egress_bytes must report Closed after cancel — \
         this is the contract the Swift egress read pump relies on to \
         terminate instead of looping on connection.receive forever"
    );

    engine.stop(0);
}

#[test]
fn builder_rejects_zero_channel_capacity() {
    // `tokio::sync::mpsc::channel(0)` panics; an explicit `Some(0)` is
    // treated as a misconfiguration rather than silently substituting the
    // default. `None` continues to mean "use default".
    let make = |tcp: Option<usize>, udp: Option<usize>| {
        let mut builder =
            TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
                .with_runtime_factory(TestRuntimeFactory);
        builder = builder.maybe_with_tcp_channel_capacity(tcp);
        builder = builder.maybe_with_udp_channel_capacity(udp);
        builder.build()
    };

    assert!(make(Some(0), None).is_err(), "Some(0) tcp must error");
    assert!(make(None, Some(0)).is_err(), "Some(0) udp must error");
    let engine = make(None, None).expect("None defaults must build");
    engine.stop(0);
}

/// Pin the load-bearing FFI invariant: when `on_client_bytes` returns
/// `Paused` the bytes are NOT taken by the Rust side, and a caller that
/// retains + replays them sees the full byte stream delivered in order.
///
/// Capacity 1 means every send after the first is `Paused`, so this test
/// hammers the pause/resume path on every chunk. A regression that drops
/// bytes (e.g. discarding the rejected chunk in the `TrySendError::Full`
/// arm — which is exactly the bug that surfaced as `tls: bad record MAC`
/// on large h2 transfers) corrupts the recovered byte sequence and fails
/// the equality check below.
#[test]
fn tcp_byte_stream_preserved_under_ingress_backpressure() {
    let received = Arc::new(Mutex::new(Vec::<u8>::new()));
    let received_clone = received.clone();
    let (eof_tx, eof_rx) = std::sync::mpsc::channel::<()>();
    let eof_tx_handler = Mutex::new(Some(eof_tx));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let received = received_clone.clone();
            let eof_tx = eof_tx_handler.lock().take().expect("single intercept");
            FlowAction::Intercept {
                meta,
                service: service_fn(move |bridge: BridgeIo<TcpFlow, NwTcpStream>| {
                    let received = received.clone();
                    let eof_tx = eof_tx.clone();
                    async move {
                        let BridgeIo(mut ingress, _egress) = bridge;
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match ingress.read(&mut buf).await {
                                Ok(0) | Err(_) => {
                                    let _ = eof_tx.send(());
                                    return Ok(());
                                }
                                Ok(n) => {
                                    received.lock().extend_from_slice(&buf[..n]);
                                }
                            }
                        }
                    }
                })
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };

    let engine = build_engine_with_tcp_channel_capacity(handler, 1);
    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    // Deterministic 4000-byte stream split into 1000 4-byte chunks. Each
    // chunk encodes its own index so any reordering / loss is detectable
    // by inspection if the equality assertion ever fails in the future.
    let mut expected = Vec::with_capacity(4000);
    for i in 0..1000_u16 {
        let chunk = [
            (i >> 8) as u8,
            i as u8,
            i.wrapping_add(0xa5) as u8,
            i.wrapping_add(0x5a) as u8,
        ];
        expected.extend_from_slice(&chunk);
        loop {
            match session.on_client_bytes(&chunk) {
                TcpDeliverStatus::Accepted => break,
                TcpDeliverStatus::Paused => {
                    // Spin lightly — bridge drains in the background. A
                    // production caller (Swift's `TcpClientReadPump`)
                    // waits on a demand callback; for the unit test we
                    // can just yield.
                    std::thread::sleep(Duration::from_millis(1));
                }
                TcpDeliverStatus::Closed => panic!("session unexpectedly closed"),
            }
        }
    }
    session.on_client_eof();

    let _ = eof_rx.recv_timeout(Duration::from_secs(5));
    let recv = received.lock().clone();
    assert_eq!(recv.len(), expected.len(), "byte count mismatch");
    assert_eq!(recv, expected, "byte stream corrupted (gap or reorder)");

    engine.stop(0);
}

/// Same shape as `tcp_byte_stream_preserved_under_ingress_backpressure`
/// but for the egress (NWConnection → service) direction. Pins the
/// `on_egress_bytes` FFI contract: `Paused` does not take ownership and
/// the caller must replay.
#[test]
fn tcp_byte_stream_preserved_under_egress_backpressure() {
    let received = Arc::new(Mutex::new(Vec::<u8>::new()));
    let received_clone = received.clone();
    let (eof_tx, eof_rx) = std::sync::mpsc::channel::<()>();
    let eof_tx_handler = Mutex::new(Some(eof_tx));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let received = received_clone.clone();
            let eof_tx = eof_tx_handler.lock().take().expect("single intercept");
            FlowAction::Intercept {
                meta,
                service: service_fn(move |bridge: BridgeIo<TcpFlow, NwTcpStream>| {
                    let received = received.clone();
                    let eof_tx = eof_tx.clone();
                    async move {
                        // Drain the egress side (i.e. bytes flowing from the
                        // NWConnection → service direction).
                        let BridgeIo(_ingress, mut egress) = bridge;
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match egress.read(&mut buf).await {
                                Ok(0) | Err(_) => {
                                    let _ = eof_tx.send(());
                                    return Ok(());
                                }
                                Ok(n) => {
                                    received.lock().extend_from_slice(&buf[..n]);
                                }
                            }
                        }
                    }
                })
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };

    let engine = build_engine_with_tcp_channel_capacity(handler, 1);
    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    let mut expected = Vec::with_capacity(4000);
    for i in 0..1000_u16 {
        let chunk = [
            (i >> 8) as u8,
            i as u8,
            i.wrapping_add(0xa5) as u8,
            i.wrapping_add(0x5a) as u8,
        ];
        expected.extend_from_slice(&chunk);
        loop {
            match session.on_egress_bytes(&chunk) {
                TcpDeliverStatus::Accepted => break,
                TcpDeliverStatus::Paused => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                TcpDeliverStatus::Closed => panic!("session unexpectedly closed"),
            }
        }
    }
    session.on_egress_eof();

    let _ = eof_rx.recv_timeout(Duration::from_secs(5));
    let recv = received.lock().clone();
    assert_eq!(recv.len(), expected.len(), "byte count mismatch");
    assert_eq!(recv, expected, "byte stream corrupted (gap or reorder)");

    engine.stop(0);
}

#[test]
fn app_message_can_return_reply() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|message| (message == b"ping").then(|| b"pong".to_vec())),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    });

    let reply = engine.handle_app_message(Bytes::from_static(b"ping"));
    assert_eq!(reply.as_deref(), Some(&b"pong"[..]));
}

fn build_engine_with_tcp_idle_timeout(
    handler: TestHandler,
    timeout: Duration,
) -> TransparentProxyEngine<TestHandler> {
    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_tcp_idle_timeout(timeout)
        .build()
        .expect("build engine")
}

fn build_engine_with_decision_deadline(
    handler: TestHandler,
    deadline: Duration,
    action: super::DecisionDeadlineAction,
) -> TransparentProxyEngine<TestHandler> {
    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_decision_deadline(deadline)
        .with_decision_deadline_action(action)
        .build()
        .expect("build engine")
}

#[derive(Clone)]
struct SlowMatchHandler {
    delay: Duration,
}

impl TransparentProxyHandler for SlowMatchHandler {
    fn transparent_proxy_config(&self) -> crate::tproxy::TransparentProxyConfig {
        TransparentProxyConfig::new()
    }

    fn match_tcp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<TcpFlow, NwTcpStream>, Output = (), Error = Infallible>,
        >,
    > + Send
    + '_ {
        let delay = self.delay;
        async move {
            tokio::time::sleep(delay).await;
            FlowAction::<TestTcpService>::Intercept {
                meta,
                service: service_fn(|bridge: BridgeIo<TcpFlow, NwTcpStream>| async move {
                    let BridgeIo(stream, egress) = bridge;
                    let _hold = (stream, egress);
                    std::future::pending::<()>().await;
                    Ok(())
                })
                .boxed(),
            }
        }
    }

    fn match_udp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<UdpFlow, NwUdpSocket>, Output = (), Error = Infallible>,
        >,
    > + Send
    + '_ {
        let delay = self.delay;
        async move {
            tokio::time::sleep(delay).await;
            FlowAction::<TestUdpService>::Intercept {
                meta,
                service: service_fn(|bridge: BridgeIo<UdpFlow, NwUdpSocket>| async move {
                    let BridgeIo(flow, egress) = bridge;
                    let _hold = (flow, egress);
                    std::future::pending::<()>().await;
                    Ok(())
                })
                .boxed(),
            }
        }
    }
}

#[derive(Clone)]
struct SlowMatchHandlerFactory(SlowMatchHandler);

impl TransparentProxyHandlerFactory for SlowMatchHandlerFactory {
    type Handler = SlowMatchHandler;
    type Error = BoxError;

    fn create_transparent_proxy_handler(
        &self,
        _ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        let h = self.0.clone();
        std::future::ready(Ok(h))
    }
}

#[test]
fn decision_deadline_blocks_slow_handler_by_default() {
    let engine = TransparentProxyEngineBuilder::new(SlowMatchHandlerFactory(SlowMatchHandler {
        delay: Duration::from_secs(5),
    }))
    .with_runtime_factory(TestRuntimeFactory)
    .with_decision_deadline(Duration::from_millis(100))
    .build()
    .expect("build engine");

    let started = Instant::now();
    let action = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    let elapsed = started.elapsed();
    assert!(
        matches!(action, SessionFlowAction::Blocked),
        "expected Blocked on deadline"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "decision deadline should fire before slow handler completes (elapsed: {:?})",
        elapsed
    );
    engine.stop(0);
}

#[test]
fn decision_deadline_passthrough_when_action_is_passthrough() {
    let engine = TransparentProxyEngineBuilder::new(SlowMatchHandlerFactory(SlowMatchHandler {
        delay: Duration::from_secs(5),
    }))
    .with_runtime_factory(TestRuntimeFactory)
    .with_decision_deadline(Duration::from_millis(100))
    .with_decision_deadline_action(super::DecisionDeadlineAction::Passthrough)
    .build()
    .expect("build engine");

    let action = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(action, SessionFlowAction::Passthrough));
    engine.stop(0);
}

#[test]
fn decision_deadline_does_not_fire_for_fast_handlers() {
    // Fast intercept — well within the default 1s deadline.
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|bridge: BridgeIo<TcpFlow, NwTcpStream>| async move {
                let BridgeIo(stream, egress) = bridge;
                let _hold = (stream, egress);
                std::future::pending::<()>().await;
                Ok(())
            })
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine_with_decision_deadline(
        handler,
        Duration::from_secs(2),
        super::DecisionDeadlineAction::Block,
    );

    let action = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(action, SessionFlowAction::Intercept(_)));
    engine.stop(0);
}

#[test]
fn flow_meta_new_generates_unique_flow_ids_and_sets_opened_at() {
    let a = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
    let b = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
    assert_ne!(a.flow_id, 0);
    assert_ne!(b.flow_id, 0);
    assert_ne!(a.flow_id, b.flow_id);
    assert!(b.flow_id > a.flow_id);
    assert!(a.opened_at <= Instant::now());
    assert!(a.intercept_decision.is_none());
    assert!(b.intercept_decision.is_none());
}

#[test]
fn flow_meta_records_intercept_decision_after_handler() {
    let seen = Arc::new(Mutex::new(None::<Arc<TransparentProxyFlowMeta>>));
    let seen_clone = seen.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let seen_clone = seen_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |bridge: BridgeIo<TcpFlow, NwTcpStream>| {
                    let seen_clone = seen_clone.clone();
                    let notify_tx = notify_tx.clone();
                    async move {
                        let BridgeIo(stream, _egress) = bridge;
                        *seen_clone.lock() =
                            stream.extensions().get_arc::<TransparentProxyFlowMeta>();
                        let _ = notify_tx.send(());
                        Ok(())
                    }
                })
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    let _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    let seen_meta = seen.lock().clone().expect("tcp flow meta");
    assert_eq!(
        seen_meta.intercept_decision,
        Some(crate::tproxy::types::TransparentProxyFlowAction::Intercept),
        "intercept_decision should be populated by the engine"
    );
    assert_ne!(seen_meta.flow_id, 0);
}

#[test]
fn tcp_bridge_idle_timeout_unwinds_session() {
    // Service holds the bridge open without doing any I/O so the bridge has
    // no progress to observe; the idle timeout backstop should close it.
    let (close_tx, close_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| FlowAction::Intercept {
            meta,
            service: service_fn(|bridge: BridgeIo<TcpFlow, NwTcpStream>| async move {
                // Keep the bridge alive — without holding it, dropping it
                // immediately closes the duplex halves and the bridge sees EOF.
                let BridgeIo(stream, egress) = bridge;
                let _hold = (stream, egress);
                std::future::pending::<()>().await;
                Ok(())
            })
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine_with_tcp_idle_timeout(handler, Duration::from_millis(100));

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        move || {
            let _ = close_tx.send(());
        },
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    // Wait for on_server_closed — fired when the ingress bridge exits its
    // loop, including via the idle timeout path.
    let started = Instant::now();
    close_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("on_server_closed within 2s");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(80),
        "idle bridge unwound too early: {:?}",
        elapsed
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "idle bridge unwound too late: {:?}",
        elapsed
    );

    engine.stop(0);
}

#[test]
fn tcp_bridge_observes_per_flow_shutdown_via_session_cancel() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| FlowAction::Intercept {
            meta,
            service: service_fn(|bridge: BridgeIo<TcpFlow, NwTcpStream>| async move {
                let BridgeIo(stream, egress) = bridge;
                let _hold = (stream, egress);
                std::future::pending::<()>().await;
                Ok(())
            })
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    // Give the bridge a moment to register, then cancel — should return
    // promptly without blocking even though the service is still parked.
    std::thread::sleep(Duration::from_millis(20));
    let started = Instant::now();
    session.cancel();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "session cancel took too long: {:?}",
        elapsed
    );

    engine.stop(0);
}
