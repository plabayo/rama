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
        |_| {},
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
        |_| {},
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
        },
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    // Phase 2: activate egress (no-op callbacks) so the service task starts.
    session.activate(|_| {}, || {}, || {});
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
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    // Phase 2: activate so the service task runs and reads extensions.
    session.activate(|_| {}, || {}, || {});
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
fn tcp_on_client_bytes_returns_false_when_ingress_channel_full() {
    // Without `activate`, the bridge tasks never start, so the channel never
    // drains: any send beyond `tcp_channel_capacity` must be rejected. This
    // proves `on_client_bytes` is non-blocking and surfaces fullness as a
    // pause signal — the load-bearing property the Swift FFI relies on.
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
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    let chunk = vec![0u8; 16];
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for _ in 0..10 {
        if session.on_client_bytes(&chunk) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }

    assert_eq!(accepted, 2, "channel capacity is 2");
    assert_eq!(rejected, 8);

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
        |_| {},
        move || {
            demand_count_clone.fetch_add(1, Ordering::Relaxed);
            let _ = notify_tx.send(());
        },
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| {}, || {}, || {});

    // Pump until we hit backpressure. With a slow service and capacity=2 we
    // expect this within a handful of iterations.
    let chunk = vec![0u8; 4096];
    let mut got_rejected = false;
    for _ in 0..1000 {
        if !session.on_client_bytes(&chunk) {
            got_rejected = true;
            break;
        }
    }
    assert!(got_rejected, "expected the bounded channel to fill up");

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
    // on `on_client_bytes` reports `false` (closed) — Swift treats this as
    // "stop reading" and waits for the eventual `on_server_closed`.
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
        |_| {},
        || {},
        move || {
            let _ = closed_tx.send(());
        },
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| {}, || {}, || {});

    // The service has nothing to do and exits, dropping ingress; the bridge's
    // first `write_all` will fail and close the receiver. Pump bytes until
    // we observe the closed signal.
    let chunk = vec![0u8; 1024];
    let mut saw_false = false;
    for _ in 0..200 {
        if !session.on_client_bytes(&chunk) {
            saw_false = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        saw_false,
        "on_client_bytes must surface the channel-closed signal after a write failure"
    );

    let _ = closed_rx.recv_timeout(Duration::from_secs(1));
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
