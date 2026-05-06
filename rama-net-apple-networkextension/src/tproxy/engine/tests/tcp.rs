//! TCP-specific tests: bridge byte delivery, demand callback wiring,
//! cancel/close-status semantics, idle timeout backstop, and per-flow
//! shutdown observation.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use parking_lot::Mutex;
use rama_core::io::BridgeIo;
use rama_core::service::service_fn;
use rama_net::address::HostWithPort;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn tcp_bridge_delivers_server_bytes() {
    let got = Arc::new(Mutex::new(Vec::<u8>::new()));
    let got_clone = got.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    let BridgeIo(mut ingress, _egress) = bridge;
                    _ = ingress.write_all(b"pong").await;
                    Ok(())
                },
            )
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
            _ = notify_tx.send(());
            TcpDeliverStatus::Accepted
        },
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    _ = session.on_client_bytes(b"ping");

    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert_eq!(got.lock().as_slice(), b"pong");
}

#[test]
fn tcp_cancel_many_idle_sessions_suppresses_callbacks_and_stops_fast() {
    let closed_count = Arc::new(AtomicUsize::new(0));
    let bytes_count = Arc::new(AtomicUsize::new(0));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |_: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move { Ok(()) },
            )
            .boxed(),
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
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |_: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move { Ok(()) },
            )
            .boxed(),
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
    let demand_count = Arc::new(AtomicUsize::new(0));
    let demand_count_clone = demand_count.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    let BridgeIo(mut ingress, _egress) = bridge;
                    let mut buf = vec![0u8; 4096];
                    loop {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        match ingress.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                    Ok(())
                },
            )
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
            _ = notify_tx.send(());
        },
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    let chunk = vec![0u8; 4096];
    let mut got_paused = false;
    for _ in 0..1000 {
        if matches!(session.on_client_bytes(&chunk), TcpDeliverStatus::Paused) {
            got_paused = true;
            break;
        }
    }
    assert!(got_paused, "expected the bounded channel to fill up");

    _ = notify_rx.recv_timeout(Duration::from_secs(2));
    assert!(
        demand_count.load(Ordering::Relaxed) >= 1,
        "demand callback should fire when the bridge frees a slot"
    );

    engine.stop(0);
}

#[test]
fn tcp_bridge_write_failure_closes_ingress_channel() {
    let (closed_tx, closed_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |_: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move { Ok(()) },
            )
            .boxed(),
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
            _ = closed_tx.send(());
        },
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

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

    _ = closed_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);
}

#[test]
fn tcp_on_bytes_signals_closed_after_session_cancel() {
    // After `cancel()`, the FFI byte-delivery calls MUST surface
    // `Closed` (not `Paused`) so the Swift pumps terminate immediately.
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |_: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move { Ok(()) },
            )
            .boxed(),
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
        "on_egress_bytes must report Closed after cancel"
    );

    engine.stop(0);
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
            service: service_fn(
                |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    let BridgeIo(stream, egress) = bridge;
                    let _hold = (stream, egress);
                    std::future::pending::<()>().await;
                    Ok(())
                },
            )
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
            _ = close_tx.send(());
        },
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    let started = Instant::now();
    close_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("on_server_closed within 2s");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(80),
        "idle bridge unwound too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "idle bridge unwound too late: {elapsed:?}"
    );

    engine.stop(0);
}

#[test]
fn tcp_bridge_observes_per_flow_shutdown_via_session_cancel() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    let BridgeIo(stream, egress) = bridge;
                    let _hold = (stream, egress);
                    std::future::pending::<()>().await;
                    Ok(())
                },
            )
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
        "session cancel took too long: {elapsed:?}"
    );

    engine.stop(0);
}
