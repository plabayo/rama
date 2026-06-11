use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use parking_lot::Mutex;
use rama_core::io::BridgeIo;
use rama_core::service::service_fn;
use rama_net::address::HostWithPort;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;

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
                service: service_fn(
                    move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                        let received = received.clone();
                        let eof_tx = eof_tx.clone();
                        async move {
                            let BridgeIo(mut ingress, _egress) = bridge;
                            let mut buf = vec![0u8; 4096];
                            loop {
                                match ingress.read(&mut buf).await {
                                    Ok(0) | Err(_) => {
                                        _ = eof_tx.send(());
                                        return Ok(());
                                    }
                                    Ok(n) => {
                                        received.lock().extend_from_slice(&buf[..n]);
                                    }
                                }
                            }
                        }
                    },
                )
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
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
            match session.on_client_bytes(&chunk) {
                TcpDeliverStatus::Accepted => break,
                TcpDeliverStatus::Paused => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                TcpDeliverStatus::Closed => panic!("session unexpectedly closed"),
            }
        }
    }
    session.on_client_eof();

    _ = eof_rx.recv_timeout(Duration::from_secs(5));
    let recv = received.lock().clone();
    assert_eq!(recv.len(), expected.len(), "byte count mismatch");
    assert_eq!(recv, expected, "byte stream corrupted (gap or reorder)");

    engine.stop(0);
}

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
                service: service_fn(
                    move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                        let received = received.clone();
                        let eof_tx = eof_tx.clone();
                        async move {
                            let BridgeIo(_ingress, mut egress) = bridge;
                            let mut buf = vec![0u8; 4096];
                            loop {
                                match egress.read(&mut buf).await {
                                    Ok(0) | Err(_) => {
                                        _ = eof_tx.send(());
                                        return Ok(());
                                    }
                                    Ok(n) => {
                                        received.lock().extend_from_slice(&buf[..n]);
                                    }
                                }
                            }
                        }
                    },
                )
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
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

    _ = eof_rx.recv_timeout(Duration::from_secs(5));
    let recv = received.lock().clone();
    assert_eq!(recv.len(), expected.len(), "byte count mismatch");
    assert_eq!(recv, expected, "byte stream corrupted (gap or reorder)");

    engine.stop(0);
}

/// Capacity-1 ingress backpressure driven by the read-demand callback —
/// NOT a busy-retry like `tcp_byte_stream_preserved_under_ingress_backpressure`.
/// This mirrors the real Swift read pump: it stops on `Paused` and only
/// resumes when `on_client_read_demand` fires. With capacity 1 it exercises
/// the `try_enqueue_client` lost-wakeup window on every chunk — if the demand
/// is ever dropped, the producer parks forever and the per-pause wait below
/// trips its deadline. Regression guard for the post-store re-check fix.
#[test]
fn tcp_ingress_resumes_via_read_demand_at_capacity_one() {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Instant;

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
                service: service_fn(
                    move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                        let received = received.clone();
                        let eof_tx = eof_tx.clone();
                        async move {
                            let BridgeIo(mut ingress, _egress) = bridge;
                            let mut buf = vec![0u8; 4096];
                            loop {
                                match ingress.read(&mut buf).await {
                                    Ok(0) | Err(_) => {
                                        _ = eof_tx.send(());
                                        return Ok(());
                                    }
                                    Ok(n) => received.lock().extend_from_slice(&buf[..n]),
                                }
                            }
                        }
                    },
                )
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };

    let engine = build_engine_with_tcp_channel_capacity(handler, 1);

    // Count read-demand callbacks so the producer can wait for one instead
    // of busy-retrying.
    let demand = Arc::new(AtomicUsize::new(0));
    let demand_cb = demand.clone();
    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        |_| TcpDeliverStatus::Accepted,
        move || {
            demand_cb.fetch_add(1, AtomicOrdering::Release);
        },
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
            let seen = demand.load(AtomicOrdering::Acquire);
            match session.on_client_bytes(&chunk) {
                TcpDeliverStatus::Accepted => break,
                TcpDeliverStatus::Paused => {
                    // Wait for a read-demand strictly newer than `seen` — never
                    // a busy-retry. A lost wakeup never bumps the counter, so
                    // this trips the deadline (the bug this test guards).
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while demand.load(AtomicOrdering::Acquire) <= seen {
                        assert!(
                            Instant::now() < deadline,
                            "read-demand lost after Paused at chunk {i}; ingress flow wedged"
                        );
                        std::thread::sleep(Duration::from_micros(50));
                    }
                }
                TcpDeliverStatus::Closed => panic!("session unexpectedly closed"),
            }
        }
    }
    session.on_client_eof();

    _ = eof_rx.recv_timeout(Duration::from_secs(5));
    let recv = received.lock().clone();
    assert_eq!(recv.len(), expected.len(), "byte count mismatch");
    assert_eq!(recv, expected, "byte stream corrupted (gap or reorder)");

    engine.stop(0);
}
