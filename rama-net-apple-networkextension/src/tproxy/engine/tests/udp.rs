//! UDP-specific tests: datagram delivery and read-demand callback wiring.

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
use std::time::Duration;

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
            service: service_fn(
                |bridge: BridgeIo<crate::UdpFlow, crate::NwUdpSocket>| async move {
                    let BridgeIo(mut ingress, _egress) = bridge;
                    if let Some(datagram) = ingress.recv().await {
                        ingress.send(datagram);
                    }
                    Ok(())
                },
            )
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
            _ = notify_tx.send(());
        },
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| {});
    session.on_client_datagram(b"ping");

    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert_eq!(got.lock().as_slice(), b"ping");
}

/// `on_client_close` must always fire `on_server_closed` so the
/// Swift dispatcher can run its terminal cleanup. UDP doesn't have
/// an in-flight pump to drain like TCP does, but the close-callback
/// contract is the same — pinned here so a future `callback_active`
/// gate on the closed-sink can't silently regress it. Mirrors
/// `tcp_cancel_during_inflight_response_still_fires_on_server_closed`.
#[test]
fn udp_on_client_close_still_fires_on_server_closed() {
    let closed_count = Arc::new(AtomicUsize::new(0));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |_bridge: BridgeIo<crate::UdpFlow, crate::NwUdpSocket>| async move {
                    std::future::pending::<()>().await;
                    Ok(())
                },
            )
            .boxed(),
        }),
    };
    let engine = build_engine(handler);

    let closed_count_cb = closed_count.clone();
    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(53)),
        |_| {},
        || {},
        move || {
            closed_count_cb.fetch_add(1, Ordering::Relaxed);
        },
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| {});

    // Give the service task time to reach its select! before close.
    std::thread::sleep(Duration::from_millis(20));

    session.on_client_close();
    drop(session);

    let started = std::time::Instant::now();
    while closed_count.load(Ordering::Relaxed) == 0 && started.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        closed_count.load(Ordering::Relaxed),
        1,
        "on_client_close must still fire on_server_closed exactly once",
    );

    engine.stop(0);
}

/// Egress (remote→service) UDP path drops datagrams when the
/// per-flow channel is saturated. Asymmetric to the ingress path:
/// the ingress demand callback re-arms a paused Swift kernel reader,
/// the egress side has no such handshake — `NWConnection.receive`
/// drives itself recursively from `NwUdpConnectionReadPump`. Drops
/// here match wire-level UDP semantics; pinning the behavior so a
/// future change to add backpressure does not silently regress (it
/// would deadlock the egress pump instead).
#[test]
fn udp_egress_drops_datagrams_when_service_does_not_drain() {
    use std::convert::Infallible;
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            // Service holds the bridge open without reading egress —
            // the egress channel saturates immediately.
            service: service_fn(
                |_bridge: BridgeIo<crate::UdpFlow, crate::NwUdpSocket>| async move {
                    std::future::pending::<Result<(), Infallible>>().await
                },
            )
            .boxed(),
        }),
    };
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_udp_channel_capacity(2)
        .build()
        .expect("build engine");

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(53)),
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| {});

    // Push more than the channel can hold. Excess datagrams are
    // dropped at `try_send` — the call must not panic, must not
    // block, and must not affect the engine's continued operation.
    for i in 0..32 {
        session.on_egress_datagram(format!("dgram {i}").as_bytes());
    }
    session.on_client_close();
    engine.stop(0);
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
            service: service_fn(
                |bridge: BridgeIo<crate::UdpFlow, crate::NwUdpSocket>| async move {
                    let BridgeIo(mut ingress, _egress) = bridge;
                    _ = ingress.recv().await;
                    Ok(())
                },
            )
            .boxed(),
        }),
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        move || {
            demand_count_clone.fetch_add(1, Ordering::Relaxed);
            _ = notify_tx.send(());
        },
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| {});
    session.on_client_datagram(b"x");

    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert!(demand_count.load(Ordering::Relaxed) >= 1);
}
