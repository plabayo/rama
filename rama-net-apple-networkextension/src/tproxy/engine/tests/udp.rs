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
        tcp_egress_options: None,
        udp_egress_options: None,
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
        tcp_egress_options: None,
        udp_egress_options: None,
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
        tcp_egress_options: None,
        udp_egress_options: None,
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

/// RFC 768 says a UDP datagram with a zero-length payload is valid
/// (the length field can be `8`, header-only). Real protocols use
/// them as keep-alives or signalling pings. The client→service path
/// MUST forward such datagrams instead of silently dropping them.
#[test]
fn udp_zero_length_datagram_from_client_reaches_service() {
    let received = Arc::new(Mutex::new(Vec::<usize>::new()));
    let received_clone = received.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let received = received_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    move |bridge: BridgeIo<crate::UdpFlow, crate::NwUdpSocket>| {
                        let received = received.clone();
                        let notify_tx = notify_tx.clone();
                        async move {
                            let BridgeIo(mut ingress, _egress) = bridge;
                            // Capture lengths so we can prove the empty
                            // datagram crossed the boundary; do NOT
                            // filter on `is_empty()` here — that's the
                            // exact mistake the framework had.
                            while let Some(datagram) = ingress.recv().await {
                                received.lock().push(datagram.len());
                                _ = notify_tx.send(());
                            }
                            Ok::<_, std::convert::Infallible>(())
                        }
                    },
                )
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        udp_egress_options: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::local_ipv4(5353)),
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| {});
    session.on_client_datagram(b"");
    session.on_client_datagram(b"payload");

    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    let lens = received.lock().clone();
    assert!(
        lens.contains(&0),
        "zero-length client datagram must reach the service; observed lengths: {lens:?}"
    );
    assert!(
        lens.contains(&7),
        "non-empty follow-up datagram must also be delivered; observed lengths: {lens:?}"
    );
}

/// Mirror of the above for the egress→service direction: a zero-
/// length datagram coming back from the egress NWConnection (think
/// of a keep-alive reply that carries no payload) must also be
/// forwarded into the service's `egress` half of the bridge.
#[test]
fn udp_zero_length_datagram_from_egress_reaches_service() {
    let received = Arc::new(Mutex::new(Vec::<usize>::new()));
    let received_clone = received.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let received = received_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    move |bridge: BridgeIo<crate::UdpFlow, crate::NwUdpSocket>| {
                        let received = received.clone();
                        let notify_tx = notify_tx.clone();
                        async move {
                            let BridgeIo(_ingress, mut egress) = bridge;
                            while let Some(datagram) = egress.recv().await {
                                received.lock().push(datagram.len());
                                _ = notify_tx.send(());
                            }
                            Ok::<_, std::convert::Infallible>(())
                        }
                    },
                )
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        udp_egress_options: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::local_ipv4(5353)),
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| {});
    session.on_egress_datagram(b"");
    session.on_egress_datagram(b"payload");

    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    let lens = received.lock().clone();
    assert!(
        lens.contains(&0),
        "zero-length egress datagram must reach the service; observed lengths: {lens:?}"
    );
    assert!(
        lens.contains(&7),
        "non-empty follow-up datagram must also be delivered; observed lengths: {lens:?}"
    );
}
