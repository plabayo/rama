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
                        // Echo back — Datagram carries peer; for the
                        // echo path we reuse the same Datagram so the
                        // reply is correlated to the originating peer.
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
        move |datagram: crate::Datagram| {
            let mut lock = got_clone.lock();
            lock.extend_from_slice(&datagram.payload);
            _ = notify_tx.send(());
        },
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    session.on_client_datagram(b"ping", None);

    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert_eq!(got.lock().as_slice(), b"ping");
}

/// End-to-end UDP loopback: client sends a datagram, the engine's
/// Rust-owned egress socket sends it via `send_to`, a real loopback
/// UDP "server" replies, and the reply is received by the service
/// through `egress.recv()`. Exercises the actual `udp_egress.rs`
/// send + recv pumps and the per-datagram peer attribution.
#[test]
fn udp_egress_loopback_multi_peer() {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

    // Two stand-in "remote" servers on loopback. Each echoes with a
    // peer-distinguishing prefix so we can prove that the per-
    // datagram peer attribution survives through the bridge.
    let server_a = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let server_b = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    server_a
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    server_b
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let addr_a = server_a.local_addr().unwrap();
    let addr_b = server_b.local_addr().unwrap();

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_a = stop.clone();
    let stop_b = stop.clone();
    let thread_a = std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while !stop_a.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = server_a.recv_from(&mut buf) {
                let mut reply = b"A:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                _ = server_a.send_to(&reply, peer);
            }
        }
    });
    let thread_b = std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while !stop_b.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = server_b.recv_from(&mut buf) {
                let mut reply = b"B:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                _ = server_b.send_to(&reply, peer);
            }
        }
    });

    let replies = Arc::new(Mutex::new(Vec::<(Vec<u8>, Option<SocketAddr>)>::new()));
    let replies_clone = replies.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let replies = replies_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    move |bridge: BridgeIo<crate::UdpFlow, crate::NwUdpSocket>| {
                        let replies = replies.clone();
                        let notify_tx = notify_tx.clone();
                        async move {
                            let BridgeIo(mut ingress, mut egress) = bridge;
                            // Forward each ingress datagram to its peer
                            // (`peer` carries the destination the app
                            // addressed) and forward each egress reply
                            // back to the client.
                            loop {
                                tokio::select! {
                                    maybe_in = ingress.recv() => {
                                        let Some(datagram) = maybe_in else { break };
                                        egress.send(datagram);
                                    }
                                    maybe_out = egress.recv() => {
                                        let Some(datagram) = maybe_out else { break };
                                        replies.lock().push((
                                            datagram.payload.to_vec(),
                                            datagram.peer,
                                        ));
                                        _ = notify_tx.send(());
                                    }
                                }
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
            .with_remote_endpoint(HostWithPort::local_ipv4(addr_a.port())),
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate();

    // Two datagrams, two different peers — the per-datagram peer is
    // what makes multi-peer UDP (DNS-over-multiple-resolvers, NTP-
    // burst, mDNS) faithfully proxied. Previously each peer needed a
    // distinct NWConnection; with the BSD socket model `send_to`
    // does the dispatch.
    session.on_client_datagram(b"ping", Some(addr_a));
    session.on_client_datagram(b"ping", Some(addr_b));

    _ = notify_rx.recv_timeout(Duration::from_secs(2));
    _ = notify_rx.recv_timeout(Duration::from_secs(2));

    session.on_client_close();
    engine.stop(0);
    stop.store(true, Ordering::Relaxed);
    // Unblock the recv_from()s so the helper threads can exit.
    _ = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .and_then(|s| s.send_to(b"", addr_a).and(s.send_to(b"", addr_b)));
    _ = thread_a.join();
    _ = thread_b.join();

    let got = replies.lock().clone();
    assert!(
        got.iter().any(|(p, _)| p.starts_with(b"A:")),
        "expected a reply from peer A; got {got:?}"
    );
    assert!(
        got.iter().any(|(p, _)| p.starts_with(b"B:")),
        "expected a reply from peer B; got {got:?}"
    );
    // The egress recv pump tags each datagram with the peer it came
    // from — without that, multi-peer UDP would not be possible to
    // disambiguate on the service side.
    assert!(
        got.iter().any(|(_, peer)| *peer == Some(addr_a)),
        "expected peer attribution for A; got {got:?}"
    );
    assert!(
        got.iter().any(|(_, peer)| *peer == Some(addr_b)),
        "expected peer attribution for B; got {got:?}"
    );
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

    session.activate();
    session.on_client_datagram(b"x", None);

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
                                received.lock().push(datagram.payload.len());
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

    session.activate();
    session.on_client_datagram(b"", None);
    session.on_client_datagram(b"payload", None);

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
/// length datagram coming back from a peer (think of a keep-alive
/// reply that carries no payload) must also be forwarded into the
/// service's `egress` half of the bridge. Uses a real loopback UDP
/// server to drive the engine's `recv_from` pump.
#[test]
fn udp_zero_length_datagram_from_egress_reaches_service() {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
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
                            let BridgeIo(mut ingress, mut egress) = bridge;
                            loop {
                                tokio::select! {
                                    maybe_in = ingress.recv() => {
                                        // Forward the "kick" out to the
                                        // loopback peer so it can reply.
                                        let Some(datagram) = maybe_in else { break };
                                        egress.send(datagram);
                                    }
                                    maybe_out = egress.recv() => {
                                        let Some(datagram) = maybe_out else { break };
                                        received.lock().push(datagram.payload.len());
                                        _ = notify_tx.send(());
                                    }
                                }
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

    // Stand-in peer that the engine's egress will reach via send_to,
    // and that will reply with an empty + a non-empty datagram.
    let server = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        if let Ok((_, peer)) = server.recv_from(&mut buf) {
            _ = server.send_to(b"", peer);
            _ = server.send_to(b"payload", peer);
        }
    });

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::local_ipv4(server_addr.port())),
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    session.on_client_datagram(b"kick", Some(server_addr));

    _ = notify_rx.recv_timeout(Duration::from_secs(2));
    _ = notify_rx.recv_timeout(Duration::from_secs(2));
    session.on_client_close();
    engine.stop(0);
    _ = server_thread.join();

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
