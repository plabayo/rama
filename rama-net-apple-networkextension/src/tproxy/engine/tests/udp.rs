//! UDP-specific tests: datagram delivery and read-demand callback wiring.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use parking_lot::Mutex;
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
            service: service_fn(|mut flow: crate::UdpFlow| async move {
                if let Some(datagram) = flow.recv().await {
                    // Echo back — Datagram carries peer; reuse the
                    // same Datagram so the reply is correlated to
                    // the originating peer.
                    flow.send(datagram);
                }
                Ok(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
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

/// End-to-end UDP loopback: client sends a datagram, the service
/// (owning egress) sends it via `send_to`, a real loopback UDP
/// "server" replies, and the reply is delivered back through
/// `flow.send`. Exercises the engine ingress path and per-datagram
/// peer attribution end-to-end.
#[test]
fn udp_loopback_multi_peer_service_owned_egress() {
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
                    move |mut flow: crate::UdpFlow| {
                        let replies = replies.clone();
                        let notify_tx = notify_tx.clone();
                        async move {
                            // Service owns egress: one unconnected
                            // tokio UDP socket, `send_to(peer)` per
                            // datagram, `recv_from` per reply. This is
                            // the shape every UDP handler is expected
                            // to implement (or to wrap with whatever
                            // socket pooling / rama-udp transport it
                            // wants).
                            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                                .await
                                .expect("bind egress socket");
                            let mut buf = vec![0u8; 65_535];
                            loop {
                                tokio::select! {
                                    maybe_in = flow.recv() => {
                                        let Some(datagram) = maybe_in else { break };
                                        if let Some(peer) = datagram.peer {
                                            _ = socket.send_to(&datagram.payload, peer).await;
                                        }
                                    }
                                    result = socket.recv_from(&mut buf) => {
                                        let Ok((n, peer)) = result else { break };
                                        let payload = rama_core::bytes::Bytes::copy_from_slice(&buf[..n]);
                                        replies.lock().push((payload.to_vec(), Some(peer)));
                                        _ = notify_tx.send(());
                                        flow.send(crate::Datagram { payload, peer: Some(peer) });
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
            service: service_fn(|mut flow: crate::UdpFlow| async move {
                _ = flow.recv().await;
                Ok(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
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
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received = received.clone();
                    let notify_tx = notify_tx.clone();
                    async move {
                        // Capture lengths so we can prove the empty
                        // datagram crossed the boundary; do NOT
                        // filter on `is_empty()` here — that's the
                        // exact mistake the framework had.
                        while let Some(datagram) = flow.recv().await {
                            received.lock().push(datagram.payload.len());
                            _ = notify_tx.send(());
                        }
                        Ok::<_, std::convert::Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
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
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received = received.clone();
                    let notify_tx = notify_tx.clone();
                    async move {
                        // Service-owned egress socket. Forwards
                        // each ingress datagram to its peer and
                        // records every reply that comes back.
                        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                            .await
                            .expect("bind egress socket");
                        let mut buf = vec![0u8; 65_535];
                        loop {
                            tokio::select! {
                                maybe_in = flow.recv() => {
                                    let Some(datagram) = maybe_in else { break };
                                    if let Some(peer) = datagram.peer {
                                        _ = socket.send_to(&datagram.payload, peer).await;
                                    }
                                }
                                result = socket.recv_from(&mut buf) => {
                                    let Ok((n, _peer)) = result else { break };
                                    received.lock().push(n);
                                    _ = notify_tx.send(());
                                }
                            }
                        }
                        Ok::<_, std::convert::Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
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

/// Contract: when a service sends a `Datagram` with `peer = None`
/// (the safety-valve case the framework reserves for kernel-
/// attribution gaps), the engine must deliver it as-is to
/// `on_server_datagram` — drop / fallback is the *Swift* writer
/// pump's problem (it caches the latest known peer and logs a
/// stall episode once). The engine itself must not crash, must
/// not synthesise a peer, must not silently drop.
#[test]
fn udp_send_with_no_peer_is_delivered_to_callback_with_none() {
    let peers = Arc::new(Mutex::new(Vec::<Option<std::net::SocketAddr>>::new()));
    let peers_clone = peers.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|flow: crate::UdpFlow| async move {
                flow.send(crate::Datagram::without_peer(
                    rama_core::bytes::Bytes::from_static(b"orphan"),
                ));
                Ok::<_, std::convert::Infallible>(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        move |datagram: crate::Datagram| {
            peers_clone.lock().push(datagram.peer);
            _ = notify_tx.send(());
        },
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    let got = peers.lock().clone();
    assert_eq!(
        got,
        vec![None],
        "engine must deliver Datagram::without_peer with peer = None, untouched"
    );
}

/// `activate()` arriving after the engine has already stopped must
/// not panic and must not leak: the service task is gone, so
/// `flow_tx.send` fails, the `UdpFlow` is dropped, and that
/// drop is the only externally observable event. Pin the
/// silent-failure path described in the activate doc.
#[test]
fn udp_activate_after_engine_stop_is_safe_noop() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|mut flow: crate::UdpFlow| async move {
                while flow.recv().await.is_some() {}
                Ok::<_, std::convert::Infallible>(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    // Stop the engine before activate — the per-flow service task
    // is cancelled by `parent_guard`, so the next `flow_tx.send`
    // will fail with a dropped receiver.
    engine.stop(0);

    // Must not panic, must not hang.
    session.activate();
    // Drop the session — its drop calls `on_client_close`, which
    // also must be safe post-stop.
    drop(session);
}

/// Double-`activate()` on the same session is misuse but must be
/// observable as a warning, not a panic / UB. The second call
/// finds `pending = None` and returns. Pin the no-crash invariant.
#[test]
fn udp_double_activate_is_safe_noop() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|mut flow: crate::UdpFlow| async move {
                while flow.recv().await.is_some() {}
                Ok::<_, std::convert::Infallible>(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    session.activate(); // second call must be a logged no-op
    engine.stop(0);
}

/// A UDP datagram approaching the maximum payload size (just
/// under 64 KiB — the IPv4 UDP cap once the 8-byte header is
/// accounted for) must round-trip through the engine without
/// truncation or panic. Real protocols (BitTorrent uTP, certain
/// game frames) hit close to this boundary; the bounded ingress
/// channel must not malfunction on a single large item.
#[test]
fn udp_large_datagram_near_max_payload_roundtrips() {
    use std::net::{Ipv4Addr, SocketAddr};
    const PAYLOAD_LEN: usize = 65_507; // IPv4 max UDP payload

    let received_len = Arc::new(AtomicUsize::new(0));
    let received_len_clone = received_len.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let received_len = received_len_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received_len = received_len.clone();
                    let notify_tx = notify_tx.clone();
                    async move {
                        if let Some(datagram) = flow.recv().await {
                            received_len.store(datagram.payload.len(), Ordering::Relaxed);
                            _ = notify_tx.send(());
                        }
                        Ok::<_, std::convert::Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    let payload = vec![0xABu8; PAYLOAD_LEN];
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
    session.on_client_datagram(&payload, Some(peer));

    _ = notify_rx.recv_timeout(Duration::from_secs(2));
    engine.stop(0);

    assert_eq!(
        received_len.load(Ordering::Relaxed),
        PAYLOAD_LEN,
        "large datagram must round-trip without truncation"
    );
}

/// Contract: when a service sends a `Datagram` whose peer is an
/// IPv6 `SocketAddrV6` with a non-zero `scope_id` (link-local
/// addressing — `fe80::1%en0` style), the engine's
/// `on_server_datagram` callback must observe the *same* scope
/// identifier. The FFI marshaling layer carries the scope id in
/// a dedicated `u32` field; this test pins the end-to-end path
/// inside the engine (no FFI boundary crossed, but the path
/// exercises the same SocketAddr that the FFI will round-trip
/// elsewhere).
#[test]
fn udp_send_preserves_ipv6_scope_id_through_engine_callback() {
    use std::net::{Ipv6Addr, SocketAddrV6};

    let observed = Arc::new(Mutex::new(Vec::<Option<std::net::SocketAddr>>::new()));
    let observed_clone = observed.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let scoped_peer = std::net::SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        5353,
        0,
        4, // non-zero zone id
    ));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let scoped_peer = scoped_peer;
            FlowAction::Intercept {
                meta,
                service: service_fn(move |flow: crate::UdpFlow| async move {
                    flow.send(crate::Datagram::new(
                        rama_core::bytes::Bytes::from_static(b"scoped"),
                        scoped_peer,
                    ));
                    Ok::<_, std::convert::Infallible>(())
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        move |datagram: crate::Datagram| {
            observed_clone.lock().push(datagram.peer);
            _ = notify_tx.send(());
        },
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    let got = observed.lock().clone();
    assert_eq!(got.len(), 1, "exactly one datagram expected; got {got:?}");
    let Some(peer) = got[0] else {
        panic!("expected Some peer, got None");
    };
    assert_eq!(peer, scoped_peer);
    match peer {
        std::net::SocketAddr::V6(v6) => {
            assert_eq!(v6.scope_id(), 4, "scope id must survive the engine path");
        }
        std::net::SocketAddr::V4(_) => panic!("expected V6"),
    }
}
