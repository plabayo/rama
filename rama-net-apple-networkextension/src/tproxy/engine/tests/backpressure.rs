//! Byte-stream-preservation tests under per-direction backpressure: pin
//! the load-bearing FFI invariant that `Paused` does not take ownership
//! and a caller that retains + replays sees the full byte stream
//! delivered in order, on both ingress and egress.

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
