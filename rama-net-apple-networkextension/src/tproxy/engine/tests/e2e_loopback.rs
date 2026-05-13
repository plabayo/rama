//! Loopback end-to-end tests for the TCP forwarding path.
//!
//! Every other test module exercises pieces of the engine in
//! isolation against in-memory primitives — `tokio::io::duplex`
//! pairs, mock pumps, or synthetic byte streams. This module is the
//! first that drives the bridge through a real `tokio::net::TcpStream`
//! connected to a real `tokio::net::TcpListener`, so the per-flow
//! service is doing real kernel I/O on one side of the bridge.
//!
//! The egress-facing `NwTcpStream` half is still simulated (in
//! production it's bridged to a Swift-managed `NWConnection` that
//! Rust never sees directly), but the ingress side is now a real
//! socket from the OS's point of view — which is the closest the
//! Rust side can get to the production transport without bringing
//! the Network.framework runtime into a unit test.
//!
//! Each scenario exercises one peer behavior that's known to be
//! problematic in the field:
//!
//! * clean echo + clean close — the happy path;
//! * peer reads bytes then half-closes write side, leaving the read
//!   side open — mirrors the Cloudflare-style stuck-FIN pattern that
//!   triggered the production accumulation;
//! * peer accepts and never responds — mirrors a backend stalled in
//!   its server loop;
//! * peer closes mid-write — sends some bytes then drops the socket
//!   (RST-style).
//!
//! Every scenario asserts that `engine.stop` completes in bounded
//! time. Any kernel-level resource (the test process's open-socket
//! count) is implicitly capped by the test harness exiting; what we
//! check explicitly is that the *engine* doesn't wedge.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use rama_core::io::BridgeIo;
use rama_core::service::service_fn;
use rama_net::address::HostWithPort;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Peer behavior selector. Picked once per scenario; the listener's
/// accept loop applies the same behavior to every connection it
/// receives.
#[derive(Clone, Copy)]
enum PeerBehavior {
    EchoAndClose,
    EchoThenHalfClose,
    AcceptAndPark,
    EchoThenAbort,
}

async fn run_peer_listener(addr: SocketAddr, behavior: PeerBehavior) {
    let listener = TcpListener::bind(addr).await.expect("bind peer listener");
    loop {
        let (mut socket, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        tokio::spawn(async move {
            match behavior {
                PeerBehavior::EchoAndClose => {
                    let mut buf = vec![0u8; 8 * 1024];
                    if let Ok(n) = socket.read(&mut buf).await {
                        if n > 0 {
                            _ = socket.write_all(&buf[..n]).await;
                        }
                    }
                    _ = socket.shutdown().await;
                }
                PeerBehavior::EchoThenHalfClose => {
                    let mut buf = vec![0u8; 8 * 1024];
                    if let Ok(n) = socket.read(&mut buf).await {
                        if n > 0 {
                            _ = socket.write_all(&buf[..n]).await;
                        }
                    }
                    // Half-close the write side — read side stays
                    // open. This is the failure shape the
                    // production captures showed: peer sends FIN
                    // for its writes but never closes the read
                    // side, leaving the connection in FIN_WAIT_1
                    // on the proxy side until something else
                    // forces cleanup.
                    let (mut r, _w) = socket.split();
                    // `_w` dropped here sends FIN; keep `r` alive
                    // to keep the peer half-open until the test
                    // tears down.
                    let _ = r.read(&mut [0u8; 8]).await;
                }
                PeerBehavior::AcceptAndPark => {
                    // Mirror of a wedged server loop — accept, do
                    // nothing. The proxy must rely on its idle /
                    // cancel paths to recover.
                    let _hold = socket;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                PeerBehavior::EchoThenAbort => {
                    let mut buf = vec![0u8; 8 * 1024];
                    if let Ok(n) = socket.read(&mut buf).await {
                        if n > 0 {
                            _ = socket.write_all(&buf[..n]).await;
                        }
                    }
                    // Drop without a clean shutdown — closer to a
                    // mid-stream RST than a graceful close.
                    drop(socket);
                }
            }
        });
    }
}

fn run_one(behavior: PeerBehavior) {
    // Dedicated runtime so the listener task can keep running while
    // the test interacts with the engine via the blocking session
    // API. The session-API calls themselves block briefly on lock
    // acquisition but don't await, so they're safe from a
    // non-runtime thread.
    let rt = tokio::runtime::Runtime::new().expect("rt");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener); // free the bind, hand the port to the async listener
    let _peer = rt.spawn(run_peer_listener(addr, behavior));

    // Give the listener a moment to come up before the engine's
    // service tries to connect.
    std::thread::sleep(Duration::from_millis(20));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    let BridgeIo(mut ingress, _egress) = bridge;
                    // Connect to the loopback peer — this is real
                    // kernel-mediated I/O, unlike every other test
                    // module that uses an in-memory duplex.
                    let mut upstream = match TcpStream::connect(addr).await {
                        Ok(s) => s,
                        Err(_) => return Ok(()),
                    };
                    // Forward bytes between the client-facing
                    // ingress (a `TcpFlow`) and the real upstream
                    // socket. `copy_bidirectional` returns when
                    // either side closes; the bridge then unwinds
                    // through its normal close path.
                    let _ = tokio::io::copy_bidirectional(&mut ingress, &mut upstream).await;
                    Ok(())
                },
            )
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        udp_egress_options: None,
        };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(addr.port())),
        |_bytes| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    _ = session.on_client_bytes(b"hello e2e\n");

    // Give the service time to forward → peer to react → bridge to
    // observe. Each scenario completes within a few hundred ms; the
    // bound below is loose to absorb CI scheduling jitter.
    std::thread::sleep(Duration::from_millis(200));

    // Whichever way the peer chose to drop the connection, the
    // bridge must converge and the engine must stop in bounded time.
    session.cancel();
    drop(session);
    let stop_started = Instant::now();
    engine.stop(0);
    let stop_elapsed = stop_started.elapsed();
    assert!(
        stop_elapsed < Duration::from_secs(5),
        "engine.stop took {stop_elapsed:?} — bridge wedged?",
    );

    rt.shutdown_timeout(Duration::from_secs(1));
}

#[test]
fn e2e_loopback_clean_echo_close() {
    run_one(PeerBehavior::EchoAndClose);
}

#[test]
fn e2e_loopback_half_close() {
    run_one(PeerBehavior::EchoThenHalfClose);
}

#[test]
fn e2e_loopback_park_then_cancel() {
    run_one(PeerBehavior::AcceptAndPark);
}

#[test]
fn e2e_loopback_peer_abort() {
    run_one(PeerBehavior::EchoThenAbort);
}
