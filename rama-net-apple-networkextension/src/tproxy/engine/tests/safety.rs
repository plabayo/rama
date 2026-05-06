//! Safety-property tests for the engine: cancel-vs-callback races, the
//! Paused-wait wedge backstop, and the UDP max-flow-lifetime cap.
//!
//! These tests target the audit findings #1 (UAF in `guarded_*_sink`),
//! #2 (UDP guard parity), #3 (Paused-wait timeout), and #6
//! (`udp_max_flow_lifetime`). They're written to fail loudly if a
//! future refactor regresses any of those properties.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use rama_core::io::BridgeIo;
use rama_core::service::service_fn;
use rama_net::address::HostWithPort;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

/// Audit #1: cancel() must serialise against any in-flight TCP user
/// callback. The fixed `guarded_bytes_status_sink` holds
/// `callback_active.lock()` across the user closure; cancel() also
/// takes `callback_active.lock()` to flip the flag, so it MUST block
/// until the closure returns. Without that lock-across-callback
/// property, cancel could free the Swift callback box while the bridge
/// is mid-dispatch (real UAF).
///
/// The test:
/// 1. Installs an `on_server_bytes` that holds a `parking_lot::Mutex`
///    while in the user closure. The test thread holds that mutex
///    initially, so the closure blocks once it's invoked.
/// 2. Triggers the bridge (the per-flow service writes a chunk that
///    arrives at the bridge's read half, which calls `on_server_bytes`).
/// 3. Spawns `session.cancel()` on a background thread.
/// 4. After a short pause, asserts `cancel()` has NOT yet returned —
///    proving it's blocked on `callback_active.lock()` because the
///    bridge thread is still inside the closure with that lock held.
/// 5. Releases the closure's mutex; asserts cancel completes.
/// 6. Asserts the closure ran exactly once (no UAF / spurious
///    re-dispatch).
#[test]
fn tcp_cancel_serialises_against_inflight_user_callback() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    let BridgeIo(mut ingress, _egress) = bridge;
                    // One write into ingress is enough — the bridge
                    // reads it and dispatches to `on_server_bytes`.
                    _ = ingress.write_all(b"trigger").await;
                    Ok(())
                },
            )
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine(handler);

    // The closure spins on a flag flipped by the test thread; until
    // then it blocks the bridge worker. Sleep-spinning a tokio worker
    // is OK in this test (multi-thread runtime, 2 workers, the other
    // is free to run cancel and the engine's shutdown machinery).
    let released = Arc::new(AtomicBool::new(false));

    let entered = Arc::new(AtomicBool::new(false));
    let invocations = Arc::new(AtomicUsize::new(0));

    let entered_cb = entered.clone();
    let invocations_cb = invocations.clone();
    let released_cb = released.clone();

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(443)),
        move |_bytes| {
            entered_cb.store(true, Ordering::Release);
            invocations_cb.fetch_add(1, Ordering::Relaxed);
            // Block until the test thread releases.
            while !released_cb.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(2));
            }
            TcpDeliverStatus::Accepted
        },
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    // Wait for the bridge to enter the user closure (bounded; if the
    // service or bridge wiring breaks, fail loudly).
    let entry_deadline = Instant::now() + Duration::from_secs(2);
    while !entered.load(Ordering::Acquire) {
        if Instant::now() > entry_deadline {
            panic!("user closure was never invoked (bridge wiring broken?)");
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    // Spawn cancel on a worker thread. The user closure is still
    // blocked, so cancel() should block on `callback_active.lock()`.
    let cancel_done = Arc::new(AtomicBool::new(false));
    let cancel_thread = {
        let cancel_done = cancel_done.clone();
        std::thread::spawn(move || {
            session.cancel();
            cancel_done.store(true, Ordering::Release);
        })
    };

    // Sleep a bit; cancel() must NOT have returned yet (callback still in flight).
    std::thread::sleep(Duration::from_millis(75));
    assert!(
        !cancel_done.load(Ordering::Acquire),
        "cancel() must block while a user callback is in-flight under the callback_active mutex"
    );

    // Release the callback. cancel() should now complete.
    released.store(true, Ordering::Release);

    cancel_thread.join().expect("cancel thread join");
    assert!(cancel_done.load(Ordering::Acquire));

    // Sanity: the closure ran exactly once. A UAF / re-dispatch after
    // cancel would surface as additional invocations.
    assert_eq!(invocations.load(Ordering::Relaxed), 1);

    engine.stop(0);
}

/// Audit #3: a per-flow TCP bridge whose `on_server_bytes` returns
/// `Paused` and whose drain signal is never delivered must close on
/// its own within the configured `paused_drain_max_wait`. Without the
/// timeout the bridge wedges forever and `engine.stop()` hangs because
/// the per-flow `flow_guard` never drops.
#[test]
fn tcp_paused_wait_closes_within_max_wait_when_drain_never_fires() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    let BridgeIo(mut ingress, _egress) = bridge;
                    _ = ingress.write_all(b"first").await;
                    // Hold the service open so the bridge stays alive
                    // long enough to observe the timeout.
                    std::future::pending::<()>().await;
                    Ok(())
                },
            )
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine_with_tcp_paused_drain_max_wait(handler, Duration::from_millis(150));

    let closed = Arc::new(AtomicUsize::new(0));
    let closed_cb = closed.clone();

    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(443)),
        // Always pause: the bridge will store the chunk in
        // `pending_to_server` and park on `server_write_notify`.
        // Without a bounded paused-wait, this hangs forever. We never
        // fire `signal_server_drain` — the test's whole point is that
        // the bridge times out by itself.
        |_bytes| TcpDeliverStatus::Paused,
        || {},
        move || {
            closed_cb.fetch_add(1, Ordering::Relaxed);
        },
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    // Configured wait is 150ms. Give a generous slack.
    let deadline = Instant::now() + Duration::from_millis(750);
    while closed.load(Ordering::Relaxed) == 0 {
        if Instant::now() > deadline {
            panic!(
                "paused-wait did not fire within slack window (configured 150ms; on_server_closed never invoked)"
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // After the bridge times out, on_server_closed must have run.
    assert!(closed.load(Ordering::Relaxed) >= 1);

    let stop_started = Instant::now();
    engine.stop(0);
    // engine.stop() blocks until all flow guards drop. If the bridge
    // had wedged, this would hang for 60s (the default constant).
    assert!(stop_started.elapsed() < Duration::from_secs(2));
}

/// Audit #6: a misbehaving UDP service that never returns must be
/// closed by `udp_max_flow_lifetime`, otherwise the per-flow service
/// task lives forever and per-flow state leaks.
#[test]
fn udp_max_flow_lifetime_closes_stuck_service() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |_bridge: BridgeIo<crate::UdpFlow, crate::NwUdpSocket>| async move {
                    // Never returns — the test verifies the timeout
                    // wraps and aborts this future.
                    std::future::pending::<()>().await;
                    Ok(())
                },
            )
            .boxed(),
        }),
    };
    let engine = build_engine_with_udp_max_flow_lifetime(handler, Duration::from_millis(150));

    let closed = Arc::new(AtomicUsize::new(0));
    let closed_cb = closed.clone();

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(53)),
        |_bytes| {},
        || {},
        move || {
            closed_cb.fetch_add(1, Ordering::Relaxed);
        },
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| {});

    let deadline = Instant::now() + Duration::from_millis(750);
    while closed.load(Ordering::Relaxed) == 0 {
        if Instant::now() > deadline {
            panic!(
                "udp_max_flow_lifetime did not fire within slack window (configured 150ms; on_server_closed never invoked)"
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(closed.load(Ordering::Relaxed) >= 1);
    engine.stop(0);
}

/// Audit #2 sanity: a UDP `on_client_close` flips `callback_active`
/// before any further dispatch can reach Swift. Verifies that even if
/// Swift races a datagram delivery against the close, the user
/// closure isn't reached after `on_client_close` returns.
///
/// (We can't directly test the cross-thread UAF on UDP without the
/// FFI surface — that lands in Layer 2 / sanitizer testing — but we
/// can verify the synchronous "no callbacks after close" property
/// here.)
#[test]
fn udp_on_client_close_suppresses_subsequent_dispatch() {
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

    let demand = Arc::new(AtomicUsize::new(0));
    let demand_cb = demand.clone();
    // We only assert against the demand counter (the bridge's
    // backpressure path is what re-fires `on_client_read_demand`); the
    // datagram counter would require pumping the bridge to the user
    // service, which the test's never-ready service doesn't reach.
    let datagram = Arc::new(AtomicUsize::new(0));

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(53)),
        move |_bytes| {
            datagram.fetch_add(1, Ordering::Relaxed);
        },
        move || {
            demand_cb.fetch_add(1, Ordering::Relaxed);
        },
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| {});

    // Push a datagram; the demand sink should fire (and the bridge
    // should accept the datagram into the channel).
    session.on_client_datagram(b"hello");
    // Tear down. After this returns, no further user callbacks fire.
    session.on_client_close();
    let demand_after_close = demand.load(Ordering::Relaxed);

    // Try to push another datagram after close. The session is closed,
    // so the user demand callback MUST NOT fire.
    session.on_client_datagram(b"after-close");
    std::thread::sleep(Duration::from_millis(25));

    assert_eq!(
        demand.load(Ordering::Relaxed),
        demand_after_close,
        "no user demand callback may fire after on_client_close()"
    );

    engine.stop(0);
}
