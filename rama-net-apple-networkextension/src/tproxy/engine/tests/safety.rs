//! Safety-property tests for the engine: cancel-vs-callback races, the
//! Paused-wait wedge backstop, and the UDP max-flow-lifetime cap.
//!
//! bugs found regarding:
//! * UAF in `guarded_*_sink`
//! * UDP guard parity
//! * Paused-wait timeout
//! * `udp_max_flow_lifetime`

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

/// cancel() must serialise against any in-flight TCP user
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

/// a per-flow TCP bridge whose `on_server_bytes` returns
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

/// a misbehaving UDP service that never returns must be
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

/// UDP `on_client_read_demand` MUST
/// continue firing on the `Full` arm. Swift's `requestRead` is the
/// only mechanism that re-issues `flow.readDatagrams`; it gates the
/// re-issue on a `demandPending` flag that's set by the demand
/// callback. If we omit demand on overflow, a saturating burst that
/// drops one datagram leaves Swift's `demandPending = false` and the
/// flow stalls forever after the next read completion.
///
/// Verifies: after a sequence of accepted + dropped datagrams, the
/// demand callback was invoked at least once per datagram so Swift
/// has at least as many "pump again" signals as datagrams pushed.
#[test]
fn udp_on_client_datagram_fires_demand_on_overflow_so_swift_keeps_pumping() {
    use std::convert::Infallible;
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            // A service that never reads: the bridge channel saturates
            // on the first burst. We rely on `on_client_datagram` to
            // keep pumping demand so Swift eventually issues another
            // `readDatagrams` once the consumer drains.
            service: service_fn(
                |_bridge: BridgeIo<crate::UdpFlow, crate::NwUdpSocket>| async move {
                    std::future::pending::<Result<(), Infallible>>().await
                },
            )
            .boxed(),
        }),
    };
    // Tiny channel capacity so we hit Full quickly.
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_udp_channel_capacity(2)
        .build()
        .expect("build engine");

    let demand_calls = Arc::new(AtomicUsize::new(0));
    let demand_cb = demand_calls.clone();

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(53)),
        |_bytes| {},
        move || {
            demand_cb.fetch_add(1, Ordering::Relaxed);
        },
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| {});

    // Push 8 datagrams. Channel capacity is 2 and the service never
    // reads, so 6 will hit `Full`. Demand must fire on every push.
    let pushed = 8usize;
    for i in 0..pushed {
        session.on_client_datagram(format!("datagram {i}").as_bytes());
    }

    assert_eq!(
        demand_calls.load(Ordering::Relaxed),
        pushed,
        "on_client_read_demand must fire on every datagram (Ok and Full both); \
         dropping demand on Full stalls Swift's `requestRead` cycle"
    );

    session.on_client_close();
    engine.stop(0);
}

/// UDP `on_client_close` MUST let the
/// service task run its close epilogue. Aborting the task drops the
/// future mid-`select!`, skipping the `closed_sink()`,
/// dial9 `record_flow_closed`, and structured `tracing::info!` close
/// event — every clean Swift teardown would lose the close record.
///
/// The fix wires `flow_guard.cancelled()` into the service task's
/// `select!`, and `on_client_close` signals shutdown via
/// `flow_stop_tx` instead of aborting. Verifies the close-related
/// callbacks fire on a clean teardown of an active session.
#[test]
fn udp_on_client_close_runs_service_close_epilogue() {
    use std::convert::Infallible;
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            // Service runs forever — the close path is what brings
            // the task down, not the service itself.
            service: service_fn(
                |_bridge: BridgeIo<crate::UdpFlow, crate::NwUdpSocket>| async move {
                    std::future::pending::<Result<(), Infallible>>().await
                },
            )
            .boxed(),
        }),
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(53)),
        |_bytes| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| {});

    // Give activate's bridge_tx → service_task wiring a moment to
    // reach the select! before we close. Without this the service
    // could still be parked on `bridge_rx.await`, falling into the
    // synthetic-close branch instead.
    std::thread::sleep(Duration::from_millis(20));

    // The closed_sink is the user-supplied callback, but it's routed
    // through `guarded_closed_sink(callback_active, ...)`.
    // `on_client_close` flips `callback_active` *before* signalling
    // shutdown, so the user closure won't run. We instead observe
    // that the service task ran to completion (close epilogue
    // emitted the dial9 / tracing event) by waiting for
    // `engine.stop()` to drain — if the task were detached without
    // shutdown observation, stop() would block on its flow_guard.
    session.on_client_close();
    drop(session);

    let stop_started = Instant::now();
    engine.stop(0);
    assert!(
        stop_started.elapsed() < Duration::from_secs(2),
        "engine.stop() after on_client_close took {:?} — service task did not exit",
        stop_started.elapsed(),
    );
}

/// a UDP `on_client_close` flips `callback_active`
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
