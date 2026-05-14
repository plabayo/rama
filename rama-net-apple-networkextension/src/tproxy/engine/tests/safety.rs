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

/// `cancel()` must serialise against an in-flight TCP user callback.
/// Both sides take `callback_active.lock()`, so a callback that's
/// mid-dispatch (holding the lock through the user closure) blocks
/// `cancel()` until it returns. The Swift callback box can therefore
/// only be released after the dispatch completes.
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
        tcp_egress_options: None,
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

/// A TCP bridge whose `on_server_bytes` returns `Paused` indefinitely
/// must close itself within `paused_drain_max_wait`; otherwise
/// `engine.stop()` hangs on the unreleased per-flow guard.
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
        tcp_egress_options: None,
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

/// A UDP service that never completes must be reaped by
/// `udp_max_flow_lifetime`; otherwise the per-flow service task and
/// its state live forever.
#[test]
fn udp_max_flow_lifetime_closes_stuck_service() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|_bridge: crate::UdpFlow| async move {
                // Never returns — the test verifies the timeout
                // wraps and aborts this future.
                std::future::pending::<()>().await;
                Ok(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
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
    session.activate();

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

/// UDP `on_client_read_demand` must fire on every accepted *and*
/// dropped-on-Full datagram. Swift's `requestRead` re-issues
/// `flow.readDatagrams` only when `demandPending` is set during the
/// in-flight read; omitting demand on overflow strands the flow
/// after the first saturating burst.
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
            //
            // The bridge MUST be moved into the future and held — an
            // `async move` only captures names referenced in its
            // body, so a `|_bridge| async move { pending().await }`
            // shape would drop `_bridge` (and therefore the
            // ingress mpsc receiver) at the end of the closure call,
            // closing the client channel underneath us in a
            // worker-vs-test-thread race. Real services keep bridge
            // alive by actually using it; the test mimics that with
            // an explicit hold.
            service: service_fn(|bridge: crate::UdpFlow| async move {
                let _hold = bridge;
                std::future::pending::<Result<(), Infallible>>().await
            })
            .boxed(),
        }),
        tcp_egress_options: None,
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
    session.activate();

    // Push 8 datagrams. Channel capacity is 2 and the service never
    // reads, so 6 will hit `Full`. Demand must fire on every push.
    let pushed = 8usize;
    for i in 0..pushed {
        session.on_client_datagram(format!("datagram {i}").as_bytes(), None);
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

/// UDP `on_client_close` must let the service task run its close
/// epilogue (close-event emission, dial9 record, `closed_sink`).
/// `flow_guard.cancelled()` is wired into the service task's
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
            service: service_fn(|_bridge: crate::UdpFlow| async move {
                std::future::pending::<Result<(), Infallible>>().await
            })
            .boxed(),
        }),
        tcp_egress_options: None,
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
    session.activate();

    // Give activate's bridge_tx → service_task wiring a moment to
    // reach the select! before we close. Without this the service
    // could still be parked on `bridge_rx.await`, falling into the
    // synthetic-close branch instead.
    std::thread::sleep(Duration::from_millis(20));

    // The closed_sink is the user-supplied callback, but it's
    // routed through `guarded_closed_sink(callback_active, ...)`.
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

/// `on_client_close` flips `callback_active` first; subsequent
/// datagrams must not reach the user closure.
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
            service: service_fn(|_bridge: crate::UdpFlow| async move {
                std::future::pending::<()>().await;
                Ok(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
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
    session.activate();

    // Push a datagram; the demand sink should fire (and the bridge
    // should accept the datagram into the channel).
    session.on_client_datagram(b"hello", None);
    // Tear down. After this returns, no further user callbacks fire.
    session.on_client_close();
    let demand_after_close = demand.load(Ordering::Relaxed);

    // Try to push another datagram after close. The session is closed,
    // so the user demand callback MUST NOT fire.
    session.on_client_datagram(b"after-close", None);
    std::thread::sleep(Duration::from_millis(25));

    assert_eq!(
        demand.load(Ordering::Relaxed),
        demand_after_close,
        "no user demand callback may fire after on_client_close()"
    );

    engine.stop(0);
}

/// Each `on_server_bytes` invocation blocks the bridge task that
/// called it until the user closure returns. If the dispatcher
/// embeds a synchronous wait on a Swift dispatch queue inside that
/// closure (the historical shape) and several flows end up with
/// stalled queues at the same time, every Tokio worker can land on
/// a blocked closure and the runtime stops scheduling. The engine's
/// shutdown path then wedges because the bridge tasks holding
/// flow-guard clones never unblock.
///
/// Pin the property: even with N concurrent sessions whose
/// `on_server_bytes` blocks longer than any single Tokio worker, the
/// engine must still complete `stop()` within bounded time. The
/// underlying invariant — bridge tasks must not be held hostage to
/// arbitrary user-closure stalls — is what the dispatcher's
/// `queue.async`-with-atomics shape preserves on the Swift side.
#[test]
fn tcp_engine_stop_completes_when_on_server_bytes_callbacks_block() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    let BridgeIo(mut ingress, _egress) = bridge;
                    // Continuously produce bytes so the bridge keeps
                    // calling on_server_bytes until cancel.
                    loop {
                        if ingress.write_all(b"X").await.is_err() {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                    Ok(())
                },
            )
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
    };
    let engine = build_engine(handler);

    const SESSIONS: usize = 8;
    let mut sessions = Vec::with_capacity(SESSIONS);
    for _ in 0..SESSIONS {
        let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
            TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
                .with_remote_endpoint(HostWithPort::example_domain_with_port(443)),
            // on_server_bytes intentionally blocks the calling
            // bridge task on a sync sleep — this is the shape of a
            // Swift-side `queue.sync` against a stalled flow queue.
            |_bytes| {
                std::thread::sleep(Duration::from_millis(80));
                TcpDeliverStatus::Accepted
            },
            || {},
            || {},
        ) else {
            panic!("expected intercept session");
        };
        session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
        sessions.push(session);
    }

    // Let bridge work pile up so several workers land in the
    // blocking callback before we stop.
    std::thread::sleep(Duration::from_millis(50));

    let started = Instant::now();
    drop(sessions);
    engine.stop(0);
    let elapsed = started.elapsed();

    // Bridge tasks must observe their flow-guard cancellation and
    // exit the user closure within bounded time. Allow 3 s slack
    // for the slowest closure to return on a busy CI machine; a
    // wedged runtime would never finish (the historical bug needed
    // a force-kill).
    assert!(
        elapsed < Duration::from_secs(3),
        "engine.stop() took {elapsed:?} with blocking on_server_bytes; runtime is wedged",
    );
}
