//! Engine-integration tests for `PromoteHandle` / `PromoteLayer`.
//!
//! These cover the public-surface contract: that every Intercept flow
//! gets a `PromoteHandle` in its `TcpFlow::extensions()`, that
//! `PromoteLayer` composes with an inner service, and that calling
//! `into_passthrough` does not break the existing read/write semantics
//! for that flow.
//!
//! The stub engine cutover used here returns `Ok(())` immediately —
//! follow-up commits will replace it with the real Swift-coordinated
//! cutover protocol. Tests written here MUST stay green when that lands.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use parking_lot::Mutex;
use rama_core::Layer;
use rama_core::extensions::ExtensionsRef;
use rama_core::io::BridgeIo;
use rama_core::service::service_fn;
use rama_net::address::HostWithPort;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[test]
fn intercept_flow_has_promote_handle_in_extensions() {
    let saw_handle = Arc::new(Mutex::new(false));
    let saw_handle_clone = saw_handle.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let done_tx = Mutex::new(Some(done_tx));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let saw_handle = saw_handle_clone.clone();
            let done_tx = done_tx.lock().take().expect("single intercept");
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                        let saw_handle = saw_handle.clone();
                        let done_tx = done_tx.clone();
                        async move {
                            let BridgeIo(ingress, _egress) = bridge;
                            let present = ingress.extensions().get_ref::<PromoteHandle>().is_some();
                            *saw_handle.lock() = present;
                            _ = done_tx.send(());
                            Ok(())
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

    let engine = build_engine(handler);
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
    // Push a byte so `saw_client_bytes` flips true — otherwise `on_client_eof`
    // cancels the session (which aborts the service task before it can run).
    assert_eq!(session.on_client_bytes(&[0u8]), TcpDeliverStatus::Accepted);
    session.on_client_eof();

    _ = done_rx.recv_timeout(Duration::from_secs(5));
    assert!(
        *saw_handle.lock(),
        "PromoteHandle missing from ingress extensions"
    );

    engine.stop(0);
}

#[test]
fn promote_layer_wraps_inner_service_and_into_passthrough_completes() {
    let received = Arc::new(Mutex::new(Vec::<u8>::new()));
    let received_clone = received.clone();
    let promote_done = Arc::new(Mutex::new(false));
    let promote_done_clone = promote_done.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let done_tx_handler = Mutex::new(Some(done_tx));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let received = received_clone.clone();
            let promote_done = promote_done_clone.clone();
            let done_tx = done_tx_handler.lock().take().expect("single intercept");

            // Inner service: byte sink that reads ingress until EOF.
            // Note: done_tx is signalled from the OUTER wrapper below,
            // not here — signalling from inside the inner service races
            // against the outer's `*promote_done.lock() = true` and the
            // main thread can race ahead and read `promote_done` while
            // the outer is still unwinding its `.await`.
            let inner = service_fn(
                move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                    let received = received.clone();
                    async move {
                        let BridgeIo(mut ingress, _egress) = bridge;
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match ingress.read(&mut buf).await {
                                Ok(0) | Err(_) => return Ok(()),
                                Ok(n) => {
                                    received.lock().extend_from_slice(&buf[..n]);
                                }
                            }
                        }
                    }
                },
            );

            // Outer service: PromoteLayer wraps inner. Layer fires promote,
            // observes success, delegates to inner. Inner reads bytes as
            // usual (stub cutover does NOT change byte routing). Signal
            // `done_tx` only after `promote_done` is set so the main
            // thread observes a fully-settled state.
            let wrapped = PromoteLayer::new().layer(inner);
            let wrapped = service_fn(move |bridge| {
                use rama_core::service::Service;
                let wrapped = wrapped.clone();
                let promote_done = promote_done.clone();
                let done_tx = done_tx.clone();
                async move {
                    let r = wrapped.serve(bridge).await;
                    // If we got here, the layer called into_passthrough
                    // then ran inner to completion (inner saw EOF).
                    *promote_done.lock() = true;
                    _ = done_tx.send(());
                    r
                }
            });

            FlowAction::Intercept {
                meta,
                service: wrapped.boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };

    let engine = build_engine(handler);
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

    // Send some bytes, then EOF.
    let payload: Vec<u8> = (0..2000_u32).map(|i| (i as u8).wrapping_mul(7)).collect();
    let mut sent = 0;
    while sent < payload.len() {
        let end = (sent + 64).min(payload.len());
        match session.on_client_bytes(&payload[sent..end]) {
            TcpDeliverStatus::Accepted => sent = end,
            TcpDeliverStatus::Paused => std::thread::sleep(Duration::from_millis(1)),
            TcpDeliverStatus::Closed => panic!("session closed unexpectedly"),
        }
    }
    session.on_client_eof();

    _ = done_rx.recv_timeout(Duration::from_secs(5));
    assert_eq!(
        *received.lock(),
        payload,
        "inner service did not receive full byte stream"
    );
    assert!(*promote_done.lock(), "PromoteLayer did not complete");

    engine.stop(0);
}

// ── Real-cutover (Swift-coordinated) tests ───────────────────────────
//
// These exercise the engine plumbing introduced by the real cutover:
// `register_promote_request_callback` + `confirm_promoted`. They use
// the Rust-typed registration shim — the FFI shape is asserted
// separately in tests/transparent_proxy_macro.rs.
//
// Test harness: `spawn_session_running_into_passthrough` builds an
// intercept-only handler whose service runs the promote handle and
// forwards the result to a `std::sync::mpsc`. Tests then drive the
// session from the main thread (register/confirm/cancel) and
// observe.

/// Returned by the helper service: the result of `into_passthrough`
/// (the only thing the service does before exiting).
type PromoteResult = Result<(), PromoteError>;

/// Build a TestHandler whose service captures the promote handle,
/// invokes `into_passthrough`, sends the result on `result_tx`, then
/// returns — letting the bridge drive the per-flow close path.
fn handler_running_into_passthrough(
    result_tx: std::sync::mpsc::Sender<PromoteResult>,
) -> TestHandler {
    let result_tx = Mutex::new(Some(result_tx));
    TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let result_tx = result_tx.lock().take().expect("single intercept");
            let service = service_fn(
                move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                    let result_tx = result_tx.clone();
                    async move {
                        let BridgeIo(ingress, _egress) = bridge;
                        let handle = ingress
                            .extensions()
                            .get_ref::<PromoteHandle>()
                            .cloned()
                            .expect("PromoteHandle in extensions");
                        let r = handle.into_passthrough().await;
                        _ = result_tx.send(r);
                        Ok(())
                    }
                },
            );
            FlowAction::Intercept {
                meta,
                service: service.boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    }
}

/// Spin up a session whose service calls `into_passthrough`. The
/// session is left activated and not cancelled — the test drives the
/// callback / confirm protocol from the outside.
fn spawn_session_running_into_passthrough() -> (
    TransparentProxyEngine<TestHandler>,
    crate::tproxy::TransparentProxyTcpSession,
    std::sync::mpsc::Receiver<PromoteResult>,
) {
    let (tx, rx) = std::sync::mpsc::channel::<PromoteResult>();
    let handler = handler_running_into_passthrough(tx);
    let engine = build_engine(handler);
    let SessionFlowAction::Intercept(session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    (engine, session, rx)
}

#[test]
fn engine_promote_fires_swift_callback_and_returns_ok_on_confirm() {
    let (engine, mut session, result_rx) = spawn_session_running_into_passthrough();

    let (cb_tx, cb_rx) = std::sync::mpsc::channel::<()>();
    let cb_tx = Mutex::new(Some(cb_tx));
    session.register_promote_request_callback(move || {
        if let Some(tx) = cb_tx.lock().take() {
            _ = tx.send(());
        }
    });

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    // Push a byte so `saw_client_bytes` flips — otherwise `on_client_eof`
    // (driven by the bridge after Ok-confirm) doesn't unblock cleanly.
    assert_eq!(session.on_client_bytes(&[0u8]), TcpDeliverStatus::Accepted);

    // Wait for the Swift callback to fire.
    cb_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("promote callback fired");

    // ACK the cutover.
    session.confirm_promoted(Ok(()));

    let r = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("service reported into_passthrough result");
    assert!(matches!(r, Ok(())), "expected Ok, got {r:?}");

    engine.stop(0);
}

#[test]
fn engine_promote_propagates_swift_cutover_failed_error() {
    let (engine, mut session, result_rx) = spawn_session_running_into_passthrough();

    let (cb_tx, cb_rx) = std::sync::mpsc::channel::<()>();
    let cb_tx = Mutex::new(Some(cb_tx));
    session.register_promote_request_callback(move || {
        if let Some(tx) = cb_tx.lock().take() {
            _ = tx.send(());
        }
    });

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    assert_eq!(session.on_client_bytes(&[0u8]), TcpDeliverStatus::Accepted);
    cb_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("promote callback fired");

    session.confirm_promoted(Err(PromoteError::SwiftCutoverFailed {
        reason: "no NWConnection state".into(),
    }));

    let r = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("service reported into_passthrough result");
    match r {
        Err(PromoteError::SwiftCutoverFailed { reason }) => {
            assert_eq!(reason, "no NWConnection state");
        }
        other => panic!("expected SwiftCutoverFailed, got {other:?}"),
    }

    engine.stop(0);
}

#[test]
fn engine_promote_without_registered_callback_returns_egress_unavailable() {
    let (engine, mut session, result_rx) = spawn_session_running_into_passthrough();

    // No callback registered.

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    assert_eq!(session.on_client_bytes(&[0u8]), TcpDeliverStatus::Accepted);
    // No `confirm_promoted` needed — fire returns synchronously.

    let r = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("service reported into_passthrough result");
    assert!(
        matches!(r, Err(PromoteError::EgressUnavailable)),
        "expected EgressUnavailable, got {r:?}",
    );

    // Drive the service to completion so engine.stop() doesn't hang
    // waiting for an active flow.
    session.on_client_eof();
    engine.stop(0);
}

#[test]
fn engine_promote_session_cancel_during_pending_ack_does_not_hang() {
    // Cancel races against the awaiting `fire` future:
    //
    //   * `cancel()` first calls `promote_registry.abort_pending()`,
    //     which drops the ACK `oneshot::Sender`. That schedules a
    //     wake on the awaiting fire future (resolves to
    //     `EngineShuttingDown`).
    //   * Then `cancel()` calls `service_task.abort()`. Tokio's
    //     abort flag is checked BEFORE polling, so depending on
    //     scheduling, the wake from step (a) may or may not be
    //     observed before the abort short-circuits the next poll.
    //
    // Both outcomes are semantically acceptable: cancel's only
    // promise is that no waiter hangs forever.
    let (engine, mut session, result_rx) = spawn_session_running_into_passthrough();

    let (cb_tx, cb_rx) = std::sync::mpsc::channel::<()>();
    let cb_tx = Mutex::new(Some(cb_tx));
    session.register_promote_request_callback(move || {
        if let Some(tx) = cb_tx.lock().take() {
            _ = tx.send(());
        }
    });

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    assert_eq!(session.on_client_bytes(&[0u8]), TcpDeliverStatus::Accepted);
    cb_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("promote callback fired");

    session.cancel();

    // Either the fire future observed the dropped ACK before
    // abort (EngineShuttingDown), or the service task was aborted
    // before the wake landed (Disconnected). Both satisfy
    // cancel's only contract: nobody hangs.
    let r = result_rx.recv_timeout(Duration::from_secs(5));
    match r {
        Ok(Err(PromoteError::EngineShuttingDown))
        | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("cancel hung: in-flight promote never resolved");
        }
        Ok(other) => panic!("unexpected promote result: {other:?}"),
    }

    engine.stop(0);
}

/// Unit-level proof that `abort_pending` resolves an in-flight
/// `into_passthrough` with `EngineShuttingDown`. This is the
/// deterministic counterpart to the
/// `_does_not_hang` integration test above — no service task, no
/// abort race.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_abort_pending_during_into_passthrough_resolves_with_engine_shutting_down() {
    use crate::tproxy::engine::promote::{PromoteRegistry, PromoteRequestCallback};

    // No-op FFI-shape callback; we only care about abort semantics.
    unsafe extern "C" fn noop(_ctx: *mut std::ffi::c_void) {}

    let registry = PromoteRegistry::new(
        Arc::new(parking_lot::Mutex::new(None)),
        Arc::new(parking_lot::Mutex::new(None)),
        Arc::new(parking_lot::Mutex::new(true)),
    );
    registry.register_raw(PromoteRequestCallback {
        context: 0,
        on_promote_request: noop,
    });
    let rt = tokio::runtime::Handle::current();
    let handle = registry.clone().into_handle(rt);

    // Start the awaiter, then abort.
    let task = tokio::spawn(async move { handle.into_passthrough().await });
    // Yield until the fire installed a pending ACK. Polling loop
    // bounded by 500 ms to avoid eternal hang if the design ever
    // regresses.
    for _ in 0..50 {
        if registry.has_pending_ack() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        registry.has_pending_ack(),
        "fire installed pending ACK within budget",
    );

    registry.abort_pending();

    let r = task.await.expect("task joined");
    assert!(
        matches!(r, Err(PromoteError::EngineShuttingDown)),
        "expected EngineShuttingDown, got {r:?}",
    );
}

#[test]
fn engine_promote_confirm_after_cancel_is_no_op() {
    // After cancel, the pending ACK sender is already dropped.
    // Subsequent `confirm_promoted` calls must not panic and must
    // not affect the cancellation outcome.
    let (engine, mut session, result_rx) = spawn_session_running_into_passthrough();

    let (cb_tx, cb_rx) = std::sync::mpsc::channel::<()>();
    let cb_tx = Mutex::new(Some(cb_tx));
    session.register_promote_request_callback(move || {
        if let Some(tx) = cb_tx.lock().take() {
            _ = tx.send(());
        }
    });

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    assert_eq!(session.on_client_bytes(&[0u8]), TcpDeliverStatus::Accepted);
    cb_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("promote callback fired");

    // Confirm AFTER cancel: pending ACK already dropped → no-op.
    session.cancel();
    session.confirm_promoted(Ok(())); // must not panic
    session.confirm_promoted(Ok(())); // and remains a no-op on repeat

    // Same race as `_does_not_hang`: either the wake from
    // abort_pending was observed (EngineShuttingDown) or abort
    // landed first (Disconnected). Both are acceptable.
    let r = result_rx.recv_timeout(Duration::from_secs(5));
    match r {
        Ok(Err(PromoteError::EngineShuttingDown))
        | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("cancel + confirm sequence hung")
        }
        Ok(other) => panic!("unexpected promote result: {other:?}"),
    }

    engine.stop(0);
}

#[test]
fn engine_promote_callback_fires_at_most_once_under_concurrent_into_passthrough() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Variant of `handler_running_into_passthrough` that spawns N
    // concurrent into_passthrough callers off the single service
    // task, so the CAS-guarded fire-at-most-once contract is
    // exercised against a real engine-side registry.
    let (tx, rx) = std::sync::mpsc::channel::<PromoteResult>();
    let tx_mtx = Mutex::new(Some(tx));
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let result_tx = tx_mtx.lock().take().expect("single intercept");
            let service = service_fn(
                move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                    let result_tx = result_tx.clone();
                    async move {
                        let BridgeIo(ingress, _egress) = bridge;
                        let handle = ingress
                            .extensions()
                            .get_ref::<PromoteHandle>()
                            .cloned()
                            .expect("PromoteHandle in extensions");
                        let (h1, h2, h3) = (handle.clone(), handle.clone(), handle);
                        let (a, b, c) = tokio::join!(
                            tokio::spawn(async move { h1.into_passthrough().await }),
                            tokio::spawn(async move { h2.into_passthrough().await }),
                            tokio::spawn(async move { h3.into_passthrough().await }),
                        );
                        // All three callers must see the same result.
                        for r in [a.unwrap(), b.unwrap(), c.unwrap()] {
                            _ = result_tx.send(r);
                        }
                        Ok(())
                    }
                },
            );
            FlowAction::Intercept {
                meta,
                service: service.boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };

    let engine = build_engine(handler);
    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    let callback_count = Arc::new(AtomicUsize::new(0));
    let (cb_tx, cb_rx) = std::sync::mpsc::channel::<()>();
    let cb_tx = Mutex::new(Some(cb_tx));
    {
        let callback_count = callback_count.clone();
        session.register_promote_request_callback(move || {
            callback_count.fetch_add(1, Ordering::SeqCst);
            if let Some(tx) = cb_tx.lock().take() {
                _ = tx.send(());
            }
        });
    }

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    assert_eq!(session.on_client_bytes(&[0u8]), TcpDeliverStatus::Accepted);
    cb_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("promote callback fired");

    session.confirm_promoted(Ok(()));

    // Drain all three results.
    let r1 = rx.recv_timeout(Duration::from_secs(5)).expect("r1");
    let r2 = rx.recv_timeout(Duration::from_secs(5)).expect("r2");
    let r3 = rx.recv_timeout(Duration::from_secs(5)).expect("r3");
    for r in [&r1, &r2, &r3] {
        assert!(matches!(r, Ok(())), "expected Ok, got {r:?}");
    }
    assert_eq!(
        callback_count.load(Ordering::SeqCst),
        1,
        "promote callback fired exactly once across concurrent callers",
    );

    engine.stop(0);
}

#[test]
fn engine_promote_ok_drains_inflight_bytes_then_emits_eof_to_service() {
    // Push bytes BEFORE confirm: the service should see every one of
    // them before EOF, then exit. Zero-byte-loss invariant for the
    // ingress direction.

    // Service: collect bytes from ingress, then signal completion.
    let received = Arc::new(Mutex::new(Vec::<u8>::new()));
    let received_clone = received.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let (cb_tx, cb_rx) = std::sync::mpsc::channel::<()>();
    let cb_tx_mtx = Mutex::new(Some(cb_tx));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let received = received_clone.clone();
            let done_tx = done_tx.clone();
            let service = service_fn(
                move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                    let received = received.clone();
                    let done_tx = done_tx.clone();
                    async move {
                        let BridgeIo(mut ingress, _egress) = bridge;
                        let handle = ingress
                            .extensions()
                            .get_ref::<PromoteHandle>()
                            .cloned()
                            .expect("PromoteHandle in extensions");
                        // Promote first, then drain — matches the
                        // documented usage of `into_passthrough`.
                        handle.into_passthrough().await.expect("promote ok");
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match ingress.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    received.lock().extend_from_slice(&buf[..n]);
                                }
                            }
                        }
                        _ = done_tx.send(());
                        Ok(())
                    }
                },
            );
            FlowAction::Intercept {
                meta,
                service: service.boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };

    let engine = build_engine(handler);
    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.register_promote_request_callback(move || {
        if let Some(tx) = cb_tx_mtx.lock().take() {
            _ = tx.send(());
        }
    });
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    // Push a payload, then wait for the promote callback (service
    // calls into_passthrough at the top of its body).
    let payload: Vec<u8> = (0..2000_u32).map(|i| (i as u8).wrapping_mul(11)).collect();
    let mut sent = 0;
    while sent < payload.len() {
        let end = (sent + 64).min(payload.len());
        match session.on_client_bytes(&payload[sent..end]) {
            TcpDeliverStatus::Accepted => sent = end,
            TcpDeliverStatus::Paused => std::thread::sleep(Duration::from_millis(1)),
            TcpDeliverStatus::Closed => panic!("session closed unexpectedly"),
        }
    }

    cb_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("promote callback fired");

    // Ack the cutover — engine drops the ingress sender. The service
    // is mid `into_passthrough.await`; on Ok it falls through to its
    // drain loop. Buffered bytes flow through, then EOF.
    session.confirm_promoted(Ok(()));

    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("service reached EOF within budget");

    assert_eq!(
        *received.lock(),
        payload,
        "every byte pushed before promote-confirm reached the service",
    );

    engine.stop(0);
}

#[test]
fn engine_promote_confirm_without_pending_ack_is_no_op() {
    // Calling confirm_promoted on a session that has no in-flight
    // promote must not panic and must not affect a later promote.
    let (engine, mut session, result_rx) = spawn_session_running_into_passthrough();

    // Confirm BEFORE the service ever runs — no pending ACK.
    session.confirm_promoted(Ok(())); // must not panic
    session.confirm_promoted(Err(PromoteError::SwiftCutoverFailed {
        reason: "bogus".into(),
    })); // also a no-op

    let (cb_tx, cb_rx) = std::sync::mpsc::channel::<()>();
    let cb_tx = Mutex::new(Some(cb_tx));
    session.register_promote_request_callback(move || {
        if let Some(tx) = cb_tx.lock().take() {
            _ = tx.send(());
        }
    });

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    assert_eq!(session.on_client_bytes(&[0u8]), TcpDeliverStatus::Accepted);
    cb_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("promote callback fired");

    // The pre-fire bogus confirms did not poison the registry.
    session.confirm_promoted(Ok(()));
    let r = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("service reported into_passthrough result");
    assert!(matches!(r, Ok(())), "expected Ok, got {r:?}");

    engine.stop(0);
}

#[test]
fn engine_promote_register_replaces_prior_callback() {
    let (engine, mut session, result_rx) = spawn_session_running_into_passthrough();

    let (cb_old_tx, cb_old_rx) = std::sync::mpsc::channel::<()>();
    let cb_old_tx = Mutex::new(Some(cb_old_tx));
    session.register_promote_request_callback(move || {
        if let Some(tx) = cb_old_tx.lock().take() {
            _ = tx.send(());
        }
    });

    // Replace it.
    let (cb_new_tx, cb_new_rx) = std::sync::mpsc::channel::<()>();
    let cb_new_tx = Mutex::new(Some(cb_new_tx));
    session.register_promote_request_callback(move || {
        if let Some(tx) = cb_new_tx.lock().take() {
            _ = tx.send(());
        }
    });

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    assert_eq!(session.on_client_bytes(&[0u8]), TcpDeliverStatus::Accepted);

    // Only the new callback should fire.
    cb_new_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("new callback fired");
    assert!(
        cb_old_rx.try_recv().is_err(),
        "old callback must not fire after being replaced",
    );

    session.confirm_promoted(Ok(()));
    let r = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("service reported into_passthrough result");
    assert!(matches!(r, Ok(())), "expected Ok, got {r:?}");

    engine.stop(0);
}

// ── Hardening tests (2e audit) ──────────────────────────────────────
//
// Each test below targets a specific audit finding. They are
// extra paranoid by design: 98% of traffic flows through this
// path, and a regression on any of these would be a Sev1.

/// Audit finding #1: a service that reads BOTH `ingress` AND
/// `egress` must observe EOF on both after a successful
/// promote — otherwise `tokio::io::copy_bidirectional`-style
/// services hang forever on the egress half. The fire path
/// must drop BOTH `client_tx` and `egress_tx`.
#[test]
fn engine_promote_ok_drains_both_ingress_and_egress_for_bidirectional_service() {
    use tokio::io::AsyncReadExt;

    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let done_tx = Mutex::new(Some(done_tx));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let done_tx = done_tx.lock().take().expect("single intercept");
            let service = service_fn(
                move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                    let done_tx = done_tx.clone();
                    async move {
                        let BridgeIo(mut ingress, mut egress) = bridge;
                        let handle = ingress
                            .extensions()
                            .get_ref::<PromoteHandle>()
                            .cloned()
                            .expect("PromoteHandle in extensions");
                        handle.into_passthrough().await.expect("promote ok");
                        // Both reads must terminate — that's the
                        // load-bearing assertion. If `egress_tx`
                        // isn't dropped on Ok, the egress.read
                        // future hangs and done_rx times out.
                        let mut buf_ingress = vec![0u8; 64];
                        let mut buf_egress = vec![0u8; 64];
                        let (_a, _b) = tokio::join!(
                            ingress.read(&mut buf_ingress),
                            egress.read(&mut buf_egress),
                        );
                        _ = done_tx.send(());
                        Ok(())
                    }
                },
            );
            FlowAction::Intercept {
                meta,
                service: service.boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };

    let engine = build_engine(handler);
    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    let (cb_tx, cb_rx) = std::sync::mpsc::channel::<()>();
    let cb_tx = Mutex::new(Some(cb_tx));
    session.register_promote_request_callback(move || {
        if let Some(tx) = cb_tx.lock().take() {
            _ = tx.send(());
        }
    });
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    assert_eq!(session.on_client_bytes(&[0u8]), TcpDeliverStatus::Accepted);
    cb_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("promote callback fired");

    session.confirm_promoted(Ok(()));

    done_rx.recv_timeout(Duration::from_secs(5)).expect(
        "bidirectional service must terminate within budget — \
                 if this times out, egress_tx wasn't dropped on Ok (audit #1)",
    );

    engine.stop(0);
}

/// Audit finding #2 + #5: the C trampoline call inside fire
/// MUST hold `callback_active`, mirroring the gate the other
/// FFI callbacks rely on. Without it, session cancel could
/// complete (and Swift's box release) while the trampoline
/// is mid-call → UAF on the Swift box. Drive a fire whose
/// callback probes the gate state — it MUST observe the
/// mutex held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_promote_fire_holds_callback_active_during_trampoline() {
    use crate::tproxy::engine::promote::PromoteRegistry;
    use std::sync::atomic::AtomicBool;

    let active = Arc::new(parking_lot::Mutex::new(true));
    let observed_held = Arc::new(AtomicBool::new(false));
    let registry = PromoteRegistry::new(
        Arc::new(parking_lot::Mutex::new(None)),
        Arc::new(parking_lot::Mutex::new(None)),
        active.clone(),
    );

    let active_for_cb = active.clone();
    let observed = observed_held.clone();
    registry.register_rust(move || {
        // `try_lock` succeeds only if the mutex is FREE.
        // With the gate fix, fire holds it → try_lock None.
        if active_for_cb.try_lock().is_none() {
            observed.store(true, Ordering::SeqCst);
        }
    });

    let rt = tokio::runtime::Handle::current();
    let handle = registry.clone().into_handle(rt);

    let task = tokio::spawn(async move { handle.into_passthrough().await });

    // Wait for the callback to land — the probe set
    // `observed_held` synchronously during the callback.
    for _ in 0..50 {
        if observed_held.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        observed_held.load(Ordering::SeqCst),
        "fire MUST hold `callback_active` while invoking the callback (audit #2 + #5) \
         — without it, a concurrent session cancel could free the Swift box mid-call",
    );

    registry.confirm(Ok(()));
    _ = task.await.expect("task joined");
}

/// Audit finding #3: Rust-typed
/// `register_promote_request_callback` must NOT leak the
/// closure (the prior `Box::leak` was a per-call permanent
/// leak). Drop-tracking via a sentinel proves the previous
/// closure is released on re-registration AND on session
/// drop.
#[test]
fn engine_promote_rust_typed_register_does_not_leak_on_re_registration() {
    use std::sync::atomic::AtomicUsize;

    let (engine, session, _result_rx) = spawn_session_running_into_passthrough();

    let drops = Arc::new(AtomicUsize::new(0));
    struct DropProbe(Arc<AtomicUsize>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    {
        let probe1 = Arc::new(DropProbe(drops.clone()));
        session.register_promote_request_callback(move || {
            let _ = &probe1;
        });
    }
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "first callback's closure is held by the registry; probe still alive",
    );

    {
        let probe2 = Arc::new(DropProbe(drops.clone()));
        session.register_promote_request_callback(move || {
            let _ = &probe2;
        });
    }
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "re-registration MUST drop the previous closure — \
         a leak would never reach 1 (audit #3)",
    );

    drop(session);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        2,
        "session drop MUST release the active closure",
    );

    engine.stop(0);
}

/// Audit finding #4: `PromoteHandle::into_passthrough` must
/// be cancel-safe — if the first caller's awaiting future is
/// dropped mid-fire, OTHER clones must still observe the
/// result. Pre-fix, the dropped caller's `fire().await`
/// would tear down the fire future, leaving `result = None`
/// and other clones hanging on `Notify` forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_promote_cancel_safe_first_caller_drop_does_not_strand_others() {
    use crate::tproxy::engine::promote::PromoteRegistry;

    let registry = PromoteRegistry::new(
        Arc::new(parking_lot::Mutex::new(None)),
        Arc::new(parking_lot::Mutex::new(None)),
        Arc::new(parking_lot::Mutex::new(true)),
    );
    let (fire_tx, fire_rx) = std::sync::mpsc::channel::<()>();
    let fire_tx = Mutex::new(Some(fire_tx));
    registry.register_rust(move || {
        if let Some(tx) = fire_tx.lock().take() {
            _ = tx.send(());
        }
    });

    let rt = tokio::runtime::Handle::current();
    let handle = registry.clone().into_handle(rt);
    let h1 = handle.clone();
    let h2 = handle.clone();

    let first = tokio::spawn(async move {
        drop(tokio::time::timeout(Duration::from_millis(50), h1.into_passthrough()).await);
    });
    let second = tokio::spawn(async move { h2.into_passthrough().await });

    fire_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("fire ran on the spawned (detached) task");
    registry.confirm(Ok(()));

    let r = tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .expect("second caller must resolve — would hang pre-fix (audit #4)")
        .expect("second task joined");
    assert!(matches!(r, Ok(())), "expected Ok, got {r:?}");

    _ = first.await;
}

/// Adjacent verification: after a successful Ok ACK, BOTH
/// the ingress and egress channel senders must be dropped
/// (visible to subsequent FFI calls as `Closed`).
#[test]
fn engine_promote_ok_makes_subsequent_on_client_and_egress_bytes_report_closed() {
    let (engine, mut session, _result_rx) = spawn_session_running_into_passthrough();

    let (cb_tx, cb_rx) = std::sync::mpsc::channel::<()>();
    let cb_tx = Mutex::new(Some(cb_tx));
    session.register_promote_request_callback(move || {
        if let Some(tx) = cb_tx.lock().take() {
            _ = tx.send(());
        }
    });
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    assert_eq!(session.on_client_bytes(&[0u8]), TcpDeliverStatus::Accepted);
    cb_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("promote callback fired");

    // Pre-confirm: both senders are alive.
    assert_eq!(session.on_egress_bytes(&[0u8]), TcpDeliverStatus::Accepted);

    session.confirm_promoted(Ok(()));

    // Post-confirm: both must be dropped. The Ok branch
    // runs on the spawned fire task, so spin briefly.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if session.on_client_bytes(&[0u8]) == TcpDeliverStatus::Closed
            && session.on_egress_bytes(&[0u8]) == TcpDeliverStatus::Closed
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        session.on_client_bytes(&[0u8]),
        TcpDeliverStatus::Closed,
        "client_tx must be dropped after Ok ACK",
    );
    assert_eq!(
        session.on_egress_bytes(&[0u8]),
        TcpDeliverStatus::Closed,
        "egress_tx must be dropped after Ok ACK (audit #1)",
    );

    engine.stop(0);
}

/// Lock-discipline invariant for audit #1's fix: register and
/// fire-callback execution are fully serialised through
/// `callback_active`. The audit's specific bug — a register
/// slipping in between fire's snapshot and dispatch — has a
/// sub-microsecond window that can't be probed deterministically
/// from a unit test; this test catches the surrounding invariant
/// (register blocks while the callback runs) so a future regression
/// that drops the gate on either side would surface here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_promote_register_serialised_with_fire_callback_dispatch() {
    use crate::tproxy::engine::promote::PromoteRegistry;

    let active = Arc::new(parking_lot::Mutex::new(true));
    let registry = PromoteRegistry::new(
        Arc::new(parking_lot::Mutex::new(None)),
        Arc::new(parking_lot::Mutex::new(None)),
        active.clone(),
    );

    let log: Arc<parking_lot::Mutex<Vec<&'static str>>> =
        Arc::new(parking_lot::Mutex::new(Vec::new()));
    let pending_join: Arc<parking_lot::Mutex<Option<std::thread::JoinHandle<()>>>> =
        Arc::new(parking_lot::Mutex::new(None));

    let registry_for_cb = registry.clone();
    let log_for_cb = log.clone();
    let pending_join_for_cb = pending_join.clone();
    registry.register_rust(move || {
        log_for_cb.lock().push("cb_enter");

        let reg = registry_for_cb.clone();
        let log_inner = log_for_cb.clone();
        let t = std::thread::spawn(move || {
            reg.register_rust(|| {});
            log_inner.lock().push("register_done");
        });
        *pending_join_for_cb.lock() = Some(t);

        // Give the register thread a chance to attempt the
        // lock. Pre-fix, register_done would land here; the
        // ordering assert below would fail.
        std::thread::sleep(Duration::from_millis(50));

        log_for_cb.lock().push("cb_exit");
    });

    let rt = tokio::runtime::Handle::current();
    let handle = registry.clone().into_handle(rt);

    let registry_for_confirm = registry.clone();
    let confirm_task = tokio::spawn(async move {
        for _ in 0..200 {
            if registry_for_confirm.has_pending_ack() {
                registry_for_confirm.confirm(Ok(()));
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    handle.into_passthrough().await.expect("ok");
    _ = confirm_task.await;

    if let Some(t) = pending_join.lock().take() {
        t.join().expect("register thread completed");
    }

    let events = log.lock().clone();
    let i_enter = events
        .iter()
        .position(|&e| e == "cb_enter")
        .expect("cb_enter logged");
    let i_exit = events
        .iter()
        .position(|&e| e == "cb_exit")
        .expect("cb_exit logged");
    let i_reg = events
        .iter()
        .position(|&e| e == "register_done")
        .expect("register_done logged");
    assert!(i_enter < i_exit, "callback enter precedes exit");
    assert!(
        i_exit < i_reg,
        "register MUST land AFTER cb_exit — events were {events:?}",
    );
}
