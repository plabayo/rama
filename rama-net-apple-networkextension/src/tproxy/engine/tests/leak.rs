//! Leak / churn tests: verify that opening many sessions and then
//! dropping or stopping the engine actually frees per-session state.
//!
//! These can't catch every leak (some manifest only on the FFI/Swift
//! boundary, which Layer 2 covers), but they reliably catch the most
//! common shapes of leak found in the audit:
//!
//! - per-flow `Arc` retained past `cancel()` due to a wedge,
//! - bridge tasks not exiting in bounded time,
//! - dropping the engine with live sessions hanging the runtime.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use rama_core::io::BridgeIo;
use rama_core::service::service_fn;
use rama_net::address::HostWithPort;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Sanity: opening a batch of TCP sessions, dropping each one (which
/// triggers `Drop for TransparentProxyTcpSession` → `cancel()`), then
/// stopping the engine completes in bounded time.
///
/// Regression target: a future change that wedges `cancel()` (e.g. an
/// unbounded await) would surface here as the test never returning.
#[test]
fn tcp_drop_many_sessions_completes_in_bounded_time() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |_bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move { Ok(()) },
            )
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine(handler);

    let started = Instant::now();
    for _ in 0..256 {
        let SessionFlowAction::Intercept(_session) = engine.new_tcp_session(
            TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
                .with_remote_endpoint(HostWithPort::example_domain_with_port(443)),
            |_bytes| TcpDeliverStatus::Accepted,
            || {},
            || {},
        ) else {
            panic!("expected intercept session");
        };
        // session drops here — fires cancel() via Drop.
    }
    let teardown = Instant::now();
    engine.stop(0);
    let total = started.elapsed();
    assert!(
        teardown.duration_since(started) < Duration::from_secs(2),
        "256 session create+drop took {:?} (>2s)",
        teardown.duration_since(started)
    );
    assert!(
        total < Duration::from_secs(3),
        "create+drop+stop took {total:?} (>3s)"
    );
}

/// Engine drop with live sessions: explicit `engine.stop()` while
/// sessions are still alive must drain cleanly. The shutdown awaits
/// every per-flow `flow_guard` to drop; a bridge task that fails to
/// observe shutdown (or holds an unbreakable Arc) wedges this.
#[test]
fn engine_stop_with_live_sessions_drains_within_bound() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |_bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    // Service stays alive so the per-flow shutdown
                    // observation path is what actually closes things.
                    std::future::pending::<()>().await;
                    Ok(())
                },
            )
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine(handler);

    let mut keep_alive = Vec::new();
    for _ in 0..32 {
        let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
            TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
                .with_remote_endpoint(HostWithPort::example_domain_with_port(443)),
            |_bytes| TcpDeliverStatus::Accepted,
            || {},
            || {},
        ) else {
            panic!("expected intercept session");
        };
        session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
        keep_alive.push(session);
    }

    // Sessions are live; engine.stop() must drain everything on its
    // own (the parent shutdown signal is what propagates to each
    // flow_guard via its select! arm).
    let stop_started = Instant::now();
    engine.stop(0);
    let stop_elapsed = stop_started.elapsed();
    assert!(
        stop_elapsed < Duration::from_secs(2),
        "engine.stop() with 32 live sessions took {stop_elapsed:?} (>2s) — possible bridge wedge"
    );

    // Sessions still need to drop after the engine stopped; their
    // Drop fires cancel() which is now a no-op (engine already
    // shut). This must not panic or hang.
    drop(keep_alive);
}

/// Churn: open + drop sessions in a tight loop. Watches for state
/// growth indirectly: if `tcp_cancel_many_idle_sessions_…` succeeds
/// AND this test's batched churn finishes in bounded total time,
/// neither the engine nor per-session state grew unboundedly across
/// batches.
#[test]
fn tcp_session_churn_does_not_grow_unboundedly() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |_bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move { Ok(()) },
            )
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    };
    let engine = build_engine(handler);

    let total = 4096_usize;
    let started = Instant::now();
    for _ in 0..total {
        let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
            TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
                .with_remote_endpoint(HostWithPort::example_domain_with_port(443)),
            |_bytes| TcpDeliverStatus::Accepted,
            || {},
            || {},
        ) else {
            panic!("expected intercept session");
        };
        session.cancel();
    }
    let elapsed = started.elapsed();
    // Per-session create+cancel should be sub-millisecond on a modern
    // machine. Allow generous slack so CI noise doesn't fail this; a
    // *quadratic* growth (e.g. list-walked-on-every-cancel) would
    // blow well past 30s long before we hit the ceiling.
    assert!(
        elapsed < Duration::from_secs(30),
        "{total} session churn took {elapsed:?} — possible quadratic state growth"
    );
    engine.stop(0);
}
