//! Engine lifecycle / builder validation tests.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use rama_core::bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;

// The TCP idle backstop, the UDP max-lifetime cap and the TCP paused-
// drain wait are the three timer-based safety nets that keep a wedged
// per-flow bridge from holding the macOS NWConnection registration
// forever. The tests below pin both the constant values and the fact
// that the builder applies them as defaults — a regression that
// silently flips any of them back to `None` would let one wedged flow
// per leak path live indefinitely, which is exactly the failure mode
// these backstops exist to prevent.

#[test]
fn default_tcp_idle_timeout_constant_is_fifteen_minutes() {
    assert_eq!(DEFAULT_TCP_IDLE_TIMEOUT, Duration::from_mins(15));
}

#[test]
fn builder_default_tcp_idle_timeout_is_the_constant() {
    let builder =
        TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()));
    assert_eq!(
        builder.current_tcp_idle_timeout(),
        Some(DEFAULT_TCP_IDLE_TIMEOUT)
    );
}

#[test]
fn builder_without_tcp_idle_timeout_sets_none() {
    let builder =
        TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
            .without_tcp_idle_timeout();
    assert_eq!(builder.current_tcp_idle_timeout(), None);
}

#[test]
fn default_udp_max_flow_lifetime_constant_is_fifteen_minutes() {
    assert_eq!(DEFAULT_UDP_MAX_FLOW_LIFETIME, Duration::from_mins(15));
}

#[test]
fn builder_default_udp_max_flow_lifetime_is_the_constant() {
    let builder =
        TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()));
    assert_eq!(
        builder.current_udp_max_flow_lifetime(),
        Some(DEFAULT_UDP_MAX_FLOW_LIFETIME)
    );
}

#[test]
fn builder_without_udp_max_flow_lifetime_sets_none() {
    let builder =
        TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
            .without_udp_max_flow_lifetime();
    assert_eq!(builder.current_udp_max_flow_lifetime(), None);
}

#[test]
fn default_udp_idle_timeout_constant_is_sixty_seconds() {
    assert_eq!(DEFAULT_UDP_IDLE_TIMEOUT, Duration::from_secs(60));
}

#[test]
fn builder_default_udp_idle_timeout_is_the_constant() {
    let builder =
        TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()));
    assert_eq!(
        builder.current_udp_idle_timeout(),
        Some(DEFAULT_UDP_IDLE_TIMEOUT)
    );
}

#[test]
fn builder_without_udp_idle_timeout_sets_none() {
    let builder =
        TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
            .without_udp_idle_timeout();
    assert_eq!(builder.current_udp_idle_timeout(), None);
}

#[test]
fn default_tcp_paused_drain_max_wait_constant_is_one_minute() {
    assert_eq!(DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT, Duration::from_mins(1));
}

#[test]
fn builder_default_tcp_paused_drain_max_wait_is_the_constant() {
    let builder =
        TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()));
    assert_eq!(
        builder.current_tcp_paused_drain_max_wait(),
        Some(DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT)
    );
}

#[test]
fn builder_without_tcp_paused_drain_max_wait_sets_none() {
    let builder =
        TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
            .without_tcp_paused_drain_max_wait();
    assert_eq!(builder.current_tcp_paused_drain_max_wait(), None);
}

#[test]
fn engine_builds_live_and_stop_is_terminal() {
    let engine = build_engine(TestHandler::passthrough());
    engine.stop(0);
}

#[test]
fn builder_rejects_zero_channel_capacity() {
    // `tokio::sync::mpsc::channel(0)` panics; an explicit `Some(0)` is
    // treated as a misconfiguration rather than silently substituting the
    // default. `None` continues to mean "use default".
    let make = |tcp: Option<usize>, udp: Option<usize>| {
        let mut builder =
            TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
                .with_runtime_factory(TestRuntimeFactory);
        builder = builder.maybe_with_tcp_channel_capacity(tcp);
        builder = builder.maybe_with_udp_channel_capacity(udp);
        builder.build()
    };

    assert!(make(Some(0), None).is_err(), "Some(0) tcp must error");
    assert!(make(None, Some(0)).is_err(), "Some(0) udp must error");
    let engine = make(None, None).expect("None defaults must build");
    engine.stop(0);
}

#[test]
fn builder_rejects_zero_tcp_flow_buffer_size() {
    // `tokio::io::duplex(0)` deadlocks the per-flow service on its first
    // `write_all` (the writer immediately backs off waiting for the
    // non-existent reader). Just like the channel-capacity zero-rejection
    // above, `Some(0)` must error rather than silently footgun.
    let builder =
        TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
            .with_runtime_factory(TestRuntimeFactory)
            .with_tcp_flow_buffer_size(0);
    assert!(
        builder.build().is_err(),
        "Some(0) tcp_flow_buffer_size must error"
    );

    // `None` (the default) must continue to build cleanly.
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
        .with_runtime_factory(TestRuntimeFactory)
        .build()
        .expect("None defaults must build");
    engine.stop(0);
}

// Handler-supplied egress options must propagate through the engine
// to the per-session accessor. Without these tests a typo on either
// the handler-trait side or the session-storage side would silently
// fall back to the Swift defaults (5s linger, 2s EOF grace, 30s
// connect timeout) with no production-visible signal.

#[test]
fn tcp_egress_options_override_flows_from_handler_to_session() {
    use crate::tproxy::{NwEgressParameters, NwTcpConnectOptions};
    use rama_core::bytes::Bytes;
    use std::sync::Arc;

    let custom = NwTcpConnectOptions {
        parameters: NwEgressParameters::default(),
        connect_timeout: Some(Duration::from_millis(7_000)),
        linger_close_timeout: Some(Duration::from_millis(12_345)),
        egress_eof_grace: Some(Duration::from_millis(6_789)),
        // Opt out of keepalive and tune the knobs so the round-trip
        // asserts both the enable flag and the timing fields propagate.
        tcp_keepalive_enabled: false,
        tcp_keepalive_idle: Some(Duration::from_secs(11)),
        tcp_keepalive_interval: Some(Duration::from_secs(7)),
        tcp_keepalive_count: Some(4),
    };

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: rama_core::service::service_fn(
                |_bridge: rama_core::io::BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    Ok(())
                },
            )
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    }
    .with_tcp_egress_options(move |_meta| Some(custom.clone()));
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    let opts = session
        .egress_connect_options()
        .expect("handler set egress options; session must surface them");
    assert_eq!(opts.connect_timeout, Some(Duration::from_millis(7_000)));
    assert_eq!(
        opts.linger_close_timeout,
        Some(Duration::from_millis(12_345))
    );
    assert_eq!(opts.egress_eof_grace, Some(Duration::from_millis(6_789)));
    assert!(
        !opts.tcp_keepalive_enabled,
        "handler opted out of keepalive; session must surface that"
    );
    assert_eq!(opts.tcp_keepalive_idle, Some(Duration::from_secs(11)));
    assert_eq!(opts.tcp_keepalive_interval, Some(Duration::from_secs(7)));
    assert_eq!(opts.tcp_keepalive_count, Some(4));

    drop(session);
    engine.stop(0);
    _ = Bytes::new(); // silence unused-warning if Bytes import drifts
}

#[test]
fn tcp_egress_options_none_handler_returns_none_at_session() {
    use rama_core::bytes::Bytes;

    let engine = build_engine(TestHandler::passthrough());

    let action = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    // Passthrough handler decides not to intercept — no session to check.
    assert!(matches!(action, SessionFlowAction::Passthrough));
    engine.stop(0);
    _ = Bytes::new();
}

#[test]
fn app_message_can_return_reply() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|message| (message == b"ping").then(|| b"pong".to_vec())),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    });

    let reply = engine.handle_app_message(Bytes::from_static(b"ping"));
    assert_eq!(reply.as_deref(), Some(&b"pong"[..]));
}

// ── on_system_sleep / on_system_wake plumbing ────────────────────────────────

use std::sync::atomic::{AtomicUsize, Ordering};

/// `notify_system_sleep` drives `TransparentProxyHandler::on_system_sleep`
/// through the engine's runtime.
#[test]
fn notify_system_sleep_invokes_handler_hook() {
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_in = counter.clone();
    let engine = build_engine(TestHandler::passthrough().with_on_sleep(move || {
        counter_in.fetch_add(1, Ordering::SeqCst);
    }));
    engine.notify_system_sleep();
    // Detached: spin briefly until the handler observes the call.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while counter.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    engine.stop(0);
}

/// `notify_system_wake` drives `TransparentProxyHandler::on_system_wake`.
#[test]
fn notify_system_wake_invokes_handler_hook() {
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_in = counter.clone();
    let engine = build_engine(TestHandler::passthrough().with_on_wake(move || {
        counter_in.fetch_add(1, Ordering::SeqCst);
    }));
    engine.notify_system_wake();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while counter.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    engine.stop(0);
}

/// The default handler impl is a noop (just a trace log). Calling
/// `notify_system_sleep` on a passthrough handler must not panic or
/// affect engine state — the handler simply observes nothing.
#[test]
fn notify_system_sleep_with_default_handler_is_safe() {
    let engine = build_engine(TestHandler::passthrough());
    engine.notify_system_sleep();
    engine.notify_system_wake();
    engine.stop(0);
}

/// A task that holds an engine shutdown guard and never drops it
/// (a stand-in for a handler hook stuck on un-timed I/O across a
/// suspend) must not hang `engine.stop()`: the wait on guards is
/// bounded by the configured `stop_drain_max_wait`, after which stop
/// proceeds. Uses a short budget so the test stays fast.
#[test]
fn stop_is_bounded_when_a_guard_is_held_past_shutdown() {
    use std::time::Instant;

    let budget = Duration::from_millis(250);
    let engine = build_engine_with_stop_drain_max_wait(TestHandler::passthrough(), budget);
    let guard = engine
        .shutdown_guard()
        .expect("a fresh engine has a live shutdown pair");
    // Park a task that holds the guard forever on the engine runtime.
    engine.rt.as_ref().unwrap().spawn(async move {
        let _held = guard;
        std::future::pending::<()>().await;
    });

    let started = Instant::now();
    engine.stop(0);
    let elapsed = started.elapsed();

    assert!(
        elapsed >= budget,
        "stop returned before the backstop ({elapsed:?}); the held guard \
         did not actually block the wait"
    );
    assert!(
        elapsed < budget + Duration::from_secs(5),
        "stop did not return within the backstop window ({elapsed:?})"
    );
}

/// The wedged-runtime regression: when EVERY runtime worker is blocked
/// in non-async code (syscall / FFI), the runtime can neither poll the
/// graceful drain nor advance its timer wheel — so a tokio-timer "hard
/// cap" on the stop can never fire, and a plain runtime drop would join
/// the blocked workers forever. Both bounds must therefore be OS-level:
/// `engine.stop()` has to return within the hard-cap window regardless.
///
/// This is the in-miniature reproduction of the field incident where a
/// hung `stopProxy` leaked a half-stopped engine (mach XPC listener
/// included) as an unreachable in-process zombie. Before the fix this
/// test never returned.
#[test]
fn stop_is_bounded_when_all_runtime_workers_are_blocked() {
    use std::time::Instant;

    let budget = Duration::from_millis(250);
    let engine = build_engine_with_stop_drain_max_wait(TestHandler::passthrough(), budget);

    // Occupy both `TestRuntimeFactory` workers with tasks that block
    // their thread without ever yielding to the scheduler.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    for _ in 0..2 {
        let ready_tx = ready_tx.clone();
        engine.rt.as_ref().unwrap().spawn(async move {
            ready_tx.send(()).unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        });
    }
    // Only proceed once both blockers actually occupy a worker.
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first blocker running");
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second blocker running");

    let started = Instant::now();
    engine.stop(0);
    let elapsed = started.elapsed();

    assert!(
        elapsed >= budget,
        "stop returned before the backstop ({elapsed:?}); the blocked \
         workers did not actually wedge the drain"
    );
    assert!(
        elapsed < budget + STOP_HARD_CAP_SLACK + Duration::from_secs(3),
        "stop did not return within the wedged-runtime bound ({elapsed:?})"
    );
}

/// The builder default for `stop_drain_max_wait` is the documented
/// constant — pin it so a future edit can't silently drop the
/// teardown backstop to an unbounded wait.
#[test]
fn builder_default_stop_drain_max_wait_is_the_constant() {
    let builder =
        TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()));
    assert_eq!(
        builder.current_stop_drain_max_wait(),
        Some(DEFAULT_STOP_DRAIN_MAX_WAIT)
    );
}

/// `stop` performs blocking teardown (drain wait + runtime disposal),
/// which tokio faults when run naively on one of its own contexts.
/// Callers legitimately stop engines from async code (tests, embedders),
/// so the blocking tail must route through `block_in_place` on a
/// multi-thread runtime…
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_from_multi_thread_async_context_does_not_fault() {
    // Build on the blocking pool: engine construction itself `block_on`s
    // the handler factory, which is not allowed on an async context.
    // The property under test is the `stop` that follows.
    let engine = tokio::task::spawn_blocking(|| build_engine(TestHandler::passthrough()))
        .await
        .expect("build engine");
    engine.stop(0);
}

/// …and onto a scoped thread on a current-thread runtime, where
/// `block_in_place` is unavailable.
#[tokio::test]
async fn stop_from_current_thread_async_context_does_not_fault() {
    let engine = tokio::task::spawn_blocking(|| build_engine(TestHandler::passthrough()))
        .await
        .expect("build engine");
    engine.stop(0);
}
