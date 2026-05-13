//! Engine lifecycle / builder validation tests.

use super::common::*;
use crate::tproxy::engine::*;
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
    let builder = TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
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
    let builder = TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
        .without_udp_max_flow_lifetime();
    assert_eq!(builder.current_udp_max_flow_lifetime(), None);
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
    let builder = TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
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

#[test]
fn app_message_can_return_reply() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|message| (message == b"ping").then(|| b"pong".to_vec())),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
    });

    let reply = engine.handle_app_message(Bytes::from_static(b"ping"));
    assert_eq!(reply.as_deref(), Some(&b"pong"[..]));
}
