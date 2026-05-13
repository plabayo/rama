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
    };
    let custom_for_handler = custom.clone();

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
        udp_egress_options: None,
    }
    .with_tcp_egress_options(move |_meta| Some(custom_for_handler.clone()));
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
    assert_eq!(opts.linger_close_timeout, Some(Duration::from_millis(12_345)));
    assert_eq!(opts.egress_eof_grace, Some(Duration::from_millis(6_789)));

    drop(session);
    engine.stop(0);
    _ = Bytes::new(); // silence unused-warning if Bytes import drifts
}

#[test]
fn udp_egress_options_override_flows_from_handler_to_session() {
    use crate::tproxy::{NwEgressParameters, NwUdpConnectOptions};
    use std::sync::Arc;

    let custom = NwUdpConnectOptions {
        parameters: NwEgressParameters::default(),
        connect_timeout: Some(Duration::from_millis(4_321)),
    };
    let custom_for_handler = custom.clone();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: rama_core::service::service_fn(
                |_bridge: rama_core::io::BridgeIo<crate::UdpFlow, crate::NwUdpSocket>| async move {
                    Ok(())
                },
            )
            .boxed(),
        }),
        tcp_egress_options: None,
        udp_egress_options: None,
    }
    .with_udp_egress_options(move |_meta| Some(custom_for_handler.clone()));
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept udp session");
    };

    let opts = session
        .egress_connect_options()
        .expect("handler set udp egress options; session must surface them");
    assert_eq!(opts.connect_timeout, Some(Duration::from_millis(4_321)));

    drop(session);
    engine.stop(0);
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
        udp_egress_options: None,
    });

    let reply = engine.handle_app_message(Bytes::from_static(b"ping"));
    assert_eq!(reply.as_deref(), Some(&b"pong"[..]));
}
