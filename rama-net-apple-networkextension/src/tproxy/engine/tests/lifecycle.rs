//! Engine lifecycle / builder validation tests.

use super::common::*;
use crate::tproxy::engine::*;
use rama_core::bytes::Bytes;
use std::sync::Arc;

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
