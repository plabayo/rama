//! Per-flow decision tests: passthrough / blocked / intercept and the
//! decision-deadline backstop.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{
    TransparentProxyConfig, TransparentProxyFlowMeta, TransparentProxyFlowProtocol,
};
use rama_core::error::BoxError;
use rama_core::io::BridgeIo;
use rama_core::rt::Executor;
use rama_core::service::{Service, service_fn};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn tcp_session_passthrough_by_default() {
    let engine = build_engine(TestHandler::passthrough());
    let decision = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Passthrough));
}

#[test]
fn udp_session_passthrough_by_default() {
    let engine = build_engine(TestHandler::passthrough());
    let decision = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Passthrough));
}

#[test]
fn tcp_session_can_be_blocked() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Blocked),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
    });
    let decision = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Blocked));
}

#[test]
fn udp_session_can_be_blocked() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|_| FlowAction::Blocked),
        tcp_egress_options: None,
    });
    let decision = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Blocked));
}

#[derive(Clone)]
struct SlowMatchHandler {
    delay: Duration,
}

impl TransparentProxyHandler for SlowMatchHandler {
    fn transparent_proxy_config(&self) -> crate::tproxy::TransparentProxyConfig {
        TransparentProxyConfig::new()
    }

    fn match_tcp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<crate::TcpFlow, crate::NwTcpStream>, Output = (), Error = Infallible>,
        >,
    > + Send
    + '_ {
        let delay = self.delay;
        async move {
            tokio::time::sleep(delay).await;
            FlowAction::<TestTcpService>::Intercept {
                meta,
                service: service_fn(
                    |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                        let BridgeIo(stream, egress) = bridge;
                        let _hold = (stream, egress);
                        std::future::pending::<()>().await;
                        Ok(())
                    },
                )
                .boxed(),
            }
        }
    }

    fn match_udp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<impl Service<crate::UdpFlow, Output = (), Error = Infallible>>,
    > + Send
    + '_ {
        let delay = self.delay;
        async move {
            tokio::time::sleep(delay).await;
            FlowAction::<TestUdpService>::Intercept {
                meta,
                service: service_fn(|flow: crate::UdpFlow| async move {
                    let _hold = flow;
                    std::future::pending::<()>().await;
                    Ok(())
                })
                .boxed(),
            }
        }
    }
}

#[derive(Clone)]
struct SlowMatchHandlerFactory(SlowMatchHandler);

impl TransparentProxyHandlerFactory for SlowMatchHandlerFactory {
    type Handler = SlowMatchHandler;
    type Error = BoxError;

    fn create_transparent_proxy_handler(
        &self,
        _ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        let h = self.0.clone();
        std::future::ready(Ok(h))
    }
}

#[test]
fn decision_deadline_blocks_slow_handler_by_default() {
    let engine = TransparentProxyEngineBuilder::new(SlowMatchHandlerFactory(SlowMatchHandler {
        delay: Duration::from_secs(5),
    }))
    .with_runtime_factory(TestRuntimeFactory)
    .with_decision_deadline(Duration::from_millis(100))
    .build()
    .expect("build engine");

    let started = Instant::now();
    let action = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    let elapsed = started.elapsed();
    assert!(
        matches!(action, SessionFlowAction::Blocked),
        "expected Blocked on deadline"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "decision deadline should fire before slow handler completes (elapsed: {elapsed:?})"
    );
    engine.stop(0);
}

#[test]
fn decision_deadline_passthrough_when_action_is_passthrough() {
    let engine = TransparentProxyEngineBuilder::new(SlowMatchHandlerFactory(SlowMatchHandler {
        delay: Duration::from_secs(5),
    }))
    .with_runtime_factory(TestRuntimeFactory)
    .with_decision_deadline(Duration::from_millis(100))
    .with_decision_deadline_action(super::super::DecisionDeadlineAction::Passthrough)
    .build()
    .expect("build engine");

    let action = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(action, SessionFlowAction::Passthrough));
    engine.stop(0);
}

#[test]
fn decision_deadline_does_not_fire_for_fast_handlers() {
    // Fast intercept — well within the configured 2s deadline.
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    let BridgeIo(stream, egress) = bridge;
                    let _hold = (stream, egress);
                    std::future::pending::<()>().await;
                    Ok(())
                },
            )
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
    };
    let engine = build_engine_with_decision_deadline(
        handler,
        Duration::from_secs(2),
        super::super::DecisionDeadlineAction::Block,
    );

    let action = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(action, SessionFlowAction::Intercept(_)));
    engine.stop(0);
}
