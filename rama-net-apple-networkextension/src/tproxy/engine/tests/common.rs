//! Shared test fixtures: runtime factory, handler factory, and small
//! engine-builder helpers used across the per-topic test modules.

use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyConfig, TransparentProxyFlowMeta};
use rama_core::{
    bytes::Bytes,
    error::BoxError,
    rt::Executor,
    service::{BoxService, Service},
};
use std::{convert::Infallible, sync::Arc, time::Duration};

pub(super) type TestTcpService =
    BoxService<rama_core::io::BridgeIo<crate::TcpFlow, crate::NwTcpStream>, (), Infallible>;
pub(super) type TestUdpService =
    BoxService<rama_core::io::BridgeIo<crate::UdpFlow, crate::NwUdpSocket>, (), Infallible>;

#[derive(Clone)]
pub(super) struct TestHandler {
    pub(super) app_message_handler: Arc<dyn Fn(Vec<u8>) -> Option<Vec<u8>> + Send + Sync>,
    pub(super) tcp_matcher:
        Arc<dyn Fn(TransparentProxyFlowMeta) -> FlowAction<TestTcpService> + Send + Sync>,
    pub(super) udp_matcher:
        Arc<dyn Fn(TransparentProxyFlowMeta) -> FlowAction<TestUdpService> + Send + Sync>,
}

impl TestHandler {
    pub(super) fn passthrough() -> Self {
        Self {
            app_message_handler: Arc::new(|_| None),
            tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
            udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        }
    }
}

impl TransparentProxyHandler for TestHandler {
    fn transparent_proxy_config(&self) -> crate::tproxy::TransparentProxyConfig {
        TransparentProxyConfig::new()
    }

    fn handle_app_message(
        &self,
        _exec: Executor,
        message: Bytes,
    ) -> impl Future<Output = Option<Bytes>> + Send + '_ {
        let reply = (self.app_message_handler)(message.to_vec()).map(Bytes::from);
        std::future::ready(reply)
    }

    fn match_tcp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<
                rama_core::io::BridgeIo<crate::TcpFlow, crate::NwTcpStream>,
                Output = (),
                Error = Infallible,
            >,
        >,
    > + Send
    + '_ {
        std::future::ready((self.tcp_matcher)(meta))
    }

    fn match_udp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<
                rama_core::io::BridgeIo<crate::UdpFlow, crate::NwUdpSocket>,
                Output = (),
                Error = Infallible,
            >,
        >,
    > + Send
    + '_ {
        std::future::ready((self.udp_matcher)(meta))
    }
}

#[derive(Clone)]
pub(super) struct TestHandlerFactory(pub(super) TestHandler);

impl TransparentProxyHandlerFactory for TestHandlerFactory {
    type Handler = TestHandler;
    type Error = BoxError;

    fn create_transparent_proxy_handler(
        &self,
        _ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        std::future::ready(Ok(self.0.clone()))
    }
}

#[derive(Clone, Copy, Default)]
pub(super) struct TestRuntimeFactory;

impl TransparentProxyAsyncRuntimeFactory for TestRuntimeFactory {
    type Error = BoxError;

    fn create_async_runtime(
        self,
        _cfg: Option<&[u8]>,
    ) -> Result<TransparentProxyAsyncRuntime, Self::Error> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()?;
        Ok(TransparentProxyAsyncRuntime::from_tokio(rt))
    }
}

pub(super) fn build_engine(handler: TestHandler) -> TransparentProxyEngine<TestHandler> {
    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .build()
        .expect("build engine")
}

pub(super) fn build_engine_with_tcp_channel_capacity(
    handler: TestHandler,
    capacity: usize,
) -> TransparentProxyEngine<TestHandler> {
    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_tcp_channel_capacity(capacity)
        .build()
        .expect("build engine")
}

pub(super) fn build_engine_with_tcp_idle_timeout(
    handler: TestHandler,
    timeout: Duration,
) -> TransparentProxyEngine<TestHandler> {
    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_tcp_idle_timeout(timeout)
        .build()
        .expect("build engine")
}

pub(super) fn build_engine_with_decision_deadline(
    handler: TestHandler,
    deadline: Duration,
    action: super::super::DecisionDeadlineAction,
) -> TransparentProxyEngine<TestHandler> {
    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_decision_deadline(deadline)
        .with_decision_deadline_action(action)
        .build()
        .expect("build engine")
}

pub(super) fn build_engine_with_tcp_paused_drain_max_wait(
    handler: TestHandler,
    wait: Duration,
) -> TransparentProxyEngine<TestHandler> {
    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_tcp_paused_drain_max_wait(wait)
        .build()
        .expect("build engine")
}

pub(super) fn build_engine_with_udp_max_flow_lifetime(
    handler: TestHandler,
    lifetime: Duration,
) -> TransparentProxyEngine<TestHandler> {
    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_udp_max_flow_lifetime(lifetime)
        .build()
        .expect("build engine")
}
