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
pub(super) type TestUdpService = BoxService<crate::UdpFlow, (), Infallible>;

#[derive(Clone)]
pub(super) struct TestHandler {
    pub(super) app_message_handler: Arc<dyn Fn(Vec<u8>) -> Option<Vec<u8>> + Send + Sync>,
    pub(super) tcp_matcher:
        Arc<dyn Fn(TransparentProxyFlowMeta) -> FlowAction<TestTcpService> + Send + Sync>,
    pub(super) udp_matcher:
        Arc<dyn Fn(TransparentProxyFlowMeta) -> FlowAction<TestUdpService> + Send + Sync>,
    // Optional override for the TCP egress-options trait method. Default
    // `None` keeps existing test sites compiling without their having
    // to know this field exists; tests that need to drive a non-default
    // option set use `with_tcp_egress_options`.
    pub(super) tcp_egress_options: Option<
        Arc<
            dyn Fn(&TransparentProxyFlowMeta) -> Option<crate::tproxy::NwTcpConnectOptions>
                + Send
                + Sync,
        >,
    >,
    /// Optional hook observed by `on_system_sleep`. Tests use it
    /// to pin that the engine's `notify_system_sleep` actually
    /// reaches the handler. Default `None` keeps every existing
    /// test site compiling.
    pub(super) on_sleep: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Symmetric for `on_system_wake`.
    pub(super) on_wake: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl TestHandler {
    pub(super) fn passthrough() -> Self {
        Self {
            app_message_handler: Arc::new(|_| None),
            tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
            udp_matcher: Arc::new(|_| FlowAction::Passthrough),
            tcp_egress_options: None,
            on_sleep: None,
            on_wake: None,
        }
    }

    pub(super) fn with_tcp_egress_options(
        mut self,
        f: impl Fn(&TransparentProxyFlowMeta) -> Option<crate::tproxy::NwTcpConnectOptions>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.tcp_egress_options = Some(Arc::new(f));
        self
    }

    pub(super) fn with_on_sleep(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_sleep = Some(Arc::new(f));
        self
    }

    pub(super) fn with_on_wake(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_wake = Some(Arc::new(f));
        self
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
        Output = FlowAction<impl Service<crate::UdpFlow, Output = (), Error = Infallible>>,
    > + Send
    + '_ {
        std::future::ready((self.udp_matcher)(meta))
    }

    fn egress_tcp_connect_options(
        &self,
        meta: &TransparentProxyFlowMeta,
    ) -> Option<crate::tproxy::NwTcpConnectOptions> {
        self.tcp_egress_options.as_ref().and_then(|f| f(meta))
    }

    fn on_system_sleep(&self, _exec: Executor) -> impl Future<Output = ()> + Send + '_ {
        if let Some(cb) = self.on_sleep.as_ref() {
            cb();
        }
        std::future::ready(())
    }

    fn on_system_wake(&self, _exec: Executor) -> impl Future<Output = ()> + Send + '_ {
        if let Some(cb) = self.on_wake.as_ref() {
            cb();
        }
        std::future::ready(())
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
            .enable_io()
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

pub(super) fn build_engine_with_stop_drain_max_wait(
    handler: TestHandler,
    wait: Duration,
) -> TransparentProxyEngine<TestHandler> {
    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_stop_drain_max_wait(wait)
        .build()
        .expect("build engine")
}

// ── close-telemetry capture ────────────────────────────────────────────────
//
// On `cancel()` the Swift-facing callbacks are suppressed, so the only signal
// the close epilogue ran is the `"tcp flow closed"` tracing event. A global
// subscriber records each closed `flow_id`; tests filter by a unique id so they
// hold whether run per-process (nextest) or shared (`cargo test`).

use std::sync::{Once, OnceLock};

static CLOSED_FLOW_IDS: OnceLock<parking_lot::Mutex<Vec<u64>>> = OnceLock::new();
static INSTALL_CAPTURE: Once = Once::new();

fn closed_flow_ids() -> &'static parking_lot::Mutex<Vec<u64>> {
    CLOSED_FLOW_IDS.get_or_init(|| parking_lot::Mutex::new(Vec::new()))
}

#[derive(Default)]
struct CloseVisitor {
    flow_id: Option<u64>,
    is_close: bool,
}

impl tracing::field::Visit for CloseVisitor {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "flow_id" {
            self.flow_id = Some(value);
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" && format!("{value:?}").contains("tcp flow closed") {
            self.is_close = true;
        }
    }
}

struct CloseCaptureSubscriber;

impl tracing::Subscriber for CloseCaptureSubscriber {
    fn enabled(&self, _md: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = CloseVisitor::default();
        event.record(&mut visitor);
        if visitor.is_close
            && let Some(id) = visitor.flow_id
        {
            closed_flow_ids().lock().push(id);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Install the close-capture subscriber exactly once for the test process.
pub(super) fn install_close_capture() {
    INSTALL_CAPTURE.call_once(|| {
        // Ignore the error: if some other harness already set a global default we
        // simply can't capture, and the caller's `flow_was_closed` will stay false
        // (surfaced as a normal assertion failure rather than a panic here).
        _ = tracing::subscriber::set_global_default(CloseCaptureSubscriber);
    });
}

/// Whether a `"tcp flow closed"` telemetry event has been observed for `flow_id`.
pub(super) fn flow_was_closed(flow_id: u64) -> bool {
    closed_flow_ids().lock().contains(&flow_id)
}
