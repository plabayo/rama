use std::sync::Arc;

use crate::tproxy::{SessionFlowAction, TransparentProxyConfig, TransparentProxyFlowMeta};
use rama_core::bytes::Bytes;

use super::{
    TransparentProxyEngine, TransparentProxyHandler, TransparentProxyTcpSession,
    TransparentProxyUdpSession,
};

pub type BoxedServerBytesSink = Arc<dyn Fn(&[u8]) + Send + Sync + 'static>;
pub type BoxedClosedSink = Arc<dyn Fn() + Send + Sync + 'static>;
pub type BoxedDemandSink = Arc<dyn Fn() + Send + Sync + 'static>;

trait BoxedTransparentProxyEngineInner: Send + Sync + 'static {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig;
    fn handle_app_message(&self, message: Bytes) -> Option<Bytes>;
    fn stop_box(self: Box<Self>, reason: i32);
    fn new_tcp_session(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_bytes: BoxedServerBytesSink,
        on_client_read_demand: BoxedDemandSink,
        on_server_closed: BoxedClosedSink,
    ) -> SessionFlowAction<TransparentProxyTcpSession>;
    fn new_udp_session(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_datagram: BoxedServerBytesSink,
        on_client_read_demand: BoxedDemandSink,
        on_server_closed: BoxedClosedSink,
    ) -> SessionFlowAction<TransparentProxyUdpSession>;
}

impl<H> BoxedTransparentProxyEngineInner for TransparentProxyEngine<H>
where
    H: TransparentProxyHandler,
{
    fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        self.transparent_proxy_config()
    }

    fn handle_app_message(&self, message: Bytes) -> Option<Bytes> {
        self.handle_app_message(message)
    }

    fn stop_box(self: Box<Self>, reason: i32) {
        (*self).stop(reason);
    }

    fn new_tcp_session(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_bytes: BoxedServerBytesSink,
        on_client_read_demand: BoxedDemandSink,
        on_server_closed: BoxedClosedSink,
    ) -> SessionFlowAction<TransparentProxyTcpSession> {
        self.new_tcp_session(
            meta,
            move |bytes| on_server_bytes(bytes.as_ref()),
            move || on_client_read_demand(),
            move || on_server_closed(),
        )
    }

    fn new_udp_session(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_datagram: BoxedServerBytesSink,
        on_client_read_demand: BoxedDemandSink,
        on_server_closed: BoxedClosedSink,
    ) -> SessionFlowAction<TransparentProxyUdpSession> {
        self.new_udp_session(
            meta,
            move |bytes| on_server_datagram(bytes.as_ref()),
            move || on_client_read_demand(),
            move || on_server_closed(),
        )
    }
}

pub struct BoxedTransparentProxyEngine(Box<dyn BoxedTransparentProxyEngineInner>);

impl BoxedTransparentProxyEngine {
    pub fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        self.0.transparent_proxy_config()
    }

    pub fn handle_app_message(&self, message: Bytes) -> Option<Bytes> {
        self.0.handle_app_message(message)
    }

    pub fn stop(self, reason: i32) {
        self.0.stop_box(reason);
    }

    pub fn new_tcp_session(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_bytes: BoxedServerBytesSink,
        on_client_read_demand: BoxedDemandSink,
        on_server_closed: BoxedClosedSink,
    ) -> SessionFlowAction<TransparentProxyTcpSession> {
        self.0.new_tcp_session(
            meta,
            on_server_bytes,
            on_client_read_demand,
            on_server_closed,
        )
    }

    pub fn new_udp_session(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_datagram: BoxedServerBytesSink,
        on_client_read_demand: BoxedDemandSink,
        on_server_closed: BoxedClosedSink,
    ) -> SessionFlowAction<TransparentProxyUdpSession> {
        self.0.new_udp_session(
            meta,
            on_server_datagram,
            on_client_read_demand,
            on_server_closed,
        )
    }
}

impl<H> From<TransparentProxyEngine<H>> for BoxedTransparentProxyEngine
where
    H: TransparentProxyHandler,
{
    fn from(value: TransparentProxyEngine<H>) -> Self {
        Self(Box::new(value))
    }
}

pub fn log_engine_build_error(err: &(dyn std::error::Error + 'static), context: &'static str) {
    tracing::error!(%err, context, "transparent proxy engine build error");
}
