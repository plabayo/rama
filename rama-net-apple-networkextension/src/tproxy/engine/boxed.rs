use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::tproxy::{
    SessionFlowAction, TcpDeliverStatus, TransparentProxyConfig, TransparentProxyFlowMeta,
};
use rama_core::bytes::Bytes;

use super::{
    DrainOutcome, TransparentProxyEngine, TransparentProxyHandler, TransparentProxyTcpSession,
    TransparentProxyUdpSession,
};

pub type BoxedServerBytesSink = Arc<dyn Fn(&[u8]) + Send + Sync + 'static>;
/// Variant of [`BoxedServerBytesSink`] for the TCP response direction. Returns
/// a [`TcpDeliverStatus`] so the bridge can pause when Swift's writer pump is
/// full.
pub(crate) type BoxedServerBytesStatusSink =
    Arc<dyn Fn(&[u8]) -> TcpDeliverStatus + Send + Sync + 'static>;
/// UDP variant of [`BoxedServerBytesSink`]. Receives the datagram
/// payload together with the peer the reply came from — Swift uses
/// `peer` as the `sentBy` endpoint when writing back through
/// `flow.writeDatagrams`. `None` is the safety valve for paths
/// without endpoint attribution.
pub type BoxedServerDatagramSink = Arc<dyn Fn(&[u8], Option<SocketAddr>) + Send + Sync + 'static>;
pub type BoxedClosedSink = Arc<dyn Fn() + Send + Sync + 'static>;
pub type BoxedDemandSink = Arc<dyn Fn() + Send + Sync + 'static>;

trait BoxedTransparentProxyEngineInner: Send + Sync + 'static {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig;
    fn handle_app_message(&self, message: Bytes) -> Option<Bytes>;
    fn notify_system_sleep(&self);
    fn notify_system_wake(&self);
    fn drain_for_sleep(&self, max_wait: Duration) -> DrainOutcome;
    fn stop_box(self: Box<Self>, reason: i32);
    fn new_tcp_session(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_bytes: BoxedServerBytesStatusSink,
        on_client_read_demand: BoxedDemandSink,
        on_server_closed: BoxedClosedSink,
    ) -> SessionFlowAction<TransparentProxyTcpSession>;
    fn new_udp_session(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_datagram: BoxedServerDatagramSink,
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

    fn notify_system_sleep(&self) {
        self.notify_system_sleep();
    }

    fn notify_system_wake(&self) {
        self.notify_system_wake();
    }

    fn drain_for_sleep(&self, max_wait: Duration) -> DrainOutcome {
        self.drain_for_sleep(max_wait)
    }

    fn stop_box(self: Box<Self>, reason: i32) {
        (*self).stop(reason);
    }

    fn new_tcp_session(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_bytes: BoxedServerBytesStatusSink,
        on_client_read_demand: BoxedDemandSink,
        on_server_closed: BoxedClosedSink,
    ) -> SessionFlowAction<TransparentProxyTcpSession> {
        self.new_tcp_session(
            meta,
            move |bytes: &[u8]| -> TcpDeliverStatus { on_server_bytes(bytes) },
            move || on_client_read_demand(),
            move || on_server_closed(),
        )
    }

    fn new_udp_session(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_datagram: BoxedServerDatagramSink,
        on_client_read_demand: BoxedDemandSink,
        on_server_closed: BoxedClosedSink,
    ) -> SessionFlowAction<TransparentProxyUdpSession> {
        self.new_udp_session(
            meta,
            move |datagram: crate::Datagram| {
                on_server_datagram(datagram.payload.as_ref(), datagram.peer)
            },
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

    pub fn notify_system_sleep(&self) {
        self.0.notify_system_sleep();
    }

    pub fn notify_system_wake(&self) {
        self.0.notify_system_wake();
    }

    /// Recoverable system-sleep drain. Forwards to
    /// [`TransparentProxyEngine::drain_for_sleep`]; see that doc for
    /// semantics.
    ///
    /// [`TransparentProxyEngine::drain_for_sleep`]:
    ///     super::TransparentProxyEngine::drain_for_sleep
    pub fn drain_for_sleep(&self, max_wait: Duration) -> DrainOutcome {
        self.0.drain_for_sleep(max_wait)
    }

    pub fn stop(self, reason: i32) {
        self.0.stop_box(reason);
    }

    pub fn new_tcp_session(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_bytes: BoxedServerBytesStatusSink,
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
        on_server_datagram: BoxedServerDatagramSink,
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
