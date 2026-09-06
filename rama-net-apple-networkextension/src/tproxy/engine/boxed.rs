use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::tproxy::{
    SessionFlowAction, TcpDeliverStatus, TransparentProxyConfig, TransparentProxyFlowMeta,
};
use rama_core::bytes::Bytes;

use super::{
    TransparentProxyEngine, TransparentProxyHandler, TransparentProxyTcpSession,
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
type BoxedUdpDemandSink = Arc<dyn Fn(u64) + Send + Sync + 'static>;

trait BoxedTransparentProxyEngineInner: Send + Sync + 'static {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig;
    fn udp_idle_timeout_ms(&self) -> u64;
    fn udp_channel_capacity(&self) -> usize;
    fn udp_ingress_per_flow_max_bytes(&self) -> usize;
    fn udp_ingress_global_max_bytes(&self) -> usize;
    fn writer_memory_max_bytes(&self) -> usize;
    fn writer_memory_max_items(&self) -> usize;
    fn udp_ingress_probe_lease(&self) -> Duration;
    fn handle_app_message(&self, message: Bytes) -> Option<Bytes>;
    fn notify_system_sleep(&self);
    fn notify_system_wake(&self);
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
        on_client_read_demand: BoxedUdpDemandSink,
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

    fn udp_idle_timeout_ms(&self) -> u64 {
        self.udp_idle_timeout_ms()
    }

    fn udp_channel_capacity(&self) -> usize {
        self.udp_channel_capacity()
    }

    fn udp_ingress_per_flow_max_bytes(&self) -> usize {
        self.udp_ingress_per_flow_max_bytes()
    }

    fn udp_ingress_global_max_bytes(&self) -> usize {
        self.udp_ingress_global_max_bytes()
    }

    fn writer_memory_max_bytes(&self) -> usize {
        self.writer_memory_max_bytes()
    }

    fn writer_memory_max_items(&self) -> usize {
        self.writer_memory_max_items()
    }

    fn udp_ingress_probe_lease(&self) -> Duration {
        self.udp_ingress_probe_lease()
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
        on_client_read_demand: BoxedUdpDemandSink,
        on_server_closed: BoxedClosedSink,
    ) -> SessionFlowAction<TransparentProxyUdpSession> {
        self.new_udp_session(
            meta,
            move |datagram: crate::Datagram| {
                on_server_datagram(datagram.payload.as_ref(), datagram.peer)
            },
            move |probe_id| on_client_read_demand(probe_id),
            move || on_server_closed(),
        )
    }
}

pub struct BoxedTransparentProxyEngine(Box<dyn BoxedTransparentProxyEngineInner>);

impl BoxedTransparentProxyEngine {
    pub fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        self.0.transparent_proxy_config()
    }

    pub fn udp_idle_timeout_ms(&self) -> u64 {
        self.0.udp_idle_timeout_ms()
    }

    pub fn udp_channel_capacity(&self) -> usize {
        self.0.udp_channel_capacity()
    }

    pub fn udp_ingress_per_flow_max_bytes(&self) -> usize {
        self.0.udp_ingress_per_flow_max_bytes()
    }

    pub fn udp_ingress_global_max_bytes(&self) -> usize {
        self.0.udp_ingress_global_max_bytes()
    }

    pub fn writer_memory_max_bytes(&self) -> usize {
        self.0.writer_memory_max_bytes()
    }

    pub fn writer_memory_max_items(&self) -> usize {
        self.0.writer_memory_max_items()
    }

    pub fn udp_ingress_probe_lease(&self) -> Duration {
        self.0.udp_ingress_probe_lease()
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
        on_client_read_demand: BoxedUdpDemandSink,
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

/// Log a panic caught at an exported C boundary without attempting to carry
/// its opaque payload across that boundary.
pub fn log_engine_build_panic(context: &'static str) {
    tracing::error!(context, "transparent proxy application callback panicked");
}
