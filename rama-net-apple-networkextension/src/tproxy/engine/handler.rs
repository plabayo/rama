use std::{convert::Infallible, future::Future};

use rama_core::{Service, bytes::Bytes, error::BoxError, io::BridgeIo, rt::Executor};

use crate::{
    NwTcpStream, NwUdpSocket, TcpFlow, UdpFlow,
    tproxy::{
        TransparentProxyConfig, TransparentProxyFlowMeta,
        types::{NwTcpConnectOptions, NwUdpConnectOptions},
    },
};

use super::TransparentProxyServiceContext;

pub trait TransparentProxyHandlerFactory: Send + Sync + 'static {
    type Handler: TransparentProxyHandler;
    type Error: Into<BoxError>;

    fn create_transparent_proxy_handler(
        &self,
        ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send;
}

impl<Handler, Error, F, Fut> TransparentProxyHandlerFactory for F
where
    Handler: TransparentProxyHandler,
    Error: Into<BoxError>,
    F: Fn(TransparentProxyServiceContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Handler, Error>> + Send,
{
    type Handler = Handler;
    type Error = Error;

    #[inline(always)]
    fn create_transparent_proxy_handler(
        &self,
        ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        (self)(ctx)
    }
}

pub enum FlowAction<S> {
    Passthrough,
    Blocked,
    Intercept {
        service: S,
        meta: TransparentProxyFlowMeta,
    },
}

pub trait TransparentProxyHandler: Clone + Send + Sync + 'static {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig;

    /// Handle a provider message from the container app.
    ///
    /// The FFI bridge collapses `None` and `Some(Bytes::new())` to the same
    /// "no reply" outcome on the Swift side (see the `BytesOwned` shim in
    /// `rama_transparent_proxy_engine_handle_app_message`). To send a
    /// distinguishable acknowledgement, return a non-empty payload.
    fn handle_app_message(
        &self,
        _exec: Executor,
        message: Bytes,
    ) -> impl Future<Output = Option<Bytes>> + Send + '_ {
        tracing::debug!(
            message_len = message.len(),
            "transparent proxy app message received without custom handler implementation"
        );
        std::future::ready(None)
    }

    /// Return custom options for the egress `NWConnection` on TCP flows.
    ///
    /// Called by the Swift layer before opening the intercepted flow.
    /// `meta` is the same metadata that will subsequently be passed to
    /// [`match_tcp_flow`](Self::match_tcp_flow).
    ///
    /// Return `None` (the default) to let Swift use sane `NWParameters` defaults.
    fn egress_tcp_connect_options(
        &self,
        _meta: &TransparentProxyFlowMeta,
    ) -> Option<NwTcpConnectOptions> {
        None
    }

    /// Return custom options for the egress `NWConnection` on UDP flows.
    ///
    /// `meta` is the same metadata that will subsequently be passed to
    /// [`match_udp_flow`](Self::match_udp_flow).
    ///
    /// Return `None` (the default) to let Swift use sane `NWParameters` defaults.
    fn egress_udp_connect_options(
        &self,
        _meta: &TransparentProxyFlowMeta,
    ) -> Option<NwUdpConnectOptions> {
        None
    }

    fn match_tcp_flow(
        &self,
        _exec: Executor,
        _meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<TcpFlow, NwTcpStream>, Output = (), Error = Infallible>,
        >,
    > + Send
    + '_ {
        std::future::ready(FlowAction::<NopSvc>::Passthrough)
    }

    fn match_udp_flow(
        &self,
        _exec: Executor,
        _meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<UdpFlow, NwUdpSocket>, Output = (), Error = Infallible>,
        >,
    > + Send
    + '_ {
        std::future::ready(FlowAction::<NopSvc>::Passthrough)
    }
}

#[derive(Debug, Clone)]
struct NopSvc;

impl<Input> Service<Input> for NopSvc {
    type Output = ();
    type Error = Infallible;

    fn serve(
        &self,
        _: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        std::future::ready(Ok(()))
    }
}
