use std::{convert::Infallible, future::Future};

use rama_core::{Service, error::BoxError, rt::Executor};

use crate::{
    TcpFlow, UdpFlow,
    tproxy::{TransparentProxyConfig, TransparentProxyFlowMeta},
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

pub trait TransparentProxyHandler: Send + Sync + 'static {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig;

    fn match_tcp_flow(
        &self,
        _exec: Executor,
        _meta: TransparentProxyFlowMeta,
    ) -> impl Future<Output = FlowAction<impl Service<TcpFlow, Output = (), Error = Infallible>>>
    + Send
    + '_ {
        std::future::ready(FlowAction::<NopSvc>::Passthrough)
    }

    fn match_udp_flow(
        &self,
        _exec: Executor,
        _meta: TransparentProxyFlowMeta,
    ) -> impl Future<Output = FlowAction<impl Service<UdpFlow, Output = (), Error = Infallible>>>
    + Send
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
