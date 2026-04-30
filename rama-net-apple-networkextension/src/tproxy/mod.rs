//! Apple Transparent Proxy Support
//!
//! ## Tech Notes
//!
//! - [App proxy provider — Implement a VPN client for a flow-oriented, custom VPN protocol](https://developer.apple.com/documentation/NetworkExtension/app-proxy-provider)
//! - [NETransparentProxyProvider](https://developer.apple.com/documentation/NetworkExtension/NETransparentProxyProvider)

mod engine;

mod types;

pub use self::{
    engine::{
        BoxedClosedSink, BoxedDemandSink, BoxedServerBytesSink, BoxedTransparentProxyEngine,
        DefaultTransparentProxyAsyncRuntimeFactory, FlowAction, SessionFlowAction,
        TcpDeliverStatus, TransparentProxyAsyncRuntimeFactory, TransparentProxyEngine,
        TransparentProxyEngineBuilder, TransparentProxyHandler, TransparentProxyHandlerFactory,
        TransparentProxyServiceContext, TransparentProxyTcpSession, TransparentProxyUdpSession,
        log_engine_build_error,
    },
    types::{
        NwAttribution, NwEgressParameters, NwInterfaceType, NwMultipathServiceType, NwServiceClass,
        NwTcpConnectOptions, NwUdpConnectOptions, TransparentProxyConfig,
        TransparentProxyFlowAction, TransparentProxyFlowMeta, TransparentProxyFlowProtocol,
        TransparentProxyNetworkRule, TransparentProxyRuleProtocol,
    },
};
pub use crate::process::AuditToken;
