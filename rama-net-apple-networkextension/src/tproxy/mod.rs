//! Apple Transparent Proxy Support
//!
//! ## Tech Notes
//!
//! - [App proxy provider — Implement a VPN client for a flow-oriented, custom VPN protocol](https://developer.apple.com/documentation/NetworkExtension/app-proxy-provider)
//! - [NETransparentProxyProvider](https://developer.apple.com/documentation/NetworkExtension/NETransparentProxyProvider)
//!
//! ## DNS resolution from inside flow handlers
//!
//! Synchronous DNS resolution from inside [`TransparentProxyHandler::match_tcp_flow`]
//! or [`TransparentProxyHandler::match_udp_flow`] can deadlock on macOS when
//! the provider intercepts UDP traffic. The system DNS daemon
//! (`mDNSResponder`) sends UDP queries, which the provider observes; if the
//! handler then itself blocks on DNS to make a decision, a circular wait
//! can form between the provider awaiting a decision and `mDNSResponder`
//! awaiting a flow decision from the provider for its own outbound query.
//!
//! Resolve hostnames out-of-band rather than on the flow-handler hot path:
//!
//! - cache name → IP mappings at startup,
//! - resolve on a separate worker / control plane that runs alongside
//!   the engine, or
//! - rely on [`TransparentProxyFlowMeta::remote_endpoint`], which is
//!   provided by the system as a [`HostWithPort`] and may already carry
//!   the resolved address depending on context.
//!
//! The [decision deadline](TransparentProxyEngineBuilder::with_decision_deadline)
//! and the [watchdog](TransparentProxyEngineBuilder::with_watchdog) are
//! recovery backstops; this guidance is what avoids the wedge in the
//! first place.
//!
//! [`HostWithPort`]: rama_net::address::HostWithPort

mod engine;

mod types;

pub use self::{
    engine::{
        BoxedClosedSink, BoxedDemandSink, BoxedServerBytesSink, BoxedTransparentProxyEngine,
        DecisionDeadlineAction, DefaultTransparentProxyAsyncRuntimeFactory, FlowAction,
        SessionFlowAction, TcpDeliverStatus, TransparentProxyAsyncRuntimeFactory,
        TransparentProxyEngine, TransparentProxyEngineBuilder, TransparentProxyHandler,
        TransparentProxyHandlerFactory, TransparentProxyServiceContext, TransparentProxyTcpSession,
        TransparentProxyUdpSession, WatchdogConfig, log_engine_build_error,
    },
    types::{
        NwAttribution, NwEgressParameters, NwInterfaceType, NwMultipathServiceType, NwServiceClass,
        NwTcpConnectOptions, NwUdpConnectOptions, TransparentProxyConfig,
        TransparentProxyFlowAction, TransparentProxyFlowMeta, TransparentProxyFlowProtocol,
        TransparentProxyNetworkRule, TransparentProxyRuleProtocol,
    },
};
pub use crate::process::AuditToken;
