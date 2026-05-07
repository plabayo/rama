//! Apple Transparent Proxy Support
//!
//! ## Tech Notes
//!
//! - [App proxy provider — Implement a VPN client for a flow-oriented, custom VPN protocol](https://developer.apple.com/documentation/NetworkExtension/app-proxy-provider)
//! - [NETransparentProxyProvider](https://developer.apple.com/documentation/NetworkExtension/NETransparentProxyProvider)
//!
//! ## Re-entrant traffic deadlocks in flow handlers
//!
//! Anything a [`TransparentProxyHandler::match_tcp_flow`] /
//! [`TransparentProxyHandler::match_udp_flow`] handler does
//! synchronously that itself produces network traffic the provider
//! intercepts can wedge: the new traffic shows up as a flow whose
//! decision the engine is waiting for, which can't make progress
//! because the original call hasn't returned. DNS lookups (UDP/53,
//! TCP/53, mDNSResponder, DoH) are the most common offenders, but the
//! pattern applies to any out-of-band traffic the handler initiates
//! (control-plane HTTP fetch, telemetry post, NTP, etc.) when it goes
//! through the same network stack.
//!
//! Mitigations:
//!
//! - keep the handler async-correct and don't issue traffic from it
//!   on the hot path,
//! - resolve / fetch on a separate worker outside the engine,
//! - cache decisions / lookups at startup,
//! - rely on [`TransparentProxyFlowMeta::remote_endpoint`], which the
//!   system already provides as a [`HostWithPort`].
//!
//! The [decision deadline](TransparentProxyEngineBuilder::with_decision_deadline)
//! is a recovery backstop; this guidance is what avoids the wedge in
//! the first place.
//!
//! [`HostWithPort`]: rama_net::address::HostWithPort

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9;

mod engine;

mod types;

pub use self::{
    engine::{
        BoxedClosedSink, BoxedDemandSink, BoxedServerBytesSink, BoxedTransparentProxyEngine,
        DEFAULT_DECISION_DEADLINE, DEFAULT_TCP_IDLE_TIMEOUT, DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT,
        DEFAULT_UDP_MAX_FLOW_LIFETIME, DecisionDeadlineAction,
        DefaultTransparentProxyAsyncRuntimeFactory, FlowAction, SessionFlowAction,
        TcpDeliverStatus, TransparentProxyAsyncRuntime, TransparentProxyAsyncRuntimeFactory,
        TransparentProxyEngine, TransparentProxyEngineBuilder, TransparentProxyHandler,
        TransparentProxyHandlerFactory, TransparentProxyServiceContext, TransparentProxyTcpSession,
        TransparentProxyUdpSession, log_engine_build_error,
    },
    types::{
        NwAttribution, NwEgressParameters, NwInterfaceType, NwMultipathServiceType, NwServiceClass,
        NwTcpConnectOptions, NwUdpConnectOptions, TransparentProxyConfig,
        TransparentProxyFlowAction, TransparentProxyFlowMeta, TransparentProxyFlowProtocol,
        TransparentProxyNetworkRule, TransparentProxyRuleProtocol,
    },
};
pub use crate::process::AuditToken;
