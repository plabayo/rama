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
//! ## Stacked-provider attribution: the packet-filter blind spot
//!
//! When the engine intercepts a flow it opens its own egress
//! `NWConnection` from the extension process. The egress packets
//! that `NWConnection` emits then traverse the rest of the on-system
//! NE stack. Two attribution paths exist:
//!
//! - Downstream **`NEAppProxyProvider`** (e.g. an enterprise proxy
//!   agent running on the same Mac): sees the egress flow as a flow
//!   object and reads its `NEFlowMetaData`. This crate stamps the
//!   original flow's metadata onto the egress `NWParameters` via
//!   `NEAppProxyFlow.setMetadata(_:)` (default behaviour, opt out
//!   via [`NwEgressParameters::preserve_original_meta_data`]) so a
//!   downstream proxy sees the original app rather than the
//!   extension process.
//!
//! - Downstream **`NEFilterPacketProvider`** (e.g. an enterprise
//!   webfilter): operates at L3 packets. It sees the *kernel
//!   socket's owning PID*, which is the extension process — there is
//!   no Apple API that propagates `NEFlowMetaData` (or any other
//!   per-flow attribution) to a packet-level filter. Per-process or
//!   per-bundle policy on a downstream packet filter therefore
//!   evaluates against this extension, not the original app.
//!
//! Deployment implication: stacked with a packet-level filter that
//! has per-process / per-bundle deny rules, this extension's egress
//! is treated as a single distinct process for that filter's
//! policy. Either allowlist the extension's signing identifier in
//! the upstream filter, or carve out the affected destinations in
//! the handler's passthrough policy. There is no rama-side fix;
//! this is a framework-level constraint.
//!
//! [`HostWithPort`]: rama_net::address::HostWithPort
//! [`NwEgressParameters::preserve_original_meta_data`]: types::NwEgressParameters::preserve_original_meta_data

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9;

mod engine;

mod types;

pub use self::{
    engine::{
        BoxedClosedSink, BoxedDemandSink, BoxedServerBytesSink, BoxedServerDatagramSink,
        BoxedTransparentProxyEngine, DEFAULT_DECISION_DEADLINE, DEFAULT_TCP_IDLE_TIMEOUT,
        DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT, DEFAULT_UDP_MAX_FLOW_LIFETIME, DecisionDeadlineAction,
        DefaultTransparentProxyAsyncRuntimeFactory, FlowAction, SessionFlowAction,
        TcpDeliverStatus, TransparentProxyAsyncRuntime, TransparentProxyAsyncRuntimeFactory,
        TransparentProxyEngine, TransparentProxyEngineBuilder, TransparentProxyHandler,
        TransparentProxyHandlerFactory, TransparentProxyServiceContext, TransparentProxyTcpSession,
        TransparentProxyUdpSession, log_engine_build_error,
    },
    types::{
        NwAttribution, NwEgressParameters, NwInterfaceType, NwMultipathServiceType, NwServiceClass,
        NwTcpConnectOptions, TransparentProxyConfig, TransparentProxyFlowAction,
        TransparentProxyFlowMeta, TransparentProxyFlowProtocol, TransparentProxyNetworkRule,
        TransparentProxyRuleProtocol,
    },
};
pub use crate::process::AuditToken;
