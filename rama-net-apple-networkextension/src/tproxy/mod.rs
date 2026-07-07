//! Apple Transparent Proxy Support
//!
//! ## Tech Notes
//!
//! - [App proxy provider — Implement a VPN client for a flow-oriented, custom VPN protocol](https://developer.apple.com/documentation/NetworkExtension/app-proxy-provider)
//! - [NETransparentProxyProvider](https://developer.apple.com/documentation/NetworkExtension/NETransparentProxyProvider)
//! - [`handleNewFlow(_:)` — return `false` "indicates that the flow should be closed"](https://developer.apple.com/documentation/networkextension/neappproxyprovider/handlenewflow(_:))
//! - [Apple DTS: returning `false` can fail the originating process; set up rules so you're not passed the flow (TCP)](https://developer.apple.com/forums/thread/716594)
//! - [Apple DTS: transparent proxy UDP flows / not-handling a flow](https://developer.apple.com/forums/thread/690456)
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
//! ## System HTTP/SOCKS proxy loop
//!
//! With a system HTTP/SOCKS proxy enabled (Charles, Proxyman, corporate
//! PAC, …) the kernel routes our egress back through it, the proxy
//! re-emits, and we intercept again — a loop. Swift sets
//! `NWParameters.preferNoProxies = true` on egress by default (see
//! `makeTcpNwParameters` + Apple TN3134); opt back in via
//! [`NwEgressParameters::allow_system_proxy`]. Scope is the
//! SystemConfiguration proxy table only — other NE providers and VPN
//! tunnels in the stack are unaffected.
//!
//! ## Declining a flow (`return false`) IS the per-flow passthrough mechanism
//!
//! For **`NETransparentProxyProvider`** — which is what this crate's provider
//! subclasses — Apple documents the decline explicitly as a hand-off, not a
//! close: "Returning `NO` from `handleNewFlow(_:)` and
//! `handleNewUDPFlow(_:initialRemoteEndpoint:)` causes the flow to proceed to
//! communicate directly with the flow's ultimate destination, instead of
//! closing the flow with a 'Connection Refused' error." The oft-quoted "the
//! flow should be closed" text belongs to `NEAppProxyProvider`, the **base
//! class** (per-app proxies with app rules), whose semantics the transparent
//! subclass deliberately overrides; DTS reports of declined flows killing the
//! originating process concern that base-class behavior. Fleet-scale
//! production of this crate (all UDP passthrough since inception, and all TCP
//! passthrough until 2026-06) confirms the transparent-provider hand-off on
//! the supported macOS range.
//!
//! History: between 2026-06-24 and 2026-07-07 this crate instead *claimed*
//! up-front-passthrough TCP flows and spliced them in-provider
//! ("born-splice"), on the belief that declining closes them. That gave every
//! passthrough flow an in-provider egress `NWConnection`; each
//! `nw_connection_start` pays an NECP path-update walk over every registered
//! endpoint handler in the process (O(N), serialized on one workloop), so
//! under a SASE re-originator (Zscaler Client Connector re-emits ~all machine
//! traffic from one process, matched passthrough by policy) the provider
//! collapsed at 100% CPU and took the host's connectivity with it. Do **not**
//! reintroduce claim-and-splice as a passthrough mechanism.
//!
//! The two passthrough tiers, by decision shape:
//!
//! - **`excludedNetworkRules`** — the flow is never diverted to the provider,
//!   so it takes the default path with zero involvement. Correct for static,
//!   remote-endpoint/CIDR-shaped exclusions (private ranges, known VPN infra).
//! - **decline in the handler (`return false`)** — per-flow / per-app
//!   decisions that can't be expressed as a static rule. The flow proceeds
//!   directly per the transparent-provider contract above, at zero further
//!   cost to the provider.
//!
//! [`HostWithPort`]: rama_net::address::HostWithPort
//! [`NwEgressParameters::preserve_original_meta_data`]: types::NwEgressParameters::preserve_original_meta_data
//! [`NwEgressParameters::allow_system_proxy`]: types::NwEgressParameters::allow_system_proxy

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9;

pub(crate) mod engine;

mod types;

pub use self::{
    engine::{
        BoxedClosedSink, BoxedDemandSink, BoxedServerBytesSink, BoxedServerDatagramSink,
        BoxedTransparentProxyEngine, DEFAULT_DECISION_DEADLINE, DEFAULT_STOP_DRAIN_MAX_WAIT,
        DEFAULT_TCP_IDLE_TIMEOUT, DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT, DEFAULT_UDP_IDLE_TIMEOUT,
        DEFAULT_UDP_MAX_FLOW_LIFETIME, DecisionDeadlineAction,
        DefaultTransparentProxyAsyncRuntimeFactory, FlowAction, Promote, PromoteError,
        PromoteHandle, PromoteLayer, SessionFlowAction, TcpDeliverStatus,
        TransparentProxyAsyncRuntime, TransparentProxyAsyncRuntimeFactory, TransparentProxyEngine,
        TransparentProxyEngineBuilder, TransparentProxyHandler, TransparentProxyHandlerFactory,
        TransparentProxyServiceContext, TransparentProxyTcpSession, TransparentProxyUdpSession,
        log_engine_build_error,
    },
    types::{
        NwAttribution, NwEgressParameters, NwInterfaceType, NwMultipathServiceType, NwServiceClass,
        NwTcpConnectOptions, TransparentProxyConfig, TransparentProxyFlowAction,
        TransparentProxyFlowMeta, TransparentProxyFlowProtocol, TransparentProxyNetworkRule,
        TransparentProxyRuleProtocol,
    },
};
pub use crate::process::AuditToken;
