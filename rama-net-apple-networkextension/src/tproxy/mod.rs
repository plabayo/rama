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
//! A system HTTP/SOCKS or PAC proxy can re-originate our TCP egress and
//! cause another interception. [`NwEgressParameters::allow_proxy`] defaults
//! to `false`: Network.framework receives the public direct preference. Swift
//! builds with the opt-in `PrivateNetworkProxyControl` trait additionally use
//! `nw_parameters_set_no_proxy` when available, resolving it once per process.
//! Without the trait or symbol, proxy fallback remains possible.
//! `allow_proxy=true` permits proxy use.
//!
//! The existing establishment log records the request (`allow_proxy`), the
//! applied control (`proxy_policy=allowed|no_proxy_applied|prefer_direct_only`),
//! and the observed `used_proxy` / `proxy_configured` / `proxy_endpoint` fields.
//! Failed establishment normally has no report; proxy use stays unknown while
//! policy, timing, errors and flow metadata remain available. Disabled logging
//! skips report collection.
//!
//! The private control is unsupported by Apple: symbol presence does not prove
//! behavior on future OS releases or App Store eligibility. Validate deployed
//! versions. Other NE providers and VPNs remain in the path. TCP still uses
//! Network.framework with native `NEAppProxyFlow.setMetadata(_:)` stamping.
//!
//! See the SDK's `<Network/parameters.h>` comment for
//! [`nw_parameters_set_prefer_no_proxy`](https://developer.apple.com/documentation/network/nw_parameters_set_prefer_no_proxy(_:_:)),
//! and Apple's [DTS clarification](https://developer.apple.com/forums/thread/828775)
//! and [frameworks reply](https://developer.apple.com/forums/thread/832291).
//!
//! ## Declining a flow (`return false`) IS the per-flow passthrough mechanism
//!
//! For `NETransparentProxyProvider` — which is what this crate's provider
//! subclasses — Apple documents the decline as a hand-off, not a close:
//! "Returning `NO` from `handleNewFlow(_:)` and
//! `handleNewUDPFlow(_:initialRemoteEndpoint:)` causes the flow to proceed to
//! communicate directly with the flow's ultimate destination, instead of
//! closing the flow with a 'Connection Refused' error." The often-quoted "the
//! flow should be closed" text belongs to `NEAppProxyProvider`, the base
//! class, whose semantics the transparent subclass overrides.
//!
//! Do not claim-and-splice passthrough flows instead: every claimed flow
//! costs an in-provider egress `NWConnection`, and NECP makes each
//! connection start pay a path-update walk over all registered handlers in
//! the process, serialized on one workloop. A process that re-originates
//! all machine traffic (SASE clients) then drives the provider to a
//! CPU-bound collapse.
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
//! [`NwEgressParameters::allow_proxy`]: types::NwEgressParameters::allow_proxy

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9;

pub(crate) mod engine;

mod types;

pub use self::{
    engine::{
        BoxedClosedSink, BoxedDemandSink, BoxedServerBytesSink, BoxedServerDatagramSink,
        BoxedTransparentProxyEngine, DEFAULT_DECISION_CONCURRENCY_LIMIT, DEFAULT_DECISION_DEADLINE,
        DEFAULT_STOP_DRAIN_MAX_WAIT, DEFAULT_TCP_IDLE_TIMEOUT, DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT,
        DEFAULT_UDP_IDLE_TIMEOUT, DEFAULT_UDP_INGRESS_GLOBAL_MAX_BYTES,
        DEFAULT_UDP_INGRESS_PER_FLOW_MAX_BYTES, DEFAULT_UDP_INGRESS_PROBE_LEASE,
        DEFAULT_UDP_MAX_FLOW_LIFETIME, DecisionDeadlineAction,
        DefaultTransparentProxyAsyncRuntimeFactory, FlowAction, MAX_UDP_DATAGRAM_PAYLOAD_SIZE,
        MAX_UDP_INGRESS_PROBE_LEASE, Promote, PromoteError, PromoteHandle, PromoteLayer,
        SessionFlowAction, TcpDeliverStatus, TcpEgressReport, TcpProxyPolicy,
        TransparentProxyAsyncRuntime, TransparentProxyAsyncRuntimeFactory, TransparentProxyEngine,
        TransparentProxyEngineBuilder, TransparentProxyHandler, TransparentProxyHandlerFactory,
        TransparentProxyServiceContext, TransparentProxyTcpSession, TransparentProxyUdpSession,
        log_engine_build_error, log_engine_build_panic, tcp_egress_reporting_enabled,
    },
    types::{
        DEFAULT_FLOW_PRESSURE_IDLE_FLOOR_MS, DEFAULT_FLOW_PRESSURE_LOW_WATER,
        DEFAULT_FLOW_PRESSURE_SOFT_CAP, DEFAULT_LIVE_FLOW_HARD_CAP,
        DEFAULT_TCP_BREAKER_CONNECT_TIMEOUT_MS, DEFAULT_TCP_PRESSURE_CONNECT_TIMEOUT_MS,
        DEFAULT_TCP_START_IN_FLIGHT_HARD_CAP, DEFAULT_TCP_START_IN_FLIGHT_SOFT_CAP,
        DEFAULT_TCP_START_LATENCY_BREAKER_CLOSE_P95_MS, DEFAULT_TCP_START_LATENCY_BREAKER_P95_MS,
        DEFAULT_WRITER_MEMORY_MAX_BYTES, DEFAULT_WRITER_MEMORY_MAX_ITEMS, FlowRefusalAction,
        MAX_WRITER_MEMORY_MAX_BYTES, MAX_WRITER_MEMORY_MAX_ITEMS, NwAttribution,
        NwEgressParameters, NwInterfaceType, NwMultipathServiceType, NwServiceClass,
        NwTcpConnectOptions, TransparentProxyConfig, TransparentProxyFlowAction,
        TransparentProxyFlowMeta, TransparentProxyFlowProtocol, TransparentProxyInitConfig,
        TransparentProxyNetworkRule, TransparentProxyRuleProtocol,
        WRITER_MEMORY_UDP_SERVICE_RESERVE_BYTES,
    },
};
pub use crate::process::AuditToken;
