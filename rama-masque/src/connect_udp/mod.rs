//! Proxying UDP in HTTP ([RFC 9298]).
//!
//! [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298

mod budget;
#[doc(inline)]
pub use budget::{ConnectUdpStats, DatagramRate, PrincipalBudget, TunnelBudget};

mod client;
#[doc(inline)]
pub use client::{
    ConnectUdpConnector, ConnectUdpConnectorLayer, MaybeTunneledSender, MaybeTunneledSocket,
    NAME_TARGET_PEER, OUTER_IDLE_TIMEOUT, OUTER_INITIAL_MTU,
};

mod context;
#[doc(inline)]
pub use context::{
    ContextId, ContextPayloadError, MAX_UDP_PAYLOAD, decode_context_payload, encode_udp_payload,
};

mod limits;
#[doc(inline)]
pub use limits::{
    ConnectUdpLimits, PrincipalKey, TunnelLease, TunnelLimitReached, UserOrClientIpKey,
};

pub mod mitm;

mod policy;
#[doc(inline)]
pub use policy::{
    ConnectUdpAction, ConnectUdpDestination, ConnectUdpPolicy, ConnectUdpRule, ConnectUdpRules,
    DestinationScopePolicy,
};

mod request;
#[doc(inline)]
pub use request::{
    ConnectUdpRequestError, ConnectUdpRequestMatcher, connect_udp_request,
    validate_connect_udp_response,
};

mod server;
#[doc(inline)]
pub use server::{ConnectUdpRelay, ConnectUdpService};

mod socket;
#[doc(inline)]
pub use socket::{
    ConnectUdpCapacityError, ConnectUdpClose, ConnectUdpSender, ConnectUdpSocket,
    ConnectUdpSocketConfig, session_config,
};

mod telemetry;
#[cfg(feature = "opentelemetry")]
#[doc(inline)]
pub use telemetry::ConnectUdpMetrics;

mod target;
#[doc(inline)]
pub use target::{ConnectUdpTarget, ConnectUdpTargetError};
