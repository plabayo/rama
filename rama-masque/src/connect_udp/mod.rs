//! Proxying UDP in HTTP ([RFC 9298]).
//!
//! [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298

mod client;
#[doc(inline)]
pub use client::{
    ConnectUdpConnector, ConnectUdpConnectorLayer, MaybeTunneledSender, MaybeTunneledSocket,
    NAME_TARGET_PEER, OUTER_INITIAL_MTU,
};

mod context;
#[doc(inline)]
pub use context::{
    ContextId, ContextPayloadError, MAX_UDP_PAYLOAD, decode_context_payload, encode_udp_payload,
};

mod policy;
#[doc(inline)]
pub use policy::{ConnectUdpDestination, ConnectUdpPolicy, DestinationScopePolicy};

mod request;
#[doc(inline)]
pub use request::{
    ConnectUdpRequestError, ConnectUdpRequestMatcher, connect_udp_request,
    validate_connect_udp_response,
};

mod server;
#[doc(inline)]
pub use server::ConnectUdpService;

mod socket;
#[doc(inline)]
pub use socket::{
    ConnectUdpCapacityError, ConnectUdpClose, ConnectUdpSender, ConnectUdpSocket,
    ConnectUdpSocketConfig, session_config,
};

mod target;
#[doc(inline)]
pub use target::{ConnectUdpTarget, ConnectUdpTargetError};
