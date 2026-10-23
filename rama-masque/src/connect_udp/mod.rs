//! Proxying UDP in HTTP ([RFC 9298]).
//!
//! [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298

mod context;
#[doc(inline)]
pub use context::{
    ContextId, ContextPayloadError, MAX_UDP_PAYLOAD, decode_context_payload, encode_udp_payload,
};

mod request;
#[doc(inline)]
pub use request::{
    ConnectUdpRequestError, ConnectUdpRequestMatcher, connect_udp_request,
    validate_connect_udp_response,
};

mod target;
#[doc(inline)]
pub use target::{ConnectUdpTarget, ConnectUdpTargetError};
