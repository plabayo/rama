//! IP proxying over HTTP (RFC 9484), using `rama_net::ip` packet primitives.
//!
//! [`ConnectIpTemplate`] builds H1 Upgrade and H2/H3 Extended CONNECT requests.
//! [`ConnectIpConnector`] wraps an existing HTTP client; [`ConnectIpService`] combines
//! a request admission service with a packet-session handler. Admission returns
//! [`ConnectIpSessionConfig`]; its [`ConnectIpPolicy`] defaults to deny all.
//! Authenticate before admission and explicitly authorize source/destination
//! prefixes. Peer address assignments and routes never grant local permission.
//!
//! [`ConnectIpSession`] is the application packet boundary: send/receive entire
//! IP packets, exchange control snapshots, or split it into send/receive halves.
//! No host interface, route, DNS configuration or privileges are changed. Route
//! and address capsules replace complete snapshots; the caller owns allocation
//! and any administrative installation. The server pins resolved hostname scope
//! for the tunnel lifetime, visible through [`ConnectIpSession::policy`].
//!
//! # Construct a scoped request
//!
//! ```
//! use rama_masque::connect_ip::{ConnectIpScope, ConnectIpTemplate};
//! use rama_http::Version;
//!
//! let template = ConnectIpTemplate::try_new(
//!     "https://proxy.example/.well-known/masque/ip/{target}/{ipproto}/",
//! )?;
//! let scope = ConnectIpScope::new(
//!     rama_masque::connect_ip::IpTarget::Prefix("192.0.2.0/24".parse()?),
//! ).with_protocol(rama_net::ip::IpProtocol::UDP);
//! let request = template.request(&scope, Version::HTTP_3)?;
//! assert_eq!(template.match_request(&request)?, scope);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Forwarding and MTU
//!
//! [`IpPacketOrigin::Forwarded`] decrements TTL/hop limit once on encapsulation;
//! [`IpPacketOrigin::Local`] preserves packets already prepared by a local stack.
//! Receipt does not decrement it. Link-local traffic cannot be forwarded across
//! links. Use `rama_net::ip::icmp::encode_icmp_error` for bounded forwarding-error
//! replies, choosing an authorized source and applying a rate limit. Invalid or
//! unauthorized incoming packets are dropped before delivery to the handler.
//! A client's receive-source policy must also authorize intermediate routers
//! whose ICMP errors it needs (including Packet Too Big for path MTU discovery).
//! Router addresses may lie outside the target scope; the quoted flow is still
//! checked against that scope and local permissions.
//!
//! IPv6 is disabled until an end-to-end link MTU is guaranteed in configuration
//! or [`ConnectIpSession::probe_ipv6_mtu`] succeeds. A local QUIC datagram limit
//! alone does not prove an intermediary path. Native shrink below 1280 aborts
//! the tunnel; oversized native packets do not silently switch to Capsules.
//! H1/H2 and H3 without negotiated datagrams use reliable Capsule delivery and
//! inherit its head-of-line blocking. Packet/byte budgets and send deadlines
//! apply to both carriers. Closing the send half leaves reception active. Dropping
//! an unfinished half aborts the tunnel; completed halves can be dropped independently.
//!
//! No IP reassembly, jumbograms, NAT, DHCP, platform TUN, context compression,
//! or DNS/PREF64 protocol extensions are implemented here.

mod wire;
pub use wire::{
    ADDRESS_ASSIGN, ADDRESS_REQUEST, AddressAssignment, AddressRequest, AddressRequestId,
    ConnectIpCapsule, ConnectIpProtocolError, IpRoute, ROUTE_ADVERTISEMENT, decode_ip_datagram,
    encode_ip_datagram, validate_routes,
};

mod state;
pub use state::{ConnectIpState, ConnectIpStateLimits, ConnectIpStateSnapshot};

mod request;
pub use request::{
    ConnectIpRequestError, ConnectIpScope, ConnectIpTemplate, IpTarget,
    validate_connect_ip_response,
};

mod policy;
pub use policy::{ConnectIpPolicy, ConnectIpRole, IpDirectionPolicy, IpPacketDrop, IpSourcePolicy};

mod session;
pub use session::{
    ConnectIpError, ConnectIpEvent, ConnectIpReceiver, ConnectIpSender, ConnectIpSession,
    ConnectIpSessionConfig, ConnectIpStats, IpPacketOrigin, IpPacketSend,
};

mod limits;
pub use limits::{ConnectIpLimits, PrincipalKey, UserOrClientIpKey};

mod client;
pub use client::{ConnectIpConnector, ConnectIpRequestBuilder};

mod server;
pub use server::{ConnectIpRequest, ConnectIpService};

#[cfg(test)]
mod tests;
