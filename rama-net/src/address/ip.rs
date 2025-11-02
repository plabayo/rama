//! IP constants and utilities

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IPv4 address with the address pointing to localhost: `127.0.0.1`
pub const IPV4_LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// An IPv4 address representing an unspecified address: `0.0.0.0`
///
/// This corresponds to the constant `INADDR_ANY` in other languages.
pub const IPV4_UNSPECIFIED: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// An IPv4 address representing the broadcast address: `255.255.255.255`.
pub const IPV4_BROADCAST: IpAddr = IpAddr::V4(Ipv4Addr::BROADCAST);

/// An IPv6 address representing localhost: `::1`.
///
/// This corresponds to constant `IN6ADDR_LOOPBACK_INIT` or `in6addr_loopback` in other
/// languages.
pub const IPV6_LOCALHOST: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

/// An IPv6 address representing the unspecified address: `::`.
///
/// This corresponds to constant `IN6ADDR_ANY_INIT` or `in6addr_any` in other languages.
pub const IPV6_UNSPECIFIED: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// The IPv6 All Nodes multicast address in link-local scope, as defined in
/// [RFC 4291 Section 2.7.1].
///
/// [RFC 4291 Section 2.7.1]: https://tools.ietf.org/html/rfc4291#section-2.7.1
pub const IPV6_ALL_NODES_LINK_LOCAL: IpAddr =
    IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));

/// The IPv6 All Routers multicast address in link-local scope, as defined
/// in [RFC 4291 Section 2.7.1].
///
/// [RFC 4291 Section 2.7.1]: https://tools.ietf.org/html/rfc4291#section-2.7.1
pub const IPV6_ALL_ROUTERS_LINK_LOCAL: IpAddr =
    IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2));
