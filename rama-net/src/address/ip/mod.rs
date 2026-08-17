//! IP constants and utilities

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod canonical;
pub use canonical::IntoCanonicalIpAddr;

/// Re-export of the [`ipnet`] crate: IPv4/IPv6 network (CIDR) types, exposed so
/// you can name them (e.g. for the typed `MmdbBuilder::insert`) without adding
/// an `ipnet` dependency of your own.
///
/// [`ipnet`]: https://docs.rs/ipnet
pub mod ipnet {
    #[doc(inline)]
    pub use ::ipnet::*;
}

/// Parse an IP network from canonical CIDR syntax or abbreviated IPv4 CIDR
/// syntax commonly emitted by operating-system network configuration APIs.
///
/// Canonical IPv4 and IPv6 networks retain [`ipnet::IpNet`]'s normal parsing
/// behavior. An abbreviated IPv4 address containing one to three octets is
/// completed with zero-valued trailing octets, so `10/8`, `172.16/12`, and
/// `192.168.1/24` parse like `10.0.0.0/8`, `172.16.0.0/12`, and
/// `192.168.1.0/24` respectively.
///
/// This parser does not accept abbreviated IPv4 addresses without a prefix.
pub fn parse_ip_net(value: &str) -> Result<ipnet::IpNet, ipnet::AddrParseError> {
    value.parse().or_else(|original_error| {
        let Some((address, prefix)) = value.split_once('/') else {
            return Err(original_error);
        };
        let Some(prefix) = parse_strict_decimal_u8(prefix) else {
            return Err(original_error);
        };

        let mut octets = [0; 4];
        let mut count = 0;
        for segment in address.split('.') {
            if count == 4 {
                return Err(original_error);
            }
            let Some(octet) = parse_strict_decimal_u8(segment) else {
                return Err(original_error);
            };
            octets[count] = octet;
            count += 1;
        }
        if !(1..=3).contains(&count) {
            return Err(original_error);
        }

        ipnet::Ipv4Net::new(Ipv4Addr::from(octets), prefix)
            .map(ipnet::IpNet::V4)
            .map_err(|_prefix_error| original_error)
    })
}

fn parse_strict_decimal_u8(value: &str) -> Option<u8> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse().ok()
}

pub mod geo;
pub mod private;
pub mod scope;

#[doc(inline)]
pub use scope::{IpScopes, ip_scope, ipv4_scope, ipv6_scope, scope_cidrs};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_net_preserves_canonical_ip_network_syntax() {
        for value in [
            "10.0.0.0/8",
            "192.168.1.42/24",
            "2001:db8::/32",
            "2001:db8::1/128",
        ] {
            assert_eq!(
                parse_ip_net(value).unwrap(),
                value.parse().unwrap(),
                "{value}"
            );
        }
    }

    #[test]
    fn parse_ip_net_completes_abbreviated_ipv4_networks() {
        for (value, expected) in [
            ("10/8", "10.0.0.0/8"),
            ("172.16/12", "172.16.0.0/12"),
            ("192.168.1/24", "192.168.1.0/24"),
            ("169.254/16", "169.254.0.0/16"),
        ] {
            assert_eq!(
                parse_ip_net(value).unwrap(),
                expected.parse().unwrap(),
                "{value}"
            );
        }

        let link_local = parse_ip_net("169.254/16").unwrap();
        assert!(link_local.contains(&IpAddr::V4(Ipv4Addr::new(169, 254, 42, 7))));
        assert!(!link_local.contains(&IpAddr::V4(Ipv4Addr::new(169, 253, 42, 7))));
    }

    #[test]
    fn parse_ip_net_rejects_malformed_abbreviated_ipv4_networks() {
        for value in [
            "10",
            "/8",
            "10./8",
            ".10/8",
            "10..1/8",
            "256/8",
            "10/33",
            "10/-1",
            "10/8/4",
            "10.20.30.40.50/8",
            "+10/8",
            "010/8",
            "10/+8",
            "10/08",
            "10.00/8",
        ] {
            parse_ip_net(value).unwrap_err();
        }
    }
}
