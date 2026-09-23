use core::net::IpAddr;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::Extension,
};

use crate::address::ip::IntoCanonicalIpAddr as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Extension)]
#[extension(tags(net))]
/// Enum representing the IP modes that can be used by the DNS resolver.
pub enum DnsResolveIpMode {
    #[default]
    Dual,
    SingleIpV4,
    SingleIpV6,
    DualPreferIpV4,
}

impl DnsResolveIpMode {
    /// checks if IPv4 is supported in current mode
    #[must_use]
    pub fn ipv4_supported(&self) -> bool {
        matches!(self, Self::Dual | Self::SingleIpV4 | Self::DualPreferIpV4)
    }

    /// checks if IPv6 is supported in current mode
    #[must_use]
    pub fn ipv6_supported(&self) -> bool {
        matches!(self, Self::Dual | Self::SingleIpV6 | Self::DualPreferIpV4)
    }
}

/// Mode for establishing a connection.
///
/// Classification is by wire family: an IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`, [RFC 4291, Section 2.5.5.2]) counts as IPv4,
/// so [`Self::Ipv6`] rejects it and [`Self::Ipv4`] accepts it.
///
/// [RFC 4291, Section 2.5.5.2]: https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Extension)]
#[extension(tags(net))]
pub enum ConnectIpMode {
    #[default]
    Dual,
    Ipv4,
    Ipv6,
}

impl ConnectIpMode {
    /// Validate the destination's wire family and return its canonical address.
    ///
    /// Shared by IP-literal connectors and DNS address selection. Mapped IPv6
    /// addresses become IPv4 before applying the connection policy.
    pub fn validate_ip(self, ip: IpAddr) -> Result<IpAddr, BoxError> {
        let ip = ip.into_canonical_ip_addr();
        match (ip, self) {
            (IpAddr::V4(_), Self::Ipv6) => {
                Err(BoxError::from_static_str("IPv4 address is not allowed"))
            }
            (IpAddr::V6(_), Self::Ipv4) => {
                Err(BoxError::from_static_str("IPv6 address is not allowed"))
            }
            _ => Ok(ip),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectIpMode;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn connect_ip_modes_classify_canonical_wire_families() {
        let ipv4 = Ipv4Addr::LOCALHOST;
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        for address in [IpAddr::V4(ipv4), IpAddr::V6(ipv4.to_ipv6_mapped())] {
            for mode in [ConnectIpMode::Dual, ConnectIpMode::Ipv4] {
                assert_eq!(mode.validate_ip(address).unwrap(), IpAddr::V4(ipv4));
            }
            ConnectIpMode::Ipv6.validate_ip(address).unwrap_err();
        }
        for mode in [ConnectIpMode::Dual, ConnectIpMode::Ipv6] {
            assert_eq!(mode.validate_ip(ipv6).unwrap(), ipv6);
        }
        ConnectIpMode::Ipv4.validate_ip(ipv6).unwrap_err();
    }
}
