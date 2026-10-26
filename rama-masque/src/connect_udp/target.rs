use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
};

use rama_net::address::{Domain, Host};

/// The UDP target of a CONNECT-UDP tunnel ([RFC 9298 §3]).
///
/// [RFC 9298 §3]: https://datatracker.ietf.org/doc/html/rfc9298#section-3
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectUdpTarget {
    /// A DNS name or IP literal.
    pub host: Host,
    /// The UDP port.
    pub port: NonZeroU16,
}

/// Why `target_host` / `target_port` values do not form a [`ConnectUdpTarget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectUdpTargetError {
    /// `target_host` is missing or empty.
    EmptyHost,
    /// `target_port` is missing or empty.
    EmptyPort,
    /// `target_host` is not an IP literal or ASCII DNS name.
    InvalidHost,
    /// `target_host` is an IPv6 literal with a zone identifier.
    ZoneId,
    /// `target_port` is not an integer from 1 to 65535.
    InvalidPort,
}

impl fmt::Display for ConnectUdpTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyHost => "connect-udp target_host is empty",
            Self::EmptyPort => "connect-udp target_port is empty",
            Self::InvalidHost => "connect-udp target_host is not an IP literal or DNS name",
            Self::ZoneId => "connect-udp target_host may not carry an IPv6 zone identifier",
            Self::InvalidPort => "connect-udp target_port is not an integer from 1 to 65535",
        })
    }
}

impl std::error::Error for ConnectUdpTargetError {}

impl ConnectUdpTarget {
    /// Create a target.
    #[must_use]
    pub fn new(host: Host, port: NonZeroU16) -> Self {
        Self { host, port }
    }

    /// Parse decoded `target_host` and `target_port` template values.
    ///
    /// IPv6 literals are expected without brackets (RFC 9298 §3); bracketed
    /// literals are accepted for compatibility with peers that send them.
    pub fn from_template_values(host: &str, port: &str) -> Result<Self, ConnectUdpTargetError> {
        Ok(Self {
            host: parse_host(host)?,
            port: parse_port(port)?,
        })
    }
}

impl fmt::Display for ConnectUdpTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Address(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            host => write!(f, "{host}:{}", self.port),
        }
    }
}

fn parse_host(host: &str) -> Result<Host, ConnectUdpTargetError> {
    if host.is_empty() {
        return Err(ConnectUdpTargetError::EmptyHost);
    }
    if !host.is_ascii() {
        return Err(ConnectUdpTargetError::InvalidHost);
    }
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if unbracketed.contains(':') {
        if unbracketed.contains('%') {
            return Err(ConnectUdpTargetError::ZoneId);
        }
        return unbracketed
            .parse::<Ipv6Addr>()
            .map(|ip| Host::Address(IpAddr::V6(ip)))
            .map_err(|_error| ConnectUdpTargetError::InvalidHost);
    }
    if unbracketed.len() != host.len() {
        // Brackets only ever enclose IPv6 literals.
        return Err(ConnectUdpTargetError::InvalidHost);
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(Host::Address(IpAddr::V4(ip)));
    }
    Domain::try_from(host)
        .map(Host::Name)
        .map_err(|_error| ConnectUdpTargetError::InvalidHost)
}

fn parse_port(port: &str) -> Result<NonZeroU16, ConnectUdpTargetError> {
    if port.is_empty() {
        return Err(ConnectUdpTargetError::EmptyPort);
    }
    if port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ConnectUdpTargetError::InvalidPort);
    }
    port.parse::<u16>()
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or(ConnectUdpTargetError::InvalidPort)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_template_values() {
        for (host, expected) in [
            ("192.0.2.6", "192.0.2.6:443"),
            ("2001:db8::42", "[2001:db8::42]:443"),
            ("[2001:db8::42]", "[2001:db8::42]:443"),
            ("example.org", "example.org:443"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example:443"),
        ] {
            let target = ConnectUdpTarget::from_template_values(host, "443").unwrap();
            assert_eq!(target.to_string(), expected, "{host}");
        }
        assert_eq!(
            ConnectUdpTarget::from_template_values("example.org", "65535")
                .unwrap()
                .port
                .get(),
            65535
        );
    }

    #[test]
    fn rejects_invalid_template_values() {
        for (host, port, expected) in [
            ("", "443", ConnectUdpTargetError::EmptyHost),
            ("example.org", "", ConnectUdpTargetError::EmptyPort),
            ("example.org", "0", ConnectUdpTargetError::InvalidPort),
            ("example.org", "65536", ConnectUdpTargetError::InvalidPort),
            ("example.org", "+443", ConnectUdpTargetError::InvalidPort),
            ("example.org", "-1", ConnectUdpTargetError::InvalidPort),
            ("example.org", "4 43", ConnectUdpTargetError::InvalidPort),
            ("example.org", "100000", ConnectUdpTargetError::InvalidPort),
            ("fe80::1%eth0", "443", ConnectUdpTargetError::ZoneId),
            ("[fe80::1%25eth0]", "443", ConnectUdpTargetError::ZoneId),
            ("[2001:db8::42", "443", ConnectUdpTargetError::InvalidHost),
            ("2001:db8::42]", "443", ConnectUdpTargetError::InvalidHost),
            ("[192.0.2.6]", "443", ConnectUdpTargetError::InvalidHost),
            ("2001:db8:::42", "443", ConnectUdpTargetError::InvalidHost),
            (
                "caf\u{e9}.example",
                "443",
                ConnectUdpTargetError::InvalidHost,
            ),
            ("bad host", "443", ConnectUdpTargetError::InvalidHost),
            ("a/b", "443", ConnectUdpTargetError::InvalidHost),
        ] {
            assert_eq!(
                ConnectUdpTarget::from_template_values(host, port).unwrap_err(),
                expected,
                "{host}:{port}"
            );
        }
    }
}
