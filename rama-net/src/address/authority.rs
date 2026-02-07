use crate::address::{HostWithOptPort, HostWithPort};
use crate::user::Basic;

use super::{Domain, DomainAddress, Host, SocketAddress};
use rama_core::error::{BoxError, ErrorContext};
use rama_utils::macros::generate_set_and_with;
use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

/// A [`Host`] with optionally a port and/or user-info ([`Basic`]).
///
/// ## Examples
///
/// - example.com
/// - 127.0.0.1
/// - example.com:80
/// - 127.0.0.1:80
/// - joe@example.com:80
/// - joe:secret@example.com
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Authority {
    pub user_info: Option<Basic>,
    pub address: HostWithOptPort,
}

impl Authority {
    /// Creates a new [`Authority`] from a [`HostWithOptPort`].
    #[must_use]
    #[inline(always)]
    pub const fn new(addr: HostWithOptPort) -> Self {
        Self {
            address: addr,
            user_info: None,
        }
    }

    /// Creates a new [`Authority`] from a [`HostWithOptPort`] and user-info ([`Basic`]).
    #[must_use]
    #[inline(always)]
    pub const fn new_with_user_info(addr: HostWithOptPort, user_info: Basic) -> Self {
        Self {
            address: addr,
            user_info: Some(user_info),
        }
    }

    /// creates a new local ipv4 [`Authority`] without a port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::local_ipv4();
    /// assert_eq!("127.0.0.1", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn local_ipv4() -> Self {
        Self::new(HostWithOptPort::local_ipv4())
    }

    /// creates a new local ipv4 [`Authority`] with the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::local_ipv4_with_port(8080);
    /// assert_eq!("127.0.0.1:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn local_ipv4_with_port(port: u16) -> Self {
        Self::new(HostWithOptPort::local_ipv4_with_port(port))
    }

    /// creates a new local ipv6 [`Authority`] without a port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::local_ipv6();
    /// assert_eq!("::1", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn local_ipv6() -> Self {
        Self::new(HostWithOptPort::local_ipv6())
    }

    /// creates a new local ipv6 [`Authority`] with the given port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::local_ipv6_with_port(8080);
    /// assert_eq!("[::1]:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn local_ipv6_with_port(port: u16) -> Self {
        Self::new(HostWithOptPort::local_ipv6_with_port(port))
    }

    /// creates a default ipv4 [`Authority`] without a port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::default_ipv4_with_port(8080);
    /// assert_eq!("0.0.0.0:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn default_ipv4() -> Self {
        Self::new(HostWithOptPort::default_ipv4())
    }

    /// creates a default ipv4 [`Authority`] with the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::default_ipv4_with_port(8080);
    /// assert_eq!("0.0.0.0:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn default_ipv4_with_port(port: u16) -> Self {
        Self::new(HostWithOptPort::default_ipv4_with_port(port))
    }

    /// creates a new default ipv6 [`Authority`] without a port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::default_ipv6();
    /// assert_eq!("::", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn default_ipv6() -> Self {
        Self::new(HostWithOptPort::default_ipv6())
    }

    /// creates a new default ipv6 [`Authority`] with the given port.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::default_ipv6_with_port(8080);
    /// assert_eq!("[::]:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn default_ipv6_with_port(port: u16) -> Self {
        Self::new(HostWithOptPort::default_ipv6_with_port(port))
    }

    /// creates a new broadcast ipv4 [`Authority`] without a port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::broadcast_ipv4();
    /// assert_eq!("255.255.255.255", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn broadcast_ipv4() -> Self {
        Self::new(HostWithOptPort::broadcast_ipv4())
    }

    /// creates a new broadcast ipv4 [`Authority`] with the given port
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::broadcast_ipv4_with_port(8080);
    /// assert_eq!("255.255.255.255:8080", addr.to_string());
    /// ```
    #[must_use]
    #[inline(always)]
    pub const fn broadcast_ipv4_with_port(port: u16) -> Self {
        Self::new(HostWithOptPort::broadcast_ipv4_with_port(port))
    }

    /// Creates a new example domain [`Authority`] without a port.
    #[must_use]
    #[inline(always)]
    pub const fn example_domain() -> Self {
        Self::new(HostWithOptPort::example_domain())
    }

    /// Creates a new example domain [`HostWithOptPort`] for the `http` default port.
    #[must_use]
    #[inline(always)]
    pub const fn example_domain_http() -> Self {
        Self::new(HostWithOptPort::example_domain_http())
    }

    /// Creates a new example domain [`HostWithOptPort`] for the `https` default port.
    #[must_use]
    #[inline(always)]
    pub const fn example_domain_https() -> Self {
        Self::new(HostWithOptPort::example_domain_https())
    }

    /// Creates a new example domain [`HostWithOptPort`] for the given port.
    #[must_use]
    #[inline(always)]
    pub const fn example_domain_with_port(port: u16) -> Self {
        Self::new(HostWithOptPort::example_domain_with_port(port))
    }

    /// Creates a new localhost domain [`HostWithOptPort`] without a port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_domain() -> Self {
        Self::new(HostWithOptPort::localhost_domain())
    }

    /// Creates a new localhost domain [`HostWithOptPort`] for the `http` default port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_domain_http() -> Self {
        Self::new(HostWithOptPort::localhost_domain_http())
    }

    /// Creates a new localhost domain [`HostWithOptPort`] for the `https` default port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_domain_https() -> Self {
        Self::new(HostWithOptPort::localhost_domain_https())
    }

    /// Creates a new localhost domain [`HostWithOptPort`] for the given port.
    #[must_use]
    #[inline(always)]
    pub const fn localhost_domain_with_port(port: u16) -> Self {
        Self::new(HostWithOptPort::localhost_domain_with_port(port))
    }

    generate_set_and_with! {
        /// Set [`Host`] of [`Authority`]
        pub fn host(mut self, host: Host) -> Self {
            self.address.set_host(host);
            self
        }
    }

    generate_set_and_with! {
        /// (un)set port (u16) of [`Authority`]
        pub fn port(mut self, port: Option<u16>) -> Self {
            self.address.maybe_set_port(port);
            self
        }
    }

    generate_set_and_with! {
        /// (un)set user-info ([`Basic`]) of [`Authority`]
        pub fn user_info(mut self, user_info: Option<Basic>) -> Self {
            self.user_info = user_info;
            self
        }
    }
}

impl From<(Domain, u16)> for Authority {
    #[inline(always)]
    fn from((domain, port): (Domain, u16)) -> Self {
        (Host::Name(domain), port).into()
    }
}

impl From<(IpAddr, u16)> for Authority {
    #[inline(always)]
    fn from((ip, port): (IpAddr, u16)) -> Self {
        (Host::Address(ip), port).into()
    }
}

impl From<(Ipv4Addr, u16)> for Authority {
    #[inline(always)]
    fn from((ip, port): (Ipv4Addr, u16)) -> Self {
        (Host::Address(IpAddr::V4(ip)), port).into()
    }
}

impl From<([u8; 4], u16)> for Authority {
    #[inline(always)]
    fn from((ip, port): ([u8; 4], u16)) -> Self {
        (Host::Address(IpAddr::V4(ip.into())), port).into()
    }
}

impl From<(Ipv6Addr, u16)> for Authority {
    #[inline(always)]
    fn from((ip, port): (Ipv6Addr, u16)) -> Self {
        (Host::Address(IpAddr::V6(ip)), port).into()
    }
}

impl From<([u8; 16], u16)> for Authority {
    #[inline(always)]
    fn from((ip, port): ([u8; 16], u16)) -> Self {
        (Host::Address(IpAddr::V6(ip.into())), port).into()
    }
}

impl From<Host> for Authority {
    #[inline(always)]
    fn from(host: Host) -> Self {
        Self::new(HostWithOptPort::new(host))
    }
}

impl From<(Host, u16)> for Authority {
    #[inline(always)]
    fn from((host, port): (Host, u16)) -> Self {
        Self::new(HostWithOptPort::new_with_port(host, port))
    }
}

impl From<Authority> for Host {
    #[inline(always)]
    fn from(authority: Authority) -> Self {
        authority.address.host
    }
}

impl From<SocketAddr> for Authority {
    #[inline(always)]
    fn from(addr: SocketAddr) -> Self {
        Self::new(HostWithOptPort::new_with_port(
            Host::Address(addr.ip()),
            addr.port(),
        ))
    }
}

impl From<&SocketAddr> for Authority {
    #[inline(always)]
    fn from(addr: &SocketAddr) -> Self {
        Self::new(HostWithOptPort::new_with_port(
            Host::Address(addr.ip()),
            addr.port(),
        ))
    }
}

impl From<HostWithOptPort> for Authority {
    #[inline(always)]
    fn from(addr: HostWithOptPort) -> Self {
        Self {
            user_info: None,
            address: addr,
        }
    }
}

impl From<Authority> for HostWithOptPort {
    #[inline(always)]
    fn from(addr: Authority) -> Self {
        addr.address
    }
}

impl From<HostWithPort> for Authority {
    #[inline(always)]
    fn from(addr: HostWithPort) -> Self {
        Self {
            user_info: None,
            address: addr.into(),
        }
    }
}

impl From<SocketAddress> for Authority {
    #[inline(always)]
    fn from(addr: SocketAddress) -> Self {
        let SocketAddress { ip_addr, port } = addr;
        Self::new(HostWithOptPort::new_with_port(Host::Address(ip_addr), port))
    }
}

impl From<&SocketAddress> for Authority {
    #[inline(always)]
    fn from(addr: &SocketAddress) -> Self {
        Self::new(HostWithOptPort::new_with_port(
            Host::Address(addr.ip_addr),
            addr.port,
        ))
    }
}

impl From<DomainAddress> for Authority {
    #[inline(always)]
    fn from(addr: DomainAddress) -> Self {
        let DomainAddress { domain, port } = addr;
        Self::from((domain, port))
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref user_info) = self.user_info {
            let username = user_info.username();
            if let Some(password) = user_info.password() {
                write!(f, "{username}:{password}@")?;
            } else {
                write!(f, "{username}@")?;
            }
        }
        self.address.fmt(f)
    }
}

impl std::str::FromStr for Authority {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<String> for Authority {
    type Error = BoxError;

    #[inline(always)]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        try_from_maybe_borrowed_str(s.into())
    }
}

impl TryFrom<&str> for Authority {
    type Error = BoxError;

    #[inline(always)]
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        try_from_maybe_borrowed_str(s.into())
    }
}

fn try_from_maybe_borrowed_str(maybe_borrowed: Cow<'_, str>) -> Result<Authority, BoxError> {
    let mut s = maybe_borrowed.as_ref();

    if s.is_empty() {
        return Err(BoxError::from("empty string is invalid authority"));
    }

    let mut user_info = None;
    if let Some((user_info_s, rest)) = s.split_once('@') {
        user_info = Some(Basic::try_from(user_info_s)?);
        s = rest;
    }

    let host;
    let mut port = None;

    if let Some(last_colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        let first_part = &s[..last_colon];
        if first_part.contains(':') {
            // ipv6
            if first_part.starts_with('[') || first_part.ends_with(']') {
                let value = first_part
                    .strip_prefix('[')
                    .and_then(|value| value.strip_suffix(']'))
                    .context("strip brackets from authority ipv6 host w/ trailing port")?;
                host = Host::Address(IpAddr::V6(
                    value
                        .parse::<Ipv6Addr>()
                        .context("parse authority host as Ipv6 w/ trailing port")?,
                ));

                port = Some(
                    s[last_colon + 1..]
                        .parse()
                        .context("parse authority port string as u16")?,
                );
            } else {
                host = Host::Address(IpAddr::V6(
                    s.parse::<Ipv6Addr>()
                        .context("parse authority host as ipv6 w/o trailing port")?,
                ));
            };
        } else {
            port = Some(
                s[last_colon + 1..]
                    .parse()
                    .context("parse authority port string as u16")?,
            );

            // try ipv4 first, domain afterwards
            host = if let Ok(ipv4) = first_part.parse::<Ipv4Addr>() {
                Host::Address(IpAddr::V4(ipv4))
            } else {
                let mut owned_vec = if user_info.is_some() {
                    s.as_bytes().to_vec()
                } else {
                    maybe_borrowed.into_owned().into_bytes()
                };
                owned_vec.truncate(last_colon);
                let owned_str = String::from_utf8(owned_vec)
                    .context("interpret authority host as utf-8 str")?;
                Host::Name(
                    Domain::try_from(owned_str)
                        .context("parse authority host utf-8 str as domain w/ trailing port")?,
                )
            };
        };
    } else {
        // no port, so either IpAddr or Domain, in that order
        host = if let Ok(ip) = s.parse::<IpAddr>() {
            Host::Address(ip)
        } else {
            let owned_str = if user_info.is_some() {
                s.to_owned()
            } else {
                maybe_borrowed.into_owned()
            };
            Host::Name(
                Domain::try_from(owned_str)
                    .context("parse host utf-8 str as domain w/o trailing port")?,
            )
        };
    }

    Ok(Authority {
        user_info,
        address: HostWithOptPort { host, port },
    })
}

impl TryFrom<Vec<u8>> for Authority {
    type Error = BoxError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let s = String::from_utf8(bytes).context("parse authority from bytes")?;
        s.try_into()
    }
}

impl TryFrom<&[u8]> for Authority {
    type Error = BoxError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes).context("parse authority from bytes")?;
        s.try_into()
    }
}

impl serde::Serialize for Authority {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let address = self.to_string();
        address.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Authority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use crate::user::credentials::basic;
    use rama_utils::str::non_empty_str;

    use super::*;

    #[allow(clippy::needless_pass_by_value)]
    fn assert_eq(
        s: &str,
        authority: Authority,
        user_info: Option<Basic>,
        host: &str,
        port: Option<u16>,
    ) {
        assert_eq!(authority.user_info, user_info, "parsing: {s}");
        assert_eq!(authority.address.host, host, "parsing: {s}");
        assert_eq!(authority.address.port, port, "parsing: {s}");
    }

    #[test]
    fn test_parse_valid() {
        for (s, (expected_user_info, expected_host, expected_port)) in [
            ("example.com", (None, "example.com", None)),
            (
                "user@example.com",
                (
                    Some(Basic::new_insecure(non_empty_str!("user"))),
                    "example.com",
                    None,
                ),
            ),
            (
                "user:password@example.com",
                (
                    Some(Basic::new(
                        non_empty_str!("user"),
                        non_empty_str!("password"),
                    )),
                    "example.com",
                    None,
                ),
            ),
            ("example.com:80", (None, "example.com", Some(80))),
            (
                "user@example.com:80",
                (
                    Some(Basic::new_insecure(non_empty_str!("user"))),
                    "example.com",
                    Some(80),
                ),
            ),
            (
                "user:secret@example.com:80",
                (Some(basic!("user", "secret")), "example.com", Some(80)),
            ),
            (
                "user@::1",
                (
                    Some(Basic::new_insecure(non_empty_str!("user"))),
                    "::1",
                    None,
                ),
            ),
            (
                "user:password@::1",
                (
                    Some(Basic::new(
                        non_empty_str!("user"),
                        non_empty_str!("password"),
                    )),
                    "::1",
                    None,
                ),
            ),
            ("::1", (None, "::1", None)),
            ("[::1]:80", (None, "::1", Some(80))),
            (
                "user@[::1]:80",
                (
                    Some(Basic::new_insecure(non_empty_str!("user"))),
                    "::1",
                    Some(80),
                ),
            ),
            (
                "user:password@[::1]:80",
                (
                    Some(Basic::new(
                        non_empty_str!("user"),
                        non_empty_str!("password"),
                    )),
                    "::1",
                    Some(80),
                ),
            ),
            ("127.0.0.1", (None, "127.0.0.1", None)),
            (
                "user@127.0.0.1",
                (
                    Some(Basic::new_insecure(non_empty_str!("user"))),
                    "127.0.0.1",
                    None,
                ),
            ),
            (
                "user:password@127.0.0.1",
                (
                    Some(Basic::new(
                        non_empty_str!("user"),
                        non_empty_str!("password"),
                    )),
                    "127.0.0.1",
                    None,
                ),
            ),
            ("127.0.0.1:80", (None, "127.0.0.1", Some(80))),
            (
                "user@127.0.0.1:80",
                (
                    Some(Basic::new_insecure(non_empty_str!("user"))),
                    "127.0.0.1",
                    Some(80),
                ),
            ),
            (
                "user:secret@127.0.0.1:80",
                (Some(basic!("user", "secret")), "127.0.0.1", Some(80)),
            ),
            (
                "2001:db8:3333:4444:5555:6666:7777:8888",
                (None, "2001:db8:3333:4444:5555:6666:7777:8888", None),
            ),
            (
                "user@2001:db8:3333:4444:5555:6666:7777:8888",
                (
                    Some(Basic::new_insecure(non_empty_str!("user"))),
                    "2001:db8:3333:4444:5555:6666:7777:8888",
                    None,
                ),
            ),
            (
                "user:secret@2001:db8:3333:4444:5555:6666:7777:8888",
                (
                    Some(basic!("user", "secret")),
                    "2001:db8:3333:4444:5555:6666:7777:8888",
                    None,
                ),
            ),
            (
                "[2001:db8:3333:4444:5555:6666:7777:8888]:80",
                (None, "2001:db8:3333:4444:5555:6666:7777:8888", Some(80)),
            ),
            (
                "user@[2001:db8:3333:4444:5555:6666:7777:8888]:80",
                (
                    Some(Basic::new_insecure(non_empty_str!("user"))),
                    "2001:db8:3333:4444:5555:6666:7777:8888",
                    Some(80),
                ),
            ),
            (
                "user:secret@[2001:db8:3333:4444:5555:6666:7777:8888]:80",
                (
                    Some(basic!("user", "secret")),
                    "2001:db8:3333:4444:5555:6666:7777:8888",
                    Some(80),
                ),
            ),
        ] {
            let msg = format!("parsing '{s}'");

            assert_eq(
                s,
                s.parse().expect(&msg),
                expected_user_info.clone(),
                expected_host,
                expected_port,
            );
            assert_eq(
                s,
                s.try_into().expect(&msg),
                expected_user_info.clone(),
                expected_host,
                expected_port,
            );
            assert_eq(
                s,
                s.to_owned().try_into().expect(&msg),
                expected_user_info.clone(),
                expected_host,
                expected_port,
            );
            assert_eq(
                s,
                s.as_bytes().try_into().expect(&msg),
                expected_user_info.clone(),
                expected_host,
                expected_port,
            );
            assert_eq(
                s,
                s.as_bytes().to_vec().try_into().expect(&msg),
                expected_user_info.clone(),
                expected_host,
                expected_port,
            );
        }
    }

    #[test]
    fn test_parse_invalid() {
        for s in [
            "",
            "-",
            ".",
            ":",
            ":80",
            "-.",
            ".-",
            "[::1]",
            "[2001:db8:3333:4444:5555:6666:7777:8888",
            "2001:db8:3333:4444:5555:6666:7777:8888]",
            "[2001:db8:3333:4444:5555:6666:7777:8888]",
            "example.com:",
            "example.com:-1",
            "example.com:999999",
            "example:com",
            "[127.0.0.1]:80",
            "2001:db8:3333:4444:5555:6666:7777:8888:80",
            ":foo@80",
            ":foo@example.com",
            ":foo@127.0.0.1",
            ":foo@example.com:80",
            ":foo@127.0.0.1:80",
            ":foo@:80",
            ":foo@:80",
        ] {
            let msg = format!("parsing '{s}'");
            assert!(s.parse::<Authority>().is_err(), "{msg}");
            assert!(Authority::try_from(s).is_err(), "{msg}");
            assert!(Authority::try_from(s.to_owned()).is_err(), "{msg}");
            assert!(Authority::try_from(s.as_bytes()).is_err(), "{msg}");
            assert!(Authority::try_from(s.as_bytes().to_vec()).is_err(), "{msg}");
        }
    }

    #[test]
    fn test_parse_display() {
        for (s, expected) in [
            ("example.com", "example.com"),
            ("user@example.com", "user@example.com"),
            ("user:secret@example.com", "user:secret@example.com"),
            ("example.com:80", "example.com:80"),
            ("user@example.com:80", "user@example.com:80"),
            ("user:secret@example.com:80", "user:secret@example.com:80"),
            ("[::1]:80", "[::1]:80"),
            ("user@[::1]:80", "user@[::1]:80"),
            ("secret:user@[::1]:80", "secret:user@[::1]:80"),
            ("::1", "::1"),
            ("user@::1", "user@::1"),
            ("user:secret@::1", "user:secret@::1"),
            ("127.0.0.1:80", "127.0.0.1:80"),
            ("user@127.0.0.1:80", "user@127.0.0.1:80"),
            ("user:secret@127.0.0.1:80", "user:secret@127.0.0.1:80"),
            ("127.0.0.1", "127.0.0.1"),
            ("user@127.0.0.1", "user@127.0.0.1"),
            ("user:secret@127.0.0.1", "user:secret@127.0.0.1"),
        ] {
            let msg = format!("parsing '{s}'");
            let authority: Authority = s.parse().expect(&msg);
            assert_eq!(authority.to_string(), expected, "{msg}");
        }
    }
}
