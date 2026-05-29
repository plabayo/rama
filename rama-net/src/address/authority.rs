use crate::address::{HostRef, HostWithOptPort, HostWithPort, OptPort, UserInfo, UserInfoRef};

use super::{Domain, DomainAddress, Host, SocketAddress};
use rama_core::error::extra::OpaqueError;
use rama_core::error::{BoxError, ErrorContext, ErrorExt};
use rama_utils::macros::generate_set_and_with;
use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

/// A [`Host`] with optionally a port and/or user-info ([`UserInfo`]).
///
/// `user_info` is the raw RFC 3986 §3.2.1 view (opaque bytes). For HTTP
/// Basic-Auth interop call [`UserInfo::to_basic`] on it.
///
/// **Planned migration**: in a follow-up PR after the URI work, when
/// rama's [`Basic`](crate::user::Basic) is relaxed to allow empty
/// usernames (per RFC 7617 §2), the intent is to replace
/// `Option<UserInfo>` here with `Option<Basic>`. See the
/// `user_info` module docs for the rationale.
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
    pub user_info: Option<UserInfo>,
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

    /// Creates a new [`Authority`] from a [`HostWithOptPort`] and user-info
    /// ([`UserInfo`]).
    ///
    /// Not `const fn` — `UserInfo` wraps `Bytes` which has no const
    /// constructor; use the builder ([`Self::with_user_info`]) plus
    /// [`UserInfo::from_static`] for the const-friendly path.
    #[must_use]
    #[inline(always)]
    pub fn new_with_user_info(addr: HostWithOptPort, user_info: UserInfo) -> Self {
        Self {
            address: addr,
            user_info: Some(user_info),
        }
    }

    /// Compile-time constructor for a domain-only [`Authority`]
    /// (no user-info, no explicit port). Panics at compile time when
    /// `s` isn't a valid domain.
    #[must_use]
    pub const fn from_static(s: &'static str) -> Self {
        Self::new(HostWithOptPort::new(Host::from_static(s)))
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
    /// IPv6 addresses always render with `[…]` brackets even with no
    /// port — see [`HostWithOptPort`]'s `Display` impl for the
    /// rationale.
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::local_ipv6();
    /// assert_eq!("[::1]", addr.to_string());
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
    /// IPv6 addresses always render with `[…]` brackets even with no
    /// port — see [`HostWithOptPort`]'s `Display` impl for the
    /// rationale.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Authority;
    ///
    /// let addr = Authority::default_ipv6();
    /// assert_eq!("[::]", addr.to_string());
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
        /// Set [`Host`] of [`Authority`]. Accepts any [`Into<Host>`] —
        /// [`Domain`], [`IpAddr`](std::net::IpAddr), and so on.
        pub fn host(mut self, host: impl Into<Host>) -> Self {
            self.address.set_host(host.into());
            self
        }
    }

    generate_set_and_with! {
        /// Set the port of [`Authority`]. Accepts `u16`, `OptPort`, or
        /// `Option<u16>` via [`Into<OptPort>`]. Pass `OptPort::Unset`
        /// to clear.
        pub fn port(mut self, port: impl Into<OptPort>) -> Self {
            self.address.port = port.into();
            self
        }
    }

    /// Relaxed view of the port — `Set(n) → Some(n)`, everything else
    /// `None`. Use when the `Unset` vs `Empty` distinction doesn't matter.
    #[must_use]
    #[inline]
    pub const fn port_u16(&self) -> Option<u16> {
        self.address.port.as_u16()
    }

    generate_set_and_with! {
        /// (un)set user-info ([`UserInfo`]) of [`Authority`]
        pub fn user_info(mut self, user_info: Option<UserInfo>) -> Self {
            self.user_info = user_info;
            self
        }
    }

    /// Borrowed view.
    #[must_use]
    #[inline]
    pub fn view(&self) -> AuthorityRef<'_> {
        AuthorityRef::from(self)
    }
}

impl<'a> From<&'a Authority> for AuthorityRef<'a> {
    fn from(a: &'a Authority) -> Self {
        Self::new(
            a.user_info.as_ref().map(UserInfoRef::from),
            HostRef::from(&a.address.host),
            a.address.port,
        )
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
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.view(), f)
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

/// Reg-name fallback for inputs `Domain::try_from` rejects but the
/// URI reg-name grammar accepts (pct-encoded / sub-delim / raw UTF-8).
/// Validates against the same byte set as the URI parser without
/// constructing a `Uri`.
fn try_as_uninterpreted_host(host_str: &str) -> Result<Host, BoxError> {
    let host = super::UninterpretedHost::try_from_reg_name_str(host_str)
        .context("parse authority host as reg-name")?;
    Ok(Host::Uninterpreted(host))
}

fn try_from_maybe_borrowed_str(maybe_borrowed: Cow<'_, str>) -> Result<Authority, BoxError> {
    let mut s = maybe_borrowed.as_ref();

    if s.is_empty() {
        return Err(
            OpaqueError::from_static_str("empty string is invalid authority").into_box_error(),
        );
    }

    // Split on the *last* `@`. See [`super::parse_utils::find_userinfo_split`]
    // for the rationale (curl / browsers / `url` crate parity, plus the
    // observation that `@` is not in the strict RFC 3986 userinfo grammar
    // and so a permissive consumer that wanted to use it MUST place it
    // before the boundary, not after).
    let mut user_info = None;
    if let Some(idx) = crate::address::parse_utils::find_userinfo_split(s.as_bytes()) {
        // Graceful path: the last-`@` split deliberately leaves
        // earlier `@`s inside the userinfo region (curl / browser /
        // url-crate parity). `UserInfo::try_from(&str)` is strict and
        // would reject those, so we do explicit control-byte
        // screening here and bypass via `from_bytes_unchecked` —
        // mirroring the URI parser's authority handler.
        let ui_bytes = &s.as_bytes()[..idx];
        if ui_bytes.iter().any(|&b| b < 0x20 || b == 0x7F) {
            return Err(
                OpaqueError::from_static_str("userinfo contains control character")
                    .into_box_error(),
            );
        }
        user_info = Some(UserInfo::from_bytes_unchecked(
            rama_core::bytes::Bytes::copy_from_slice(ui_bytes),
        ));
        s = &s[idx + 1..];
    }

    let host;
    let mut port = OptPort::Unset;

    // Standalone bracketed IP-literal (no trailing port): `[::1]` or
    // `[v1.fe80::a]`. Without this fast-path the colon-split below
    // treats the final `:` inside the address as a port separator.
    if s.starts_with('[') && s.ends_with(']') {
        let inside = &s[1..s.len() - 1];
        if inside.is_empty() {
            return Err(OpaqueError::from_static_str("empty bracketed IP-literal").into_box_error());
        }
        // IPvFuture: `[v1.xxx]` — stored as `Uninterpreted(bracketed=true)`
        // verbatim, matching the URI authority parser's shape.
        if matches!(inside.as_bytes().first(), Some(b'v' | b'V')) {
            crate::uri::parser::authority::validate_ipvfuture(inside.as_bytes())
                .map_err(BoxError::from)
                .context("parse bracketed IPvFuture")?;
            return Ok(Authority {
                user_info,
                address: HostWithOptPort {
                    host: Host::Uninterpreted(super::UninterpretedHost::from_validated_bytes(
                        rama_core::bytes::Bytes::copy_from_slice(inside.as_bytes()),
                        true,
                    )),
                    port: OptPort::Unset,
                },
            });
        }
        if crate::address::parse_utils::ipv6_bracket_has_zone(inside.as_bytes()) {
            return Err(OpaqueError::from_static_str(
                "ipv6 zone identifiers (RFC 6874) are not supported",
            )
            .into_box_error());
        }
        let addr = inside
            .parse::<Ipv6Addr>()
            .context("parse bracketed ipv6 authority host without port")?;
        return Ok(Authority {
            user_info,
            address: HostWithOptPort {
                host: Host::Address(IpAddr::V6(addr)),
                port: OptPort::Unset,
            },
        });
    }

    if let Some(last_colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        let first_part = &s[..last_colon];
        if first_part.contains(':') {
            // ipv6 (bare or bracketed, possibly with trailing port)
            let (addr, parsed_port) =
                crate::address::parse_utils::parse_bracketed_ipv6_with_port(s, last_colon)
                    .context("authority: parse ipv6 host")?;
            host = Host::Address(IpAddr::V6(addr));
            port = parsed_port;
        } else {
            // Reject `:port` (empty host before colon). The URI authority
            // parser rejects the same shape — keep the eager paths
            // symmetric.
            if first_part.is_empty() {
                return Err(
                    OpaqueError::from_static_str("empty host before ':port' is invalid")
                        .into_box_error(),
                );
            }
            let port_bytes = &s.as_bytes()[last_colon + 1..];
            port = if port_bytes.is_empty() {
                OptPort::Empty
            } else {
                OptPort::Set(
                    crate::address::parse_utils::parse_port_bytes(port_bytes)
                        .context("parse authority port string as u16")?,
                )
            };

            // try ipv4 first, domain afterwards, then Uninterpreted fallback
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
                match Domain::try_from(owned_str.as_str()) {
                    Ok(domain) => Host::Name(domain),
                    // Pct-encoded reg-name, sub-delim reg-name, etc. — the
                    // URI parser accepts these and the `Host` enum can
                    // represent them. Route through the URI authority-
                    // form parser so the byte-set validation matches.
                    Err(_) => try_as_uninterpreted_host(&owned_str)?,
                }
            };
        };
    } else {
        // no port, so either IpAddr, Domain, or Uninterpreted fallback
        host = if let Ok(ip) = s.parse::<IpAddr>() {
            Host::Address(ip)
        } else {
            let owned_str = if user_info.is_some() {
                s.to_owned()
            } else {
                maybe_borrowed.into_owned()
            };
            match Domain::try_from(owned_str.as_str()) {
                Ok(domain) => Host::Name(domain),
                Err(_) => try_as_uninterpreted_host(&owned_str)?,
            }
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

/// Borrowed view of an [`Authority`] — userinfo + host + port, each
/// borrowing into the underlying buffer. Mirrors the [`HostRef`] /
/// [`DomainRef`](crate::address::DomainRef) /
/// [`UserInfoRef`](super::UserInfoRef) pattern for the rest of the
/// address types.
///
/// Constructed by [`Uri::authority`](crate::uri::Uri::authority) and
/// — eventually — by [`Authority`]'s own borrow accessor.
///
/// `PartialEq` / `Eq` / `Hash` follow the same component-wise rules as
/// the owned [`Authority`] (case-insensitive host via `HostRef`'s impl,
/// strict equality on userinfo / port), so the two types are
/// interchangeable as collection keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorityRef<'a> {
    pub(crate) userinfo: Option<UserInfoRef<'a>>,
    pub(crate) host: HostRef<'a>,
    pub(crate) port: OptPort,
}

impl<'a> AuthorityRef<'a> {
    /// `pub(crate)` constructor — only [`Uri::authority`] and
    /// internal helpers should build one.
    #[must_use]
    #[inline]
    pub(crate) const fn new(
        userinfo: Option<UserInfoRef<'a>>,
        host: HostRef<'a>,
        port: OptPort,
    ) -> Self {
        Self {
            userinfo,
            host,
            port,
        }
    }

    /// Userinfo component, or `None` if the authority has no `@`
    /// (RFC 3986 §3.2.1 userinfo is optional).
    ///
    /// `Some("")` (an empty userinfo before the `@`) is distinct from
    /// `None` — preserved for wire fidelity.
    #[must_use]
    pub fn userinfo(&self) -> Option<UserInfoRef<'a>> {
        self.userinfo
    }

    /// The host component. Always present — every well-formed
    /// authority has a host.
    #[must_use]
    pub fn host(&self) -> HostRef<'a> {
        self.host
    }

    /// The port marker. Distinguishes wire-level `Unset` / `Empty` /
    /// `Set(u16)`. Most callers want [`port_u16`](Self::port_u16) which
    /// collapses to `Option<u16>`.
    #[must_use]
    pub const fn port(&self) -> OptPort {
        self.port
    }

    /// Relaxed view of the port — `Set(n) → Some(n)`, everything else
    /// `None`. Use when the `Unset` vs `Empty` distinction doesn't matter.
    #[must_use]
    #[inline]
    pub const fn port_u16(&self) -> Option<u16> {
        self.port.as_u16()
    }

    /// Promote this borrowed view to an owned [`Authority`] by copying
    /// the underlying bytes. Mirrors the `into_owned` family on the
    /// other borrowed views.
    #[must_use]
    pub fn into_owned(self) -> Authority {
        Authority {
            user_info: self.userinfo.map(|u| u.into_owned()),
            address: HostWithOptPort {
                host: self.host.into_owned(),
                port: self.port,
            },
        }
    }
}

impl fmt::Display for AuthorityRef<'_> {
    /// Renders `[userinfo@]host[:port]`. Matches [`Authority`]'s
    /// `Display` byte-for-byte.
    ///
    /// IPv6 hosts are **always** bracketed (`[ip]`), regardless of
    /// whether a port follows — same rule [`HostWithOptPort`]'s
    /// `Display` uses. Without brackets, `::1:8080` would be ambiguous between
    /// "address `::1` + port `8080`" and "address `::1:8080`, no
    /// port". We bracket inline here rather than delegating to
    /// `HostRef`'s `Display` because that formatter is a standalone-
    /// host renderer that doesn't compose with `:port`.
    ///
    /// Note: userinfo emission is the *Display* contract — wire writers
    /// for HTTP request-targets strip userinfo separately
    /// (`write_http_authority_form` / `write_h2_authority` on
    /// [`crate::uri::Uri`]).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ui) = self.userinfo {
            write!(f, "{ui}@")?;
        }
        match self.host {
            HostRef::Address(IpAddr::V6(ip)) => write!(f, "[{ip}]")?,
            _ => self.host.fmt(f)?,
        }
        self.port.fmt(f)
    }
}

impl serde::Serialize for Authority {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
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
    use super::*;

    #[expect(clippy::needless_pass_by_value)]
    fn assert_eq(
        s: &str,
        authority: Authority,
        user_info: Option<UserInfo>,
        host: &str,
        port: Option<u16>,
    ) {
        assert_eq!(authority.user_info, user_info, "parsing: {s}");
        assert_eq!(authority.address.host, host, "parsing: {s}");
        assert_eq!(authority.address.port.as_u16(), port, "parsing: {s}");
    }

    #[test]
    fn test_parse_valid() {
        for (s, (expected_user_info, expected_host, expected_port)) in [
            ("example.com", (None, "example.com", None)),
            (
                "user@example.com",
                (Some(UserInfo::from_static("user")), "example.com", None),
            ),
            (
                "user:password@example.com",
                (
                    Some(UserInfo::from_static("user:password")),
                    "example.com",
                    None,
                ),
            ),
            ("example.com:80", (None, "example.com", Some(80))),
            // Empty port (`host:`) — `OptPort::Empty`, surfaces as
            // `None` in the relaxed `.as_u16()` view. See the dedicated
            // round-trip test below for the Display check.
            ("example.com:", (None, "example.com", None)),
            (
                "user@example.com:80",
                (Some(UserInfo::from_static("user")), "example.com", Some(80)),
            ),
            (
                "user:secret@example.com:80",
                (
                    Some(UserInfo::from_static("user:secret")),
                    "example.com",
                    Some(80),
                ),
            ),
            (
                "user@::1",
                (Some(UserInfo::from_static("user")), "::1", None),
            ),
            (
                "user:password@::1",
                (Some(UserInfo::from_static("user:password")), "::1", None),
            ),
            ("::1", (None, "::1", None)),
            ("[::1]:80", (None, "::1", Some(80))),
            (
                "user@[::1]:80",
                (Some(UserInfo::from_static("user")), "::1", Some(80)),
            ),
            (
                "user:password@[::1]:80",
                (
                    Some(UserInfo::from_static("user:password")),
                    "::1",
                    Some(80),
                ),
            ),
            ("127.0.0.1", (None, "127.0.0.1", None)),
            (
                "user@127.0.0.1",
                (Some(UserInfo::from_static("user")), "127.0.0.1", None),
            ),
            (
                "user:password@127.0.0.1",
                (
                    Some(UserInfo::from_static("user:password")),
                    "127.0.0.1",
                    None,
                ),
            ),
            ("127.0.0.1:80", (None, "127.0.0.1", Some(80))),
            (
                "user@127.0.0.1:80",
                (Some(UserInfo::from_static("user")), "127.0.0.1", Some(80)),
            ),
            (
                "user:secret@127.0.0.1:80",
                (
                    Some(UserInfo::from_static("user:secret")),
                    "127.0.0.1",
                    Some(80),
                ),
            ),
            (
                "2001:db8:3333:4444:5555:6666:7777:8888",
                (None, "2001:db8:3333:4444:5555:6666:7777:8888", None),
            ),
            (
                "user@2001:db8:3333:4444:5555:6666:7777:8888",
                (
                    Some(UserInfo::from_static("user")),
                    "2001:db8:3333:4444:5555:6666:7777:8888",
                    None,
                ),
            ),
            (
                "user:secret@2001:db8:3333:4444:5555:6666:7777:8888",
                (
                    Some(UserInfo::from_static("user:secret")),
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
                    Some(UserInfo::from_static("user")),
                    "2001:db8:3333:4444:5555:6666:7777:8888",
                    Some(80),
                ),
            ),
            (
                "user:secret@[2001:db8:3333:4444:5555:6666:7777:8888]:80",
                (
                    Some(UserInfo::from_static("user:secret")),
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
            // Empty host with port — eager and lazy paths agree on
            // rejection.
            ":80",
            ":foo@:80",
            // Empty bracketed IP-literal.
            "[]",
            "[2001:db8:3333:4444:5555:6666:7777:8888",
            "2001:db8:3333:4444:5555:6666:7777:8888]",
            "example.com:-1",
            "example.com:999999",
            "[127.0.0.1]:80",
            "2001:db8:3333:4444:5555:6666:7777:8888:80",
            // IPv6 zone identifiers (RFC 9844 `%25en0` wire form) — rejected
            // by both eager and lazy paths with the same `parse_utils`
            // helper.
            "[fe80::1%25en0]",
            "[fe80::1%25en0]:8080",
            "user@[fe80::1%25en0]:8080",
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
    fn ipv6_zone_rejection_has_clear_message() {
        // The eager path now surfaces a specific message instead of letting
        // `Ipv6Addr::parse` fail opaquely on `%25`. Consumers can match on
        // the substring "zone identifiers" for diagnostics.
        let err = Authority::try_from("[fe80::1%25en0]:8080").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("zone identifier") || msg.contains("zone identifiers"),
            "expected zone-identifier message, got: {msg}"
        );
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
            // IPv6 hosts ALWAYS render with `[…]` brackets — even
            // when no port is present — to avoid the `::1:8080`
            // ambiguity. See `HostWithOptPort::Display` for the
            // single-source-of-truth rationale.
            ("::1", "[::1]"),
            ("user@::1", "user@[::1]"),
            ("user:secret@::1", "user:secret@[::1]"),
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

    /// Regression: when an authority contains multiple `@`, the userinfo
    /// section runs up to the *last* `@` (RFC 3986 §3.2 / §3.2.1).
    /// Splitting on the first `@` mis-parsed `user@name:pass@host:80` as
    /// userinfo=`user`, host=`name:pass@host` and rejected it.
    #[test]
    fn regression_authority_userinfo_splits_on_last_at() {
        let auth = Authority::try_from("user@name:pass@example.com:80").unwrap();
        assert_eq!(auth.address.host, "example.com");
        assert_eq!(auth.address.port, OptPort::Set(80));
        let ui = auth.user_info.as_ref().expect("userinfo present");
        let (user, pass) = ui.split_user_password();
        assert_eq!(user, b"user@name");
        assert_eq!(pass, Some(&b"pass"[..]));
    }

    /// Regression: pct-encoded reg-names are accepted by both the URI
    /// parser and the eager `Authority::try_from` path — uniform host
    /// shape across the public API.
    #[test]
    fn authority_try_from_accepts_pct_encoded_reg_name() {
        let from_uri = crate::uri::Uri::parse_authority_form("exa%6Dple.com")
            .unwrap()
            .authority()
            .unwrap()
            .into_owned();
        let direct = Authority::try_from("exa%6Dple.com").unwrap();
        assert_eq!(direct, from_uri);
        // ...and with a port.
        let from_uri_p = crate::uri::Uri::parse_authority_form("exa%6Dple.com:443")
            .unwrap()
            .authority()
            .unwrap()
            .into_owned();
        let direct_p = Authority::try_from("exa%6Dple.com:443").unwrap();
        assert_eq!(direct_p, from_uri_p);
    }

    /// `:port` with empty host is rejected at the eager parser, matching
    /// the URI authority-form parser's behavior. Without this the eager
    /// and lazy paths disagree.
    #[test]
    fn authority_try_from_rejects_empty_host_with_port() {
        Authority::try_from(":80").unwrap_err();
        Authority::try_from(":foo@:80").unwrap_err();
        // Confirm the URI parser agrees.
        crate::uri::Uri::parse_authority_form(":80").unwrap_err();
    }

    /// Standalone bracketed IPvFuture (`[vN.X]`) parses as
    /// `Host::Uninterpreted(bracketed=true)`, mirroring the URI parser.
    #[test]
    fn authority_try_from_bracketed_ipvfuture() {
        let direct = Authority::try_from("[v1.fe80::a]").unwrap();
        let from_uri = crate::uri::Uri::parse_authority_form("[v1.fe80::a]")
            .unwrap()
            .authority()
            .unwrap()
            .into_owned();
        assert_eq!(direct, from_uri);
        assert!(matches!(direct.address.host, Host::Uninterpreted(_)));
    }

    /// Standalone bracketed IPv6 (no trailing port) parses as a typed
    /// `Host::Address`, not as `Host::Uninterpreted`.
    #[test]
    fn authority_try_from_bracketed_ipv6_no_port_is_typed_address() {
        let auth = Authority::try_from("[::1]").unwrap();
        assert!(
            matches!(auth.address.host, Host::Address(IpAddr::V6(_))),
            "expected typed IPv6 Address, got {:?}",
            auth.address.host
        );
        assert_eq!(auth.address.port, OptPort::Unset);
        // Display round-trips with brackets.
        assert_eq!(auth.to_string(), "[::1]");
    }

    /// Regression: RFC 6874 IPv6 zone-ids must never be accepted in an
    /// authority position. See `host::tests::regression_host_rejects_ipv6_zone_id`
    /// for the rationale; this guards the higher-level `Authority` entry
    /// points so a future change to lower-level parsing can't silently
    /// re-allow them.
    #[test]
    fn regression_authority_rejects_ipv6_zone_id() {
        for input in [
            "[fe80::1%eth0]:80",
            "[fe80::1%25eth0]:80",
            "user@[fe80::1%eth0]:80",
        ] {
            assert!(
                Authority::try_from(input).is_err(),
                "authority should reject zone-id input {input:?}",
            );
        }
    }

    // ---- AuthorityRef::Display parity -----------------------

    #[test]
    fn authority_ref_display_matches_owned() {
        for input in [
            "example.com",
            "example.com:443",
            "user@example.com:80",
            "user:secret@example.com:8080",
            "127.0.0.1:8080",
            "[2001:db8::1]:443",
        ] {
            let owned: Authority = input.parse().unwrap();
            let ref_view = AuthorityRef::new(
                owned.user_info.as_ref().map(UserInfoRef::from),
                HostRef::from(&owned.address.host),
                owned.address.port,
            );
            assert_eq!(
                ref_view.to_string(),
                owned.to_string(),
                "AuthorityRef Display must match Authority for {input:?}"
            );
        }
    }
}
