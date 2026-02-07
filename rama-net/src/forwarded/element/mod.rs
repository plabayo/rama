use super::{ForwardedProtocol, ForwardedVersion, NodeId};
use crate::address::{Domain, HostWithOptPort};
use crate::address::{Host, HostWithPort, SocketAddress};
use ahash::HashMap;
use rama_core::error::BoxError;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::net::{Ipv6Addr, SocketAddr};

#[cfg(feature = "http")]
use rama_http_types::HeaderValue;

mod parser;
#[doc(inline)]
pub(crate) use parser::{parse_one_plus_forwarded_elements, parse_single_forwarded_element};

#[derive(Debug, Clone, PartialEq, Eq)]
/// A single entry in the [`Forwarded`] chain.
///
/// [`Forwarded`]: crate::forwarded::Forwarded
pub struct ForwardedElement {
    by_node: Option<NodeId>,
    for_node: Option<NodeId>,
    authority: Option<ForwardedAuthority>,
    proto: Option<ForwardedProtocol>,
    proto_version: Option<ForwardedVersion>,

    // not expected, but if used these parameters (keys)
    // should be registered ideally also in
    // <https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#forwarded>
    extensions: Option<HashMap<String, ExtensionValue>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExtensionValue {
    value: String,
    quoted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Wrapper of a value [`HostWithOptPort`] to provide some forward-specific utilities.
pub struct ForwardedAuthority(pub HostWithOptPort);

impl ForwardedAuthority {
    /// Create a new [`ForwardedAuthority`]
    #[must_use]
    #[inline(always)]
    pub const fn new(host: Host) -> Self {
        Self(HostWithOptPort::new(host))
    }

    /// Create a new [`ForwardedAuthority`] with port
    #[must_use]
    #[inline(always)]
    pub const fn new_with_port(host: Host, port: u16) -> Self {
        Self(HostWithOptPort::new_with_port(host, port))
    }
}

impl From<Host> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: Host) -> Self {
        Self::new(value)
    }
}

impl From<Domain> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: Domain) -> Self {
        Self::new(value.into())
    }
}

impl From<IpAddr> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: IpAddr) -> Self {
        Self::new(value.into())
    }
}

impl From<Ipv4Addr> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: Ipv4Addr) -> Self {
        Self::new(value.into())
    }
}

impl From<[u8; 4]> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: [u8; 4]) -> Self {
        Self::new(Host::Address(value.into()))
    }
}

impl From<[u8; 16]> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: [u8; 16]) -> Self {
        Self::new(Host::Address(value.into()))
    }
}

impl From<Ipv6Addr> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: Ipv6Addr) -> Self {
        Self::new(value.into())
    }
}

impl From<SocketAddr> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: SocketAddr) -> Self {
        Self(HostWithOptPort {
            host: Host::Address(value.ip()),
            port: Some(value.port()),
        })
    }
}

impl From<SocketAddress> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: SocketAddress) -> Self {
        Self(HostWithOptPort {
            host: Host::Address(value.ip_addr),
            port: Some(value.port),
        })
    }
}

impl From<HostWithOptPort> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: HostWithOptPort) -> Self {
        Self(value)
    }
}

impl From<HostWithPort> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: HostWithPort) -> Self {
        Self::new(value.into())
    }
}

impl ForwardedElement {
    /// Merge the properties of another [`ForwardedElement`] into this one.
    pub fn merge(&mut self, other: Self) -> &mut Self {
        if let Some(by_node) = other.by_node {
            self.by_node = Some(by_node);
        }
        if let Some(for_node) = other.for_node {
            self.for_node = Some(for_node);
        }
        if let Some(authority) = other.authority {
            self.authority = Some(authority);
        }
        if let Some(proto) = other.proto {
            self.proto = Some(proto);
        }
        if let Some(extensions) = other.extensions {
            match &mut self.extensions {
                Some(map) => {
                    map.extend(extensions);
                }
                None => {
                    self.extensions = Some(extensions);
                }
            }
        }
        self
    }

    /// Return the host if one is defined.
    #[must_use]
    pub fn authority(&self) -> Option<HostWithOptPort> {
        self.authority.as_ref().map(|authority| authority.0.clone())
    }

    /// Create a new [`ForwardedElement`] with the "host" parameter set
    /// using the given [`Host`], [`Domain`], [`HostWithPort`], [`IpAddr`], [`SocketAddress`] and more.
    pub fn new_forwarded_host(authority: impl Into<ForwardedAuthority>) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: Some(authority.into()),
            proto: None,
            proto_version: None,
            extensions: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets the "host" parameter in this [`ForwardedElement`] using
        /// the given authority value.
        pub fn forwarded_host(mut self, authority: impl Into<ForwardedAuthority>) -> Self {
            self.authority = Some(authority.into());
            self
        }
    }

    /// Get a reference to the "host" parameter if it is set.
    #[must_use]
    pub fn forwarded_host(&self) -> Option<&ForwardedAuthority> {
        self.authority.as_ref()
    }

    /// Create a new [`ForwardedElement`] with the "for" parameter
    /// set to the given valid node identifier. Examples are
    /// an Ip Address or Domain, with or without a port.
    pub fn new_forwarded_for(node_id: impl Into<NodeId>) -> Self {
        Self {
            by_node: None,
            for_node: Some(node_id.into()),
            authority: None,
            proto: None,
            proto_version: None,
            extensions: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets the "for" parameter for this [`ForwardedElement`] using the given valid node identifier.
        /// Examples are an Ip Address or Domain, with or without a port.
        pub fn forwarded_for(mut self, node_id: impl Into<NodeId>) -> Self {
            self.for_node = Some(node_id.into());
            self
        }
    }

    /// Get a reference to the "for" parameter if it is set.
    #[must_use]
    pub fn forwarded_for(&self) -> Option<&NodeId> {
        self.for_node.as_ref()
    }

    /// Create a new [`ForwardedElement`] with the "by" parameter
    /// set to the given valid node identifier. Examples are
    /// an Ip Address or Domain, with or without a port.
    pub fn new_forwarded_by(node_id: impl Into<NodeId>) -> Self {
        Self {
            by_node: Some(node_id.into()),
            for_node: None,
            authority: None,
            proto: None,
            proto_version: None,
            extensions: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets the "by" parameter for this [`ForwardedElement`] using the given valid node identifier.
        /// Examples are an Ip Address or Domain, with or without a port.
        pub fn forwarded_by(mut self, node_id: impl Into<NodeId>) -> Self {
            self.by_node = Some(node_id.into());
            self
        }
    }

    /// Get a reference to the "by" parameter if it is set.
    #[must_use]
    pub fn forwarded_by(&self) -> Option<&NodeId> {
        self.by_node.as_ref()
    }

    /// Create a new [`ForwardedElement`] with the "proto" parameter
    /// set to the given valid/recognised [`ForwardedProtocol`]
    #[must_use]
    pub fn new_forwarded_proto(protocol: ForwardedProtocol) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: None,
            proto: Some(protocol),
            proto_version: None,
            extensions: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the "proto" parameter to the given valid/recognised [`ForwardedProtocol`].
        pub fn forwarded_proto(mut self, protocol: ForwardedProtocol) -> Self {
            self.proto = Some(protocol);
            self
        }
    }

    /// Get a reference to the "proto" parameter if it is set.
    #[must_use]
    pub fn forwarded_proto(&self) -> Option<ForwardedProtocol> {
        self.proto.clone()
    }

    /// Create a new [`ForwardedElement`] with the "version" parameter
    /// set to the given valid/recognised [`ForwardedVersion`].
    #[must_use]
    pub fn new_forwarded_version(version: ForwardedVersion) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: None,
            proto: None,
            proto_version: Some(version),
            extensions: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the "version" parameter to the given valid/recognised [`ForwardedVersion`].
        pub fn forwarded_version(mut self, version: ForwardedVersion) -> Self {
            self.proto_version = Some(version);
            self
        }
    }

    /// Get a copy of the "version" parameter, if it is set.
    #[must_use]
    pub fn forwarded_version(&self) -> Option<ForwardedVersion> {
        self.proto_version
    }
}

impl fmt::Display for ForwardedAuthority {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for ForwardedElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut separator = "";

        if let Some(ref by_node) = self.by_node {
            write!(f, "by=")?;
            let quoted =
                by_node.has_any_port() || by_node.ip().map(|ip| ip.is_ipv6()).unwrap_or_default();
            if quoted {
                write!(f, r##""{by_node}""##)?;
            } else {
                by_node.fmt(f)?;
            }
            separator = ";";
        }

        if let Some(ref for_node) = self.for_node {
            write!(f, "{separator}for=")?;
            let quoted =
                for_node.has_any_port() || for_node.ip().map(|ip| ip.is_ipv6()).unwrap_or_default();
            if quoted {
                write!(f, r##""{for_node}""##)?;
            } else {
                for_node.fmt(f)?;
            }
            separator = ";";
        }

        if let Some(ref authority) = self.authority {
            write!(f, "{separator}host=")?;
            let quoted = authority.0.port.is_some()
                || matches!(authority.0.host, Host::Address(IpAddr::V6(_)));
            if quoted {
                write!(f, r##""{authority}""##)?;
            } else {
                authority.fmt(f)?;
            }
            separator = ";";
        }

        if let Some(ref proto) = self.proto {
            write!(f, "{separator}proto=")?;
            proto.fmt(f)?;
        }

        Ok(())
    }
}

impl std::str::FromStr for ForwardedElement {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_single_forwarded_element(s.as_bytes())
    }
}

impl TryFrom<String> for ForwardedElement {
    type Error = BoxError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(s.as_bytes())
    }
}

impl TryFrom<&str> for ForwardedElement {
    type Error = BoxError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(s.as_bytes())
    }
}

#[cfg(feature = "http")]
impl TryFrom<HeaderValue> for ForwardedElement {
    type Error = BoxError;

    fn try_from(header: HeaderValue) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(header.as_bytes())
    }
}

#[cfg(feature = "http")]
impl TryFrom<&HeaderValue> for ForwardedElement {
    type Error = BoxError;

    fn try_from(header: &HeaderValue) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(header.as_bytes())
    }
}

impl TryFrom<Vec<u8>> for ForwardedElement {
    type Error = BoxError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(bytes.as_ref())
    }
}

impl TryFrom<&[u8]> for ForwardedElement {
    type Error = BoxError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(bytes)
    }
}

impl std::str::FromStr for ForwardedAuthority {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let address = HostWithOptPort::from_str(s)?;
        Ok(Self(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forwarded_element_parse_invalid() {
        for s in [
            "",
            "foobar",
            "127.0.0.1",
            "⌨️",
            "for=_foo;for=_bar",
            "for=foo,proto=http",
        ] {
            if let Ok(el) = ForwardedElement::try_from(s) {
                panic!("unexpected parse success: input {s}: {el:?}");
            }
        }
    }

    #[test]
    fn test_forwarded_element_parse_happy_spec() {
        for (s, expected) in [
            (
                r##"for="_gazonk""##,
                ForwardedElement::new_forwarded_for(NodeId::try_from("_gazonk").unwrap()),
            ),
            (
                r##"For="[2001:db8:cafe::17]:4711""##,
                ForwardedElement::new_forwarded_for(
                    NodeId::try_from("[2001:db8:cafe::17]:4711").unwrap(),
                ),
            ),
            (
                r##"For="[2001:db8:cafe::17]:4711";proto=http"##,
                ForwardedElement {
                    by_node: None,
                    for_node: Some(NodeId::try_from("[2001:db8:cafe::17]:4711").unwrap()),
                    authority: None,
                    proto: Some(ForwardedProtocol::HTTP),
                    proto_version: None,
                    extensions: None,
                },
            ),
            (
                r##"For="[2001:db8:cafe::17]:4711";proto=http;foo=bar"##,
                ForwardedElement {
                    by_node: None,
                    for_node: Some(NodeId::try_from("[2001:db8:cafe::17]:4711").unwrap()),
                    authority: None,
                    proto: Some(ForwardedProtocol::HTTP),
                    proto_version: None,
                    extensions: Some(
                        [(
                            "foo".to_owned(),
                            ExtensionValue {
                                value: "bar".to_owned(),
                                quoted: false,
                            },
                        )]
                        .into_iter()
                        .collect(),
                    ),
                },
            ),
            (
                r##"for=192.0.2.60;proto=http;by=203.0.113.43"##,
                ForwardedElement {
                    by_node: Some(NodeId::try_from("203.0.113.43").unwrap()),
                    for_node: Some(NodeId::try_from("192.0.2.60").unwrap()),
                    authority: None,
                    proto: Some(ForwardedProtocol::HTTP),
                    proto_version: None,
                    extensions: None,
                },
            ),
        ] {
            let element = match ForwardedElement::try_from(s) {
                Ok(el) => el,
                Err(err) => panic!("failed to parse happy spec el '{s}': {err}"),
            };
            assert_eq!(element, expected, "input: {s}");
        }
    }
}
