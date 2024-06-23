use super::{ForwardedProtocol, ForwardedVersion, NodeId};
use crate::http::HeaderValue;
use crate::{
    error::{ErrorContext, OpaqueError},
    net::address::{Authority, Host},
};
use std::fmt;
use std::net::SocketAddr;
use std::{collections::HashMap, net::IpAddr};

mod parser;
#[doc(inline)]
pub(crate) use parser::{parse_one_plus_forwarded_elements, parse_single_forwarded_element};

#[derive(Debug, Clone, PartialEq, Eq)]
/// A single entry in the [`Forwarded`] chain.
///
/// [`Forwarded`]: crate::net::forwarded::Forwarded
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

#[derive(Debug, Clone, PartialEq, Eq)]
/// Similar to [`Authority`] but with the port being optional.
pub struct ForwardedAuthority {
    host: Host,
    port: Option<u16>,
}

impl ForwardedAuthority {
    /// Create a new [`ForwardedAuthority`]
    pub fn new(host: Host, port: Option<u16>) -> Self {
        Self { host, port }
    }

    /// Get a reference to the [`Host`] of this [`ForwardedAuthority`].
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Get a copy of the `port` of this [`ForwardedAuthority`] if it is set.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Consume self and return the inner [`Host`] and `port` if it is set.
    pub fn into_parts(self) -> (Host, Option<u16>) {
        (self.host, self.port)
    }
}

impl From<Host> for ForwardedAuthority {
    fn from(value: Host) -> Self {
        Self {
            host: value,
            port: None,
        }
    }
}

impl From<SocketAddr> for ForwardedAuthority {
    fn from(value: SocketAddr) -> Self {
        Self {
            host: value.ip().into(),
            port: Some(value.port()),
        }
    }
}

impl From<Authority> for ForwardedAuthority {
    fn from(value: Authority) -> Self {
        let (host, port) = value.into_parts();
        Self {
            host,
            port: Some(port),
        }
    }
}

impl ForwardedElement {
    /// Merge the properties of another [`ForwardedElement`] into this one.
    pub fn merge(&mut self, other: ForwardedElement) -> &mut Self {
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
    pub fn authority(&self) -> Option<(Host, Option<u16>)> {
        self.authority
            .as_ref()
            .map(|authority| (authority.host.clone(), authority.port))
    }

    /// Create a new [`ForwardedElement`] with the "host" parameter set
    /// using the given [`Host`], [`Authority`] or [`SocketAddr`].
    pub fn forwarded_host(authority: impl Into<ForwardedAuthority>) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: Some(authority.into()),
            proto: None,
            proto_version: None,
            extensions: None,
        }
    }

    /// Sets the "host" parameter in this [`ForwardedElement`] using
    /// the given [`Host`], [`Authority`] or [`SocketAddr`].
    pub fn set_forwarded_host(&mut self, authority: impl Into<ForwardedAuthority>) -> &mut Self {
        self.authority = Some(authority.into());
        self
    }

    /// Get a reference to the "host" parameter if it is set.
    pub fn ref_forwarded_host(&self) -> Option<&ForwardedAuthority> {
        self.authority.as_ref()
    }

    /// Create a new [`ForwardedElement`] with the "for" parameter
    /// set to the given valid node identifier. Examples are
    /// an Ip Address or Domain, with or without a port.
    pub fn forwarded_for(node_id: impl Into<NodeId>) -> Self {
        Self {
            by_node: None,
            for_node: Some(node_id.into()),
            authority: None,
            proto: None,
            proto_version: None,
            extensions: None,
        }
    }

    /// Sets the "for" parameter for this [`ForwardedElement`] using the given valid node identifier.
    /// Examples are an Ip Address or Domain, with or without a port.
    pub fn set_forwarded_for(&mut self, node_id: impl Into<NodeId>) -> &mut Self {
        self.for_node = Some(node_id.into());
        self
    }

    /// Get a reference to the "for" parameter if it is set.
    pub fn ref_forwarded_for(&self) -> Option<&NodeId> {
        self.for_node.as_ref()
    }

    /// Create a new [`ForwardedElement`] with the "by" parameter
    /// set to the given valid node identifier. Examples are
    /// an Ip Address or Domain, with or without a port.
    pub fn forwarded_by(node_id: impl Into<NodeId>) -> Self {
        Self {
            by_node: Some(node_id.into()),
            for_node: None,
            authority: None,
            proto: None,
            proto_version: None,
            extensions: None,
        }
    }

    /// Sets the "by" parameter for this [`ForwardedElement`] using the given valid node identifier.
    /// Examples are an Ip Address or Domain, with or without a port.
    pub fn set_forwarded_by(&mut self, node_id: impl Into<NodeId>) -> &mut Self {
        self.by_node = Some(node_id.into());
        self
    }

    /// Get a reference to the "by" parameter if it is set.
    pub fn ref_forwarded_by(&self) -> Option<&NodeId> {
        self.by_node.as_ref()
    }

    /// Create a new [`ForwardedElement`] with the "proto" parameter
    /// set to the given valid/recognised [`ForwardedProtocol`]
    pub fn forwarded_proto(protocol: ForwardedProtocol) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: None,
            proto: Some(protocol),
            proto_version: None,
            extensions: None,
        }
    }

    /// Set the "proto" parameter to the given valid/recognised [`ForwardedProtocol`].
    pub fn set_forwarded_proto(&mut self, protocol: ForwardedProtocol) -> &mut Self {
        self.proto = Some(protocol);
        self
    }

    /// Get a reference to the "proto" parameter if it is set.
    pub fn ref_forwarded_proto(&self) -> Option<ForwardedProtocol> {
        self.proto.clone()
    }

    /// Create a new [`ForwardedElement`] with the "version" parameter
    /// set to the given valid/recognised [`ForwardedVersion`].
    pub fn forwarded_version(version: ForwardedVersion) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: None,
            proto: None,
            proto_version: Some(version),
            extensions: None,
        }
    }

    /// Set the "version" parameter to the given valid/recognised [`ForwardedVersion`].
    pub fn set_forwarded_version(&mut self, version: ForwardedVersion) -> &mut Self {
        self.proto_version = Some(version);
        self
    }

    /// Get a copy of the "version" parameter, if it is set.
    pub fn ref_forwarded_version(&self) -> Option<ForwardedVersion> {
        self.proto_version
    }
}

impl fmt::Display for ForwardedAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.port {
            Some(port) => match &self.host {
                Host::Address(IpAddr::V6(ip)) => write!(f, "[{ip}]:{port}"),
                host => write!(f, "{host}:{port}"),
            },
            None => self.host.fmt(f),
        }
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
            let quoted =
                authority.port.is_some() || matches!(authority.host, Host::Address(IpAddr::V6(_)));
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
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_single_forwarded_element(s.as_bytes())
    }
}

impl TryFrom<String> for ForwardedElement {
    type Error = OpaqueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(s.as_bytes())
    }
}

impl TryFrom<&str> for ForwardedElement {
    type Error = OpaqueError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(s.as_bytes())
    }
}

impl TryFrom<HeaderValue> for ForwardedElement {
    type Error = OpaqueError;

    fn try_from(header: HeaderValue) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(header.as_bytes())
    }
}

impl TryFrom<&HeaderValue> for ForwardedElement {
    type Error = OpaqueError;

    fn try_from(header: &HeaderValue) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(header.as_bytes())
    }
}

impl TryFrom<Vec<u8>> for ForwardedElement {
    type Error = OpaqueError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(bytes.as_ref())
    }
}

impl TryFrom<&[u8]> for ForwardedElement {
    type Error = OpaqueError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(bytes)
    }
}

impl std::str::FromStr for ForwardedAuthority {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(host) = Host::try_from(s) {
            // first try host alone, as it is most common,
            // and also prevents IPv6 to be seen by default with port
            return Ok(ForwardedAuthority { host, port: None });
        }

        let (s, port) = try_to_split_num_port_from_str(s);
        let host = Host::try_from(s).context("parse forwarded host")?;

        match host {
            Host::Address(IpAddr::V6(_)) if port.is_some() && !s.starts_with('[') => Err(
                OpaqueError::from_display("missing brackets for host IPv6 address with port"),
            ),
            _ => Ok(ForwardedAuthority { host, port }),
        }
    }
}

fn try_to_split_num_port_from_str(s: &str) -> (&str, Option<u16>) {
    if let Some(colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        match s[colon + 1..].parse() {
            Ok(port) => (&s[..colon], Some(port)),
            Err(_) => (s, None),
        }
    } else {
        (s, None)
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
                ForwardedElement::forwarded_for(NodeId::try_from("_gazonk").unwrap()),
            ),
            (
                r##"For="[2001:db8:cafe::17]:4711""##,
                ForwardedElement::forwarded_for(
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
                        .into(),
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
            assert_eq!(element, expected, "input: {}", s);
        }
    }
}
