use super::NodeId;
use crate::http::HeaderValue;
use crate::{
    error::{ErrorContext, OpaqueError},
    net::{
        address::{Authority, Host},
        Protocol,
    },
};
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
    proto: Option<Protocol>,

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
struct ForwardedAuthority {
    host: Host,
    port: Option<u16>,
}

impl ForwardedElement {
    /// Return the host if one is defined.
    pub fn authority(&self) -> Option<(Host, Option<u16>)> {
        self.authority
            .as_ref()
            .map(|authority| (authority.host.clone(), authority.port))
    }

    /// Return the protocol if one is defined.
    pub fn proto(&self) -> Option<Protocol> {
        self.proto.clone()
    }

    /// Create a new [`ForwardedElement`] with the "host" parameter set
    /// using the given [`Host`].
    pub fn forwarded_host(host: Host) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: Some(ForwardedAuthority { host, port: None }),
            proto: None,
            extensions: None,
        }
    }

    /// Sets the "host" parameter in this [`ForwardedElement`] using
    /// the given [`Host`].
    pub fn set_forwarded_host(&mut self, host: Host) -> &mut Self {
        self.authority = Some(ForwardedAuthority { host, port: None });
        self
    }

    /// Create a new [`ForwardedElement`] with the "host" parameter set
    /// using the given [`Authority`].
    pub fn forwarded_authority(authority: Authority) -> Self {
        let (host, port) = authority.into_parts();
        Self {
            by_node: None,
            for_node: None,
            authority: Some(ForwardedAuthority {
                host,
                port: Some(port),
            }),
            proto: None,
            extensions: None,
        }
    }

    /// Sets the "host" parameter in this [`ForwardedElement`] using
    /// the given [`Authority`].
    pub fn set_authority(&mut self, authority: Authority) -> &mut Self {
        let (host, port) = authority.into_parts();
        self.authority = Some(ForwardedAuthority {
            host,
            port: Some(port),
        });
        self
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
            extensions: None,
        }
    }

    /// Sets the "for" parameter for this [`ForwardedElement`] using the given valid node identifier.
    /// Examples are an Ip Address or Domain, with or without a port.
    pub fn set_for(&mut self, node_id: impl Into<NodeId>) -> &mut Self {
        self.for_node = Some(node_id.into());
        self
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
            extensions: None,
        }
    }

    /// Sets the "by" parameter for this [`ForwardedElement`] usin the given valid node identifier.
    /// Examples are an Ip Address or Domain, with or without a port.
    pub fn set_by(&mut self, node_id: impl Into<NodeId>) -> &mut Self {
        self.by_node = Some(node_id.into());
        self
    }

    /// Create a new [`ForwardedElement`] with the "proto" parameter
    /// set to the given valid/recognised [`Protocol`]
    pub fn forwarded_proto(protocol: Protocol) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: None,
            proto: Some(protocol),
            extensions: None,
        }
    }

    /// Set the "proto" parameter to the given valid/recognised [`Protocol`].
    pub fn set_proto(&mut self, protocol: Protocol) -> &mut Self {
        self.proto = Some(protocol);
        self
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
                    proto: Some(Protocol::Http),
                    extensions: None,
                },
            ),
            (
                r##"For="[2001:db8:cafe::17]:4711";proto=http;foo=bar"##,
                ForwardedElement {
                    by_node: None,
                    for_node: Some(NodeId::try_from("[2001:db8:cafe::17]:4711").unwrap()),
                    authority: None,
                    proto: Some(Protocol::Http),
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
                    proto: Some(Protocol::Http),
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
