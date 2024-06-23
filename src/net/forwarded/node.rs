use std::{
    fmt,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use crate::{
    error::{ErrorContext, OpaqueError},
    net::address::{Authority, Domain, Host},
};

use super::{ObfNode, ObfPort};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Node Identifier
///
/// The node identifier is one of the following:
///
/// - The client's IP address, with an optional port number
/// - A token indicating that the IP address of the client is not known
///   to the proxy server (unknown)
/// - A generated token, allowing for tracing and debugging, while
///   allowing the internal structure or sensitive information to be
///   hidden
///
/// As specified in proposal section:
/// <https://datatracker.ietf.org/doc/html/rfc7239#section-6>
pub struct NodeId {
    name: NodeName,
    port: Option<NodePort>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum NodeName {
    Unknown,
    Ip(IpAddr),
    Obf(ObfNode),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum NodePort {
    Num(u16),
    Obf(ObfPort),
}

impl NodeId {
    /// Try to convert a vector of bytes to a [`NodeId`].
    pub fn try_from_bytes(vec: Vec<u8>) -> Result<Self, OpaqueError> {
        vec.try_into()
    }

    /// Try to convert a string slice to a [`NodeId`].
    pub fn try_from_str(s: &str) -> Result<Self, OpaqueError> {
        s.to_owned().try_into()
    }

    #[inline]
    /// Converts a vector of bytes to a [`NodeId`], converting invalid characters to underscore.
    pub fn from_bytes_lossy(vec: &[u8]) -> Self {
        let s = String::from_utf8_lossy(vec);
        Self::from_str_lossy(&s)
    }

    /// Converts a string slice to a [`NodeId`], converting invalid characters to underscore.
    pub fn from_str_lossy(s: &str) -> Self {
        let s_original = s;

        if s.eq_ignore_ascii_case(UNKNOWN_STR) {
            return NodeId {
                name: NodeName::Unknown,
                port: None,
            };
        }

        if let Ok(ip) = try_to_parse_str_to_ip(s) {
            // early return to prevent stuff like `::1` to
            // be interpreted as node { name = obf(:), port = num(1) }
            return NodeId {
                name: NodeName::Ip(ip),
                port: None,
            };
        }

        let (s, port) = try_to_split_node_port_lossy_from_str(s);
        let name = try_to_parse_str_to_ip(s)
            .map(NodeName::Ip)
            .unwrap_or_else(|_| NodeName::Obf(ObfNode::from_str_lossy(s)));

        match name {
            NodeName::Ip(IpAddr::V6(_)) if port.is_some() && !s.starts_with('[') => NodeId {
                name: NodeName::Obf(ObfNode::from_str_lossy(s_original)),
                port: None,
            },
            _ => NodeId { name, port },
        }
    }

    /// Return the [`IpAddr`] if one was defined for this [`NodeId`].
    pub fn ip(&self) -> Option<IpAddr> {
        match &self.name {
            NodeName::Ip(addr) => Some(*addr),
            NodeName::Unknown | NodeName::Obf(_) => None,
        }
    }

    /// Return true if this [`NodeId`] has a any kind of port defined,
    /// even if obfuscated.
    pub fn has_any_port(&self) -> bool {
        self.port.is_some()
    }

    /// Return the numeric port if one was defined for this [`NodeId`].
    pub fn port(&self) -> Option<u16> {
        if let Some(NodePort::Num(n)) = self.port {
            Some(n)
        } else {
            None
        }
    }

    /// Return the [`Authority`] if this [`NodeId`] has either
    /// an [`IpAddr`] or [`Domain`] defined, as well as a numeric port.
    pub fn authority(&self) -> Option<Authority> {
        match (&self.name, self.port()) {
            (NodeName::Ip(ip), Some(port)) => Some((*ip, port).into()),
            // every domain is a valid node name, but not every valid node name is a valid domain!!
            (NodeName::Obf(s), Some(port)) => s
                .as_str()
                .parse::<Domain>()
                .ok()
                .map(|domain| (domain, port).into()),
            _ => None,
        }
    }
}

impl NodePort {
    /// Converts a string slice to a [`NodePort`], converting invalid characters to underscore.
    fn from_str_lossy(s: &str) -> Self {
        s.parse::<u16>()
            .map(NodePort::Num)
            .unwrap_or_else(|_| NodePort::Obf(ObfPort::from_str_lossy(s)))
    }
}

impl From<IpAddr> for NodeId {
    #[inline]
    fn from(ip: IpAddr) -> Self {
        (ip, None).into()
    }
}

impl From<(IpAddr, u16)> for NodeId {
    #[inline]
    fn from((ip, port): (IpAddr, u16)) -> Self {
        (ip, Some(port)).into()
    }
}

impl From<(IpAddr, Option<u16>)> for NodeId {
    fn from((ip, port): (IpAddr, Option<u16>)) -> Self {
        NodeId {
            name: NodeName::Ip(ip),
            port: port.map(NodePort::Num),
        }
    }
}

impl From<Domain> for NodeId {
    #[inline]
    fn from(domain: Domain) -> Self {
        (domain, None).into()
    }
}

impl From<(Domain, u16)> for NodeId {
    #[inline]
    fn from((domain, port): (Domain, u16)) -> Self {
        (domain, Some(port)).into()
    }
}

impl From<(Domain, Option<u16>)> for NodeId {
    fn from((domain, port): (Domain, Option<u16>)) -> Self {
        NodeId {
            // NOTE: this assumes all domains are valid obf nodes,
            // which should be ok given the validation rules for domains are more strict!
            name: NodeName::Obf(ObfNode::from_inner(domain.into_inner())),
            port: port.map(NodePort::Num),
        }
    }
}

impl From<Authority> for NodeId {
    fn from(authority: Authority) -> Self {
        let (host, port) = authority.into_parts();
        match host {
            Host::Name(domain) => (domain, port).into(),
            Host::Address(ip) => (ip, port).into(),
        }
    }
}

impl From<SocketAddr> for NodeId {
    fn from(addr: SocketAddr) -> Self {
        NodeId {
            name: NodeName::Ip(addr.ip()),
            port: Some(NodePort::Num(addr.port())),
        }
    }
}

impl From<&SocketAddr> for NodeId {
    fn from(addr: &SocketAddr) -> Self {
        NodeId {
            name: NodeName::Ip(addr.ip()),
            port: Some(NodePort::Num(addr.port())),
        }
    }
}

const UNKNOWN_STR: &str = "unknown";

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.name {
            NodeName::Unknown => UNKNOWN_STR.fmt(f),
            NodeName::Ip(ip) => match &self.port {
                None => ip.fmt(f),
                Some(port) => match ip {
                    std::net::IpAddr::V4(ip) => write!(f, "{ip}:{port}"),
                    std::net::IpAddr::V6(ip) => write!(f, "[{ip}]:{port}"),
                },
            },
            NodeName::Obf(s) => match &self.port {
                None => s.fmt(f),
                Some(port) => write!(f, "{s}:{port}"),
            },
        }
    }
}

impl fmt::Display for NodePort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodePort::Num(num) => num.fmt(f),
            NodePort::Obf(s) => s.fmt(f),
        }
    }
}

impl std::str::FromStr for NodeId {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NodeId::try_from(s)
    }
}

impl TryFrom<String> for NodeId {
    type Error = OpaqueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}

impl TryFrom<&str> for NodeId {
    type Error = OpaqueError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.eq_ignore_ascii_case(UNKNOWN_STR) {
            return Ok(NodeId {
                name: NodeName::Unknown,
                port: None,
            });
        }

        if let Ok(ip) = try_to_parse_str_to_ip(s) {
            // early return to prevent stuff like `::1` to
            // be interpreted as node { name = obf(:), port = num(1) }
            return Ok(NodeId {
                name: NodeName::Ip(ip),
                port: None,
            });
        }

        let (s, port) = try_to_split_node_port_from_str(s);
        let name = try_to_parse_str_to_ip(s)
            .map(NodeName::Ip)
            .or_else(|_| s.parse::<ObfNode>().map(NodeName::Obf))
            .context("parse str as Node")?;

        match name {
            NodeName::Ip(IpAddr::V6(_)) if port.is_some() && !s.starts_with('[') => Err(
                OpaqueError::from_display("missing brackets for node IPv6 address with port"),
            ),
            _ => Ok(NodeId { name, port }),
        }
    }
}

fn try_to_parse_str_to_ip(value: &str) -> Result<IpAddr, OpaqueError> {
    if value.starts_with('[') || value.ends_with(']') {
        let value = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .context("strip brackets from ipv6 str")?;
        Ok(IpAddr::V6(
            value.parse::<Ipv6Addr>().context("parse str as ipv6")?,
        ))
    } else {
        value.parse::<IpAddr>().context("parse ipv4/6 str")
    }
}

impl TryFrom<Vec<u8>> for NodeId {
    type Error = OpaqueError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let s = String::from_utf8(bytes).context("parse node from bytes")?;
        s.try_into()
    }
}

impl TryFrom<&[u8]> for NodeId {
    type Error = OpaqueError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes).context("parse node from bytes")?;
        s.try_into()
    }
}

fn try_to_split_node_port_from_str(s: &str) -> (&str, Option<NodePort>) {
    if let Some(colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        match s[colon + 1..].parse() {
            Ok(port) => (&s[..colon], Some(port)),
            Err(_) => (s, None),
        }
    } else {
        (s, None)
    }
}

fn try_to_split_node_port_lossy_from_str(s: &str) -> (&str, Option<NodePort>) {
    if let Some(colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        let port = NodePort::from_str_lossy(&s[colon + 1..]);
        let s = &s[..colon];
        (s, Some(port))
    } else {
        (s, None)
    }
}

impl std::str::FromStr for NodePort {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u16>()
            .map(NodePort::Num)
            .or_else(|_| s.parse::<ObfPort>().map(NodePort::Obf))
            .context("parse str as NodePort")
    }
}

impl serde::Serialize for NodeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let address = self.to_string();
        address.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for NodeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_node_id_valid() {
        for (s, expected) in [
            (
                "unknown",
                NodeId {
                    name: NodeName::Unknown,
                    port: None,
                },
            ),
            (
                "::1",
                NodeId {
                    name: NodeName::Ip("::1".parse().unwrap()),
                    port: None,
                },
            ),
            (
                "127.0.0.1",
                NodeId {
                    name: NodeName::Ip("127.0.0.1".parse().unwrap()),
                    port: None,
                },
            ),
            (
                "192.0.2.43:47011",
                NodeId {
                    name: NodeName::Ip("192.0.2.43".parse().unwrap()),
                    port: Some(NodePort::Num(47011)),
                },
            ),
            (
                "[2001:db8:cafe::17]:47011",
                NodeId {
                    name: NodeName::Ip("2001:db8:cafe::17".parse().unwrap()),
                    port: Some(NodePort::Num(47011)),
                },
            ),
            (
                "192.0.2.43:_foo",
                NodeId {
                    name: NodeName::Ip("192.0.2.43".parse().unwrap()),
                    port: Some(NodePort::Obf(ObfPort::from_static("_foo"))),
                },
            ),
            (
                "[2001:db8:cafe::17]:_bar",
                NodeId {
                    name: NodeName::Ip("2001:db8:cafe::17".parse().unwrap()),
                    port: Some(NodePort::Obf(ObfPort::from_static("_bar"))),
                },
            ),
            (
                "foo",
                NodeId {
                    name: NodeName::Obf(ObfNode::from_static("foo")),
                    port: None,
                },
            ),
            (
                "_foo",
                NodeId {
                    name: NodeName::Obf(ObfNode::from_static("_foo")),
                    port: None,
                },
            ),
            (
                "foo:_bar",
                NodeId {
                    name: NodeName::Obf(ObfNode::from_static("foo")),
                    port: Some(NodePort::Obf(ObfPort::from_static("_bar"))),
                },
            ),
            (
                "foo:42",
                NodeId {
                    name: NodeName::Obf(ObfNode::from_static("foo")),
                    port: Some(NodePort::Num(42)),
                },
            ),
        ] {
            match s.parse::<NodeId>() {
                Err(err) => panic!("failed to parse '{s}': {err}"),
                Ok(node_id) => assert_eq!(node_id, expected, "parse: {}", s),
            }
        }
    }

    #[test]
    fn test_parse_node_id_invalid() {
        for s in [
            "",
            "@",
            "2001:db8:3333:4444:5555:6666:7777:8888:80",
            "foo:bar",
            "foo:_b+r",
            "😀",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",

        ] {
            let node_result = s.parse::<NodeId>();
            assert!(node_result.is_err(), "parse invalid: {}; parsed: {:?}", s, node_result);
        }
    }

    #[test]
    fn test_parse_node_id_lossy() {
        for (s, expected) in [
            ("", NodeId {
                name: NodeName::Obf(ObfNode::from_static("_")),
                port: None,
            }),
            ("@", NodeId {
                name: NodeName::Obf(ObfNode::from_static("_")),
                port: None,
            }),
            ("2001:db8:3333:4444:5555:6666:7777:8888:80", NodeId {
                name: NodeName::Obf(ObfNode::from_static("2001_db8_3333_4444_5555_6666_7777_8888_80")),
                port: None,
            }),
            ("foo:bar", NodeId {
                name: NodeName::Obf(ObfNode::from_static("foo")),
                port: Some(NodePort::Obf(ObfPort::from_static("_bar"))),
            }),
            ("foo:_b+r", NodeId {
                name: NodeName::Obf(ObfNode::from_static("foo")),
                port: Some(NodePort::Obf(ObfPort::from_static("_b_r"))),
            }),
            ("😀", NodeId {
                name: NodeName::Obf(ObfNode::from_static("____")),
                port: None,
            }),
            ("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", NodeId {
                name: NodeName::Obf(ObfNode::from_static("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv")),
                port: None,
            }),
        ] {
            let node_id = NodeId::from_str_lossy(s);
            assert_eq!(node_id, expected, "parse str: {}", s);

            let node_id = NodeId::from_bytes_lossy(s.as_bytes());
            assert_eq!(node_id, expected, "parse bytes: {}", s);
        }
    }
}
