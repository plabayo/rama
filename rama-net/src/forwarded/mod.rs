//! rama support for the "Forwarded HTTP Extension"
//!
//! RFC: <https://datatracker.ietf.org/doc/html/rfc7239>

use rama_core::error::OpaqueError;
use std::fmt;
use std::net::IpAddr;

#[cfg(feature = "http")]
use rama_http_types::HeaderValue;

mod obfuscated;
#[doc(inline)]
use obfuscated::{ObfNode, ObfPort};

mod node;
#[doc(inline)]
pub use node::NodeId;

mod element;
#[doc(inline)]
pub use element::{ForwardedAuthority, ForwardedElement};

mod proto;
#[doc(inline)]
pub use proto::ForwardedProtocol;

mod version;
#[doc(inline)]
pub use version::ForwardedVersion;

use crate::address::SocketAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Forwarding information stored as a chain.
///
/// This extension (which can be stored and modified via the [`Extensions`])
/// allows to keep track of the forward information. E.g. what was the original
/// host used by the user, by which proxy it was forwarded, what was the intended
/// protocol (e.g. https), etc...
///
/// RFC: <https://datatracker.ietf.org/doc/html/rfc7239>
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct Forwarded {
    first: ForwardedElement,
    others: Vec<ForwardedElement>,
}

impl Forwarded {
    /// Create a new [`Forwarded`] extension for the given [`ForwardedElement`]
    /// as the client Element (the first element).
    #[must_use]
    pub const fn new(element: ForwardedElement) -> Self {
        Self {
            first: element,
            others: Vec::new(),
        }
    }

    /// Return the client host of this [`Forwarded`] context,
    /// if there is one defined.
    ///
    /// It is assumed that only the first element can be
    /// described as client information.
    #[must_use]
    pub fn client_host(&self) -> Option<&ForwardedAuthority> {
        self.first.forwarded_host()
    }

    /// Return the client [`SocketAddress`] of this [`Forwarded`] context,
    /// if both an Ip and a port are defined.
    ///
    /// You can try to fallback to [`Self::client_ip`],
    /// in case this method returns `None`.
    #[must_use]
    pub fn client_socket_addr(&self) -> Option<SocketAddress> {
        self.first
            .forwarded_for()
            .and_then(|node| match (node.ip(), node.port()) {
                (Some(ip), Some(port)) => Some((ip, port).into()),
                _ => None,
            })
    }

    /// Return the client port of this [`Forwarded`] context,
    /// if there is one defined.
    #[must_use]
    pub fn client_port(&self) -> Option<u16> {
        self.first.forwarded_for().and_then(|node| node.port())
    }

    /// Return the client Ip of this [`Forwarded`] context,
    /// if there is one defined.
    ///
    /// This method may return None because there is no forwarded "for"
    /// information for the client element or because the IP is obfuscated.
    ///
    /// It is assumed that only the first element can be
    /// described as client information.
    #[must_use]
    pub fn client_ip(&self) -> Option<IpAddr> {
        self.first.forwarded_for().and_then(|node| node.ip())
    }

    /// Return the client protocol of this [`Forwarded`] context,
    /// if there is one defined.
    #[must_use]
    pub fn client_proto(&self) -> Option<ForwardedProtocol> {
        self.first.forwarded_proto()
    }

    /// Return the client protocol version of this [`Forwarded`] context,
    /// if there is one defined.
    #[must_use]
    pub fn client_version(&self) -> Option<ForwardedVersion> {
        self.first.forwarded_version()
    }

    /// Append a [`ForwardedElement`] to this [`Forwarded`] context.
    pub fn append(&mut self, element: ForwardedElement) -> &mut Self {
        self.others.push(element);
        self
    }

    /// Extend this [`Forwarded`] context with the given [`ForwardedElement`]s.
    pub fn extend(&mut self, elements: impl IntoIterator<Item = ForwardedElement>) -> &mut Self {
        self.others.extend(elements);
        self
    }

    /// Iterate over the [`ForwardedElement`]s in this [`Forwarded`] context.
    pub fn iter(&self) -> impl Iterator<Item = &ForwardedElement> {
        std::iter::once(&self.first).chain(self.others.iter())
    }
}

impl IntoIterator for Forwarded {
    type Item = ForwardedElement;
    type IntoIter =
        std::iter::Chain<std::iter::Once<ForwardedElement>, std::vec::IntoIter<ForwardedElement>>;

    fn into_iter(self) -> Self::IntoIter {
        let iter = self.others.into_iter();
        std::iter::once(self.first).chain(iter)
    }
}

impl From<ForwardedElement> for Forwarded {
    #[inline]
    fn from(value: ForwardedElement) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for Forwarded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.first.fmt(f)?;
        for other in &self.others {
            write!(f, ",{other}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Forwarded {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (first, others) = element::parse_one_plus_forwarded_elements(s.as_bytes())?;
        Ok(Self { first, others })
    }
}

impl TryFrom<String> for Forwarded {
    type Error = OpaqueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(s.as_bytes())?;
        Ok(Self { first, others })
    }
}

impl TryFrom<&str> for Forwarded {
    type Error = OpaqueError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(s.as_bytes())?;
        Ok(Self { first, others })
    }
}

#[cfg(feature = "http")]
impl TryFrom<HeaderValue> for Forwarded {
    type Error = OpaqueError;

    fn try_from(header: HeaderValue) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(header.as_bytes())?;
        Ok(Self { first, others })
    }
}

#[cfg(feature = "http")]
impl TryFrom<&HeaderValue> for Forwarded {
    type Error = OpaqueError;

    fn try_from(header: &HeaderValue) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(header.as_bytes())?;
        Ok(Self { first, others })
    }
}

impl TryFrom<Vec<u8>> for Forwarded {
    type Error = OpaqueError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(bytes.as_ref())?;
        Ok(Self { first, others })
    }
}

impl TryFrom<&[u8]> for Forwarded {
    type Error = OpaqueError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(bytes)?;
        Ok(Self { first, others })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::HostWithOptPort;

    #[test]
    fn test_forwarded_parse_invalid() {
        for s in [
            "",
            "foobar",
            "127.0.0.1",
            "⌨️",
            "for=_foo;for=_bar",
            ",",
            "for=127.0.0.1,",
            "for=127.0.0.1,foobar",
            "for=127.0.0.1,127.0.0.1",
            "for=127.0.0.1,⌨️",
            "for=127.0.0.1,for=_foo;for=_bar",
            "foobar,for=127.0.0.1",
            "127.0.0.1,for=127.0.0.1",
            "⌨️,for=127.0.0.1",
            "for=_foo;for=_bar,for=127.0.0.1",
        ] {
            if let Ok(el) = Forwarded::try_from(s) {
                panic!("unexpected parse success: input {s}: {el:?}");
            }
        }
    }

    #[test]
    fn test_forwarded_parse_happy_spec() {
        for (s, expected) in [
            (
                r##"for="_gazonk""##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("_gazonk").unwrap(),
                    ),
                    others: Vec::new(),
                },
            ),
            (
                r##"for=192.0.2.43, for=198.51.100.17"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![ForwardedElement::new_forwarded_for(
                        NodeId::try_from("198.51.100.17").unwrap(),
                    )],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![ForwardedElement::new_forwarded_for(
                        NodeId::try_from("198.51.100.17").unwrap(),
                    )],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17,for=127.0.0.1"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::new_forwarded_for(
                            NodeId::try_from("198.51.100.17").unwrap(),
                        ),
                        ForwardedElement::new_forwarded_for(NodeId::try_from("127.0.0.1").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17,for=unknown"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::new_forwarded_for(
                            NodeId::try_from("198.51.100.17").unwrap(),
                        ),
                        ForwardedElement::new_forwarded_for(NodeId::try_from("unknown").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43,for="[2001:db8:cafe::17]",for=unknown"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::new_forwarded_for(
                            NodeId::try_from("[2001:db8:cafe::17]").unwrap(),
                        ),
                        ForwardedElement::new_forwarded_for(NodeId::try_from("unknown").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43, for="[2001:db8:cafe::17]", for=unknown"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::new_forwarded_for(
                            NodeId::try_from("[2001:db8:cafe::17]").unwrap(),
                        ),
                        ForwardedElement::new_forwarded_for(NodeId::try_from("unknown").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43, for="[2001:db8:cafe::17]:4000", for=unknown"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::new_forwarded_for(
                            NodeId::try_from("[2001:db8:cafe::17]:4000").unwrap(),
                        ),
                        ForwardedElement::new_forwarded_for(NodeId::try_from("unknown").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::try_from(
                            "for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com",
                        )
                        .unwrap(),
                    ],
                },
            ),
            (
                r##"for="192.0.2.43:4000",for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"##,
                Forwarded {
                    first: ForwardedElement::new_forwarded_for(
                        NodeId::try_from("192.0.2.43:4000").unwrap(),
                    ),
                    others: vec![
                        ForwardedElement::try_from(
                            "for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com",
                        )
                        .unwrap(),
                    ],
                },
            ),
        ] {
            let element = match Forwarded::try_from(s) {
                Ok(el) => el,
                Err(err) => panic!("failed to parse happy spec el '{s}': {err}"),
            };
            assert_eq!(element, expected, "input: {s}");
        }
    }

    #[test]
    fn test_forwarded_client_authority() {
        for (s, expected) in [
            (
                r##"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"##,
                None,
            ),
            (
                r##"host=example.com,for=195.2.34.12"##,
                Some(HostWithOptPort::example_domain()),
            ),
            (
                r##"host="example.com:443",for=195.2.34.12"##,
                Some(HostWithOptPort::example_domain_https()),
            ),
        ] {
            let forwarded = Forwarded::try_from(s).unwrap();
            assert_eq!(
                forwarded
                    .iter()
                    .next()
                    .and_then(|el| el.forwarded_host())
                    .map(|authority| authority.0.clone()),
                expected
            );
        }
    }

    #[test]
    fn test_forwarded_client_protoy() {
        for (s, expected) in [
            (
                r##"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"##,
                None,
            ),
            (
                r##"proto=http,for=195.2.34.12"##,
                Some(ForwardedProtocol::HTTP),
            ),
        ] {
            let forwarded = Forwarded::try_from(s).unwrap();
            assert_eq!(
                forwarded.iter().next().and_then(|el| el.forwarded_proto()),
                expected
            );
        }
    }
}
