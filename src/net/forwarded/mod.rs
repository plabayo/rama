//! rama support for the "Forwarded HTTP Extension"
//!
//! RFC: <https://datatracker.ietf.org/doc/html/rfc7239>

use super::{address::Host, Protocol};
use crate::error::OpaqueError;
use crate::http::headers::Header;
use crate::http::HeaderValue;
use std::fmt;

mod obfuscated;
#[doc(inline)]
use obfuscated::{ObfNode, ObfPort};

mod node;
#[doc(inline)]
pub use node::NodeId;

mod element;
#[doc(inline)]
pub use element::{ForwardedAuthority, ForwardedElement};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Forwarding information stored as a chain.
///
/// This extension (which can be stored and modified via the [`Context`])
/// allows to keep track of the forward information. E.g. what was the original
/// host used by the user, by which proxy it was forwarded, what was the intended
/// protocol (e.g. https), etc...
///
/// RFC: <https://datatracker.ietf.org/doc/html/rfc7239>
///
/// [`Context`]: crate::service::Context
pub struct Forwarded {
    first: ForwardedElement,
    others: Vec<ForwardedElement>,
}

impl Forwarded {
    /// Create a new [`Forwarded`] extension for the given [`ForwardedElement`]
    /// as the client Element (the first element).
    pub fn new(element: ForwardedElement) -> Self {
        Self {
            first: element,
            others: Vec::new(),
        }
    }

    /// Return the client (host) if one is defined.
    pub fn client_authority(&self) -> Option<(Host, Option<u16>)> {
        self.first.authority()
    }

    /// Return the client protocol if one is defined.
    pub fn client_proto(&self) -> Option<Protocol> {
        self.first.proto()
    }

    /// Merge the other [`Forwarded`] extension with this one.
    pub fn merge(&mut self, other: Forwarded) -> &mut Self {
        self.others.push(other.first);
        self.others.extend(other.others);
        self
    }

    /// Append a [`ForwardedElement`] to this [`Forwarded`] context.
    pub fn append(&mut self, element: ForwardedElement) -> &mut Self {
        self.others.push(element);
        self
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
        Ok(Forwarded { first, others })
    }
}

impl TryFrom<String> for Forwarded {
    type Error = OpaqueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(s.as_bytes())?;
        Ok(Forwarded { first, others })
    }
}

impl TryFrom<&str> for Forwarded {
    type Error = OpaqueError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(s.as_bytes())?;
        Ok(Forwarded { first, others })
    }
}

impl TryFrom<HeaderValue> for Forwarded {
    type Error = OpaqueError;

    fn try_from(header: HeaderValue) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(header.as_bytes())?;
        Ok(Forwarded { first, others })
    }
}

impl TryFrom<&HeaderValue> for Forwarded {
    type Error = OpaqueError;

    fn try_from(header: &HeaderValue) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(header.as_bytes())?;
        Ok(Forwarded { first, others })
    }
}

impl TryFrom<Vec<u8>> for Forwarded {
    type Error = OpaqueError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(bytes.as_ref())?;
        Ok(Forwarded { first, others })
    }
}

impl TryFrom<&[u8]> for Forwarded {
    type Error = OpaqueError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let (first, others) = element::parse_one_plus_forwarded_elements(bytes)?;
        Ok(Forwarded { first, others })
    }
}

// TODO: support Header <-> Forwarded
// TODO: test header code
// TODO: test Display code for Forwarded & ForwardedElement
// TODO: modify Forwarded Code: IS NOT NOT NOT Response!!! it is is request, both, just one is Get, other is Set!
// TODO: test SetForwardedLayerCode
// TODO: test SetForwardedLayerCode with other layers interacted
// TODO: develop GetForwardedLayerCode (new)
// TODO: develop GetForwardedLayerCode (legacy)
// TODO: test SetForwardedLayerCode (new)
// TODO: test SetForwardedLayerCode (legacy)
// TODO: test SetForwardedLayerCode with other layers interacted
// TODO: test SetForwardedLayerCode (legacy) with other layers interacted

impl Header for Forwarded {
    fn name() -> &'static http::HeaderName {
        &crate::http::header::FORWARDED
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let first_header = values
            .next()
            .ok_or_else(crate::http::headers::Error::invalid)?;

        let mut forwarded: Forwarded = match first_header.as_bytes().try_into() {
            Ok(f) => f,
            Err(err) => {
                tracing::trace!(err = %err, "failed to turn header into Forwarded extension");
                return Err(crate::http::headers::Error::invalid());
            }
        };

        for header in values {
            let other: Forwarded = match header.as_bytes().try_into() {
                Ok(f) => f,
                Err(err) => {
                    tracing::trace!(err = %err, "failed to turn header into Forwarded extension");
                    return Err(crate::http::headers::Error::invalid());
                }
            };
            forwarded.merge(other);
        }

        Ok(forwarded)
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let s = self.to_string();

        let value = HeaderValue::from_str(&s)
            .expect("Forwarded extension should always result in a valid header value");

        values.extend(std::iter::once(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    first: ForwardedElement::forwarded_for(NodeId::try_from("_gazonk").unwrap()),
                    others: Vec::new(),
                },
            ),
            (
                r##"for=192.0.2.43, for=198.51.100.17"##,
                Forwarded {
                    first: ForwardedElement::forwarded_for(NodeId::try_from("192.0.2.43").unwrap()),
                    others: vec![ForwardedElement::forwarded_for(
                        NodeId::try_from("198.51.100.17").unwrap(),
                    )],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17"##,
                Forwarded {
                    first: ForwardedElement::forwarded_for(NodeId::try_from("192.0.2.43").unwrap()),
                    others: vec![ForwardedElement::forwarded_for(
                        NodeId::try_from("198.51.100.17").unwrap(),
                    )],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17,for=127.0.0.1"##,
                Forwarded {
                    first: ForwardedElement::forwarded_for(NodeId::try_from("192.0.2.43").unwrap()),
                    others: vec![
                        ForwardedElement::forwarded_for(NodeId::try_from("198.51.100.17").unwrap()),
                        ForwardedElement::forwarded_for(NodeId::try_from("127.0.0.1").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17,for=unknown"##,
                Forwarded {
                    first: ForwardedElement::forwarded_for(NodeId::try_from("192.0.2.43").unwrap()),
                    others: vec![
                        ForwardedElement::forwarded_for(NodeId::try_from("198.51.100.17").unwrap()),
                        ForwardedElement::forwarded_for(NodeId::try_from("unknown").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43,for="[2001:db8:cafe::17]",for=unknown"##,
                Forwarded {
                    first: ForwardedElement::forwarded_for(NodeId::try_from("192.0.2.43").unwrap()),
                    others: vec![
                        ForwardedElement::forwarded_for(
                            NodeId::try_from("[2001:db8:cafe::17]").unwrap(),
                        ),
                        ForwardedElement::forwarded_for(NodeId::try_from("unknown").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43, for="[2001:db8:cafe::17]", for=unknown"##,
                Forwarded {
                    first: ForwardedElement::forwarded_for(NodeId::try_from("192.0.2.43").unwrap()),
                    others: vec![
                        ForwardedElement::forwarded_for(
                            NodeId::try_from("[2001:db8:cafe::17]").unwrap(),
                        ),
                        ForwardedElement::forwarded_for(NodeId::try_from("unknown").unwrap()),
                    ],
                },
            ),
            (
                r##"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"##,
                Forwarded {
                    first: ForwardedElement::forwarded_for(NodeId::try_from("192.0.2.43").unwrap()),
                    others: vec![ForwardedElement::try_from(
                        "for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com",
                    )
                    .unwrap()],
                },
            ),
        ] {
            let element = match Forwarded::try_from(s) {
                Ok(el) => el,
                Err(err) => panic!("failed to parse happy spec el '{s}': {err}"),
            };
            assert_eq!(element, expected, "input: {}", s);
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
                Some((Host::try_from("example.com").unwrap(), None)),
            ),
            (
                r##"host="example.com:443",for=195.2.34.12"##,
                Some((Host::try_from("example.com").unwrap(), Some(443))),
            ),
        ] {
            let forwarded = Forwarded::try_from(s).unwrap();
            assert_eq!(forwarded.client_authority(), expected);
        }
    }

    #[test]
    fn test_forwarded_client_protoy() {
        for (s, expected) in [
            (
                r##"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"##,
                None,
            ),
            (r##"proto=http,for=195.2.34.12"##, Some(Protocol::Http)),
        ] {
            let forwarded = Forwarded::try_from(s).unwrap();
            assert_eq!(forwarded.client_proto(), expected);
        }
    }
}
