//! rama support for the "Forwarded HTTP Extension"
//!
//! RFC: <https://datatracker.ietf.org/doc/html/rfc7239>

use crate::error::OpaqueError;
use crate::http::HeaderValue;

mod obfuscated;
#[doc(inline)]
use obfuscated::{ObfNode, ObfPort};

mod node;
#[doc(inline)]
pub use node::NodeId;

mod element;
#[doc(inline)]
pub use element::ForwardedElement;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Forwarding information stored as a chain.
///
/// This extension (which can be stored and modified via the [`Context`])
/// allows to keep track of the forward information. E.g. what was the original
/// host used by the user, by which proxy it was forwarded, what was the intended
/// protocol (e.g. https), etc...
///
/// [`Context`]: crate::service::Context
pub struct Forwarded {
    first: ForwardedElement,
    others: Vec<ForwardedElement>,
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

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: add tests: invalids, mini fuzz

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
}
