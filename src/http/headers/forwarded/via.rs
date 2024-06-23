use crate::error::{ErrorContext, OpaqueError};
use crate::http::headers::{self, Header};
use crate::http::{HeaderName, HeaderValue};
use crate::net::forwarded::{ForwardedElement, ForwardedProtocol, ForwardedVersion, NodeId};

/// The Via general header is added by proxies, both forward and reverse.
///
/// This header can appear in the request or response headers.
/// It is used for tracking message forwards, avoiding request loops,
/// and identifying the protocol capabilities of senders along the request/response chain.
///
/// It is recommended to use the [`Forwarded`](super::Forwarded) header instead if you can.
///
/// More info can be found at <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via>.
///
/// # Syntax
///
/// ```text
/// Via: [ <protocol-name> "/" ] <protocol-version> <host> [ ":" <port> ]
/// Via: [ <protocol-name> "/" ] <protocol-version> <pseudonym>
/// ```
///
/// # Example values
///
/// * `1.1 vegur`
/// * `HTTP/1.1 GWA`
/// * `1.0 fred, 1.1 p.example.net`
/// * `HTTP/1.1 proxy.example.re, 1.1 edge_1`
/// * `1.1 2e9b3ee4d534903f433e1ed8ea30e57a.cloudfront.net (CloudFront)`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via(Vec<ViaElement>);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ViaElement {
    protocol: Option<ForwardedProtocol>,
    version: ForwardedVersion,
    node_id: NodeId,
}

impl From<ViaElement> for ForwardedElement {
    fn from(via: ViaElement) -> Self {
        let mut el = ForwardedElement::forwarded_by(via.node_id);
        el.set_forwarded_version(via.version);
        if let Some(protocol) = via.protocol {
            el.set_forwarded_proto(protocol);
        }
        el
    }
}

impl Header for Via {
    fn name() -> &'static HeaderName {
        &crate::http::header::VIA
    }

    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(
        values: &mut I,
    ) -> Result<Self, headers::Error> {
        crate::http::headers::util::csv::from_comma_delimited(values).map(Via)
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        use std::fmt;
        struct Format<F>(F);
        impl<F> fmt::Display for Format<F>
        where
            F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result,
        {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                (self.0)(f)
            }
        }
        let s = format!(
            "{}",
            Format(|f: &mut fmt::Formatter<'_>| {
                crate::http::headers::util::csv::fmt_comma_delimited(&mut *f, self.0.iter())
            })
        );
        values.extend(Some(HeaderValue::from_str(&s).unwrap()))
    }
}

impl FromIterator<ViaElement> for Via {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ViaElement>,
    {
        Via(iter.into_iter().collect())
    }
}

impl super::ForwardHeader for Via {
    fn try_from_forwarded<'a, I>(input: I) -> Option<Self>
    where
        I: IntoIterator<Item = &'a ForwardedElement>,
    {
        let vec: Vec<_> = input
            .into_iter()
            .filter_map(|el| {
                let node_id = el.ref_forwarded_by()?.clone();
                let version = el.ref_forwarded_version()?;
                let protocol = el.ref_forwarded_proto();
                Some(ViaElement {
                    protocol,
                    version,
                    node_id,
                })
            })
            .collect();
        if vec.is_empty() {
            None
        } else {
            Some(Via(vec))
        }
    }
}

impl IntoIterator for Via {
    type Item = ForwardedElement;
    type IntoIter = ViaIterator;

    fn into_iter(self) -> Self::IntoIter {
        ViaIterator(self.0.into_iter())
    }
}

#[derive(Debug, Clone)]
/// An iterator over the `Via` header's elements.
pub struct ViaIterator(std::vec::IntoIter<ViaElement>);

impl Iterator for ViaIterator {
    type Item = ForwardedElement;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Into::into)
    }
}

impl std::str::FromStr for ViaElement {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = s.as_bytes();

        bytes = trim_left(bytes);

        let (protocol, version) = match bytes.iter().position(|b| *b == b'/' || *b == b' ') {
            Some(index) => match bytes[index] {
                b'/' => {
                    let protocol: ForwardedProtocol = std::str::from_utf8(&bytes[..index])
                        .context("parse via protocol as utf-8")?
                        .try_into()
                        .context("parse via utf-8 protocol as protocol")?;
                    bytes = &bytes[index + 1..];
                    let index = bytes.iter().position(|b| *b == b' ').ok_or_else(|| {
                        OpaqueError::from_display("via str: missing space after protocol separator")
                    })?;
                    let version =
                        ForwardedVersion::try_from(&bytes[..index]).context("parse via version")?;
                    bytes = &bytes[index + 1..];
                    (Some(protocol), version)
                }
                b' ' => {
                    let version =
                        ForwardedVersion::try_from(&bytes[..index]).context("parse via version")?;
                    bytes = &bytes[index + 1..];
                    (None, version)
                }
                _ => unreachable!(),
            },
            None => {
                return Err(OpaqueError::from_display("via str: missing version"));
            }
        };

        bytes = trim_right(trim_left(bytes));
        let node_id = NodeId::from_bytes_lossy(bytes);

        Ok(Self {
            protocol,
            version,
            node_id,
        })
    }
}

impl std::fmt::Display for ViaElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref proto) = self.protocol {
            write!(f, "{proto}/")?;
        }
        write!(f, "{} {}", self.version, self.node_id)
    }
}

fn trim_left(b: &[u8]) -> &[u8] {
    let mut offset = 0;
    while offset < b.len() && b[offset] == b' ' {
        offset += 1;
    }
    &b[offset..]
}

fn trim_right(b: &[u8]) -> &[u8] {
    if b.is_empty() {
        return b;
    }

    let mut offset = b.len();
    while offset > 0 && b[offset - 1] == b' ' {
        offset -= 1;
    }
    &b[..offset]
}

#[cfg(test)]
mod tests {
    use super::*;

    use http::HeaderValue;

    macro_rules! test_header {
        ($name: ident, $input: expr, $expected: expr) => {
            #[test]
            fn $name() {
                assert_eq!(
                    Via::decode(
                        &mut $input
                            .into_iter()
                            .map(|s| HeaderValue::from_bytes(s.as_bytes()).unwrap())
                            .collect::<Vec<_>>()
                            .iter()
                    )
                    .ok(),
                    $expected,
                );
            }
        };
    }

    // Tests from the Docs
    test_header!(
        test1,
        vec!["1.1 vegur"],
        Some(Via(vec![ViaElement {
            protocol: None,
            version: ForwardedVersion::HTTP_11,
            node_id: NodeId::try_from_str("vegur").unwrap(),
        }]))
    );
    test_header!(
        test2,
        vec!["1.1     vegur    "],
        Some(Via(vec![ViaElement {
            protocol: None,
            version: ForwardedVersion::HTTP_11,
            node_id: NodeId::try_from_str("vegur").unwrap(),
        }]))
    );
    test_header!(
        test3,
        vec!["1.0 fred, 1.1 p.example.net"],
        Some(Via(vec![
            ViaElement {
                protocol: None,
                version: ForwardedVersion::HTTP_10,
                node_id: NodeId::try_from_str("fred").unwrap(),
            },
            ViaElement {
                protocol: None,
                version: ForwardedVersion::HTTP_11,
                node_id: NodeId::try_from_str("p.example.net").unwrap(),
            }
        ]))
    );
    test_header!(
        test4,
        vec!["1.0 fred    ,    1.1 p.example.net   "],
        Some(Via(vec![
            ViaElement {
                protocol: None,
                version: ForwardedVersion::HTTP_10,
                node_id: NodeId::try_from_str("fred").unwrap(),
            },
            ViaElement {
                protocol: None,
                version: ForwardedVersion::HTTP_11,
                node_id: NodeId::try_from_str("p.example.net").unwrap(),
            }
        ]))
    );
    test_header!(
        test5,
        vec!["1.0 fred", "1.1 p.example.net"],
        Some(Via(vec![
            ViaElement {
                protocol: None,
                version: ForwardedVersion::HTTP_10,
                node_id: NodeId::try_from_str("fred").unwrap(),
            },
            ViaElement {
                protocol: None,
                version: ForwardedVersion::HTTP_11,
                node_id: NodeId::try_from_str("p.example.net").unwrap(),
            }
        ]))
    );
    test_header!(
        test6,
        vec!["HTTP/1.1 proxy.example.re, 1.1 edge_1"],
        Some(Via(vec![
            ViaElement {
                protocol: Some(ForwardedProtocol::HTTP),
                version: ForwardedVersion::HTTP_11,
                node_id: NodeId::try_from_str("proxy.example.re").unwrap(),
            },
            ViaElement {
                protocol: None,
                version: ForwardedVersion::HTTP_11,
                node_id: NodeId::try_from_str("edge_1").unwrap(),
            }
        ]))
    );
    test_header!(
        test7,
        vec!["1.1 2e9b3ee4d534903f433e1ed8ea30e57a.cloudfront.net (CloudFront)"],
        Some(Via(vec![ViaElement {
            protocol: None,
            version: ForwardedVersion::HTTP_11,
            node_id: NodeId::try_from_str(
                "2e9b3ee4d534903f433e1ed8ea30e57a.cloudfront.net__CloudFront_"
            )
            .unwrap(),
        }]))
    );

    #[test]
    fn test_via_symmetric_encoder() {
        for via_input in [
            Via(vec![
                ViaElement {
                    protocol: None,
                    version: ForwardedVersion::HTTP_10,
                    node_id: NodeId::try_from_str("fred").unwrap(),
                },
                ViaElement {
                    protocol: None,
                    version: ForwardedVersion::HTTP_11,
                    node_id: NodeId::try_from_str("p.example.net").unwrap(),
                },
            ]),
            Via(vec![
                ViaElement {
                    protocol: Some(ForwardedProtocol::HTTP),
                    version: ForwardedVersion::HTTP_11,
                    node_id: NodeId::try_from_str("proxy.example.re").unwrap(),
                },
                ViaElement {
                    protocol: None,
                    version: ForwardedVersion::HTTP_11,
                    node_id: NodeId::try_from_str("edge_1").unwrap(),
                },
            ]),
            Via(vec![ViaElement {
                protocol: None,
                version: ForwardedVersion::HTTP_11,
                node_id: NodeId::try_from_str(
                    "2e9b3ee4d534903f433e1ed8ea30e57a.cloudfront.net__CloudFront_",
                )
                .unwrap(),
            }]),
        ] {
            let mut values = Vec::new();
            via_input.encode(&mut values);
            let via_output = Via::decode(&mut values.iter()).unwrap();
            assert_eq!(via_input, via_output);
        }
    }
}
