use crate::{HeaderDecode, HeaderEncode, TypedHeader, util};
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    error::{BoxError, ErrorContext},
    telemetry::tracing,
};
use rama_http_types::{HeaderName, HeaderValue, header};
use rama_net::forwarded::{ForwardedElement, ForwardedProtocol, ForwardedVersion, NodeId};
use rama_utils::bytes::{trim_ows, trim_ows_start};

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
        let mut el = Self::new_forwarded_by(via.node_id);
        el.set_forwarded_version(via.version);
        if let Some(protocol) = via.protocol {
            el.set_forwarded_proto(protocol);
        }
        el
    }
}

impl TypedHeader for Via {
    fn name() -> &'static HeaderName {
        &header::VIA
    }
}

impl HeaderDecode for Via {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(
        values: &mut I,
    ) -> Result<Self, crate::Error> {
        util::csv::from_comma_delimited(values).map(Via)
    }
}

impl HeaderEncode for Via {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let s = rama_utils::fmt::display_fn(|f: &mut std::fmt::Formatter<'_>| {
            util::csv::fmt_comma_delimited(&mut *f, self.0.iter())
        })
        .to_string();
        match HeaderValue::try_from(s) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => tracing::debug!("failed to encode via as header value: {err}"),
        }
    }
}

impl FromIterator<ViaElement> for Via {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ViaElement>,
    {
        Self(iter.into_iter().collect())
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
                let node_id = el.forwarded_by()?.clone();
                let version = el.forwarded_version()?;
                let protocol = el.forwarded_proto();
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
            Some(Self(vec))
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
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = trim_ows_start(s.as_bytes());

        // RWS separates the parts, and may be HTAB as well as SP (RFC 9110 §7.6.3)
        let (protocol, version, bytes) = match split_once(bytes, |b| b == b'/' || is_rws(b)) {
            Some((head, b'/', tail)) => {
                let protocol: ForwardedProtocol = std::str::from_utf8(head)
                    .context("parse via protocol as utf-8")?
                    .try_into()
                    .context("parse via utf-8 protocol as protocol")?;
                let (version, _, tail) = split_once(tail, is_rws).ok_or_else(|| {
                    BoxError::from_static_str("via str: missing space after protocol separator")
                })?;
                let version = ForwardedVersion::try_from(version).context("parse via version")?;
                (Some(protocol), version, tail)
            }
            Some((head, _, tail)) => {
                let version = ForwardedVersion::try_from(head).context("parse via version")?;
                (None, version, tail)
            }
            None => {
                return Err(BoxError::from_static_str("via str: missing version"));
            }
        };

        let bytes = trim_ows(bytes);
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

/// Split around the first byte matching `pred`, returning `(head, separator, tail)`.
fn split_once(b: &[u8], pred: impl Fn(u8) -> bool) -> Option<(&[u8], u8, &[u8])> {
    let index = b.iter().position(|c| pred(*c))?;
    let (head, rest) = b.split_at_checked(index)?;
    let (separator, tail) = rest.split_first()?;
    Some((head, *separator, tail))
}

const fn is_rws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

#[cfg(test)]
mod tests {
    use super::*;

    use rama_http_types::HeaderValue;

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

    test_header!(
        tab_separated_parts,
        vec!["\t1.1\tvegur\t, HTTP/1.0\t \tfred"],
        Some(Via(vec![
            ViaElement {
                protocol: None,
                version: ForwardedVersion::HTTP_11,
                node_id: NodeId::try_from_str("vegur").unwrap(),
            },
            ViaElement {
                protocol: Some(ForwardedProtocol::HTTP),
                version: ForwardedVersion::HTTP_10,
                node_id: NodeId::try_from_str("fred").unwrap(),
            }
        ]))
    );

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

    test_header!(test_empty_node, vec!["1.1"], None);
    test_header!(test_protocol_without_version, vec!["HTTP/"], None);
    test_header!(test_protocol_without_space, vec!["HTTP/1.1"], None);
    test_header!(test_only_separator, vec!["/"], None);
    test_header!(test_empty_protocol, vec!["/1.1 foo"], None);

    #[test]
    fn element_trims_trailing_ows() {
        let element: ViaElement = "1.1 vegur \t".parse().unwrap();
        assert_eq!(element.node_id, NodeId::try_from_str("vegur").unwrap());
    }

    #[test]
    fn test_via_adversarial_input_no_panic() {
        for input in [
            " ",
            "/",
            "//",
            "/ ",
            " /",
            "1.1 ",
            "1.1  ",
            "HTTP/ ",
            "HTTP/1.1 ",
            "HTTP/1.1 /",
            "HTTP//1.1 x",
            "\t1.1 x",
            "1.1\tx",
            "1.1 [::1]:",
            "1.1 :",
            "1.1 x:99999999999",
            "1.1 ü",
            "HTTP/1.1 ü:ü",
        ] {
            let Ok(value) = HeaderValue::from_bytes(input.as_bytes()) else {
                continue;
            };
            if let Ok(via) = Via::decode(&mut [value].iter()) {
                let mut values = Vec::new();
                via.encode(&mut values);
                via.into_iter().for_each(|el| _ = el.to_string());
            }
        }
    }

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
