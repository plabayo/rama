use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};
use rama_core::telemetry::tracing;
use rama_http_types::{HeaderName, HeaderValue, header};
use rama_net::forwarded::{ForwardedElement, ForwardedProtocol};
use rama_utils::collections::NonEmptyVec;

/// The X-Forwarded-Proto (XFP) header is a de-facto standard header for
/// identifying the protocol (HTTP or HTTPS) that a client used to connect to your proxy or load balancer.
///
/// Your server access logs contain the protocol used between the server and the load balancer,
/// but not the protocol used between the client and the load balancer. To determine the protocol
/// used between the client and the load balancer, the X-Forwarded-Proto request header can be used.
///
/// It is recommended to use the [`Forwarded`](super::Forwarded) header instead if you can.
///
/// More info can be found at <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Proto>.
///
/// # Syntax
///
/// ```text
/// X-Forwarded-Proto: <protocol>
/// ```
///
/// Proxies that append keep one protocol per hop, on one line or several, nearest last: every
/// one is kept, and [`protocol`](Self::protocol) reads the nearest, as the default
/// [`ForwardedSelectionPolicy`](rama_net::forwarded::ForwardedSelectionPolicy) does.
///
/// # Example values
///
/// * `https`
/// * `http`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XForwardedProto(NonEmptyVec<ForwardedProtocol>);

impl TypedHeader for XForwardedProto {
    fn name() -> &'static HeaderName {
        &header::X_FORWARDED_PROTO
    }
}

impl HeaderDecode for XForwardedProto {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let protocols: Vec<ForwardedProtocol> = crate::util::csv::from_comma_delimited(values)?;
        NonEmptyVec::from_vec(protocols)
            .map(Self)
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for XForwardedProto {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let s = self
            .0
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        match HeaderValue::try_from(s) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                tracing::debug!("failed to encode x-forwarded-proto as header value: {err}")
            }
        }
    }
}

impl XForwardedProto {
    /// The nearest hop's [`ForwardedProtocol`].
    #[must_use]
    pub fn protocol(&self) -> &ForwardedProtocol {
        self.0.last()
    }

    /// Every hop's protocol, nearest last.
    #[must_use]
    pub fn protocols(&self) -> &NonEmptyVec<ForwardedProtocol> {
        &self.0
    }

    /// Consume this header into every hop's protocol, nearest last.
    #[must_use]
    pub fn into_protocols(self) -> NonEmptyVec<ForwardedProtocol> {
        self.0
    }
}

impl IntoIterator for XForwardedProto {
    type Item = ForwardedElement;
    type IntoIter = XForwardedProtoIterator;

    fn into_iter(self) -> Self::IntoIter {
        XForwardedProtoIterator(self.0.into_iter())
    }
}

impl super::ForwardHeader for XForwardedProto {
    fn try_from_forwarded<'a, I>(input: I) -> Option<Self>
    where
        I: IntoIterator<Item = &'a ForwardedElement>,
    {
        let protocols: Vec<_> = input
            .into_iter()
            .filter_map(ForwardedElement::forwarded_proto)
            .collect();
        NonEmptyVec::from_vec(protocols).map(Self)
    }
}

#[derive(Debug, Clone)]
/// An iterator over the `XForwardedProto` header's elements.
pub struct XForwardedProtoIterator(<NonEmptyVec<ForwardedProtocol> as IntoIterator>::IntoIter);

impl Iterator for XForwardedProtoIterator {
    type Item = ForwardedElement;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(ForwardedElement::new_forwarded_proto)
    }
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
                    XForwardedProto::decode(
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
        vec!["https"],
        Some(XForwardedProto(NonEmptyVec::new(ForwardedProtocol::HTTPS)))
    );
    test_header!(
        test2,
        // every line is a hop
        vec!["https", "http"],
        Some(XForwardedProto(
            NonEmptyVec::from_vec(vec![ForwardedProtocol::HTTPS, ForwardedProtocol::HTTP]).unwrap()
        ))
    );
    test_header!(
        test3,
        vec!["http"],
        Some(XForwardedProto(NonEmptyVec::new(ForwardedProtocol::HTTP)))
    );

    /// The nearest hop is the last value, over separate lines or one comma list.
    #[test]
    fn the_nearest_protocol_is_the_last() {
        for lines in [&["http", "https"][..], &["http, https"]] {
            let values: Vec<_> = lines.iter().map(|s| HeaderValue::from_static(s)).collect();
            let header = XForwardedProto::decode(&mut values.iter()).unwrap();
            assert_eq!(header.protocol(), &ForwardedProtocol::HTTPS, "{lines:?}");
            assert_eq!(header.protocols().len(), 2, "{lines:?}");
        }
    }

    #[test]
    fn test_x_forwarded_proto_symmetric_encoder() {
        for input in [ForwardedProtocol::HTTP, ForwardedProtocol::HTTPS] {
            let input = XForwardedProto(NonEmptyVec::new(input));
            let mut values = Vec::new();
            input.encode(&mut values);
            let output = XForwardedProto::decode(&mut values.iter()).unwrap();
            assert_eq!(input, output);
        }
    }
}
