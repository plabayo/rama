use crate::http::headers::{self, Header};
use crate::http::{HeaderName, HeaderValue};
use crate::net::Protocol;

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
pub struct Via(Protocol);

impl Header for Via {
    fn name() -> &'static HeaderName {
        &crate::http::header::X_FORWARDED_PROTO
    }

    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(
        values: &mut I,
    ) -> Result<Self, headers::Error> {
        Ok(Via(values
            .next()
            .and_then(|value| value.to_str().ok().and_then(|s| s.parse().ok()))
            .ok_or_else(crate::http::headers::Error::invalid)?))
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let s = self.0.to_string();
        values.extend(Some(HeaderValue::from_str(&s).unwrap()))
    }
}

impl Via {
    /// Get a reference to the [`Protocol`] of this [`Via`].
    pub fn protocol(&self) -> &Protocol {
        &self.0
    }
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
    test_header!(test1, vec!["https"], Some(Via(Protocol::Https)));
    test_header!(
        test2,
        // 2nd one gets ignored
        vec!["https", "http"],
        Some(Via(Protocol::Https))
    );
    test_header!(test3, vec!["http"], Some(Via(Protocol::Http)));
}
