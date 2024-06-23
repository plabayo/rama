use crate::http::headers::{self, Header};
use crate::http::{HeaderName, HeaderValue};
use crate::net::forwarded::ForwardedElement;
use std::iter::FromIterator;
use std::net::IpAddr;

/// The `X-Forwarded-For` (XFF) request header is a de-facto standard header for
/// identifying the originating IP address of a client connecting to a web server through a proxy server.
///
/// It is recommended to use the [`Forwarded`](super::Forwarded) header instead if you can.
///
/// More info can be found at <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For>.
///
/// # Syntax
///
/// ```text
/// X-Forwarded-For: <client>, <proxy1>, <proxy2>
/// ```
///
/// # Example values
///
/// * `2001:db8:85a3:8d3:1319:8a2e:370:7348`
/// * `203.0.113.195`
/// * `203.0.113.195,2001:db8:85a3:8d3:1319:8a2e:370:7348,198.51.100.178`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XForwardedFor(Vec<IpAddr>);

impl Header for XForwardedFor {
    fn name() -> &'static HeaderName {
        &crate::http::header::X_FORWARDED_FOR
    }

    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(
        values: &mut I,
    ) -> Result<Self, headers::Error> {
        crate::http::headers::util::csv::from_comma_delimited(values).map(XForwardedFor)
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

impl FromIterator<IpAddr> for XForwardedFor {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = IpAddr>,
    {
        XForwardedFor(iter.into_iter().collect())
    }
}

impl super::ForwardHeader for XForwardedFor {
    fn try_from_forwarded<'a, I>(input: I) -> Option<Self>
    where
        I: IntoIterator<Item = &'a ForwardedElement>,
    {
        let vec: Vec<_> = input
            .into_iter()
            .filter_map(|el| el.ref_forwarded_for()?.ip())
            .collect();
        if vec.is_empty() {
            None
        } else {
            Some(XForwardedFor(vec))
        }
    }
}

impl XForwardedFor {
    /// Returns an iterator over the defined [`IpAddr`].
    pub fn iter(&self) -> impl Iterator<Item = &IpAddr> {
        self.0.iter()
    }
}

impl IntoIterator for XForwardedFor {
    type Item = ForwardedElement;
    type IntoIter = XForwardedForIterator;

    fn into_iter(self) -> Self::IntoIter {
        XForwardedForIterator(self.0.into_iter())
    }
}

#[derive(Debug, Clone)]
/// An iterator over the `XForwardedFor` header's elements.
pub struct XForwardedForIterator(std::vec::IntoIter<IpAddr>);

impl Iterator for XForwardedForIterator {
    type Item = ForwardedElement;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(ForwardedElement::forwarded_for)
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
                    XForwardedFor::decode(
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
        vec!["2001:db8:85a3:8d3:1319:8a2e:370:7348"],
        Some(XForwardedFor(vec!["2001:db8:85a3:8d3:1319:8a2e:370:7348"
            .parse()
            .unwrap(),]))
    );
    test_header!(
        test2,
        vec!["203.0.113.195"],
        Some(XForwardedFor(vec!["203.0.113.195".parse().unwrap(),]))
    );
    test_header!(
        test3,
        vec!["203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348"],
        Some(XForwardedFor(vec![
            "203.0.113.195".parse().unwrap(),
            "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap()
        ]))
    );
    test_header!(
        test4,
        vec!["203.0.113.195", "2001:db8:85a3:8d3:1319:8a2e:370:7348"],
        Some(XForwardedFor(vec![
            "203.0.113.195".parse().unwrap(),
            "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap()
        ]))
    );
    test_header!(
        test5,
        vec![
            "203.0.113.195,2001:db8:85a3:8d3:1319:8a2e:370:7348",
            "198.51.100.178"
        ],
        Some(XForwardedFor(vec![
            "203.0.113.195".parse().unwrap(),
            "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap(),
            "198.51.100.178".parse().unwrap()
        ]))
    );
    test_header!(
        test6,
        vec![
            "203.0.113.195",
            "2001:db8:85a3:8d3:1319:8a2e:370:7348",
            "198.51.100.178",
        ],
        Some(XForwardedFor(vec![
            "203.0.113.195".parse().unwrap(),
            "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap(),
            "198.51.100.178".parse().unwrap()
        ]))
    );
    test_header!(
        test7,
        vec![
            "203.0.113.195",
            "2001:db8:85a3:8d3:1319:8a2e:370:7348,198.51.100.178",
        ],
        Some(XForwardedFor(vec![
            "203.0.113.195".parse().unwrap(),
            "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap(),
            "198.51.100.178".parse().unwrap()
        ]))
    );

    #[test]
    fn test_x_forwarded_for_symmetric_encoder() {
        for input in [
            XForwardedFor(vec!["203.0.113.195".parse().unwrap()]),
            XForwardedFor(vec![
                "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap(),
                "203.0.113.195".parse().unwrap(),
            ]),
        ] {
            let mut values = Vec::new();
            input.encode(&mut values);
            assert_eq!(XForwardedFor::decode(&mut values.iter()).ok(), Some(input),);
        }
    }
}
