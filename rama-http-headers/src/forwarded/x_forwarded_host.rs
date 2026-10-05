use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};
use rama_core::telemetry::tracing;
use rama_http_types::header;
use rama_http_types::{HeaderName, HeaderValue};
use rama_net::address::Host;
use rama_net::forwarded::{ForwardedAuthority, ForwardedElement};
use rama_utils::collections::NonEmptyVec;

/// The X-Forwarded-Host (XFH) header is a de-facto standard header for identifying the
/// original host requested by the client in the Host HTTP request header.
///
/// It is recommended to use the [`Forwarded`](super::Forwarded) header instead if you can.
///
/// More info can be found at <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host>.
///
/// # Syntax
///
/// ```text
/// X-Forwarded-Host: <host>
/// ```
///
/// Proxies that append keep one host per hop, on one line or several, nearest last: every one
/// is kept, and the accessors read the nearest, as the default
/// [`ForwardedSelectionPolicy`](rama_net::forwarded::ForwardedSelectionPolicy) does.
///
/// # Example values
///
/// * `id42.example-cdn.com`
/// * `id42.example-cdn.com:443`
/// * `203.0.113.195`
/// * `203.0.113.195:80`
/// * `2001:db8:85a3:8d3:1319:8a2e:370:7348`
/// * `[2001:db8:85a3:8d3:1319:8a2e:370:7348]:8080`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XForwardedHost(NonEmptyVec<ForwardedAuthority>);

impl TypedHeader for XForwardedHost {
    fn name() -> &'static HeaderName {
        &header::X_FORWARDED_HOST
    }
}

impl HeaderDecode for XForwardedHost {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let hosts: Vec<ForwardedAuthority> = crate::util::csv::from_comma_delimited(values)?;
        NonEmptyVec::from_vec(hosts)
            .map(Self)
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for XForwardedHost {
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
                tracing::debug!("failed to encode x-forwarded-host as header value: {err}")
            }
        }
    }
}

impl XForwardedHost {
    #[inline]
    /// Get a reference to the [`Host`] of the nearest hop of this [`XForwardedHost`].
    #[must_use]
    pub fn host(&self) -> &Host {
        &self.0.last().0.host
    }

    #[inline]
    /// Get a copy of the `port` of the nearest hop of this [`XForwardedHost`] if it is set.
    /// Empty (`:` with no digits) maps to `None` along with truly absent.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.0.last().0.port.as_u16()
    }

    /// The nearest hop's host.
    #[must_use]
    pub fn inner(&self) -> &ForwardedAuthority {
        self.0.last()
    }

    /// Every hop's host, nearest last.
    #[must_use]
    pub fn hosts(&self) -> &NonEmptyVec<ForwardedAuthority> {
        &self.0
    }

    /// Consume this header into every hop's host, nearest last.
    #[must_use]
    pub fn into_inner(self) -> NonEmptyVec<ForwardedAuthority> {
        self.0
    }
}

impl IntoIterator for XForwardedHost {
    type Item = ForwardedElement;
    type IntoIter = XForwardedHostIterator;

    fn into_iter(self) -> Self::IntoIter {
        XForwardedHostIterator(self.0.into_iter())
    }
}

impl super::ForwardHeader for XForwardedHost {
    fn try_from_forwarded<'a, I>(input: I) -> Option<Self>
    where
        I: IntoIterator<Item = &'a ForwardedElement>,
    {
        let hosts: Vec<_> = input
            .into_iter()
            .filter_map(|element| element.forwarded_host().cloned())
            .collect();
        NonEmptyVec::from_vec(hosts).map(Self)
    }
}

#[derive(Debug, Clone)]
/// An iterator over the `XForwardedHost` header's elements.
pub struct XForwardedHostIterator(<NonEmptyVec<ForwardedAuthority> as IntoIterator>::IntoIter);

impl Iterator for XForwardedHostIterator {
    type Item = ForwardedElement;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(ForwardedElement::new_forwarded_host)
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
                    XForwardedHost::decode(
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
        vec!["id42.example-cdn.com"],
        Some(XForwardedHost(NonEmptyVec::new(
            "id42.example-cdn.com".parse().unwrap()
        )))
    );
    test_header!(
        test2,
        // Every line counts, nearest last.
        vec!["id42.example-cdn.com", "example.com"],
        Some(XForwardedHost(
            NonEmptyVec::from_vec(vec![
                "id42.example-cdn.com".parse().unwrap(),
                "example.com".parse().unwrap(),
            ])
            .unwrap()
        ))
    );
    test_header!(
        test3,
        vec!["id42.example-cdn.com:443"],
        Some(XForwardedHost(NonEmptyVec::new(
            "id42.example-cdn.com:443".parse().unwrap()
        )))
    );
    test_header!(
        test4,
        vec!["203.0.113.195"],
        Some(XForwardedHost(NonEmptyVec::new(
            "203.0.113.195".parse().unwrap()
        )))
    );
    test_header!(
        test5,
        vec!["203.0.113.195:80"],
        Some(XForwardedHost(NonEmptyVec::new(
            "203.0.113.195:80".parse().unwrap()
        )))
    );
    test_header!(
        test6,
        vec!["2001:db8:85a3:8d3:1319:8a2e:370:7348"],
        Some(XForwardedHost(NonEmptyVec::new(
            "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap()
        )))
    );
    test_header!(
        test7,
        vec!["[2001:db8:85a3:8d3:1319:8a2e:370:7348]:8080"],
        Some(XForwardedHost(NonEmptyVec::new(
            "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:8080"
                .parse()
                .unwrap()
        )))
    );

    #[test]
    fn test_x_forwarded_host_adversarial_input_no_panic() {
        for input in [
            "",
            ":",
            "::",
            ":80",
            "[",
            "]",
            "[]",
            "[]:80",
            "[::1",
            "::1]",
            "[::1]:",
            "[::1]:99999",
            "::1:80",
            "example.com:",
            "example.com:65536",
            "example.com::80",
            "[example.com]:80",
            "%",
            "%zz",
            "%c3%bc",
            "ü",
            "ü.example.com",
            "example.com:ü",
            "[v1.x]:80",
            "user@example.com",
            "@",
            ".",
            "..",
            "a..b",
            "-.example.com",
        ] {
            let Ok(value) = HeaderValue::from_bytes(input.as_bytes()) else {
                continue;
            };
            if let Ok(header) = XForwardedHost::decode(&mut [value].iter()) {
                _ = header.host().to_string();
                _ = header.port();
                let mut values = Vec::new();
                header.encode(&mut values);
                header.into_iter().for_each(|el| _ = el.to_string());
            }
        }
    }

    /// The nearest hop is the last value, over separate lines or one comma list.
    #[test]
    fn the_nearest_host_is_the_last() {
        for lines in [
            &["cdn.example.com", "example.com:8443"][..],
            &["cdn.example.com, example.com:8443"],
        ] {
            let values: Vec<_> = lines.iter().map(|s| HeaderValue::from_static(s)).collect();
            let header = XForwardedHost::decode(&mut values.iter()).unwrap();
            assert_eq!(header.host().to_string(), "example.com", "{lines:?}");
            assert_eq!(header.port(), Some(8443), "{lines:?}");
            assert_eq!(header.inner().to_string(), "example.com:8443", "{lines:?}");
            assert_eq!(header.hosts().len(), 2, "{lines:?}");
        }
    }

    #[test]
    fn test_x_forwarded_host_symmetry_encode() {
        for input in [
            XForwardedHost(NonEmptyVec::new("id42.example-cdn.com".parse().unwrap())),
            XForwardedHost(NonEmptyVec::new(
                "id42.example-cdn.com:443".parse().unwrap(),
            )),
            XForwardedHost(NonEmptyVec::new("127.0.0.1".parse().unwrap())),
        ] {
            let mut values = Vec::new();
            input.encode(&mut values);
            assert_eq!(XForwardedHost::decode(&mut values.iter()).unwrap(), input);
        }
    }
}
