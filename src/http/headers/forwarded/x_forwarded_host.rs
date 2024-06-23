use crate::http::headers::{self, Header};
use crate::http::{HeaderName, HeaderValue};
use crate::net::address::Host;
use crate::net::forwarded::{ForwardedAuthority, ForwardedElement};

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
/// # Example values
///
/// * `id42.example-cdn.com`
/// * `id42.example-cdn.com:443`
/// * `203.0.113.195`
/// * `203.0.113.195:80`
/// * `2001:db8:85a3:8d3:1319:8a2e:370:7348`
/// * `[2001:db8:85a3:8d3:1319:8a2e:370:7348]:8080`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XForwardedHost(ForwardedAuthority);

impl Header for XForwardedHost {
    fn name() -> &'static HeaderName {
        &crate::http::header::X_FORWARDED_HOST
    }

    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(
        values: &mut I,
    ) -> Result<Self, headers::Error> {
        Ok(XForwardedHost(
            values
                .next()
                .and_then(|value| value.to_str().ok().and_then(|s| s.parse().ok()))
                .ok_or_else(crate::http::headers::Error::invalid)?,
        ))
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let s = self.0.to_string();
        values.extend(Some(HeaderValue::from_str(&s).unwrap()))
    }
}

impl XForwardedHost {
    #[inline]
    /// Get a reference to the [`Host`] of this [`XForwardedHost`].
    pub fn host(&self) -> &Host {
        self.0.host()
    }

    #[inline]
    /// Get a copy of the `port` of this [`XForwardedHost`] if it is set.
    pub fn port(&self) -> Option<u16> {
        self.0.port()
    }

    /// Return a reference to the inner data of this [`Header`].
    pub fn inner(&self) -> &ForwardedAuthority {
        &self.0
    }

    /// Consume this [`Header`] into its inner data.
    pub fn into_inner(self) -> ForwardedAuthority {
        self.0
    }
}

impl IntoIterator for XForwardedHost {
    type Item = ForwardedElement;
    type IntoIter = XForwardedHostIterator;

    fn into_iter(self) -> Self::IntoIter {
        XForwardedHostIterator(Some(self.0))
    }
}

impl super::ForwardHeader for XForwardedHost {
    fn try_from_forwarded<'a, I>(input: I) -> Option<Self>
    where
        I: IntoIterator<Item = &'a ForwardedElement>,
    {
        let el = input.into_iter().next()?;
        let host = el.ref_forwarded_host().cloned()?;
        Some(XForwardedHost(host))
    }
}

#[derive(Debug, Clone)]
/// An iterator over the `XForwardedHost` header's elements.
pub struct XForwardedHostIterator(Option<ForwardedAuthority>);

impl Iterator for XForwardedHostIterator {
    type Item = ForwardedElement;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.take().map(ForwardedElement::forwarded_host)
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
        Some(XForwardedHost("id42.example-cdn.com".parse().unwrap()))
    );
    test_header!(
        test2,
        // 2nd one gets ignored
        vec!["id42.example-cdn.com", "example.com"],
        Some(XForwardedHost("id42.example-cdn.com".parse().unwrap()))
    );
    test_header!(
        test3,
        vec!["id42.example-cdn.com:443"],
        Some(XForwardedHost("id42.example-cdn.com:443".parse().unwrap()))
    );
    test_header!(
        test4,
        vec!["203.0.113.195"],
        Some(XForwardedHost("203.0.113.195".parse().unwrap()))
    );
    test_header!(
        test5,
        vec!["203.0.113.195:80"],
        Some(XForwardedHost("203.0.113.195:80".parse().unwrap()))
    );
    test_header!(
        test6,
        vec!["2001:db8:85a3:8d3:1319:8a2e:370:7348"],
        Some(XForwardedHost(
            "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap()
        ))
    );
    test_header!(
        test7,
        vec!["[2001:db8:85a3:8d3:1319:8a2e:370:7348]:8080"],
        Some(XForwardedHost(
            "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:8080"
                .parse()
                .unwrap()
        ))
    );

    #[test]
    fn test_x_forwarded_host_symmetry_encode() {
        for input in [
            XForwardedHost("id42.example-cdn.com".parse().unwrap()),
            XForwardedHost("id42.example-cdn.com:443".parse().unwrap()),
            XForwardedHost("127.0.0.1".parse().unwrap()),
        ] {
            let mut values = Vec::new();
            input.encode(&mut values);
            assert_eq!(XForwardedHost::decode(&mut values.iter()).unwrap(), input);
        }
    }
}
