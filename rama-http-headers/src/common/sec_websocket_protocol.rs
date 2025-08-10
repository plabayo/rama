use rama_core::telemetry::tracing;
use rama_http_types::{HeaderName, HeaderValue};
use std::{fmt, sync::Arc};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader, util::csv};

/// The `Sec-Websocket-Protocol` header, containing one or multiple protocols.
///
/// Sub protocols are advertised by the client,
/// and the server has to match it if defined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecWebsocketProtocol(Vec<Arc<str>>);

#[derive(Debug, Clone, PartialEq, Eq)]
/// Utility type containing the accepted [`SecWebsocketProtocol`].
pub struct AcceptedWebsocketProtocol(Arc<str>);

impl AcceptedWebsocketProtocol {
    #[inline]
    #[must_use]
    /// consume this instance as a `Arc<str>`.
    pub fn into_inner(self) -> Arc<str> {
        self.0
    }

    #[inline]
    #[must_use]
    /// consume this instance as a [`SecWebsocketProtocol`]
    ///
    /// Useful for servers to communicate back to clients.
    pub fn into_header(self) -> SecWebsocketProtocol {
        self.into()
    }
}

impl From<AcceptedWebsocketProtocol> for SecWebsocketProtocol {
    fn from(value: AcceptedWebsocketProtocol) -> Self {
        Self::new(value.0)
    }
}

impl TypedHeader for SecWebsocketProtocol {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::SEC_WEBSOCKET_PROTOCOL
    }
}

impl HeaderDecode for SecWebsocketProtocol {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let mut iter = values.flat_map(|value| {
            value.to_str().into_iter().flat_map(|string| {
                string.split(',').filter_map(|x| match x.trim() {
                    "" => None,
                    y => Some(Arc::from(y)),
                })
            })
        });
        let first = iter.next().ok_or_else(|| {
            tracing::debug!(
                "invalid sec-websocket-protocol header value: no non-empty values found; return invalid err"
            );
            Error::invalid()
        })?;

        let mut v = vec![first];
        v.extend(iter);
        Ok(Self(v))
    }
}

impl HeaderEncode for SecWebsocketProtocol {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
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
            Format(|f: &mut fmt::Formatter<'_>| { csv::fmt_comma_delimited(&mut *f, self.iter()) })
        );
        values.extend(Some(HeaderValue::try_from(s).unwrap()))
    }
}

impl SecWebsocketProtocol {
    #[inline]
    /// Create a new [`SecWebSocketProtocol`] header from the given protocol
    pub fn new(protocol: impl Into<Arc<str>>) -> Self {
        Self(vec![protocol.into()])
    }

    #[must_use]
    /// Return the first protocol in this [`SecWebSocketProtocol`] as the [`AcceptedWebSocketProtocol`].
    pub fn accept_first_protocol(&self) -> AcceptedWebsocketProtocol {
        // assumption: we always have at least one item
        AcceptedWebsocketProtocol(self.0[0].clone())
    }

    /// returns true if the given protocol is found in this [`SubProtocols`]
    pub fn contains(&self, protocol: impl AsRef<str>) -> Option<AcceptedWebsocketProtocol> {
        let protocol = protocol.as_ref().trim();
        self.0.iter().find_map(|candidate| {
            candidate
                .trim()
                .eq_ignore_ascii_case(protocol)
                .then(|| AcceptedWebsocketProtocol(candidate.clone()))
        })
    }

    /// returns true if any of the given protocol is found in this [`SubProtocols`]
    ///
    /// Searched in order.
    pub fn contains_any(
        &self,
        protocols: impl IntoIterator<Item: AsRef<str>>,
    ) -> Option<AcceptedWebsocketProtocol> {
        protocols
            .into_iter()
            .find_map(|protocol| self.contains(protocol))
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|it| it.as_ref())
    }

    pub fn iter_cloned(&self) -> impl Iterator<Item = Arc<str>> {
        self.0.iter().cloned()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add the WebSocket protocol, appending it to any existing protocol(s).
        pub fn additional_protocol(mut self, protocol: impl Into<Arc<str>>) -> Self {
            self.0.push(protocol.into());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add the WebSocket protocols, appending it to any existing protocol(s).
        pub fn additional_protocols(mut self, protocols: impl IntoIterator<Item = impl Into<Arc<str>>>) -> Self {
            self.0.extend(protocols.into_iter().map(Into::into));
            self
        }
    }
}

impl IntoIterator for SecWebsocketProtocol {
    type Item = Arc<str>;
    type IntoIter = std::vec::IntoIter<Arc<str>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl AcceptedWebsocketProtocol {
    /// Create a new [`AcceptedWebSocketProtocol`]
    pub fn new(s: impl Into<Arc<str>>) -> Self {
        Self(s.into())
    }
}

impl AcceptedWebsocketProtocol {
    #[must_use]
    /// View the [`AcceptedSubProtocol`] as a `str` reference.
    pub fn as_str(&self) -> &str {
        self.0.as_ref().trim()
    }
}

impl AsRef<str> for AcceptedWebsocketProtocol {
    fn as_ref(&self) -> &str {
        self.0.as_ref().trim()
    }
}

impl PartialEq<str> for AcceptedWebsocketProtocol {
    fn eq(&self, other: &str) -> bool {
        self.as_str().eq_ignore_ascii_case(other.trim())
    }
}
impl PartialEq<&str> for AcceptedWebsocketProtocol {
    fn eq(&self, other: &&str) -> bool {
        self.as_str().eq_ignore_ascii_case(other.trim())
    }
}

impl PartialEq<AcceptedWebsocketProtocol> for str {
    fn eq(&self, other: &AcceptedWebsocketProtocol) -> bool {
        self.trim().eq_ignore_ascii_case(other.as_str())
    }
}

impl PartialEq<AcceptedWebsocketProtocol> for &str {
    fn eq(&self, other: &AcceptedWebsocketProtocol) -> bool {
        self.trim().eq_ignore_ascii_case(other.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    #[test]
    fn protocols_reflective_str_single() {
        fn assert_encode_decode_eq(s: &str, equal: bool) {
            let header: SecWebsocketProtocol = test_decode(&[s]).unwrap();
            let headers = test_encode(header);
            let output = &headers["sec-websocket-protocol"];
            if equal {
                assert_eq!(s, output, "input ({s}) != output ({output:?})");
            } else {
                assert_ne!(s, output, "input ({s}) == output ({output:?})");
            }
        }
        assert_encode_decode_eq("foo", true);
        assert_encode_decode_eq(" foo ", false);
        assert_encode_decode_eq("x-foo-123", true);
        assert_encode_decode_eq("X-Foo-Bar", true);
        assert_encode_decode_eq("a b", true);
    }

    #[test]
    fn protocols_reflective_str_multiple() {
        fn assert_encode_decode_eq(s: &[&'static str], equal: bool) {
            let header: SecWebsocketProtocol = test_decode(s).unwrap();
            let headers = test_encode(header);
            let output = &headers["sec-websocket-protocol"];
            if equal {
                assert_eq!(
                    &s.join(", "),
                    output,
                    "input ({s:?}) != output ({output:?})"
                );
            } else {
                assert_ne!(
                    &s.join(", "),
                    output,
                    "input ({s:?}) == output ({output:?})"
                );
            }
        }
        assert_encode_decode_eq(&["foo"], true);
        assert_encode_decode_eq(&["x-foo-123", "foo"], true);
        assert_encode_decode_eq(&["a", "b", "c"], true);
        assert_encode_decode_eq(&["a b", "c d"], true);
    }

    #[test]
    fn test_accept_first_protocol() {
        let header: SecWebsocketProtocol = test_decode(&["a, b"]).unwrap();
        assert_eq!("a", header.accept_first_protocol());
    }

    #[test]
    fn test_contains() {
        for (input, protocol, expected) in [
            ("a", "b", None),
            ("a", "a", Some("a")),
            ("a", " a", Some("a")),
            ("a", "A ", Some("a")),
            ("a", " A ", Some("a")),
            ("a, b", " A ", Some("a")),
            ("a, b", "b", Some("b")),
            ("a, b", " B ", Some("b")),
            ("a, b", " c ", None),
        ] {
            let header: SecWebsocketProtocol = test_decode(&[input]).unwrap();
            assert_eq!(
                expected,
                header.contains(protocol).as_ref().map(|p| p.as_str()),
                "input: '{input}'"
            );
        }
    }

    #[test]
    fn test_contains_any() {
        struct Case {
            input: &'static str,
            protocols: &'static [&'static str],
            expected: Option<&'static str>,
        }
        impl Case {
            fn new(
                input: &'static str,
                protocols: &'static [&'static str],
                expected: Option<&'static str>,
            ) -> Self {
                Self {
                    input,
                    protocols,
                    expected,
                }
            }
        }

        for case in [
            Case::new("a", &["b"], None),
            Case::new("a", &["a"], Some("a")),
            Case::new("a", &[" a"], Some("a")),
            Case::new("a", &[" A "], Some("a")),
            Case::new("a, b", &["b", "a"], Some("b")),
            Case::new("a, b", &["c", "a", "b", "a"], Some("a")),
            Case::new("a, b", &["c", "d"], None),
            Case::new("a", &["c", "d"], None),
            Case::new("d", &["c", "d"], Some("d")),
        ] {
            let header: SecWebsocketProtocol = test_decode(&[case.input]).unwrap();
            assert_eq!(
                case.expected,
                header
                    .contains_any(case.protocols)
                    .as_ref()
                    .map(|p| p.as_str()),
                "input: '{}'",
                case.input,
            );
        }
    }
}
