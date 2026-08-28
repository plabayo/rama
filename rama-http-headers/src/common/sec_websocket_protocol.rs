use rama_core::extensions::Extension;
use rama_http_types::{HeaderName, HeaderValue};
use rama_utils::collections::NonEmptySmallVec;
use rama_utils::str::NonEmptyStr;
use std::fmt;

/// The `Sec-WebSocket-Protocol` header, containing one or multiple protocols.
///
/// Subprotocols are advertised by the client and matched case-sensitively by
/// the server. Each value must use the HTTP `token` syntax required by RFC 6455.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecWebSocketProtocol(pub NonEmptySmallVec<3, NonEmptyStr>);

/// Error returned for a WebSocket subprotocol that is not an HTTP token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidWebSocketProtocol {
    _private: (),
}

impl fmt::Display for InvalidWebSocketProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("websocket subprotocol is not a valid HTTP token")
    }
}

impl std::error::Error for InvalidWebSocketProtocol {}

impl crate::TypedHeader for SecWebSocketProtocol {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::SEC_WEBSOCKET_PROTOCOL
    }
}

impl crate::HeaderDecode for SecWebSocketProtocol {
    fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let protocols: NonEmptySmallVec<3, NonEmptyStr> =
            crate::util::try_decode_flat_csv_header_values_as_non_empty_smallvec(
                values,
                crate::util::FlatCsvSeparator::Comma,
            )
            .map_err(|err| {
                rama_core::telemetry::tracing::debug!(
                    "failed to decode Sec-WebSocket-Protocol as a flat CSV header: {err}"
                );
                crate::Error::invalid()
            })?;

        if protocols.iter().all(|protocol| is_http_token(protocol)) {
            Ok(Self(protocols))
        } else {
            rama_core::telemetry::tracing::debug!(
                "failed to decode Sec-WebSocket-Protocol: invalid protocol token"
            );
            Err(crate::Error::invalid())
        }
    }
}

impl crate::HeaderEncode for SecWebSocketProtocol {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        if !self.0.iter().all(|protocol| is_http_token(protocol)) {
            rama_core::telemetry::tracing::debug!(
                "failed to encode Sec-WebSocket-Protocol: invalid protocol token"
            );
            return;
        }

        match crate::util::try_encode_non_empty_smallvec_as_flat_csv_header_value(
            &self.0,
            crate::util::FlatCsvSeparator::Comma,
        ) {
            Ok(value) => values.extend(std::iter::once(value)),
            Err(err) => rama_core::telemetry::tracing::debug!(
                "failed to encode Sec-WebSocket-Protocol as a flat CSV header: {err}"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Extension)]
#[extension(tags(http, ws))]
/// Utility type containing the accepted [`SecWebSocketProtocol`].
pub struct AcceptedWebSocketProtocol(pub NonEmptyStr);

impl AcceptedWebSocketProtocol {
    #[inline]
    #[must_use]
    /// consume this instance as a [`SecWebSocketProtocol`]
    ///
    /// Useful for servers to communicate back to clients.
    pub fn into_header(self) -> SecWebSocketProtocol {
        self.into()
    }
}

impl From<AcceptedWebSocketProtocol> for SecWebSocketProtocol {
    fn from(value: AcceptedWebSocketProtocol) -> Self {
        Self::new(value.0)
    }
}

impl SecWebSocketProtocol {
    /// Construct a protocol header without validation.
    ///
    /// Prefer [`Self::try_new`] when the protocol is not a trusted constant.
    #[must_use]
    pub fn new(value: NonEmptyStr) -> Self {
        Self(NonEmptySmallVec::new(value))
    }

    /// Construct a protocol header after validating RFC 6455 token syntax.
    pub fn try_new(value: NonEmptyStr) -> Result<Self, InvalidWebSocketProtocol> {
        if is_http_token(&value) {
            Ok(Self::new(value))
        } else {
            Err(InvalidWebSocketProtocol { _private: () })
        }
    }

    #[must_use]
    /// Return the first protocol in this [`SecWebSocketProtocol`] as the [`AcceptedWebSocketProtocol`].
    pub fn accept_first_protocol(&self) -> AcceptedWebSocketProtocol {
        // assumption: we always have at least one item
        AcceptedWebSocketProtocol(self.0[0].clone())
    }

    /// returns true if the given protocol is found in this [`SecWebSocketProtocol`]
    pub fn contains(&self, protocol: impl AsRef<str>) -> Option<AcceptedWebSocketProtocol> {
        let protocol = protocol.as_ref().trim();
        self.0.iter().find_map(|candidate| {
            (candidate.trim() == protocol).then(|| AcceptedWebSocketProtocol(candidate.clone()))
        })
    }

    /// returns true if any of the given protocol is found in this [`SecWebSocketProtocol`]
    ///
    /// Searched in order.
    pub fn contains_any(
        &self,
        protocols: impl IntoIterator<Item: AsRef<str>>,
    ) -> Option<AcceptedWebSocketProtocol> {
        protocols
            .into_iter()
            .find_map(|protocol| self.contains(protocol))
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|it| it.as_ref())
    }
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    #[test]
    fn protocols_reflective_str_single() {
        fn assert_encode_decode_eq(s: &str, equal: bool) {
            let header: SecWebSocketProtocol = test_decode(&[s]).unwrap();
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
    }

    #[test]
    fn protocols_reflective_str_multiple() {
        fn assert_encode_decode_eq(s: &[&'static str], equal: bool) {
            let header: SecWebSocketProtocol = test_decode(s).unwrap();
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
    }

    #[test]
    fn test_accept_first_protocol() {
        let header: SecWebSocketProtocol = test_decode(&["a, b"]).unwrap();
        assert_eq!("a", header.accept_first_protocol().0);
    }

    #[test]
    fn test_contains() {
        for (input, protocol, expected) in [
            ("a", "b", None),
            ("a", "a", Some("a")),
            ("a", " a", Some("a")),
            ("a", "A ", None),
            ("a", " A ", None),
            ("a, b", " A ", None),
            ("a, b", "b", Some("b")),
            ("a, b", " B ", None),
            ("a, b", " c ", None),
        ] {
            let header: SecWebSocketProtocol = test_decode(&[input]).unwrap();
            assert_eq!(
                expected,
                header.contains(protocol).as_ref().map(|p| p.0.as_ref()),
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
            Case::new("a", &[" A "], None),
            Case::new("a, b", &["b", "a"], Some("b")),
            Case::new("a, b", &["c", "a", "b", "a"], Some("a")),
            Case::new("a, b", &["c", "d"], None),
            Case::new("a", &["c", "d"], None),
            Case::new("d", &["c", "d"], Some("d")),
        ] {
            let header: SecWebSocketProtocol = test_decode(&[case.input]).unwrap();
            assert_eq!(
                case.expected,
                header
                    .contains_any(case.protocols)
                    .as_ref()
                    .map(|p| p.0.as_ref()),
                "input: '{}'",
                case.input,
            );
        }
    }

    #[test]
    fn rejects_invalid_protocol_tokens() {
        for value in ["a b", "quoted\"value", "foo/bar", "foo=bar", "(foo)"] {
            assert!(
                test_decode::<SecWebSocketProtocol>(&[value]).is_none(),
                "{value}"
            );
        }
        SecWebSocketProtocol::try_new(NonEmptyStr::try_from("a b").unwrap()).unwrap_err();
    }
}
