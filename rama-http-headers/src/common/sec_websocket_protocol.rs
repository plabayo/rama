use rama_utils::str::NonEmptyStr;

derive_non_empty_flat_csv_header! {
    #[header(name = SEC_WEBSOCKET_PROTOCOL, sep = Comma)]
    /// The `Sec-WebSocket-Protocol` header, containing one or multiple protocols.
    ///
    /// Sub protocols are advertised by the client,
    /// and the server has to match it if defined.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SecWebSocketProtocol(pub NonEmptySmallVec<3, NonEmptyStr>);
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
            candidate
                .trim()
                .eq_ignore_ascii_case(protocol)
                .then(|| AcceptedWebSocketProtocol(candidate.clone()))
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
        assert_encode_decode_eq("a b", true);
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
        assert_encode_decode_eq(&["a b", "c d"], true);
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
            ("a", "A ", Some("a")),
            ("a", " A ", Some("a")),
            ("a, b", " A ", Some("a")),
            ("a, b", "b", Some("b")),
            ("a, b", " B ", Some("b")),
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
            Case::new("a", &[" A "], Some("a")),
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
}
