use std::{fmt, str::FromStr};

use rama_http_types::{
    HeaderName, HeaderValue,
    structured_fields::{BareItem, ListEvent, ListMember, parse_list},
};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

rama_utils::macros::enums::enum_builder! {
    /// The purpose token of a [`SecPurpose`] header.
    ///
    /// Matched case-sensitively, as a Structured Field token: `PREFETCH` is
    /// another, unknown, token.
    ///
    /// # Example values
    ///
    /// * `prefetch`
    @String
    #[case_sensitive]
    pub enum SecPurposeKind {
        /// A speculative fetch: a prefetch, or a prerender when [`SecPurpose`]
        /// carries the `prerender` parameter.
        Prefetch => "prefetch",
    }
}

/// The `Sec-Purpose` [request header][mdn].
///
/// Sent by browsers on a speculative request: something fetched before the
/// user asked for it. The header is a Structured Field List (RFC 9651) with
/// a member that is the token `prefetch`, optionally with parameters:
///
/// * `prefetch`: `<link rel=prefetch>` or a speculation-rules prefetch.
/// * `prefetch;prerender`: a speculation-rules prerender, or one the browser
///   started itself (e.g. from the address bar).
/// * `prefetch;anonymous-client-ip`: a prefetch sent through a private
///   prefetch proxy, hiding the client's IP address.
///
/// A parameter is set by any value but `?0`, and unknown parameters are
/// ignored. Several field lines combine into one List. The first `prefetch`
/// member is read, wherever it is; without one, a first member that is
/// another token (`prefetch` matches case-sensitively) is kept as
/// [`SecPurposeKind::Unknown`], and anything else is invalid.
///
/// The legacy spellings `Purpose: prefetch`, `X-Purpose: preview` (Safari)
/// and `X-Moz: prefetch` (older Firefox) are separate headers this type does
/// not read.
///
/// It is not one of the [Fetch Metadata] headers, but describes the same
/// request context; [`FetchMetadata`] carries it alongside them.
///
/// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Purpose
/// [Fetch Metadata]: https://w3c.github.io/webappsec-fetch-metadata/
/// [`FetchMetadata`]: super::FetchMetadata
///
/// # Example
///
/// ```
/// use rama_http_headers::{HeaderMapExt, SecPurpose};
/// use rama_http_types::HeaderMap;
///
/// let mut headers = HeaderMap::new();
/// headers.typed_insert(SecPurpose::prerender());
/// assert_eq!(headers["sec-purpose"], "prefetch;prerender");
///
/// let purpose: SecPurpose = headers.typed_get().unwrap();
/// assert!(purpose.is_prefetch());
/// assert!(purpose.is_prerender());
/// assert!(!purpose.anonymous_client_ip());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecPurpose {
    kind: SecPurposeKind,
    prerender: bool,
    anonymous_client_ip: bool,
}

impl SecPurpose {
    /// A purpose of `kind`, without parameters.
    #[must_use]
    pub const fn new(kind: SecPurposeKind) -> Self {
        Self {
            kind,
            prerender: false,
            anonymous_client_ip: false,
        }
    }

    /// `prefetch`: a speculative fetch of a resource or document.
    #[must_use]
    pub const fn prefetch() -> Self {
        Self::new(SecPurposeKind::Prefetch)
    }

    /// `prefetch;prerender`: a speculative fetch that is also rendered.
    #[must_use]
    pub const fn prerender() -> Self {
        Self::prefetch().with_prerender(true)
    }

    /// The purpose token.
    #[must_use]
    pub fn kind(&self) -> &SecPurposeKind {
        &self.kind
    }

    /// Whether the purpose token is `prefetch`.
    ///
    /// A prerender is a prefetch on the wire, so this holds for it as well.
    #[must_use]
    pub fn is_prefetch(&self) -> bool {
        self.kind == SecPurposeKind::Prefetch
    }

    /// Whether the `prerender` parameter is set: the browser renders the
    /// response in the background, running its scripts.
    #[must_use]
    pub const fn is_prerender(&self) -> bool {
        self.prerender
    }

    /// Whether the `anonymous-client-ip` parameter is set: the request went
    /// through a private prefetch proxy, so the peer address is the proxy's,
    /// not the client's.
    #[must_use]
    pub const fn anonymous_client_ip(&self) -> bool {
        self.anonymous_client_ip
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `prerender` parameter.
        pub const fn prerender(mut self, prerender: bool) -> Self {
            self.prerender = prerender;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `anonymous-client-ip` parameter.
        pub const fn anonymous_client_ip(mut self, anonymous_client_ip: bool) -> Self {
            self.anonymous_client_ip = anonymous_client_ip;
            self
        }
    }

    /// Decode a complete Structured Field List.
    fn parse(input: &[u8]) -> Result<Self, Error> {
        /// The member the parameters being reported belong to.
        enum Target {
            Prefetch,
            First,
            Other,
        }

        // The first `prefetch` member, wherever it is in the List.
        let mut prefetch: Option<Self> = None;
        // The first member, when it is a token other than `prefetch`.
        let mut first: Option<Self> = None;
        let mut seen_member = false;
        let mut target = Target::Other;
        parse_list(input, |event| match event {
            ListEvent::Member(member) => {
                let is_first = !seen_member;
                seen_member = true;
                target = match member {
                    // Tokens are case-sensitive: `PREFETCH` is another token.
                    ListMember::Item(BareItem::Token("prefetch")) if prefetch.is_none() => {
                        prefetch = Some(Self::prefetch());
                        Target::Prefetch
                    }
                    ListMember::Item(BareItem::Token(token)) if is_first => {
                        first = Some(Self::new(SecPurposeKind::Unknown(token.into())));
                        Target::First
                    }
                    _ => Target::Other,
                };
            }
            ListEvent::Parameter { key, value } => {
                let purpose = match target {
                    Target::Prefetch => prefetch.as_mut(),
                    Target::First => first.as_mut(),
                    Target::Other => None,
                };
                if let Some(purpose) = purpose {
                    // Any value but `?0` sets a flag; a repeated key overrides the earlier one.
                    let set = value != BareItem::Boolean(false);
                    match key {
                        "prerender" => purpose.prerender = set,
                        "anonymous-client-ip" => purpose.anonymous_client_ip = set,
                        _ => {}
                    }
                }
            }
        })
        .map_err(|_error| Error::invalid())?;
        prefetch.or(first).ok_or_else(Error::invalid)
    }
}

impl TypedHeader for SecPurpose {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::SEC_PURPOSE
    }
}

impl HeaderDecode for SecPurpose {
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        // A List: every field line combines into one, empty ones included (RFC 9651 §4.2).
        let Some(first) = values.next() else {
            return Err(Error::invalid());
        };
        let Some(second) = values.next() else {
            return Self::parse(first.as_bytes());
        };
        let mut combined = first.as_bytes().to_vec();
        for value in std::iter::once(second).chain(values) {
            combined.extend_from_slice(b", ");
            combined.extend_from_slice(value.as_bytes());
        }
        Self::parse(&combined)
    }
}

impl HeaderEncode for SecPurpose {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(HeaderValue::try_from(self.to_string()).ok());
    }
}

impl fmt::Display for SecPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.as_str())?;
        if self.prerender {
            f.write_str(";prerender")?;
        }
        if self.anonymous_client_ip {
            f.write_str(";anonymous-client-ip")?;
        }
        Ok(())
    }
}

impl FromStr for SecPurpose {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s.as_bytes())
    }
}

impl serde::Serialize for SecPurpose {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for SecPurpose {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    #[test]
    fn known_forms_round_trip() {
        for (raw, purpose) in [
            ("prefetch", SecPurpose::prefetch()),
            ("prefetch;prerender", SecPurpose::prerender()),
            (
                "prefetch;anonymous-client-ip",
                SecPurpose::prefetch().with_anonymous_client_ip(true),
            ),
            (
                "prefetch;prerender;anonymous-client-ip",
                SecPurpose::prerender().with_anonymous_client_ip(true),
            ),
        ] {
            assert_eq!(test_decode::<SecPurpose>(&[raw]).as_ref(), Some(&purpose));
            assert_eq!(test_encode(purpose.clone())["sec-purpose"], raw);
            assert_eq!(raw.parse::<SecPurpose>().unwrap(), purpose);
        }
    }

    #[test]
    fn accessors() {
        let prefetch = SecPurpose::prefetch();
        assert!(prefetch.is_prefetch());
        assert!(!prefetch.is_prerender());
        assert!(!prefetch.anonymous_client_ip());

        let prerender = SecPurpose::prerender();
        assert!(prerender.is_prefetch());
        assert!(prerender.is_prerender());
        assert_eq!(prerender.kind(), &SecPurposeKind::Prefetch);

        let unknown = SecPurpose::new(SecPurposeKind::Unknown("preview".into()));
        assert!(!unknown.is_prefetch());
    }

    #[test]
    fn parameters() {
        let decode = |raw| test_decode::<SecPurpose>(&[raw]);
        // Unknown parameters are ignored.
        assert_eq!(
            decode("prefetch;foo;bar=1;prerender"),
            Some(SecPurpose::prerender())
        );
        // Parameter order does not matter on decode.
        assert_eq!(
            decode("prefetch;anonymous-client-ip;prerender"),
            Some(SecPurpose::prerender().with_anonymous_client_ip(true))
        );
        // Any value but `?0` sets a flag; the last repetition of a key wins.
        assert_eq!(
            decode("prefetch;prerender=?0"),
            Some(SecPurpose::prefetch())
        );
        assert_eq!(
            decode("prefetch;prerender=1;anonymous-client-ip=x"),
            Some(SecPurpose::prerender().with_anonymous_client_ip(true))
        );
        assert_eq!(
            decode("prefetch;prerender=0;anonymous-client-ip=\"?0\""),
            Some(SecPurpose::prerender().with_anonymous_client_ip(true))
        );
        assert_eq!(
            decode("prefetch;prerender;prerender=?0"),
            Some(SecPurpose::prefetch())
        );
        assert_eq!(
            decode("prefetch;prerender=?0;prerender"),
            Some(SecPurpose::prerender())
        );
        // Spaces may lead the List and a parameter key (RFC 9651 §4.2.3.2), not precede `;`.
        assert_eq!(
            decode("  prefetch;prerender"),
            Some(SecPurpose::prerender())
        );
        assert_eq!(decode("prefetch; prerender"), Some(SecPurpose::prerender()));
        assert_eq!(decode("prefetch ;prerender"), None);
    }

    #[test]
    fn unknown_token_round_trips() {
        let purpose = test_decode::<SecPurpose>(&["preview;prerender"]).unwrap();
        assert_eq!(purpose.kind(), &SecPurposeKind::Unknown("preview".into()));
        assert!(purpose.is_prerender());
        assert_eq!(test_encode(purpose)["sec-purpose"], "preview;prerender");
    }

    #[test]
    fn the_first_prefetch_member_counts() {
        let decode = |lines: &[&str]| test_decode::<SecPurpose>(lines);
        assert_eq!(
            decode(&["prefetch;prerender, prefetch;anonymous-client-ip"]),
            Some(SecPurpose::prerender())
        );
        // Lines combine as a List, so the first line wins.
        assert_eq!(
            decode(&["prefetch", "prefetch;prerender"]),
            Some(SecPurpose::prefetch())
        );
        assert_eq!(
            decode(&["prefetch;prerender", "prefetch"]),
            Some(SecPurpose::prerender())
        );
        // A `prefetch` member need not be first; other members' parameters are not its own.
        for lines in [
            &["preview;anonymous-client-ip, prefetch;prerender"][..],
            &["(a b);prerender=?0, prefetch;prerender"],
            &["1, prefetch;prerender"],
            &["preview", "prefetch;prerender"],
        ] {
            assert_eq!(decode(lines), Some(SecPurpose::prerender()), "{lines:?}");
        }
        // Without one, a leading token is kept, with its own parameters.
        assert_eq!(
            decode(&["preview;prerender, other;anonymous-client-ip"]),
            Some(SecPurpose::new(SecPurposeKind::Unknown("preview".into())).with_prerender(true))
        );
        // Later members must still be valid List syntax.
        assert_eq!(decode(&["prefetch", "\"x"]), None);
        assert_eq!(
            decode(&["prefetch", "(a b);x=1"]),
            Some(SecPurpose::prefetch())
        );
    }

    #[test]
    fn prefetch_matches_case_sensitively() {
        for raw in ["PREFETCH;prerender", "Prefetch;prerender"] {
            let purpose = test_decode::<SecPurpose>(&[raw]).unwrap();
            assert_eq!(purpose.kind(), &SecPurposeKind::Unknown(raw[..8].into()));
            assert!(!purpose.is_prefetch());
            assert!(purpose.is_prerender());
            assert_eq!(test_encode(purpose)["sec-purpose"], raw);
        }
        // An exact `prefetch` later in the List still counts.
        assert_eq!(
            test_decode::<SecPurpose>(&["PREFETCH, prefetch"]),
            Some(SecPurpose::prefetch())
        );
    }

    #[test]
    fn lines_combine_like_their_joined_value() {
        for lines in [
            &["prefetch", "prefetch;prerender"][..],
            &["preview", "prefetch"],
            &["", "prefetch"],
            &[" ", "prefetch"],
            &["prefetch", ""],
            &["prefetch", "", "prefetch"],
        ] {
            assert_eq!(
                test_decode::<SecPurpose>(lines),
                test_decode::<SecPurpose>(&[&lines.join(", ")]),
                "{lines:?}"
            );
        }
    }

    #[test]
    fn rejects_garbage() {
        for raw in [
            "",
            "   ",
            "\"prefetch\"",
            "1",
            "?1",
            "(prefetch)",
            ":cHJlZmV0Y2g=:",
            "prefetch,",
            ",prefetch",
            "prefetch;",
            "prefetch;PRERENDER",
            "prefetch;prerender=",
            "pre fetch",
            "pre\"fetch",
        ] {
            assert_eq!(test_decode::<SecPurpose>(&[raw]), None, "{raw:?}");
            assert!(raw.parse::<SecPurpose>().is_err(), "{raw:?}");
        }
        // Without a `prefetch` member, a first member that is not a token is invalid.
        for lines in [&["1", "preview"][..], &["(preview)", "preview"]] {
            assert_eq!(test_decode::<SecPurpose>(lines), None, "{lines:?}");
        }
        // Combining an empty line leaves a stray comma: not a List.
        for lines in [&["", "prefetch"][..], &["prefetch", ""], &[" ", "prefetch"]] {
            assert_eq!(test_decode::<SecPurpose>(lines), None, "{lines:?}");
        }
    }

    #[test]
    fn standalone_kind_keeps_its_case() {
        use serde::{Deserialize, de::IntoDeserializer, de::value::Error as DeError};

        let kind: SecPurposeKind = "PREFETCH".parse().unwrap();
        assert_eq!(kind, SecPurposeKind::Unknown("PREFETCH".into()));
        assert_eq!(SecPurposeKind::from("PREFETCH".to_owned()), kind);
        assert_eq!(kind.to_string().parse::<SecPurposeKind>().unwrap(), kind);
        let deserialized: Result<SecPurposeKind, DeError> =
            SecPurposeKind::deserialize("PREFETCH".into_deserializer());
        assert_eq!(deserialized.unwrap(), kind);
        assert!(!SecPurpose::new(kind).is_prefetch());
    }

    #[test]
    fn unknown_kind_encodes_as_is() {
        // Like the Sec-Fetch tokens: an unknown value is sent as given, even if not a token.
        let purpose = SecPurpose::new(SecPurposeKind::Unknown("not a token".into()));
        assert_eq!(test_encode(purpose)["sec-purpose"], "not a token");
    }

    #[test]
    fn deserializes_the_wire_form() {
        use serde::{Deserialize, de::IntoDeserializer, de::value::Error as DeError};

        let decode = |s: &str| -> Result<SecPurpose, DeError> {
            SecPurpose::deserialize(s.into_deserializer())
        };
        assert_eq!(
            decode("prefetch;prerender;anonymous-client-ip").unwrap(),
            SecPurpose::prerender().with_anonymous_client_ip(true)
        );
        decode("1").unwrap_err();
    }
}
