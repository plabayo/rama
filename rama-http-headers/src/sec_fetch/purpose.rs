use std::{fmt, str::FromStr};

use rama_http_types::{
    HeaderName, HeaderValue,
    structured_fields::{BareItem, ListEvent, ListMember, parse_item, parse_list},
};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

rama_utils::macros::enums::enum_builder! {
    /// The purpose token that opens a [`SecPurpose`] header.
    ///
    /// # Example values
    ///
    /// * `prefetch`
    @String
    pub enum SecPurposeKind {
        /// A speculative fetch: a prefetch, or a prerender when [`SecPurpose`]
        /// carries the `prerender` parameter.
        Prefetch => "prefetch",
    }
}

/// The `Sec-Purpose` [request header][mdn].
///
/// Sent by browsers on a speculative request: something fetched before the
/// user asked for it. The header is a Structured Field List (RFC 9651) whose
/// first member is the token `prefetch`, optionally with parameters:
///
/// * `prefetch`: `<link rel=prefetch>` or a speculation-rules prefetch.
/// * `prefetch;prerender`: a speculation-rules prerender, or one the browser
///   started itself (e.g. from the address bar).
/// * `prefetch;anonymous-client-ip`: a prefetch sent through a private
///   prefetch proxy, hiding the client's IP address.
///
/// Unknown parameters are ignored and an unknown first token is kept as
/// [`SecPurposeKind::Unknown`]. Several field lines combine into one List,
/// of which only the first member is read; a first member that is not a
/// token, or no member at all, is invalid.
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
        let mut purpose: Option<Self> = None;
        let mut seen_member = false;
        // Whether the parameters being reported belong to the first member.
        let mut in_first = false;
        let mut invalid = false;
        parse_list(input, |event| match event {
            ListEvent::Member(member) => {
                in_first = !seen_member;
                seen_member = true;
                if in_first {
                    match member {
                        ListMember::Item(BareItem::Token(token)) => {
                            purpose = Some(Self::new(token.into()));
                        }
                        _ => invalid = true,
                    }
                }
            }
            ListEvent::Parameter { key, value } => {
                if in_first && let Some(purpose) = purpose.as_mut() {
                    // Parameters are a map: a repeated key overrides the earlier one.
                    let set = value == BareItem::Boolean(true);
                    match key {
                        "prerender" => purpose.prerender = set,
                        "anonymous-client-ip" => purpose.anonymous_client_ip = set,
                        _ => {}
                    }
                }
            }
        })
        .map_err(|_error| Error::invalid())?;
        if invalid {
            return Err(Error::invalid());
        }
        purpose.ok_or_else(Error::invalid)
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
        // A List: several field lines combine into one (RFC 9651 §4.2).
        let mut combined = Vec::new();
        for value in values {
            if !combined.is_empty() {
                combined.extend_from_slice(b", ");
            }
            combined.extend_from_slice(value.as_bytes());
        }
        Self::parse(&combined)
    }
}

impl HeaderEncode for SecPurpose {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        // A hand-built unknown kind may not be a token; send nothing rather than garbage.
        if !matches!(
            parse_item(self.kind.as_str().as_bytes()),
            Ok(BareItem::Token(_))
        ) {
            return;
        }
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
        // Only `?1` sets a flag; the last repetition of a key wins.
        assert_eq!(
            decode("prefetch;prerender=?0"),
            Some(SecPurpose::prefetch())
        );
        assert_eq!(decode("prefetch;prerender=1"), Some(SecPurpose::prefetch()));
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
    fn only_the_first_member_counts() {
        assert_eq!(
            test_decode::<SecPurpose>(&["prefetch;prerender, prefetch;anonymous-client-ip"]),
            Some(SecPurpose::prerender())
        );
        // Lines combine as a List, so the first line wins.
        assert_eq!(
            test_decode::<SecPurpose>(&["prefetch", "prefetch;prerender"]),
            Some(SecPurpose::prefetch())
        );
        assert_eq!(
            test_decode::<SecPurpose>(&["prefetch;prerender", "prefetch"]),
            Some(SecPurpose::prerender())
        );
        // Later members must still be valid List syntax.
        assert_eq!(test_decode::<SecPurpose>(&["prefetch", "\"x"]), None);
        assert_eq!(
            test_decode::<SecPurpose>(&["prefetch", "(a b);x=1"]),
            Some(SecPurpose::prefetch())
        );
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
        // A non-token first member is invalid even before a valid one.
        assert_eq!(test_decode::<SecPurpose>(&["1", "prefetch"]), None);
        // An empty line is an empty List, adding no member.
        assert_eq!(
            test_decode::<SecPurpose>(&["", "prefetch"]),
            Some(SecPurpose::prefetch())
        );
    }

    #[test]
    fn unencodable_kind_encodes_nothing() {
        let purpose = SecPurpose::new(SecPurposeKind::Unknown("not a token".into()));
        assert_eq!(purpose.encode_to_value(), None);
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
