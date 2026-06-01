use rama_http_types::{HeaderName, HeaderValue};
use rama_utils::macros::enums::enum_builder;

use crate::util::{self, IterExt};
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

enum_builder! {
    /// `Cross-Origin-Resource-Policy` (CORP) header, defined by
    /// [Fetch § cross-origin-resource-policy-header](https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header).
    ///
    /// Lets a server opt resources out of being embedded by cross-
    /// origin / cross-site documents. Single token, no parameters, no
    /// report-only variant.
    ///
    /// # Default semantics
    ///
    /// When the header is absent the user agent applies its default
    /// embedding policy (effectively `cross-origin` for legacy
    /// backwards compatibility). The typed value here represents the
    /// header being *present*. The auto-generated
    /// [`Unknown`](Self::Unknown) variant is reachable only if a
    /// caller constructs it directly — the [`HeaderDecode`] impl uses
    /// strict parsing and rejects any unknown token.
    ///
    /// # Example values
    ///
    /// * `same-origin`
    /// * `same-site`
    /// * `cross-origin`
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http_headers::CrossOriginResourcePolicy;
    ///
    /// let corp = CrossOriginResourcePolicy::SameOrigin;
    /// assert_eq!(corp.to_string(), "same-origin");
    /// ```
    @String
    pub enum CrossOriginResourcePolicy {
        /// `same-site` — only documents from the same registrable
        /// site may embed the resource.
        SameSite => "same-site",
        /// `same-origin` — only same-origin documents may embed.
        SameOrigin => "same-origin",
        /// `cross-origin` — any document may embed. Matches the
        /// legacy default but makes the intent explicit on the wire.
        CrossOrigin => "cross-origin",
    }
}

impl TypedHeader for CrossOriginResourcePolicy {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::CROSS_ORIGIN_RESOURCE_POLICY
    }
}

impl HeaderDecode for CrossOriginResourcePolicy {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        // Strict parse: unknown tokens fail rather than landing in
        // `Unknown(...)`. CORP is a closed set per Fetch — anything
        // else on the wire is malformed.
        values
            .just_one()
            .and_then(|v| v.to_str().ok())
            .and_then(|s| Self::strict_parse(s.trim()))
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for CrossOriginResourcePolicy {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once(util::fmt(self)));
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;

    #[test]
    fn round_trip_same_site() {
        let map = test_encode(CrossOriginResourcePolicy::SameSite);
        let raw = map
            .get(CrossOriginResourcePolicy::name())
            .expect("set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, "same-site");
        assert_eq!(
            test_decode::<CrossOriginResourcePolicy>(&[raw.as_str()]),
            Some(CrossOriginResourcePolicy::SameSite),
        );
    }

    #[test]
    fn round_trip_same_origin() {
        assert_eq!(
            test_decode::<CrossOriginResourcePolicy>(&["same-origin"]),
            Some(CrossOriginResourcePolicy::SameOrigin),
        );
    }

    #[test]
    fn round_trip_cross_origin() {
        assert_eq!(
            test_decode::<CrossOriginResourcePolicy>(&["cross-origin"]),
            Some(CrossOriginResourcePolicy::CrossOrigin),
        );
    }

    #[test]
    fn parser_case_insensitive() {
        assert_eq!(
            test_decode::<CrossOriginResourcePolicy>(&["Same-Origin"]),
            Some(CrossOriginResourcePolicy::SameOrigin),
        );
        assert_eq!(
            test_decode::<CrossOriginResourcePolicy>(&["CROSS-ORIGIN"]),
            Some(CrossOriginResourcePolicy::CrossOrigin),
        );
    }

    #[test]
    fn parser_tolerates_surrounding_whitespace() {
        assert_eq!(
            test_decode::<CrossOriginResourcePolicy>(&["  same-origin  "]),
            Some(CrossOriginResourcePolicy::SameOrigin),
        );
    }

    #[test]
    fn parser_rejects_unknown_token() {
        // The auto-generated `Unknown(String)` variant exists, but the
        // decoder uses strict parsing — unknown tokens must fail.
        assert_eq!(test_decode::<CrossOriginResourcePolicy>(&["nope"]), None);
    }

    #[test]
    fn parser_rejects_empty_value() {
        assert_eq!(test_decode::<CrossOriginResourcePolicy>(&[""]), None);
    }
}
