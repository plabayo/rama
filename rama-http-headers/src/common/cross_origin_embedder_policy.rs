//! `Cross-Origin-Embedder-Policy` (COEP) and its report-only sibling.
//!
//! Per the [HTML Standard § COEP](https://html.spec.whatwg.org/multipage/browsers.html#coep).
//! Both types share their payload (token + optional `report-to`
//! parameter); only the header name differs.

use std::borrow::Cow;
use std::fmt;

use rama_http_types::{HeaderName, HeaderValue};
use rama_utils::macros::enums::enum_builder;

use crate::util::{self, IterExt};
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

use super::cross_origin_policy_util::{
    SingleTokenWithReportTo, format_single_token_with_report_to, parse_single_token_with_report_to,
};

enum_builder! {
    /// Embedder-policy token values per the HTML Standard.
    ///
    /// The auto-generated [`Unknown`](Self::Unknown) variant is
    /// reachable only via direct construction; the COEP decoder uses
    /// strict parsing and rejects any token outside the spec set.
    @String
    pub enum CrossOriginEmbedderPolicyValue {
        /// `unsafe-none` — the spec default when the header is absent.
        ///
        /// Sending this explicitly is distinguishable on the wire from
        /// absence; both produce the same browser behaviour.
        UnsafeNone => "unsafe-none",
        /// `require-corp` — same-origin policy, requires every loaded
        /// resource to opt in via a `Cross-Origin-Resource-Policy`
        /// header or CORS.
        RequireCorp => "require-corp",
        /// `credentialless` — like `require-corp` but allows
        /// no-credential loads as a relaxation.
        Credentialless => "credentialless",
    }
}

/// `Cross-Origin-Embedder-Policy` (COEP) header.
///
/// Send `require-corp` or `credentialless` to opt the document into
/// process isolation suitable for using `SharedArrayBuffer` and other
/// cross-origin-isolated capabilities.
///
/// The optional `report-to` parameter names a [Reporting API endpoint]
/// (defined in the `Reporting-Endpoints` header) where the browser
/// posts violation reports.
///
/// [Reporting API endpoint]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Reporting-Endpoints
///
/// # Default semantics
///
/// When the header is absent the user agent applies `unsafe-none`
/// (effectively: no embedder-policy enforcement). The
/// [`UnsafeNone`](CrossOriginEmbedderPolicyValue::UnsafeNone) variant
/// represents the header being *present* with that explicit value —
/// both produce the same browser behaviour but the presence is
/// distinguishable on the wire.
///
/// # Example
///
/// ```
/// use rama_http_headers::{CrossOriginEmbedderPolicy, CrossOriginEmbedderPolicyValue};
///
/// let coep = CrossOriginEmbedderPolicy {
///     value: CrossOriginEmbedderPolicyValue::RequireCorp,
///     report_to: Some("coep-endpoint".into()),
/// };
/// assert_eq!(coep.to_string(), r#"require-corp; report-to="coep-endpoint""#);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CrossOriginEmbedderPolicy {
    pub value: CrossOriginEmbedderPolicyValue,
    /// `; report-to="<endpoint>"` — endpoint name defined in the
    /// `Reporting-Endpoints` header. Always emitted as a quoted
    /// sf-string per RFC 8941.
    pub report_to: Option<Cow<'static, str>>,
}

impl CrossOriginEmbedderPolicy {
    /// Builder shortcut: `unsafe-none`, no `report-to`.
    #[must_use]
    pub fn unsafe_none() -> Self {
        Self {
            value: CrossOriginEmbedderPolicyValue::UnsafeNone,
            report_to: None,
        }
    }

    /// Builder shortcut: `require-corp`, no `report-to`.
    #[must_use]
    pub fn require_corp() -> Self {
        Self {
            value: CrossOriginEmbedderPolicyValue::RequireCorp,
            report_to: None,
        }
    }

    /// Builder shortcut: `credentialless`, no `report-to`.
    #[must_use]
    pub fn credentialless() -> Self {
        Self {
            value: CrossOriginEmbedderPolicyValue::Credentialless,
            report_to: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn report_to(mut self, endpoint: impl Into<Cow<'static, str>>) -> Self {
            self.report_to = Some(endpoint.into());
            self
        }
    }
}

impl fmt::Display for CrossOriginEmbedderPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_single_token_with_report_to(f, self.value.as_str(), self.report_to.as_deref())
    }
}

impl TypedHeader for CrossOriginEmbedderPolicy {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::CROSS_ORIGIN_EMBEDDER_POLICY
    }
}

impl HeaderDecode for CrossOriginEmbedderPolicy {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let raw = values
            .just_one()
            .and_then(|v| v.to_str().ok())
            .ok_or_else(Error::invalid)?;
        let SingleTokenWithReportTo { token, report_to } =
            parse_single_token_with_report_to(raw).ok_or_else(Error::invalid)?;
        let value =
            CrossOriginEmbedderPolicyValue::strict_parse(token).ok_or_else(Error::invalid)?;
        Ok(Self { value, report_to })
    }
}

impl HeaderEncode for CrossOriginEmbedderPolicy {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once(util::fmt(self)));
    }
}

/// `Cross-Origin-Embedder-Policy-Report-Only` — same payload as
/// [`CrossOriginEmbedderPolicy`], reports violations without enforcing
/// the policy.
///
/// Use this to roll out a new embedder policy without breaking the page
/// for users, then promote to the enforcing header once the report
/// volume is acceptable.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CrossOriginEmbedderPolicyReportOnly {
    pub value: CrossOriginEmbedderPolicyValue,
    pub report_to: Option<Cow<'static, str>>,
}

impl CrossOriginEmbedderPolicyReportOnly {
    /// Convert an enforcing [`CrossOriginEmbedderPolicy`] to its
    /// report-only sibling, mirroring the payload.
    #[must_use]
    pub fn from_enforcing(p: CrossOriginEmbedderPolicy) -> Self {
        Self {
            value: p.value,
            report_to: p.report_to,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn report_to(mut self, endpoint: impl Into<Cow<'static, str>>) -> Self {
            self.report_to = Some(endpoint.into());
            self
        }
    }
}

impl fmt::Display for CrossOriginEmbedderPolicyReportOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_single_token_with_report_to(f, self.value.as_str(), self.report_to.as_deref())
    }
}

impl TypedHeader for CrossOriginEmbedderPolicyReportOnly {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY
    }
}

impl HeaderDecode for CrossOriginEmbedderPolicyReportOnly {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let raw = values
            .just_one()
            .and_then(|v| v.to_str().ok())
            .ok_or_else(Error::invalid)?;
        let SingleTokenWithReportTo { token, report_to } =
            parse_single_token_with_report_to(raw).ok_or_else(Error::invalid)?;
        let value =
            CrossOriginEmbedderPolicyValue::strict_parse(token).ok_or_else(Error::invalid)?;
        Ok(Self { value, report_to })
    }
}

impl HeaderEncode for CrossOriginEmbedderPolicyReportOnly {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once(util::fmt(self)));
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;

    #[test]
    fn round_trip_each_variant_no_report_to() {
        for variant in [
            CrossOriginEmbedderPolicyValue::UnsafeNone,
            CrossOriginEmbedderPolicyValue::RequireCorp,
            CrossOriginEmbedderPolicyValue::Credentialless,
        ] {
            let expected_str = variant.as_str().to_owned();
            let v = CrossOriginEmbedderPolicy {
                value: variant,
                report_to: None,
            };
            let map = test_encode(v.clone());
            let raw = map
                .get(CrossOriginEmbedderPolicy::name())
                .expect("set")
                .to_str()
                .unwrap()
                .to_owned();
            assert_eq!(raw, expected_str);
            let parsed = test_decode::<CrossOriginEmbedderPolicy>(&[raw.as_str()]).expect("decode");
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn round_trip_with_report_to() {
        let v = CrossOriginEmbedderPolicy::require_corp().with_report_to("coep-endpoint");
        let map = test_encode(v.clone());
        let raw = map
            .get(CrossOriginEmbedderPolicy::name())
            .expect("set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, r#"require-corp; report-to="coep-endpoint""#);
        let parsed = test_decode::<CrossOriginEmbedderPolicy>(&[raw.as_str()]).expect("decode");
        assert_eq!(parsed, v);
    }

    #[test]
    fn parser_case_insensitive_token() {
        assert_eq!(
            test_decode::<CrossOriginEmbedderPolicy>(&["Require-Corp"]),
            Some(CrossOriginEmbedderPolicy::require_corp()),
        );
    }

    #[test]
    fn parser_rejects_unknown_token() {
        assert!(test_decode::<CrossOriginEmbedderPolicy>(&["nope"]).is_none());
    }

    #[test]
    fn parser_accepts_unquoted_report_to() {
        let parsed =
            test_decode::<CrossOriginEmbedderPolicy>(&["require-corp; report-to=coep-endpoint"])
                .expect("decode unquoted");
        assert_eq!(
            parsed,
            CrossOriginEmbedderPolicy::require_corp().with_report_to("coep-endpoint"),
        );
    }

    #[test]
    fn report_only_round_trip() {
        let v = CrossOriginEmbedderPolicyReportOnly {
            value: CrossOriginEmbedderPolicyValue::RequireCorp,
            report_to: Some("ep".into()),
        };
        let map = test_encode(v.clone());
        let raw = map
            .get(CrossOriginEmbedderPolicyReportOnly::name())
            .expect("set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, r#"require-corp; report-to="ep""#);
        let parsed =
            test_decode::<CrossOriginEmbedderPolicyReportOnly>(&[raw.as_str()]).expect("decode");
        assert_eq!(parsed, v);
    }

    #[test]
    fn enforcing_and_report_only_use_distinct_header_names() {
        assert_ne!(
            CrossOriginEmbedderPolicy::name(),
            CrossOriginEmbedderPolicyReportOnly::name(),
        );
    }
}
