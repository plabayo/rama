//! `Cross-Origin-Opener-Policy` (COOP) and its report-only sibling.
//!
//! Per the [HTML Standard § the-coop-headers](https://html.spec.whatwg.org/multipage/browsers.html#the-coop-headers).

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
    /// Opener-policy token values per the HTML Standard.
    ///
    /// Per [HTML § the-coop-headers](https://html.spec.whatwg.org/multipage/browsers.html#the-coop-headers),
    /// these are the four token values a `Cross-Origin-Opener-Policy`
    /// header may carry. The spec explicitly excludes
    /// `same-origin-plus-COEP` from the valid wire values — that token
    /// is the *computed* opener policy assigned when a `same-origin`
    /// COOP is combined with a cross-origin-isolating COEP, and the
    /// COOP header parser rejects it. It's intentionally not modelled
    /// here.
    ///
    /// The auto-generated [`Unknown`](Self::Unknown) variant is
    /// reachable only via direct construction; the COOP decoder uses
    /// strict parsing and rejects any token outside the spec set.
    @String
    pub enum CrossOriginOpenerPolicyValue {
        /// `unsafe-none` — the spec default when the header is absent.
        UnsafeNone => "unsafe-none",
        /// `same-origin-allow-popups` — same-origin opener
        /// relationships are preserved, popups remain attached.
        SameOriginAllowPopups => "same-origin-allow-popups",
        /// `same-origin` — strict isolation; cross-origin openers are
        /// severed from this window.
        SameOrigin => "same-origin",
        /// `noopener-allow-popups` — added 2024, severs the opener
        /// while still letting popups open.
        NoopenerAllowPopups => "noopener-allow-popups",
    }
}

/// `Cross-Origin-Opener-Policy` (COOP) header.
///
/// Send `same-origin` (paired with a cross-origin-isolating
/// `Cross-Origin-Embedder-Policy`) to opt the document into process
/// isolation. Required for `SharedArrayBuffer` and other cross-origin-
/// isolated capabilities. The browser then internally tracks the
/// combined policy as `same-origin-plus-COEP`, which is *not* itself a
/// header-settable value.
///
/// The optional `report-to` parameter names a [Reporting API endpoint]
/// (defined in the `Reporting-Endpoints` header) where the browser
/// posts violation reports.
///
/// [Reporting API endpoint]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Reporting-Endpoints
///
/// # Default semantics
///
/// When the header is absent the user agent applies `unsafe-none`. The
/// [`UnsafeNone`](CrossOriginOpenerPolicyValue::UnsafeNone) variant
/// represents the header being *present* with that explicit value —
/// both produce the same browser behaviour but the presence is
/// distinguishable on the wire.
///
/// # Example
///
/// ```
/// use rama_http_headers::{CrossOriginOpenerPolicy, CrossOriginOpenerPolicyValue};
///
/// let coop = CrossOriginOpenerPolicy {
///     value: CrossOriginOpenerPolicyValue::SameOrigin,
///     report_to: Some("coop-endpoint".into()),
/// };
/// assert_eq!(coop.to_string(), r#"same-origin; report-to="coop-endpoint""#);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CrossOriginOpenerPolicy {
    pub value: CrossOriginOpenerPolicyValue,
    /// `; report-to="<endpoint>"` — endpoint name defined in the
    /// `Reporting-Endpoints` header. Always emitted as a quoted
    /// sf-string per RFC 8941.
    pub report_to: Option<Cow<'static, str>>,
}

impl CrossOriginOpenerPolicy {
    /// Builder shortcut: `unsafe-none`, no `report-to`.
    #[must_use]
    pub fn unsafe_none() -> Self {
        Self {
            value: CrossOriginOpenerPolicyValue::UnsafeNone,
            report_to: None,
        }
    }

    /// Builder shortcut: `same-origin-allow-popups`, no `report-to`.
    #[must_use]
    pub fn same_origin_allow_popups() -> Self {
        Self {
            value: CrossOriginOpenerPolicyValue::SameOriginAllowPopups,
            report_to: None,
        }
    }

    /// Builder shortcut: `same-origin`, no `report-to`.
    #[must_use]
    pub fn same_origin() -> Self {
        Self {
            value: CrossOriginOpenerPolicyValue::SameOrigin,
            report_to: None,
        }
    }

    /// Builder shortcut: `noopener-allow-popups`, no `report-to`.
    #[must_use]
    pub fn noopener_allow_popups() -> Self {
        Self {
            value: CrossOriginOpenerPolicyValue::NoopenerAllowPopups,
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

impl fmt::Display for CrossOriginOpenerPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_single_token_with_report_to(f, self.value.as_str(), self.report_to.as_deref())
    }
}

impl TypedHeader for CrossOriginOpenerPolicy {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::CROSS_ORIGIN_OPENER_POLICY
    }
}

impl HeaderDecode for CrossOriginOpenerPolicy {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let raw = values
            .just_one()
            .and_then(|v| v.to_str().ok())
            .ok_or_else(Error::invalid)?;
        let SingleTokenWithReportTo { token, report_to } =
            parse_single_token_with_report_to(raw).ok_or_else(Error::invalid)?;
        let value = CrossOriginOpenerPolicyValue::strict_parse(token).ok_or_else(Error::invalid)?;
        Ok(Self { value, report_to })
    }
}

impl HeaderEncode for CrossOriginOpenerPolicy {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once(util::fmt(self)));
    }
}

/// `Cross-Origin-Opener-Policy-Report-Only` — same payload as
/// [`CrossOriginOpenerPolicy`], reports violations without enforcing
/// the policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CrossOriginOpenerPolicyReportOnly {
    pub value: CrossOriginOpenerPolicyValue,
    pub report_to: Option<Cow<'static, str>>,
}

impl CrossOriginOpenerPolicyReportOnly {
    /// Convert an enforcing [`CrossOriginOpenerPolicy`] to its
    /// report-only sibling, mirroring the payload.
    #[must_use]
    pub fn from_enforcing(p: CrossOriginOpenerPolicy) -> Self {
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

impl fmt::Display for CrossOriginOpenerPolicyReportOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_single_token_with_report_to(f, self.value.as_str(), self.report_to.as_deref())
    }
}

impl TypedHeader for CrossOriginOpenerPolicyReportOnly {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY
    }
}

impl HeaderDecode for CrossOriginOpenerPolicyReportOnly {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let raw = values
            .just_one()
            .and_then(|v| v.to_str().ok())
            .ok_or_else(Error::invalid)?;
        let SingleTokenWithReportTo { token, report_to } =
            parse_single_token_with_report_to(raw).ok_or_else(Error::invalid)?;
        let value = CrossOriginOpenerPolicyValue::strict_parse(token).ok_or_else(Error::invalid)?;
        Ok(Self { value, report_to })
    }
}

impl HeaderEncode for CrossOriginOpenerPolicyReportOnly {
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
            CrossOriginOpenerPolicyValue::UnsafeNone,
            CrossOriginOpenerPolicyValue::SameOriginAllowPopups,
            CrossOriginOpenerPolicyValue::SameOrigin,
            CrossOriginOpenerPolicyValue::NoopenerAllowPopups,
        ] {
            let expected_str = variant.as_str().to_owned();
            let v = CrossOriginOpenerPolicy {
                value: variant,
                report_to: None,
            };
            let map = test_encode(v.clone());
            let raw = map
                .get(CrossOriginOpenerPolicy::name())
                .expect("set")
                .to_str()
                .unwrap()
                .to_owned();
            assert_eq!(raw, expected_str);
            let parsed = test_decode::<CrossOriginOpenerPolicy>(&[raw.as_str()]).expect("decode");
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn round_trip_with_report_to() {
        let v = CrossOriginOpenerPolicy::same_origin().with_report_to("coop-endpoint");
        let map = test_encode(v.clone());
        let raw = map
            .get(CrossOriginOpenerPolicy::name())
            .expect("set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, r#"same-origin; report-to="coop-endpoint""#);
        let parsed = test_decode::<CrossOriginOpenerPolicy>(&[raw.as_str()]).expect("decode");
        assert_eq!(parsed, v);
    }

    #[test]
    fn parser_rejects_same_origin_plus_coep_per_spec() {
        // The HTML Standard explicitly excludes `same-origin-plus-COEP`
        // from valid wire values for the COOP header — it's an
        // *effective* policy the user agent computes when a
        // `same-origin` COOP is paired with a cross-origin-isolating
        // COEP, not a value the server can set directly. The COOP
        // parser must reject it.
        assert!(test_decode::<CrossOriginOpenerPolicy>(&["same-origin-plus-COEP"]).is_none());
        assert!(test_decode::<CrossOriginOpenerPolicy>(&["same-origin-plus-coep"]).is_none());
    }

    #[test]
    fn parser_accepts_noopener_allow_popups() {
        // Added 2024 — make sure the parser handles it.
        let parsed =
            test_decode::<CrossOriginOpenerPolicy>(&["noopener-allow-popups"]).expect("decode");
        assert_eq!(parsed, CrossOriginOpenerPolicy::noopener_allow_popups());
    }

    #[test]
    fn parser_rejects_unknown_token() {
        assert!(test_decode::<CrossOriginOpenerPolicy>(&["nope"]).is_none());
    }

    #[test]
    fn parser_accepts_unquoted_report_to() {
        let parsed =
            test_decode::<CrossOriginOpenerPolicy>(&["same-origin; report-to=coop-endpoint"])
                .expect("decode unquoted");
        assert_eq!(
            parsed,
            CrossOriginOpenerPolicy::same_origin().with_report_to("coop-endpoint"),
        );
    }

    #[test]
    fn parser_ignores_unknown_parameters() {
        let parsed =
            test_decode::<CrossOriginOpenerPolicy>(&["same-origin; foo=bar; report-to=\"ep\""])
                .expect("decode unknown");
        assert_eq!(
            parsed,
            CrossOriginOpenerPolicy::same_origin().with_report_to("ep"),
        );
    }

    #[test]
    fn report_only_round_trip() {
        let v = CrossOriginOpenerPolicyReportOnly {
            value: CrossOriginOpenerPolicyValue::SameOrigin,
            report_to: Some("ep".into()),
        };
        let map = test_encode(v.clone());
        let raw = map
            .get(CrossOriginOpenerPolicyReportOnly::name())
            .expect("set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, r#"same-origin; report-to="ep""#);
        let parsed =
            test_decode::<CrossOriginOpenerPolicyReportOnly>(&[raw.as_str()]).expect("decode");
        assert_eq!(parsed, v);
    }

    #[test]
    fn enforcing_and_report_only_use_distinct_header_names() {
        assert_ne!(
            CrossOriginOpenerPolicy::name(),
            CrossOriginOpenerPolicyReportOnly::name(),
        );
    }
}
