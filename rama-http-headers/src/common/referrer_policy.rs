use std::fmt;

use rama_http_types::{HeaderName, HeaderValue};
use rama_utils::collections::NonEmptySmallVec;
use rama_utils::collections::smallvec::SmallVec;
use rama_utils::macros::generate_set_and_with;

use crate::util::{self};
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `Referrer-Policy` header, part of
/// [Referrer Policy](https://www.w3.org/TR/referrer-policy/#referrer-policy-header)
///
/// The `Referrer-Policy` HTTP header specifies the referrer
/// policy that the user agent applies when determining what
/// referrer information should be included with requests made,
/// and with browsing contexts created from the context of the
/// protected resource.
///
/// # Fallback chains
///
/// Per the [Referrer Policy spec § 3.2](https://www.w3.org/TR/referrer-policy/#parse-referrer-policy-from-header)
/// the wire form is `1#policy-token` — a comma-separated list where the
/// user agent walks RIGHT-TO-LEFT and picks the *last* token it
/// recognises. This lets a server ship a modern policy with a fallback
/// for older clients:
///
/// ```
/// use rama_http_headers::ReferrerPolicy;
///
/// // Emits: `no-referrer, strict-origin-when-cross-origin`.
/// // A pre-CSP3 browser falls back to `no-referrer`; a modern browser
/// // picks `strict-origin-when-cross-origin`.
/// let rp = ReferrerPolicy::NO_REFERRER
///     .with_fallback(ReferrerPolicy::STRICT_ORIGIN_WHEN_CROSS_ORIGIN);
/// ```
///
/// `with_fallback` appends; emitted order is preserved on the wire
/// (oldest-known first → newest-known last).
///
/// # ABNF
///
/// ```text
/// Referrer-Policy: 1#policy-token
/// policy-token   = "no-referrer" / "no-referrer-when-downgrade"
///                  / "same-origin" / "origin"
///                  / "origin-when-cross-origin" / "unsafe-url"
///                  / "strict-origin" / "strict-origin-when-cross-origin"
/// ```
///
/// # Example values
///
/// * `no-referrer`
/// * `no-referrer, strict-origin-when-cross-origin`
///
/// # Example
///
/// ```
/// use rama_http_headers::ReferrerPolicy;
///
/// let rp = ReferrerPolicy::NO_REFERRER;
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReferrerPolicy(NonEmptySmallVec<2, Policy>);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
enum Policy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    SameOrigin,
    Origin,
    OriginWhenCrossOrigin,
    UnsafeUrl,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
}

impl ReferrerPolicy {
    /// `no-referrer`
    pub const NO_REFERRER: Self = Self::single(Policy::NoReferrer);

    /// `no-referrer-when-downgrade`
    pub const NO_REFERRER_WHEN_DOWNGRADE: Self = Self::single(Policy::NoReferrerWhenDowngrade);

    /// `same-origin`
    pub const SAME_ORIGIN: Self = Self::single(Policy::SameOrigin);

    /// `origin`
    pub const ORIGIN: Self = Self::single(Policy::Origin);

    /// `origin-when-cross-origin`
    pub const ORIGIN_WHEN_CROSS_ORIGIN: Self = Self::single(Policy::OriginWhenCrossOrigin);

    /// `unsafe-url`
    pub const UNSAFE_URL: Self = Self::single(Policy::UnsafeUrl);

    /// `strict-origin`
    pub const STRICT_ORIGIN: Self = Self::single(Policy::StrictOrigin);

    ///`strict-origin-when-cross-origin`
    pub const STRICT_ORIGIN_WHEN_CROSS_ORIGIN: Self =
        Self::single(Policy::StrictOriginWhenCrossOrigin);

    const fn single(policy: Policy) -> Self {
        // Tail is inline-allocated up to 2 elements before spilling to
        // the heap, so single-token construction and the common
        // 2-token fallback chain stay heap-free.
        Self(NonEmptySmallVec {
            head: policy,
            tail: SmallVec::new_const(),
        })
    }

    generate_set_and_with! {
        /// Append a fallback policy.
        ///
        /// Multiple calls compound; emitted order is preserved on the
        /// wire (oldest-known first → newest-known last). Browsers
        /// walk right-to-left and select the last token they
        /// recognise, so the *appended* policy is the one a modern
        /// client will pick — call this on your older / pre-CSP3
        /// baseline and pass the modern token you want.
        ///
        /// The argument's full policy list is appended in order (so
        /// chaining preserves any fallback chain it already carried).
        pub fn fallback(mut self, policy: Self) -> Self {
            let (head, tail) = (policy.0.head, policy.0.tail);
            self.0.tail.push(head);
            self.0.tail.extend(tail);
            self
        }
    }
}

impl TypedHeader for ReferrerPolicy {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::REFERRER_POLICY
    }
}

impl HeaderDecode for ReferrerPolicy {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        // Preserve every recognised policy token in declared order so
        // the browser still sees a fallback chain on re-encode. Walk
        // all header values, all comma-separated tokens, and skip
        // anything we don't recognise.
        let mut all: SmallVec<[Policy; 2]> = SmallVec::new();
        let mut any_value = false;
        for value in values {
            any_value = true;
            let s = value.to_str().map_err(|_err| Error::invalid())?;
            for raw in s.split(',') {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Some(p) = Policy::from_token(trimmed) {
                    all.push(p);
                }
            }
        }
        if !any_value {
            return Err(Error::invalid());
        }
        let inner = NonEmptySmallVec::from_smallvec(all).ok_or_else(Error::invalid)?;
        Ok(Self(inner))
    }
}

impl HeaderEncode for ReferrerPolicy {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        struct Adapter<'a>(&'a ReferrerPolicy);

        impl fmt::Display for Adapter<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for (i, p) in self.0.0.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(p.as_str())?;
                }
                Ok(())
            }
        }

        values.extend(::std::iter::once(util::fmt(Adapter(self))));
    }
}

impl Policy {
    fn from_token(s: &str) -> Option<Self> {
        // Tokens are ASCII case-insensitive per spec.
        //
        // The legacy Gecko-only aliases `never` (→ no-referrer),
        // `default` (→ no-referrer-when-downgrade), and `always`
        // (→ unsafe-url) were dropped from the W3C Referrer Policy
        // spec and are intentionally NOT recognised — a server still
        // sending them would have its policy fall through to the user
        // agent default in real browsers.
        Some(match s {
            x if x.eq_ignore_ascii_case("no-referrer") => Self::NoReferrer,
            x if x.eq_ignore_ascii_case("no-referrer-when-downgrade") => {
                Self::NoReferrerWhenDowngrade
            }
            x if x.eq_ignore_ascii_case("same-origin") => Self::SameOrigin,
            x if x.eq_ignore_ascii_case("origin") => Self::Origin,
            x if x.eq_ignore_ascii_case("origin-when-cross-origin") => Self::OriginWhenCrossOrigin,
            x if x.eq_ignore_ascii_case("strict-origin") => Self::StrictOrigin,
            x if x.eq_ignore_ascii_case("strict-origin-when-cross-origin") => {
                Self::StrictOriginWhenCrossOrigin
            }
            x if x.eq_ignore_ascii_case("unsafe-url") => Self::UnsafeUrl,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::NoReferrer => "no-referrer",
            Self::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            Self::SameOrigin => "same-origin",
            Self::Origin => "origin",
            Self::OriginWhenCrossOrigin => "origin-when-cross-origin",
            Self::StrictOrigin => "strict-origin",
            Self::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            Self::UnsafeUrl => "unsafe-url",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::ReferrerPolicy;
    use crate::TypedHeader;

    #[test]
    fn decode_single_token() {
        assert_eq!(
            test_decode::<ReferrerPolicy>(&["origin"]),
            Some(ReferrerPolicy::ORIGIN),
        );
    }

    #[test]
    fn decode_skips_unknown_tokens_when_single_recognised() {
        let chained = test_decode::<ReferrerPolicy>(&["origin, nope, nope, nope"]).unwrap();
        assert_eq!(chained, ReferrerPolicy::ORIGIN);

        let chained = test_decode::<ReferrerPolicy>(&["nope, origin, nope, nope"]).unwrap();
        assert_eq!(chained, ReferrerPolicy::ORIGIN);

        let chained = test_decode::<ReferrerPolicy>(&["nope, origin", "nope, nope"]).unwrap();
        assert_eq!(chained, ReferrerPolicy::ORIGIN);

        let chained = test_decode::<ReferrerPolicy>(&["nope", "origin", "nope, nope"]).unwrap();
        assert_eq!(chained, ReferrerPolicy::ORIGIN);
    }

    #[test]
    fn decode_preserves_multi_token_chain() {
        let parsed =
            test_decode::<ReferrerPolicy>(&["no-referrer, strict-origin-when-cross-origin"])
                .expect("decode");
        let expected = ReferrerPolicy::NO_REFERRER
            .with_fallback(ReferrerPolicy::STRICT_ORIGIN_WHEN_CROSS_ORIGIN);
        assert_eq!(parsed, expected);
    }

    #[test]
    fn decode_unknown() {
        assert_eq!(test_decode::<ReferrerPolicy>(&["nope"]), None);
    }

    #[test]
    fn decode_rejects_dropped_legacy_aliases() {
        // `never`, `default`, `always` were Gecko-only and have been
        // dropped from the W3C spec — the parser must treat them as
        // unknown so the chain falls through to the next valid token.
        for legacy in ["never", "default", "always"] {
            assert!(
                test_decode::<ReferrerPolicy>(&[legacy]).is_none(),
                "legacy alias `{legacy}` should no longer parse",
            );
        }
        // …but a chain containing one alongside a recognised token
        // still works (the alias is just dropped):
        let chained = test_decode::<ReferrerPolicy>(&["never, no-referrer"]).expect("decode");
        assert_eq!(chained, ReferrerPolicy::NO_REFERRER);
    }

    #[test]
    fn decode_empty_returns_error() {
        assert_eq!(test_decode::<ReferrerPolicy>(&[] as &[&str]), None);
    }

    #[test]
    fn matches_via_equality() {
        // Pattern matching against the const constants is no longer
        // possible (the inner SmallVec is non-structural), but
        // `assert_eq!` works the same as before for the common usage
        // pattern.
        let rp = ReferrerPolicy::ORIGIN;
        assert_eq!(rp, ReferrerPolicy::ORIGIN);
        assert_ne!(rp, ReferrerPolicy::NO_REFERRER);
    }

    #[test]
    fn encode_single_token() {
        let map = test_encode(ReferrerPolicy::NO_REFERRER);
        let raw = map
            .get(super::ReferrerPolicy::name())
            .expect("header set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, "no-referrer");
    }

    #[test]
    fn encode_fallback_chain_canonical_order() {
        let rp = ReferrerPolicy::NO_REFERRER
            .with_fallback(ReferrerPolicy::STRICT_ORIGIN_WHEN_CROSS_ORIGIN);
        let map = test_encode(rp);
        let raw = map
            .get(super::ReferrerPolicy::name())
            .expect("header set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, "no-referrer, strict-origin-when-cross-origin");
    }

    #[test]
    fn fallback_chains_compound() {
        let rp = ReferrerPolicy::NO_REFERRER
            .with_fallback(ReferrerPolicy::ORIGIN)
            .with_fallback(ReferrerPolicy::STRICT_ORIGIN_WHEN_CROSS_ORIGIN);
        let map = test_encode(rp);
        let raw = map
            .get(super::ReferrerPolicy::name())
            .expect("header set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, "no-referrer, origin, strict-origin-when-cross-origin");
    }

    #[test]
    fn fallback_preserves_existing_chain() {
        // The argument can itself be a multi-token chain — append it
        // wholesale rather than just the head.
        let inner = ReferrerPolicy::ORIGIN.with_fallback(ReferrerPolicy::STRICT_ORIGIN);
        let outer = ReferrerPolicy::NO_REFERRER.with_fallback(inner);
        let map = test_encode(outer);
        let raw = map
            .get(super::ReferrerPolicy::name())
            .expect("header set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, "no-referrer, origin, strict-origin");
    }

    #[test]
    fn full_round_trip_through_header_map() {
        let original = ReferrerPolicy::NO_REFERRER
            .with_fallback(ReferrerPolicy::STRICT_ORIGIN_WHEN_CROSS_ORIGIN);
        let map = test_encode(original.clone());
        let raw = map
            .get(super::ReferrerPolicy::name())
            .expect("header set")
            .to_str()
            .unwrap()
            .to_owned();
        let parsed = test_decode::<ReferrerPolicy>(&[raw.as_str()]).expect("re-decode");
        assert_eq!(parsed, original);
    }
}
