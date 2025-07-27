use rama_http_types::HeaderValue;

use crate::Error;
use crate::util::TryFromValues;

/// `Referrer-Policy` header, part of
/// [Referrer Policy](https://www.w3.org/TR/referrer-policy/#referrer-policy-header)
///
/// The `Referrer-Policy` HTTP header specifies the referrer
/// policy that the user agent applies when determining what
/// referrer information should be included with requests made,
/// and with browsing contexts created from the context of the
/// protected resource.
///
/// # ABNF
///
/// ```text
/// Referrer-Policy: 1#policy-token
/// policy-token   = "no-referrer" / "no-referrer-when-downgrade"
///                  / "same-origin" / "origin"
///                  / "origin-when-cross-origin" / "unsafe-url"
/// ```
///
/// # Example values
///
/// * `no-referrer`
///
/// # Example
///
/// ```
/// use rama_http_headers::ReferrerPolicy;
///
/// let rp = ReferrerPolicy::NO_REFERRER;
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReferrerPolicy(Policy);

derive_header! {
    ReferrerPolicy(_),
    name: REFERRER_POLICY
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
    pub const NO_REFERRER: Self = Self(Policy::NoReferrer);

    /// `no-referrer-when-downgrade`
    pub const NO_REFERRER_WHEN_DOWNGRADE: Self = Self(Policy::NoReferrerWhenDowngrade);

    /// `same-origin`
    pub const SAME_ORIGIN: Self = Self(Policy::SameOrigin);

    /// `origin`
    pub const ORIGIN: Self = Self(Policy::Origin);

    /// `origin-when-cross-origin`
    pub const ORIGIN_WHEN_CROSS_ORIGIN: Self = Self(Policy::OriginWhenCrossOrigin);

    /// `unsafe-url`
    pub const UNSAFE_URL: Self = Self(Policy::UnsafeUrl);

    /// `strict-origin`
    pub const STRICT_ORIGIN: Self = Self(Policy::StrictOrigin);

    ///`strict-origin-when-cross-origin`
    pub const STRICT_ORIGIN_WHEN_CROSS_ORIGIN: Self = Self(Policy::StrictOriginWhenCrossOrigin);
}

impl TryFromValues for Policy {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        // See https://www.w3.org/TR/referrer-policy/#determine-policy-for-token
        // tl;dr - Pick *last* known policy in the list
        let mut known = None;
        for s in csv(values) {
            known = Some(match s {
                "no-referrer" | "never" => Self::NoReferrer,
                "no-referrer-when-downgrade" | "default" => Self::NoReferrerWhenDowngrade,
                "same-origin" => Self::SameOrigin,
                "origin" => Self::Origin,
                "origin-when-cross-origin" => Self::OriginWhenCrossOrigin,
                "strict-origin" => Self::StrictOrigin,
                "strict-origin-when-cross-origin" => Self::StrictOriginWhenCrossOrigin,
                "unsafe-url" | "always" => Self::UnsafeUrl,
                _ => continue,
            });
        }

        known.ok_or_else(Error::invalid)
    }
}

impl<'a> From<&'a Policy> for HeaderValue {
    fn from(policy: &'a Policy) -> Self {
        Self::from_static(match *policy {
            Policy::NoReferrer => "no-referrer",
            Policy::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            Policy::SameOrigin => "same-origin",
            Policy::Origin => "origin",
            Policy::OriginWhenCrossOrigin => "origin-when-cross-origin",
            Policy::StrictOrigin => "strict-origin",
            Policy::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            Policy::UnsafeUrl => "unsafe-url",
        })
    }
}

fn csv<'i, I>(values: I) -> impl Iterator<Item = &'i str>
where
    I: Iterator<Item = &'i HeaderValue>,
{
    values.flat_map(|value| {
        value.to_str().into_iter().flat_map(|string| {
            string.split(',').filter_map(|x| match x.trim() {
                "" => None,
                y => Some(y),
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_decode;
    use super::ReferrerPolicy;

    #[test]
    fn decode_as_last_policy() {
        assert_eq!(
            test_decode::<ReferrerPolicy>(&["same-origin, origin"]),
            Some(ReferrerPolicy::ORIGIN),
        );

        assert_eq!(
            test_decode::<ReferrerPolicy>(&["origin", "same-origin"]),
            Some(ReferrerPolicy::SAME_ORIGIN),
        );
    }

    #[test]
    fn decode_as_last_known() {
        assert_eq!(
            test_decode::<ReferrerPolicy>(&["origin, nope, nope, nope"]),
            Some(ReferrerPolicy::ORIGIN),
        );

        assert_eq!(
            test_decode::<ReferrerPolicy>(&["nope, origin, nope, nope"]),
            Some(ReferrerPolicy::ORIGIN),
        );

        assert_eq!(
            test_decode::<ReferrerPolicy>(&["nope, origin", "nope, nope"]),
            Some(ReferrerPolicy::ORIGIN),
        );

        assert_eq!(
            test_decode::<ReferrerPolicy>(&["nope", "origin", "nope, nope"]),
            Some(ReferrerPolicy::ORIGIN),
        );
    }

    #[test]
    fn decode_unknown() {
        assert_eq!(test_decode::<ReferrerPolicy>(&["nope"]), None,);
    }

    #[test]
    fn matching() {
        let rp = ReferrerPolicy::ORIGIN;

        match rp {
            ReferrerPolicy::ORIGIN => (),
            _ => panic!("matched wrong"),
        }
    }
}
