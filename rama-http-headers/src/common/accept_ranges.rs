use rama_core::telemetry::tracing;
use rama_http_types::HeaderValue;

use crate::util::TryFromValues;

/// `Accept-Ranges` header, defined in [RFC7233](https://datatracker.ietf.org/doc/html/rfc7233#section-2.3)
///
/// Unit list: <https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#range-units>.
///
/// The `Accept-Ranges` header field allows a server to indicate that it
/// supports range requests for the target resource.
///
/// # ABNF
///
/// ```text
/// Accept-Ranges     = acceptable-ranges
/// acceptable-ranges = 1#range-unit / \"none\"
///
/// # Example values
/// * `bytes`
/// * `none`
/// * `unknown-unit`
/// ```
///
/// # Examples
///
/// ```
/// use rama_http_headers::{AcceptRanges, HeaderMapExt};
/// use rama_http_types::HeaderMap;
///
/// let mut headers = HeaderMap::new();
///
/// headers.typed_insert(AcceptRanges::bytes());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptRanges(Unit);

derive_header! {
    AcceptRanges(_),
    name: ACCEPT_RANGES
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    None,
    Bytes,
}

impl From<Unit> for HeaderValue {
    fn from(value: Unit) -> Self {
        match value {
            Unit::None => ACCEPT_RANGES_NONE,
            Unit::Bytes => ACCEPT_RANGES_BYTES,
        }
    }
}

impl From<&Unit> for HeaderValue {
    fn from(value: &Unit) -> Self {
        match value {
            Unit::None => ACCEPT_RANGES_NONE,
            Unit::Bytes => ACCEPT_RANGES_BYTES,
        }
    }
}

impl TryFromValues for Unit {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, crate::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        values
            .next()
            .and_then(|val| {
                let s = val
                    .to_str()
                    .inspect_err(|err| {
                        tracing::trace!("invalid accept-ranges header (unit) value: {err}")
                    })
                    .ok()?
                    .trim();
                if s.eq_ignore_ascii_case("bytes") {
                    Some(Self::Bytes)
                } else if s.eq_ignore_ascii_case("none") {
                    Some(Self::None)
                } else {
                    tracing::trace!("unknown accept-ranges unit value: '{s}'");
                    None
                }
            })
            .ok_or_else(crate::Error::invalid)
    }
}

const ACCEPT_RANGES_NONE: HeaderValue = HeaderValue::from_static("none");
const ACCEPT_RANGES_BYTES: HeaderValue = HeaderValue::from_static("bytes");

impl AcceptRanges {
    /// A constructor to easily create the common `Accept-Ranges: bytes` header.
    #[must_use]
    pub fn bytes() -> Self {
        Self(Unit::Bytes)
    }

    /// Check if the unit is `bytes`.
    #[must_use]
    pub fn is_bytes(&self) -> bool {
        self.0 == Unit::Bytes
    }

    /// A constructor to easily create the common `Accept-Ranges: none` header.
    #[must_use]
    pub fn none() -> Self {
        Self(Unit::None)
    }

    /// Check if the unit is `none`.
    #[must_use]
    pub fn is_none(&self) -> bool {
        self.0 == Unit::None
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_decode;
    use super::*;

    fn accept_ranges(s: &str) -> AcceptRanges {
        test_decode(&[s]).unwrap()
    }

    // bytes
    #[test]
    fn bytes_constructor() {
        assert_eq!(accept_ranges("bytes"), AcceptRanges::bytes());
        assert_eq!(accept_ranges("Bytes"), AcceptRanges::bytes());
        assert_eq!(accept_ranges("BYTES"), AcceptRanges::bytes());
    }

    #[test]
    fn is_bytes_method_successful_with_bytes_ranges() {
        assert!(accept_ranges("bytes").is_bytes());
    }

    #[test]
    fn is_bytes_method_successful_with_bytes_ranges_by_constructor() {
        assert!(AcceptRanges::bytes().is_bytes());
    }

    #[test]
    fn unknown_range_unit_value_failed() {
        assert!(test_decode::<AcceptRanges>(&["dummy"]).is_none());
    }

    // none
    #[test]
    fn none_constructor() {
        assert_eq!(accept_ranges("none"), AcceptRanges::none());
        assert_eq!(accept_ranges("None"), AcceptRanges::none());
        assert_eq!(accept_ranges("NONE"), AcceptRanges::none());
    }

    #[test]
    fn is_none_method_successful_with_none_ranges() {
        assert!(accept_ranges("none").is_none());
    }

    #[test]
    fn is_none_method_successful_with_none_ranges_by_constructor() {
        assert!(AcceptRanges::none().is_none());
    }
}
