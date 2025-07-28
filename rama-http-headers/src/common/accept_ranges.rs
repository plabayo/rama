use rama_http_types::HeaderValue;

use crate::util::FlatCsv;

/// `Accept-Ranges` header, defined in [RFC7233](https://datatracker.ietf.org/doc/html/rfc7233#section-2.3)
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
/// headers.typed_insert(&AcceptRanges::bytes());
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct AcceptRanges(FlatCsv);

derive_header! {
    AcceptRanges(_),
    name: ACCEPT_RANGES
}

const ACCEPT_RANGES_BYTES: &str = "bytes";
const ACCEPT_RANGES_NONE: &str = "none";

impl AcceptRanges {
    /// A constructor to easily create the common `Accept-Ranges: bytes` header.
    #[must_use]
    pub fn bytes() -> Self {
        Self(HeaderValue::from_static(ACCEPT_RANGES_BYTES).into())
    }

    /// Check if the unit is `bytes`.
    pub fn is_bytes(&self) -> bool {
        self.0.value == ACCEPT_RANGES_BYTES
    }

    /// A constructor to easily create the common `Accept-Ranges: none` header.
    #[must_use]
    pub fn none() -> Self {
        Self(HeaderValue::from_static(ACCEPT_RANGES_NONE).into())
    }

    /// Check if the unit is `none`.
    pub fn is_none(&self) -> bool {
        self.0.value == ACCEPT_RANGES_NONE
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
    fn is_bytes_method_failed_with_not_bytes_ranges() {
        assert!(!accept_ranges("dummy").is_bytes());
    }

    // none
    #[test]
    fn none_constructor() {
        assert_eq!(accept_ranges("none"), AcceptRanges::none());
    }

    #[test]
    fn is_none_method_successful_with_none_ranges() {
        assert!(accept_ranges("none").is_none());
    }

    #[test]
    fn is_none_method_successful_with_none_ranges_by_constructor() {
        assert!(AcceptRanges::none().is_none());
    }

    #[test]
    fn is_none_method_failed_with_not_none_ranges() {
        assert!(!accept_ranges("dummy").is_none());
    }
}
