use std::iter::FromIterator;

use rama_http_types::{HeaderName, HeaderValue};

use crate::util::FlatCsv;

/// `Access-Control-Expose-Headers` header, part of
/// [CORS](http://www.w3.org/TR/cors/#access-control-expose-headers-response-header)
///
/// The Access-Control-Expose-Headers header indicates which headers are safe to expose to the
/// API of a CORS API specification.
///
/// # ABNF
///
/// ```text
/// Access-Control-Expose-Headers = "Access-Control-Expose-Headers" ":" #field-name
/// ```
///
/// # Example values
/// * `ETag, Content-Length`
///
/// # Examples
///
/// ```
/// # fn main() {
/// use rama_http_types::header::{CONTENT_LENGTH, ETAG};
/// use rama_http_headers::AccessControlExposeHeaders;
///
/// let expose = vec![CONTENT_LENGTH, ETAG]
///     .into_iter()
///     .collect::<AccessControlExposeHeaders>();
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct AccessControlExposeHeaders(FlatCsv);

derive_header! {
    AccessControlExposeHeaders(_),
    name: ACCESS_CONTROL_EXPOSE_HEADERS
}

impl AccessControlExposeHeaders {
    /// Returns an iterator over `HeaderName`s contained within.
    pub fn iter(&self) -> impl Iterator<Item = HeaderName> + '_ {
        self.0.iter().filter_map(|s| s.parse().ok())
    }
}

impl FromIterator<HeaderName> for AccessControlExposeHeaders {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = HeaderName>,
    {
        let flat = iter.into_iter().map(HeaderValue::from).collect();
        Self(flat)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;

    #[test]
    fn iter() {
        let expose_headers = test_decode::<AccessControlExposeHeaders>(&["foo, bar"]).unwrap();

        let as_vec = expose_headers.iter().collect::<Vec<_>>();
        assert_eq!(as_vec.len(), 2);
        assert_eq!(as_vec[0], "foo");
        assert_eq!(as_vec[1], "bar");
    }

    #[test]
    fn from_iter() {
        let expose: AccessControlExposeHeaders = vec![
            ::rama_http_types::header::CACHE_CONTROL,
            ::rama_http_types::header::IF_RANGE,
        ]
        .into_iter()
        .collect();

        let headers = test_encode(expose);
        assert_eq!(
            headers["access-control-expose-headers"],
            "cache-control, if-range"
        );
    }
}
