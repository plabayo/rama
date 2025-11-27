use rama_http_types::HeaderName;

derive_non_empty_flat_csv_header! {
    #[header(name = ACCESS_CONTROL_EXPOSE_HEADERS, sep = Comma)]
    #[derive(Clone, Debug)]
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
    /// use rama_utils::collections::non_empty_vec;
    /// use rama_http_types::header::{CONTENT_LENGTH, ETAG};
    /// use rama_http_headers::AccessControlExposeHeaders;
    ///
    /// let expose = AccessControlExposeHeaders(
    ///     non_empty_vec![CONTENT_LENGTH, ETAG],
    /// );
    /// # }
    /// ```
    pub struct AccessControlExposeHeaders(pub NonEmptyVec<HeaderName>);
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn decode_header_single() {
        let AccessControlExposeHeaders(allow_headers) = test_decode(&["foo, bar"]).unwrap();

        assert_eq!(allow_headers.len(), 2);
        assert_eq!(allow_headers[0], "foo");
        assert_eq!(allow_headers[1], "bar");
    }

    #[test]
    fn decode_header_multi() {
        let AccessControlExposeHeaders(allow_headers) = test_decode(&["foo, bar", "baz"]).unwrap();

        assert_eq!(allow_headers.len(), 3);
        assert_eq!(allow_headers[0], "foo");
        assert_eq!(allow_headers[1], "bar");
        assert_eq!(allow_headers[2], "baz");
    }

    #[test]
    fn encode() {
        let allow = AccessControlExposeHeaders(non_empty_vec![
            ::rama_http_types::header::CACHE_CONTROL,
            ::rama_http_types::header::IF_RANGE,
        ]);

        let headers = test_encode(allow);
        assert_eq!(
            headers["access-control-expose-headers"],
            "cache-control, if-range"
        );
    }

    #[test]
    fn decode_with_empty_header_value() {
        assert!(test_decode::<AccessControlExposeHeaders>(&[""]).is_none());
    }

    #[test]
    fn decode_with_no_headers() {
        assert!(test_decode::<AccessControlExposeHeaders>(&[]).is_none());
    }

    #[test]
    fn decode_with_invalid_value_str() {
        assert!(test_decode::<AccessControlExposeHeaders>(&["foo foo, bar"]).is_none());
    }
}
