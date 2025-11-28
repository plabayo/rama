use rama_http_types::HeaderName;

derive_non_empty_flat_csv_header! {
    #[header(name = ACCESS_CONTROL_ALLOW_HEADERS, sep = Comma)]
    #[derive(Clone, Debug, PartialEq)]
    /// `Access-Control-Allow-Headers` header, part of
    /// [CORS](http://www.w3.org/TR/cors/#access-control-allow-headers-response-header)
    ///
    /// The `Access-Control-Allow-Headers` header indicates, as part of the
    /// response to a preflight request, which header field names can be used
    /// during the actual request.
    ///
    /// # ABNF
    ///
    /// ```text
    /// Access-Control-Allow-Headers: "Access-Control-Allow-Headers" ":" #field-name
    /// ```
    ///
    /// # Example values
    /// * `accept-language, date`
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::non_empty_vec;
    /// use rama_http_types::header::{CACHE_CONTROL, CONTENT_TYPE};
    /// use rama_http_headers::AccessControlAllowHeaders;
    ///
    /// let allow_headers = AccessControlAllowHeaders(
    ///     non_empty_vec![CACHE_CONTROL, CONTENT_TYPE],
    /// );
    /// ```
    pub struct AccessControlAllowHeaders(pub NonEmptyVec<HeaderName>);
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn decode_header_single() {
        let AccessControlAllowHeaders(allow_headers) = test_decode(&["foo, bar"]).unwrap();

        assert_eq!(allow_headers.len(), 2);
        assert_eq!(allow_headers[0], "foo");
        assert_eq!(allow_headers[1], "bar");
    }

    #[test]
    fn decode_header_multi() {
        let AccessControlAllowHeaders(allow_headers) = test_decode(&["foo, bar", "baz"]).unwrap();

        assert_eq!(allow_headers.len(), 3);
        assert_eq!(allow_headers[0], "foo");
        assert_eq!(allow_headers[1], "bar");
        assert_eq!(allow_headers[2], "baz");
    }

    #[test]
    fn encode() {
        let allow = AccessControlAllowHeaders(non_empty_vec![
            ::rama_http_types::header::CACHE_CONTROL,
            ::rama_http_types::header::IF_RANGE,
        ]);

        let headers = test_encode(allow);
        assert_eq!(
            headers["access-control-allow-headers"],
            "cache-control, if-range"
        );
    }

    #[test]
    fn decode_with_empty_header_value() {
        assert!(test_decode::<AccessControlAllowHeaders>(&[""]).is_none());
    }

    #[test]
    fn decode_with_no_headers() {
        assert!(test_decode::<AccessControlAllowHeaders>(&[]).is_none());
    }

    #[test]
    fn decode_with_invalid_value_str() {
        assert!(test_decode::<AccessControlAllowHeaders>(&["foo foo, bar"]).is_none());
    }
}
