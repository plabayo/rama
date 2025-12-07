use rama_http_types::HeaderName;

derive_non_empty_flat_csv_header! {
    #[header(name = ACCESS_CONTROL_REQUEST_HEADERS, sep = Comma)]
    #[derive(Clone, Debug)]
    /// `Access-Control-Request-Headers` header, as defined on
    /// [mdn](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Request-Headers).
    ///
    /// The `Access-Control-Request-Headers` header indicates which headers will
    /// be used in the actual request as part of the preflight request.
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
    /// # fn main() {
    /// use rama_utils::collections::non_empty_vec;
    /// use rama_http_types::header::{CONTENT_LENGTH, ETAG};
    /// use rama_http_headers::AccessControlRequestHeaders;
    ///
    /// let expose = AccessControlRequestHeaders(
    ///     non_empty_vec![CONTENT_LENGTH, ETAG],
    /// );
    /// # }
    /// ```
    pub struct AccessControlRequestHeaders(pub NonEmptyVec<HeaderName>);
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn decode_header_single() {
        let AccessControlRequestHeaders(allow_headers) = test_decode(&["foo, bar"]).unwrap();

        assert_eq!(allow_headers.len(), 2);
        assert_eq!(allow_headers[0], "foo");
        assert_eq!(allow_headers[1], "bar");
    }

    #[test]
    fn decode_header_multi() {
        let AccessControlRequestHeaders(allow_headers) = test_decode(&["foo, bar", "baz"]).unwrap();

        assert_eq!(allow_headers.len(), 3);
        assert_eq!(allow_headers[0], "foo");
        assert_eq!(allow_headers[1], "bar");
        assert_eq!(allow_headers[2], "baz");
    }

    #[test]
    fn encode() {
        let allow = AccessControlRequestHeaders(non_empty_vec![
            ::rama_http_types::header::CACHE_CONTROL,
            ::rama_http_types::header::IF_RANGE,
        ]);

        let headers = test_encode(allow);
        assert_eq!(
            headers["access-control-request-headers"],
            "cache-control, if-range"
        );
    }

    #[test]
    fn decode_with_empty_header_value() {
        assert!(test_decode::<AccessControlRequestHeaders>(&[""]).is_none());
    }

    #[test]
    fn decode_with_no_headers() {
        assert!(test_decode::<AccessControlRequestHeaders>(&[]).is_none());
    }

    #[test]
    fn decode_with_invalid_value_str() {
        assert!(test_decode::<AccessControlRequestHeaders>(&["foo foo, bar"]).is_none());
    }
}
