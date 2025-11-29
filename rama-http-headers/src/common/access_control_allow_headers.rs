use rama_http_types::HeaderName;

derive_values_or_any_header! {
    #[header(name = ACCESS_CONTROL_ALLOW_HEADERS, sep = Comma)]
    #[derive(Clone, Debug, PartialEq)]
    /// `Access-Control-Allow-Headers` header, as defined on
    /// [mdn](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Headers).
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
    /// * `*` (any)
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::non_empty_vec;
    /// use rama_http_types::header::{CACHE_CONTROL, CONTENT_TYPE};
    /// use rama_http_headers::AccessControlAllowHeaders;
    ///
    /// let allow_headers = AccessControlAllowHeaders::new_values(
    ///     non_empty_vec![CACHE_CONTROL, CONTENT_TYPE],
    /// );
    ///
    /// let any_allow_headers = AccessControlAllowHeaders::new_any();
    /// ```
    pub struct AccessControlAllowHeaders(pub ValuesOrAny<HeaderName>);
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn decode_header_single() {
        let allow_headers = test_decode::<AccessControlAllowHeaders>(&["foo, bar"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(allow_headers.len(), 2);
        assert_eq!(allow_headers[0], "foo");
        assert_eq!(allow_headers[1], "bar");
    }

    #[test]
    fn decode_any() {
        assert!(
            test_decode::<AccessControlAllowHeaders>(&["*"])
                .unwrap()
                .is_any(),
        );
    }

    #[test]
    fn decode_any_with_trailer_value() {
        let allow_headers = test_decode::<AccessControlAllowHeaders>(&["*, bar"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(allow_headers.len(), 2);
        assert_eq!(allow_headers[0], "*");
        assert_eq!(allow_headers[1], "bar");
    }

    #[test]
    fn decode_any_with_trailer_header() {
        let allow_headers = test_decode::<AccessControlAllowHeaders>(&["*", "bar"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(allow_headers.len(), 2);
        assert_eq!(allow_headers[0], "*");
        assert_eq!(allow_headers[1], "bar");
    }

    #[test]
    fn decode_header_multi() {
        let allow_headers = test_decode::<AccessControlAllowHeaders>(&["foo, bar", "baz"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(allow_headers.len(), 3);
        assert_eq!(allow_headers[0], "foo");
        assert_eq!(allow_headers[1], "bar");
        assert_eq!(allow_headers[2], "baz");
    }

    #[test]
    fn encode() {
        let allow = AccessControlAllowHeaders::new_values(non_empty_vec![
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
    fn encode_any() {
        let allow = AccessControlAllowHeaders::new_any();
        let headers = test_encode(allow);
        assert_eq!(headers["access-control-allow-headers"], "*");
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
