use rama_http_types::HeaderName;

derive_values_or_any_header! {
    #[header(name = ACCESS_CONTROL_EXPOSE_HEADERS, sep = Comma)]
    #[derive(Clone, Debug)]
    /// `Access-Control-Expose-Headers` header, as defined on
    /// [mdn](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Expose-Headers).
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
    /// let expose = AccessControlExposeHeaders::new_values(
    ///     non_empty_vec![CONTENT_LENGTH, ETAG],
    /// );
    /// # }
    /// ```
    pub struct AccessControlExposeHeaders(pub ValuesOrAny<HeaderName>);
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn decode_header_single() {
        let expose_headers = test_decode::<AccessControlExposeHeaders>(&["foo, bar"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(expose_headers.len(), 2);
        assert_eq!(expose_headers[0], "foo");
        assert_eq!(expose_headers[1], "bar");
    }

    #[test]
    fn decode_any() {
        assert!(
            test_decode::<AccessControlExposeHeaders>(&["*"])
                .unwrap()
                .is_any(),
        );
    }

    #[test]
    fn decode_any_with_trailer_value() {
        let expose_headers = test_decode::<AccessControlExposeHeaders>(&["*, bar"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(expose_headers.len(), 2);
        assert_eq!(expose_headers[0], "*");
        assert_eq!(expose_headers[1], "bar");
    }

    #[test]
    fn decode_any_with_trailer_header() {
        let expose_headers = test_decode::<AccessControlExposeHeaders>(&["*", "bar"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(expose_headers.len(), 2);
        assert_eq!(expose_headers[0], "*");
        assert_eq!(expose_headers[1], "bar");
    }

    #[test]
    fn decode_header_multi() {
        let expose_headers = test_decode::<AccessControlExposeHeaders>(&["foo, bar", "baz"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(expose_headers.len(), 3);
        assert_eq!(expose_headers[0], "foo");
        assert_eq!(expose_headers[1], "bar");
        assert_eq!(expose_headers[2], "baz");
    }

    #[test]
    fn encode() {
        let allow = AccessControlExposeHeaders::new_values(non_empty_vec![
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
    fn encode_any() {
        let allow = AccessControlExposeHeaders::new_any();
        let headers = test_encode(allow);
        assert_eq!(headers["access-control-expose-headers"], "*");
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
