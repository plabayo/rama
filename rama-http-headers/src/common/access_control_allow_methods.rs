use rama_http_types::Method;

derive_values_or_any_header! {
    #[header(name = ACCESS_CONTROL_ALLOW_METHODS, sep = Comma)]
    #[derive(Clone, Debug, PartialEq)]
    /// `Access-Control-Allow-Methods` header, as defined on
    /// [mdn](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Methods).
    ///
    /// The `Access-Control-Allow-Methods` header indicates, as part of the
    /// response to a preflight request, which methods can be used during the
    /// actual request.
    ///
    /// # ABNF
    ///
    /// ```text
    /// Access-Control-Allow-Methods: "Access-Control-Allow-Methods" ":" #Method | *
    /// ```
    ///
    /// # Example values
    /// * `PUT, DELETE, XMODIFY`
    /// * `*`
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::non_empty_vec;
    /// use rama_http_types::Method;
    /// use rama_http_headers::AccessControlAllowMethods;
    ///
    /// let allow_methods = AccessControlAllowMethods::new_values(
    ///     non_empty_vec![Method::GET, Method::PUT],
    /// );
    ///
    /// let allow_any_methods = AccessControlAllowMethods::new_any();
    /// ```
    pub struct AccessControlAllowMethods(pub ValuesOrAny<Method>);
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn decode_single() {
        let allowed_methods = test_decode::<AccessControlAllowMethods>(&["GET, PUT"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(allowed_methods.len(), 2);
        assert_eq!(allowed_methods[0], Method::GET);
        assert_eq!(allowed_methods[1], Method::PUT);
    }

    #[test]
    fn decode_any() {
        assert!(
            test_decode::<AccessControlAllowMethods>(&["*"])
                .unwrap()
                .is_any()
        );
    }

    #[test]
    fn decode_any_with_trailer_value() {
        let allowed_methods = test_decode::<AccessControlAllowMethods>(&["*, GET"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(allowed_methods.len(), 2);
        assert_eq!(allowed_methods[0], "*".parse::<Method>().unwrap());
        assert_eq!(allowed_methods[1], Method::GET);
    }

    #[test]
    fn decode_any_with_trailer_header() {
        let allowed_methods = test_decode::<AccessControlAllowMethods>(&["*", "GET"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(allowed_methods.len(), 2);
        assert_eq!(allowed_methods[0], "*".parse::<Method>().unwrap());
        assert_eq!(allowed_methods[1], Method::GET);
    }

    #[test]
    fn decode_multi() {
        let allowed_methods = test_decode::<AccessControlAllowMethods>(&["GET, PUT", "POST"])
            .unwrap()
            .into_values()
            .unwrap();

        assert_eq!(allowed_methods.len(), 3);
        assert_eq!(allowed_methods[0], Method::GET);
        assert_eq!(allowed_methods[1], Method::PUT);
        assert_eq!(allowed_methods[2], Method::POST);
    }

    #[test]
    fn decode_single_empty_value() {
        assert!(test_decode::<AccessControlAllowMethods>(&[""]).is_none());
    }

    #[test]
    fn decode_single_no_header_values() {
        assert!(test_decode::<AccessControlAllowMethods>(&[]).is_none());
    }

    #[test]
    fn encode_methods() {
        let allow = AccessControlAllowMethods::new_values(non_empty_vec![Method::GET, Method::PUT]);

        let headers = test_encode(allow);
        assert_eq!(headers["access-control-allow-methods"], "GET, PUT");
    }

    #[test]
    fn encodeany() {
        let allow = AccessControlAllowMethods::new_any();

        let headers = test_encode(allow);
        assert_eq!(headers["access-control-allow-methods"], "*");
    }
}
