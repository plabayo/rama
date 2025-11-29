use rama_http_types::Method;

derive_non_empty_flat_csv_header! {
    #[header(name = ACCESS_CONTROL_ALLOW_METHODS, sep = Comma)]
    #[derive(Clone, Debug, PartialEq)]
    /// `Access-Control-Allow-Methods` header, part of
    /// [CORS](http://www.w3.org/TR/cors/#access-control-allow-methods-response-header)
    ///
    /// The `Access-Control-Allow-Methods` header indicates, as part of the
    /// response to a preflight request, which methods can be used during the
    /// actual request.
    ///
    /// # ABNF
    ///
    /// ```text
    /// Access-Control-Allow-Methods: "Access-Control-Allow-Methods" ":" #Method
    /// ```
    ///
    /// # Example values
    /// * `PUT, DELETE, XMODIFY`
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::non_empty_vec;
    /// use rama_http_types::Method;
    /// use rama_http_headers::AccessControlAllowMethods;
    ///
    /// let allow_methods = AccessControlAllowMethods(
    ///     non_empty_vec![Method::GET, Method::PUT],
    /// );
    /// ```
    pub struct AccessControlAllowMethods(pub NonEmptyVec<Method>);
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use rama_utils::collections::non_empty_vec;

    #[test]
    fn decode_single() {
        let AccessControlAllowMethods(allowed) = test_decode(&["GET, PUT"]).unwrap();

        assert_eq!(allowed.len(), 2);
        assert_eq!(allowed[0], Method::GET);
        assert_eq!(allowed[1], Method::PUT);
    }

    #[test]
    fn decode_multi() {
        let AccessControlAllowMethods(allowed) = test_decode(&["GET, PUT", "POST"]).unwrap();

        assert_eq!(allowed.len(), 3);
        assert_eq!(allowed[0], Method::GET);
        assert_eq!(allowed[1], Method::PUT);
        assert_eq!(allowed[2], Method::POST);
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
    fn encode() {
        let allow = AccessControlAllowMethods(non_empty_vec![Method::GET, Method::PUT]);

        let headers = test_encode(allow);
        assert_eq!(headers["access-control-allow-methods"], "GET, PUT");
    }
}
