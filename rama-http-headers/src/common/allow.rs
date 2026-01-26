use rama_http_types::Method;

derive_non_empty_flat_csv_header! {
    #[header(name = ALLOW, sep = Comma)]
    #[derive(Clone, Debug, PartialEq)]
    /// `Allow` header, defined in [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231#section-7.4.1)
    ///
    /// The `Allow` header field lists the set of methods advertised as
    /// supported by the target resource.  The purpose of this field is
    /// strictly to inform the recipient of valid request methods associated
    /// with the resource.
    ///
    /// # ABNF
    ///
    /// ```text
    /// Allow = #method
    /// ```
    ///
    /// # Example values
    /// * `GET, HEAD, PUT`
    /// * `OPTIONS, GET, PUT, POST, DELETE, HEAD, TRACE, CONNECT, PATCH, fOObAr`
    /// * ``
    ///
    /// # Examples
    ///
    /// ```
    /// use rama_utils::collections::non_empty_smallvec;
    /// use rama_http_types::Method;
    /// use rama_http_headers::Allow;
    ///
    /// let allow_methods = Allow(
    ///     non_empty_smallvec![Method::GET, Method::PUT],
    /// );
    /// ```
    pub struct Allow(pub NonEmptySmallVec<7, Method>);
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;
    use rama_utils::collections::non_empty_smallvec;

    #[test]
    fn decode_single() {
        let Allow(allowed) = test_decode(&["GET, PUT"]).unwrap();

        assert_eq!(allowed.len(), 2);
        assert_eq!(allowed[0], Method::GET);
        assert_eq!(allowed[1], Method::PUT);
    }

    #[test]
    fn decode_multi() {
        let Allow(allowed) = test_decode(&["GET, PUT", "POST"]).unwrap();

        assert_eq!(allowed.len(), 3);
        assert_eq!(allowed[0], Method::GET);
        assert_eq!(allowed[1], Method::PUT);
        assert_eq!(allowed[2], Method::POST);
    }

    #[test]
    fn decode_single_empty_value() {
        assert!(test_decode::<Allow>(&[""]).is_none());
    }

    #[test]
    fn decode_single_no_header_values() {
        assert!(test_decode::<Allow>(&[]).is_none());
    }

    #[test]
    fn encode() {
        let allow = Allow(non_empty_smallvec![Method::GET, Method::PUT]);

        let headers = test_encode(allow);
        assert_eq!(headers["allow"], "GET, PUT");
    }
}
