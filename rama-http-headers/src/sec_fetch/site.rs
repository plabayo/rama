rama_utils::macros::enums::enum_builder! {
    /// The `Sec-Fetch-Site` [fetch metadata request header][mdn].
    ///
    /// Sent by browsers to indicate the relationship between the origin that initiated the request
    /// and the origin of the requested resource. It is the primary signal used by modern CSRF
    /// protection (see [`CsrfLayer`]).
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site
    /// [`CsrfLayer`]: https://docs.rs/rama-http/latest/rama_http/layer/csrf/struct.CsrfLayer.html
    ///
    /// # Example values
    ///
    /// * `same-origin`
    /// * `same-site`
    /// * `cross-site`
    /// * `none`
    @String
    pub enum SecFetchSite {
        /// The request initiator and the target share the same origin.
        SameOrigin => "same-origin",
        /// The request initiator and the target share the same site (registrable domain) but not
        /// the same origin.
        SameSite => "same-site",
        /// The request initiator and the target are cross-site.
        CrossSite => "cross-site",
        /// The request was initiated by the user (e.g. typing a URL), not by another origin.
        None => "none",
    }
}

token_header!(SecFetchSite, SEC_FETCH_SITE);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    #[test]
    fn decode_known_values() {
        assert_eq!(
            test_decode::<SecFetchSite>(&["same-origin"]),
            Some(SecFetchSite::SameOrigin)
        );
        assert_eq!(
            test_decode::<SecFetchSite>(&["same-site"]),
            Some(SecFetchSite::SameSite)
        );
        assert_eq!(
            test_decode::<SecFetchSite>(&["cross-site"]),
            Some(SecFetchSite::CrossSite)
        );
        assert_eq!(
            test_decode::<SecFetchSite>(&["none"]),
            Some(SecFetchSite::None)
        );
    }

    #[test]
    fn decode_accepts_unknown_and_empty() {
        assert_eq!(
            test_decode::<SecFetchSite>(&["nope"]),
            Some(SecFetchSite::Unknown("nope".into()))
        );
        assert_eq!(test_decode::<SecFetchSite>(&[""]), None);
        // The Fetch spec mandates lowercase; uppercase is recognised.
        assert_eq!(
            test_decode::<SecFetchSite>(&["Same-Origin"]),
            Some(SecFetchSite::SameOrigin)
        );
    }

    #[test]
    fn encode_round_trip() {
        let headers = test_encode(SecFetchSite::CrossSite);
        assert_eq!(headers["sec-fetch-site"], "cross-site");
    }
}
