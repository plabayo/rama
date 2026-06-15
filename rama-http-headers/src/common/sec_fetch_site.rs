use std::borrow::Cow;

use rama_http_types::{HeaderName, HeaderValue};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

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

impl TypedHeader for SecFetchSite {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::SEC_FETCH_SITE
    }
}

impl HeaderDecode for SecFetchSite {
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        values
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|s| (!s.is_empty()).then(|| Self::from(s)))
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for SecFetchSite {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match self.as_static_str() {
            Cow::Borrowed(s) => values.extend(std::iter::once(HeaderValue::from_static(s))),
            Cow::Owned(s) => values.extend(HeaderValue::try_from(s).ok()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;

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
