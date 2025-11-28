use crate::specifier::QualityValue;
use rama_http_types::mime::{self, Mime};

derive_non_empty_flat_csv_header! {
    #[header(name = ACCEPT, sep = Comma)]
    /// `Accept` header, defined in [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.2)
    ///
    /// The `Accept` header field can be used by user agents to specify
    /// response media types that are acceptable.  Accept header fields can
    /// be used to indicate that the request is specifically limited to a
    /// small set of desired types, as in the case of a request for an
    /// in-line image
    ///
    /// # ABNF
    ///
    /// ```text
    /// Accept = #( media-range [ accept-params ] )
    ///
    /// media-range    = ( "*/*"
    ///                  / ( type "/" "*" )
    ///                  / ( type "/" subtype )
    ///                  ) *( OWS ";" OWS parameter )
    /// accept-params  = weight *( accept-ext )
    /// accept-ext = OWS ";" OWS token [ "=" ( token / quoted-string ) ]
    /// ```
    ///
    /// # Example values
    /// * `audio/*; q=0.2, audio/basic`
    /// * `text/plain; q=0.5, text/html, text/x-dvi; q=0.8, text/x-c`
    ///
    /// # Examples
    /// ```
    /// use std::iter::FromIterator;
    /// use rama_http_headers::{Accept, specifier::QualityValue, HeaderMapExt};
    /// use rama_http_types::mime;
    ///
    /// let mut headers = rama_http_types::HeaderMap::new();
    ///
    /// headers.typed_insert(
    ///     Accept::new(
    ///         QualityValue::new(mime::TEXT_HTML, Default::default()),
    ///     )
    /// );
    /// ```
    ///
    /// ```
    /// use std::iter::FromIterator;
    /// use rama_http_headers::{Accept, specifier::QualityValue, HeaderMapExt};
    /// use rama_http_types::mime;
    ///
    /// let mut headers = rama_http_types::HeaderMap::new();
    /// headers.typed_insert(
    ///     Accept::new(
    ///         QualityValue::new(mime::APPLICATION_JSON, Default::default()),
    ///     )
    /// );
    /// ```
    /// ```
    /// use std::iter::FromIterator;
    /// use rama_utils::collections::non_empty_vec;
    /// use rama_http_headers::{Accept, specifier::QualityValue, HeaderMapExt};
    /// use rama_http_types::mime;
    ///
    /// let mut headers = rama_http_types::HeaderMap::new();
    ///
    /// headers.typed_insert(
    ///     Accept(non_empty_vec![
    ///         QualityValue::from(mime::TEXT_HTML),
    ///         QualityValue::from("application/xhtml+xml".parse::<mime::Mime>().unwrap()),
    ///         QualityValue::new(
    ///             mime::TEXT_XML,
    ///             900.into()
    ///         ),
    ///         QualityValue::from("image/webp".parse::<mime::Mime>().unwrap()),
    ///         QualityValue::new(
    ///             mime::STAR_STAR,
    ///             800.into()
    ///         ),
    ///     ])
    /// );
    /// ```
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Accept(pub NonEmptyVec<QualityValue<Mime>>);
}

impl Accept {
    #[inline(always)]
    #[must_use]
    pub fn new_from_mime(mime: Mime) -> Self {
        Self::new(QualityValue::new_value(mime))
    }

    /// A constructor to easily create `Accept: */*`.
    #[must_use]
    #[inline(always)]
    pub fn star() -> Self {
        Self::new_from_mime(mime::STAR_STAR)
    }

    /// A constructor to easily create `Accept: application/json`.
    #[must_use]
    #[inline(always)]
    pub fn json() -> Self {
        Self::new_from_mime(mime::APPLICATION_JSON)
    }

    /// A constructor to easily create `Accept: text/*`.
    #[must_use]
    #[inline(always)]
    pub fn text() -> Self {
        Self::new_from_mime(mime::TEXT_STAR)
    }

    /// A constructor to easily create `Accept: image/*`.
    #[must_use]
    #[inline(always)]
    pub fn image() -> Self {
        Self::new_from_mime(mime::IMAGE_STAR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeaderDecode, specifier::Quality};
    use rama_http_types::{
        HeaderValue,
        mime::{TEXT_HTML, TEXT_PLAIN, TEXT_PLAIN_UTF_8},
    };
    use rama_utils::collections::non_empty_vec;

    macro_rules! test_header {
        ($name: ident, $input: expr, $expected: expr) => {
            #[test]
            fn $name() {
                assert_eq!(
                    Accept::decode(
                        &mut $input
                            .into_iter()
                            .map(|s| HeaderValue::from_bytes(s).unwrap())
                            .collect::<Vec<_>>()
                            .iter()
                    )
                    .ok(),
                    $expected,
                );
            }
        };
    }

    // Tests from the RFC
    test_header!(
        test1,
        vec![b"audio/*; q=0.2, audio/basic"],
        Some(Accept(non_empty_vec![
            QualityValue::new("audio/*".parse().unwrap(), Quality::from(200)),
            QualityValue::new("audio/basic".parse().unwrap(), Default::default()),
        ]))
    );
    test_header!(
        test2,
        vec![b"text/plain; q=0.5, text/html, text/x-dvi; q=0.8, text/x-c"],
        Some(Accept(non_empty_vec![
            QualityValue::new(TEXT_PLAIN, Quality::from(500)),
            QualityValue::new(TEXT_HTML, Default::default()),
            QualityValue::new("text/x-dvi".parse().unwrap(), Quality::from(800)),
            QualityValue::new("text/x-c".parse().unwrap(), Default::default()),
        ]))
    );
    // Custom tests
    test_header!(
        test3,
        vec![b"text/plain; charset=utf-8"],
        Some(Accept(non_empty_vec![QualityValue::new(
            TEXT_PLAIN_UTF_8,
            Default::default()
        )]))
    );
    test_header!(
        test4,
        vec![b"text/plain; charset=utf-8; q=0.5"],
        Some(Accept(non_empty_vec![QualityValue::new(
            TEXT_PLAIN_UTF_8,
            Quality::from(500)
        ),]))
    );
}
