use std::{fmt, str::FromStr};

use rama_http_types::{
    HeaderName, HeaderValue,
    mime::{self, Mime},
};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `Content-Type` header, defined in
/// [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231#section-3.1.1.5)
///
/// The `Content-Type` header field indicates the media type of the
/// associated representation: either the representation enclosed in the
/// message payload or the selected representation, as determined by the
/// message semantics.  The indicated media type defines both the data
/// format and how that data is intended to be processed by a recipient,
/// within the scope of the received message semantics, after any content
/// codings indicated by Content-Encoding are decoded.
///
/// Although the `mime` crate allows the mime options to be any slice, this crate
/// forces the use of Vec. This is to make sure the same header can't have more than 1 type. If
/// this is an issue, it's possible to implement `Header` on a custom struct.
///
/// # ABNF
///
/// ```text
/// Content-Type = media-type
/// ```
///
/// # Example values
///
/// * `text/html; charset=utf-8`
/// * `application/json`
///
/// # Examples
///
/// ```
/// use rama_http_headers::ContentType;
///
/// let ct = ContentType::json();
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct ContentType(Mime);

impl ContentType {
    /// Create a new [`ContentType`] from any [`Mime`].
    #[inline]
    #[must_use]
    pub fn new(mime: Mime) -> Self {
        Self(mime)
    }

    /// A constructor to easily create a `Content-Type: application/json` header.
    #[inline]
    #[must_use]
    pub fn json() -> Self {
        Self(mime::APPLICATION_JSON)
    }

    #[inline]
    #[must_use]
    pub fn ndjson() -> Self {
        Self(Mime::from_str("application/x-ndjson").unwrap())
    }

    /// A constructor to easily create a `Content-Type: text/plain` header.
    #[inline]
    #[must_use]
    pub fn text() -> Self {
        Self(mime::TEXT_PLAIN)
    }

    /// A constructor to easily create a `Content-Type: text/plain; charset=utf-8` header.
    #[inline]
    #[must_use]
    pub fn text_utf8() -> Self {
        Self(mime::TEXT_PLAIN_UTF_8)
    }

    /// A constructor to easily create a `Content-Type: text/event-stream` header.
    #[inline]
    #[must_use]
    pub fn text_event_stream() -> Self {
        Self(mime::TEXT_EVENT_STREAM)
    }

    /// A constructor to easily create a `Content-Type: text/html` header.
    #[inline]
    #[must_use]
    pub fn html() -> Self {
        Self(mime::TEXT_HTML)
    }

    /// A constructor to easily create a `Content-Type: text/html; charset=utf-8` header.
    #[inline]
    #[must_use]
    pub fn html_utf8() -> Self {
        Self(mime::TEXT_HTML_UTF_8)
    }

    /// A constructor to easily create a `Content-Type: text/css` header.
    #[inline]
    #[must_use]
    pub fn css() -> Self {
        Self(mime::TEXT_CSS)
    }

    /// A constructor to easily create a `text/css; charset=utf-8` header.
    #[inline]
    #[must_use]
    pub fn css_utf8() -> Self {
        Self(mime::TEXT_CSS_UTF_8)
    }

    /// A constructor to easily create a `Content-Type: text/xml` header.
    #[inline]
    #[must_use]
    pub fn xml() -> Self {
        Self(mime::TEXT_XML)
    }

    /// A constructor to easily create a `Content-Type: text/csv` header.
    #[inline]
    #[must_use]
    pub fn csv() -> Self {
        Self(mime::TEXT_CSV)
    }

    /// A constructor to easily create a `Content-Type: text/csv; charset=utf-8` header.
    #[inline]
    #[must_use]
    pub fn csv_utf8() -> Self {
        Self(mime::TEXT_CSV_UTF_8)
    }

    /// A constructor to easily create a `Content-Type: application/www-form-url-encoded` header.
    #[inline]
    #[must_use]
    pub fn form_url_encoded() -> Self {
        Self(mime::APPLICATION_WWW_FORM_URLENCODED)
    }
    /// A constructor to easily create a `Content-Type: image/jpeg` header.
    #[inline]
    #[must_use]
    pub fn jpeg() -> Self {
        Self(mime::IMAGE_JPEG)
    }

    /// A constructor to easily create a `Content-Type: image/png` header.
    #[inline]
    #[must_use]
    pub fn png() -> Self {
        Self(mime::IMAGE_PNG)
    }

    /// A constructor to easily create a `Content-Type: application/octet-stream` header.
    #[inline]
    #[must_use]
    pub fn octet_stream() -> Self {
        Self(mime::APPLICATION_OCTET_STREAM)
    }

    /// A constructor to easily create a `Content-Type: application/javascript` header.
    #[inline]
    #[must_use]
    pub fn javascript() -> Self {
        Self(mime::APPLICATION_JAVASCRIPT)
    }

    /// A constructor to easily create a `Content-Type: application/javascript; charset=utf-8` header.
    #[inline]
    #[must_use]
    pub fn javascript_utf8() -> Self {
        Self(mime::APPLICATION_JAVASCRIPT_UTF_8)
    }

    /// A constructor to easily create a `Content-Type: application/jose+json` header.
    #[inline]
    #[must_use]
    pub fn jose_json() -> Self {
        Self(Mime::from_str("application/jose+json").unwrap())
    }

    /// Reference to the internal [`Mime`].
    #[must_use]
    pub fn mime(&self) -> &Mime {
        &self.0
    }

    /// Consume `self` into the inner [`Mime`].
    #[must_use]
    pub fn into_mime(self) -> Mime {
        self.0
    }
}

impl TypedHeader for ContentType {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::CONTENT_TYPE
    }
}

impl HeaderDecode for ContentType {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .next()
            .and_then(|v| v.to_str().ok()?.parse().ok())
            .map(ContentType)
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for ContentType {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let value = self
            .0
            .as_ref()
            .parse()
            .expect("Mime is always a valid HeaderValue");
        values.extend(::std::iter::once(value));
    }
}

impl From<mime::Mime> for ContentType {
    fn from(m: mime::Mime) -> Self {
        Self(m)
    }
}

impl From<ContentType> for mime::Mime {
    fn from(ct: ContentType) -> Self {
        ct.0
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::str::FromStr for ContentType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<Mime>()
            .map(|m| m.into())
            .map_err(|_| Error::invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_decode;
    use super::ContentType;

    #[test]
    fn json() {
        assert_eq!(
            test_decode::<ContentType>(&["application/json"]),
            Some(ContentType::json()),
        );
    }

    #[test]
    fn from_str() {
        assert_eq!(
            "application/json".parse::<ContentType>().unwrap(),
            ContentType::json(),
        );
        assert!("invalid-mimetype".parse::<ContentType>().is_err());
    }

    bench_header!(bench_plain, ContentType, "text/plain");
    bench_header!(bench_json, ContentType, "application/json");
    bench_header!(
        bench_formdata,
        ContentType,
        "multipart/form-data; boundary=---------------abcd"
    );
}
