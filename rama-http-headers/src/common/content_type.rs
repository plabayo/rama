use std::{fmt, str::FromStr, sync::OnceLock};

use rama_core::telemetry::tracing;
use rama_http_types::{
    HeaderName, HeaderValue,
    header::content_type::extract_mime_type,
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
#[derive(Clone)]
pub struct ContentType(ContentTypeValue);

#[derive(Clone)]
enum ContentTypeValue {
    Parsed(Mime),
    Static(&'static StaticContentType),
}

struct StaticContentType {
    value: &'static str,
    mime: OnceLock<Mime>,
}

impl StaticContentType {
    const fn new(value: &'static str) -> Self {
        Self {
            value,
            mime: OnceLock::new(),
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "only built from private literals, each parsed in `every_static_content_type_parses`"
    )]
    fn mime(&self) -> &Mime {
        self.mime
            .get_or_init(|| self.value.parse().expect("valid static MIME value"))
    }
}

// TODO: Collapse this representation when `mime` supports validated static
// custom media types. Until then it keeps typed hot-path encoding allocation
// free while preserving `mime()` and `into_mime()` compatibility.
static GRPC: StaticContentType = StaticContentType::new("application/grpc");
static GRPC_WEB: StaticContentType = StaticContentType::new("application/grpc-web");
static GRPC_WEB_PROTO: StaticContentType = StaticContentType::new("application/grpc-web+proto");
static GRPC_WEB_TEXT_PROTO: StaticContentType =
    StaticContentType::new("application/grpc-web-text+proto");
static PROTOBUF: StaticContentType = StaticContentType::new("application/x-protobuf");

impl fmt::Debug for ContentType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut tuple = formatter.debug_tuple("ContentType");
        match &self.0 {
            ContentTypeValue::Parsed(mime) => tuple.field(mime),
            ContentTypeValue::Static(value) => tuple.field(&value.value),
        };
        tuple.finish()
    }
}

impl PartialEq for ContentType {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (ContentTypeValue::Static(lhs), ContentTypeValue::Static(rhs)) => {
                lhs.value == rhs.value
            }
            _ => self.mime() == other.mime(),
        }
    }
}

impl ContentType {
    /// Create a new [`ContentType`] from any [`Mime`].
    #[inline]
    #[must_use]
    pub fn new(mime: Mime) -> Self {
        Self(ContentTypeValue::Parsed(mime))
    }

    const fn from_static(value: &'static StaticContentType) -> Self {
        Self(ContentTypeValue::Static(value))
    }

    /// Markdown encoded as UTF-8.
    #[must_use]
    pub const fn markdown_utf8() -> Self {
        static MARKDOWN: StaticContentType = StaticContentType::new("text/markdown; charset=utf-8");
        Self::from_static(&MARKDOWN)
    }

    /// PEM-encoded certificates and keys.
    #[must_use]
    pub const fn pem() -> Self {
        static PEM: StaticContentType = StaticContentType::new("application/x-pem-file");
        Self::from_static(&PEM)
    }

    /// A constructor to easily create a `Content-Type: application/json` header.
    #[inline]
    #[must_use]
    pub fn json() -> Self {
        Self::new(mime::APPLICATION_JSON)
    }

    /// A constructor for the registered JSON-LD media type.
    #[inline]
    #[must_use]
    pub const fn json_ld() -> Self {
        static JSON_LD: StaticContentType = StaticContentType::new("application/ld+json");
        Self::from_static(&JSON_LD)
    }

    #[inline]
    #[must_use]
    pub const fn ndjson() -> Self {
        static NDJSON: StaticContentType = StaticContentType::new("application/x-ndjson");
        Self::from_static(&NDJSON)
    }

    /// A constructor to easily create a `Content-Type: text/plain` header.
    #[inline]
    #[must_use]
    pub fn text() -> Self {
        Self::new(mime::TEXT_PLAIN)
    }

    /// A constructor to easily create a `Content-Type: text/plain; charset=utf-8` header.
    #[inline]
    #[must_use]
    pub fn text_utf8() -> Self {
        Self::new(mime::TEXT_PLAIN_UTF_8)
    }

    /// A constructor to easily create a `Content-Type: text/event-stream` header.
    #[inline]
    #[must_use]
    pub fn text_event_stream() -> Self {
        Self::new(mime::TEXT_EVENT_STREAM)
    }

    /// A constructor to easily create a `Content-Type: text/html` header.
    #[inline]
    #[must_use]
    pub fn html() -> Self {
        Self::new(mime::TEXT_HTML)
    }

    /// A constructor to easily create a `Content-Type: text/html; charset=utf-8` header.
    #[inline]
    #[must_use]
    pub fn html_utf8() -> Self {
        Self::new(mime::TEXT_HTML_UTF_8)
    }

    /// A constructor to easily create a `Content-Type: text/css` header.
    #[inline]
    #[must_use]
    pub fn css() -> Self {
        Self::new(mime::TEXT_CSS)
    }

    /// A constructor to easily create a `text/css; charset=utf-8` header.
    #[inline]
    #[must_use]
    pub fn css_utf8() -> Self {
        Self::new(mime::TEXT_CSS_UTF_8)
    }

    /// A constructor to easily create a `Content-Type: text/xml` header.
    #[inline]
    #[must_use]
    pub fn xml() -> Self {
        Self::new(mime::TEXT_XML)
    }

    /// A constructor to easily create a `Content-Type: text/csv` header.
    #[inline]
    #[must_use]
    pub fn csv() -> Self {
        Self::new(mime::TEXT_CSV)
    }

    /// A constructor to easily create a `Content-Type: text/csv; charset=utf-8` header.
    #[inline]
    #[must_use]
    pub fn csv_utf8() -> Self {
        Self::new(mime::TEXT_CSV_UTF_8)
    }

    /// A constructor to easily create a `Content-Type: application/x-www-form-url-encoded` header.
    #[inline]
    #[must_use]
    pub fn form_url_encoded() -> Self {
        Self::new(mime::APPLICATION_WWW_FORM_URLENCODED)
    }

    /// A constructor to easily create a `Content-Type: image/jpeg` header.
    #[inline]
    #[must_use]
    pub fn jpeg() -> Self {
        Self::new(mime::IMAGE_JPEG)
    }

    /// A constructor to easily create a `Content-Type: image/png` header.
    #[inline]
    #[must_use]
    pub fn png() -> Self {
        Self::new(mime::IMAGE_PNG)
    }

    /// A constructor to easily create a `Content-Type: application/octet-stream` header.
    #[inline]
    #[must_use]
    pub fn octet_stream() -> Self {
        Self::new(mime::APPLICATION_OCTET_STREAM)
    }

    /// A constructor to easily create a `Content-Type: application/javascript` header.
    #[inline]
    #[must_use]
    pub fn javascript() -> Self {
        Self::new(mime::APPLICATION_JAVASCRIPT)
    }

    /// A constructor to easily create a `Content-Type: application/grpc` header.
    #[inline]
    #[must_use]
    pub const fn grpc() -> Self {
        Self::from_static(&GRPC)
    }

    /// A constructor to easily create a `Content-Type: application/grpc-web` header.
    #[inline]
    #[must_use]
    pub const fn grpc_web() -> Self {
        Self::from_static(&GRPC_WEB)
    }

    /// A constructor for `Content-Type: application/grpc-web+proto`.
    #[inline]
    #[must_use]
    pub const fn grpc_web_proto() -> Self {
        Self::from_static(&GRPC_WEB_PROTO)
    }

    /// A constructor for `Content-Type: application/grpc-web-text+proto`.
    #[inline]
    #[must_use]
    pub const fn grpc_web_text_proto() -> Self {
        Self::from_static(&GRPC_WEB_TEXT_PROTO)
    }

    /// A constructor for `Content-Type: application/x-protobuf`.
    #[inline]
    #[must_use]
    pub const fn protobuf() -> Self {
        Self::from_static(&PROTOBUF)
    }

    /// A constructor to easily create a `Content-Type: application/javascript; charset=utf-8` header.
    #[inline]
    #[must_use]
    pub fn javascript_utf8() -> Self {
        Self::new(mime::APPLICATION_JAVASCRIPT_UTF_8)
    }

    /// A constructor to easily create a `Content-Type: application/rss+xml` header.
    #[inline]
    #[must_use]
    pub const fn rss() -> Self {
        static RSS: StaticContentType = StaticContentType::new("application/rss+xml");
        Self::from_static(&RSS)
    }

    /// A constructor to easily create a `Content-Type: application/atom+xml` header.
    #[inline]
    #[must_use]
    pub const fn atom() -> Self {
        static ATOM: StaticContentType = StaticContentType::new("application/atom+xml");
        Self::from_static(&ATOM)
    }

    /// A constructor to easily create a `Content-Type: application/jose+json` header.
    #[inline]
    #[must_use]
    pub const fn jose_json() -> Self {
        static JOSE_JSON: StaticContentType = StaticContentType::new("application/jose+json");
        Self::from_static(&JOSE_JSON)
    }

    /// A constructor to easily create a `Content-Type: application/manifest+json` header,
    /// as defined by the [W3C Web App Manifest spec](https://www.w3.org/TR/appmanifest/#media-type-registration).
    #[inline]
    #[must_use]
    pub const fn manifest_json() -> Self {
        static MANIFEST_JSON: StaticContentType =
            StaticContentType::new("application/manifest+json");
        Self::from_static(&MANIFEST_JSON)
    }

    /// A constructor to easily create a `Content-Type: image/svg+xml` header.
    ///
    /// ```
    /// use rama_http_headers::ContentType;
    ///
    /// assert_eq!(ContentType::svg().to_string(), "image/svg+xml");
    /// ```
    #[inline]
    #[must_use]
    pub fn svg() -> Self {
        Self::new(mime::IMAGE_SVG)
    }

    /// A constructor to easily create a `Content-Type: application/xml; charset=utf-8` header.
    ///
    /// Distinct from [`Self::xml`] (which is `text/xml`): per
    /// [RFC 7303](https://datatracker.ietf.org/doc/html/rfc7303) `application/xml`
    /// is preferred for sitemaps/RSS/Atom, and the charset is stated explicitly
    /// so the document's XML prolog and the HTTP `Content-Type` agree.
    ///
    /// ```
    /// use rama_http_headers::ContentType;
    ///
    /// assert_eq!(
    ///     ContentType::xml_utf8().to_string(),
    ///     "application/xml; charset=utf-8",
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn xml_utf8() -> Self {
        static XML_UTF8: StaticContentType =
            StaticContentType::new("application/xml; charset=utf-8");
        Self::from_static(&XML_UTF8)
    }

    /// A constructor to easily create a `Content-Type: application/wasm` header.
    ///
    /// The spec mandates this exact value for `WebAssembly.instantiateStreaming`
    /// to accept the response.
    ///
    /// ```
    /// use rama_http_headers::ContentType;
    ///
    /// assert_eq!(ContentType::wasm().to_string(), "application/wasm");
    /// ```
    #[inline]
    #[must_use]
    pub const fn wasm() -> Self {
        static WASM: StaticContentType = StaticContentType::new("application/wasm");
        Self::from_static(&WASM)
    }

    /// A constructor to easily create a `Content-Type: font/woff2` header.
    ///
    /// ```
    /// use rama_http_headers::ContentType;
    ///
    /// assert_eq!(ContentType::woff2().to_string(), "font/woff2");
    /// ```
    #[inline]
    #[must_use]
    pub fn woff2() -> Self {
        Self::new(mime::FONT_WOFF2)
    }

    /// A constructor to easily create a `Content-Type: application/manifest+json` header.
    ///
    /// Alias of [`Self::manifest_json`], named after the `.webmanifest` file
    /// extension that web app manifests actually use; both coexist.
    ///
    /// ```
    /// use rama_http_headers::ContentType;
    ///
    /// assert_eq!(
    ///     ContentType::webmanifest().to_string(),
    ///     "application/manifest+json",
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub fn webmanifest() -> Self {
        Self::manifest_json()
    }

    /// Reference to the internal [`Mime`].
    #[must_use]
    pub fn mime(&self) -> &Mime {
        match &self.0 {
            ContentTypeValue::Parsed(mime) => mime,
            ContentTypeValue::Static(value) => value.mime(),
        }
    }

    /// Consume `self` into the inner [`Mime`].
    #[must_use]
    pub fn into_mime(self) -> Mime {
        match self.0 {
            ContentTypeValue::Parsed(mime) => mime,
            ContentTypeValue::Static(value) => value.mime().clone(),
        }
    }
}

impl TypedHeader for ContentType {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::CONTENT_TYPE
    }
}

impl HeaderDecode for ContentType {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        // As browsers read it, over every line (Fetch §3.5).
        extract_mime_type(values)
            .map(Self::new)
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for ContentType {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match &self.0 {
            ContentTypeValue::Static(value) => {
                values.extend(::std::iter::once(HeaderValue::from_static(value.value)));
            }
            ContentTypeValue::Parsed(mime) => match mime.as_ref().parse() {
                Ok(value) => values.extend(::std::iter::once(value)),
                Err(err) => {
                    tracing::debug!("failed to encode content-type's mime as header value: {err}");
                }
            },
        }
    }
}

impl From<mime::Mime> for ContentType {
    fn from(m: mime::Mime) -> Self {
        Self::new(m)
    }
}

impl From<ContentType> for mime::Mime {
    fn from(ct: ContentType) -> Self {
        ct.into_mime()
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            ContentTypeValue::Parsed(mime) => fmt::Display::fmt(mime, f),
            ContentTypeValue::Static(value) => f.write_str(value.value),
        }
    }
}

impl FromStr for ContentType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<Mime>()
            .map(|m| m.into())
            .map_err(|_e| Error::invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentType, HeaderValue, mime};
    use crate::HeaderDecode;
    use crate::common::{test_decode, test_encode};

    #[test]
    fn several_lines_decode_as_fetch_extracts_them() {
        let content_type =
            test_decode::<ContentType>(&["text/html;charset=gbk", "text/html;x=y"]).unwrap();
        assert_eq!(content_type.mime().essence_str(), "text/html");
        assert_eq!(
            content_type
                .mime()
                .get_param(mime::CHARSET)
                .map(|c| c.as_str()),
            Some("gbk")
        );
        assert!(test_decode::<ContentType>(&["cannot-parse"]).is_none());
    }

    #[test]
    fn jose_json_is_valid() {
        _ = ContentType::jose_json().mime();
    }

    #[test]
    fn ndjson_is_valid() {
        _ = ContentType::ndjson().mime();
    }

    #[test]
    fn manifest_json_is_valid() {
        _ = ContentType::manifest_json().mime();
    }

    #[test]
    fn manifest_json_roundtrip() {
        assert_eq!(
            test_decode::<ContentType>(&["application/manifest+json"]),
            Some(ContentType::manifest_json()),
        );
    }

    #[test]
    fn xml_utf8_is_valid() {
        _ = ContentType::xml_utf8().mime();
    }

    #[test]
    fn xml_utf8_roundtrip() {
        assert_eq!(
            test_decode::<ContentType>(&["application/xml; charset=utf-8"]),
            Some(ContentType::xml_utf8()),
        );
    }

    #[test]
    fn wasm_is_valid() {
        _ = ContentType::wasm().mime();
    }

    #[test]
    fn webmanifest_matches_manifest_json() {
        assert_eq!(ContentType::webmanifest(), ContentType::manifest_json());
    }

    #[test]
    fn rss_is_valid() {
        _ = ContentType::rss().mime();
    }

    #[test]
    fn atom_is_valid() {
        _ = ContentType::atom().mime();
    }

    #[test]
    fn grpc_variants_are_valid() {
        assert_eq!(ContentType::grpc().to_string(), "application/grpc");
        assert_eq!(ContentType::grpc_web().to_string(), "application/grpc-web");
        assert_eq!(
            ContentType::grpc_web_proto().to_string(),
            "application/grpc-web+proto"
        );
        assert_eq!(
            ContentType::grpc_web_text_proto().to_string(),
            "application/grpc-web-text+proto"
        );
        assert_eq!(
            ContentType::protobuf().to_string(),
            "application/x-protobuf"
        );
    }

    #[test]
    fn grpc_variants_expose_their_parsed_mime() {
        for (content_type, expected) in [
            (ContentType::grpc(), "application/grpc"),
            (ContentType::grpc_web(), "application/grpc-web"),
            (ContentType::grpc_web_proto(), "application/grpc-web+proto"),
            (
                ContentType::grpc_web_text_proto(),
                "application/grpc-web-text+proto",
            ),
            (ContentType::protobuf(), "application/x-protobuf"),
        ] {
            assert_eq!(content_type.mime().as_ref(), expected);
            assert_eq!(content_type.into_mime().as_ref(), expected);
        }
    }

    #[test]
    fn every_static_content_type_parses() {
        for (content_type, expected) in [
            (ContentType::markdown_utf8(), "text/markdown; charset=utf-8"),
            (ContentType::pem(), "application/x-pem-file"),
            (ContentType::json_ld(), "application/ld+json"),
            (ContentType::ndjson(), "application/x-ndjson"),
            (ContentType::rss(), "application/rss+xml"),
            (ContentType::atom(), "application/atom+xml"),
            (ContentType::jose_json(), "application/jose+json"),
            (ContentType::manifest_json(), "application/manifest+json"),
            (ContentType::xml_utf8(), "application/xml; charset=utf-8"),
            (ContentType::wasm(), "application/wasm"),
            (ContentType::grpc(), "application/grpc"),
            (ContentType::grpc_web(), "application/grpc-web"),
            (ContentType::grpc_web_proto(), "application/grpc-web+proto"),
            (
                ContentType::grpc_web_text_proto(),
                "application/grpc-web-text+proto",
            ),
            (ContentType::protobuf(), "application/x-protobuf"),
        ] {
            assert_eq!(content_type.mime().as_ref(), expected);
            assert_eq!(content_type.to_string(), expected);
            assert_eq!(test_encode(content_type.clone())["content-type"], expected);
            assert_eq!(test_decode::<ContentType>(&[expected]), Some(content_type));
        }
    }

    #[test]
    fn adversarial_values_do_not_panic() {
        for raw in [
            b"".as_slice(),
            b"/",
            b"a/",
            b"/b",
            b"a/b;",
            b"a/b; ",
            b"a/b;=",
            b"a/b; c",
            b"a/b; c=",
            b"a/b; c=\"",
            b"a/b; c=\"\"",
            b"a/b; charset=\"utf-8\"; d=e",
            b"text/plain; charset=utf-8; charset=utf-8",
            b"a/b; c=\"\xc3\xa9\"; d=e",
            b"\xff/\xfe",
        ] {
            let value = HeaderValue::from_bytes(raw).unwrap();
            if let Ok(content_type) = ContentType::decode(&mut std::iter::once(&value)) {
                let mime = content_type.mime();
                _ = (
                    mime.type_(),
                    mime.subtype(),
                    mime.suffix(),
                    mime.essence_str(),
                );
                _ = (mime.get_param("charset"), mime.params().count());
                _ = test_encode(content_type);
            }
        }
        for s in [
            "a/b; c=\"é\"; d=e",
            "a/b; charset=\"é\"",
            "é/b",
            "a/é",
            "a/b+é",
        ] {
            if let Ok(content_type) = s.parse::<ContentType>() {
                let mime = content_type.mime();
                _ = (
                    mime.type_(),
                    mime.subtype(),
                    mime.suffix(),
                    mime.params().count(),
                );
                _ = test_encode(content_type);
            }
        }
    }

    #[test]
    fn json() {
        assert_eq!(
            test_decode::<ContentType>(&["application/json"]),
            Some(ContentType::json()),
        );
    }

    #[test]
    fn json_ld() {
        assert_eq!(
            test_decode::<ContentType>(&["application/ld+json"]),
            Some(ContentType::json_ld()),
        );
    }

    #[test]
    fn from_str() {
        assert_eq!(
            "application/json".parse::<ContentType>().unwrap(),
            ContentType::json(),
        );
        "invalid-mimetype".parse::<ContentType>().unwrap_err();
    }

    bench_header!(bench_plain, ContentType, "text/plain");
    bench_header!(bench_json, ContentType, "application/json");
    bench_header!(
        bench_formdata,
        ContentType,
        "multipart/form-data; boundary=---------------abcd"
    );
}
