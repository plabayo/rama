//! Server-side `multipart/form-data` extractor.
//!
//! Built on top of the [`multer`] crate. Use [`Multipart`] as a handler
//! argument to iterate over form fields. See the `http_multipart` example
//! for usage.
//!
//! Spec references (vendored under `rama-http/specifications/`):
//! - RFC 7578 — `multipart/form-data`
//! - RFC 2046 — MIME Part Two: Media Types (boundary framing)
//! - RFC 6266 / RFC 8187 — `Content-Disposition` / charset-encoded params
//!
//! Parsing leans accept-friendly: the underlying `multer` parser accepts
//! the various non-ASCII filename forms surveyed by RFC 7578 §5.1.3
//! (raw UTF-8, RFC 2047 encoded-words, RFC 2231 / RFC 8187 ext-value),
//! tolerates transport padding around boundaries (RFC 2046 §5.1.1), and
//! ignores preamble and epilogue bytes.

use crate::Request;
use crate::service::web::extract::FromRequest;
use crate::utils::macros::{composite_http_rejection, define_http_rejection};
use ahash::HashMap;
use rama_core::bytes::Bytes;
use rama_core::extensions::{Extension, ExtensionsRef};
use rama_core::futures::{Stream, TryStream};
use rama_http_types::{HeaderMap, StatusCode, header};
use rama_utils::macros::generate_set_and_with;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Per-field size constraints for [`Multipart`].
///
/// Insert a `MultipartConfig` as a request extension via a layer to apply
/// project-wide limits, or pass it to
/// [`Multipart::from_body_with_config`] for direct programmatic use.
///
/// **Combining sources is opt-in.** When multiple `MultipartConfig`
/// extensions are inserted on the same request, the extractor reads the
/// most-recently-inserted one — earlier values are *not* auto-merged.
/// To compose limits across layers (and have the lowest value per field
/// win), call [`merge_floor`](Self::merge_floor) explicitly in the
/// inserting middleware before storing the resulting config.
///
/// The total payload size is governed by the standard body limit and is not
/// configured here.
#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(http))]
pub struct MultipartConfig {
    default_field_limit: Option<u64>,
    field_limits: HashMap<Cow<'static, str>, u64>,
}

impl MultipartConfig {
    /// Create an empty config. No limits are applied unless set via the
    /// builder methods.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Default per-field byte limit applied when no field-specific
        /// limit overrides it.
        pub fn default_field_limit(mut self, limit: Option<u64>) -> Self {
            self.default_field_limit = limit;
            self
        }
    }

    /// Set a byte limit for a specific field by name.
    #[must_use]
    pub fn with_field_limit(mut self, name: impl Into<Cow<'static, str>>, limit: u64) -> Self {
        self.field_limits.insert(name.into(), limit);
        self
    }

    /// Set a byte limit for a specific field by name.
    pub fn set_field_limit(&mut self, name: impl Into<Cow<'static, str>>, limit: u64) -> &mut Self {
        self.field_limits.insert(name.into(), limit);
        self
    }

    /// Merge another configuration into this one using a floor: for every
    /// limit set in either source, keep the lower value.
    pub fn merge_floor(&mut self, other: &Self) {
        if let Some(other_default) = other.default_field_limit {
            self.default_field_limit = Some(match self.default_field_limit {
                Some(cur) => cur.min(other_default),
                None => other_default,
            });
        }
        for (name, &other_limit) in &other.field_limits {
            self.field_limits
                .entry(name.clone())
                .and_modify(|cur| *cur = (*cur).min(other_limit))
                .or_insert(other_limit);
        }
    }

    /// Build a fresh `multer::Constraints` from this config.
    ///
    /// Allocates a `String` per named field limit (multer requires
    /// `Into<String>`); bounded by the small number of distinct field names
    /// users typically configure. The extractor only calls this when a
    /// `MultipartConfig` is actually present as a request extension —
    /// otherwise the parser is built with no constraints at all.
    fn to_constraints(&self) -> multer::Constraints {
        let mut limit = multer::SizeLimit::new();
        if let Some(default) = self.default_field_limit {
            limit = limit.per_field(default);
        }
        for (name, &n) in &self.field_limits {
            limit = limit.for_field(name.as_ref().to_owned(), n);
        }
        multer::Constraints::new().size_limit(limit)
    }
}

/// Extractor for `multipart/form-data` request bodies.
///
/// Iterate fields with [`Multipart::next_field`]. Per-field limits are
/// configured via [`MultipartConfig`], either inserted as a request
/// extension by a layer (the path the extractor reads) or passed to
/// [`from_body_with_config`](Self::from_body_with_config) for direct use.
/// Combine multiple configs with [`MultipartConfig::merge_floor`]; the
/// lowest limit per field wins.
///
/// `Multipart` enforces field exclusivity at compile time: each [`Field`]
/// borrows from `&mut self`, so the previous field must be dropped before the
/// next is requested.
///
/// For producing multipart bodies on the client, see
/// [`crate::service::client::multipart`].
#[derive(Debug)]
pub struct Multipart {
    inner: multer::Multipart<'static>,
}

impl Multipart {
    /// Build a `Multipart` from a body and boundary string with no per-field
    /// limits.
    pub fn from_body(body: crate::Body, boundary: impl Into<String>) -> Self {
        let stream = body.into_data_stream();
        let inner = multer::Multipart::new(stream, boundary);
        Self { inner }
    }

    /// Build a `Multipart` from a body and boundary string, applying the
    /// per-field limits in `config`. Pass `None` to skip building any
    /// `multer::Constraints` and use parser defaults.
    pub fn from_body_with_config(
        body: crate::Body,
        boundary: impl Into<String>,
        config: Option<&MultipartConfig>,
    ) -> Self {
        let stream = body.into_data_stream();
        let inner = match config {
            Some(c) => multer::Multipart::with_constraints(stream, boundary, c.to_constraints()),
            None => multer::Multipart::new(stream, boundary),
        };
        Self { inner }
    }

    /// Construct from any stream of `Result<Bytes, _>` and a boundary, with the
    /// per-field limits in `config`. Pass `None` to skip building any
    /// `multer::Constraints` and use parser defaults.
    pub fn from_stream_with_config<S, O, E, B>(
        stream: S,
        boundary: B,
        config: Option<&MultipartConfig>,
    ) -> Self
    where
        S: Stream<Item = Result<O, E>> + Send + 'static,
        O: Into<Bytes> + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
        B: Into<String>,
    {
        let inner = match config {
            Some(c) => multer::Multipart::with_constraints(stream, boundary, c.to_constraints()),
            None => multer::Multipart::new(stream, boundary),
        };
        Self { inner }
    }

    /// Yield the next [`Field`] in the multipart stream, or `None` if the
    /// stream is exhausted.
    ///
    /// The previous `Field` must be dropped before this returns; the borrow
    /// checker enforces this.
    pub async fn next_field(&mut self) -> Result<Option<Field<'_>>, MultipartError> {
        match self.inner.next_field().await {
            Ok(Some(inner)) => Ok(Some(Field {
                inner,
                _marker: PhantomData,
            })),
            Ok(None) => Ok(None),
            Err(err) => Err(MultipartError::from(err)),
        }
    }
}

/// A single field inside a [`Multipart`] stream.
///
/// `Field` borrows from `&mut Multipart`, so only one field is live at a time.
/// Read the body with [`bytes`](Self::bytes) or [`text`](Self::text), or pull
/// chunks via [`chunk`](Self::chunk) or by iterating the field as a [`Stream`].
#[derive(Debug)]
pub struct Field<'a> {
    inner: multer::Field<'static>,
    _marker: PhantomData<&'a mut Multipart>,
}

impl Field<'_> {
    /// Field name from `Content-Disposition: form-data; name="…"`.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.inner.name()
    }

    /// File name from `Content-Disposition: form-data; filename="…"`.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.inner.file_name()
    }

    /// Parsed `Content-Type` of the field, if any.
    ///
    /// Returns `None` when the part has no `Content-Type` header. Per
    /// RFC 7578 §4.4 the default in that case is `text/plain`; users that
    /// want to honor that default should substitute it themselves.
    #[must_use]
    pub fn content_type(&self) -> Option<&crate::mime::Mime> {
        self.inner.content_type()
    }

    /// Header map of this field.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    /// Index of this field within the multipart stream (0-based).
    #[must_use]
    pub fn index(&self) -> usize {
        self.inner.index()
    }

    /// Collect the entire field body as bytes.
    pub async fn bytes(self) -> Result<Bytes, MultipartError> {
        self.inner.bytes().await.map_err(MultipartError::from)
    }

    /// Collect the entire field body as a UTF-8 string. Honors a
    /// `charset` parameter on the field's `Content-Type` if present.
    pub async fn text(self) -> Result<String, MultipartError> {
        self.inner.text().await.map_err(MultipartError::from)
    }

    /// Pull the next chunk of the field body, or `None` once it is exhausted.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, MultipartError> {
        self.inner.chunk().await.map_err(MultipartError::from)
    }
}

impl Stream for Field<'_> {
    type Item = Result<Bytes, MultipartError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let inner = Pin::new(&mut this.inner);
        inner
            .try_poll_next(cx)
            .map(|opt| opt.map(|res| res.map_err(MultipartError::from)))
    }
}

/// Error type returned while reading a [`Multipart`] field.
///
/// Maps multer parser failures to suitable HTTP status codes when used as a
/// rejection: parse errors return `400 Bad Request`, size violations return
/// `413 Payload Too Large`, and unexpected stream read failures return
/// `500 Internal Server Error`.
#[derive(Debug)]
pub struct MultipartError {
    source: multer::Error,
}

impl MultipartError {
    /// HTTP status used when this error is converted into a response.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match &self.source {
            multer::Error::FieldSizeExceeded { .. } | multer::Error::StreamSizeExceeded { .. } => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            multer::Error::StreamReadFailed(_) | multer::Error::LockFailure => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => StatusCode::BAD_REQUEST,
        }
    }

    /// Body text used for the rejection response.
    #[must_use]
    pub fn body_text(&self) -> String {
        format!(
            "Failed to parse `multipart/form-data` request: {}",
            self.source
        )
    }
}

impl From<multer::Error> for MultipartError {
    fn from(source: multer::Error) -> Self {
        Self { source }
    }
}

impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error parsing `multipart/form-data` request")
    }
}

impl std::error::Error for MultipartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl crate::service::web::endpoint::IntoResponse for MultipartError {
    fn into_response(self) -> crate::Response {
        crate::utils::macros::log_http_rejection!(
            rejection_type = MultipartError,
            body_text = self.body_text(),
            status = self.status(),
        );
        (self.status(), self.body_text()).into_response()
    }
}

define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Multipart request is missing or has an invalid `Content-Type` boundary"]
    /// Rejection used when no boundary parameter is present in the
    /// `Content-Type` header (or when the header itself is missing).
    pub struct InvalidMultipartBoundary;
}

define_http_rejection! {
    #[status = UNSUPPORTED_MEDIA_TYPE]
    #[body = "Multipart requests must have `Content-Type: multipart/form-data`"]
    /// Rejection used when the `Content-Type` is not `multipart/form-data`
    /// (e.g. `multipart/mixed` or another media type entirely).
    pub struct InvalidMultipartContentType;
}

composite_http_rejection! {
    /// Rejection type for the [`Multipart`] extractor.
    pub enum MultipartRejection {
        InvalidMultipartContentType,
        InvalidMultipartBoundary,
        MultipartError,
    }
}

impl FromRequest for Multipart {
    type Rejection = MultipartRejection;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .ok_or(InvalidMultipartContentType)?;

        // RFC 7578 §4.1 requires the media type to be `multipart/form-data`.
        // `multer::parse_boundary` only checks for a `boundary=` parameter
        // and would otherwise accept `multipart/mixed`, `application/foo`,
        // etc. Reject anything else with 415.
        if !is_multipart_form_data(content_type) {
            return Err(InvalidMultipartContentType.into());
        }
        let boundary =
            multer::parse_boundary(content_type).map_err(|_| InvalidMultipartBoundary)?;

        // Look up the optional `MultipartConfig` extension via `get_arc` to
        // avoid cloning the inner field-limits map on every request. When no
        // config is set we skip building `multer::Constraints` entirely.
        let config = req.extensions().get_arc::<MultipartConfig>();
        Ok(Self::from_body_with_config(
            req.into_body(),
            boundary,
            config.as_deref(),
        ))
    }
}

fn is_multipart_form_data(content_type: &str) -> bool {
    content_type
        .parse::<crate::mime::Mime>()
        .ok()
        .is_some_and(|m| {
            m.type_() == crate::mime::MULTIPART && m.subtype() == crate::mime::FORM_DATA
        })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::StatusCode;
    use crate::service::web::WebService;
    use rama_core::Service;

    const BOUNDARY: &str = "X-RAMA-TEST-BOUNDARY";

    fn body_with(parts: &[(&str, Option<&str>, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, file_name, content_type, data) in parts {
            out.extend_from_slice(b"--");
            out.extend_from_slice(BOUNDARY.as_bytes());
            out.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b"\"");
            if let Some(fname) = file_name {
                out.extend_from_slice(b"; filename=\"");
                out.extend_from_slice(fname.as_bytes());
                out.extend_from_slice(b"\"");
            }
            out.extend_from_slice(b"\r\n");
            if let Some(ct) = content_type {
                out.extend_from_slice(b"Content-Type: ");
                out.extend_from_slice(ct.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(data);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"--");
        out.extend_from_slice(BOUNDARY.as_bytes());
        out.extend_from_slice(b"--\r\n");
        out
    }

    fn ct() -> String {
        format!("multipart/form-data; boundary={BOUNDARY}")
    }

    #[tokio::test]
    async fn test_multipart_text_and_file() {
        let service =
            WebService::default().with_post("/", async |mut mp: Multipart| -> StatusCode {
                let f1 = mp.next_field().await.unwrap().unwrap();
                assert_eq!(f1.name(), Some("name"));
                assert_eq!(f1.file_name(), None);
                assert_eq!(f1.text().await.unwrap(), "glen");

                let f2 = mp.next_field().await.unwrap().unwrap();
                assert_eq!(f2.name(), Some("avatar"));
                assert_eq!(f2.file_name(), Some("a.bin"));
                assert_eq!(
                    f2.content_type().map(|m| m.essence_str()),
                    Some("application/octet-stream")
                );
                assert_eq!(f2.bytes().await.unwrap().as_ref(), b"\x00\x01\x02");

                assert!(mp.next_field().await.unwrap().is_none());
                StatusCode::OK
            });

        let body = body_with(&[
            ("name", None, None, b"glen"),
            (
                "avatar",
                Some("a.bin"),
                Some("application/octet-stream"),
                &[0, 1, 2],
            ),
        ]);
        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .body(body.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_multipart_quoted_boundary_in_content_type() {
        // RFC 2046 §5.1.1 allows the boundary to be quoted in the
        // Content-Type header, especially when it contains characters that
        // require it. multer's parser strips the quotes; our wrapper must
        // handle it transparently.
        let service =
            WebService::default().with_post("/", async |mut mp: Multipart| -> StatusCode {
                let f = mp.next_field().await.unwrap().unwrap();
                assert_eq!(f.text().await.unwrap(), "v");
                StatusCode::OK
            });

        let body = body_with(&[("k", None, None, b"v")]);
        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(
                rama_http_types::header::CONTENT_TYPE,
                format!("multipart/form-data; boundary=\"{BOUNDARY}\""),
            )
            .body(body.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_multipart_with_preamble_and_epilogue() {
        // RFC 2046 §5.1.1 says implementations MUST ignore anything before
        // the first boundary (preamble) and after the close boundary
        // (epilogue).
        let mut body = Vec::new();
        body.extend_from_slice(b"This is a preamble that must be ignored.\r\n");
        body.extend_from_slice(&body_with(&[("k", None, None, b"v")]));
        body.extend_from_slice(b"trailing epilogue ignored\r\n");

        let service =
            WebService::default().with_post("/", async |mut mp: Multipart| -> StatusCode {
                let f = mp.next_field().await.unwrap().unwrap();
                assert_eq!(f.name(), Some("k"));
                assert_eq!(f.text().await.unwrap(), "v");
                StatusCode::OK
            });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .body(body.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_multipart_with_transport_padding() {
        // RFC 2046 §5.1.1 receivers must accept linear-whitespace transport
        // padding between the boundary delimiter and the trailing CRLF.
        // Hand-craft a body with `--boundary  \r\n` (extra spaces).
        let mut body = Vec::new();
        body.extend_from_slice(b"--");
        body.extend_from_slice(BOUNDARY.as_bytes());
        body.extend_from_slice(b"   \r\n"); // padding
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"k\"\r\n\r\n");
        body.extend_from_slice(b"v\r\n");
        body.extend_from_slice(b"--");
        body.extend_from_slice(BOUNDARY.as_bytes());
        body.extend_from_slice(b"--\t \r\n"); // padding before final CRLF

        let service =
            WebService::default().with_post("/", async |mut mp: Multipart| -> StatusCode {
                let f = mp.next_field().await.unwrap().unwrap();
                assert_eq!(f.text().await.unwrap(), "v");
                StatusCode::OK
            });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .body(body.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_multipart_filename_with_rfc5987_ext_value() {
        // RFC 7578 §4.2 explicitly forbids senders from using the RFC 5987
        // `filename*` ext-value in multipart/form-data; §5.1.3 likewise
        // doesn't list it among the encodings receivers should accept.
        // multer correspondingly does not decode `filename*` and returns
        // `None` for `file_name()` when only that form is present. Our
        // wrapper accepts the request (we don't 415/400 on it), the field
        // body is intact, and we surface multer's choice unchanged. Pin
        // this so any future change in multer or our pipeline is caught.
        let mut body = Vec::new();
        body.extend_from_slice(b"--");
        body.extend_from_slice(BOUNDARY.as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename*=UTF-8''r%C3%A9sum%C3%A9.txt\r\n",
        );
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(b"hello\r\n");
        body.extend_from_slice(b"--");
        body.extend_from_slice(BOUNDARY.as_bytes());
        body.extend_from_slice(b"--\r\n");

        let service =
            WebService::default().with_post("/", async |mut mp: Multipart| -> StatusCode {
                let f = mp.next_field().await.unwrap().unwrap();
                assert_eq!(f.name(), Some("file"));
                // multer 3.1 does not decode `filename*` — pin that.
                assert_eq!(f.file_name(), None);
                assert_eq!(f.text().await.unwrap(), "hello");
                StatusCode::OK
            });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .body(body.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_multipart_filename_utf8_passthrough() {
        // RFC 7578 §5.1.1 says senders SHOULD use UTF-8 for non-ASCII
        // names; §5.1.3 says receivers should accept unencoded UTF-8.
        // multer passes raw bytes through verbatim. Pin the exact
        // decoded value.
        let mut body = Vec::new();
        body.extend_from_slice(b"--");
        body.extend_from_slice(BOUNDARY.as_bytes());
        body.extend_from_slice(b"\r\n");
        // "résumé.txt" as raw UTF-8 in the quoted-string form.
        body.extend_from_slice(
            "Content-Disposition: form-data; name=\"file\"; filename=\"résumé.txt\"\r\n".as_bytes(),
        );
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(b"hello\r\n");
        body.extend_from_slice(b"--");
        body.extend_from_slice(BOUNDARY.as_bytes());
        body.extend_from_slice(b"--\r\n");

        let service =
            WebService::default().with_post("/", async |mut mp: Multipart| -> StatusCode {
                let f = mp.next_field().await.unwrap().unwrap();
                assert_eq!(f.name(), Some("file"));
                assert_eq!(f.file_name(), Some("résumé.txt"));
                assert_eq!(f.text().await.unwrap(), "hello");
                StatusCode::OK
            });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .body(body.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_multipart_filename_with_escaped_quote() {
        // Quote-escaped filenames in quoted-string form (`\"`).
        let mut body = Vec::new();
        body.extend_from_slice(b"--");
        body.extend_from_slice(BOUNDARY.as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(
            br#"Content-Disposition: form-data; name="file"; filename="we\"ird.txt""#,
        );
        body.extend_from_slice(b"\r\n\r\nhello\r\n");
        body.extend_from_slice(b"--");
        body.extend_from_slice(BOUNDARY.as_bytes());
        body.extend_from_slice(b"--\r\n");

        let service =
            WebService::default().with_post("/", async |mut mp: Multipart| -> StatusCode {
                let f = mp.next_field().await.unwrap().unwrap();
                assert_eq!(f.file_name(), Some("we\"ird.txt"));
                assert_eq!(f.text().await.unwrap(), "hello");
                StatusCode::OK
            });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .body(body.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_multipart_invalid_boundary() {
        let service = WebService::default().with_post("/", async |_: Multipart| StatusCode::OK);

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, "multipart/form-data")
            .body("ignored".into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_multipart_rejects_non_form_data_subtype() {
        // Regression: previously the extractor would accept any media type
        // that carried a `boundary=` parameter (e.g. multipart/mixed).
        // RFC 7578 §4.1 mandates multipart/form-data specifically.
        let service = WebService::default().with_post("/", async |_: Multipart| StatusCode::OK);

        let body = body_with(&[("k", None, None, b"v")]);
        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(
                rama_http_types::header::CONTENT_TYPE,
                format!("multipart/mixed; boundary={BOUNDARY}"),
            )
            .body(body.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_multipart_rejects_missing_content_type() {
        let service = WebService::default().with_post("/", async |_: Multipart| StatusCode::OK);
        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .body("ignored".into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_multipart_field_limit_exceeded() {
        let service = WebService::default().with_post(
            "/",
            async |mut mp: Multipart| -> Result<StatusCode, MultipartError> {
                let f = mp.next_field().await?.unwrap();
                let _ = f.bytes().await?;
                Ok(StatusCode::OK)
            },
        );

        let body = body_with(&[("blob", None, None, &[42u8; 64])]);
        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .body(body.into())
            .unwrap();
        req.extensions()
            .insert(MultipartConfig::new().with_default_field_limit(8));
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_multipart_field_as_stream_chunks() {
        let service =
            WebService::default().with_post("/", async |mut mp: Multipart| -> StatusCode {
                let mut field = mp.next_field().await.unwrap().unwrap();
                let mut total = Vec::new();
                while let Some(chunk) = field.chunk().await.unwrap() {
                    total.extend_from_slice(&chunk);
                }
                assert_eq!(total, b"hello world");
                StatusCode::OK
            });

        let body = body_with(&[("payload", None, None, b"hello world")]);
        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .body(body.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_roundtrip_with_client_form() {
        use crate::service::client::multipart as client;

        let service =
            WebService::default().with_post("/", async |mut mp: Multipart| -> StatusCode {
                let f1 = mp.next_field().await.unwrap().unwrap();
                assert_eq!(f1.name(), Some("greeting"));
                assert_eq!(f1.text().await.unwrap(), "hello world");

                let f2 = mp.next_field().await.unwrap().unwrap();
                assert_eq!(f2.name(), Some("payload"));
                assert_eq!(f2.file_name(), Some("blob.bin"));
                assert_eq!(
                    f2.content_type().map(|m| m.essence_str()),
                    Some("application/octet-stream")
                );
                assert_eq!(f2.bytes().await.unwrap().as_ref(), &[7u8, 8, 9, 10]);

                assert!(mp.next_field().await.unwrap().is_none());
                StatusCode::OK
            });

        let form = client::Form::new().text("greeting", "hello world").part(
            "payload",
            client::Part::bytes([7u8, 8, 9, 10].as_slice())
                .with_file_name("blob.bin")
                .with_mime(crate::mime::APPLICATION_OCTET_STREAM),
        );
        let content_type = form.content_type();
        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, content_type)
            .body(form.into_body())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_config_merge_floor_keeps_min() {
        let mut a = MultipartConfig::new()
            .with_default_field_limit(1024)
            .with_field_limit("avatar", 8 * 1024);
        let b = MultipartConfig::new()
            .with_default_field_limit(2048)
            .with_field_limit("avatar", 4 * 1024)
            .with_field_limit("doc", 100);
        a.merge_floor(&b);
        assert_eq!(a.default_field_limit, Some(1024));
        assert_eq!(a.field_limits.get("avatar").copied(), Some(4 * 1024));
        assert_eq!(a.field_limits.get("doc").copied(), Some(100));
    }
}
