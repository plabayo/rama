//! Server-side `multipart/form-data` extractor.
//!
//! Use [`Multipart`] as a handler argument to iterate over form fields. See
//! the `http_multipart` example for usage.
//!
//! Spec references (vendored under `rama-http/specifications/`):
//! - RFC 7578 — `multipart/form-data`
//! - RFC 2046 — MIME Part Two: Media Types (boundary framing)
//! - RFC 6266 — `Content-Disposition`
//!
//! Built on the sans-IO parser in [`crate::protocols::multipart`], which a
//! proxy can use directly to rewrite a form as it streams by.
//!
//! The body is parsed as it streams in and field data is handed out as slices
//! of the body chunks, without buffering or copying it.
//!
//! Framing is strict wherever leniency would leave room for two parsers to
//! read one body differently: lines end in CRLF, header lines are not folded,
//! a line opening with the delimiter is a delimiter, and a body has to reach
//! its close delimiter. Transport padding after a boundary is accepted, the
//! preamble and epilogue are ignored (RFC 2046 §5.1.1).
//!
//! Names and file names are UTF-8, taken from a token or quoted string as
//! sent: percent-encoding and RFC 2047 encoded-words are not decoded, and
//! `filename*` is ignored (RFC 7578 §4.2). A file name is client input and can
//! hold a path, never use it as one.

use crate::Request;
use crate::mime::{self, Mime};
use crate::protocols::multipart::{Boundary, Event, FormData, InvalidBoundary, ParseError, Parser};
use crate::service::web::extract::{FromRequest, FromRequestBody};
use crate::utils::macros::{composite_http_rejection, define_http_rejection};
use ahash::HashMap;
use rama_core::bytes::{Bytes, BytesMut};
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorExt as _, error_chain};
use rama_core::extensions::Extension;
use rama_core::futures::Stream;
use rama_http_types::{
    HeaderMap, StatusCode,
    body::{BodyDataStream, util::LengthLimitError},
    header::{CONTENT_TYPE, content_type::parse_mime_type},
};
use rama_utils::macros::generate_set_and_with;
use std::borrow::Cow;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

/// Per-field size and part-count constraints for [`Multipart`].
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
#[derive(Debug, Clone, Extension)]
#[extension(tags(http))]
pub struct MultipartConfig {
    default_field_limit: Option<u64>,
    field_limits: HashMap<Cow<'static, str>, u64>,
    max_parts: Option<usize>,
}

impl Default for MultipartConfig {
    fn default() -> Self {
        Self {
            default_field_limit: None,
            field_limits: HashMap::default(),
            max_parts: Some(Self::DEFAULT_MAX_PARTS),
        }
    }
}

impl MultipartConfig {
    /// Default maximum number of parts in a [`Multipart`] stream.
    pub const DEFAULT_MAX_PARTS: usize = 1000;

    /// Create a config without per-field byte limits and with the
    /// [default part limit](MultipartConfig::DEFAULT_MAX_PARTS).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Maximum number of parts accepted in one stream, `None` for no limit.
        ///
        /// Every part counts, whatever its name, content or position. The part
        /// past the limit is rejected once its headers are read, before its body.
        ///
        /// Defaults to [`Self::DEFAULT_MAX_PARTS`].
        pub fn max_parts(mut self, max: Option<usize>) -> Self {
            self.max_parts = max;
            self
        }
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
        if let Some(other_max) = other.max_parts {
            self.max_parts = Some(match self.max_parts {
                Some(cur) => cur.min(other_max),
                None => other_max,
            });
        }
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

    /// Byte limit of the field with the given name.
    fn field_limit(&self, name: Option<&str>) -> Option<u64> {
        name.and_then(|name| self.field_limits.get(name).copied())
            .or(self.default_field_limit)
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
/// An error ends the stream: every later read fails the same way.
///
/// For producing multipart bodies on the client, see
/// [`crate::service::client::multipart`].
#[derive(Debug)]
pub struct Multipart {
    body: BodyDataStream,
    /// `None` when the boundary cannot frame a body, with `failed` set to match.
    parser: Option<Parser>,
    config: Option<Arc<MultipartConfig>>,
    max_parts: Option<usize>,
    parts_seen: usize,
    /// Whether the data of the part opened last is still being read.
    in_field: bool,
    field_limit: Option<u64>,
    field_read: u64,
    failed: Option<MultipartErrorKind>,
}

impl Multipart {
    /// Build a `Multipart` from a body and boundary string with no per-field
    /// limits and the [default part limit](MultipartConfig::DEFAULT_MAX_PARTS).
    pub fn from_body(body: crate::Body, boundary: impl AsRef<[u8]>) -> Self {
        Self::from_body_with_config(body, boundary, None)
    }

    /// Build a `Multipart` from a body and boundary string, applying the
    /// limits in `config`. Pass `None` for no per-field limits and the
    /// [default part limit](MultipartConfig::DEFAULT_MAX_PARTS).
    ///
    /// A boundary that cannot frame a body fails the first read.
    pub fn from_body_with_config(
        body: crate::Body,
        boundary: impl AsRef<[u8]>,
        config: Option<&MultipartConfig>,
    ) -> Self {
        Self::new(body, Boundary::new(boundary), config.cloned().map(Arc::new))
    }

    /// Construct from any stream of `Result<Bytes, _>` and a boundary, with the
    /// limits in `config`. Pass `None` for no per-field limits and the
    /// [default part limit](MultipartConfig::DEFAULT_MAX_PARTS).
    ///
    /// A boundary that cannot frame a body fails the first read.
    pub fn from_stream_with_config<S, O, E>(
        stream: S,
        boundary: impl AsRef<[u8]>,
        config: Option<&MultipartConfig>,
    ) -> Self
    where
        S: Stream<Item = Result<O, E>> + Send + 'static,
        O: Into<Bytes> + 'static,
        E: Into<BoxError> + 'static,
    {
        Self::from_body_with_config(crate::Body::from_stream(stream), boundary, config)
    }

    fn new(
        body: crate::Body,
        boundary: Result<Boundary, InvalidBoundary>,
        config: Option<Arc<MultipartConfig>>,
    ) -> Self {
        let parser = boundary.ok().map(|boundary| Parser::new(&boundary));
        Self {
            body: body.into_data_stream(),
            failed: parser
                .is_none()
                .then_some(MultipartErrorKind::InvalidBoundary),
            parser,
            max_parts: match &config {
                Some(config) => config.max_parts,
                None => Some(MultipartConfig::DEFAULT_MAX_PARTS),
            },
            config,
            parts_seen: 0,
            in_field: false,
            field_limit: None,
            field_read: 0,
        }
    }

    /// Yield the next [`Field`] in the multipart stream, or `None` if the
    /// stream is exhausted.
    ///
    /// What is left unread of the previous field is skipped, and still counts
    /// toward its byte limit.
    ///
    /// Fails once the stream holds more parts than the configured maximum,
    /// and keeps failing on later calls.
    ///
    /// The previous `Field` must be dropped before this returns; the borrow
    /// checker enforces this.
    pub async fn next_field(&mut self) -> Result<Option<Field<'_>>, MultipartError> {
        while poll_fn(|cx| self.poll_chunk(cx)).await?.is_some() {}

        // the parser opens a part or ends the stream once the previous part is done
        let Event::Part(headers) = poll_fn(|cx| self.poll_event(cx)).await? else {
            return Ok(None);
        };

        self.parts_seen = self.parts_seen.saturating_add(1);
        if let Some(max) = self.max_parts
            && self.parts_seen > max
        {
            return Err(self.fail(MultipartErrorKind::TooManyParts, None));
        }

        let Ok(disposition) = FormData::from_headers(&headers) else {
            return Err(self.fail(MultipartErrorKind::InvalidContentDisposition, None));
        };
        let content_type = match read_content_type(&headers) {
            Ok(content_type) => content_type,
            Err(kind) => return Err(self.fail(kind, None)),
        };

        self.in_field = true;
        self.field_read = 0;
        self.field_limit = self
            .config
            .as_deref()
            .and_then(|config| config.field_limit(disposition.name()));
        let (name, file_name) = disposition.into_parts();

        Ok(Some(Field {
            index: self.parts_seen - 1,
            multipart: self,
            headers,
            name,
            file_name,
            content_type,
        }))
    }

    /// Drive the parser to its next event, reading the body as it asks for input.
    fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, MultipartError>> {
        if let Some(kind) = self.failed {
            return Poll::Ready(Err(kind.into()));
        }
        let Some(parser) = &mut self.parser else {
            return Poll::Ready(Err(MultipartErrorKind::InvalidBoundary.into()));
        };
        loop {
            match parser.step() {
                Ok(Event::NeedInput) => match ready!(Pin::new(&mut self.body).poll_next(cx)) {
                    Some(Ok(chunk)) => parser.feed(chunk),
                    Some(Err(err)) => {
                        let kind = if is_size_limit_error(&err) {
                            MultipartErrorKind::BodyTooLarge
                        } else {
                            MultipartErrorKind::Stream
                        };
                        return Poll::Ready(Err(self.fail(kind, Some(err))));
                    }
                    None => parser.set_eof(),
                },
                Ok(event) => return Poll::Ready(Ok(event)),
                Err(err) => {
                    return Poll::Ready(Err(self.fail(MultipartErrorKind::Parse(err), None)));
                }
            }
        }
    }

    /// Next chunk of the open field, `None` once its data is read in full.
    fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, MultipartError>> {
        if !self.in_field {
            if let Some(kind) = self.failed {
                return Poll::Ready(Err(kind.into()));
            }
            return Poll::Ready(Ok(None));
        }
        // a part's data is followed by nothing but the end of that part
        let Event::Data(data) = ready!(self.poll_event(cx))? else {
            self.in_field = false;
            return Poll::Ready(Ok(None));
        };
        self.field_read = self.field_read.saturating_add(data.len() as u64);
        if let Some(limit) = self.field_limit
            && self.field_read > limit
        {
            let source = BoxError::from_static_str("multipart field exceeds its limit")
                .context_field("limit", limit);
            return Poll::Ready(Err(
                self.fail(MultipartErrorKind::FieldTooLarge, Some(source))
            ));
        }
        Poll::Ready(Ok(Some(data)))
    }

    fn fail(&mut self, kind: MultipartErrorKind, source: Option<BoxError>) -> MultipartError {
        self.failed = Some(kind);
        self.in_field = false;
        MultipartError { kind, source }
    }
}

fn read_content_type(headers: &HeaderMap) -> Result<Option<Mime>, MultipartErrorKind> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    match (values.next(), values.next()) {
        (None, _) => Ok(None),
        (Some(value), None) => Ok(value.to_str().ok().and_then(|value| value.parse().ok())),
        (Some(_), Some(_)) => Err(MultipartErrorKind::DuplicateContentType),
    }
}

/// A single field inside a [`Multipart`] stream.
///
/// `Field` borrows from `&mut Multipart`, so only one field is live at a time.
/// Read the body with [`bytes`](Self::bytes) or [`text`](Self::text), or pull
/// chunks via [`chunk`](Self::chunk) or by iterating the field as a [`Stream`].
#[derive(Debug)]
pub struct Field<'a> {
    multipart: &'a mut Multipart,
    headers: HeaderMap,
    name: Option<Box<str>>,
    file_name: Option<Box<str>>,
    content_type: Option<Mime>,
    index: usize,
}

impl Field<'_> {
    /// Field name from `Content-Disposition: form-data; name="…"`.
    ///
    /// `None` when the part has no `Content-Disposition` header or the header
    /// has no `name` parameter.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// File name from `Content-Disposition: form-data; filename="…"`.
    ///
    /// This is the value the client sent, which can be a full path or hold
    /// `..` segments.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.file_name.as_deref()
    }

    /// Parsed `Content-Type` of the field, if any.
    ///
    /// Returns `None` when the part has no `Content-Type` header. Per
    /// RFC 7578 §4.4 the default in that case is `text/plain`; users that
    /// want to honor that default should substitute it themselves.
    #[must_use]
    pub fn content_type(&self) -> Option<&Mime> {
        self.content_type.as_ref()
    }

    /// Header map of this field.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Index of this field within the multipart stream (0-based).
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    /// Collect the entire field body as bytes.
    pub async fn bytes(mut self) -> Result<Bytes, MultipartError> {
        let Some(first) = self.chunk().await? else {
            return Ok(Bytes::new());
        };
        // a field within one body chunk is handed out as is
        let Some(second) = self.chunk().await? else {
            return Ok(first);
        };
        let mut collected = BytesMut::with_capacity(first.len() + second.len());
        collected.extend_from_slice(&first);
        collected.extend_from_slice(&second);
        while let Some(chunk) = self.chunk().await? {
            collected.extend_from_slice(&chunk);
        }
        Ok(collected.freeze())
    }

    /// Collect the entire field body as a UTF-8 string.
    ///
    /// Fails when the body is not UTF-8, or when the `charset` parameter on
    /// the field's `Content-Type` names another encoding; read such a field
    /// with [`bytes`](Self::bytes) and decode it as needed. Such a failure
    /// leaves the stream usable: the next field can still be read.
    pub async fn text(self) -> Result<String, MultipartError> {
        let is_utf8 = self
            .content_type
            .as_ref()
            .and_then(|content_type| content_type.get_param(mime::CHARSET))
            .is_none_or(|charset| charset == mime::UTF_8 || charset == "us-ascii");
        if !is_utf8 {
            return Err(MultipartErrorKind::InvalidText.into());
        }
        let bytes = self.bytes().await?;
        String::from_utf8(bytes.into()).map_err(|_e| MultipartErrorKind::InvalidText.into())
    }

    /// Pull the next chunk of the field body, or `None` once it is exhausted.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, MultipartError> {
        poll_fn(|cx| self.multipart.poll_chunk(cx)).await
    }
}

impl Stream for Field<'_> {
    type Item = Result<Bytes, MultipartError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut()
            .multipart
            .poll_chunk(cx)
            .map(Result::transpose)
    }
}

/// Error type returned while reading a [`Multipart`] field.
///
/// Maps to an HTTP status when used as a rejection: a malformed body returns
/// `400 Bad Request`, size and part-count violations return
/// `413 Payload Too Large`, and unexpected stream read failures return
/// `500 Internal Server Error`.
#[derive(Debug)]
pub struct MultipartError {
    kind: MultipartErrorKind,
    source: Option<BoxError>,
}

#[derive(Debug, Clone, Copy)]
enum MultipartErrorKind {
    Parse(ParseError),
    InvalidBoundary,
    InvalidContentDisposition,
    DuplicateContentType,
    InvalidText,
    FieldTooLarge,
    TooManyParts,
    /// The body stream failed on a size limit of its own.
    BodyTooLarge,
    Stream,
}

impl MultipartErrorKind {
    fn reason(self) -> &'static str {
        match self {
            Self::Parse(ParseError::Incomplete) => "body ended before its close delimiter",
            Self::Parse(ParseError::InvalidDelimiter) => "malformed delimiter line",
            Self::Parse(ParseError::HeadersTooLarge) => "part headers are too large",
            Self::Parse(_) => "malformed part headers",
            Self::InvalidBoundary => "invalid boundary",
            Self::InvalidContentDisposition => "invalid part `Content-Disposition`",
            Self::DuplicateContentType => "part has more than one `Content-Type`",
            Self::InvalidText => "field is not UTF-8 text",
            Self::FieldTooLarge => "field exceeds its size limit",
            Self::TooManyParts => "too many parts",
            Self::BodyTooLarge => "body exceeds its size limit",
            Self::Stream => "failed to read the body",
        }
    }
}

impl From<MultipartErrorKind> for MultipartError {
    fn from(kind: MultipartErrorKind) -> Self {
        Self { kind, source: None }
    }
}

impl MultipartError {
    /// HTTP status used when this error is converted into a response.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self.kind {
            MultipartErrorKind::FieldTooLarge
            | MultipartErrorKind::TooManyParts
            | MultipartErrorKind::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            MultipartErrorKind::Stream => StatusCode::INTERNAL_SERVER_ERROR,
            MultipartErrorKind::Parse(_)
            | MultipartErrorKind::InvalidBoundary
            | MultipartErrorKind::InvalidContentDisposition
            | MultipartErrorKind::DuplicateContentType
            | MultipartErrorKind::InvalidText => StatusCode::BAD_REQUEST,
        }
    }

    /// Body text used for the rejection response.
    #[must_use]
    pub fn body_text(&self) -> String {
        match self.kind {
            MultipartErrorKind::TooManyParts => {
                "Request has too many `multipart/form-data` parts".to_owned()
            }
            MultipartErrorKind::FieldTooLarge | MultipartErrorKind::BodyTooLarge => {
                "Request payload is too large".to_owned()
            }
            kind => [
                "Failed to parse `multipart/form-data` request: ",
                kind.reason(),
            ]
            .concat(),
        }
    }
}

// Size errors can arrive wrapped, e.g. from a nested multipart stream or a limited body.
fn is_size_limit_error(error: &BoxError) -> bool {
    error_chain(error.as_ref()).any(|cause| {
        cause.is::<LengthLimitError>()
            || cause
                .downcast_ref::<MultipartError>()
                .is_some_and(|nested| nested.status() == StatusCode::PAYLOAD_TOO_LARGE)
    })
}

impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error parsing `multipart/form-data` request: {}",
            self.kind.reason()
        )
    }
}

impl std::error::Error for MultipartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match (&self.source, &self.kind) {
            (Some(source), _) => Some(source.as_ref()),
            (None, MultipartErrorKind::Parse(err)) => Some(err),
            (None, _) => None,
        }
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
    /// Rejection used when the `Content-Type` header has no usable boundary
    /// parameter: none, more than one, or one that cannot frame a body.
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
        let (parts, body) = req.into_parts();
        let future = Self::from_request_body(&parts, body);
        future.await
    }
}

/// The boundary framing a `multipart/form-data` body of the given type.
///
/// The type holds the first of repeated parameters, as every request gate reads it. A
/// `boundary*` is rejected: it leaves room for another reader of the request to frame the
/// body differently.
fn read_boundary(content_type: &Mime) -> Result<Boundary, InvalidMultipartBoundary> {
    if content_type.get_param("boundary*").is_some() {
        return Err(InvalidMultipartBoundary);
    }
    let boundary = content_type
        .get_param(mime::BOUNDARY)
        .ok_or(InvalidMultipartBoundary)?;
    Boundary::new(boundary.as_str()).map_err(|_e| InvalidMultipartBoundary)
}

impl FromRequestBody for Multipart {
    fn from_request_body(
        parts: &crate::request::Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        let prepared: Result<_, MultipartRejection> = (|| {
            // The whole value as one type, as every request gate reads it.
            let content_type = parse_mime_type(parts.headers.get_all(CONTENT_TYPE))
                .ok_or(InvalidMultipartContentType)?;

            // RFC 7578 §4.1 requires the media type to be `multipart/form-data`.
            if content_type.type_() != mime::MULTIPART || content_type.subtype() != mime::FORM_DATA
            {
                return Err(InvalidMultipartContentType.into());
            }
            let boundary = read_boundary(&content_type)?;

            // `get_arc` shares the config instead of cloning its field-limits map per request.
            let config = parts.extensions.get_arc::<MultipartConfig>();
            Ok((boundary, config))
        })();

        async move {
            let (boundary, config) = prepared?;
            Ok(Self::new(body, Ok(boundary), config))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::StatusCode;
    use crate::body::util::BodyExt;
    use crate::service::web::WebService;
    use rama_core::Service;
    use rama_core::extensions::ExtensionsRef;
    use rama_core::futures::StreamExt as _;
    use rama_utils::octets::kib_u64;

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

    /// The type and boundary come from the whole value as one type, as the CORS safelist reads
    /// it: what a browser sends cross-site as `text/plain` is never multipart.
    #[tokio::test]
    async fn test_multipart_content_type_is_the_whole_value() {
        let service =
            WebService::default().with_post("/", async |mut mp: Multipart| -> StatusCode {
                match mp.next_field().await {
                    Ok(Some(field)) if field.name() == Some("name") => StatusCode::OK,
                    _ => StatusCode::BAD_REQUEST,
                }
            });
        for (lines, status) in [
            (vec![ct()], StatusCode::OK),
            (
                vec![format!("text/plain;,{}", ct())],
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            // The first type's boundary runs on into the next line: not the one framing the body.
            (
                vec!["multipart/form-data; boundary=wrong".to_owned(), ct()],
                StatusCode::BAD_REQUEST,
            ),
            (vec![ct(), "text/plain".to_owned()], StatusCode::BAD_REQUEST),
        ] {
            let mut req = crate::Request::builder().method(crate::Method::POST);
            for line in &lines {
                req = req.header(crate::header::CONTENT_TYPE, line);
            }
            let req = req
                .body(body_with(&[("name", None, None, b"glen")]).into())
                .unwrap();
            let resp = service.serve(req).await.unwrap();
            assert_eq!(resp.status(), status, "{lines:?}");
        }
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
    async fn test_multipart_composes_after_owned_headers() {
        let service = WebService::default().with_post(
            "/",
            async |headers: HeaderMap, mut multipart: Multipart| -> StatusCode {
                assert_eq!(headers.get("x-request-id").unwrap(), "multipart-test");

                let field = multipart.next_field().await.unwrap().unwrap();
                assert_eq!(field.name(), Some("message"));
                assert_eq!(field.text().await.unwrap(), "body remains available");
                assert!(multipart.next_field().await.unwrap().is_none());

                StatusCode::OK
            },
        );

        let request = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .header("x-request-id", "multipart-test")
            .body(body_with(&[("message", None, None, b"body remains available")]).into())
            .unwrap();

        let response = service.serve(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_multipart_quoted_boundary_in_content_type() {
        // RFC 2046 §5.1.1 allows the boundary to be quoted in the
        // Content-Type header, especially when it contains characters that
        // require it. The quotes are not part of the boundary.
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
        // `filename*` is not decoded: `file_name()` is `None` when only that
        // form is present, the request is accepted and the field body is intact.
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
        // The raw bytes pass through verbatim.
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
            async |mut mp: Multipart| -> Result<StatusCode, MultipartRejection> {
                let f = mp.next_field().await?.unwrap();
                _ = f.bytes().await?;
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
        assert_eq!(
            resp.into_body().collect().await.unwrap().to_bytes(),
            "Request payload is too large"
        );
    }

    #[tokio::test]
    async fn test_application_body_limit_returns_payload_too_large() {
        use crate::layer::body_limit::BodyLimitLayer;
        use rama_core::Layer;

        let service = BodyLimitLayer::new(8).layer(WebService::default().with_post(
            "/",
            async |mut mp: Multipart| -> Result<StatusCode, MultipartRejection> {
                let field = mp.next_field().await?.unwrap();
                _ = field.bytes().await?;
                Ok(StatusCode::OK)
            },
        ));

        let body = body_with(&[("blob", None, None, &[42u8; 64])]);
        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .body(crate::Body::from(body))
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            resp.into_body().collect().await.unwrap().to_bytes(),
            "Request payload is too large"
        );
    }

    #[tokio::test]
    async fn test_stream_read_failure_returns_internal_server_error() {
        let service = WebService::default().with_post(
            "/",
            async |mut mp: Multipart| -> Result<StatusCode, MultipartRejection> {
                _ = mp.next_field().await?;
                Ok(StatusCode::OK)
            },
        );

        let body = crate::Body::from_stream(rama_core::futures::stream::once(async {
            Err::<rama_core::bytes::Bytes, _>(std::io::Error::other("body read failed"))
        }));
        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .body(body)
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Status of a read whose body stream fails with `error`.
    async fn stream_error_status(error: BoxError) -> (StatusCode, String) {
        let stream = rama_core::futures::stream::once(async { Err::<Bytes, _>(error) });
        let mut mp = Multipart::from_stream_with_config(stream, BOUNDARY, None);
        let error = mp.next_field().await.unwrap_err();
        (error.status(), error.body_text())
    }

    /// An error as the body stream of an outer `Multipart` would report it for `inner`.
    fn nested(inner: impl Into<BoxError>) -> BoxError {
        MultipartError {
            kind: MultipartErrorKind::Stream,
            source: Some(inner.into()),
        }
        .into()
    }

    #[tokio::test]
    async fn test_size_limit_anywhere_in_error_chain_returns_payload_too_large() {
        let field = || MultipartError::from(MultipartErrorKind::FieldTooLarge);
        let parts = || MultipartError::from(MultipartErrorKind::TooManyParts);
        for error in [
            field().into(),
            parts().into(),
            nested(field()),
            nested(nested(parts())),
            nested(LengthLimitError::default()),
        ] {
            let (status, text) = stream_error_status(error).await;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(text, "Request payload is too large");
        }

        for error in [
            BoxError::from(std::io::Error::other("read failed")),
            nested(std::io::Error::other("read failed")),
            MultipartError::from(MultipartErrorKind::Parse(ParseError::Incomplete)).into(),
        ] {
            let (status, _) = stream_error_status(error).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        }
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
            .with_field_limit("avatar", kib_u64(8))
            .without_max_parts();
        let b = MultipartConfig::new()
            .with_default_field_limit(2048)
            .with_field_limit("avatar", kib_u64(4))
            .with_field_limit("doc", 100)
            .with_max_parts(10);
        a.merge_floor(&b);
        assert_eq!(a.default_field_limit, Some(1024));
        assert_eq!(a.field_limits.get("avatar").copied(), Some(kib_u64(4)));
        assert_eq!(a.field_limits.get("doc").copied(), Some(100));
        assert_eq!(a.max_parts, Some(10));

        a.merge_floor(&MultipartConfig::new().without_max_parts());
        assert_eq!(a.max_parts, Some(10));
        a.merge_floor(&MultipartConfig::new().with_max_parts(5));
        assert_eq!(a.max_parts, Some(5));
    }

    /// Empty, duplicate and file parts alike, so every kind of part is counted.
    fn body_with_part_count(count: usize) -> Vec<u8> {
        let kinds: [(&str, Option<&str>, Option<&str>, &[u8]); 3] = [
            ("dup", None, None, b""),
            ("dup", None, None, b"value"),
            (
                "file",
                Some("a.bin"),
                Some("application/octet-stream"),
                b"\x00",
            ),
        ];
        let parts: Vec<_> = kinds.into_iter().cycle().take(count).collect();
        body_with(&parts)
    }

    fn part_counting_service() -> WebService {
        WebService::default().with_post(
            "/",
            async |mut mp: Multipart| -> Result<String, MultipartRejection> {
                let mut count = 0usize;
                while mp.next_field().await?.is_some() {
                    count += 1;
                }
                Ok(count.to_string())
            },
        )
    }

    async fn post_parts(count: usize, config: Option<MultipartConfig>) -> (StatusCode, Bytes) {
        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, ct())
            .body(body_with_part_count(count).into())
            .unwrap();
        if let Some(config) = config {
            req.extensions().insert(config);
        }
        let resp = part_counting_service().serve(req).await.unwrap();
        let status = resp.status();
        (status, resp.into_body().collect().await.unwrap().to_bytes())
    }

    #[tokio::test]
    async fn test_multipart_default_part_limit() {
        let max = MultipartConfig::DEFAULT_MAX_PARTS;
        for config in [None, Some(MultipartConfig::new())] {
            assert_eq!(
                post_parts(max, config.clone()).await,
                (StatusCode::OK, Bytes::from(max.to_string()))
            );
            assert_eq!(
                post_parts(max + 1, config).await,
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Bytes::from_static(b"Request has too many `multipart/form-data` parts")
                )
            );
        }
    }

    #[tokio::test]
    async fn test_multipart_custom_part_limit() {
        let config = MultipartConfig::new().with_max_parts(3);
        assert_eq!(
            post_parts(3, Some(config.clone())).await,
            (StatusCode::OK, Bytes::from_static(b"3"))
        );
        assert_eq!(
            post_parts(4, Some(config)).await.0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn test_multipart_unlimited_parts() {
        let config = MultipartConfig::new().without_max_parts();
        let count = MultipartConfig::DEFAULT_MAX_PARTS + 50;
        assert_eq!(
            post_parts(count, Some(config)).await,
            (StatusCode::OK, Bytes::from(count.to_string()))
        );
    }

    #[tokio::test]
    async fn test_multipart_part_limit_rejects_before_reading_the_body() {
        let mut head = body_with(&[("a", None, None, b"1"), ("b", None, None, b"2")]);
        // drop the close delimiter, then open a third part whose body never arrives
        head.truncate(head.len() - BOUNDARY.len() - 6);
        head.extend_from_slice(b"--");
        head.extend_from_slice(BOUNDARY.as_bytes());
        head.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\n");
        // the extra part's body never arrives, so a body read would hang
        let stream = rama_core::futures::stream::iter([Ok::<_, std::io::Error>(Bytes::from(head))])
            .chain(rama_core::futures::stream::pending());
        let config = MultipartConfig::new().with_max_parts(2);
        let mut mp = Multipart::from_stream_with_config(stream, BOUNDARY, Some(&config));

        for _ in 0..2 {
            assert!(mp.next_field().await.unwrap().is_some());
        }
        let error = mp.next_field().await.unwrap_err();
        assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
        // the limit keeps holding once exceeded
        let error = mp.next_field().await.unwrap_err();
        assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// A body of parts given as `(header lines, data)`.
    fn raw_body(parts: &[(&[&str], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (lines, data) in parts {
            out.extend_from_slice(b"--");
            out.extend_from_slice(BOUNDARY.as_bytes());
            out.extend_from_slice(b"\r\n");
            for line in *lines {
                out.extend_from_slice(line.as_bytes());
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

    /// A `Multipart` over `body` arriving in chunks of `size` bytes.
    fn chunked(body: &[u8], size: usize, config: Option<&MultipartConfig>) -> Multipart {
        let chunks: Vec<_> = body
            .chunks(size)
            .map(|chunk| Ok::<_, std::io::Error>(Bytes::copy_from_slice(chunk)))
            .collect();
        Multipart::from_stream_with_config(
            rama_core::futures::stream::iter(chunks),
            BOUNDARY,
            config,
        )
    }

    type Collected = (Option<String>, Option<String>, Option<String>, usize, Bytes);

    async fn collect(mut mp: Multipart) -> Result<Vec<Collected>, MultipartError> {
        let mut fields = Vec::new();
        while let Some(field) = mp.next_field().await? {
            fields.push((
                field.name().map(ToOwned::to_owned),
                field.file_name().map(ToOwned::to_owned),
                field.content_type().map(ToString::to_string),
                field.index(),
                field.bytes().await?,
            ));
        }
        Ok(fields)
    }

    #[tokio::test]
    async fn test_multipart_reads_the_same_at_every_chunk_size() {
        let mut large = Vec::new();
        for n in 0..2000u32 {
            large.extend_from_slice(b"\r\n--");
            large.extend_from_slice(&BOUNDARY.as_bytes()[..(n as usize) % BOUNDARY.len()]);
            large.extend_from_slice(&n.to_be_bytes());
        }
        let body = body_with(&[
            ("text", None, None, b"hello"),
            ("empty", None, None, b""),
            (
                "file",
                Some("a.bin"),
                Some("application/octet-stream"),
                &large,
            ),
            (
                "lines",
                None,
                Some("text/plain; charset=utf-8"),
                b"\r\n\r\n",
            ),
        ]);

        let whole = collect(chunked(&body, body.len(), None)).await.unwrap();
        assert_eq!(whole.len(), 4);
        assert_eq!(whole[0].0.as_deref(), Some("text"));
        assert_eq!(whole[1].4, Bytes::new());
        assert_eq!(whole[2].1.as_deref(), Some("a.bin"));
        assert_eq!(whole[2].2.as_deref(), Some("application/octet-stream"));
        assert_eq!(whole[2].4, large);
        assert_eq!(whole[3].3, 3);
        assert_eq!(&whole[3].4[..], b"\r\n\r\n");

        for size in [1, 2, 3, 7, 31, 64, 1021, 4096] {
            let split = collect(chunked(&body, size, None)).await.unwrap();
            assert_eq!(split, whole, "chunks of {size}");
        }
    }

    #[tokio::test]
    async fn test_multipart_field_limit_is_exact() {
        let config = MultipartConfig::new().with_field_limit("a", 5);
        for size in [1, 4, 1024] {
            let fits = body_with(&[("a", None, None, b"12345"), ("b", None, None, b"123456")]);
            let fields = collect(chunked(&fits, size, Some(&config))).await.unwrap();
            assert_eq!(fields.len(), 2, "chunks of {size}");

            let over = body_with(&[("a", None, None, b"123456")]);
            let error = collect(chunked(&over, size, Some(&config)))
                .await
                .unwrap_err();
            assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(error.body_text(), "Request payload is too large");
        }
    }

    #[tokio::test]
    async fn test_multipart_skipped_field_counts_toward_its_limit() {
        let config = MultipartConfig::new().with_field_limit("a", 5);
        let body = body_with(&[("a", None, None, b"123456"), ("b", None, None, b"v")]);
        for size in [1, 1024] {
            let mut mp = chunked(&body, size, Some(&config));
            drop(mp.next_field().await.unwrap().unwrap());
            let error = mp.next_field().await.unwrap_err();
            assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    #[tokio::test]
    async fn test_multipart_partially_read_field_is_skipped() {
        let body = body_with(&[("a", None, None, &[b'x'; 300]), ("b", None, None, b"v")]);
        let mut mp = chunked(&body, 16, None);
        let mut field = mp.next_field().await.unwrap().unwrap();
        assert!(field.chunk().await.unwrap().is_some());
        drop(field);
        let field = mp.next_field().await.unwrap().unwrap();
        assert_eq!(field.name(), Some("b"));
        assert_eq!(field.text().await.unwrap(), "v");
        assert!(mp.next_field().await.unwrap().is_none());
        assert!(mp.next_field().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_multipart_errors_repeat() {
        let mut body = body_with(&[("a", None, None, b"1"), ("b", None, None, b"2")]);
        // drop the close delimiter
        body.truncate(body.len() - BOUNDARY.len() - 6);
        for size in [1, 1024] {
            let mut mp = chunked(&body, size, None);
            let field = mp.next_field().await.unwrap().unwrap();
            assert_eq!(field.text().await.unwrap(), "1");
            let mut field = mp.next_field().await.unwrap().unwrap();
            // the data seen so far may still turn out to open a delimiter
            let error = loop {
                match field.chunk().await {
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("field ended without its delimiter"),
                    Err(error) => break error,
                }
            };
            assert_eq!(error.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                error.body_text(),
                "Failed to parse `multipart/form-data` request: body ended before its close delimiter"
            );
            assert_eq!(
                field.chunk().await.unwrap_err().status(),
                StatusCode::BAD_REQUEST
            );
            drop(field);
            for _ in 0..2 {
                let error = mp.next_field().await.unwrap_err();
                assert_eq!(error.status(), StatusCode::BAD_REQUEST);
            }
        }
    }

    #[tokio::test]
    async fn test_multipart_invalid_boundary_fails_every_read() {
        for boundary in [
            "",
            "ends with space ",
            "line\nbreak",
            "caf\u{e9}",
            &"x".repeat(71),
        ] {
            let mut mp = Multipart::from_body(crate::Body::from("--x--\r\n"), boundary);
            for _ in 0..2 {
                let error = mp.next_field().await.unwrap_err();
                assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{boundary:?}");
                assert_eq!(
                    error.body_text(),
                    "Failed to parse `multipart/form-data` request: invalid boundary"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_multipart_boundary_parameter_rules() {
        let service =
            WebService::default().with_post("/", async |mut mp: Multipart| -> StatusCode {
                match mp.next_field().await {
                    Ok(Some(_)) => StatusCode::OK,
                    _ => StatusCode::IM_A_TEAPOT,
                }
            });
        for (content_type, status) in [
            (ct(), StatusCode::OK),
            // the first of repeated parameters is the one in use
            (
                format!("multipart/form-data; boundary={BOUNDARY}; BOUNDARY=other"),
                StatusCode::OK,
            ),
            (
                format!("multipart/form-data; boundary=other; boundary={BOUNDARY}"),
                StatusCode::IM_A_TEAPOT,
            ),
            (
                format!("multipart/form-data; boundary*=utf-8''other; boundary={BOUNDARY}"),
                StatusCode::BAD_REQUEST,
            ),
            (
                format!("multipart/form-data; boundary={BOUNDARY}; boundary*=utf-8''other"),
                StatusCode::BAD_REQUEST,
            ),
            (
                "multipart/form-data; boundary=\"\"".to_owned(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "multipart/form-data; boundary=\"ends with space \"".to_owned(),
                StatusCode::BAD_REQUEST,
            ),
            (
                format!("multipart/form-data; boundary={}", "x".repeat(71)),
                StatusCode::BAD_REQUEST,
            ),
            (
                "multipart/form-data; charset=utf-8".to_owned(),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let req = rama_http_types::Request::builder()
                .method(rama_http_types::Method::POST)
                .header(rama_http_types::header::CONTENT_TYPE, &content_type)
                .body(body_with(&[("a", None, None, b"v")]).into())
                .unwrap();
            let resp = service.serve(req).await.unwrap();
            assert_eq!(resp.status(), status, "{content_type:?}");
        }
    }

    #[tokio::test]
    async fn test_multipart_part_header_rules() {
        let rejected: [&[&str]; 5] = [
            &[
                "Content-Disposition: form-data; name=\"a\"",
                "Content-Disposition: form-data; name=\"b\"",
            ],
            &["Content-Disposition: attachment; name=\"a\""],
            &["Content-Disposition: form-data; name=\"a\"; name=\"b\""],
            &["Content-Disposition: form-data; name=\"a"],
            &[
                "Content-Disposition: form-data; name=\"a\"",
                "Content-Type: text/plain",
                "Content-Type: text/html",
            ],
        ];
        for lines in rejected {
            let body = raw_body(&[
                (&["Content-Disposition: form-data; name=\"ok\""], b"v"),
                (lines, b"v"),
            ]);
            let mut mp = chunked(&body, 5, None);
            assert!(mp.next_field().await.unwrap().is_some());
            for _ in 0..2 {
                let error = mp.next_field().await.unwrap_err();
                assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{lines:?}");
            }
        }

        // a part can go without a name, or without any header
        let body = raw_body(&[
            (&[], b"bare"),
            (&["Content-Disposition: form-data"], b"nameless"),
            (&["Content-Type: not a media type"], b"untyped"),
        ]);
        let fields = collect(chunked(&body, 5, None)).await.unwrap();
        let data: Vec<_> = fields.iter().map(|field| &field.4[..]).collect();
        assert_eq!(data, [&b"bare"[..], b"nameless", b"untyped"]);
        assert!(
            fields
                .iter()
                .all(|field| field.0.is_none() && field.2.is_none())
        );
    }

    #[tokio::test]
    async fn test_multipart_text_failure_leaves_the_stream_usable() {
        const NAME: &str = "Content-Disposition: form-data; name=\"a\"";
        let body = raw_body(&[
            (
                &[NAME, "Content-Type: text/plain; charset=iso-8859-1"],
                b"caf\xe9",
            ),
            (&[NAME], b"caf\xe9"),
            (
                &[NAME, "Content-Type: text/plain; charset=UTF-8"],
                "café".as_bytes(),
            ),
            (
                &[NAME, "Content-Type: text/plain; charset=us-ascii"],
                b"cafe",
            ),
            (
                &[NAME, "Content-Type: text/plain; charset=utf-16"],
                b"c\0a\0",
            ),
            (&[NAME], b""),
        ]);
        for size in [1, 1024] {
            let mut mp = chunked(&body, size, None);
            let mut texts = Vec::new();
            while let Some(field) = mp.next_field().await.unwrap() {
                texts.push(field.text().await.map_err(|error| {
                    assert_eq!(
                        error.body_text(),
                        "Failed to parse `multipart/form-data` request: field is not UTF-8 text"
                    );
                    error.status()
                }));
            }
            let invalid = || Err(StatusCode::BAD_REQUEST);
            assert_eq!(
                texts,
                [
                    invalid(),
                    invalid(),
                    Ok("café".to_owned()),
                    Ok("cafe".to_owned()),
                    invalid(),
                    Ok(String::new()),
                ]
            );
        }
    }

    #[tokio::test]
    async fn test_multipart_part_without_data() {
        let mut body = Vec::new();
        for name in ["a", "b"] {
            body.extend_from_slice(b"--");
            body.extend_from_slice(BOUNDARY.as_bytes());
            body.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
            body.extend_from_slice(name.as_bytes());
            // no CRLF of its own before the next delimiter
            body.extend_from_slice(b"\"\r\n\r\n");
        }
        body.extend_from_slice(b"--");
        body.extend_from_slice(BOUNDARY.as_bytes());
        body.extend_from_slice(b"--");
        for size in [1, 1024] {
            let fields = collect(chunked(&body, size, None)).await.unwrap();
            let names: Vec<_> = fields.iter().map(|field| field.0.as_deref()).collect();
            assert_eq!(names, [Some("a"), Some("b")]);
            assert!(fields.iter().all(|field| field.4.is_empty()));
        }
    }

    #[tokio::test]
    async fn test_multipart_malformed_bodies_are_bad_requests() {
        let valid = body_with(&[("a", None, None, b"v")]);
        let text = String::from_utf8(valid).unwrap();
        for body in [
            String::new(),
            "no delimiter at all".to_owned(),
            text.replace("\r\n", "\n"),
            text.replacen("\r\n", " junk\r\n", 1),
            text.replacen("Content-Disposition:", "Content-Disposition :", 1),
            text.replacen("\r\n\r\n", "\r\n folded\r\n\r\n", 1),
            text.replacen("\r\n\r\n", "\r\nX: a\0b\r\n\r\n", 1),
            text.replacen(
                "\r\n\r\n",
                &format!("\r\nX: {}\r\n\r\n", "x".repeat(17_000)),
                1,
            ),
            text.replacen("\r\n\r\n", &"\r\nX: 1".repeat(40), 1),
        ] {
            for size in [1, 1024] {
                let error = collect(chunked(body.as_bytes(), size, None))
                    .await
                    .unwrap_err();
                assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{body:?}");
            }
        }
    }
}
