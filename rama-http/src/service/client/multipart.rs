//! Client-side `multipart/form-data` form builder.
//!
//! Build a [`Form`] from text, byte, file, or streaming [`Part`]s and send it
//! via [`RequestBuilder::multipart`](super::ext::RequestBuilder::multipart) or
//! by converting it directly to a [`Body`](crate::Body).
//!
//! Each [`Part`] carries an optional content size. When every part of a form
//! has a known size, the form has a known content length; otherwise the body
//! is sent with chunked transfer encoding.
//!
//! Output is RFC 7578 (`multipart/form-data`) on top of RFC 2046 framing.
//! Boundaries use only characters from RFC 2046 §5.1.1's `bcharsnospace` set
//! (random hex with `-` separators, ≤ 70 bytes). Each part is emitted with a
//! `Content-Disposition: form-data` header carrying `name` and, where
//! applicable, `filename` per RFC 7578 §4.2; non-ASCII bytes in those values
//! are passed through as raw UTF-8. The legacy `filename*` ext-value form is
//! deliberately not produced (RFC 7578 §4.2 forbids it for senders); the
//! `Content-Transfer-Encoding` header is likewise omitted (§4.7).

use rama_core::bytes::{BufMut, Bytes, BytesMut};
use rama_core::error::{BoxError, ErrorContext as _, ErrorExt as _};
use rama_core::futures::{StreamExt, TryStreamExt, stream};
use rama_core::stream::io::ReaderStream;
use rama_core::telemetry::tracing;
use rama_http_types::{HeaderMap, HeaderValue, header, mime};
use rama_utils::collections::smallvec::SmallVec;
use rama_utils::macros::generate_set_and_with;
use rama_utils::str::smol_str::{SmolStr, format_smolstr};
use rand::RngExt as _;
use std::borrow::Cow;
use std::path::Path;
use std::pin::Pin;
use tokio::io::AsyncReadExt as _;

/// Most multipart forms have a small number of parts; the inline buffer
/// avoids a heap allocation in the common case (e.g. a text field plus a
/// single file upload).
const PARTS_INLINE_CAP: usize = 4;

const CRLF: &[u8] = b"\r\n";
const DASH_DASH: &[u8] = b"--";
const FIELD_DISPOSITION_PREFIX: &[u8] = b"Content-Disposition: form-data; name=\"";
const FILENAME_PREFIX: &[u8] = b"; filename=\"";
const CONTENT_TYPE_PREFIX: &[u8] = b"Content-Type: ";
const QUOTE: &[u8] = b"\"";
const HEADER_KV_SEP: &[u8] = b": ";

type ChunkStream = Pin<Box<dyn rama_core::futures::Stream<Item = Result<Bytes, BoxError>> + Send>>;

/// A multipart form body.
///
/// Generates a random boundary on construction. Add named [`Part`]s with
/// [`text`](Self::text), [`bytes`](Self::bytes), [`file`](Self::file), or
/// [`part`](Self::part), then convert to a [`Body`](crate::Body) (or feed via
/// [`RequestBuilder::multipart`](super::ext::RequestBuilder::multipart)).
#[derive(Debug)]
#[must_use]
pub struct Form {
    boundary: SmolStr,
    parts: SmallVec<[NamedPart; PARTS_INLINE_CAP]>,
}

#[derive(Debug)]
struct NamedPart {
    name: Cow<'static, str>,
    part: Part,
}

impl Default for Form {
    fn default() -> Self {
        Self::new()
    }
}

impl Form {
    /// Create a new empty `Form` with a random boundary.
    pub fn new() -> Self {
        Self {
            boundary: gen_boundary(),
            parts: SmallVec::new(),
        }
    }

    /// The boundary string used to separate this form's parts.
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// The `Content-Type` header value (`multipart/form-data; boundary=…`).
    #[must_use]
    pub fn content_type(&self) -> HeaderValue {
        let value = format!("multipart/form-data; boundary={}", self.boundary);
        // Boundaries are randomly generated `[0-9a-f-]` (all valid
        // header-value bytes), so this conversion is infallible by
        // construction. The branch only exists to satisfy the
        // `unwrap_used`/`expect_used` lints; fall through to an
        // unreachable rather than a silent header without the boundary
        // parameter (which would be a protocol bug).
        match HeaderValue::try_from(value) {
            Ok(v) => v,
            Err(_) => unreachable!("multipart boundary always converts to a HeaderValue"),
        }
    }

    /// Add a text part to the form.
    pub fn text<N, V>(self, name: N, value: V) -> Self
    where
        N: Into<Cow<'static, str>>,
        V: Into<Cow<'static, str>>,
    {
        self.part(name, Part::text(value))
    }

    /// Add a bytes part to the form.
    pub fn bytes<N, B>(self, name: N, value: B) -> Self
    where
        N: Into<Cow<'static, str>>,
        B: Into<Bytes>,
    {
        self.part(name, Part::bytes(value))
    }

    /// Add a file part to the form. Reads the file asynchronously, infers the
    /// MIME type from the file extension (falling back to
    /// `application/octet-stream`), and sets `filename` from the path.
    pub async fn file<N, P>(self, name: N, path: P) -> std::io::Result<Self>
    where
        N: Into<Cow<'static, str>>,
        P: AsRef<Path>,
    {
        let part = Part::file(path).await?;
        Ok(self.part(name, part))
    }

    /// Add a part described by a compact `name=value` field-spec string.
    ///
    /// See [`FieldSpec`] for the supported syntax (the same convention used
    /// by curl `-F`, httpie, and similar tools). Performs the I/O implied by
    /// `=@` (file), `=<` (file-as-text), and `=@-` / `=<-` (stdin) sources;
    /// the `=value` form is purely textual.
    pub async fn with_field_spec(self, spec: &str) -> Result<Self, FieldSpecError> {
        let parsed = FieldSpec::parse(spec)?;
        let name = parsed.name.to_owned();
        let part = parsed.into_part().await?;
        Ok(self.part(name, part))
    }

    /// Add a custom [`Part`] to the form.
    pub fn part<N>(mut self, name: N, part: Part) -> Self
    where
        N: Into<Cow<'static, str>>,
    {
        self.parts.push(NamedPart {
            name: name.into(),
            part,
        });
        self
    }

    /// Total content length of the encoded form, if every part has a known
    /// size. Returns `None` otherwise (use chunked transfer encoding in that
    /// case).
    ///
    /// Computed analytically — no headers are rendered into a buffer.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        let mut total: u64 = 0;
        for np in &self.parts {
            let part_size = np.part.content_size?;
            let header_len = part_headers_len(&self.boundary, &np.name, &np.part) as u64;
            total = total.checked_add(header_len)?;
            total = total.checked_add(part_size)?;
            total = total.checked_add(CRLF.len() as u64)?;
        }
        let trailer_len =
            (DASH_DASH.len() + self.boundary.len() + DASH_DASH.len() + CRLF.len()) as u64;
        total = total.checked_add(trailer_len)?;
        Some(total)
    }

    /// Convert this form into a stream of body chunks.
    ///
    /// Per-part overhead: one heap-allocated framing chunk (boundary
    /// delimiter + headers, prefixed with CRLF on all but the first part)
    /// and the part body. Bytes-bodied parts are emitted in a single chunk;
    /// streamed bodies pass through their underlying chunks unchanged.
    pub fn into_stream(
        self,
    ) -> impl rama_core::futures::Stream<Item = Result<Bytes, BoxError>> + Send {
        let boundary = self.boundary;
        let n_parts = self.parts.len();

        // Build the closing trailer up front: the leading CRLF replaces the
        // last part's body-trailing CRLF (the CRLF before each boundary
        // delimiter is part of the delimiter per RFC 2046 §5.1.1).
        let trailer = {
            let cap = if n_parts == 0 { 0 } else { CRLF.len() }
                + DASH_DASH.len()
                + boundary.len()
                + DASH_DASH.len()
                + CRLF.len();
            let mut buf = BytesMut::with_capacity(cap);
            if n_parts > 0 {
                buf.put_slice(CRLF);
            }
            buf.put_slice(DASH_DASH);
            buf.put_slice(boundary.as_bytes());
            buf.put_slice(DASH_DASH);
            buf.put_slice(CRLF);
            buf.freeze()
        };

        // 2 streams per part (framing + body) + 1 for the trailer.
        let mut chunks: Vec<ChunkStream> = Vec::with_capacity(n_parts * 2 + 1);
        for (i, np) in self.parts.into_iter().enumerate() {
            // Framing: for parts after the first we prepend CRLF (the
            // delimiter's leading CRLF, which doubles as the prior body's
            // trailer per RFC 2046).
            let framing = render_framing(&boundary, &np.name, &np.part, i > 0);
            chunks.push(Box::pin(stream::iter([Ok::<Bytes, BoxError>(framing)])));
            chunks.push(match np.part.body {
                PartBody::Bytes(b) => Box::pin(stream::iter([Ok::<Bytes, BoxError>(b)])),
                PartBody::Stream(s) => s,
            });
        }
        chunks.push(Box::pin(stream::iter([Ok::<Bytes, BoxError>(trailer)])));

        stream::iter(chunks).flatten()
    }

    /// Consume the form and produce a [`Body`](crate::Body) ready to be set on
    /// a request. Use [`content_type`](Self::content_type) and
    /// [`content_length`](Self::content_length) to set the relevant request
    /// headers.
    pub fn into_body(self) -> crate::Body {
        crate::Body::from_stream(self.into_stream())
    }
}

/// A single part of a multipart [`Form`].
///
/// Built via [`text`](Self::text), [`bytes`](Self::bytes),
/// [`stream`](Self::stream), or [`file`](Self::file). Customise with
/// [`with_file_name`](Self::with_file_name),
/// [`try_with_mime_str`](Self::try_with_mime_str),
/// [`with_content_size`](Self::with_content_size), or
/// [`with_headers`](Self::with_headers).
#[must_use]
pub struct Part {
    body: PartBody,
    content_size: Option<u64>,
    file_name: Option<Cow<'static, str>>,
    mime: Option<mime::Mime>,
    headers: HeaderMap,
}

impl std::fmt::Debug for Part {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Part")
            .field(
                "body_kind",
                &match &self.body {
                    PartBody::Bytes(b) => format!("bytes ({} B)", b.len()),
                    PartBody::Stream(_) => String::from("stream"),
                },
            )
            .field("content_size", &self.content_size)
            .field("file_name", &self.file_name)
            .field("mime", &self.mime.as_ref().map(mime::Mime::essence_str))
            .field("headers", &self.headers)
            .finish()
    }
}

enum PartBody {
    Bytes(Bytes),
    Stream(ChunkStream),
}

impl Part {
    /// Create a text part.
    pub fn text<V: Into<Cow<'static, str>>>(value: V) -> Self {
        let bytes = Bytes::from(value.into().into_owned().into_bytes());
        let len = bytes.len() as u64;
        Self {
            body: PartBody::Bytes(bytes),
            content_size: Some(len),
            file_name: None,
            mime: None,
            headers: HeaderMap::new(),
        }
    }

    /// Create a part from raw bytes.
    pub fn bytes<B: Into<Bytes>>(value: B) -> Self {
        let bytes: Bytes = value.into();
        let len = bytes.len() as u64;
        Self {
            body: PartBody::Bytes(bytes),
            content_size: Some(len),
            file_name: None,
            mime: None,
            headers: HeaderMap::new(),
        }
    }

    /// Create a streaming part. The content size is unknown unless set
    /// explicitly via [`with_content_size`](Self::with_content_size).
    pub fn stream<S, O, E>(stream: S) -> Self
    where
        S: rama_core::futures::Stream<Item = Result<O, E>> + Send + 'static,
        O: Into<Bytes> + 'static,
        E: Into<BoxError> + 'static,
    {
        let mapped = stream.map_ok(Into::into).map_err(Into::into);
        Self {
            body: PartBody::Stream(Box::pin(mapped)),
            content_size: None,
            file_name: None,
            mime: None,
            headers: HeaderMap::new(),
        }
    }

    /// Create a part from a file. The filename is taken from the path's last
    /// component, the MIME type is inferred from the extension (falling back
    /// to `application/octet-stream`), and the content size is read from
    /// filesystem metadata.
    ///
    /// Filenames are converted to UTF-8 using lossy replacement of any
    /// non-UTF-8 bytes (relevant on Unix where filenames are arbitrary
    /// byte sequences). If you need to preserve non-UTF-8 names verbatim,
    /// build the [`Part`] yourself with [`Part::file`] and override the
    /// name via [`Part::with_file_name`] from a known UTF-8 source.
    ///
    /// The reported `content_size` is taken from filesystem metadata at
    /// the moment of the call. Concurrent writers that change the file
    /// size between this call and the body being sent can desynchronise
    /// the advertised `Content-Length` from the actually-streamed bytes;
    /// avoid passing a path to a file that may be modified mid-flight.
    pub async fn file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref();
        let file_name: Option<Cow<'static, str>> = path
            .file_name()
            .map(|name| Cow::Owned(name.to_string_lossy().into_owned()));
        let mime = path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .and_then(|ext| mime_guess::from_ext(ext).first())
            .unwrap_or(mime::APPLICATION_OCTET_STREAM);

        let file = tokio::fs::File::open(path).await?;
        let metadata = file.metadata().await?;
        let len = metadata.len();

        tracing::debug!(
            path = %path.display(),
            size = len,
            mime = %mime,
            "multipart::Part::file: opened file for streaming",
        );

        let stream = ReaderStream::new(file);
        let mapped = stream.map_ok(Bytes::from).map_err(BoxError::from);

        Ok(Self {
            body: PartBody::Stream(Box::pin(mapped)),
            content_size: Some(len),
            file_name,
            mime: Some(mime),
            headers: HeaderMap::new(),
        })
    }

    generate_set_and_with! {
        /// Filename used in the part's `Content-Disposition` header.
        ///
        /// Accepts anything that converts into [`Cow<'static, str>`] —
        /// `&'static str` literals, owned `String`, or an explicit
        /// `Cow::Owned`/`Cow::Borrowed`.
        pub fn file_name(mut self, file_name: impl Into<Cow<'static, str>>) -> Self {
            self.file_name = Some(file_name.into());
            self
        }
    }

    generate_set_and_with! {
        /// The part's `Content-Type`, as a parsed [`Mime`](mime::Mime).
        ///
        /// `with_*`/`set_*` set, `without_*`/`unset_*` clear any
        /// previously-set value.
        pub fn mime(mut self, mime: Option<mime::Mime>) -> Self {
            self.mime = mime;
            self
        }
    }

    generate_set_and_with! {
        /// The part's `Content-Type` parsed from a string such as
        /// `"image/png"`. Generates `try_with_mime_str` /
        /// `try_set_mime_str` companions returning `Result`.
        pub fn mime_str(mut self, mime_str: &str) -> Result<Self, mime::FromStrError> {
            self.mime = Some(mime_str.parse()?);
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Known content size in bytes. For streaming parts this allows the
        /// surrounding [`Form`] to advertise a `Content-Length`.
        pub fn content_size(mut self, size: Option<u64>) -> Self {
            self.content_size = size;
            self
        }
    }

    generate_set_and_with! {
        /// Replace the part's headers (other than `Content-Disposition` and
        /// `Content-Type`, which are derived from the part's metadata).
        ///
        /// RFC 7578 §4.8 states that headers other than `Content-Disposition`,
        /// `Content-Type`, and (legacy) `Content-Transfer-Encoding` "MUST NOT be
        /// included and MUST be ignored" by receivers. Custom headers are
        /// allowed here for compatibility with non-standard receivers, but
        /// strictly conforming peers will silently drop them.
        pub fn headers(mut self, headers: HeaderMap) -> Self {
            self.headers = headers;
            self
        }
    }
}

/// Render the boundary delimiter plus part headers as a single chunk.
///
/// `with_leading_crlf` adds the delimiter's CRLF prefix used between parts;
/// the very first part of a form has no preceding CRLF (its preamble is
/// empty), per RFC 2046 §5.1.1.
fn render_framing(boundary: &str, name: &str, part: &Part, with_leading_crlf: bool) -> Bytes {
    let cap =
        if with_leading_crlf { CRLF.len() } else { 0 } + part_headers_len(boundary, name, part);
    let mut buf = BytesMut::with_capacity(cap);
    if with_leading_crlf {
        buf.put_slice(CRLF);
    }
    buf.put_slice(DASH_DASH);
    buf.put_slice(boundary.as_bytes());
    buf.put_slice(CRLF);
    buf.put_slice(FIELD_DISPOSITION_PREFIX);
    write_quoted(&mut buf, name);
    buf.put_slice(QUOTE);
    if let Some(file_name) = part.file_name.as_deref() {
        buf.put_slice(FILENAME_PREFIX);
        write_quoted(&mut buf, file_name);
        buf.put_slice(QUOTE);
    }
    buf.put_slice(CRLF);
    if let Some(mime) = &part.mime {
        buf.put_slice(CONTENT_TYPE_PREFIX);
        // `as_ref` returns the full mime string including parameters
        // (e.g. `text/plain; charset=utf-8`); essence_str would drop them.
        buf.put_slice(mime.as_ref().as_bytes());
        buf.put_slice(CRLF);
    }
    for (name, value) in &part.headers {
        if name == header::CONTENT_DISPOSITION || name == header::CONTENT_TYPE {
            continue;
        }
        buf.put_slice(name.as_str().as_bytes());
        buf.put_slice(HEADER_KV_SEP);
        buf.put_slice(value.as_bytes());
        buf.put_slice(CRLF);
    }
    buf.put_slice(CRLF);
    buf.freeze()
}

/// Compute the byte length of the headers `render_part_headers` would emit,
/// without doing any allocation. Must stay in lock-step with the rendering
/// logic.
fn part_headers_len(boundary: &str, name: &str, part: &Part) -> usize {
    // "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\""
    let mut len = DASH_DASH.len()
        + boundary.len()
        + CRLF.len()
        + FIELD_DISPOSITION_PREFIX.len()
        + quoted_len(name)
        + QUOTE.len();
    // "; filename=\"{file_name}\""
    if let Some(file_name) = part.file_name.as_deref() {
        len += FILENAME_PREFIX.len() + quoted_len(file_name) + QUOTE.len();
    }
    len += CRLF.len();
    // "Content-Type: {mime}\r\n" — full mime string including any parameters
    // (e.g. `text/plain; charset=utf-8`).
    if let Some(mime) = &part.mime {
        len += CONTENT_TYPE_PREFIX.len() + mime.as_ref().len() + CRLF.len();
    }
    // Custom headers (excluding the two we always derive ourselves).
    for (h_name, h_value) in &part.headers {
        if h_name == header::CONTENT_DISPOSITION || h_name == header::CONTENT_TYPE {
            continue;
        }
        len += h_name.as_str().len() + HEADER_KV_SEP.len() + h_value.as_bytes().len() + CRLF.len();
    }
    // Blank line separating headers from body.
    len += CRLF.len();
    len
}

/// Counts the bytes `write_quoted` would emit.
fn quoted_len(s: &str) -> usize {
    s.bytes()
        .map(|b| match b {
            b'"' | b'\\' => 2,
            // CR/LF replaced by a single space.
            _ => 1,
        })
        .sum()
}

fn write_quoted(buf: &mut BytesMut, s: &str) {
    for byte in s.as_bytes() {
        match *byte {
            b'"' | b'\\' => {
                buf.put_u8(b'\\');
                buf.put_u8(*byte);
            }
            b'\r' | b'\n' => {
                // RFC 7578 forbids CR/LF in name/filename — replace with space.
                buf.put_u8(b' ');
            }
            b => buf.put_u8(b),
        }
    }
}

/// A parsed `name=…` field spec for use with [`Form::with_field_spec`].
///
/// The same compact convention used by `curl -F` and friends:
///
/// | Spec | Meaning |
/// |---|---|
/// | `name=value` | text field |
/// | `name=@path` | file upload (mime guessed from extension) |
/// | `name=@-` | file upload from stdin |
/// | `name=<path` | file content as a text field (not an upload) |
/// | `name=<-` | text field content from stdin |
///
/// Modifiers may follow the source, separated by `;`:
/// - `;type=mime/sub` overrides the part's `Content-Type`
/// - `;filename=name` overrides the `filename` parameter
///
/// Example: `avatar=@./photo.png;type=image/png;filename=me.png`
///
/// # Limitations
///
/// Modifier splitting is naive: the first `;` after the value terminates the
/// value. A literal `;` cannot appear inside a `name=value` text payload via
/// this syntax. For text values containing `;`, build the [`Part`] directly
/// with [`Part::text`] and add it via [`Form::part`].
#[derive(Debug, Clone)]
pub struct FieldSpec<'a> {
    /// Field name (the part to the left of `=`).
    pub name: &'a str,
    /// Where the value comes from.
    pub source: FieldSpecSource<'a>,
    /// Optional `;type=…` override.
    pub content_type: Option<&'a str>,
    /// Optional `;filename=…` override.
    pub filename: Option<&'a str>,
}

/// Source of a [`FieldSpec`] value.
#[derive(Debug, Clone)]
pub enum FieldSpecSource<'a> {
    /// `name=value` — literal text.
    Text(&'a str),
    /// `name=@path` — upload the file's bytes; `path = "-"` reads stdin.
    File(&'a str),
    /// `name=<path` — read file content into a text field; `path = "-"` reads stdin.
    FileText(&'a str),
}

/// Error type returned by [`FieldSpec::parse`].
#[derive(Debug)]
pub enum FieldSpecError {
    /// The spec is missing a `=` separator between name and value.
    MissingSeparator,
    /// The field name (left of `=`) is empty.
    EmptyName,
    /// A `;…` modifier was malformed, or an I/O step (file open, stdin
    /// read) failed during [`FieldSpec::into_part`].
    InvalidModifier(BoxError),
}

impl std::fmt::Display for FieldSpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSeparator => write!(f, "field spec is missing `=` separator"),
            Self::EmptyName => write!(f, "field spec has empty name"),
            Self::InvalidModifier(err) => write!(f, "invalid field spec: {err}"),
        }
    }
}

impl std::error::Error for FieldSpecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidModifier(err) => Some(&**err),
            _ => None,
        }
    }
}

/// Small adapter to box a dynamic-string error message without going
/// through `String` and the heavier error machinery.
#[derive(Debug)]
struct InlineErr(SmolStr);

impl std::fmt::Display for InlineErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InlineErr {}

impl<'a> FieldSpec<'a> {
    /// Parse a field spec string. Pure: does no I/O.
    pub fn parse(spec: &'a str) -> Result<Self, FieldSpecError> {
        let (name, rest) = spec
            .split_once('=')
            .ok_or(FieldSpecError::MissingSeparator)?;
        if name.is_empty() {
            return Err(FieldSpecError::EmptyName);
        }

        // Modifiers (;type=, ;filename=) are split off the right of the
        // value. Multiple modifiers may follow.
        let mut content_type: Option<&str> = None;
        let mut filename: Option<&str> = None;
        let value_part: &str;

        if let Some((value, modifiers)) = split_modifiers(rest) {
            value_part = value;
            for modifier in modifiers.split(';') {
                let modifier = modifier.trim();
                if modifier.is_empty() {
                    continue;
                }
                let (key, val) = modifier.split_once('=').ok_or_else(|| {
                    FieldSpecError::InvalidModifier(
                        InlineErr(format_smolstr!("missing `=` in modifier `{modifier}`")).into(),
                    )
                })?;
                match key.trim() {
                    "type" => content_type = Some(val),
                    "filename" => filename = Some(val),
                    other => {
                        return Err(FieldSpecError::InvalidModifier(
                            InlineErr(format_smolstr!("unknown modifier key `{other}`")).into(),
                        ));
                    }
                }
            }
        } else {
            value_part = rest;
        }

        let source = if let Some(path) = value_part.strip_prefix('@') {
            FieldSpecSource::File(path)
        } else if let Some(path) = value_part.strip_prefix('<') {
            FieldSpecSource::FileText(path)
        } else {
            FieldSpecSource::Text(value_part)
        };

        Ok(Self {
            name,
            source,
            content_type,
            filename,
        })
    }

    /// Resolve this spec into a [`Part`], performing any necessary I/O.
    pub async fn into_part(self) -> Result<Part, FieldSpecError> {
        let mut part = match self.source {
            FieldSpecSource::Text(s) => Part::text(s.to_owned()),
            FieldSpecSource::File("-") => Part::stream(read_stdin_stream()),
            FieldSpecSource::File(path) => Part::file(path)
                .await
                .with_context(|| format_smolstr!("multipart field spec: open file `{path}`"))
                .map_err(|e| FieldSpecError::InvalidModifier(e.into_box_error()))?,
            FieldSpecSource::FileText("-") => {
                let s = read_stdin_to_string()
                    .await
                    .context("multipart field spec: read stdin as text")
                    .map_err(|e| FieldSpecError::InvalidModifier(e.into_box_error()))?;
                Part::text(s)
            }
            FieldSpecSource::FileText(path) => {
                let s = tokio::fs::read_to_string(path)
                    .await
                    .with_context(|| format_smolstr!("multipart field spec: read file `{path}`"))
                    .map_err(|e| FieldSpecError::InvalidModifier(e.into_box_error()))?;
                Part::text(s)
            }
        };
        if let Some(ct) = self.content_type {
            part.try_set_mime_str(ct)
                .with_context(|| format_smolstr!("invalid `;type=` mime in field spec: {ct}"))
                .map_err(|e| FieldSpecError::InvalidModifier(e.into_box_error()))?;
        }
        if let Some(fname) = self.filename {
            part.set_file_name(fname.to_owned());
        }
        Ok(part)
    }
}

/// Find the first un-quoted `;` that starts a modifier section, splitting
/// the value from the modifier list. Returns `None` if there are no
/// modifiers.
fn split_modifiers(input: &str) -> Option<(&str, &str)> {
    // Naive split on the first `;` is fine here — values in field specs
    // do not have a quoted form, by convention.
    input.split_once(';')
}

async fn read_stdin_to_string() -> Result<String, BoxError> {
    let mut buf = String::new();
    tokio::io::stdin()
        .read_to_string(&mut buf)
        .await
        .context("read multipart field value from stdin")?;
    Ok(buf)
}

fn read_stdin_stream() -> impl rama_core::futures::Stream<Item = Result<Bytes, BoxError>> + Send {
    ReaderStream::new(tokio::io::stdin())
        .map_ok(Bytes::from)
        .map_err(BoxError::from)
}

fn gen_boundary() -> SmolStr {
    let mut rng = rand::rng();
    format_smolstr!(
        "{:016x}-{:016x}-{:016x}-{:016x}",
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use rama_core::futures::TryStreamExt;

    async fn collect(form: Form) -> (HeaderValue, Option<u64>, Vec<u8>) {
        let ct = form.content_type();
        let len = form.content_length();
        let bytes: Vec<u8> = form
            .into_stream()
            .map_ok(|chunk| chunk.to_vec())
            .try_collect::<Vec<Vec<u8>>>()
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .collect();
        (ct, len, bytes)
    }

    #[tokio::test]
    async fn test_form_text_only() {
        let form = Form::new().text("name", "glen").text("language", "rust");
        let boundary = form.boundary().to_owned();
        let (ct, len, bytes) = collect(form).await;
        assert!(ct.to_str().unwrap().contains(&boundary));
        assert_eq!(len.unwrap() as usize, bytes.len());
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("name=\"name\""));
        assert!(s.contains("name=\"language\""));
        assert!(s.contains("\r\nglen\r\n"));
        assert!(s.contains("\r\nrust\r\n"));
        assert!(s.ends_with("--\r\n"));
    }

    #[tokio::test]
    async fn test_form_bytes_with_filename_and_mime() {
        let part = Part::bytes(b"\x00\x01\x02".as_slice())
            .with_file_name("a.bin")
            .with_mime(mime::APPLICATION_OCTET_STREAM);
        let form = Form::new().part("avatar", part);
        let (_, len, bytes) = collect(form).await;
        assert!(len.is_some());
        let s = std::str::from_utf8(&bytes[..bytes.iter().position(|&b| b == 0).unwrap()]).unwrap();
        assert!(s.contains("filename=\"a.bin\""));
        assert!(s.contains("Content-Type: application/octet-stream"));
    }

    #[tokio::test]
    async fn test_form_unknown_length_when_streaming() {
        let part = Part::stream(stream::iter([
            Ok::<Bytes, BoxError>(Bytes::from_static(b"hello ")),
            Ok::<Bytes, BoxError>(Bytes::from_static(b"world")),
        ]));
        let form = Form::new().part("payload", part);
        assert!(form.content_length().is_none());
        let (_, _len, bytes) = collect(form).await;
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("hello world"));
    }

    #[tokio::test]
    async fn test_form_known_length_when_streaming_with_content_size() {
        let part = Part::stream(stream::iter([Ok::<Bytes, BoxError>(Bytes::from_static(
            b"abcdef",
        ))]))
        .with_content_size(6);
        let form = Form::new().part("payload", part);
        let len = form.content_length().expect("length known");
        let (_, _, bytes) = collect(form).await;
        assert_eq!(len as usize, bytes.len());
    }

    #[tokio::test]
    async fn test_form_quoting_escapes_quotes() {
        let form = Form::new().text("we\"ird", "v");
        let (_, _, bytes) = collect(form).await;
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("name=\"we\\\"ird\""));
    }

    #[tokio::test]
    async fn test_form_preserves_mime_parameters() {
        // Regression: prior implementation used `mime.essence_str()` which
        // dropped the charset parameter. Senders must emit the full mime
        // including any params like `charset=utf-8`.
        let part = Part::bytes(b"hi".as_slice())
            .try_with_mime_str("text/plain; charset=utf-8")
            .unwrap();
        let form = Form::new().part("note", part);
        let len = form.content_length().expect("length known");
        let (_, _, bytes) = collect(form).await;
        assert_eq!(len as usize, bytes.len());
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(
            s.contains("Content-Type: text/plain; charset=utf-8"),
            "rendered body: {s}"
        );
    }

    #[test]
    fn test_field_spec_text() {
        let s = FieldSpec::parse("name=glen").unwrap();
        assert_eq!(s.name, "name");
        assert!(matches!(s.source, FieldSpecSource::Text("glen")));
        assert!(s.content_type.is_none());
        assert!(s.filename.is_none());
    }

    #[test]
    fn test_field_spec_file_with_modifiers() {
        let s = FieldSpec::parse("avatar=@./photo.png;type=image/png;filename=me.png").unwrap();
        assert_eq!(s.name, "avatar");
        assert!(matches!(s.source, FieldSpecSource::File("./photo.png")));
        assert_eq!(s.content_type, Some("image/png"));
        assert_eq!(s.filename, Some("me.png"));
    }

    #[test]
    fn test_field_spec_file_text() {
        let s = FieldSpec::parse("greeting=<hello.txt").unwrap();
        assert_eq!(s.name, "greeting");
        assert!(matches!(s.source, FieldSpecSource::FileText("hello.txt")));
    }

    #[test]
    fn test_field_spec_stdin() {
        let s = FieldSpec::parse("blob=@-").unwrap();
        assert!(matches!(s.source, FieldSpecSource::File("-")));
    }

    #[test]
    fn test_field_spec_errors() {
        assert!(matches!(
            FieldSpec::parse("noequal"),
            Err(FieldSpecError::MissingSeparator)
        ));
        assert!(matches!(
            FieldSpec::parse("=value"),
            Err(FieldSpecError::EmptyName)
        ));
        assert!(matches!(
            FieldSpec::parse("name=v;invalid"),
            Err(FieldSpecError::InvalidModifier(_))
        ));
        assert!(matches!(
            FieldSpec::parse("name=v;weird=val"),
            Err(FieldSpecError::InvalidModifier(_))
        ));
    }

    #[tokio::test]
    async fn test_form_with_field_spec_text() {
        let form = Form::new()
            .with_field_spec("name=glen")
            .await
            .unwrap()
            .with_field_spec("lang=rust")
            .await
            .unwrap();
        let (_, _, bytes) = collect(form).await;
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("name=\"name\""));
        assert!(s.contains("\r\nglen\r\n"));
        assert!(s.contains("name=\"lang\""));
        assert!(s.contains("\r\nrust\r\n"));
    }

    #[tokio::test]
    async fn test_form_with_field_spec_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        tokio::fs::write(&path, b"hi from disk").await.unwrap();
        let spec = format!("note=@{};type=text/plain", path.display());

        let form = Form::new().with_field_spec(&spec).await.unwrap();
        let (_, _, bytes) = collect(form).await;
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("name=\"note\""));
        assert!(s.contains("filename=\"hello.txt\""));
        assert!(s.contains("Content-Type: text/plain"));
        assert!(s.contains("hi from disk"));
    }
}
