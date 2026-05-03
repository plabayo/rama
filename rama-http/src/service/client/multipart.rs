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
use rama_core::error::BoxError;
use rama_core::futures::{StreamExt, TryStreamExt, stream};
use rama_http_types::{HeaderMap, HeaderValue, header, mime};
use rand::RngExt as _;
use std::borrow::Cow;
use std::path::Path;
use std::pin::Pin;

const CRLF: &[u8] = b"\r\n";

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
    boundary: String,
    parts: Vec<NamedPart>,
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
            parts: Vec::new(),
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
        // Boundaries are randomly generated hex chars, so the resulting
        // value is always a valid ASCII header value.
        HeaderValue::try_from(value)
            .unwrap_or_else(|_| HeaderValue::from_static("multipart/form-data"))
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
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        let mut total: u64 = 0;
        for np in &self.parts {
            let part_size = np.part.content_size?;
            let header = render_part_headers(&self.boundary, &np.name, &np.part);
            total = total.checked_add(header.len() as u64)?;
            total = total.checked_add(part_size)?;
            total = total.checked_add(CRLF.len() as u64)?;
        }
        let trailer_len = (b"--".len() + self.boundary.len() + b"--\r\n".len()) as u64;
        total = total.checked_add(trailer_len)?;
        Some(total)
    }

    /// Convert this form into a stream of body chunks.
    pub fn into_stream(
        self,
    ) -> impl rama_core::futures::Stream<Item = Result<Bytes, BoxError>> + Send {
        let boundary = self.boundary;
        let trailer = {
            let mut buf = BytesMut::with_capacity(boundary.len() + 4);
            buf.put_slice(b"--");
            buf.put_slice(boundary.as_bytes());
            buf.put_slice(b"--\r\n");
            buf.freeze()
        };

        let chunks: Vec<ChunkStream> = self
            .parts
            .into_iter()
            .flat_map(|np| {
                let header = render_part_headers(&boundary, &np.name, &np.part);
                let header_stream: ChunkStream =
                    Box::pin(stream::iter([Ok::<Bytes, BoxError>(header)]));
                let body_stream: ChunkStream = match np.part.body {
                    PartBody::Bytes(b) => Box::pin(stream::iter([Ok::<Bytes, BoxError>(b)])),
                    PartBody::Stream(s) => s,
                };
                let crlf_stream: ChunkStream = Box::pin(stream::iter([Ok::<Bytes, BoxError>(
                    Bytes::from_static(CRLF),
                )]));
                [header_stream, body_stream, crlf_stream]
            })
            .collect();

        let trailer_stream: ChunkStream = Box::pin(stream::iter([Ok::<Bytes, BoxError>(trailer)]));
        let mut all: Vec<ChunkStream> = chunks;
        all.push(trailer_stream);

        stream::iter(all).flatten()
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
/// [`with_mime_str`](Self::with_mime_str),
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
        let stream = rama_core::stream::io::ReaderStream::new(file);

        let mapped = stream.map_ok(Bytes::from).map_err(BoxError::from);

        Ok(Self {
            body: PartBody::Stream(Box::pin(mapped)),
            content_size: Some(len),
            file_name,
            mime: Some(mime),
            headers: HeaderMap::new(),
        })
    }

    /// Override or set the filename used in the part's `Content-Disposition`.
    pub fn with_file_name<V: Into<Cow<'static, str>>>(mut self, name: V) -> Self {
        self.file_name = Some(name.into());
        self
    }

    /// Set the part's `Content-Type` from a string like `"image/png"`.
    pub fn with_mime_str(mut self, mime_str: &str) -> Result<Self, mime::FromStrError> {
        self.mime = Some(mime_str.parse()?);
        Ok(self)
    }

    /// Set the part's `Content-Type` from a [`Mime`](mime::Mime) value.
    pub fn with_mime(mut self, mime: mime::Mime) -> Self {
        self.mime = Some(mime);
        self
    }

    /// Set the part's known content size in bytes. For streaming parts this
    /// allows the surrounding [`Form`] to advertise a `Content-Length`.
    pub fn with_content_size(mut self, size: u64) -> Self {
        self.content_size = Some(size);
        self
    }

    /// Replace the part's headers (other than `Content-Disposition` and
    /// `Content-Type`, which are derived from the part's metadata).
    ///
    /// RFC 7578 §4.8 states that headers other than `Content-Disposition`,
    /// `Content-Type`, and (legacy) `Content-Transfer-Encoding` "MUST NOT be
    /// included and MUST be ignored" by receivers. Custom headers are
    /// allowed here for compatibility with non-standard receivers, but
    /// strictly conforming peers will silently drop them.
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }
}

fn render_part_headers(boundary: &str, name: &str, part: &Part) -> Bytes {
    let mut buf = BytesMut::with_capacity(128);
    buf.put_slice(b"--");
    buf.put_slice(boundary.as_bytes());
    buf.put_slice(CRLF);
    buf.put_slice(b"Content-Disposition: form-data; name=\"");
    write_quoted(&mut buf, name);
    buf.put_slice(b"\"");
    if let Some(file_name) = part.file_name.as_deref() {
        buf.put_slice(b"; filename=\"");
        write_quoted(&mut buf, file_name);
        buf.put_slice(b"\"");
    }
    buf.put_slice(CRLF);
    if let Some(mime) = &part.mime {
        buf.put_slice(b"Content-Type: ");
        buf.put_slice(mime.essence_str().as_bytes());
        buf.put_slice(CRLF);
    }
    for (name, value) in &part.headers {
        if name == header::CONTENT_DISPOSITION || name == header::CONTENT_TYPE {
            continue;
        }
        buf.put_slice(name.as_str().as_bytes());
        buf.put_slice(b": ");
        buf.put_slice(value.as_bytes());
        buf.put_slice(CRLF);
    }
    buf.put_slice(CRLF);
    buf.freeze()
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

fn gen_boundary() -> String {
    let mut rng = rand::rng();
    format!(
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
}
