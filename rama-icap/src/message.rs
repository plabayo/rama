//! Owned ICAP message metadata for asynchronous transactions.

use core::fmt;

use rama_core::bytes::{Bytes, BytesMut};

use crate::{
    codec::{
        self, DEFAULT_MAX_HEAD_BYTES, DEFAULT_MAX_HEADERS, EncodeError, HeadParserConfig, Header,
        HeaderSlot, ParseError, ParseStatus, RequestHead, RequestLine, RequestLineSource,
        ResponseHead, ResponseLine, Trailers,
    },
    proto::{EncapsulatedKind, EncapsulatedSection, MethodKind, Preview, StatusCode, header},
};

const MAX_ENCAPSULATED_VALUE_BYTES: usize = 128;
const MAX_DECIMAL_U64_BYTES: usize = 20;
// Two spaces separate the fields, followed by CRLF.
const REQUEST_LINE_OVERHEAD: usize = 2 + 2;
// Spaces surround the three-digit status, followed by CRLF.
const RESPONSE_LINE_OVERHEAD: usize = 1 + 3 + 1 + 2;
// Each field has a `: ` separator and a trailing CRLF.
const HEADER_FIELD_OVERHEAD: usize = 2 + 2;
// An empty line terminates the header block.
const HEADER_BLOCK_END_BYTES: usize = 2;

#[derive(Clone)]
pub(crate) struct AcceptedHead {
    bytes: Bytes,
    parser: HeadParserConfig,
}

impl AcceptedHead {
    fn encoded(bytes: Bytes) -> Self {
        let parser = HeadParserConfig::new().with_max_bytes(bytes.len());
        Self { bytes, parser }
    }

    pub(crate) fn from_wire(bytes: Bytes, parser: HeadParserConfig) -> Self {
        Self { bytes, parser }
    }
}

/// Owned non-body sections and body kind of an ICAP message.
///
/// The HTTP header sections remain opaque bytes here, apart from validating
/// their terminating empty line. The `http` feature will provide typed
/// conversion without coupling the transport core to an HTTP implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct EncapsulatedParts {
    request_header: Option<Bytes>,
    response_header: Option<Bytes>,
    body_kind: EncapsulatedKind,
    sections: [EncapsulatedSection; 3],
    section_count: usize,
}

impl fmt::Debug for EncapsulatedParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncapsulatedParts")
            .field(
                "request_header_len",
                &self.request_header.as_ref().map(Bytes::len),
            )
            .field(
                "response_header_len",
                &self.response_header.as_ref().map(Bytes::len),
            )
            .field("body_kind", &self.body_kind)
            .field("sections", &&self.sections[..self.section_count])
            .finish()
    }
}

impl EncapsulatedParts {
    /// Construct and validate encapsulated message sections.
    pub fn new(
        request_header: Option<Bytes>,
        response_header: Option<Bytes>,
        body_kind: EncapsulatedKind,
    ) -> Result<Self, BuildError> {
        if !body_kind.is_body() {
            return Err(BuildError::InvalidEncapsulated);
        }
        if request_header
            .iter()
            .chain(response_header.iter())
            .any(|head| !head.ends_with(b"\r\n\r\n"))
        {
            return Err(BuildError::InvalidEncapsulated);
        }

        let mut sections = [
            EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
            EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
            EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
        ];
        let mut section_count = 0;
        let mut offset = 0_u64;

        if let Some(value) = &request_header {
            sections[section_count] =
                EncapsulatedSection::new(EncapsulatedKind::RequestHeader, offset);
            section_count += 1;
            offset = offset
                .checked_add(
                    u64::try_from(value.len()).map_err(|_error| BuildError::MessageTooLarge)?,
                )
                .ok_or(BuildError::MessageTooLarge)?;
        }
        if let Some(value) = &response_header {
            sections[section_count] =
                EncapsulatedSection::new(EncapsulatedKind::ResponseHeader, offset);
            section_count += 1;
            offset = offset
                .checked_add(
                    u64::try_from(value.len()).map_err(|_error| BuildError::MessageTooLarge)?,
                )
                .ok_or(BuildError::MessageTooLarge)?;
        }
        sections[section_count] = EncapsulatedSection::new(body_kind, offset);
        section_count += 1;

        let mut encoded = [0; MAX_ENCAPSULATED_VALUE_BYTES];
        codec::encode_encapsulated(&sections[..section_count], &mut encoded)
            .map_err(|_error| BuildError::InvalidEncapsulated)?;

        Ok(Self {
            request_header,
            response_header,
            body_kind,
            sections,
            section_count,
        })
    }

    /// Construct `Encapsulated: null-body=0`.
    pub fn null() -> Self {
        Self {
            request_header: None,
            response_header: None,
            body_kind: EncapsulatedKind::NullBody,
            sections: [
                EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
                EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
                EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
            ],
            section_count: 1,
        }
    }

    /// Return the raw encapsulated HTTP request head, when present.
    #[must_use]
    pub fn request_header(&self) -> Option<&Bytes> {
        self.request_header.as_ref()
    }

    /// Return the raw encapsulated HTTP response head, when present.
    #[must_use]
    pub fn response_header(&self) -> Option<&Bytes> {
        self.response_header.as_ref()
    }

    /// Return the terminal body kind.
    #[must_use]
    pub const fn body_kind(&self) -> EncapsulatedKind {
        self.body_kind
    }

    /// Return whether an ICAP chunk stream follows the header sections.
    #[must_use]
    pub const fn has_body(&self) -> bool {
        !matches!(self.body_kind, EncapsulatedKind::NullBody)
    }

    /// Iterate over the derived `Encapsulated` sections.
    pub fn sections(&self) -> impl ExactSizeIterator<Item = EncapsulatedSection> + '_ {
        self.sections[..self.section_count].iter().copied()
    }

    pub(crate) fn from_sections(
        input: &[EncapsulatedSection],
        prefix: &Bytes,
    ) -> Result<Self, BuildError> {
        let mut sections = [
            EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
            EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
            EncapsulatedSection::new(EncapsulatedKind::NullBody, 0),
        ];
        if input.len() > sections.len() {
            return Err(BuildError::InvalidEncapsulated);
        }
        sections[..input.len()].copy_from_slice(input);
        let count = input.len();
        let body = sections
            .get(count.saturating_sub(1))
            .copied()
            .ok_or(BuildError::InvalidEncapsulated)?;
        let expected = body.offset_usize().ok_or(BuildError::MessageTooLarge)?;
        if expected != prefix.len() || !body.kind().is_body() {
            return Err(BuildError::InvalidEncapsulated);
        }

        let mut request_header = None;
        let mut response_header = None;
        for index in 0..count.saturating_sub(1) {
            let section = sections[index];
            let start = section.offset_usize().ok_or(BuildError::MessageTooLarge)?;
            let end = sections[index + 1]
                .offset_usize()
                .ok_or(BuildError::MessageTooLarge)?;
            let value = prefix.slice(start..end);
            match section.kind() {
                EncapsulatedKind::RequestHeader => {
                    request_header = Some(value);
                }
                EncapsulatedKind::ResponseHeader => {
                    response_header = Some(value);
                }
                _ => return Err(BuildError::InvalidEncapsulated),
            }
        }
        Self::new(request_header, response_header, body.kind())
    }
}

/// An owned, validated ICAP request head and encapsulated prefix.
#[derive(Clone)]
pub struct Request {
    head: AcceptedHead,
    method: MethodKind,
    preview: Option<Preview>,
    encapsulated: Option<EncapsulatedParts>,
    original_body_len: Option<u64>,
    allow_204: bool,
    allow_206: bool,
    close: bool,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("preview", &self.preview)
            .field("head_len", &self.head.bytes.len())
            .field("encapsulated", &self.encapsulated)
            .field("original_body_len", &self.original_body_len)
            .field("allow_204", &self.allow_204)
            .field("allow_206", &self.allow_206)
            .field("close", &self.close)
            .finish()
    }
}

impl Request {
    /// Encode an ICAP request without Preview.
    pub fn new(
        line: RequestLine<'_>,
        headers: &[Header<'_>],
        encapsulated: Option<EncapsulatedParts>,
    ) -> Result<Self, BuildError> {
        Self::new_from_source(line.into(), headers, encapsulated)
    }

    pub(crate) fn new_from_source(
        line: RequestLineSource<'_>,
        headers: &[Header<'_>],
        encapsulated: Option<EncapsulatedParts>,
    ) -> Result<Self, BuildError> {
        Self::build(line, headers, encapsulated, None)
    }

    /// Encode an ICAP request with an explicit Preview limit.
    pub fn with_preview(
        line: RequestLine<'_>,
        headers: &[Header<'_>],
        encapsulated: EncapsulatedParts,
        preview: Preview,
    ) -> Result<Self, BuildError> {
        Self::with_preview_from_source(line.into(), headers, encapsulated, preview)
    }

    pub(crate) fn with_preview_from_source(
        line: RequestLineSource<'_>,
        headers: &[Header<'_>],
        encapsulated: EncapsulatedParts,
        preview: Preview,
    ) -> Result<Self, BuildError> {
        if !encapsulated.has_body() {
            return Err(BuildError::InvalidPreview);
        }
        Self::build(line, headers, Some(encapsulated), Some(preview))
    }

    fn build(
        line: RequestLineSource<'_>,
        headers: &[Header<'_>],
        encapsulated: Option<EncapsulatedParts>,
        preview: Option<Preview>,
    ) -> Result<Self, BuildError> {
        if headers.iter().any(|field| {
            field.name().eq_ignore_ascii_case(header::ENCAPSULATED)
                || field.name().eq_ignore_ascii_case(header::PREVIEW)
        }) {
            return Err(BuildError::ReservedHeader);
        }

        let mut encapsulated_value = [0; MAX_ENCAPSULATED_VALUE_BYTES];
        let encapsulated_header = if let Some(parts) = &encapsulated {
            let sections = parts.sections;
            let len = codec::encode_encapsulated(
                &sections[..parts.section_count],
                &mut encapsulated_value,
            )?;
            Some(Header::new(
                header::ENCAPSULATED,
                &encapsulated_value[..len],
            )?)
        } else {
            None
        };

        let mut preview_value = [0; MAX_DECIMAL_U64_BYTES];
        let preview_header = if let Some(preview) = preview {
            let value = encode_decimal(preview.as_u64(), &mut preview_value);
            Some(Header::new(header::PREVIEW, value)?)
        } else {
            None
        };
        let generated = [preview_header, encapsulated_header];
        let fields = headers
            .iter()
            .copied()
            .chain(generated.into_iter().flatten());
        let len = request_head_len(line, fields.clone())?;
        let mut head = BytesMut::zeroed(len);
        let written = codec::encode_request_head_source_iter(line, fields, &mut head)?;
        debug_assert_eq!(written, len);

        Ok(Self {
            head: AcceptedHead::encoded(head.freeze()),
            method: line.method().kind(),
            preview,
            encapsulated,
            original_body_len: None,
            allow_204: has_header_token(headers, header::ALLOW, b"204"),
            allow_206: has_header_token(headers, header::ALLOW, b"206"),
            close: has_header_token(headers, header::CONNECTION, b"close"),
        })
    }

    /// Return the lifetime-free request method.
    #[must_use]
    pub const fn method(&self) -> MethodKind {
        self.method
    }

    /// Return the Preview limit, when enabled.
    #[must_use]
    pub const fn preview(&self) -> Option<Preview> {
        self.preview
    }

    /// Return the encapsulated metadata, when present.
    #[must_use]
    pub const fn encapsulated(&self) -> Option<&EncapsulatedParts> {
        self.encapsulated.as_ref()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Declare the exact length of the original HTTP entity body.
        ///
        /// This is local client metadata and is not encoded on the wire. It
        /// lets the client validate `use-original-body` in an early 206
        /// response, before the complete original body has been sent.
        pub fn original_body_len(mut self, len: u64) -> Result<Self, BuildError> {
            if self
                .encapsulated
                .as_ref()
                .is_none_or(|parts| !parts.has_body())
            {
                return Err(BuildError::InvalidBodyLength);
            }
            self.original_body_len = Some(len);
            Ok(self)
        }
    }

    /// Return the declared exact original HTTP entity-body length.
    #[must_use]
    pub const fn original_body_len(&self) -> Option<u64> {
        self.original_body_len
    }

    /// Return whether a 204 response was negotiated outside Preview.
    #[must_use]
    pub const fn allows_204(&self) -> bool {
        self.allow_204
    }

    /// Return whether the Partial Content extension was negotiated.
    #[must_use]
    pub const fn allows_206(&self) -> bool {
        self.allow_206
    }

    /// Return the encoded ICAP head.
    #[must_use]
    pub const fn head_bytes(&self) -> &Bytes {
        &self.head.bytes
    }

    /// Return whether this message asks to close the connection.
    #[must_use]
    pub const fn should_close(&self) -> bool {
        self.close
    }

    /// Decode the owned head into caller-provided header slots.
    pub fn parse_head<'headers>(
        &self,
        slots: &'headers mut [HeaderSlot],
    ) -> Result<RequestHead<'headers, '_>, ParseError> {
        match codec::parse_request_head_with_config(&self.head.bytes, slots, self.head.parser)? {
            ParseStatus::Complete(head, consumed) if consumed == self.head.bytes.len() => Ok(head),
            _ => Err(ParseError::InvalidStartLine),
        }
    }

    pub(crate) fn from_wire(
        head: AcceptedHead,
        method: MethodKind,
        preview: Option<Preview>,
        encapsulated: Option<EncapsulatedParts>,
        allow_204: bool,
        allow_206: bool,
        close: bool,
    ) -> Self {
        Self {
            head,
            method,
            preview,
            encapsulated,
            original_body_len: None,
            allow_204,
            allow_206,
            close,
        }
    }
}

/// An owned, validated ICAP response head and encapsulated prefix.
#[derive(Clone)]
pub struct Response {
    head: AcceptedHead,
    method: MethodKind,
    status: StatusCode,
    encapsulated: Option<EncapsulatedParts>,
    close: bool,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("method", &self.method)
            .field("status", &self.status)
            .field("head_len", &self.head.bytes.len())
            .field("encapsulated", &self.encapsulated)
            .field("close", &self.close)
            .finish()
    }
}

impl Response {
    /// Encode an ICAP response for the corresponding request method.
    pub fn new(
        method: MethodKind,
        line: ResponseLine<'_>,
        headers: &[Header<'_>],
        encapsulated: Option<EncapsulatedParts>,
    ) -> Result<Self, BuildError> {
        if headers
            .iter()
            .any(|field| field.name().eq_ignore_ascii_case(header::ENCAPSULATED))
        {
            return Err(BuildError::ReservedHeader);
        }

        let mut encapsulated_value = [0; MAX_ENCAPSULATED_VALUE_BYTES];
        let encapsulated_header = if let Some(parts) = &encapsulated {
            let sections = parts.sections;
            let len = codec::encode_encapsulated(
                &sections[..parts.section_count],
                &mut encapsulated_value,
            )?;
            Some(Header::new(
                header::ENCAPSULATED,
                &encapsulated_value[..len],
            )?)
        } else {
            None
        };
        let fields = headers.iter().copied().chain(encapsulated_header);
        let len = response_head_len(line, fields.clone())?;
        let mut head = BytesMut::zeroed(len);
        let written = codec::encode_response_head_iter(method, line, fields, &mut head)?;
        debug_assert_eq!(written, len);

        Ok(Self {
            head: AcceptedHead::encoded(head.freeze()),
            method,
            status: line.status(),
            encapsulated,
            close: has_header_token(headers, header::CONNECTION, b"close"),
        })
    }

    /// Return the corresponding request method.
    #[must_use]
    pub const fn method(&self) -> MethodKind {
        self.method
    }

    /// Return the response status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Return the encapsulated metadata, when present.
    #[must_use]
    pub const fn encapsulated(&self) -> Option<&EncapsulatedParts> {
        self.encapsulated.as_ref()
    }

    /// Return the encoded ICAP head.
    #[must_use]
    pub const fn head_bytes(&self) -> &Bytes {
        &self.head.bytes
    }

    /// Return whether this message asks to close the connection.
    #[must_use]
    pub const fn should_close(&self) -> bool {
        self.close
    }

    /// Decode the owned head into caller-provided header slots.
    pub fn parse_head<'headers>(
        &self,
        slots: &'headers mut [HeaderSlot],
    ) -> Result<ResponseHead<'headers, '_>, ParseError> {
        match codec::parse_response_head_with_config(
            self.method,
            &self.head.bytes,
            slots,
            self.head.parser,
        )? {
            ParseStatus::Complete(head, consumed) if consumed == self.head.bytes.len() => Ok(head),
            _ => Err(ParseError::InvalidStartLine),
        }
    }

    pub(crate) fn from_wire(
        head: AcceptedHead,
        method: MethodKind,
        status: StatusCode,
        encapsulated: Option<EncapsulatedParts>,
        close: bool,
    ) -> Self {
        Self {
            head,
            method,
            status,
            encapsulated,
            close,
        }
    }
}

/// A validated raw encapsulated HTTP trailer block.
#[derive(Clone, Eq, PartialEq)]
pub struct TrailerBlock(Bytes);

impl TrailerBlock {
    /// Construct and validate a complete trailer block.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, ParseError> {
        let mut slots = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        match codec::parse_trailers(&bytes, &mut slots)? {
            ParseStatus::Complete(_, consumed) if consumed == bytes.len() => Ok(Self(bytes)),
            _ => Err(ParseError::InvalidHeader),
        }
    }

    /// Construct an empty trailer block.
    #[must_use]
    pub fn empty() -> Self {
        Self(Bytes::from_static(b"\r\n"))
    }

    /// Return the encoded trailer block, including its final empty line.
    #[must_use]
    pub const fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Return whether the block has no trailer fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.as_ref() == b"\r\n"
    }

    /// Decode the block into caller-provided header slots.
    pub fn parse<'headers>(
        &self,
        slots: &'headers mut [HeaderSlot],
    ) -> Result<Trailers<'headers, '_>, ParseError> {
        match codec::parse_trailers(&self.0, slots)? {
            ParseStatus::Complete(trailers, consumed) if consumed == self.0.len() => Ok(trailers),
            _ => Err(ParseError::InvalidHeader),
        }
    }

    pub(crate) const fn from_validated(bytes: Bytes) -> Self {
        Self(bytes)
    }
}

impl Default for TrailerBlock {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for TrailerBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrailerBlock")
            .field("encoded_len", &self.0.len())
            .finish()
    }
}

/// An owned ICAP message could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    /// A generated or supplied protocol value is invalid.
    Encode(EncodeError),
    /// A caller supplied a header generated by the message type.
    ReservedHeader,
    /// Encapsulated sections have an invalid shape or offset.
    InvalidEncapsulated,
    /// Preview was requested for a message without an entity body.
    InvalidPreview,
    /// An original-body length was supplied for a message without a body.
    InvalidBodyLength,
    /// A length cannot be represented or exceeds the head bound.
    MessageTooLarge,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Encode(_) => "invalid ICAP message",
            Self::ReservedHeader => "ICAP framing header is generated",
            Self::InvalidEncapsulated => "invalid encapsulated sections",
            Self::InvalidPreview => "invalid ICAP Preview use",
            Self::InvalidBodyLength => "invalid ICAP original-body length",
            Self::MessageTooLarge => "ICAP message metadata is too large",
        })
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EncodeError> for BuildError {
    fn from(value: EncodeError) -> Self {
        Self::Encode(value)
    }
}

impl From<crate::codec::InvalidHeader> for BuildError {
    fn from(_: crate::codec::InvalidHeader) -> Self {
        Self::Encode(EncodeError::InvalidInput)
    }
}

fn request_head_len<'a>(
    line: RequestLineSource<'_>,
    headers: impl Iterator<Item = Header<'a>>,
) -> Result<usize, BuildError> {
    let len = line
        .method()
        .as_str()
        .len()
        .checked_add(line.uri_len())
        .and_then(|len| len.checked_add(line.version().as_str().len()))
        .and_then(|len| len.checked_add(REQUEST_LINE_OVERHEAD))
        .ok_or(BuildError::MessageTooLarge)?;
    head_len_with_headers(len, headers)
}

fn response_head_len<'a>(
    line: ResponseLine<'_>,
    headers: impl Iterator<Item = Header<'a>>,
) -> Result<usize, BuildError> {
    let len = line
        .version()
        .as_str()
        .len()
        .checked_add(line.reason().len())
        .and_then(|len| len.checked_add(RESPONSE_LINE_OVERHEAD))
        .ok_or(BuildError::MessageTooLarge)?;
    head_len_with_headers(len, headers)
}

fn head_len_with_headers<'a>(
    mut len: usize,
    headers: impl Iterator<Item = Header<'a>>,
) -> Result<usize, BuildError> {
    for field in headers {
        let field_len = field
            .name()
            .len()
            .checked_add(field.value().encoded_len())
            .and_then(|len| len.checked_add(HEADER_FIELD_OVERHEAD))
            .ok_or(BuildError::MessageTooLarge)?;
        len = len
            .checked_add(field_len)
            .ok_or(BuildError::MessageTooLarge)?;
    }
    len = len
        .checked_add(HEADER_BLOCK_END_BYTES)
        .ok_or(BuildError::MessageTooLarge)?;
    if len > DEFAULT_MAX_HEAD_BYTES {
        Err(BuildError::MessageTooLarge)
    } else {
        Ok(len)
    }
}

fn encode_decimal(mut value: u64, dst: &mut [u8; 20]) -> &[u8] {
    let mut start = dst.len();
    loop {
        start -= 1;
        dst[start] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
        if value == 0 {
            return &dst[start..];
        }
    }
}

pub(crate) fn header_value_has_token(
    value: crate::codec::HeaderValue<'_>,
    expected: &[u8],
) -> bool {
    value.segments().any(|segment| {
        segment
            .split(|byte| *byte == b',')
            .any(|token| trim_ascii_whitespace(token).eq_ignore_ascii_case(expected))
    })
}

fn has_header_token(headers: &[Header<'_>], name: &str, expected: &[u8]) -> bool {
    headers.iter().copied().any(|field| {
        field.name().eq_ignore_ascii_case(name) && header_value_has_token(field.value(), expected)
    })
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{Header, HeaderFolding, RequestLine, ResponseLine},
        proto::{Method, StatusCode},
    };

    #[test]
    fn request_derives_offsets_without_copying_http_heads() {
        let req = Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n");
        let res = Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\n");
        let parts = EncapsulatedParts::new(
            Some(req.clone()),
            Some(res.clone()),
            EncapsulatedKind::ResponseBody,
        )
        .unwrap();
        let sections: Vec<_> = parts.sections().collect();
        assert_eq!(sections[0].offset(), 0);
        assert_eq!(sections[1].offset(), req.len() as u64);
        assert_eq!(sections[2].offset(), (req.len() + res.len()) as u64);
        assert_eq!(parts.request_header().unwrap().as_ptr(), req.as_ptr());
        assert_eq!(parts.response_header().unwrap().as_ptr(), res.as_ptr());

        let line = RequestLine::new(Method::Respmod, "icap://icap.test/echo").unwrap();
        let request = Request::with_preview(
            line,
            &[Header::new("Host", b"icap.test").unwrap()],
            parts,
            Preview::new(1024),
        )
        .unwrap();
        let mut slots = [HeaderSlot::EMPTY; 8];
        let head = request.parse_head(&mut slots).unwrap();
        assert_eq!(head.preview(), Some(Preview::new(1024)));
        assert_eq!(head.encapsulated().unwrap().section_count(), 3);
    }

    #[test]
    fn encapsulated_http_heads_require_a_terminating_empty_line() {
        assert_eq!(
            EncapsulatedParts::new(
                Some(Bytes::from_static(b"GET / HTTP/1.1\r\n")),
                None,
                EncapsulatedKind::NullBody,
            ),
            Err(BuildError::InvalidEncapsulated)
        );
    }

    #[test]
    fn original_body_length_requires_an_entity_body() {
        let request = Request::new(
            RequestLine::new(Method::Options, "icap://icap.test/echo").unwrap(),
            &[Header::new(header::HOST, b"icap.test").unwrap()],
            Some(EncapsulatedParts::null()),
        )
        .unwrap();
        assert!(matches!(
            request.try_with_original_body_len(0),
            Err(BuildError::InvalidBodyLength)
        ));
    }

    #[test]
    fn response_generates_encapsulated_header() {
        let parts = EncapsulatedParts::new(
            None,
            Some(Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\n")),
            EncapsulatedKind::NullBody,
        )
        .unwrap();
        let line = ResponseLine::new(StatusCode::OK, b"OK").unwrap();
        let response = Response::new(
            MethodKind::Respmod,
            line,
            &[Header::new(header::ISTAG, b"\"rama\"").unwrap()],
            Some(parts),
        )
        .unwrap();
        let mut slots = [HeaderSlot::EMPTY; 8];
        let head = response.parse_head(&mut slots).unwrap();
        assert_eq!(head.line().status(), StatusCode::OK);
        assert_eq!(
            head.encapsulated()
                .unwrap()
                .offset(EncapsulatedKind::NullBody),
            Some(19)
        );
    }

    #[test]
    fn wire_messages_reparse_with_their_accepted_policy() {
        let parser = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
        let request = Request::from_wire(
            AcceptedHead::from_wire(
                Bytes::from_static(
                    b"OPTIONS icap://icap.test/scan ICAP/1.0\r\n\
                      Host: icap.test\r\nX-Note: one\r\n two\r\n\r\n",
                ),
                parser,
            ),
            MethodKind::Options,
            None,
            None,
            false,
            false,
            false,
        );
        let mut slots = [HeaderSlot::EMPTY; 4];
        assert!(
            request
                .parse_head(&mut slots)
                .unwrap()
                .headers()
                .any(|field| field == Header::new("X-Note", b"one two").unwrap())
        );

        let response = Response::from_wire(
            AcceptedHead::from_wire(
                Bytes::from_static(
                    b"ICAP/1.0 404 Not Found\r\n\
                      ISTag: \"rama\"\r\nX-Note: one\r\n two\r\n\r\n",
                ),
                parser,
            ),
            MethodKind::Options,
            StatusCode::NOT_FOUND,
            None,
            false,
        );
        assert!(
            response
                .parse_head(&mut slots)
                .unwrap()
                .headers()
                .any(|field| field == Header::new("X-Note", b"one two").unwrap())
        );
    }

    #[test]
    fn trailer_block_validates_complete_input() {
        let block =
            TrailerBlock::from_bytes(Bytes::from_static(b"X-Checksum: abc\r\n\r\n")).unwrap();
        let mut slots = [HeaderSlot::EMPTY; 2];
        let trailers = block.parse(&mut slots).unwrap();
        assert_eq!(trailers.header_count(), 1);
        assert_eq!(TrailerBlock::empty().as_bytes().as_ref(), b"\r\n");
    }

    #[test]
    fn owned_message_debug_views_redact_wire_bytes() {
        let parts = EncapsulatedParts::new(
            Some(Bytes::from_static(
                b"GET / HTTP/1.1\r\nCookie: sensitive-http-cookie\r\n\r\n",
            )),
            None,
            EncapsulatedKind::NullBody,
        )
        .unwrap();
        let request = Request::new(
            RequestLine::new(Method::Reqmod, "icap://icap.test/echo").unwrap(),
            &[
                Header::new(header::HOST, b"icap.test").unwrap(),
                Header::new("Authorization", b"sensitive-icap-token").unwrap(),
            ],
            Some(parts),
        )
        .unwrap();
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains("sensitive-icap-token"));
        assert!(!request_debug.contains("sensitive-http-cookie"));

        let response = Response::new(
            MethodKind::Reqmod,
            ResponseLine::new(StatusCode::NO_MODIFICATION_NEEDED, b"No Content").unwrap(),
            &[
                Header::new(header::ISTAG, b"\"rama\"").unwrap(),
                Header::new("X-Secret", b"sensitive-response-token").unwrap(),
            ],
            None,
        )
        .unwrap();
        assert!(!format!("{response:?}").contains("sensitive-response-token"));
    }
}
