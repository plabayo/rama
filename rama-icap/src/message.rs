//! Owned ICAP message metadata for asynchronous transactions.

use core::fmt;

use rama_core::bytes::{Bytes, BytesMut};

use crate::{
    byte_sets::{comma_separated_items, is_token_byte},
    codec::{
        self, DEFAULT_MAX_HEAD_BYTES, DEFAULT_MAX_HEADERS, EncodeError, HeadParserConfig, Header,
        HeaderSlot, HeaderValue, ParseError, ParseStatus, RequestHead, RequestLine,
        RequestLineSource, ResponseHead, ResponseLine, Trailers,
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

/// Validated names promised for a negotiated outer ICAP trailer block.
///
/// The stored value uses one canonical comma-separated representation. Names
/// retain their spelling and comparisons are case-insensitive. The list is
/// bounded by the protocol header-count limit.
#[derive(Clone, Eq, PartialEq)]
pub struct IcapTrailerNames(Bytes);

impl IcapTrailerNames {
    /// Construct a trailer promise from a comma-separated field-name list.
    pub fn from_bytes(value: &[u8]) -> Result<Self, BuildError> {
        if value.len() > DEFAULT_MAX_HEAD_BYTES {
            return Err(BuildError::InvalidTrailerPromise);
        }
        canonicalize_icap_trailer_names(BytesMut::from(value))
            .map(Self)
            .map_err(|()| BuildError::InvalidTrailerPromise)
    }

    /// Construct a trailer promise from individual field names.
    pub fn new<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Self, BuildError> {
        let mut stored = [""; DEFAULT_MAX_HEADERS];
        let mut count = 0;
        let mut length = 0_usize;
        for name in names {
            let bytes = name.as_bytes();
            let separator_len = usize::from(count != 0).saturating_mul(2);
            if count == DEFAULT_MAX_HEADERS
                || bytes.is_empty()
                || !bytes.iter().copied().all(is_token_byte)
                || length
                    .checked_add(separator_len)
                    .and_then(|len| len.checked_add(bytes.len()))
                    .is_none_or(|len| len > DEFAULT_MAX_HEAD_BYTES)
            {
                return Err(BuildError::InvalidTrailerPromise);
            }
            stored[count] = name;
            length += separator_len + bytes.len();
            count += 1;
        }
        let mut value = BytesMut::with_capacity(length);
        for (index, name) in stored[..count].iter().enumerate() {
            if index != 0 {
                value.extend_from_slice(b", ");
            }
            value.extend_from_slice(name.as_bytes());
        }
        canonicalize_icap_trailer_names(value)
            .map(Self)
            .map_err(|()| BuildError::InvalidTrailerPromise)
    }

    /// Return the canonical comma-separated value.
    #[must_use]
    pub const fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Iterate over the promised field names without allocating.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        comma_separated_items(&self.0).filter_map(|name| core::str::from_utf8(name).ok())
    }

    /// Return whether `name` occurs in the promise.
    #[must_use]
    pub fn contains_ignore_ascii_case(&self, name: &str) -> bool {
        self.iter()
            .any(|promised| promised.eq_ignore_ascii_case(name))
    }

    pub(crate) fn from_header_values<'a, I>(values: I) -> Result<Option<Self>, ParseError>
    where
        I: IntoIterator<Item = HeaderValue<'a>>,
        I::IntoIter: Clone,
    {
        let values = values.into_iter();
        let mut value_count = 0_usize;
        let capacity = values
            .clone()
            .try_fold(0_usize, |length, value| {
                let mut segment_count = 0_usize;
                let value_length = value.segments().try_fold(0_usize, |length, segment| {
                    let separator = usize::from(segment_count != 0);
                    segment_count += 1;
                    length
                        .checked_add(separator)
                        .and_then(|length| length.checked_add(segment.len()))
                })?;
                let separator = usize::from(value_count != 0);
                value_count += 1;
                length
                    .checked_add(separator)
                    .and_then(|length| length.checked_add(value_length))
            })
            .filter(|length| *length <= DEFAULT_MAX_HEAD_BYTES)
            .ok_or(ParseError::InvalidHeader)?;
        if value_count == 0 {
            return Ok(None);
        }

        let mut normalized = BytesMut::with_capacity(capacity);
        let mut saw_value = false;
        for value in values {
            if saw_value {
                normalized.extend_from_slice(b",");
            }
            let mut saw_segment = false;
            for segment in value.segments() {
                if saw_segment {
                    normalized.extend_from_slice(b" ");
                }
                normalized.extend_from_slice(segment);
                saw_segment = true;
            }
            saw_value = true;
        }
        debug_assert!(saw_value);
        canonicalize_icap_trailer_names(normalized)
            .map(|value| Some(Self(value)))
            .map_err(|()| ParseError::InvalidHeader)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RequestWireMetadata {
    pub(crate) preview: Option<Preview>,
    pub(crate) allow_204: bool,
    pub(crate) allow_206: bool,
    pub(crate) allow_icap_trailers: bool,
    pub(crate) close: bool,
}

impl fmt::Debug for IcapTrailerNames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IcapTrailerNames")
            .field("count", &self.iter().count())
            .finish()
    }
}

fn canonicalize_icap_trailer_names(mut value: BytesMut) -> Result<Bytes, ()> {
    let source_len = value.len();
    if source_len > DEFAULT_MAX_HEAD_BYTES {
        return Err(());
    }
    let mut ranges = [(0_usize, 0_usize); DEFAULT_MAX_HEADERS];
    let mut item_start = 0;
    let mut count = 0;
    for item_end in 0..=source_len {
        if item_end != source_len && value[item_end] != b',' {
            continue;
        }
        let mut start = item_start;
        let mut end = item_end;
        while start < end && matches!(value[start], b' ' | b'\t') {
            start += 1;
        }
        while end > start && matches!(value[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        if start == end || !value[start..end].iter().copied().all(is_token_byte) {
            return Err(());
        }
        if count == DEFAULT_MAX_HEADERS {
            return Err(());
        }
        ranges[count] = (start, end);
        count += 1;
        item_start = item_end.saturating_add(1);
    }
    if count == 0 {
        return Err(());
    }

    let ranges = &mut ranges[..count];
    ranges.sort_unstable_by(|left, right| {
        value[left.0..left.1]
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(value[right.0..right.1].iter().map(u8::to_ascii_lowercase))
    });
    if ranges
        .windows(2)
        .any(|pair| value[pair[0].0..pair[0].1].eq_ignore_ascii_case(&value[pair[1].0..pair[1].1]))
    {
        return Err(());
    }

    ranges.sort_unstable_by_key(|range| range.0);
    let mut write = 0;
    for (index, &(start, end)) in ranges.iter().enumerate() {
        if index != 0 {
            value[write] = b',';
            write += 1;
        }
        for source in start..end {
            value[write] = value[source];
            write += 1;
        }
    }
    value.truncate(write);
    Ok(value.freeze())
}

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
    allow_icap_trailers: bool,
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
            .field("allow_icap_trailers", &self.allow_icap_trailers)
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
            allow_icap_trailers: has_header_token(headers, header::ALLOW, b"trailers"),
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

    /// Return whether the request offers negotiated outer ICAP trailers.
    #[must_use]
    pub const fn allows_icap_trailers(&self) -> bool {
        self.allow_icap_trailers
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
        encapsulated: Option<EncapsulatedParts>,
        metadata: RequestWireMetadata,
    ) -> Self {
        Self {
            head,
            method,
            preview: metadata.preview,
            encapsulated,
            original_body_len: None,
            allow_204: metadata.allow_204,
            allow_206: metadata.allow_206,
            allow_icap_trailers: metadata.allow_icap_trailers,
            close: metadata.close,
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
    allow_icap_trailers: bool,
    icap_trailer_names: Option<IcapTrailerNames>,
    close: bool,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("method", &self.method)
            .field("status", &self.status)
            .field("head_len", &self.head.bytes.len())
            .field("encapsulated", &self.encapsulated)
            .field("allow_icap_trailers", &self.allow_icap_trailers)
            .field("icap_trailer_names", &self.icap_trailer_names)
            .field("close", &self.close)
            .finish()
    }
}

impl Response {
    /// Construct a response from a complete, validated wire head.
    ///
    /// The separately framed encapsulated prefix must already have been
    /// converted into [`EncapsulatedParts`]. Its derived sections must match
    /// the head's `Encapsulated` field. The parser policy is retained so later
    /// calls to [`Response::parse_head`] use the same accepted syntax.
    pub fn from_head_bytes(
        method: MethodKind,
        bytes: Bytes,
        headers: &mut [HeaderSlot],
        parser: HeadParserConfig,
        encapsulated: Option<EncapsulatedParts>,
    ) -> Result<Self, ParseError> {
        let (status, allow_icap_trailers, icap_trailer_names, close) = {
            let ParseStatus::Complete(head, consumed) =
                codec::parse_response_head_with_config(method, &bytes, headers, parser)?
            else {
                return Err(ParseError::InvalidStartLine);
            };
            if consumed != bytes.len()
                || !match (head.encapsulated(), encapsulated.as_ref()) {
                    (Some(parsed), Some(parts)) => parsed.iter().eq(parts.sections()),
                    (None, None) => true,
                    _ => false,
                }
            {
                return Err(ParseError::InvalidComposition);
            }
            let close = head.headers().any(|field| {
                field.name().eq_ignore_ascii_case(header::CONNECTION)
                    && header_value_has_token(field.value(), b"close")
            });
            let allow_icap_trailers = head.headers().any(|field| {
                field.name().eq_ignore_ascii_case(header::ALLOW)
                    && header_value_has_token(field.value(), b"trailers")
            });
            let icap_trailer_names = IcapTrailerNames::from_header_values(
                head.headers()
                    .filter(|field| field.name().eq_ignore_ascii_case(header::TRAILER))
                    .map(Header::value),
            )?;
            (
                head.line().status(),
                allow_icap_trailers,
                icap_trailer_names,
                close,
            )
        };

        Ok(Self {
            head: AcceptedHead::from_wire(bytes, parser),
            method,
            status,
            encapsulated,
            allow_icap_trailers,
            icap_trailer_names,
            close,
        })
    }

    /// Encode an ICAP response for the corresponding request method.
    pub fn new(
        method: MethodKind,
        line: ResponseLine<'_>,
        headers: &[Header<'_>],
        encapsulated: Option<EncapsulatedParts>,
    ) -> Result<Self, BuildError> {
        Self::build(method, line, headers, encapsulated, None)
    }

    /// Encode a response that promises a separate outer ICAP trailer block.
    ///
    /// The response automatically advertises `Allow: trailers`. The actual
    /// outer fields are supplied when the streaming body is finished.
    pub fn new_with_icap_trailer_names(
        method: MethodKind,
        line: ResponseLine<'_>,
        headers: &[Header<'_>],
        encapsulated: EncapsulatedParts,
        names: IcapTrailerNames,
    ) -> Result<Self, BuildError> {
        Self::build(method, line, headers, Some(encapsulated), Some(names))
    }

    fn build(
        method: MethodKind,
        line: ResponseLine<'_>,
        headers: &[Header<'_>],
        encapsulated: Option<EncapsulatedParts>,
        icap_trailer_names: Option<IcapTrailerNames>,
    ) -> Result<Self, BuildError> {
        if headers.iter().any(|field| {
            field.name().eq_ignore_ascii_case(header::ENCAPSULATED)
                || field.name().eq_ignore_ascii_case(header::TRAILER)
        }) {
            return Err(BuildError::ReservedHeader);
        }
        if icap_trailer_names.is_some()
            && (!matches!(method, MethodKind::Reqmod | MethodKind::Respmod)
                || line.status() == StatusCode::CONTINUE
                || line.status() == StatusCode::NO_MODIFICATION_NEEDED
                || encapsulated.as_ref().is_none_or(|parts| !parts.has_body()))
        {
            return Err(BuildError::InvalidTrailerPromise);
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
        let trailer_header = icap_trailer_names
            .as_ref()
            .map(|names| Header::new(header::TRAILER, names.as_bytes()))
            .transpose()?;
        let generated_allow = icap_trailer_names
            .as_ref()
            .filter(|_| !has_header_token(headers, header::ALLOW, b"trailers"))
            .map(|_| Header::new(header::ALLOW, b"trailers"))
            .transpose()?;
        let fields = headers
            .iter()
            .copied()
            .chain(generated_allow)
            .chain(trailer_header)
            .chain(encapsulated_header);
        let len = response_head_len(line, fields.clone())?;
        let mut head = BytesMut::zeroed(len);
        let written = codec::encode_response_head_iter(method, line, fields, &mut head)?;
        debug_assert_eq!(written, len);

        Ok(Self {
            head: AcceptedHead::encoded(head.freeze()),
            method,
            status: line.status(),
            encapsulated,
            allow_icap_trailers: has_header_token(headers, header::ALLOW, b"trailers")
                || icap_trailer_names.is_some(),
            icap_trailer_names,
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

    /// Return whether this response advertises support for outer ICAP trailers.
    #[must_use]
    pub const fn allows_icap_trailers(&self) -> bool {
        self.allow_icap_trailers
    }

    /// Return the names promised for the outer ICAP trailer block.
    #[must_use]
    pub const fn icap_trailer_names(&self) -> Option<&IcapTrailerNames> {
        self.icap_trailer_names.as_ref()
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
        allow_icap_trailers: bool,
        icap_trailer_names: Option<IcapTrailerNames>,
        close: bool,
    ) -> Self {
        Self {
            head,
            method,
            status,
            encapsulated,
            allow_icap_trailers,
            icap_trailer_names,
            close,
        }
    }
}

/// One validated raw trailer field block.
///
/// Transaction APIs assign the block's provenance explicitly as either
/// encapsulated HTTP trailers or negotiated outer ICAP trailers.
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

    pub(crate) fn empty_icap_compat() -> Self {
        Self(Bytes::from_static(b"X-Empty-Trailer: 0\r\n\r\n"))
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
#[non_exhaustive]
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
    /// An outer ICAP trailer promise is malformed or invalid for the response.
    InvalidTrailerPromise,
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
            Self::InvalidTrailerPromise => "invalid outer ICAP trailer promise",
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
        .checked_add(line.uri_len()?)
        .and_then(|len| len.checked_add(line.version().as_str().len()))
        .and_then(|len| len.checked_add(REQUEST_LINE_OVERHEAD))
        .ok_or(BuildError::MessageTooLarge)?;
    let len = match line.prepared_host_len()? {
        Some(host_len) => len
            .checked_add(header::HOST.len())
            .and_then(|len| len.checked_add(host_len))
            .and_then(|len| len.checked_add(HEADER_FIELD_OVERHEAD))
            .ok_or(BuildError::MessageTooLarge)?,
        None => len,
    };
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
        comma_separated_items(segment).any(|token| token.eq_ignore_ascii_case(expected))
    })
}

fn has_header_token(headers: &[Header<'_>], name: &str, expected: &[u8]) -> bool {
    headers.iter().copied().any(|field| {
        field.name().eq_ignore_ascii_case(name) && header_value_has_token(field.value(), expected)
    })
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
            RequestWireMetadata {
                preview: None,
                allow_204: false,
                allow_206: false,
                allow_icap_trailers: false,
                close: false,
            },
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
    fn icap_trailer_names_are_canonical_unique_tokens() {
        let names = IcapTrailerNames::from_bytes(b" X-Scan , X-Score\t").unwrap();
        assert_eq!(names.as_bytes().as_ref(), b"X-Scan,X-Score");
        assert!(names.contains_ignore_ascii_case("x-scan"));
        assert_eq!(names.iter().collect::<Vec<_>>(), ["X-Scan", "X-Score"]);

        for invalid in [
            b"".as_slice(),
            b"X-Scan,".as_slice(),
            b"X-Scan,,X-Score".as_slice(),
            b"X Scan".as_slice(),
            b"X-Scan,x-scan".as_slice(),
        ] {
            assert_eq!(
                IcapTrailerNames::from_bytes(invalid),
                Err(BuildError::InvalidTrailerPromise)
            );
        }

        let oversized = (0..=DEFAULT_MAX_HEADERS)
            .map(|index| format!("X-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            IcapTrailerNames::from_bytes(oversized.as_bytes()),
            Err(BuildError::InvalidTrailerPromise)
        );

        let boundary = (0..DEFAULT_MAX_HEADERS)
            .rev()
            .map(|index| format!("X-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            IcapTrailerNames::from_bytes(boundary.as_bytes())
                .unwrap()
                .iter()
                .count(),
            DEFAULT_MAX_HEADERS
        );
        let duplicate_at_boundary = (0..DEFAULT_MAX_HEADERS - 1)
            .rev()
            .map(|index| format!("X-{index}"))
            .chain(core::iter::once(String::from("x-0")))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            IcapTrailerNames::from_bytes(duplicate_at_boundary.as_bytes()),
            Err(BuildError::InvalidTrailerPromise)
        );

        let exact_head_limit = vec![b'x'; DEFAULT_MAX_HEAD_BYTES];
        assert_eq!(
            IcapTrailerNames::from_bytes(&exact_head_limit)
                .unwrap()
                .as_bytes()
                .len(),
            DEFAULT_MAX_HEAD_BYTES
        );
    }

    #[test]
    fn strict_requires_response_trailer_echo_while_compatible_records_promise() {
        let wire = Bytes::from_static(
            b"ICAP/1.0 200 OK\r\n\
              ISTag: \"rama\"\r\n\
              Trailer: X-Scan\r\n\
              Encapsulated: res-body=0\r\n\r\n",
        );
        let parts = EncapsulatedParts::new(None, None, EncapsulatedKind::ResponseBody).unwrap();
        let mut slots = [HeaderSlot::EMPTY; 8];
        assert!(matches!(
            Response::from_head_bytes(
                MethodKind::Respmod,
                wire.clone(),
                &mut slots,
                HeadParserConfig::new(),
                Some(parts.clone()),
            ),
            Err(ParseError::InvalidComposition)
        ));
        let response = Response::from_head_bytes(
            MethodKind::Respmod,
            wire,
            &mut slots,
            HeadParserConfig::compatible(),
            Some(parts),
        )
        .unwrap();
        assert!(!response.allows_icap_trailers());
        assert!(
            response
                .icap_trailer_names()
                .unwrap()
                .contains_ignore_ascii_case("x-scan")
        );
    }

    #[test]
    fn unrelated_allow_tokens_do_not_negotiate_icap_trailers() {
        let wire = Bytes::from_static(
            b"ICAP/1.0 200 OK\r\n\
              ISTag: \"rama\"\r\n\
              Allow: 204\r\n\
              Encapsulated: res-body=0\r\n\r\n",
        );
        let parts = EncapsulatedParts::new(None, None, EncapsulatedKind::ResponseBody).unwrap();
        let mut slots = [HeaderSlot::EMPTY; 8];
        let response = Response::from_head_bytes(
            MethodKind::Respmod,
            wire,
            &mut slots,
            HeadParserConfig::compatible(),
            Some(parts),
        )
        .unwrap();
        assert!(!response.allows_icap_trailers());
    }

    #[test]
    fn response_combines_repeated_and_compatibly_folded_trailer_promises() {
        let wire = Bytes::from_static(
            b"ICAP/1.0 200 OK\r\nISTag: \"rama\"\r\nAllow: trailers\r\nTrailer: X-Scan,\r\n X-Score\r\nTrailer: X-Policy\r\nEncapsulated: res-body=0\r\n\r\n",
        );
        let parts = EncapsulatedParts::new(None, None, EncapsulatedKind::ResponseBody).unwrap();
        let mut slots = [HeaderSlot::EMPTY; 8];
        let response = Response::from_head_bytes(
            MethodKind::Respmod,
            wire,
            &mut slots,
            HeadParserConfig::compatible(),
            Some(parts),
        )
        .unwrap();
        assert_eq!(
            response.icap_trailer_names().unwrap().as_bytes().as_ref(),
            b"X-Scan,X-Score,X-Policy"
        );
    }

    #[test]
    fn request_derives_outer_trailer_offer_across_allow_fields() {
        let request = Request::new(
            RequestLine::new(Method::Reqmod, "icap://icap.test/echo").unwrap(),
            &[
                Header::new(header::HOST, b"icap.test").unwrap(),
                Header::new(header::ALLOW, b"204").unwrap(),
                Header::new(header::ALLOW, b"206, Trailers").unwrap(),
            ],
            Some(EncapsulatedParts::new(None, None, EncapsulatedKind::RequestBody).unwrap()),
        )
        .unwrap();
        assert!(request.allows_icap_trailers());
    }

    #[test]
    fn response_builder_reserves_and_validates_outer_trailer_promises() {
        let names = IcapTrailerNames::new(["X-Scan"]).unwrap();
        let body = EncapsulatedParts::new(None, None, EncapsulatedKind::ResponseBody).unwrap();
        let response = Response::new_with_icap_trailer_names(
            MethodKind::Respmod,
            ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
            &[Header::new(header::ISTAG, b"\"rama\"").unwrap()],
            body,
            names.clone(),
        )
        .unwrap();
        assert!(response.allows_icap_trailers());
        assert_eq!(response.icap_trailer_names(), Some(&names));
        assert!(
            response
                .head_bytes()
                .windows(b"Allow: trailers".len())
                .any(|value| { value.eq_ignore_ascii_case(b"Allow: trailers") })
        );

        let reserved = Response::new(
            MethodKind::Respmod,
            ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
            &[
                Header::new(header::ISTAG, b"\"rama\"").unwrap(),
                Header::new(header::TRAILER, b"X-Scan").unwrap(),
            ],
            Some(EncapsulatedParts::null()),
        );
        assert!(matches!(reserved, Err(BuildError::ReservedHeader)));

        for (method, status, parts) in [
            (
                MethodKind::Options,
                StatusCode::OK,
                EncapsulatedParts::null(),
            ),
            (
                MethodKind::Respmod,
                StatusCode::CONTINUE,
                EncapsulatedParts::new(None, None, EncapsulatedKind::ResponseBody).unwrap(),
            ),
            (
                MethodKind::Respmod,
                StatusCode::NO_MODIFICATION_NEEDED,
                EncapsulatedParts::new(None, None, EncapsulatedKind::ResponseBody).unwrap(),
            ),
            (
                MethodKind::Respmod,
                StatusCode::OK,
                EncapsulatedParts::null(),
            ),
        ] {
            assert!(matches!(
                Response::new_with_icap_trailer_names(
                    method,
                    ResponseLine::new(status, b"status").unwrap(),
                    &[Header::new(header::ISTAG, b"\"rama\"").unwrap()],
                    parts,
                    names.clone(),
                ),
                Err(BuildError::InvalidTrailerPromise)
            ));
        }
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
