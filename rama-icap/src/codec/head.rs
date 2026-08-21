use core::fmt;

use rama_net::{Protocol, uri::AbsoluteUriRef};

use crate::{
    byte_sets::{is_field_value_byte, is_horizontal_whitespace_byte, is_token_byte},
    proto::{
        InvalidMethod, InvalidStatusCode, InvalidVersion, Method, MethodKind, Preview, StatusCode,
        Version, header, is_token,
    },
};

use super::encapsulated::{Encapsulated, EncapsulatedContext, parse_encapsulated};
use super::{Framed, ScanStatus};

/// Default maximum number of ICAP header fields decoded into a head.
pub const DEFAULT_MAX_HEADERS: usize = 64;

/// Default maximum encoded size of an ICAP start line and header block.
pub const DEFAULT_MAX_HEAD_BYTES: usize = 64 * 1024;

/// Policy for the obsolete line folding admitted by RFC 3507.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderFolding {
    /// Reject folded field values.
    Reject,
    /// Accept folded values and normalize folds when encoding.
    Allow,
}

/// Policy for method-, status-, and direction-specific head validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionValidation {
    /// Reject a syntactically valid head with invalid message composition.
    Enabled,
    /// Return the head and leave composition checks to its `validate` method.
    Disabled,
}

/// Accepted syntax for the ICAP service tag header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceTagSyntax {
    /// Require the quoted-string syntax specified by RFC 3507.
    Quoted,
    /// Also accept an unquoted token for compatibility with c-icap.
    AllowUnquotedToken,
}

/// Bounds and compatibility policy for ICAP head decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadParserConfig {
    max_bytes: usize,
    header_folding: HeaderFolding,
    composition_validation: CompositionValidation,
    service_tag_syntax: ServiceTagSyntax,
}

impl HeadParserConfig {
    /// Construct the default bounded, strict parser configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_HEAD_BYTES,
            header_folding: HeaderFolding::Reject,
            composition_validation: CompositionValidation::Enabled,
            service_tag_syntax: ServiceTagSyntax::Quoted,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum start-line and header-block size.
        pub const fn max_bytes(mut self, max_bytes: usize) -> Self {
            self.max_bytes = max_bytes;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the obsolete line-folding policy.
        pub const fn header_folding(mut self, header_folding: HeaderFolding) -> Self {
            self.header_folding = header_folding;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether parsing also validates message composition.
        pub const fn composition_validation(
            mut self,
            composition_validation: CompositionValidation,
        ) -> Self {
            self.composition_validation = composition_validation;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the accepted service tag syntax.
        pub const fn service_tag_syntax(
            mut self,
            service_tag_syntax: ServiceTagSyntax,
        ) -> Self {
            self.service_tag_syntax = service_tag_syntax;
            self
        }
    }

    /// Return the maximum start-line and header-block size.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    /// Return the obsolete line-folding policy.
    #[must_use]
    pub const fn header_folding(self) -> HeaderFolding {
        self.header_folding
    }

    /// Return whether parsing also validates message composition.
    #[must_use]
    pub const fn composition_validation(self) -> CompositionValidation {
        self.composition_validation
    }

    /// Return the accepted service tag syntax.
    #[must_use]
    pub const fn service_tag_syntax(self) -> ServiceTagSyntax {
        self.service_tag_syntax
    }
}

impl Default for HeadParserConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of parsing a possibly incomplete input buffer.
///
/// The stateless parsers rescan their input. A network decoder receiving
/// small increments should use [`HeadScanner`] and invoke the head parser
/// only after the scanner finds the terminating empty line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseStatus<T> {
    /// More bytes are required.
    Partial,
    /// A complete value and its consumed byte count.
    Complete(T, usize),
}

/// Incremental, allocation-free ICAP head terminator scanner.
///
/// Each call consumes only bytes received since the previous call. A
/// completed scanner becomes a [`Framed`] value and cannot be polled again.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeadScanner {
    scanned: usize,
    tail: [u8; 3],
    tail_len: u8,
}

impl HeadScanner {
    /// Construct an empty scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scanned: 0,
            tail: [0; 3],
            tail_len: 0,
        }
    }

    /// Scan the next stream bytes for the end of an ICAP head.
    ///
    /// Pass only bytes not supplied to an earlier call. When more input is
    /// required, continue with the scanner returned by [`ScanStatus::Partial`].
    pub fn scan(
        mut self,
        src: &[u8],
        config: HeadParserConfig,
    ) -> Result<ScanStatus<Self>, ParseError> {
        if self.scanned > config.max_bytes {
            return Err(ParseError::HeadTooLarge);
        }
        for byte in src.iter().copied() {
            if self.scanned >= config.max_bytes {
                return Err(ParseError::HeadTooLarge);
            }
            let previous = self.previous();
            match byte {
                b'\n' if previous != Some(b'\r') => {
                    return Err(ParseError::InvalidLineEnding);
                }
                b'\n' => {}
                _ if previous == Some(b'\r') => {
                    return Err(ParseError::InvalidLineEnding);
                }
                _ => {}
            }
            let complete = self.tail_len == 3 && self.tail == *b"\r\n\r" && byte == b'\n';
            self.scanned = self
                .scanned
                .checked_add(1)
                .ok_or(ParseError::HeadTooLarge)?;
            if complete {
                return Ok(ScanStatus::Complete(Framed::new(self.scanned)));
            }
            self.push_tail(byte);
        }
        Ok(ScanStatus::Partial(self))
    }

    fn previous(&self) -> Option<u8> {
        if self.tail_len == 0 {
            None
        } else {
            Some(self.tail[usize::from(self.tail_len) - 1])
        }
    }

    fn push_tail(&mut self, byte: u8) {
        let tail_len = usize::from(self.tail_len);
        if tail_len < self.tail.len() {
            self.tail[tail_len] = byte;
            self.tail_len += 1;
        } else {
            // Only the last three bytes can begin the CRLFCRLF terminator.
            self.tail.copy_within(1.., 0);
            self.tail[2] = byte;
        }
    }
}

/// Incremental scanner for an encapsulated HTTP trailer block.
///
/// Unlike an ICAP head, an empty trailer block is framed by one CRLF. Each
/// call consumes only bytes received since the previous call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrailerScanner(HeadScanner);

impl TrailerScanner {
    /// Construct an empty trailer scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self(HeadScanner {
            scanned: 0,
            tail: [b'\r', b'\n', 0],
            tail_len: 2,
        })
    }

    /// Scan the next stream bytes for the end of the trailer block.
    pub fn scan(
        self,
        src: &[u8],
        config: HeadParserConfig,
    ) -> Result<ScanStatus<Self>, ParseError> {
        match self.0.scan(src, config)? {
            ScanStatus::Partial(scanner) => Ok(ScanStatus::Partial(Self(scanner))),
            ScanStatus::Complete(framed) => Ok(ScanStatus::Complete(framed)),
        }
    }
}

impl Default for TrailerScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// A borrowed header field value.
///
/// Strictly parsed and constructed values are contiguous. Compatibility-mode
/// values retain obsolete wire folds internally and expose only unfolded
/// segments, preventing embedded CRLF from escaping as an ordinary value.
#[derive(Clone, Copy)]
pub struct HeaderValue<'a>(HeaderValueKind<'a>);

#[derive(Clone, Copy, Eq, PartialEq)]
enum HeaderValueKind<'a> {
    Contiguous(&'a [u8]),
    Folded(&'a [u8]),
}

impl fmt::Debug for HeaderValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, len) = match self.0 {
            HeaderValueKind::Contiguous(value) => ("contiguous", value.len()),
            HeaderValueKind::Folded(value) => ("folded", value.len()),
        };
        f.debug_struct("HeaderValue")
            .field("kind", &kind)
            .field("len", &len)
            .finish()
    }
}

impl<'a> HeaderValue<'a> {
    const fn contiguous(value: &'a [u8]) -> Self {
        Self(HeaderValueKind::Contiguous(value))
    }

    const fn folded(raw: &'a [u8]) -> Self {
        Self(HeaderValueKind::Folded(raw))
    }

    /// Return the contiguous bytes, or `None` for a folded wire value.
    #[must_use]
    pub const fn as_bytes(self) -> Option<&'a [u8]> {
        match self.0 {
            HeaderValueKind::Contiguous(value) => Some(value),
            HeaderValueKind::Folded(_) => None,
        }
    }

    /// Iterate over non-empty unfolded value segments.
    pub const fn segments(self) -> HeaderValueSegments<'a> {
        let raw = match self.0 {
            HeaderValueKind::Contiguous(value) | HeaderValueKind::Folded(value) => value,
        };
        HeaderValueSegments {
            remaining: raw,
            contiguous: matches!(self.0, HeaderValueKind::Contiguous(_)),
        }
    }

    /// Return the encoded length after obsolete folds are normalized.
    #[must_use]
    pub fn encoded_len(self) -> usize {
        let mut len = 0_usize;
        let mut count = 0_usize;
        for segment in self.segments() {
            len = len.saturating_add(segment.len());
            count += 1;
        }
        len.saturating_add(count.saturating_sub(1))
    }
}

impl PartialEq for HeaderValue<'_> {
    fn eq(&self, other: &Self) -> bool {
        NormalizedHeaderValueBytes::new(*self).eq(NormalizedHeaderValueBytes::new(*other))
    }
}

impl Eq for HeaderValue<'_> {}

/// Iterator over the normalized segments of a header value.
#[derive(Clone)]
pub struct HeaderValueSegments<'a> {
    remaining: &'a [u8],
    contiguous: bool,
}

impl fmt::Debug for HeaderValueSegments<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderValueSegments")
            .field("remaining_len", &self.remaining.len())
            .field("contiguous", &self.contiguous)
            .finish()
    }
}

impl<'a> Iterator for HeaderValueSegments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.remaining.is_empty() {
                return None;
            }
            if self.contiguous {
                self.contiguous = false;
                return Some(core::mem::take(&mut self.remaining));
            }

            let (segment, rest) = match self
                .remaining
                .windows(2)
                .position(|window| window == b"\r\n")
            {
                Some(index) => (&self.remaining[..index], &self.remaining[index + 2..]),
                None => (self.remaining, &[] as &[u8]),
            };
            self.remaining = rest;
            let segment = trim_header_whitespace(segment);
            if !segment.is_empty() {
                return Some(segment);
            }
        }
    }
}

struct NormalizedHeaderValueBytes<'a> {
    segments: HeaderValueSegments<'a>,
    current: &'a [u8],
    index: usize,
    emitted_segment: bool,
}

impl<'a> NormalizedHeaderValueBytes<'a> {
    fn new(value: HeaderValue<'a>) -> Self {
        Self {
            segments: value.segments(),
            current: &[],
            index: 0,
            emitted_segment: false,
        }
    }
}

impl Iterator for NormalizedHeaderValueBytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(byte) = self.current.get(self.index).copied() {
                self.index += 1;
                return Some(byte);
            }
            self.current = self.segments.next()?;
            self.index = 0;
            if core::mem::replace(&mut self.emitted_segment, true) {
                return Some(b' ');
            }
        }
    }
}

/// A borrowed ICAP header field.
#[derive(Clone, Copy)]
pub struct Header<'a> {
    name: &'a str,
    value: HeaderValue<'a>,
}

impl fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("name", &self.name)
            .field("value", &self.value)
            .finish()
    }
}

/// One caller-owned slot used while parsing an ICAP head.
///
/// Initialize a buffer with [`HeaderSlot::EMPTY`]. Parsed heads borrow the
/// initialized prefix, keeping capacity and stack use under caller control.
/// Slots contain byte ranges rather than source references, so the same
/// storage can be reused while an input buffer grows or after it is recycled.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeaderSlot(Option<HeaderRange>);

impl HeaderSlot {
    /// An empty parser output slot.
    pub const EMPTY: Self = Self(None);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeaderRange {
    name_start: u32,
    name_end: u32,
    value_start: u32,
    value_end: u32,
    folded: bool,
}

impl HeaderRange {
    fn new(
        name_start: usize,
        name_end: usize,
        value_start: usize,
        value_end: usize,
    ) -> Result<Self, ParseError> {
        Ok(Self {
            name_start: u32::try_from(name_start).map_err(|_error| ParseError::HeadTooLarge)?,
            name_end: u32::try_from(name_end).map_err(|_error| ParseError::HeadTooLarge)?,
            value_start: u32::try_from(value_start).map_err(|_error| ParseError::HeadTooLarge)?,
            value_end: u32::try_from(value_end).map_err(|_error| ParseError::HeadTooLarge)?,
            folded: false,
        })
    }

    fn name(self) -> Option<core::ops::Range<usize>> {
        Some(usize::try_from(self.name_start).ok()?..usize::try_from(self.name_end).ok()?)
    }

    fn value(self) -> Option<core::ops::Range<usize>> {
        Some(usize::try_from(self.value_start).ok()?..usize::try_from(self.value_end).ok()?)
    }
}

/// Iterator over parsed header fields.
#[derive(Clone)]
pub struct ParsedHeaders<'headers, 'src> {
    src: &'src [u8],
    slots: &'headers [HeaderSlot],
    index: usize,
}

impl fmt::Debug for ParsedHeaders<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedHeaders")
            .field("header_count", &self.slots.len())
            .field("index", &self.index)
            .finish()
    }
}

impl<'src> Iterator for ParsedHeaders<'_, 'src> {
    type Item = Header<'src>;

    fn next(&mut self) -> Option<Self::Item> {
        let range = self.slots.get(self.index)?.0?;
        self.index += 1;
        header_from_range(self.src, range)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.slots.len().saturating_sub(self.index);
        (0, Some(remaining))
    }
}

/// A decoded encapsulated HTTP trailer block.
///
/// RFC 3507 erratum e2 requires ICAP recipients to accept and preserve HTTP
/// trailers. ICAP trailer fields are intentionally not encoded here because
/// erratum e3 requires prior negotiation for those fields.
#[derive(Clone)]
pub struct Trailers<'headers, 'src> {
    src: &'src [u8],
    headers: &'headers [HeaderSlot],
}

impl fmt::Debug for Trailers<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trailers")
            .field("header_count", &self.headers.len())
            .finish()
    }
}

impl<'headers, 'src> Trailers<'headers, 'src> {
    /// Return the parsed encapsulated HTTP trailer fields.
    #[must_use]
    pub const fn headers(&self) -> ParsedHeaders<'headers, 'src> {
        ParsedHeaders {
            src: self.src,
            slots: self.headers,
            index: 0,
        }
    }

    /// Return the number of parsed trailer fields.
    #[must_use]
    pub const fn header_count(&self) -> usize {
        self.headers.len()
    }

    /// Find the first trailer field with the given case-insensitive name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<HeaderValue<'src>> {
        self.headers().find_map(|header| {
            header
                .name
                .eq_ignore_ascii_case(name)
                .then_some(header.value)
        })
    }
}

impl PartialEq for Trailers<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        self.headers().eq(other.headers())
    }
}

impl Eq for Trailers<'_, '_> {}

impl<'a> Header<'a> {
    /// Construct and validate a borrowed ICAP header field.
    pub fn new(name: &'a str, value: &'a [u8]) -> Result<Self, InvalidHeader> {
        if !valid_header_value(value) || has_surrounding_whitespace(value) {
            return Err(InvalidHeader);
        }
        let value = HeaderValue::contiguous(value);
        if !is_token(name.as_bytes())
            || validate_known_header(name, value, ServiceTagSyntax::Quoted).is_err()
        {
            return Err(InvalidHeader);
        }
        Ok(Self { name, value })
    }

    /// Return the case-preserving field name.
    #[must_use]
    pub const fn name(self) -> &'a str {
        self.name
    }

    /// Return the borrowed field value.
    ///
    /// Folded compatibility input does not expose its raw CRLF bytes. Iterate
    /// [`HeaderValue::segments`] to consume its zero-copy normalized view.
    #[must_use]
    pub const fn value(self) -> HeaderValue<'a> {
        self.value
    }
}

impl PartialEq for Header<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq_ignore_ascii_case(other.name) && self.value == other.value
    }
}

impl Eq for Header<'_> {}

/// A borrowed ICAP request line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestLine<'a> {
    method: Method<'a>,
    uri: AbsoluteUriRef<'a>,
    version: Version,
}

impl<'a> RequestLine<'a> {
    /// Construct a request line for an absolute ICAP URI with a service path.
    pub fn new(method: Method<'a>, uri: &'a str) -> Result<Self, ParseError> {
        let uri = parse_icap_uri(uri.as_bytes())?;
        Ok(Self {
            method,
            uri,
            version: Version::ICAP_10,
        })
    }

    /// Return the request method.
    #[must_use]
    pub const fn method(self) -> Method<'a> {
        self.method
    }

    /// Return the absolute ICAP URI.
    #[must_use]
    pub const fn uri(self) -> AbsoluteUriRef<'a> {
        self.uri
    }

    /// Return the ICAP version.
    #[must_use]
    pub const fn version(self) -> Version {
        self.version
    }
}

/// A decoded ICAP request head.
#[derive(Clone)]
pub struct RequestHead<'headers, 'src> {
    line: RequestLine<'src>,
    src: &'src [u8],
    headers: &'headers [HeaderSlot],
}

impl fmt::Debug for RequestHead<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestHead")
            .field("line", &self.line)
            .field("header_count", &self.headers.len())
            .finish()
    }
}

impl<'headers, 'src> RequestHead<'headers, 'src> {
    /// Return the parsed request line.
    #[must_use]
    pub const fn line(&self) -> RequestLine<'src> {
        self.line
    }

    /// Return the parsed ICAP header fields.
    #[must_use]
    pub const fn headers(&self) -> ParsedHeaders<'headers, 'src> {
        ParsedHeaders {
            src: self.src,
            slots: self.headers,
            index: 0,
        }
    }

    /// Return the number of parsed ICAP header fields.
    #[must_use]
    pub const fn header_count(&self) -> usize {
        self.headers.len()
    }

    /// Find the first field with the given case-insensitive name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<HeaderValue<'src>> {
        self.headers().find_map(|header| {
            header
                .name
                .eq_ignore_ascii_case(name)
                .then_some(header.value)
        })
    }

    /// Return the typed `Preview` field, when present.
    #[must_use]
    pub fn preview(&self) -> Option<Preview> {
        self.header(header::PREVIEW)
            .and_then(HeaderValue::as_bytes)
            .and_then(|value| Preview::from_bytes(value).ok())
    }

    /// Return the structurally validated `Encapsulated` field, when present.
    #[must_use]
    pub fn encapsulated(&self) -> Option<Encapsulated<'src>> {
        self.header(header::ENCAPSULATED)
            .and_then(HeaderValue::as_bytes)
            .and_then(|value| parse_encapsulated(value).ok())
    }

    /// Validate method-specific message-body composition.
    pub fn validate(&self) -> Result<(), InvalidComposition> {
        validate_request_composition(self.line.method, self.headers())
    }
}

impl PartialEq for RequestHead<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        self.line == other.line && self.headers().eq(other.headers())
    }
}

impl Eq for RequestHead<'_, '_> {}

/// A borrowed ICAP response status line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseLine<'a> {
    version: Version,
    status: StatusCode,
    reason: &'a [u8],
}

impl<'a> ResponseLine<'a> {
    /// Construct and validate an ICAP response line.
    pub fn new(status: StatusCode, reason: &'a [u8]) -> Result<Self, ParseError> {
        validate_reason(reason)?;
        Ok(Self {
            version: Version::ICAP_10,
            status,
            reason,
        })
    }

    /// Return the ICAP version.
    #[must_use]
    pub const fn version(self) -> Version {
        self.version
    }

    /// Return the response status.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        self.status
    }

    /// Return the borrowed reason phrase.
    #[must_use]
    pub const fn reason(self) -> &'a [u8] {
        self.reason
    }
}

/// A decoded ICAP response head.
#[derive(Clone)]
pub struct ResponseHead<'headers, 'src> {
    line: ResponseLine<'src>,
    src: &'src [u8],
    headers: &'headers [HeaderSlot],
}

impl fmt::Debug for ResponseHead<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseHead")
            .field("line", &self.line)
            .field("header_count", &self.headers.len())
            .finish()
    }
}

impl<'headers, 'src> ResponseHead<'headers, 'src> {
    /// Return the parsed response line.
    #[must_use]
    pub const fn line(&self) -> ResponseLine<'src> {
        self.line
    }

    /// Return the parsed ICAP header fields.
    #[must_use]
    pub const fn headers(&self) -> ParsedHeaders<'headers, 'src> {
        ParsedHeaders {
            src: self.src,
            slots: self.headers,
            index: 0,
        }
    }

    /// Return the number of parsed ICAP header fields.
    #[must_use]
    pub const fn header_count(&self) -> usize {
        self.headers.len()
    }

    /// Find the first field with the given case-insensitive name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<HeaderValue<'src>> {
        self.headers().find_map(|header| {
            header
                .name
                .eq_ignore_ascii_case(name)
                .then_some(header.value)
        })
    }

    /// Return the typed `Preview` field on an OPTIONS response.
    #[must_use]
    pub fn preview(&self) -> Option<Preview> {
        self.header(header::PREVIEW)
            .and_then(HeaderValue::as_bytes)
            .and_then(|value| Preview::from_bytes(value).ok())
    }

    /// Return the structurally validated `Encapsulated` field, when present.
    #[must_use]
    pub fn encapsulated(&self) -> Option<Encapsulated<'src>> {
        self.header(header::ENCAPSULATED)
            .and_then(HeaderValue::as_bytes)
            .and_then(|value| parse_encapsulated(value).ok())
    }

    /// Validate status- and request-method-specific composition.
    pub fn validate(&self, method: MethodKind) -> Result<(), InvalidComposition> {
        validate_response_composition(method, self.line.status, self.headers())
    }
}

impl PartialEq for ResponseHead<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        self.line == other.line && self.headers().eq(other.headers())
    }
}

impl Eq for ResponseHead<'_, '_> {}

/// A malformed ICAP message head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The start line does not have the required shape.
    InvalidStartLine,
    /// The method is not a valid token.
    InvalidMethod,
    /// The request target is not an absolute ICAP URI.
    InvalidUri,
    /// The protocol version is malformed or unsupported.
    InvalidVersion,
    /// The response status is not a three-digit number.
    InvalidStatus,
    /// The response reason phrase contains prohibited bytes.
    InvalidReason,
    /// A header field is malformed.
    InvalidHeader,
    /// The encapsulated sections do not fit the method and status.
    InvalidComposition,
    /// Obsolete header line folding is disabled by the parser policy.
    ObsoleteLineFolding,
    /// The supplied header capacity was exceeded.
    TooManyHeaders,
    /// The configured encoded head size was exceeded.
    HeadTooLarge,
    /// A line did not end with CRLF.
    InvalidLineEnding,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidStartLine => "invalid ICAP start line",
            Self::InvalidMethod => "invalid ICAP method",
            Self::InvalidUri => "invalid ICAP URI",
            Self::InvalidVersion => "invalid ICAP version",
            Self::InvalidStatus => "invalid ICAP status",
            Self::InvalidReason => "invalid ICAP reason phrase",
            Self::InvalidHeader => "invalid ICAP header field",
            Self::InvalidComposition => "invalid ICAP message composition",
            Self::ObsoleteLineFolding => "obsolete ICAP header line folding is disabled",
            Self::TooManyHeaders => "too many ICAP header fields",
            Self::HeadTooLarge => "ICAP message head is too large",
            Self::InvalidLineEnding => "invalid ICAP line ending",
        })
    }
}

impl core::error::Error for ParseError {}

impl From<InvalidMethod> for ParseError {
    fn from(_: InvalidMethod) -> Self {
        Self::InvalidMethod
    }
}

impl From<InvalidVersion> for ParseError {
    fn from(_: InvalidVersion) -> Self {
        Self::InvalidVersion
    }
}

impl From<InvalidStatusCode> for ParseError {
    fn from(_: InvalidStatusCode) -> Self {
        Self::InvalidStatus
    }
}

/// An invalid ICAP header field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidHeader;

impl fmt::Display for InvalidHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ICAP header field")
    }
}

impl core::error::Error for InvalidHeader {}

/// Encapsulated sections do not fit an ICAP method, direction, or status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidComposition;

impl fmt::Display for InvalidComposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ICAP message composition")
    }
}

impl core::error::Error for InvalidComposition {}

/// An ICAP value could not be encoded.
///
/// On error, bytes already written to the destination are unspecified. A
/// caller reusing a scratch buffer must discard its contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// The fixed output buffer was too small.
    BufferTooSmall,
    /// The supplied protocol values form an invalid message.
    InvalidInput,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BufferTooSmall => "ICAP output buffer is too small",
            Self::InvalidInput => "invalid ICAP encoder input",
        })
    }
}

impl core::error::Error for EncodeError {}

/// Parse an encapsulated HTTP trailer block into caller-owned storage.
///
/// ```
/// use rama_icap::codec::{HeaderSlot, ParseStatus, parse_trailers};
///
/// let wire = b"Content-MD5: abc\r\n\r\nnext";
/// let mut slots = [HeaderSlot::EMPTY; 4];
/// let ParseStatus::Complete(trailers, consumed) =
///     parse_trailers(wire, &mut slots)?
/// else {
///     panic!("complete trailer block expected");
/// };
/// assert_eq!(trailers.header_count(), 1);
/// assert_eq!(&wire[consumed..], b"next");
/// # Ok::<(), rama_icap::codec::ParseError>(())
/// ```
pub fn parse_trailers<'headers, 'src>(
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
) -> Result<ParseStatus<Trailers<'headers, 'src>>, ParseError> {
    parse_trailers_with_config(src, headers, HeadParserConfig::new())
}

/// Parse an encapsulated HTTP trailer block with explicit bounds and folding.
pub fn parse_trailers_with_config<'headers, 'src>(
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
    config: HeadParserConfig,
) -> Result<ParseStatus<Trailers<'headers, 'src>>, ParseError> {
    let bounded_len = src.len().min(config.max_bytes);
    let bounded = &src[..bounded_len];
    let parsed = parse_headers(bounded, 0, headers, config, HeaderBlockKind::Trailer)?;
    let Some((headers, consumed)) = parsed else {
        return if src.len() > config.max_bytes {
            Err(ParseError::HeadTooLarge)
        } else {
            Ok(ParseStatus::Partial)
        };
    };
    Ok(ParseStatus::Complete(
        Trailers {
            src: &bounded[..consumed],
            headers,
        },
        consumed,
    ))
}

/// Parse an ICAP request head into caller-owned header storage.
///
/// ```
/// use rama_icap::codec::{HeaderSlot, ParseStatus, parse_request_head};
/// use rama_icap::proto::Method;
///
/// let wire = b"OPTIONS icap://icap.test/service ICAP/1.0\r\n\r\n";
/// let mut slots = [HeaderSlot::EMPTY; 8];
/// let ParseStatus::Complete(head, consumed) =
///     parse_request_head(wire, &mut slots)?
/// else {
///     panic!("complete ICAP head expected");
/// };
/// assert_eq!(head.line().method(), Method::Options);
/// assert_eq!(consumed, wire.len());
/// # Ok::<(), rama_icap::codec::ParseError>(())
/// ```
pub fn parse_request_head<'headers, 'src>(
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
) -> Result<ParseStatus<RequestHead<'headers, 'src>>, ParseError> {
    parse_request_head_with_config(src, headers, HeadParserConfig::new())
}

/// Parse an ICAP request head with explicit bounds and compatibility policy.
pub fn parse_request_head_with_config<'headers, 'src>(
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
    config: HeadParserConfig,
) -> Result<ParseStatus<RequestHead<'headers, 'src>>, ParseError> {
    let bounded_len = src.len().min(config.max_bytes);
    match parse_request_head_inner(&src[..bounded_len], headers, config)? {
        ParseStatus::Partial if src.len() > config.max_bytes => Err(ParseError::HeadTooLarge),
        status => Ok(status),
    }
}

fn parse_request_head_inner<'headers, 'src>(
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
    config: HeadParserConfig,
) -> Result<ParseStatus<RequestHead<'headers, 'src>>, ParseError> {
    let Some((line, line_len)) = take_line(src)? else {
        return Ok(ParseStatus::Partial);
    };
    let line = parse_request_line(line)?;
    let Some((headers, consumed)) =
        parse_headers(src, line_len, headers, config, HeaderBlockKind::Icap)?
    else {
        return Ok(ParseStatus::Partial);
    };
    let head = RequestHead {
        line,
        src: &src[..consumed],
        headers,
    };
    if config.composition_validation == CompositionValidation::Enabled {
        head.validate()
            .map_err(|_error| ParseError::InvalidComposition)?;
    }

    Ok(ParseStatus::Complete(head, consumed))
}

/// Parse an ICAP response head into caller-owned header storage.
pub fn parse_response_head<'headers, 'src>(
    method: MethodKind,
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
) -> Result<ParseStatus<ResponseHead<'headers, 'src>>, ParseError> {
    parse_response_head_with_config(method, src, headers, HeadParserConfig::new())
}

/// Parse an ICAP response head with explicit bounds and compatibility policy.
pub fn parse_response_head_with_config<'headers, 'src>(
    method: MethodKind,
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
    config: HeadParserConfig,
) -> Result<ParseStatus<ResponseHead<'headers, 'src>>, ParseError> {
    let bounded_len = src.len().min(config.max_bytes);
    match parse_response_head_inner(method, &src[..bounded_len], headers, config)? {
        ParseStatus::Partial if src.len() > config.max_bytes => Err(ParseError::HeadTooLarge),
        status => Ok(status),
    }
}

fn parse_response_head_inner<'headers, 'src>(
    method: MethodKind,
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
    config: HeadParserConfig,
) -> Result<ParseStatus<ResponseHead<'headers, 'src>>, ParseError> {
    let Some((line, line_len)) = take_line(src)? else {
        return Ok(ParseStatus::Partial);
    };
    let line = parse_response_line(line)?;
    let Some((headers, consumed)) =
        parse_headers(src, line_len, headers, config, HeaderBlockKind::Icap)?
    else {
        return Ok(ParseStatus::Partial);
    };

    let head = ResponseHead {
        line,
        src: &src[..consumed],
        headers,
    };
    if config.composition_validation == CompositionValidation::Enabled {
        head.validate(method)
            .map_err(|_error| ParseError::InvalidComposition)?;
    }
    Ok(ParseStatus::Complete(head, consumed))
}

/// Encode an ICAP request line and header block into `dst`.
pub fn encode_request_head(
    line: RequestLine<'_>,
    headers: &[Header<'_>],
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    validate_request_composition(line.method, headers.iter().copied())
        .map_err(|_error| EncodeError::InvalidInput)?;
    encode_request_head_fields(line, headers.iter().copied(), HeaderEncoding::Strict, dst)
}

#[cfg(feature = "std")]
pub(crate) fn encode_request_head_iter<'a, I>(
    line: RequestLine<'_>,
    headers: I,
    dst: &mut [u8],
) -> Result<usize, EncodeError>
where
    I: Clone + Iterator<Item = Header<'a>>,
{
    validate_request_composition(line.method, headers.clone())
        .map_err(|_error| EncodeError::InvalidInput)?;
    encode_request_head_fields(line, headers, HeaderEncoding::Strict, dst)
}

/// Encode a previously parsed ICAP request head into `dst`.
pub fn encode_parsed_request_head(
    head: &RequestHead<'_, '_>,
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    validate_request_composition(head.line.method, head.headers())
        .map_err(|_error| EncodeError::InvalidInput)?;
    encode_request_head_fields(
        head.line,
        head.headers(),
        HeaderEncoding::CanonicalizeUnquotedServiceTag,
        dst,
    )
}

fn encode_request_head_fields<'a>(
    line: RequestLine<'_>,
    headers: impl IntoIterator<Item = Header<'a>>,
    header_encoding: HeaderEncoding,
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut dst = Output::new(dst);
    dst.put(line.method.as_str().as_bytes())?;
    dst.put(b" ")?;
    dst.put(line.uri.as_bytes())?;
    dst.put(b" ")?;
    dst.put(line.version.as_str().as_bytes())?;
    dst.put(b"\r\n")?;
    encode_headers(headers, header_encoding, &mut dst)?;
    Ok(dst.len())
}

/// Encode an ICAP response line and header block into `dst`.
pub fn encode_response_head(
    method: MethodKind,
    line: ResponseLine<'_>,
    headers: &[Header<'_>],
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    validate_response_composition(method, line.status, headers.iter().copied())
        .map_err(|_error| EncodeError::InvalidInput)?;
    encode_response_head_fields(line, headers.iter().copied(), HeaderEncoding::Strict, dst)
}

#[cfg(feature = "std")]
pub(crate) fn encode_response_head_iter<'a, I>(
    method: MethodKind,
    line: ResponseLine<'_>,
    headers: I,
    dst: &mut [u8],
) -> Result<usize, EncodeError>
where
    I: Clone + Iterator<Item = Header<'a>>,
{
    validate_response_composition(method, line.status, headers.clone())
        .map_err(|_error| EncodeError::InvalidInput)?;
    encode_response_head_fields(line, headers, HeaderEncoding::Strict, dst)
}

/// Encode a previously parsed ICAP response head into `dst`.
pub fn encode_parsed_response_head(
    method: MethodKind,
    head: &ResponseHead<'_, '_>,
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    head.validate(method)
        .map_err(|_error| EncodeError::InvalidInput)?;
    encode_response_head_fields(
        head.line,
        head.headers(),
        HeaderEncoding::CanonicalizeUnquotedServiceTag,
        dst,
    )
}

fn encode_response_head_fields<'a>(
    line: ResponseLine<'_>,
    headers: impl IntoIterator<Item = Header<'a>>,
    header_encoding: HeaderEncoding,
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut dst = Output::new(dst);
    dst.put(line.version.as_str().as_bytes())?;
    dst.put(b" ")?;
    put_status(line.status, &mut dst)?;
    dst.put(b" ")?;
    dst.put(line.reason)?;
    dst.put(b"\r\n")?;
    encode_headers(headers, header_encoding, &mut dst)?;
    Ok(dst.len())
}

fn parse_request_line(line: &[u8]) -> Result<RequestLine<'_>, ParseError> {
    let mut parts = line.split(|byte| *byte == b' ');
    let method = parts.next().ok_or(ParseError::InvalidStartLine)?;
    let uri = parts.next().ok_or(ParseError::InvalidStartLine)?;
    let version = parts.next().ok_or(ParseError::InvalidStartLine)?;
    if parts.next().is_some() || uri.is_empty() {
        return Err(ParseError::InvalidStartLine);
    }

    let method = Method::from_bytes(method)?;
    let uri = parse_icap_uri(uri)?;
    let version = Version::from_bytes(version)?;
    Ok(RequestLine {
        method,
        uri,
        version,
    })
}

fn parse_response_line(line: &[u8]) -> Result<ResponseLine<'_>, ParseError> {
    let Some(version_end) = line.iter().position(|byte| *byte == b' ') else {
        return Err(ParseError::InvalidStartLine);
    };
    let version = Version::from_bytes(&line[..version_end])?;
    let rest = &line[version_end + 1..];
    if rest.len() < 4 || rest[3] != b' ' {
        return Err(ParseError::InvalidStartLine);
    }
    let status = StatusCode::from_bytes(&rest[..3])?;
    let reason = &rest[4..];
    validate_reason(reason)?;
    Ok(ResponseLine {
        version,
        status,
        reason,
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HeaderBlockKind {
    Icap,
    Trailer,
}

fn parse_headers<'headers>(
    src: &[u8],
    mut offset: usize,
    storage: &'headers mut [HeaderSlot],
    config: HeadParserConfig,
    block_kind: HeaderBlockKind,
) -> Result<Option<(&'headers [HeaderSlot], usize)>, ParseError> {
    let mut count = 0;
    let mut value_start = 0;

    loop {
        let Some((line, line_len)) = take_line(&src[offset..])? else {
            return Ok(None);
        };
        if line.is_empty() {
            let headers = &storage[..count];
            if block_kind == HeaderBlockKind::Icap {
                validate_parsed_headers(src, headers, config.service_tag_syntax)?;
            }
            return Ok(Some((headers, offset + line_len)));
        }

        if is_horizontal_whitespace_byte(line[0]) {
            if config.header_folding == HeaderFolding::Reject {
                return Err(ParseError::ObsoleteLineFolding);
            }
            if count == 0 || !valid_header_value(line) {
                return Err(ParseError::InvalidHeader);
            }
            let value_end = offset + trim_folded_line_end(line);
            let Some(range) = storage[count - 1].0.as_mut() else {
                return Err(ParseError::InvalidHeader);
            };
            let name_range = range.name().ok_or(ParseError::InvalidHeader)?;
            let name = core::str::from_utf8(&src[name_range])
                .map_err(|_utf8_error| ParseError::InvalidHeader)?;
            if block_kind == HeaderBlockKind::Icap && is_framing_header(name) {
                return Err(ParseError::InvalidHeader);
            }
            // Preserve the first line's start so folded values remain a
            // zero-copy span and are exposed only through normalized segments.
            range.value_start =
                u32::try_from(value_start).map_err(|_error| ParseError::HeadTooLarge)?;
            range.value_end =
                u32::try_from(value_end).map_err(|_error| ParseError::HeadTooLarge)?;
            range.folded = true;
            offset += line_len;
            continue;
        }

        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(ParseError::InvalidHeader)?;
        let name = &line[..colon];
        if count == storage.len() || !is_token(name) {
            return Err(if count == storage.len() {
                ParseError::TooManyHeaders
            } else {
                ParseError::InvalidHeader
            });
        }
        core::str::from_utf8(name).map_err(|_utf8_error| ParseError::InvalidHeader)?;
        let value = &line[colon + 1..];
        if !valid_header_value(value) {
            return Err(ParseError::InvalidHeader);
        }
        let leading = value
            .iter()
            .take_while(|byte| is_horizontal_whitespace_byte(**byte))
            .count();
        let value = &value[leading..];
        let value = trim_header_end(value);
        value_start = offset + colon + 1 + leading;
        let value_end = value_start + value.len();
        storage[count].0 = Some(HeaderRange::new(
            offset,
            offset + colon,
            value_start,
            value_end,
        )?);
        count += 1;
        offset += line_len;
    }
}

fn header_from_range(src: &[u8], range: HeaderRange) -> Option<Header<'_>> {
    let name = core::str::from_utf8(src.get(range.name()?)?).ok()?;
    let raw = src.get(range.value()?)?;
    let value = if range.folded {
        HeaderValue::folded(raw)
    } else {
        HeaderValue::contiguous(raw)
    };
    Some(Header { name, value })
}

fn take_line(src: &[u8]) -> Result<Option<(&[u8], usize)>, ParseError> {
    for (index, byte) in src.iter().copied().enumerate() {
        match byte {
            b'\n' => {
                if index == 0 || src[index - 1] != b'\r' {
                    return Err(ParseError::InvalidLineEnding);
                }
                return Ok(Some((&src[..index - 1], index + 1)));
            }
            b'\r' if src.get(index + 1).is_some_and(|byte| *byte != b'\n') => {
                return Err(ParseError::InvalidLineEnding);
            }
            _ => {}
        }
    }
    Ok(None)
}

fn parse_icap_uri(uri: &[u8]) -> Result<AbsoluteUriRef<'_>, ParseError> {
    let uri = AbsoluteUriRef::parse_strict(uri).map_err(|_uri_error| ParseError::InvalidUri)?;
    // RFC 3507 excludes userinfo and disallows an empty explicit port.
    // Its service examples do use query arguments, so those remain valid.
    if !uri.scheme().eq_ignore_ascii_case(Protocol::ICAP_SCHEME)
        || uri.host().is_none_or(str::is_empty)
        || !uri.path_str().starts_with('/')
        || uri.userinfo().is_some()
        || uri.port().is_empty()
        || uri.fragment().is_some()
    {
        return Err(ParseError::InvalidUri);
    }
    Ok(uri)
}

fn validate_reason(reason: &[u8]) -> Result<(), ParseError> {
    if reason.iter().copied().all(is_field_value_byte) {
        Ok(())
    } else {
        Err(ParseError::InvalidReason)
    }
}

fn valid_header_value(value: &[u8]) -> bool {
    value.iter().copied().all(is_field_value_byte)
}

fn has_surrounding_whitespace(value: &[u8]) -> bool {
    value
        .first()
        .is_some_and(|byte| is_horizontal_whitespace_byte(*byte))
        || value
            .last()
            .is_some_and(|byte| is_horizontal_whitespace_byte(*byte))
}

fn is_framing_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(header::ENCAPSULATED) || name.eq_ignore_ascii_case(header::PREVIEW)
}

fn validate_known_header(
    name: &str,
    value: HeaderValue<'_>,
    service_tag_syntax: ServiceTagSyntax,
) -> Result<(), InvalidHeader> {
    if name.eq_ignore_ascii_case(header::PREVIEW) {
        Preview::from_bytes(value.as_bytes().ok_or(InvalidHeader)?)
            .map(drop)
            .map_err(|_error| InvalidHeader)
    } else if name.eq_ignore_ascii_case(header::ENCAPSULATED) {
        parse_encapsulated(value.as_bytes().ok_or(InvalidHeader)?)
            .map(drop)
            .map_err(|_error| InvalidHeader)
    } else if name.eq_ignore_ascii_case(header::ISTAG) {
        if valid_istag(value.as_bytes().ok_or(InvalidHeader)?, service_tag_syntax) {
            Ok(())
        } else {
            Err(InvalidHeader)
        }
    } else if name.eq_ignore_ascii_case(header::METHODS) {
        if valid_methods(value) {
            Ok(())
        } else {
            Err(InvalidHeader)
        }
    } else {
        Ok(())
    }
}

fn valid_istag(value: &[u8], syntax: ServiceTagSyntax) -> bool {
    let Some(value) = value
        .strip_prefix(b"\"")
        .and_then(|value| value.strip_suffix(b"\""))
    else {
        return syntax == ServiceTagSyntax::AllowUnquotedToken
            && value.len() <= 32
            && is_token(value);
    };
    if value.len() > 32 {
        return false;
    }
    let mut escaped = false;
    for byte in value.iter().copied() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'"' => return false,
            _ if is_field_value_byte(byte) => {}
            _ => return false,
        }
    }
    !escaped
}

fn valid_methods(value: HeaderValue<'_>) -> bool {
    #[derive(Clone, Copy)]
    enum State {
        Before,
        In,
        After,
    }

    fn valid_completed_method(len: usize, is_options: bool) -> bool {
        len != 0 && !(len == b"OPTIONS".len() && is_options)
    }

    let mut state = State::Before;
    let mut method_len = 0;
    let mut is_options = true;

    for byte in NormalizedHeaderValueBytes::new(value) {
        match state {
            State::Before | State::After if is_horizontal_whitespace_byte(byte) => {}
            State::Before if is_token_byte(byte) => {
                method_len = 1;
                is_options = b"OPTIONS".first() == Some(&byte);
                state = State::In;
            }
            State::In if is_token_byte(byte) => {
                is_options &= b"OPTIONS".get(method_len) == Some(&byte);
                method_len += 1;
            }
            State::In if is_horizontal_whitespace_byte(byte) => {
                if !valid_completed_method(method_len, is_options) {
                    return false;
                }
                state = State::After;
            }
            State::In if byte == b',' => {
                if !valid_completed_method(method_len, is_options) {
                    return false;
                }
                method_len = 0;
                is_options = true;
                state = State::Before;
            }
            State::After if byte == b',' => {
                method_len = 0;
                is_options = true;
                state = State::Before;
            }
            _ => return false,
        }
    }

    match state {
        State::Before => false,
        State::In => valid_completed_method(method_len, is_options),
        State::After => true,
    }
}

fn validate_parsed_headers(
    src: &[u8],
    headers: &[HeaderSlot],
    service_tag_syntax: ServiceTagSyntax,
) -> Result<(), ParseError> {
    let mut validation = HeaderValidation::new(service_tag_syntax);
    for slot in headers {
        let range = slot.0.ok_or(ParseError::InvalidHeader)?;
        let header = header_from_range(src, range).ok_or(ParseError::InvalidHeader)?;
        validation
            .validate(header)
            .map_err(|_error| ParseError::InvalidHeader)?;
    }
    Ok(())
}

fn validate_request_composition<'a>(
    method: Method<'_>,
    headers: impl IntoIterator<Item = Header<'a>>,
) -> Result<(), InvalidComposition> {
    let mut encapsulated = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case(header::PREVIEW)
            && !matches!(method.kind(), MethodKind::Reqmod | MethodKind::Respmod)
        {
            return Err(InvalidComposition);
        }
        if header.name.eq_ignore_ascii_case(header::ENCAPSULATED) {
            let value = header.value.as_bytes().ok_or(InvalidComposition)?;
            encapsulated = Some(parse_encapsulated(value).map_err(|_error| InvalidComposition)?);
        }
    }
    let Some(encapsulated) = encapsulated else {
        return if matches!(method.kind(), MethodKind::Options | MethodKind::Extension) {
            Ok(())
        } else {
            Err(InvalidComposition)
        };
    };
    let context = match method.kind() {
        MethodKind::Reqmod => EncapsulatedContext::ReqmodRequest,
        MethodKind::Respmod => EncapsulatedContext::RespmodRequest,
        MethodKind::Options => EncapsulatedContext::OptionsRequest,
        MethodKind::Extension => {
            if has_message_body(encapsulated) {
                return Err(InvalidComposition);
            }
            return Ok(());
        }
    };
    encapsulated
        .validate(context)
        .map_err(|_error| InvalidComposition)
}

fn validate_response_composition<'a>(
    method: MethodKind,
    status: StatusCode,
    headers: impl IntoIterator<Item = Header<'a>>,
) -> Result<(), InvalidComposition> {
    if status == StatusCode::PARTIAL_CONTENT
        && !matches!(method, MethodKind::Reqmod | MethodKind::Respmod)
    {
        return Err(InvalidComposition);
    }
    let mut encapsulated = None;
    let mut saw_istag = false;
    let mut saw_methods = false;
    let mut saw_preview = false;
    let mut saw_transfer = false;
    let mut transfer_wildcards = 0_usize;
    for header in headers {
        if header.name.eq_ignore_ascii_case(header::ISTAG) {
            saw_istag = true;
        } else if header.name.eq_ignore_ascii_case(header::METHODS) {
            saw_methods = true;
        } else if header.name.eq_ignore_ascii_case(header::PREVIEW) {
            saw_preview = true;
        } else if is_transfer_header(header.name) {
            saw_transfer = true;
            transfer_wildcards = transfer_wildcards
                .checked_add(transfer_wildcard_count(header.value))
                .ok_or(InvalidComposition)?;
        } else if header.name.eq_ignore_ascii_case(header::ENCAPSULATED) {
            let value = header.value.as_bytes().ok_or(InvalidComposition)?;
            encapsulated = Some(parse_encapsulated(value).map_err(|_error| InvalidComposition)?);
        }
    }
    if matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT) && !saw_istag {
        return Err(InvalidComposition);
    }
    let successful_options = method == MethodKind::Options && status == StatusCode::OK;
    if saw_preview && !successful_options {
        return Err(InvalidComposition);
    }
    if saw_transfer && (!successful_options || transfer_wildcards != 1) {
        return Err(InvalidComposition);
    }
    if successful_options && (!saw_methods || encapsulated.is_none()) {
        return Err(InvalidComposition);
    }
    let Some(encapsulated) = encapsulated else {
        return Ok(());
    };
    if !has_message_body(encapsulated) {
        return Ok(());
    }
    // RFC 3507 erratum e1 permits bodies only when recipient support is
    // known. The strict codec recognizes that support for 200 and 206 only.
    if !matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT) {
        return Err(InvalidComposition);
    }
    let context = match method {
        MethodKind::Reqmod => EncapsulatedContext::ReqmodResponse,
        MethodKind::Respmod => EncapsulatedContext::RespmodResponse,
        MethodKind::Options => EncapsulatedContext::OptionsResponse,
        MethodKind::Extension => return Err(InvalidComposition),
    };
    encapsulated
        .validate(context)
        .map_err(|_error| InvalidComposition)
}

fn is_transfer_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(header::TRANSFER_PREVIEW)
        || name.eq_ignore_ascii_case(header::TRANSFER_IGNORE)
        || name.eq_ignore_ascii_case(header::TRANSFER_COMPLETE)
}

fn transfer_wildcard_count(value: HeaderValue<'_>) -> usize {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Item {
        LeadingWhitespace,
        Wildcard,
        Other,
    }

    let mut count = 0;
    let mut item = Item::LeadingWhitespace;
    for byte in NormalizedHeaderValueBytes::new(value) {
        match byte {
            b',' => {
                count += usize::from(item == Item::Wildcard);
                item = Item::LeadingWhitespace;
            }
            b'*' if item == Item::LeadingWhitespace => item = Item::Wildcard,
            byte if is_horizontal_whitespace_byte(byte)
                && matches!(item, Item::LeadingWhitespace | Item::Wildcard) => {}
            _ => item = Item::Other,
        }
    }
    count + usize::from(item == Item::Wildcard)
}

fn has_message_body(encapsulated: Encapsulated<'_>) -> bool {
    let mut sections = encapsulated.iter();
    !matches!(
        (sections.next(), sections.next()),
        (Some(section), None)
            if section.kind() == crate::proto::EncapsulatedKind::NullBody
                && section.offset() == 0
    )
}

struct HeaderValidation {
    service_tag_syntax: ServiceTagSyntax,
    saw_preview: bool,
    saw_encapsulated: bool,
    saw_istag: bool,
}

impl HeaderValidation {
    const fn new(service_tag_syntax: ServiceTagSyntax) -> Self {
        Self {
            service_tag_syntax,
            saw_preview: false,
            saw_encapsulated: false,
            saw_istag: false,
        }
    }

    fn validate(&mut self, header: Header<'_>) -> Result<(), InvalidHeader> {
        if !is_token(header.name.as_bytes()) {
            return Err(InvalidHeader);
        }
        validate_known_header(header.name, header.value, self.service_tag_syntax)?;
        let seen = if header.name.eq_ignore_ascii_case(header::PREVIEW) {
            &mut self.saw_preview
        } else if header.name.eq_ignore_ascii_case(header::ENCAPSULATED) {
            &mut self.saw_encapsulated
        } else if header.name.eq_ignore_ascii_case(header::ISTAG) {
            &mut self.saw_istag
        } else {
            return Ok(());
        };
        if core::mem::replace(seen, true) {
            Err(InvalidHeader)
        } else {
            Ok(())
        }
    }
}

impl Default for HeaderValidation {
    fn default() -> Self {
        Self::new(ServiceTagSyntax::Quoted)
    }
}

fn trim_header_end(mut value: &[u8]) -> &[u8] {
    while value
        .last()
        .is_some_and(|byte| is_horizontal_whitespace_byte(*byte))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn trim_header_start(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| is_horizontal_whitespace_byte(*byte))
    {
        value = &value[1..];
    }
    value
}

fn trim_header_whitespace(value: &[u8]) -> &[u8] {
    trim_header_end(trim_header_start(value))
}

fn trim_folded_line_end(line: &[u8]) -> usize {
    let end = trim_header_end(line).len();
    end.max(1)
}

#[derive(Clone, Copy)]
enum HeaderEncoding {
    Strict,
    CanonicalizeUnquotedServiceTag,
}

fn encode_headers<'a>(
    headers: impl IntoIterator<Item = Header<'a>>,
    encoding: HeaderEncoding,
    dst: &mut Output<'_>,
) -> Result<(), EncodeError> {
    let syntax = match encoding {
        HeaderEncoding::Strict => ServiceTagSyntax::Quoted,
        HeaderEncoding::CanonicalizeUnquotedServiceTag => ServiceTagSyntax::AllowUnquotedToken,
    };
    let mut validation = HeaderValidation::new(syntax);
    for header in headers {
        validation
            .validate(header)
            .map_err(|_error| EncodeError::InvalidInput)?;
        dst.put(header.name.as_bytes())?;
        dst.put(b": ")?;
        let canonicalize_istag = matches!(encoding, HeaderEncoding::CanonicalizeUnquotedServiceTag)
            && header.name.eq_ignore_ascii_case(header::ISTAG)
            && header.value.as_bytes().is_some_and(|value| {
                valid_istag(value, syntax) && !valid_istag(value, ServiceTagSyntax::Quoted)
            });
        if canonicalize_istag {
            dst.put(b"\"")?;
        }
        put_header_value(header.value, dst)?;
        if canonicalize_istag {
            dst.put(b"\"")?;
        }
        dst.put(b"\r\n")?;
    }
    dst.put(b"\r\n")
}

fn put_header_value(value: HeaderValue<'_>, dst: &mut Output<'_>) -> Result<(), EncodeError> {
    let mut wrote_segment = false;
    for segment in value.segments() {
        if wrote_segment {
            dst.put(b" ")?;
        }
        dst.put(segment)?;
        wrote_segment = true;
    }
    Ok(())
}

fn put_status(status: StatusCode, dst: &mut Output<'_>) -> Result<(), EncodeError> {
    let status = status.as_u16();
    let bytes = [
        b'0' + u8::try_from(status / 100).map_err(|_conversion_error| EncodeError::InvalidInput)?,
        b'0' + u8::try_from((status / 10) % 10)
            .map_err(|_conversion_error| EncodeError::InvalidInput)?,
        b'0' + u8::try_from(status % 10).map_err(|_conversion_error| EncodeError::InvalidInput)?,
    ];
    dst.put(&bytes)
}

pub(super) struct Output<'a> {
    dst: &'a mut [u8],
    offset: usize,
}

impl<'a> Output<'a> {
    pub(super) const fn new(dst: &'a mut [u8]) -> Self {
        Self { dst, offset: 0 }
    }

    pub(super) fn put(&mut self, value: &[u8]) -> Result<(), EncodeError> {
        let end = self
            .offset
            .checked_add(value.len())
            .ok_or(EncodeError::BufferTooSmall)?;
        let target = self
            .dst
            .get_mut(self.offset..end)
            .ok_or(EncodeError::BufferTooSmall)?;
        target.copy_from_slice(value);
        self.offset = end;
        Ok(())
    }

    pub(super) const fn len(&self) -> usize {
        self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_result(src: &[u8]) -> Result<ParseStatus<()>, ParseError> {
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        parse_request_head(src, &mut headers).map(|status| match status {
            ParseStatus::Partial => ParseStatus::Partial,
            ParseStatus::Complete(_, consumed) => ParseStatus::Complete((), consumed),
        })
    }

    fn response_result(src: &[u8]) -> Result<ParseStatus<()>, ParseError> {
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        parse_response_head(MethodKind::Respmod, src, &mut headers).map(|status| match status {
            ParseStatus::Partial => ParseStatus::Partial,
            ParseStatus::Complete(_, consumed) => ParseStatus::Complete((), consumed),
        })
    }

    fn request_config_result(
        src: &[u8],
        config: HeadParserConfig,
    ) -> Result<ParseStatus<()>, ParseError> {
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        parse_request_head_with_config(src, &mut headers, config).map(|status| match status {
            ParseStatus::Partial => ParseStatus::Partial,
            ParseStatus::Complete(_, consumed) => ParseStatus::Complete((), consumed),
        })
    }

    fn response_config_result(
        src: &[u8],
        config: HeadParserConfig,
    ) -> Result<ParseStatus<()>, ParseError> {
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        parse_response_head_with_config(MethodKind::Respmod, src, &mut headers, config).map(
            |status| match status {
                ParseStatus::Partial => ParseStatus::Partial,
                ParseStatus::Complete(_, consumed) => ParseStatus::Complete((), consumed),
            },
        )
    }

    #[test]
    fn parses_request_head_without_copying_fields() {
        let src = b"REQMOD icap://icap.test/scan ICAP/1.0\r\n\
            Host: icap.test\r\n\
            Preview: 128\r\n\
            Encapsulated: req-body=0\r\n\r\nbody";
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(head, consumed) = parse_request_head(src, &mut headers).unwrap()
        else {
            panic!("complete request expected");
        };
        assert_eq!(head.line().method(), Method::Reqmod);
        let uri = head.line().uri();
        assert_eq!(uri.as_str(), "icap://icap.test/scan");
        assert_eq!(uri.scheme(), Protocol::ICAP_SCHEME);
        assert_eq!(uri.host(), Some("icap.test"));
        assert_eq!(uri.path_str(), "/scan");
        assert_eq!(
            head.header("preview").and_then(HeaderValue::as_bytes),
            Some(b"128".as_slice())
        );
        assert_eq!(head.preview().map(Preview::as_u64), Some(128));
        assert_eq!(
            head.encapsulated()
                .and_then(|value| value.offset(crate::proto::EncapsulatedKind::RequestBody)),
            Some(0)
        );
        assert_eq!(&src[consumed..], b"body");
        let value = head.headers().next().unwrap().value().as_bytes().unwrap();
        let offset = value.as_ptr() as usize - src.as_ptr() as usize;
        assert_eq!(&src[offset..offset + value.len()], b"icap.test");
    }

    #[test]
    fn incrementally_parses_head() {
        let src = b"OPTIONS icap://icap.test/ ICAP/1.0\r\n";
        assert_eq!(request_result(src), Ok(ParseStatus::Partial));
    }

    #[test]
    fn enforces_encoded_head_bounds_incrementally() {
        assert_eq!(DEFAULT_MAX_HEAD_BYTES, 65_536);
        let src = b"OPTIONS icap://icap.test/ ICAP/1.0\r\n\r\n";
        let exact = HeadParserConfig::new().with_max_bytes(src.len());
        assert_eq!(
            request_config_result(src, exact),
            Ok(ParseStatus::Complete((), src.len()))
        );

        let with_body = [src.as_slice(), b"body"].concat();
        assert_eq!(
            request_config_result(&with_body, exact),
            Ok(ParseStatus::Complete((), src.len()))
        );

        let one_short = exact.with_max_bytes(src.len() - 1);
        assert_eq!(
            request_config_result(src, one_short),
            Err(ParseError::HeadTooLarge)
        );

        let mut unterminated = b"OPTIONS ".to_vec();
        let limit = unterminated.len();
        let config = HeadParserConfig::new().with_max_bytes(limit);
        assert_eq!(
            request_config_result(&unterminated, config),
            Ok(ParseStatus::Partial)
        );
        unterminated.push(b'x');
        assert_eq!(
            request_config_result(&unterminated, config),
            Err(ParseError::HeadTooLarge)
        );
        assert_eq!(config.max_bytes(), limit);
        assert_eq!(config.header_folding(), HeaderFolding::Reject);
        assert_eq!(
            config.composition_validation(),
            CompositionValidation::Enabled
        );
        assert_eq!(config.service_tag_syntax(), ServiceTagSyntax::Quoted);
    }

    #[test]
    fn line_folding_is_explicit_and_reencodes_safely() {
        let src = b"OPTIONS icap://icap.test/ ICAP/1.0\r\n\
            X-Test: first\r\n second\r\n\tthird  \r\n\r\n";
        assert_eq!(request_result(src), Err(ParseError::ObsoleteLineFolding));

        let config = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(head, consumed) =
            parse_request_head_with_config(src, &mut headers, config).unwrap()
        else {
            panic!("complete request expected");
        };
        assert_eq!(consumed, src.len());
        assert_eq!(config.header_folding(), HeaderFolding::Allow);
        let value = head.header("x-test").unwrap();
        assert!(value.as_bytes().is_none());
        assert_eq!(
            value.segments().collect::<std::vec::Vec<_>>(),
            [
                b"first".as_slice(),
                b"second".as_slice(),
                b"third".as_slice()
            ]
        );

        let mut encoded = [0; 128];
        let len = encode_parsed_request_head(&head, &mut encoded).unwrap();
        assert_eq!(
            &encoded[..len],
            b"OPTIONS icap://icap.test/ ICAP/1.0\r\n\
              X-Test: first second third\r\n\r\n"
        );
        let mut reparsed_headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(reparsed, reparsed_len) =
            parse_request_head(&encoded[..len], &mut reparsed_headers).unwrap()
        else {
            panic!("canonical request expected");
        };
        assert_eq!(reparsed_len, len);
        assert_eq!(
            reparsed.header("x-test").and_then(HeaderValue::as_bytes),
            Some(b"first second third".as_slice())
        );

        for malformed in [
            b"OPTIONS icap://icap.test/ ICAP/1.0\r\n leading\r\n\r\n".as_slice(),
            b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX: good\r\n \0bad\r\n\r\n".as_slice(),
        ] {
            assert_eq!(
                request_config_result(malformed, config),
                Err(ParseError::InvalidHeader)
            );
        }

        let trailing_fold = b"OPTIONS icap://icap.test/ ICAP/1.0\r\n\
            X-Test: value\r\n \r\n\r\n";
        let mut trailing_headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(head, _) =
            parse_request_head_with_config(trailing_fold, &mut trailing_headers, config).unwrap()
        else {
            panic!("complete request expected");
        };
        let len = encode_parsed_request_head(&head, &mut encoded).unwrap();
        assert_eq!(
            &encoded[..len],
            b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX-Test: value\r\n\r\n"
        );
    }

    #[test]
    fn folding_normalization_handles_empty_initial_values() {
        let config = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
        let cases: &[(&[u8], &[u8])] = &[
            (
                b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX:\r\n text\r\n\r\n",
                b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX: text\r\n\r\n",
            ),
            (
                b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX:\r\n \t \r\n\r\n",
                b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX: \r\n\r\n",
            ),
        ];
        for (wire, expected) in cases {
            let mut headers = [HeaderSlot::EMPTY; 4];
            let ParseStatus::Complete(head, _) =
                parse_request_head_with_config(wire, &mut headers, config).unwrap()
            else {
                panic!("complete request expected");
            };
            let mut encoded = [0; 128];
            let len = encode_parsed_request_head(&head, &mut encoded).unwrap();
            assert_eq!(&encoded[..len], *expected);
        }

        let responses: &[(&[u8], &[u8])] = &[
            (
                b"ICAP/1.0 200 OK\r\nISTag: \"rama\"\r\nX:\r\n text\r\n\r\n",
                b"ICAP/1.0 200 OK\r\nISTag: \"rama\"\r\nX: text\r\n\r\n",
            ),
            (
                b"ICAP/1.0 200 OK\r\nISTag: \"rama\"\r\nX:\r\n \t \r\n\r\n",
                b"ICAP/1.0 200 OK\r\nISTag: \"rama\"\r\nX: \r\n\r\n",
            ),
        ];
        for (wire, expected) in responses {
            let mut headers = [HeaderSlot::EMPTY; 4];
            let ParseStatus::Complete(head, _) =
                parse_response_head_with_config(MethodKind::Respmod, wire, &mut headers, config)
                    .unwrap()
            else {
                panic!("complete response expected");
            };
            let mut encoded = [0; 64];
            let len =
                encode_parsed_response_head(MethodKind::Respmod, &head, &mut encoded).unwrap();
            assert_eq!(&encoded[..len], *expected);
        }
    }

    #[test]
    fn validates_framing_headers_and_request_composition() {
        assert_eq!(
            Header::new("X-Test", b"opaque value")
                .unwrap()
                .value()
                .as_bytes(),
            Some(b"opaque value".as_slice())
        );
        for value in [
            b" leading".as_slice(),
            b"trailing\t".as_slice(),
            b"embedded\r\nline".as_slice(),
            b"control\0byte".as_slice(),
        ] {
            assert_eq!(Header::new("X-Test", value), Err(InvalidHeader));
        }
        assert_eq!(Header::new("Preview", b"-1"), Err(InvalidHeader));
        assert_eq!(
            Header::new("Encapsulated", b"req-hdr=0, null-body=0"),
            Err(InvalidHeader)
        );

        for wire in [
            b"REQMOD icap://icap.test/ ICAP/1.0\r\nPreview: 1\r\nPreview: 2\r\n\r\n".as_slice(),
            b"REQMOD icap://icap.test/ ICAP/1.0\r\nEncapsulated: res-hdr=0, res-body=1\r\n\r\n"
                .as_slice(),
        ] {
            request_result(wire).unwrap_err();
        }

        for wire in [
            b"REQMOD icap://icap.test/ ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://icap.test/ ICAP/1.0\r\nEncapsulated: null-body=0\r\n\r\n".as_slice(),
            b"RESPMOD icap://icap.test/ ICAP/1.0\r\nEncapsulated: null-body=0\r\n\r\n".as_slice(),
            b"RESPMOD icap://icap.test/ ICAP/1.0\r\n\
              Encapsulated: req-hdr=0, null-body=10\r\n\r\n"
                .as_slice(),
        ] {
            assert_eq!(request_result(wire), Err(ParseError::InvalidComposition));
        }

        let folded = b"REQMOD icap://icap.test/ ICAP/1.0\r\nPreview: 1\r\n 0\r\n\r\n";
        let config = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
        assert_eq!(
            request_config_result(folded, config),
            Err(ParseError::InvalidHeader)
        );

        let line = RequestLine::new(Method::Reqmod, "icap://icap.test/").unwrap();
        let duplicate = [
            Header::new("Preview", b"1").unwrap(),
            Header::new("preview", b"2").unwrap(),
        ];
        assert_eq!(
            encode_request_head(line, &duplicate, &mut [0; 128]),
            Err(EncodeError::InvalidInput)
        );
        let wrong_composition = [Header::new("Encapsulated", b"res-hdr=0, res-body=1").unwrap()];
        assert_eq!(
            encode_request_head(line, &wrong_composition, &mut [0; 128]),
            Err(EncodeError::InvalidInput)
        );
        assert_eq!(
            encode_request_head(line, &[], &mut [0; 128]),
            Err(EncodeError::InvalidInput)
        );
    }

    #[test]
    fn validates_response_composition_with_method_and_status() {
        let tag = Header::new("ISTag", b"\"rama\"").unwrap();
        let body = [
            tag,
            Header::new("Encapsulated", b"res-hdr=0, res-body=10").unwrap(),
        ];
        for status in [StatusCode::CONTINUE, StatusCode::NO_MODIFICATION_NEEDED] {
            let line = ResponseLine::new(status, b"No Body").unwrap();
            assert_eq!(
                encode_response_head(MethodKind::Respmod, line, &body, &mut [0; 128]),
                Err(EncodeError::InvalidInput)
            );
        }

        let wire = b"ICAP/1.0 204 No Content\r\n\
            ISTag: \"rama\"\r\n\
            Encapsulated: res-hdr=0, res-body=10\r\n\r\n";
        assert_eq!(response_result(wire), Err(ParseError::InvalidComposition));

        let ok = ResponseLine::new(StatusCode::OK, b"OK").unwrap();
        encode_response_head(MethodKind::Respmod, ok, &body, &mut [0; 128]).unwrap();
        assert_eq!(
            encode_response_head(MethodKind::Options, ok, &body, &mut [0; 128]),
            Err(EncodeError::InvalidInput)
        );
        let options_body = [
            tag,
            Header::new("Methods", b"RESPMOD").unwrap(),
            Header::new("Encapsulated", b"opt-body=0").unwrap(),
        ];
        encode_response_head(MethodKind::Options, ok, &options_body, &mut [0; 128]).unwrap();
        let partial = ResponseLine::new(StatusCode::PARTIAL_CONTENT, b"Partial").unwrap();
        assert_eq!(
            encode_response_head(MethodKind::Options, partial, &options_body, &mut [0; 128]),
            Err(EncodeError::InvalidInput)
        );

        let empty = [tag, Header::new("Encapsulated", b"null-body=0").unwrap()];
        for method in [MethodKind::Reqmod, MethodKind::Respmod] {
            encode_response_head(method, partial, &[tag], &mut [0; 128]).unwrap();
            encode_response_head(method, partial, &empty, &mut [0; 128]).unwrap();
        }
        for method in [MethodKind::Options, MethodKind::Extension] {
            assert_eq!(
                encode_response_head(method, partial, &[tag], &mut [0; 128]),
                Err(EncodeError::InvalidInput)
            );
            assert_eq!(
                encode_response_head(method, partial, &empty, &mut [0; 128]),
                Err(EncodeError::InvalidInput)
            );
            for wire in [
                b"ICAP/1.0 206 Partial Content\r\nISTag: \"rama\"\r\n\r\n".as_slice(),
                b"ICAP/1.0 206 Partial Content\r\n\
                  ISTag: \"rama\"\r\n\
                  Encapsulated: null-body=0\r\n\r\n"
                    .as_slice(),
            ] {
                let mut headers = [HeaderSlot::EMPTY; 4];
                assert_eq!(
                    parse_response_head(method, wire, &mut headers).unwrap_err(),
                    ParseError::InvalidComposition
                );
            }
        }
        let no_content =
            ResponseLine::new(StatusCode::NO_MODIFICATION_NEEDED, b"No Content").unwrap();
        encode_response_head(MethodKind::Respmod, no_content, &empty, &mut [0; 128]).unwrap();

        assert_eq!(
            encode_response_head(MethodKind::Respmod, ok, &[], &mut [0; 128]),
            Err(EncodeError::InvalidInput)
        );
    }

    #[test]
    fn gates_preview_by_method_and_direction() {
        for wire in [
            b"OPTIONS icap://icap.test/ ICAP/1.0\r\nPreview: 1\r\n\r\n".as_slice(),
            b"LOG icap://icap.test/ ICAP/1.0\r\nPreview: 1\r\n\r\n".as_slice(),
        ] {
            assert_eq!(request_result(wire), Err(ParseError::InvalidComposition));
        }

        let mut storage = [HeaderSlot::EMPTY; 8];
        for wire in [
            b"ICAP/1.0 100 Continue\r\nISTag: \"rama\"\r\nPreview: 1\r\n\r\n".as_slice(),
            b"ICAP/1.0 204 No Content\r\nISTag: \"rama\"\r\nPreview: 1\r\n\r\n".as_slice(),
        ] {
            assert_eq!(
                parse_response_head(MethodKind::Respmod, wire, &mut storage),
                Err(ParseError::InvalidComposition)
            );
        }

        let wire = b"ICAP/1.0 200 OK\r\n\
            Methods: RESPMOD\r\n\
            ISTag: \"rama\"\r\n\
            Encapsulated: null-body=0\r\n\
            Preview: 1024\r\n\r\n";
        let ParseStatus::Complete(head, _) =
            parse_response_head(MethodKind::Options, wire, &mut storage).unwrap()
        else {
            panic!("OPTIONS response expected");
        };
        assert_eq!(head.preview().and_then(Preview::as_usize), Some(1024));
    }

    #[test]
    fn validates_istag_and_options_response_fields() {
        Header::new("ISTag", b"\"has spaces & !@#\"").unwrap();
        Header::new("ISTag", b"\"12345678901234567890123456789012\"").unwrap();
        assert!(!valid_istag(b"\"bad\0\"", ServiceTagSyntax::Quoted));
        for value in [
            b"unquoted".as_slice(),
            b"\"unterminated".as_slice(),
            b"\"bad\\\"".as_slice(),
            b"\"bad\"quote\"".as_slice(),
            b"\"123456789012345678901234567890123\"".as_slice(),
        ] {
            assert_eq!(Header::new("ISTag", value), Err(InvalidHeader));
        }

        let mut storage = [HeaderSlot::EMPTY; 8];
        assert_eq!(
            parse_response_head(
                MethodKind::Respmod,
                b"ICAP/1.0 200 OK\r\n\r\n",
                &mut storage,
            ),
            Err(ParseError::InvalidComposition)
        );
        for wire in [
            b"ICAP/1.0 200 OK\r\nMethods: RESPMOD\r\nISTag: \"rama\"\r\n\r\n".as_slice(),
            b"ICAP/1.0 200 OK\r\nISTag: \"rama\"\r\nEncapsulated: null-body=0\r\n\r\n".as_slice(),
        ] {
            assert_eq!(
                parse_response_head(MethodKind::Options, wire, &mut storage),
                Err(ParseError::InvalidComposition)
            );
        }
    }

    #[test]
    fn validates_methods_header_values() {
        for value in [
            b"RESPMOD".as_slice(),
            b"REQMOD, RESPMOD".as_slice(),
            b"REQMOD , RESPMOD".as_slice(),
            b"RESPMOD, LOG".as_slice(),
            b"XPTIONS".as_slice(),
            b"options".as_slice(),
        ] {
            Header::new(header::METHODS, value).unwrap();
        }
        for value in [
            b"".as_slice(),
            b"OPTIONS".as_slice(),
            b"RESPMOD, OPTIONS".as_slice(),
            b"@@@".as_slice(),
            b",REQMOD".as_slice(),
            b"REQMOD,".as_slice(),
            b"REQMOD,,RESPMOD".as_slice(),
            b"REQ MOD".as_slice(),
            b"REQMOD@RESPMOD".as_slice(),
        ] {
            assert_eq!(Header::new(header::METHODS, value), Err(InvalidHeader));
        }

        let valid = b"ICAP/1.0 200 OK\r\n\
            Methods: REQMOD,\r\n RESPMOD\r\n\
            ISTag: \"rama\"\r\n\
            Encapsulated: null-body=0\r\n\r\n";
        let config = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
        let mut storage = [HeaderSlot::EMPTY; 8];
        assert!(matches!(
            parse_response_head_with_config(MethodKind::Options, valid, &mut storage, config),
            Ok(ParseStatus::Complete(_, _))
        ));

        for value in [
            b"OPTIONS".as_slice(),
            b"@@@".as_slice(),
            b"REQ MOD".as_slice(),
        ] {
            let mut wire = b"ICAP/1.0 200 OK\r\nMethods: ".to_vec();
            wire.extend_from_slice(value);
            wire.extend_from_slice(b"\r\nISTag: \"rama\"\r\nEncapsulated: null-body=0\r\n\r\n");
            assert_eq!(
                parse_response_head(MethodKind::Options, &wire, &mut storage),
                Err(ParseError::InvalidHeader)
            );
        }
    }

    #[test]
    fn supports_explicit_c_icap_service_tag_compatibility() {
        let wire = b"ICAP/1.0 200 OK\r\n\
            ISTag: CI0001-NgJDaXzq7eNcJYIO4MFnugAA\r\n\r\n";
        let mut storage = [HeaderSlot::EMPTY; 4];
        assert_eq!(
            parse_response_head(MethodKind::Respmod, wire, &mut storage),
            Err(ParseError::InvalidHeader)
        );

        let config =
            HeadParserConfig::new().with_service_tag_syntax(ServiceTagSyntax::AllowUnquotedToken);
        assert_eq!(
            config.service_tag_syntax(),
            ServiceTagSyntax::AllowUnquotedToken
        );
        let ParseStatus::Complete(head, _) =
            parse_response_head_with_config(MethodKind::Respmod, wire, &mut storage, config)
                .unwrap()
        else {
            panic!("complete response expected");
        };
        let mut encoded = [0; 128];
        let written =
            encode_parsed_response_head(MethodKind::Respmod, &head, &mut encoded).unwrap();
        assert_eq!(
            &encoded[..written],
            b"ICAP/1.0 200 OK\r\n\
                ISTag: \"CI0001-NgJDaXzq7eNcJYIO4MFnugAA\"\r\n\r\n"
        );
        let mut strict_storage = [HeaderSlot::EMPTY; 4];
        assert!(matches!(
            parse_response_head(
                MethodKind::Respmod,
                &encoded[..written],
                &mut strict_storage,
            ),
            Ok(ParseStatus::Complete(_, _))
        ));

        for value in [
            b"".as_slice(),
            b"bad tag".as_slice(),
            b"123456789012345678901234567890123".as_slice(),
        ] {
            assert!(!valid_istag(value, ServiceTagSyntax::AllowUnquotedToken));
        }
    }

    #[test]
    fn permits_syntax_only_parsing_by_explicit_policy() {
        let request = b"REQMOD icap://icap.test/scan ICAP/1.0\r\n\r\n";
        assert_eq!(request_result(request), Err(ParseError::InvalidComposition));
        let config =
            HeadParserConfig::new().with_composition_validation(CompositionValidation::Disabled);
        assert_eq!(
            config.composition_validation(),
            CompositionValidation::Disabled
        );
        let mut request_storage = [HeaderSlot::EMPTY; 4];
        let ParseStatus::Complete(head, _) =
            parse_request_head_with_config(request, &mut request_storage, config).unwrap()
        else {
            panic!("complete request expected");
        };
        assert_eq!(head.validate(), Err(InvalidComposition));

        let response = b"ICAP/1.0 200 OK\r\n\r\n";
        assert_eq!(
            response_result(response),
            Err(ParseError::InvalidComposition)
        );
        let mut response_storage = [HeaderSlot::EMPTY; 4];
        let ParseStatus::Complete(head, _) = parse_response_head_with_config(
            MethodKind::Respmod,
            response,
            &mut response_storage,
            config,
        )
        .unwrap() else {
            panic!("complete response expected");
        };
        assert_eq!(head.validate(MethodKind::Respmod), Err(InvalidComposition));
    }

    #[test]
    fn accepts_bodyless_responses_without_service_tags() {
        for wire in [
            b"ICAP/1.0 100 Continue\r\n\r\n".as_slice(),
            b"ICAP/1.0 204 No Content\r\n\r\n".as_slice(),
            b"ICAP/1.0 400 Bad Request\r\n\r\n".as_slice(),
            b"ICAP/1.0 500 Server Error\r\n\r\n".as_slice(),
        ] {
            let mut storage = [HeaderSlot::EMPTY; 1];
            assert!(matches!(
                parse_response_head(MethodKind::Respmod, wire, &mut storage),
                Ok(ParseStatus::Complete(_, _))
            ));
        }

        for status in [
            StatusCode::CONTINUE,
            StatusCode::NO_MODIFICATION_NEEDED,
            StatusCode::BAD_REQUEST,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let line = ResponseLine::new(status, b"status").unwrap();
            encode_response_head(MethodKind::Respmod, line, &[], &mut [0; 64]).unwrap();
        }
    }

    #[test]
    fn validates_options_transfer_wildcard() {
        let line = ResponseLine::new(StatusCode::OK, b"OK").unwrap();
        let required = [
            Header::new("ISTag", b"\"rama\"").unwrap(),
            Header::new("Methods", b"RESPMOD").unwrap(),
            Header::new("Encapsulated", b"null-body=0").unwrap(),
        ];
        let valid = [
            required[0],
            required[1],
            required[2],
            Header::new("Transfer-Preview", b"*").unwrap(),
            Header::new("Transfer-Ignore", b"html").unwrap(),
        ];
        encode_response_head(MethodKind::Options, line, &valid, &mut [0; 256]).unwrap();

        let missing = [
            required[0],
            required[1],
            required[2],
            Header::new("Transfer-Ignore", b"html").unwrap(),
        ];
        assert_eq!(
            encode_response_head(MethodKind::Options, line, &missing, &mut [0; 256]),
            Err(EncodeError::InvalidInput)
        );
        let embedded = [
            required[0],
            required[1],
            required[2],
            Header::new("Transfer-Preview", b"html*").unwrap(),
        ];
        assert_eq!(
            encode_response_head(MethodKind::Options, line, &embedded, &mut [0; 256]),
            Err(EncodeError::InvalidInput)
        );
        let leading_whitespace = [
            required[0],
            required[1],
            required[2],
            Header::new("Transfer-Preview", b"html, *").unwrap(),
        ];
        encode_response_head(
            MethodKind::Options,
            line,
            &leading_whitespace,
            &mut [0; 256],
        )
        .unwrap();
        let duplicate = [
            required[0],
            required[1],
            required[2],
            Header::new("Transfer-Preview", b"*").unwrap(),
            Header::new("Transfer-Complete", b"*").unwrap(),
        ];
        assert_eq!(
            encode_response_head(MethodKind::Options, line, &duplicate, &mut [0; 256]),
            Err(EncodeError::InvalidInput)
        );
        assert_eq!(
            encode_response_head(MethodKind::Respmod, line, &valid, &mut [0; 256]),
            Err(EncodeError::InvalidInput)
        );

        let invalid_fold = b"ICAP/1.0 200 OK\r\n\
            Methods: RESPMOD\r\n\
            ISTag: \"rama\"\r\n\
            Encapsulated: null-body=0\r\n\
            Transfer-Preview: *\r\n\
            \x20html\r\n\r\n";
        let config = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
        let mut storage = [HeaderSlot::EMPTY; 8];
        assert_eq!(
            parse_response_head_with_config(
                MethodKind::Options,
                invalid_fold,
                &mut storage,
                config,
            ),
            Err(ParseError::InvalidComposition)
        );

        let valid_fold = b"ICAP/1.0 200 OK\r\n\
            Methods: RESPMOD\r\n\
            ISTag: \"rama\"\r\n\
            Encapsulated: null-body=0\r\n\
            Transfer-Preview: *,\r\n\
            \x20html\r\n\r\n";
        let ParseStatus::Complete(head, _) =
            parse_response_head_with_config(MethodKind::Options, valid_fold, &mut storage, config)
                .unwrap()
        else {
            panic!("complete response expected");
        };
        let mut encoded = [0; 256];
        let written =
            encode_parsed_response_head(MethodKind::Options, &head, &mut encoded).unwrap();
        let mut strict_storage = [HeaderSlot::EMPTY; 8];
        assert!(matches!(
            parse_response_head(
                MethodKind::Options,
                &encoded[..written],
                &mut strict_storage,
            ),
            Ok(ParseStatus::Complete(_, _))
        ));
    }

    #[test]
    fn head_scanner_consumes_each_stream_byte_once() {
        let head = b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX: y\r\n\r\nbody";
        let consumed = head.len() - 4;
        let config = HeadParserConfig::new().with_max_bytes(consumed);
        let mut scanner = HeadScanner::new();
        for byte in &head[..consumed - 1] {
            let ScanStatus::Partial(next) =
                scanner.scan(core::slice::from_ref(byte), config).unwrap()
            else {
                panic!("partial head expected");
            };
            scanner = next;
        }
        let ScanStatus::Complete(framed) = scanner.scan(&head[consumed - 1..], config).unwrap()
        else {
            panic!("complete head expected");
        };
        assert_eq!(framed.consumed(), consumed);

        let ScanStatus::Complete(framed) = HeadScanner::new().scan(head, config).unwrap() else {
            panic!("complete head expected");
        };
        assert_eq!(framed.consumed(), consumed);

        let short = HeadParserConfig::new().with_max_bytes(3);
        assert_eq!(
            HeadScanner::new().scan(b"abcd", short),
            Err(ParseError::HeadTooLarge)
        );
        assert!(matches!(
            HeadScanner::new().scan(b"abc", short),
            Ok(ScanStatus::Partial(_))
        ));
        let ScanStatus::Partial(scanner) = HeadScanner::new()
            .scan(b"abc", HeadParserConfig::new().with_max_bytes(3))
            .unwrap()
        else {
            panic!("partial head expected");
        };
        assert!(matches!(
            scanner
                .clone()
                .scan(b"", HeadParserConfig::new().with_max_bytes(3)),
            Ok(ScanStatus::Partial(_))
        ));
        let lowered = HeadParserConfig::new().with_max_bytes(2);
        assert_eq!(
            scanner.clone().scan(b"", lowered),
            Err(ParseError::HeadTooLarge)
        );
        assert_eq!(scanner.scan(b"d", lowered), Err(ParseError::HeadTooLarge));

        assert_eq!(
            HeadScanner::new().scan(b"OPTIONS icap://host/ ICAP/1.0\n", config),
            Err(ParseError::InvalidLineEnding)
        );
        assert_eq!(
            HeadScanner::new().scan(b"OPTIONS icap://host/ ICAP/1.0\rX", config),
            Err(ParseError::InvalidLineEnding)
        );
        assert_eq!(
            HeadScanner::new().scan(b"A\rX", HeadParserConfig::new().with_max_bytes(2)),
            Err(ParseError::HeadTooLarge)
        );
        assert_eq!(
            HeadScanner::new().scan(b"A\rX", HeadParserConfig::new().with_max_bytes(3)),
            Err(ParseError::InvalidLineEnding)
        );
        assert_eq!(
            HeadScanner::new().scan(b"A\r\n\r\n", HeadParserConfig::new().with_max_bytes(2)),
            Err(ParseError::HeadTooLarge)
        );
        let ScanStatus::Complete(framed) = HeadScanner::new()
            .scan(b"A\r\n\r\n", HeadParserConfig::new().with_max_bytes(5))
            .unwrap()
        else {
            panic!("complete head expected");
        };
        assert_eq!(framed.consumed(), 5);
    }

    #[test]
    fn head_scanner_handles_recycled_input_as_new_stream_bytes() {
        let config = HeadParserConfig::new();
        let partial = b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX: y\r\n";
        let ScanStatus::Partial(scanner) = HeadScanner::new().scan(partial, config).unwrap() else {
            panic!("partial head expected");
        };
        let ScanStatus::Complete(framed) = scanner.scan(b"\r\nbody", config).unwrap() else {
            panic!("complete head expected");
        };
        assert_eq!(framed.consumed(), partial.len() + 2);

        let ScanStatus::Partial(scanner) = HeadScanner::new()
            .scan(b"Header: value\r\n", config)
            .unwrap()
        else {
            panic!("partial head expected");
        };
        assert_eq!(
            scanner.scan(b"0\nAAAAAAAAAA", config),
            Err(ParseError::InvalidLineEnding)
        );

        let replacement = b"OPTIONS icap://new.test/ ICAP/1.0\r\n\r\n";
        let ScanStatus::Complete(framed) = HeadScanner::new().scan(replacement, config).unwrap()
        else {
            panic!("complete head expected");
        };
        assert_eq!(framed.consumed(), replacement.len());
    }

    #[test]
    fn parses_and_frames_encapsulated_http_trailers() {
        let wire = b"Content-MD5: abc\r\nPreview: opaque-http-value\r\n\r\nNEXT";
        let mut storage = [HeaderSlot::EMPTY; 4];
        let ParseStatus::Complete(trailers, consumed) = parse_trailers(wire, &mut storage).unwrap()
        else {
            panic!("complete trailers expected");
        };
        assert_eq!(consumed, wire.len() - 4);
        assert_eq!(trailers.header_count(), 2);
        assert_eq!(
            trailers
                .header("content-md5")
                .and_then(HeaderValue::as_bytes),
            Some(b"abc".as_slice())
        );
        assert_eq!(&wire[consumed..], b"NEXT");

        let mut empty_storage = [HeaderSlot::EMPTY; 1];
        let ParseStatus::Complete(empty, consumed) =
            parse_trailers(b"\r\nNEXT", &mut empty_storage).unwrap()
        else {
            panic!("empty trailers expected");
        };
        assert_eq!(consumed, 2);
        assert_eq!(empty.header_count(), 0);

        let ScanStatus::Complete(framed) = TrailerScanner::new()
            .scan(b"\r\nNEXT", HeadParserConfig::new())
            .unwrap()
        else {
            panic!("empty trailer frame expected");
        };
        assert_eq!(framed.consumed(), 2);

        let ScanStatus::Partial(scanner) = TrailerScanner::new()
            .scan(b"Content-MD5: abc\r\n", HeadParserConfig::new())
            .unwrap()
        else {
            panic!("partial trailers expected");
        };
        let ScanStatus::Complete(framed) =
            scanner.scan(b"\r\nNEXT", HeadParserConfig::new()).unwrap()
        else {
            panic!("complete trailers expected");
        };
        assert_eq!(framed.consumed(), 20);

        let ScanStatus::Partial(scanner) = TrailerScanner::new()
            .scan(b"X: y\r\n", HeadParserConfig::new().with_max_bytes(6))
            .unwrap()
        else {
            panic!("partial trailers expected");
        };
        assert!(matches!(
            scanner
                .clone()
                .scan(b"", HeadParserConfig::new().with_max_bytes(6)),
            Ok(ScanStatus::Partial(_))
        ));
        let lowered = HeadParserConfig::new().with_max_bytes(4);
        assert_eq!(
            scanner.clone().scan(b"", lowered),
            Err(ParseError::HeadTooLarge)
        );
        assert_eq!(scanner.scan(b"x", lowered), Err(ParseError::HeadTooLarge));

        let partial = b"X-Test: value\r\n";
        let mut partial_storage = [HeaderSlot::EMPTY; 1];
        let exact = HeadParserConfig::new().with_max_bytes(partial.len());
        assert!(matches!(
            parse_trailers_with_config(partial, &mut partial_storage, exact,),
            Ok(ParseStatus::Partial)
        ));
        let larger = HeadParserConfig::new().with_max_bytes(partial.len() + 1);
        assert!(matches!(
            parse_trailers_with_config(partial, &mut partial_storage, larger,),
            Ok(ParseStatus::Partial)
        ));
        let smaller = HeadParserConfig::new().with_max_bytes(partial.len() - 1);
        assert_eq!(
            parse_trailers_with_config(partial, &mut partial_storage, smaller,),
            Err(ParseError::HeadTooLarge)
        );
    }

    #[test]
    fn header_storage_is_compact_and_equality_is_semantic() {
        assert_eq!(core::mem::size_of::<HeaderSlot>(), 20);

        let strict = b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX-Test: first second\r\n\r\n";
        let folded = b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX-Test: first\r\n second\r\n\r\n";
        let mut strict_storage = [HeaderSlot::EMPTY; 2];
        let ParseStatus::Complete(strict, _) =
            parse_request_head(strict, &mut strict_storage).unwrap()
        else {
            panic!("strict head expected");
        };
        let mut folded_storage = [HeaderSlot::EMPTY; 2];
        let config = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
        let ParseStatus::Complete(folded, _) =
            parse_request_head_with_config(folded, &mut folded_storage, config).unwrap()
        else {
            panic!("folded head expected");
        };
        assert_eq!(strict, folded);
        assert_eq!(strict.header_count(), 1);
        assert_eq!(strict.headers().size_hint(), (0, Some(1)));
    }

    #[test]
    fn header_storage_is_reusable_across_buffer_changes() {
        let mut input = b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX: one\r\n".to_vec();
        let mut headers = [HeaderSlot::EMPTY; 4];
        assert!(matches!(
            parse_request_head(&input, &mut headers),
            Ok(ParseStatus::Partial)
        ));

        input.extend_from_slice(b"\r\n");
        {
            let ParseStatus::Complete(head, consumed) =
                parse_request_head(&input, &mut headers).unwrap()
            else {
                panic!("complete request expected");
            };
            assert_eq!(consumed, input.len());
            assert_eq!(
                head.header("x").and_then(HeaderValue::as_bytes),
                Some(b"one".as_slice())
            );
        }

        input.clear();
        input.extend_from_slice(
            b"REQMOD icap://icap.test/ ICAP/1.0\r\n\
              Encapsulated: req-body=0\r\n\r\n",
        );
        let ParseStatus::Complete(head, consumed) =
            parse_request_head(&input, &mut headers).unwrap()
        else {
            panic!("complete recycled request expected");
        };
        assert_eq!(consumed, input.len());
        assert_eq!(head.line().method(), Method::Reqmod);
    }

    #[test]
    fn rejects_lf_only_messages() {
        let src = b"OPTIONS icap://icap.test/ ICAP/1.0\n\n";
        assert_eq!(request_result(src), Err(ParseError::InvalidLineEnding));
    }

    #[test]
    fn enforces_header_limit() {
        let src = b"OPTIONS icap://icap.test/ ICAP/1.0\r\n\
            Host: one\r\nPreview: 0\r\n\r\n";
        let mut headers = [HeaderSlot::EMPTY; 1];
        assert_eq!(
            parse_request_head(src, &mut headers),
            Err(ParseError::TooManyHeaders)
        );

        let src = b"OPTIONS icap://icap.test/ ICAP/1.0\r\n\
            Host: one\r\n\r\n";
        let mut headers = [HeaderSlot::EMPTY; 1];
        let ParseStatus::Complete(head, _) = parse_request_head(src, &mut headers).unwrap() else {
            panic!("complete request expected");
        };
        assert_eq!(head.header_count(), 1);
    }

    #[test]
    fn parses_response_head_and_binary_reason() {
        let src = b"ICAP/1.0 204 N\xf6 Content\r\nISTag: \"abc\"\r\n\r\n";
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(head, consumed) =
            parse_response_head(MethodKind::Respmod, src, &mut headers).unwrap()
        else {
            panic!("complete response expected");
        };
        assert_eq!(head.line().status(), StatusCode::NO_MODIFICATION_NEEDED);
        assert_eq!(head.line().reason(), b"N\xf6 Content");
        assert_eq!(head.line().version(), Version::ICAP_10);
        assert_eq!(
            head.header("istag").and_then(HeaderValue::as_bytes),
            Some(b"\"abc\"".as_slice())
        );
        assert_eq!(head.headers().next().unwrap().name(), "ISTag");
        assert_eq!(consumed, src.len());

        let src = b"ICAP/1.0 200 \r\nISTag: \"rama\"\r\n\r\n";
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(head, _) =
            parse_response_head(MethodKind::Respmod, src, &mut headers).unwrap()
        else {
            panic!("complete response expected");
        };
        assert_eq!(head.line().reason(), b"");
    }

    #[test]
    fn response_parser_honors_bounds_and_folding_policy() {
        let src = b"ICAP/1.0 200 OK\r\n\
            ISTag: \"rama\"\r\n\
            Service: first\r\n second\r\n\r\n";
        let allow = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(head, consumed) =
            parse_response_head_with_config(MethodKind::Respmod, src, &mut headers, allow).unwrap()
        else {
            panic!("complete response expected");
        };
        assert_eq!(consumed, src.len());
        assert_eq!(
            head.header("service")
                .unwrap()
                .segments()
                .collect::<std::vec::Vec<_>>(),
            [b"first".as_slice(), b"second".as_slice()]
        );

        let too_small = allow.with_max_bytes(src.len() - 1);
        assert_eq!(
            response_config_result(src, too_small),
            Err(ParseError::HeadTooLarge)
        );
    }

    #[test]
    fn request_head_round_trip() {
        let line = RequestLine::new(Method::Respmod, "icap://icap.test/a").unwrap();
        let headers = [
            Header::new("Host", b"icap.test").unwrap(),
            Header::new("Encapsulated", b"res-hdr=0, null-body=1").unwrap(),
        ];
        let mut dst = [0; 256];
        let len = encode_request_head(line, &headers, &mut dst).unwrap();
        let mut parsed_headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(parsed, consumed) =
            parse_request_head(&dst[..len], &mut parsed_headers).unwrap()
        else {
            panic!("complete request expected");
        };
        assert_eq!(consumed, len);
        assert_eq!(parsed.line(), line);
        assert_eq!(parsed.headers().collect::<std::vec::Vec<_>>(), headers);
        assert_eq!(
            parsed
                .encapsulated()
                .unwrap()
                .offset(crate::proto::EncapsulatedKind::NullBody),
            Some(1)
        );
    }

    #[test]
    fn response_head_round_trip() {
        for (status, expected) in [
            (StatusCode::CONTINUE, b"ICAP/1.0 100 OK\r\n".as_slice()),
            (
                StatusCode::from_u16(101).unwrap(),
                b"ICAP/1.0 101 OK\r\n".as_slice(),
            ),
            (
                StatusCode::from_u16(999).unwrap(),
                b"ICAP/1.0 999 OK\r\n".as_slice(),
            ),
        ] {
            let line = ResponseLine::new(status, b"OK").unwrap();
            let headers = [Header::new("ISTag", b"\"rama\"").unwrap()];
            let mut dst = [0; 128];
            let len = encode_response_head(MethodKind::Respmod, line, &headers, &mut dst).unwrap();
            assert!(dst[..len].starts_with(expected));
            let mut parsed_headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
            let ParseStatus::Complete(parsed, consumed) =
                parse_response_head(MethodKind::Respmod, &dst[..len], &mut parsed_headers).unwrap()
            else {
                panic!("complete response expected");
            };
            assert_eq!(consumed, len);
            assert_eq!(parsed.line(), line);
            assert_eq!(parsed.headers().collect::<std::vec::Vec<_>>(), headers);
        }
    }

    #[test]
    fn encoder_reports_small_buffer() {
        let line = ResponseLine::new(StatusCode::OK, b"OK").unwrap();
        let headers = [Header::new("ISTag", b"\"rama\"").unwrap()];
        assert_eq!(
            encode_response_head(MethodKind::Respmod, line, &headers, &mut [0; 4]),
            Err(EncodeError::BufferTooSmall)
        );
    }

    #[test]
    fn validates_public_head_components() {
        assert_eq!(Header::new("", b"ok"), Err(InvalidHeader));
        assert_eq!(Header::new("bad name", b"ok"), Err(InvalidHeader));
        assert_eq!(Header::new("Good", b"bad\n"), Err(InvalidHeader));
        let header = Header::new("X-Test", b"value").unwrap();
        assert_eq!(header.name(), "X-Test");
        assert_eq!(header.value().as_bytes(), Some(b"value".as_slice()));
        assert_eq!(Header::new("X-Test", b" value"), Err(InvalidHeader));
        assert_eq!(Header::new("X-Test", b"value "), Err(InvalidHeader));

        let extension = Method::extension("X-ICAP").unwrap();
        let line = RequestLine::new(extension, "icap://icap.test/service").unwrap();
        let mut encoded = [0; 128];
        let written = encode_request_head(line, &[], &mut encoded).unwrap();
        let mut slots = [HeaderSlot::EMPTY; 1];
        let ParseStatus::Complete(reparsed, consumed) =
            parse_request_head(&encoded[..written], &mut slots).unwrap()
        else {
            panic!("extension request expected");
        };
        assert_eq!(consumed, written);
        assert_eq!(reparsed.line(), line);

        for (method, encapsulated) in [
            (Method::Reqmod, Some(b"req-body=0".as_slice())),
            (Method::Respmod, Some(b"res-body=0".as_slice())),
            (Method::Options, None),
        ] {
            let header = encapsulated
                .map(|value| Header::new("Encapsulated", value))
                .transpose()
                .unwrap();
            let headers = header.as_slice();
            let line = RequestLine::new(method, "icap://icap.test/service").unwrap();
            let written = encode_request_head(line, headers, &mut encoded).unwrap();
            let ParseStatus::Complete(reparsed, consumed) =
                parse_request_head(&encoded[..written], &mut slots).unwrap()
            else {
                panic!("standard request expected");
            };
            assert_eq!(consumed, written);
            assert_eq!(reparsed.line(), line);
        }

        for uri in [
            "icap://icap.test/service",
            "ICAP://icap.test:1344/service?mode=%20",
            "icap://[::1]:1344/service",
        ] {
            assert!(
                RequestLine::new(Method::Reqmod, uri).is_ok(),
                "rejected {uri}"
            );
        }

        assert_eq!(
            RequestLine::new(Method::Reqmod, "http://icap.test/a"),
            Err(ParseError::InvalidUri)
        );
        assert_eq!(
            RequestLine::new(Method::Reqmod, "icap:///a"),
            Err(ParseError::InvalidUri)
        );
        for uri in ["icap://icap.test", "icap://icap.test?mode=scan"] {
            assert_eq!(
                RequestLine::new(Method::Options, uri),
                Err(ParseError::InvalidUri)
            );
        }
        for uri in [
            "icap://icap.test:/service",
            "icap://user:secret@icap.test/service",
        ] {
            assert_eq!(
                RequestLine::new(Method::Options, uri),
                Err(ParseError::InvalidUri)
            );
        }
        RequestLine::new(Method::Options, "icap://icap.test/service?mode=scan").unwrap();
        assert_eq!(
            ResponseLine::new(StatusCode::OK, b"bad\n"),
            Err(ParseError::InvalidReason)
        );
        assert_eq!(InvalidHeader.to_string(), "invalid ICAP header field");
        assert_eq!(
            EncodeError::BufferTooSmall.to_string(),
            "ICAP output buffer is too small"
        );
        assert_eq!(
            EncodeError::InvalidInput.to_string(),
            "invalid ICAP encoder input"
        );
    }

    #[test]
    fn rejects_malformed_request_lines_and_uris() {
        for src in [
            b"REQMOD  ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://host/a ICAP/1.0 extra\r\n\r\n".as_slice(),
            b"REQMOD icap://host/a\r\n\r\n".as_slice(),
            b"REQMOD /relative ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap:///path ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://?query ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://host ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://host?query ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://#fragment ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://host/a#fragment ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://:/service ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://host:abc/service ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://host:+1/service ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://host:/service ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://user:secret@host/service ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://user@/service ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://[::1/service ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://host/%zz ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://host/a\x7f ICAP/1.0\r\n\r\n".as_slice(),
            b"REQMOD icap://host/a ICAP/1.1\r\n\r\n".as_slice(),
        ] {
            assert!(request_result(src).is_err(), "accepted {src:?}");
        }
    }

    #[test]
    fn debug_views_do_not_dump_raw_head_buffers() {
        let request = b"OPTIONS icap://host/service?arg=87 ICAP/1.0\r\n\
            X-Secret: request-secret\r\n\r\n";
        let mut request_storage = [HeaderSlot::EMPTY; 2];
        let ParseStatus::Complete(head, _) =
            parse_request_head(request, &mut request_storage).unwrap()
        else {
            panic!("complete request expected");
        };
        let head_debug = std::format!("{head:?}");
        assert!(head_debug.contains("RequestHead"));
        assert!(head_debug.contains("service?arg=87"));
        assert!(head_debug.contains("header_count: 1"));
        assert!(!head_debug.contains("request-secret"));
        let headers_debug = std::format!("{:?}", head.headers());
        assert!(headers_debug.contains("ParsedHeaders"));
        assert!(headers_debug.contains("header_count: 1"));
        assert!(!headers_debug.contains("request-secret"));
        let header = head.headers().next().unwrap();
        assert_eq!(
            std::format!("{header:?}"),
            "Header { name: \"X-Secret\", value: HeaderValue { kind: \
             \"contiguous\", len: 14 } }"
        );
        assert_eq!(
            std::format!("{:?}", header.value()),
            "HeaderValue { kind: \"contiguous\", len: 14 }"
        );
        assert_eq!(
            std::format!("{:?}", header.value().segments()),
            "HeaderValueSegments { remaining_len: 14, contiguous: true }"
        );

        let response = b"ICAP/1.0 204 No Content\r\n\
            X-Secret: response-secret\r\n\r\n";
        let mut response_storage = [HeaderSlot::EMPTY; 2];
        let ParseStatus::Complete(head, _) =
            parse_response_head(MethodKind::Respmod, response, &mut response_storage).unwrap()
        else {
            panic!("complete response expected");
        };
        let head_debug = std::format!("{head:?}");
        assert!(head_debug.contains("ResponseHead"));
        assert!(head_debug.contains("header_count: 1"));
        assert!(!head_debug.contains("response-secret"));
        let headers_debug = std::format!("{:?}", head.headers());
        assert!(headers_debug.contains("ParsedHeaders"));
        assert!(headers_debug.contains("header_count: 1"));
        assert!(!headers_debug.contains("response-secret"));

        let mut trailer_storage = [HeaderSlot::EMPTY; 2];
        let ParseStatus::Complete(trailers, _) =
            parse_trailers(b"X-Secret: trailer-secret\r\n\r\n", &mut trailer_storage).unwrap()
        else {
            panic!("complete trailers expected");
        };
        let debug = std::format!("{trailers:?}");
        assert!(debug.contains("Trailers"));
        assert!(debug.contains("header_count: 1"));
        assert!(!debug.contains("trailer-secret"));

        let header = trailers.headers().next().unwrap();
        assert_eq!(
            std::format!("{header:?}"),
            "Header { name: \"X-Secret\", value: HeaderValue { kind: \
             \"contiguous\", len: 14 } }"
        );
        assert_eq!(
            std::format!("{:?}", header.value()),
            "HeaderValue { kind: \"contiguous\", len: 14 }"
        );
        assert_eq!(
            std::format!("{:?}", header.value().segments()),
            "HeaderValueSegments { remaining_len: 14, contiguous: true }"
        );
    }

    #[test]
    fn rejects_malformed_response_lines() {
        for src in [
            b"ICAP/1.0\r\n\r\n".as_slice(),
            b"ICAP/1.0 20 OK\r\n\r\n".as_slice(),
            b"ICAP/1.0 200\r\n\r\n".as_slice(),
            b"ICAP/1.0 200OK\r\n\r\n".as_slice(),
            b"ICAP/1.0 abc OK\r\n\r\n".as_slice(),
            b"ICAP/1.0 000 Nope\r\n\r\n".as_slice(),
            b"ICAP/1.0 200 bad\x00reason\r\n\r\n".as_slice(),
            b"ICAP/1.1 200 OK\r\n\r\n".as_slice(),
        ] {
            assert!(response_result(src).is_err(), "accepted {src:?}");
        }
    }

    #[test]
    fn rejects_invalid_crlf_in_every_head_part() {
        for src in [
            b"OPTIONS icap://host/a ICAP/1.0\rX".as_slice(),
            b"OPTIONS icap://host/a ICAP/1.0\r\nX: a\n\n".as_slice(),
            b"OPTIONS icap://host/a ICAP/1.0\r\nX: a\rX".as_slice(),
            b"OPTIONS icap://host/a ICAP/1.0\r\nX: a\r\n\n".as_slice(),
        ] {
            assert!(request_result(src).is_err(), "accepted {src:?}");
        }
    }

    #[test]
    fn formats_all_parse_errors() {
        let cases = [
            (ParseError::InvalidStartLine, "invalid ICAP start line"),
            (ParseError::InvalidMethod, "invalid ICAP method"),
            (ParseError::InvalidUri, "invalid ICAP URI"),
            (ParseError::InvalidVersion, "invalid ICAP version"),
            (ParseError::InvalidStatus, "invalid ICAP status"),
            (ParseError::InvalidReason, "invalid ICAP reason phrase"),
            (ParseError::InvalidHeader, "invalid ICAP header field"),
            (
                ParseError::InvalidComposition,
                "invalid ICAP message composition",
            ),
            (
                ParseError::ObsoleteLineFolding,
                "obsolete ICAP header line folding is disabled",
            ),
            (ParseError::TooManyHeaders, "too many ICAP header fields"),
            (ParseError::HeadTooLarge, "ICAP message head is too large"),
            (ParseError::InvalidLineEnding, "invalid ICAP line ending"),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
        assert_eq!(
            InvalidComposition.to_string(),
            "invalid ICAP message composition"
        );
    }
}
