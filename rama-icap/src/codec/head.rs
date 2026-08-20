use core::fmt;

use crate::proto::{
    InvalidMethod, InvalidStatusCode, InvalidVersion, Method, Preview, StatusCode, Version,
    is_token,
};

use super::encapsulated::{Encapsulated, EncapsulatedContext, parse_encapsulated};

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

/// Bounds and compatibility policy for ICAP head decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadParserConfig {
    max_bytes: usize,
    header_folding: HeaderFolding,
}

impl HeadParserConfig {
    /// Construct the default bounded, strict parser configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_HEAD_BYTES,
            header_folding: HeaderFolding::Reject,
        }
    }

    /// Set the maximum start-line and header-block size.
    #[must_use]
    pub const fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Set the obsolete line-folding policy.
    #[must_use]
    pub const fn with_header_folding(mut self, header_folding: HeaderFolding) -> Self {
        self.header_folding = header_folding;
        self
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
/// The caller must preserve the already scanned prefix between calls. Once a
/// complete head is found, later calls return the same consumed byte count
/// until [`HeadScanner::reset`] is called.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeadScanner {
    scanned: usize,
    complete: Option<usize>,
}

impl HeadScanner {
    /// Construct an empty scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scanned: 0,
            complete: None,
        }
    }

    /// Scan newly appended bytes for the end of an ICAP head.
    pub fn scan(
        &mut self,
        src: &[u8],
        config: HeadParserConfig,
    ) -> Result<ParseStatus<()>, ParseError> {
        if let Some(consumed) = self.complete {
            return Ok(ParseStatus::Complete((), consumed));
        }
        if src.len() < self.scanned {
            self.scanned = 0;
        }
        let bounded_len = src.len().min(config.max_bytes);
        if bounded_len < self.scanned {
            self.scanned = 0;
        }
        let start = self.scanned.saturating_sub(3);
        for index in start..bounded_len {
            if src
                .get(index..bounded_len)
                .is_some_and(|tail| tail.starts_with(b"\r\n\r\n"))
            {
                let consumed = index + 4;
                self.scanned = consumed;
                self.complete = Some(consumed);
                return Ok(ParseStatus::Complete((), consumed));
            }
            match src[index] {
                b'\n' if index == 0 || src[index - 1] != b'\r' => {
                    return Err(ParseError::InvalidLineEnding);
                }
                b'\r' if index + 1 < bounded_len && src[index + 1] != b'\n' => {
                    return Err(ParseError::InvalidLineEnding);
                }
                _ => {}
            }
        }
        self.scanned = bounded_len;
        if src.len() > config.max_bytes {
            Err(ParseError::HeadTooLarge)
        } else {
            Ok(ParseStatus::Partial)
        }
    }

    /// Reset the scanner for the next message.
    pub const fn reset(&mut self) {
        self.scanned = 0;
        self.complete = None;
    }
}

/// A borrowed header field value.
///
/// Strictly parsed and constructed values are contiguous. Compatibility-mode
/// values retain obsolete wire folds internally and expose only unfolded
/// segments, preventing embedded CRLF from escaping as an ordinary value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderValue<'a>(HeaderValueKind<'a>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderValueKind<'a> {
    Contiguous(&'a [u8]),
    Folded(&'a [u8]),
}

impl<'a> HeaderValue<'a> {
    /// Construct a validated, contiguous header value.
    pub fn new(value: &'a [u8]) -> Result<Self, InvalidHeader> {
        if !valid_header_value(value) || has_surrounding_whitespace(value) {
            return Err(InvalidHeader);
        }
        Ok(Self::contiguous(value))
    }

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
}

/// Iterator over the normalized segments of a header value.
#[derive(Clone, Debug)]
pub struct HeaderValueSegments<'a> {
    remaining: &'a [u8],
    contiguous: bool,
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

/// A borrowed ICAP header field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header<'a> {
    name: &'a str,
    value: HeaderValue<'a>,
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
    name_start: usize,
    name_end: usize,
    value_start: usize,
    value_end: usize,
    folded: bool,
}

/// Iterator over parsed header fields.
#[derive(Clone, Debug)]
pub struct ParsedHeaders<'headers, 'src> {
    src: &'src [u8],
    slots: &'headers [HeaderSlot],
    index: usize,
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
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ParsedHeaders<'_, '_> {}

impl<'a> Header<'a> {
    /// Construct and validate a borrowed ICAP header field.
    pub fn new(name: &'a str, value: &'a [u8]) -> Result<Self, InvalidHeader> {
        let value = HeaderValue::new(value)?;
        if !is_token(name.as_bytes()) || validate_known_header(name, value).is_err() {
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

/// A borrowed ICAP request line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestLine<'a> {
    method: Method<'a>,
    uri: &'a str,
    version: Version,
}

impl<'a> RequestLine<'a> {
    /// Construct a request line for an absolute ICAP URI with a service path.
    pub fn new(method: Method<'a>, uri: &'a str) -> Result<Self, ParseError> {
        validate_icap_uri(uri.as_bytes())?;
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
    pub const fn uri(self) -> &'a str {
        self.uri
    }

    /// Return the ICAP version.
    #[must_use]
    pub const fn version(self) -> Version {
        self.version
    }
}

/// A decoded ICAP request head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestHead<'headers, 'src> {
    line: RequestLine<'src>,
    src: &'src [u8],
    headers: &'headers [HeaderSlot],
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
        self.header("Preview")
            .and_then(HeaderValue::as_bytes)
            .and_then(|value| Preview::parse(value).ok())
    }

    /// Return the structurally validated `Encapsulated` field, when present.
    #[must_use]
    pub fn encapsulated(&self) -> Option<Encapsulated<'src>> {
        self.header("Encapsulated")
            .and_then(HeaderValue::as_bytes)
            .and_then(|value| parse_encapsulated(value).ok())
    }

    /// Validate method-specific message-body composition.
    pub fn validate(&self) -> Result<(), InvalidComposition> {
        validate_request_composition(self.line.method, self.headers())
    }
}

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHead<'headers, 'src> {
    line: ResponseLine<'src>,
    src: &'src [u8],
    headers: &'headers [HeaderSlot],
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
        self.header("Preview")
            .and_then(HeaderValue::as_bytes)
            .and_then(|value| Preview::parse(value).ok())
    }

    /// Return the structurally validated `Encapsulated` field, when present.
    #[must_use]
    pub fn encapsulated(&self) -> Option<Encapsulated<'src>> {
        self.header("Encapsulated")
            .and_then(HeaderValue::as_bytes)
            .and_then(|value| parse_encapsulated(value).ok())
    }

    /// Validate status- and request-method-specific composition.
    pub fn validate(&self, method: Method<'_>) -> Result<(), InvalidComposition> {
        validate_response_composition(method, self.line.status, self.headers())
    }
}

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

/// Parse an ICAP request head into caller-owned header storage.
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
    match parse_request_head_inner(&src[..bounded_len], headers, config.header_folding)? {
        ParseStatus::Partial if src.len() > config.max_bytes => Err(ParseError::HeadTooLarge),
        status => Ok(status),
    }
}

fn parse_request_head_inner<'headers, 'src>(
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
    header_folding: HeaderFolding,
) -> Result<ParseStatus<RequestHead<'headers, 'src>>, ParseError> {
    let Some((line, line_len)) = take_line(src)? else {
        return Ok(ParseStatus::Partial);
    };
    let line = parse_request_line(line)?;
    let Some((headers, consumed)) = parse_headers(src, line_len, headers, header_folding)? else {
        return Ok(ParseStatus::Partial);
    };
    let head = RequestHead {
        line,
        src: &src[..consumed],
        headers,
    };
    head.validate()
        .map_err(|_error| ParseError::InvalidComposition)?;

    Ok(ParseStatus::Complete(head, consumed))
}

/// Parse an ICAP response head into caller-owned header storage.
pub fn parse_response_head<'headers, 'src>(
    method: Method<'_>,
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
) -> Result<ParseStatus<ResponseHead<'headers, 'src>>, ParseError> {
    parse_response_head_with_config(method, src, headers, HeadParserConfig::new())
}

/// Parse an ICAP response head with explicit bounds and compatibility policy.
pub fn parse_response_head_with_config<'headers, 'src>(
    method: Method<'_>,
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
    config: HeadParserConfig,
) -> Result<ParseStatus<ResponseHead<'headers, 'src>>, ParseError> {
    let bounded_len = src.len().min(config.max_bytes);
    match parse_response_head_inner(method, &src[..bounded_len], headers, config.header_folding)? {
        ParseStatus::Partial if src.len() > config.max_bytes => Err(ParseError::HeadTooLarge),
        status => Ok(status),
    }
}

fn parse_response_head_inner<'headers, 'src>(
    method: Method<'_>,
    src: &'src [u8],
    headers: &'headers mut [HeaderSlot],
    header_folding: HeaderFolding,
) -> Result<ParseStatus<ResponseHead<'headers, 'src>>, ParseError> {
    let Some((line, line_len)) = take_line(src)? else {
        return Ok(ParseStatus::Partial);
    };
    let line = parse_response_line(line)?;
    let Some((headers, consumed)) = parse_headers(src, line_len, headers, header_folding)? else {
        return Ok(ParseStatus::Partial);
    };

    let head = ResponseHead {
        line,
        src: &src[..consumed],
        headers,
    };
    head.validate(method)
        .map_err(|_error| ParseError::InvalidComposition)?;
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
    encode_request_head_fields(line, headers.iter().copied(), dst)
}

/// Encode a previously parsed ICAP request head into `dst`.
pub fn encode_parsed_request_head(
    head: &RequestHead<'_, '_>,
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    validate_request_composition(head.line.method, head.headers())
        .map_err(|_error| EncodeError::InvalidInput)?;
    encode_request_head_fields(head.line, head.headers(), dst)
}

fn encode_request_head_fields<'a>(
    line: RequestLine<'_>,
    headers: impl IntoIterator<Item = Header<'a>>,
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut dst = Output::new(dst);
    dst.put(line.method.as_str().as_bytes())?;
    dst.put(b" ")?;
    dst.put(line.uri.as_bytes())?;
    dst.put(b" ")?;
    dst.put(line.version.as_str().as_bytes())?;
    dst.put(b"\r\n")?;
    encode_headers(headers, &mut dst)?;
    Ok(dst.len())
}

/// Encode an ICAP response line and header block into `dst`.
pub fn encode_response_head(
    method: Method<'_>,
    line: ResponseLine<'_>,
    headers: &[Header<'_>],
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    validate_response_composition(method, line.status, headers.iter().copied())
        .map_err(|_error| EncodeError::InvalidInput)?;
    encode_response_head_fields(line, headers.iter().copied(), dst)
}

/// Encode a previously parsed ICAP response head into `dst`.
pub fn encode_parsed_response_head(
    method: Method<'_>,
    head: &ResponseHead<'_, '_>,
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    head.validate(method)
        .map_err(|_error| EncodeError::InvalidInput)?;
    encode_response_head_fields(head.line, head.headers(), dst)
}

fn encode_response_head_fields<'a>(
    line: ResponseLine<'_>,
    headers: impl IntoIterator<Item = Header<'a>>,
    dst: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut dst = Output::new(dst);
    dst.put(line.version.as_str().as_bytes())?;
    dst.put(b" ")?;
    put_status(line.status, &mut dst)?;
    dst.put(b" ")?;
    dst.put(line.reason)?;
    dst.put(b"\r\n")?;
    encode_headers(headers, &mut dst)?;
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

    let method = Method::parse(method)?;
    validate_icap_uri(uri)?;
    let uri = core::str::from_utf8(uri).map_err(|_utf8_error| ParseError::InvalidUri)?;
    let version = Version::parse(version)?;
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
    let version = Version::parse(&line[..version_end])?;
    let rest = &line[version_end + 1..];
    if rest.len() < 4 || rest[3] != b' ' {
        return Err(ParseError::InvalidStartLine);
    }
    let digits = &rest[..3];
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(ParseError::InvalidStatus);
    }
    let value = u16::from(digits[0] - b'0') * 100
        + u16::from(digits[1] - b'0') * 10
        + u16::from(digits[2] - b'0');
    let status = StatusCode::from_u16(value)?;
    let reason = &rest[4..];
    validate_reason(reason)?;
    Ok(ResponseLine {
        version,
        status,
        reason,
    })
}

fn parse_headers<'headers>(
    src: &[u8],
    mut offset: usize,
    storage: &'headers mut [HeaderSlot],
    header_folding: HeaderFolding,
) -> Result<Option<(&'headers [HeaderSlot], usize)>, ParseError> {
    let mut count = 0;
    let mut value_start = 0;

    loop {
        let Some((line, line_len)) = take_line(&src[offset..])? else {
            return Ok(None);
        };
        if line.is_empty() {
            let headers = &storage[..count];
            validate_parsed_headers(src, headers)?;
            return Ok(Some((headers, offset + line_len)));
        }

        if matches!(line[0], b' ' | b'\t') {
            if header_folding == HeaderFolding::Reject {
                return Err(ParseError::ObsoleteLineFolding);
            }
            if count == 0 || !valid_header_value(line) {
                return Err(ParseError::InvalidHeader);
            }
            let value_end = offset + trim_folded_line_end(line);
            let Some(range) = storage[count - 1].0.as_mut() else {
                return Err(ParseError::InvalidHeader);
            };
            let name = core::str::from_utf8(&src[range.name_start..range.name_end])
                .map_err(|_utf8_error| ParseError::InvalidHeader)?;
            if is_framing_header(name) {
                return Err(ParseError::InvalidHeader);
            }
            range.value_start = value_start;
            range.value_end = value_end;
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
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .count();
        let value = &value[leading..];
        let value = trim_header_end(value);
        value_start = offset + colon + 1 + leading;
        let value_end = value_start + value.len();
        storage[count].0 = Some(HeaderRange {
            name_start: offset,
            name_end: offset + colon,
            value_start,
            value_end,
            folded: false,
        });
        count += 1;
        offset += line_len;
    }
}

fn header_from_range(src: &[u8], range: HeaderRange) -> Option<Header<'_>> {
    let name = core::str::from_utf8(src.get(range.name_start..range.name_end)?).ok()?;
    let raw = src.get(range.value_start..range.value_end)?;
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

fn validate_icap_uri(uri: &[u8]) -> Result<(), ParseError> {
    let Some(scheme) = uri.get(..7) else {
        return Err(ParseError::InvalidUri);
    };
    if !scheme.eq_ignore_ascii_case(b"icap://") || uri.contains(&b'#') {
        return Err(ParseError::InvalidUri);
    }
    rama_net::uri::validate_absolute_uri_strict(uri)
        .map_err(|_uri_error| ParseError::InvalidUri)?;

    let authority_end = uri[7..]
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?'))
        .map_or(uri.len(), |offset| offset + 7);
    if uri.get(authority_end) != Some(&b'/') {
        return Err(ParseError::InvalidUri);
    }
    let authority = &uri[7..authority_end];
    let host_and_port = authority
        .rsplit(|byte| *byte == b'@')
        .next()
        .ok_or(ParseError::InvalidUri)?;
    if host_and_port.is_empty() {
        return Err(ParseError::InvalidUri);
    }
    Ok(())
}

fn validate_reason(reason: &[u8]) -> Result<(), ParseError> {
    if reason
        .iter()
        .all(|byte| matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff))
    {
        Ok(())
    } else {
        Err(ParseError::InvalidReason)
    }
}

fn valid_header_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff))
}

fn has_surrounding_whitespace(value: &[u8]) -> bool {
    value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        || value
            .last()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
}

fn is_framing_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("Encapsulated") || name.eq_ignore_ascii_case("Preview")
}

fn validate_known_header(name: &str, value: HeaderValue<'_>) -> Result<(), InvalidHeader> {
    if !is_framing_header(name) {
        return Ok(());
    }
    let value = value.as_bytes().ok_or(InvalidHeader)?;
    if name.eq_ignore_ascii_case("Preview") {
        Preview::parse(value)
            .map(drop)
            .map_err(|_error| InvalidHeader)
    } else {
        parse_encapsulated(value)
            .map(drop)
            .map_err(|_error| InvalidHeader)
    }
}

fn validate_parsed_headers(src: &[u8], headers: &[HeaderSlot]) -> Result<(), ParseError> {
    let mut validation = HeaderValidation::default();
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
    let context = match method {
        Method::Reqmod => EncapsulatedContext::ReqmodRequest,
        Method::Respmod => EncapsulatedContext::RespmodRequest,
        Method::Options => EncapsulatedContext::OptionsRequest,
        Method::Extension(_) => {
            return validate_unrecognized_composition(headers);
        }
    };
    for header in headers {
        if header.name.eq_ignore_ascii_case("Encapsulated") {
            let value = header.value.as_bytes().ok_or(InvalidComposition)?;
            return parse_encapsulated(value)
                .and_then(|encapsulated| encapsulated.validate(context))
                .map_err(|_error| InvalidComposition);
        }
    }
    if method == Method::Options {
        Ok(())
    } else {
        Err(InvalidComposition)
    }
}

fn validate_response_composition<'a>(
    method: Method<'_>,
    status: StatusCode,
    headers: impl IntoIterator<Item = Header<'a>>,
) -> Result<(), InvalidComposition> {
    if status == StatusCode::PARTIAL_CONTENT && !matches!(method, Method::Reqmod | Method::Respmod)
    {
        return Err(InvalidComposition);
    }
    let mut encapsulated = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("Encapsulated") {
            let value = header.value.as_bytes().ok_or(InvalidComposition)?;
            encapsulated = Some(parse_encapsulated(value).map_err(|_error| InvalidComposition)?);
            break;
        }
    }
    let Some(encapsulated) = encapsulated else {
        return Ok(());
    };
    if !has_message_body(encapsulated) {
        return Ok(());
    }
    if !matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT) {
        return Err(InvalidComposition);
    }
    let context = match method {
        Method::Reqmod => EncapsulatedContext::ReqmodResponse,
        Method::Respmod => EncapsulatedContext::RespmodResponse,
        Method::Options => EncapsulatedContext::OptionsResponse,
        Method::Extension(_) => return Err(InvalidComposition),
    };
    encapsulated
        .validate(context)
        .map_err(|_error| InvalidComposition)
}

fn validate_unrecognized_composition<'a>(
    headers: impl IntoIterator<Item = Header<'a>>,
) -> Result<(), InvalidComposition> {
    for header in headers {
        if header.name.eq_ignore_ascii_case("Encapsulated") {
            let value = header.value.as_bytes().ok_or(InvalidComposition)?;
            let value = parse_encapsulated(value).map_err(|_error| InvalidComposition)?;
            if has_message_body(value) {
                return Err(InvalidComposition);
            }
        }
    }
    Ok(())
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

#[derive(Default)]
struct HeaderValidation {
    saw_preview: bool,
    saw_encapsulated: bool,
}

impl HeaderValidation {
    fn validate(&mut self, header: Header<'_>) -> Result<(), InvalidHeader> {
        if !is_token(header.name.as_bytes()) {
            return Err(InvalidHeader);
        }
        validate_known_header(header.name, header.value)?;
        let seen = if header.name.eq_ignore_ascii_case("Preview") {
            &mut self.saw_preview
        } else if header.name.eq_ignore_ascii_case("Encapsulated") {
            &mut self.saw_encapsulated
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

fn trim_header_end(mut value: &[u8]) -> &[u8] {
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn trim_header_start(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
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

fn encode_headers<'a>(
    headers: impl IntoIterator<Item = Header<'a>>,
    dst: &mut Output<'_>,
) -> Result<(), EncodeError> {
    let mut validation = HeaderValidation::default();
    for header in headers {
        validation
            .validate(header)
            .map_err(|_error| EncodeError::InvalidInput)?;
        dst.put(header.name.as_bytes())?;
        dst.put(b": ")?;
        put_header_value(header.value, dst)?;
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
        parse_response_head(Method::Respmod, src, &mut headers).map(|status| match status {
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
        parse_response_head_with_config(Method::Respmod, src, &mut headers, config).map(|status| {
            match status {
                ParseStatus::Partial => ParseStatus::Partial,
                ParseStatus::Complete(_, consumed) => ParseStatus::Complete((), consumed),
            }
        })
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
        assert_eq!(head.line().uri(), "icap://icap.test/scan");
        assert_eq!(
            head.header("preview").and_then(HeaderValue::as_bytes),
            Some(b"128".as_slice())
        );
        assert_eq!(head.preview(), Some(Preview::new(128)));
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
                b"ICAP/1.0 200 OK\r\nX:\r\n text\r\n\r\n",
                b"ICAP/1.0 200 OK\r\nX: text\r\n\r\n",
            ),
            (
                b"ICAP/1.0 200 OK\r\nX:\r\n \t \r\n\r\n",
                b"ICAP/1.0 200 OK\r\nX: \r\n\r\n",
            ),
        ];
        for (wire, expected) in responses {
            let mut headers = [HeaderSlot::EMPTY; 4];
            let ParseStatus::Complete(head, _) =
                parse_response_head_with_config(Method::Respmod, wire, &mut headers, config)
                    .unwrap()
            else {
                panic!("complete response expected");
            };
            let mut encoded = [0; 64];
            let len = encode_parsed_response_head(Method::Respmod, &head, &mut encoded).unwrap();
            assert_eq!(&encoded[..len], *expected);
        }
    }

    #[test]
    fn validates_framing_headers_and_request_composition() {
        assert_eq!(
            HeaderValue::new(b"opaque value").unwrap().as_bytes(),
            Some(b"opaque value".as_slice())
        );
        for value in [
            b" leading".as_slice(),
            b"trailing\t".as_slice(),
            b"embedded\r\nline".as_slice(),
            b"control\0byte".as_slice(),
        ] {
            assert_eq!(HeaderValue::new(value), Err(InvalidHeader));
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
        let body = [Header::new("Encapsulated", b"res-hdr=0, res-body=10").unwrap()];
        for status in [StatusCode::CONTINUE, StatusCode::NO_MODIFICATION_NEEDED] {
            let line = ResponseLine::new(status, b"No Body").unwrap();
            assert_eq!(
                encode_response_head(Method::Respmod, line, &body, &mut [0; 128]),
                Err(EncodeError::InvalidInput)
            );
        }

        let wire = b"ICAP/1.0 204 No Content\r\n\
            Encapsulated: res-hdr=0, res-body=10\r\n\r\n";
        assert_eq!(response_result(wire), Err(ParseError::InvalidComposition));

        let ok = ResponseLine::new(StatusCode::OK, b"OK").unwrap();
        encode_response_head(Method::Respmod, ok, &body, &mut [0; 128]).unwrap();
        assert_eq!(
            encode_response_head(Method::Options, ok, &body, &mut [0; 128]),
            Err(EncodeError::InvalidInput)
        );
        let options_body = [Header::new("Encapsulated", b"opt-body=0").unwrap()];
        encode_response_head(Method::Options, ok, &options_body, &mut [0; 128]).unwrap();
        let partial = ResponseLine::new(StatusCode::PARTIAL_CONTENT, b"Partial").unwrap();
        assert_eq!(
            encode_response_head(Method::Options, partial, &options_body, &mut [0; 128]),
            Err(EncodeError::InvalidInput)
        );

        let empty = [Header::new("Encapsulated", b"null-body=0").unwrap()];
        for method in [Method::Reqmod, Method::Respmod] {
            encode_response_head(method, partial, &[], &mut [0; 128]).unwrap();
            encode_response_head(method, partial, &empty, &mut [0; 128]).unwrap();
        }
        for method in [Method::Options, Method::extension("X-ICAP").unwrap()] {
            assert_eq!(
                encode_response_head(method, partial, &[], &mut [0; 128]),
                Err(EncodeError::InvalidInput)
            );
            assert_eq!(
                encode_response_head(method, partial, &empty, &mut [0; 128]),
                Err(EncodeError::InvalidInput)
            );
            for wire in [
                b"ICAP/1.0 206 Partial Content\r\n\r\n".as_slice(),
                b"ICAP/1.0 206 Partial Content\r\n\
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
        encode_response_head(Method::Respmod, no_content, &empty, &mut [0; 128]).unwrap();
    }

    #[test]
    fn scanners_avoid_rescanning_growing_buffers() {
        let head = b"OPTIONS icap://icap.test/ ICAP/1.0\r\nX: y\r\n\r\nbody";
        let config = HeadParserConfig::new().with_max_bytes(head.len() - 4);
        let mut scanner = HeadScanner::new();
        for len in 0..head.len() - 4 {
            assert_eq!(scanner.scan(&head[..len], config), Ok(ParseStatus::Partial));
        }
        assert_eq!(
            scanner.scan(head, config),
            Ok(ParseStatus::Complete((), head.len() - 4))
        );
        assert_eq!(
            scanner.scan(head, config),
            Ok(ParseStatus::Complete((), head.len() - 4))
        );
        scanner.reset();
        assert_eq!(scanner, HeadScanner::new());

        let short = HeadParserConfig::new().with_max_bytes(3);
        assert_eq!(scanner.scan(b"abcd", short), Err(ParseError::HeadTooLarge));

        scanner.reset();
        assert_eq!(scanner.scan(b"abc", short), Ok(ParseStatus::Partial));

        let mut scanner = HeadScanner::new();
        assert_eq!(scanner.scan(&head[..10], config), Ok(ParseStatus::Partial));
        assert_eq!(
            scanner.scan(head, config),
            Ok(ParseStatus::Complete((), head.len() - 4))
        );

        scanner.reset();
        assert_eq!(
            scanner.scan(b"OPTIONS icap://host/ ICAP/1.0\n", config),
            Err(ParseError::InvalidLineEnding)
        );
        scanner.reset();
        assert_eq!(
            scanner.scan(b"OPTIONS icap://host/ ICAP/1.0\rX", config),
            Err(ParseError::InvalidLineEnding)
        );
        scanner.reset();
        assert_eq!(
            scanner.scan(b"A\rX", HeadParserConfig::new().with_max_bytes(2)),
            Err(ParseError::HeadTooLarge)
        );
        scanner.reset();
        assert_eq!(
            scanner.scan(b"A\rX", HeadParserConfig::new().with_max_bytes(3)),
            Err(ParseError::InvalidLineEnding)
        );
        scanner.reset();
        assert_eq!(
            scanner.scan(b"A\r\n\r\n", HeadParserConfig::new().with_max_bytes(2)),
            Err(ParseError::HeadTooLarge)
        );
        scanner.reset();
        assert_eq!(
            scanner.scan(b"A\r\n\r\n", HeadParserConfig::new().with_max_bytes(5)),
            Ok(ParseStatus::Complete((), 5))
        );

        let wire = b"OPTIONS icap://host/ ICAP/1.0\r\n\r\n";
        let mut scanner = HeadScanner::new();
        assert_eq!(
            scanner.scan(wire, HeadParserConfig::new()),
            Ok(ParseStatus::Complete((), wire.len()))
        );
        for suffix in [
            b"\r\n".as_slice(),
            b"\n".as_slice(),
            b"ICAP/1.0 200 OK\r\n\r\n".as_slice(),
        ] {
            let mut with_body = wire.to_vec();
            with_body.extend_from_slice(suffix);
            assert_eq!(
                scanner.scan(&with_body, HeadParserConfig::new()),
                Ok(ParseStatus::Complete((), wire.len()))
            );
        }
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
        assert_eq!(head.headers().len(), 1);
    }

    #[test]
    fn parses_response_head_and_binary_reason() {
        let src = b"ICAP/1.0 204 N\xf6 Content\r\nISTag: abc\r\n\r\n";
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(head, consumed) =
            parse_response_head(Method::Respmod, src, &mut headers).unwrap()
        else {
            panic!("complete response expected");
        };
        assert_eq!(head.line().status(), StatusCode::NO_MODIFICATION_NEEDED);
        assert_eq!(head.line().reason(), b"N\xf6 Content");
        assert_eq!(head.line().version(), Version::ICAP_10);
        assert_eq!(
            head.header("istag").and_then(HeaderValue::as_bytes),
            Some(b"abc".as_slice())
        );
        assert_eq!(head.headers().next().unwrap().name(), "ISTag");
        assert_eq!(consumed, src.len());

        let src = b"ICAP/1.0 200 \r\n\r\n";
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(head, _) =
            parse_response_head(Method::Respmod, src, &mut headers).unwrap()
        else {
            panic!("complete response expected");
        };
        assert_eq!(head.line().reason(), b"");
    }

    #[test]
    fn response_parser_honors_bounds_and_folding_policy() {
        let src = b"ICAP/1.0 200 OK\r\nService: first\r\n second\r\n\r\n";
        let allow = HeadParserConfig::new().with_header_folding(HeaderFolding::Allow);
        let mut headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
        let ParseStatus::Complete(head, consumed) =
            parse_response_head_with_config(Method::Respmod, src, &mut headers, allow).unwrap()
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
            let headers = [Header::new("ISTag", b"rama").unwrap()];
            let mut dst = [0; 128];
            let len = encode_response_head(Method::Respmod, line, &headers, &mut dst).unwrap();
            assert!(dst[..len].starts_with(expected));
            let mut parsed_headers = [HeaderSlot::EMPTY; DEFAULT_MAX_HEADERS];
            let ParseStatus::Complete(parsed, consumed) =
                parse_response_head(Method::Respmod, &dst[..len], &mut parsed_headers).unwrap()
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
        assert_eq!(
            encode_response_head(Method::Respmod, line, &[], &mut [0; 4]),
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
            "ICAP://user@icap.test:1344/service?mode=%20",
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
