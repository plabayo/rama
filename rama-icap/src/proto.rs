//! ICAP protocol values independent of transport I/O.

use core::fmt;

/// An ICAP request method.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Method<'a> {
    /// Request modification.
    Reqmod,
    /// Response modification.
    Respmod,
    /// Service capability discovery.
    Options,
    /// A protocol extension method.
    Extension(ExtensionMethod<'a>),
}

impl<'a> Method<'a> {
    /// Construct a validated extension method.
    pub fn extension(value: &'a str) -> Result<Self, InvalidMethod> {
        ExtensionMethod::new(value).map(Self::Extension)
    }

    /// Parse an ICAP method token.
    pub fn parse(value: &'a [u8]) -> Result<Self, InvalidMethod> {
        if !is_token(value) {
            return Err(InvalidMethod);
        }

        match value {
            b"REQMOD" => Ok(Self::Reqmod),
            b"RESPMOD" => Ok(Self::Respmod),
            b"OPTIONS" => Ok(Self::Options),
            _ => {
                let value = core::str::from_utf8(value).map_err(|_utf8_error| InvalidMethod)?;
                Self::extension(value)
            }
        }
    }

    /// Return the method as it appears on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        match self {
            Self::Reqmod => "REQMOD",
            Self::Respmod => "RESPMOD",
            Self::Options => "OPTIONS",
            Self::Extension(value) => value.as_str(),
        }
    }
}

/// A validated ICAP extension method distinct from standard methods.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExtensionMethod<'a>(&'a str);

impl<'a> ExtensionMethod<'a> {
    /// Construct an extension method token.
    pub fn new(value: &'a str) -> Result<Self, InvalidMethod> {
        if !is_token(value.as_bytes()) || matches!(value, "REQMOD" | "RESPMOD" | "OPTIONS") {
            return Err(InvalidMethod);
        }
        Ok(Self(value))
    }

    /// Return the extension method as it appears on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

impl fmt::Display for ExtensionMethod<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for Method<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An invalid ICAP method token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidMethod;

impl fmt::Display for InvalidMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ICAP method")
    }
}

impl core::error::Error for InvalidMethod {}

/// An ICAP protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Version(());

impl Version {
    /// ICAP version 1.0.
    pub const ICAP_10: Self = Self(());

    /// Parse an ICAP version.
    pub fn parse(value: &[u8]) -> Result<Self, InvalidVersion> {
        if value == b"ICAP/1.0" {
            Ok(Self::ICAP_10)
        } else {
            Err(InvalidVersion)
        }
    }

    /// Return the version as it appears on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        "ICAP/1.0"
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An unsupported or malformed ICAP version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidVersion;

impl fmt::Display for InvalidVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ICAP version")
    }
}

impl core::error::Error for InvalidVersion {}

/// A three-digit ICAP response status code.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StatusCode(u16);

impl StatusCode {
    /// Continue after a Preview.
    pub const CONTINUE: Self = Self(100);
    /// Successful adaptation.
    pub const OK: Self = Self(200);
    /// No adaptation was required.
    pub const NO_MODIFICATION_NEEDED: Self = Self(204);
    /// Partial adaptation response.
    pub const PARTIAL_CONTENT: Self = Self(206);
    /// Malformed ICAP request.
    pub const BAD_REQUEST: Self = Self(400);
    /// ICAP service not found.
    pub const NOT_FOUND: Self = Self(404);
    /// Method unsupported by the service.
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    /// ICAP request timeout.
    pub const REQUEST_TIMEOUT: Self = Self(408);
    /// Encapsulated sections do not match the service's needs.
    pub const BAD_COMPOSITION: Self = Self(418);
    /// Internal ICAP server error.
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    /// ICAP method not implemented.
    pub const NOT_IMPLEMENTED: Self = Self(501);
    /// ICAP version unsupported by the server.
    pub const VERSION_NOT_SUPPORTED: Self = Self(505);

    /// Construct a three-digit status code.
    pub const fn from_u16(value: u16) -> Result<Self, InvalidStatusCode> {
        if value >= 100 && value <= 999 {
            Ok(Self(value))
        } else {
            Err(InvalidStatusCode)
        }
    }

    /// Return the numeric status code.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An ICAP status code outside the three-digit wire range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidStatusCode;

impl fmt::Display for InvalidStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ICAP status code")
    }
}

impl core::error::Error for InvalidStatusCode {}

/// The maximum number of encapsulated body bytes sent as a Preview.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Preview(u64);

impl Preview {
    /// Construct a Preview byte limit.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Parse a `Preview` header field value.
    pub fn parse(value: &[u8]) -> Result<Self, InvalidPreview> {
        if value.is_empty() {
            return Err(InvalidPreview);
        }
        let value = value.iter().try_fold(0_u64, |result, byte| {
            if !byte.is_ascii_digit() {
                return Err(InvalidPreview);
            }
            let digit = u64::from(byte - b'0');
            result
                .checked_mul(10)
                .and_then(|result| result.checked_add(digit))
                .ok_or(InvalidPreview)
        })?;
        Ok(Self(value))
    }

    /// Return the Preview byte limit.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Preview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A malformed or overflowing `Preview` header value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPreview;

impl fmt::Display for InvalidPreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ICAP Preview header")
    }
}

impl core::error::Error for InvalidPreview {}

/// A kind of entity listed by the `Encapsulated` header.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EncapsulatedKind {
    /// Encapsulated HTTP request headers.
    RequestHeader,
    /// Encapsulated HTTP response headers.
    ResponseHeader,
    /// Encapsulated HTTP request body.
    RequestBody,
    /// Encapsulated HTTP response body.
    ResponseBody,
    /// Encapsulated OPTIONS body.
    OptionsBody,
    /// No encapsulated body.
    NullBody,
}

impl EncapsulatedKind {
    /// Parse an `Encapsulated` entity name.
    pub fn parse(value: &[u8]) -> Result<Self, InvalidEncapsulated> {
        match value {
            b"req-hdr" => Ok(Self::RequestHeader),
            b"res-hdr" => Ok(Self::ResponseHeader),
            b"req-body" => Ok(Self::RequestBody),
            b"res-body" => Ok(Self::ResponseBody),
            b"opt-body" => Ok(Self::OptionsBody),
            b"null-body" => Ok(Self::NullBody),
            _ => Err(InvalidEncapsulated),
        }
    }

    /// Return the entity name as it appears on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestHeader => "req-hdr",
            Self::ResponseHeader => "res-hdr",
            Self::RequestBody => "req-body",
            Self::ResponseBody => "res-body",
            Self::OptionsBody => "opt-body",
            Self::NullBody => "null-body",
        }
    }

    /// Return whether this entity terminates the section list.
    #[must_use]
    pub const fn is_body(self) -> bool {
        matches!(
            self,
            Self::RequestBody | Self::ResponseBody | Self::OptionsBody | Self::NullBody
        )
    }
}

/// One entity and offset from an `Encapsulated` header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncapsulatedSection {
    kind: EncapsulatedKind,
    offset: u64,
}

impl EncapsulatedSection {
    /// Construct an encapsulated section.
    #[must_use]
    pub const fn new(kind: EncapsulatedKind, offset: u64) -> Self {
        Self { kind, offset }
    }

    /// Return the entity kind.
    #[must_use]
    pub const fn kind(self) -> EncapsulatedKind {
        self.kind
    }

    /// Return the byte offset in the ICAP message body as a wire-width value.
    ///
    /// Consumers must use checked conversion and checked streaming counters;
    /// an offset beyond the available body is a transaction error.
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Convert the body offset to a platform index without truncation.
    ///
    /// The result must still be checked against the available body length.
    #[must_use]
    pub fn offset_usize(self) -> Option<usize> {
        usize::try_from(self.offset).ok()
    }
}

/// A syntactically invalid `Encapsulated` header value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidEncapsulated;

impl fmt::Display for InvalidEncapsulated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ICAP Encapsulated header")
    }
}

impl core::error::Error for InvalidEncapsulated {}

pub(crate) fn is_token(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().copied().all(is_token_byte)
}

pub(crate) const fn is_token_byte(value: u8) -> bool {
    matches!(value, 0x21..=0x7e)
        && !matches!(
            value,
            b'(' | b')'
                | b'<'
                | b'>'
                | b'@'
                | b','
                | b';'
                | b':'
                | b'\\'
                | b'"'
                | b'/'
                | b'['
                | b']'
                | b'?'
                | b'='
                | b'{'
                | b'}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_and_extension_methods() {
        let log = Method::extension("LOG").unwrap();
        assert_eq!(Method::parse(b"REQMOD"), Ok(Method::Reqmod));
        assert_eq!(Method::parse(b"RESPMOD"), Ok(Method::Respmod));
        assert_eq!(Method::parse(b"OPTIONS"), Ok(Method::Options));
        assert_eq!(Method::parse(b"LOG"), Ok(log));
        assert_eq!(Method::Reqmod.as_str(), "REQMOD");
        assert_eq!(Method::Respmod.to_string(), "RESPMOD");
        assert_eq!(Method::Options.as_str(), "OPTIONS");
        assert_eq!(log.as_str(), "LOG");
        let Method::Extension(log) = log else {
            panic!("extension method expected");
        };
        assert_eq!(log.as_str(), "LOG");
        assert_eq!(log.to_string(), "LOG");
        for reserved in ["REQMOD", "RESPMOD", "OPTIONS"] {
            assert_eq!(Method::extension(reserved), Err(InvalidMethod));
            assert_eq!(ExtensionMethod::new(reserved), Err(InvalidMethod));
        }
        assert_eq!(Method::extension("bad method"), Err(InvalidMethod));
        assert_eq!(Method::extension("bad\r\nmethod"), Err(InvalidMethod));
        assert_eq!(Method::parse(b""), Err(InvalidMethod));
        assert_eq!(Method::parse(b"BAD METHOD"), Err(InvalidMethod));
        assert_eq!(Method::parse(&[0xff]), Err(InvalidMethod));
        assert_eq!(InvalidMethod.to_string(), "invalid ICAP method");
    }

    #[test]
    fn parses_and_formats_version() {
        assert_eq!(Version::parse(b"ICAP/1.0"), Ok(Version::ICAP_10));
        assert_eq!(Version::parse(b"ICAP/1.1"), Err(InvalidVersion));
        assert_eq!(Version::ICAP_10.as_str(), "ICAP/1.0");
        assert_eq!(Version::ICAP_10.to_string(), "ICAP/1.0");
        assert_eq!(InvalidVersion.to_string(), "invalid ICAP version");
    }

    #[test]
    fn status_code_requires_three_digits() {
        assert_eq!(StatusCode::from_u16(99), Err(InvalidStatusCode));
        assert_eq!(StatusCode::from_u16(100), Ok(StatusCode::CONTINUE));
        assert_eq!(StatusCode::from_u16(999).map(StatusCode::as_u16), Ok(999));
        assert_eq!(StatusCode::from_u16(1000), Err(InvalidStatusCode));
        assert_eq!(StatusCode::PARTIAL_CONTENT.as_u16(), 206);
        assert_eq!(StatusCode::BAD_COMPOSITION.as_u16(), 418);
        assert_eq!(StatusCode::NOT_IMPLEMENTED.to_string(), "501");
        assert_eq!(InvalidStatusCode.to_string(), "invalid ICAP status code");
    }

    #[test]
    fn parses_preview_limit() {
        assert_eq!(Preview::parse(b"0"), Ok(Preview::new(0)));
        assert_eq!(Preview::parse(b"4096"), Ok(Preview::new(4096)));
        assert_eq!(Preview::parse(b"4096").unwrap().as_u64(), 4096);
        assert_eq!(Preview::new(42).to_string(), "42");
        assert_eq!(Preview::parse(b""), Err(InvalidPreview));
        assert_eq!(Preview::parse(b"-1"), Err(InvalidPreview));
        assert_eq!(
            Preview::parse(b"999999999999999999999999999999999999"),
            Err(InvalidPreview)
        );
        assert_eq!(InvalidPreview.to_string(), "invalid ICAP Preview header");
    }

    #[test]
    fn encapsulated_protocol_values_round_trip() {
        let kinds = [
            EncapsulatedKind::RequestHeader,
            EncapsulatedKind::ResponseHeader,
            EncapsulatedKind::RequestBody,
            EncapsulatedKind::ResponseBody,
            EncapsulatedKind::OptionsBody,
            EncapsulatedKind::NullBody,
        ];
        for kind in kinds {
            assert_eq!(EncapsulatedKind::parse(kind.as_str().as_bytes()), Ok(kind));
        }
        assert!(!EncapsulatedKind::RequestHeader.is_body());
        assert!(!EncapsulatedKind::ResponseHeader.is_body());
        for kind in &kinds[2..] {
            assert!(kind.is_body());
        }
        assert_eq!(
            EncapsulatedKind::parse(b"unknown"),
            Err(InvalidEncapsulated)
        );

        let section = EncapsulatedSection::new(EncapsulatedKind::ResponseBody, 123);
        assert_eq!(section.kind(), EncapsulatedKind::ResponseBody);
        assert_eq!(section.offset(), 123);
        assert_eq!(section.offset_usize(), Some(123));
        assert_eq!(
            InvalidEncapsulated.to_string(),
            "invalid ICAP Encapsulated header"
        );
    }
}
