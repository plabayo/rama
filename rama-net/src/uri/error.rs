//! Error types for the [`crate::uri`] module.
//!
//! Two distinct enums:
//!
//! - [`ParseError`] — surfaced when bytes coming in cannot be turned into a
//!   valid [`Uri`](super::Uri). Carries enough information to point at *what*
//!   went wrong (offset, component) for diagnostics.
//! - [`UriError`] — surfaced when an operation on an already-parsed Uri
//!   cannot be applied (e.g. setting an invalid path, encoding bound checks).
//!
//! Both are ordinary enums (no `#[non_exhaustive]`): adding a variant is a
//! breaking change, which rama accepts at major-bump time.

use std::fmt;

/// Reasons parsing a byte string into a [`Uri`](super::Uri) can fail.
///
/// **Graceful by default**: the regular `Uri::parse` entry point (lands in
/// M3) accepts inputs that browsers and curl tolerate. Only inputs in the
/// "differential-parse hazard" set (control chars, backslash-as-slash,
/// alternate IPv4 forms, etc.) are unconditionally rejected — and those are
/// the variants below that can fire even from `parse`.
///
/// `Uri::parse_strict` (lands in M3) additionally rejects everything outside
/// RFC 3986.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input was empty.
    Empty,

    /// A `\0`, `\r`, `\n`, `\t`, or other ASCII control character was found
    /// inside a URI component. Always rejected — these are header-injection
    /// and request-smuggling vectors.
    ControlCharInUri { at: usize, byte: u8 },

    /// The input contained a non-ASCII byte outside an IDN-eligible host
    /// position, or contained a non-ASCII host with the `idna` feature
    /// disabled.
    NonAsciiOutsideHost { at: usize },

    /// The scheme component was malformed or contained disallowed characters.
    InvalidScheme,

    /// The authority component was malformed.
    InvalidAuthority,

    /// A userinfo subcomponent was malformed.
    InvalidUserInfo,

    /// The host subcomponent was malformed (e.g. mismatched brackets, empty
    /// host, invalid IDN form).
    InvalidHost,

    /// The port subcomponent was not a valid `1..=65535` decimal.
    InvalidPort,

    /// The path component contained disallowed bytes.
    InvalidPath,

    /// The query component contained disallowed bytes.
    InvalidQuery,

    /// The fragment component contained disallowed bytes.
    InvalidFragment,

    /// A percent-encoded escape was malformed (`%` not followed by two hex
    /// digits, or the resulting byte is itself disallowed in the component).
    InvalidPercentEncoding { at: usize },

    /// An IPv6 literal carried a zone identifier (`%25en0` on the wire).
    /// Not currently supported — see module-level docs for the path forward.
    IPv6ZoneNotSupported,

    /// IDNA processing rejected the host, or non-ASCII host bytes were
    /// supplied without the `idna` feature enabled.
    IdnaNotEnabled,

    /// Strict-mode-only rejection: input parsed under graceful rules but
    /// violates RFC 3986. Only produced by `Uri::parse_strict` (M3).
    StrictViolation,

    /// The URI exceeded the maximum representable length.
    TooLong { len: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("uri is empty"),
            Self::ControlCharInUri { at, byte } => {
                write!(f, "control character 0x{byte:02X} at byte {at}")
            }
            Self::NonAsciiOutsideHost { at } => {
                write!(
                    f,
                    "non-ASCII byte at {at} outside an IDN-eligible host position"
                )
            }
            Self::InvalidScheme => f.write_str("invalid scheme"),
            Self::InvalidAuthority => f.write_str("invalid authority"),
            Self::InvalidUserInfo => f.write_str("invalid userinfo"),
            Self::InvalidHost => f.write_str("invalid host"),
            Self::InvalidPort => f.write_str("invalid port"),
            Self::InvalidPath => f.write_str("invalid path"),
            Self::InvalidQuery => f.write_str("invalid query"),
            Self::InvalidFragment => f.write_str("invalid fragment"),
            Self::InvalidPercentEncoding { at } => {
                write!(f, "invalid percent-encoded escape at byte {at}")
            }
            Self::IPv6ZoneNotSupported => f.write_str(
                "IPv6 zone identifiers are not currently supported in uri host literals",
            ),
            Self::IdnaNotEnabled => {
                f.write_str("non-ASCII host requires the `idna` feature to be enabled")
            }
            Self::StrictViolation => f.write_str("input does not satisfy RFC 3986 strict syntax"),
            Self::TooLong { len } => write!(f, "uri is {len} bytes long, exceeds the maximum"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Reasons an operation on an already-parsed [`Uri`](super::Uri) can fail.
///
/// Distinct from [`ParseError`] because the failure mode for *mutation*
/// (e.g. trying to set an invalid path) is different from the failure mode
/// for *parsing* (e.g. structural rejection). Both share semantic territory
/// — invalid bytes are still invalid bytes — but the diagnostics callers want
/// differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriError {
    /// A setter received an input that fails component validation.
    InvalidComponent {
        /// Which component was being set.
        component: Component,
        /// Underlying parse-level cause if available.
        cause: ParseError,
    },

    /// An operation was attempted that is meaningless for the asterisk-form
    /// URI (e.g. iterating path segments of `*`). Most setters auto-upgrade
    /// asterisk to a reference; the few that cannot return this error.
    AsteriskOperation,
}

/// Which URI component a [`UriError`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    Scheme,
    UserInfo,
    Host,
    Port,
    Path,
    Query,
    Fragment,
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Scheme => "scheme",
            Self::UserInfo => "userinfo",
            Self::Host => "host",
            Self::Port => "port",
            Self::Path => "path",
            Self::Query => "query",
            Self::Fragment => "fragment",
        })
    }
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidComponent { component, cause } => {
                write!(f, "invalid {component} component: {cause}")
            }
            Self::AsteriskOperation => {
                f.write_str("operation is not valid on the asterisk-form uri")
            }
        }
    }
}

impl std::error::Error for UriError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidComponent { cause, .. } => Some(cause),
            Self::AsteriskOperation => None,
        }
    }
}
