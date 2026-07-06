//! Error types for the [`crate::uri`] module.
//!
//! Two distinct enums:
//!
//! - [`ParseError`] — surfaced when bytes coming in cannot be turned into a
//!   valid [`Uri`](super::Uri). Carries enough information to point at *what*
//!   went wrong (offset, component) for diagnostics.
//! - [`UriError`] — surfaced when an operation on an already-parsed Uri
//!   cannot be applied (e.g. setting an invalid path).

use core::fmt;

use rama_core::error::BoxError;

/// Reasons parsing a byte string into a [`Uri`](super::Uri) can fail.
///
/// **Graceful by default**: the regular `Uri::parse` entry point accepts
/// inputs that browsers and curl tolerate. Only inputs in the
/// "differential-parse hazard" set (control chars, backslash-as-slash,
/// alternate IPv4 forms, etc.) are unconditionally rejected — and those are
/// the variants below that can fire even from `parse`.
///
/// `Uri::parse_strict` (lands in M3) additionally rejects everything outside
/// RFC 3986 with [`ParseError::StrictViolation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input was empty.
    Empty,

    /// A URI component is structurally invalid: bad delimiter placement,
    /// disallowed character, empty where forbidden, etc. The wrapped
    /// [`Component`] identifies which one. More specific failure modes
    /// (control chars, percent-encoding, etc.) have their own variants
    /// below.
    InvalidComponent(Component),

    /// A `\0`, `\r`, `\n`, `\t`, or other ASCII control character was found
    /// inside a URI component. Always rejected — these are header-injection
    /// and request-smuggling vectors.
    ControlCharInUri { at: usize, byte: u8 },

    /// A percent-encoded escape was malformed — `%` not followed by two hex
    /// digits, or (after decoding) the resulting byte is itself disallowed
    /// in the component where it appeared.
    InvalidPercentEncoding { at: usize },

    /// An IPv6 literal carried a zone identifier (`%25en0` on the wire).
    /// Not currently supported — see module-level docs for the path forward.
    IPv6ZoneNotSupported,

    /// Non-ASCII host bytes were supplied without the `idna` feature
    /// enabled. Only present when the `idna` feature is **off** — when it
    /// is on, non-ASCII hosts are processed and either succeed or surface
    /// as [`ParseError::InvalidComponent`] for [`Component::Host`].
    #[cfg(not(feature = "idna"))]
    #[cfg_attr(docsrs, doc(cfg(not(feature = "idna"))))]
    IdnaNotEnabled,

    /// Strict-mode-only rejection: input parsed under graceful rules but
    /// violates RFC 3986. Only produced by `Uri::parse_strict`.
    StrictViolation,

    /// The URI exceeded the maximum representable length.
    TooLong { len: usize },

    /// Input bytes were not valid UTF-8.
    ///
    /// Graceful mode tolerates raw UTF-8 in path / query / fragment
    /// (browsers and curl do too), but the bytes must still *be* valid
    /// UTF-8 — every component accessor returns `&str`, and the
    /// presence of a stray continuation byte or truncated multi-byte
    /// sequence would otherwise be UB at access time.
    ///
    /// Always rejected. Strict mode rejects more aggressively (per-byte
    /// ASCII grammar checks), but this is the floor.
    NonUtf8 { at: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("uri is empty"),
            Self::InvalidComponent(c) => write!(f, "invalid {c} component"),
            Self::ControlCharInUri { at, byte } => {
                write!(f, "control character 0x{byte:02X} at byte {at}")
            }
            Self::InvalidPercentEncoding { at } => {
                write!(f, "invalid percent-encoded escape at byte {at}")
            }
            Self::IPv6ZoneNotSupported => f.write_str(
                "IPv6 zone identifiers are not currently supported in uri host literals",
            ),
            #[cfg(not(feature = "idna"))]
            Self::IdnaNotEnabled => {
                f.write_str("non-ASCII host requires the `idna` feature to be enabled")
            }
            Self::StrictViolation => f.write_str("input does not satisfy RFC 3986 strict syntax"),
            Self::TooLong { len } => write!(f, "uri is {len} bytes long, exceeds the maximum"),
            Self::NonUtf8 { at } => {
                write!(f, "invalid UTF-8 byte sequence starting at byte {at}")
            }
        }
    }
}

impl core::error::Error for ParseError {}

/// Reasons an operation on an already-parsed [`Uri`](super::Uri) can fail.
///
/// Distinct from [`ParseError`] because mutation has different diagnostic
/// needs from parsing — when a setter fails, callers want to know which
/// component they were touching, even if the underlying cause didn't tag
/// it (e.g. a control-char rejection during `set_path` is more useful as
/// `InvalidComponent { component: Path, cause: ControlCharInUri }` than
/// as a bare `ControlCharInUri`).
#[derive(Debug)]
pub enum UriError {
    /// A setter received an input that fails component validation. The
    /// `cause` is the underlying parse-level failure.
    InvalidComponent {
        /// Which component the setter targeted.
        component: Component,
        /// Underlying parse-level cause.
        cause: ParseError,
    },

    /// A typed-input conversion into a URI component failed before the
    /// value reached the setter. The boxed cause is whatever the
    /// upstream `TryInto` impl returned — typically from
    /// [`Host::try_from`](crate::address::Host) or
    /// [`Domain::try_from`](crate::address::Domain) for inputs like raw
    /// UTF-8 hosts when the `idna` feature is disabled.
    ///
    /// Distinct from [`UriError::InvalidComponent`] because the failure
    /// originates outside the URI parser, so the cause cannot always be
    /// expressed as a [`ParseError`].
    ComponentConversion {
        /// Which component the setter targeted.
        component: Component,
        /// Underlying conversion cause (boxed because typed input
        /// converters live across crate boundaries).
        cause: BoxError,
    },

    /// An operation was attempted that is meaningless for the asterisk-form
    /// URI (e.g. iterating path segments of `*`). Most setters auto-upgrade
    /// asterisk to a reference; the few that cannot return this error.
    AsteriskOperation,
}

/// Which URI component a [`ParseError`] or [`UriError`] refers to.
///
/// `Authority` is the umbrella for `UserInfo` + `Host` + `Port`; a parse
/// failure *inside* a sub-component is reported against the sub-component,
/// not against `Authority` itself. The variant still surfaces for
/// structural failures that aren't attributable to one sub-component
/// — e.g. IP-literal bracket mismatches in `parser::authority`, and
/// path / query / fragment delimiters appearing in a CONNECT
/// authority-form input (`parse_authority_form`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    Scheme,
    Authority,
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
            Self::Authority => "authority",
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
            Self::ComponentConversion { component, cause } => {
                write!(f, "{component} component conversion failed: {cause}")
            }
            Self::AsteriskOperation => {
                f.write_str("operation is not valid on the asterisk-form uri")
            }
        }
    }
}

impl core::error::Error for UriError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InvalidComponent { cause, .. } => Some(cause),
            Self::ComponentConversion { cause, .. } => Some(cause.as_ref()),
            Self::AsteriskOperation => None,
        }
    }
}
