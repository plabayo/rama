use crate::util::HeaderValueString;
use rama_http_types::header::HeaderValue;
use std::sync::OnceLock;

/// Rama's built-in HTTP product identifier.
const RAMA_ID: &str =
    const_format::formatcp!("{}/{}", rama_utils::info::NAME, rama_utils::info::VERSION);

static IDENTITY: OnceLock<HeaderValueString> = OnceLock::new();
static RAMA: HeaderValueString = HeaderValueString::from_static(RAMA_ID);

/// The application's HTTP identity as a string. Defaults to `rama/<version>`.
pub fn identity() -> &'static str {
    identity_header_str().as_str()
}

/// The application's HTTP identity as a header value sharing the static string's bytes.
pub fn identity_header() -> &'static HeaderValue {
    identity_header_str().as_ref()
}

/// The application's typed HTTP identity. Reading the fallback leaves [`set_identity`] available.
pub fn identity_header_str() -> &'static HeaderValueString {
    IDENTITY.get().unwrap_or(&RAMA)
}

/// The application identity could not be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetIdentityError {
    /// The supplied identity cannot be represented as an HTTP header value.
    InvalidValue,
    /// An application identity has already been installed.
    AlreadySet,
}

impl std::fmt::Display for SetIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidValue => "invalid HTTP identity",
            Self::AlreadySet => "HTTP identity already set",
        })
    }
}

impl std::error::Error for SetIdentityError {}

/// Set the default `Server` and `User-Agent` for this process.
/// Applications can install one static string at startup. Its bytes are shared without copying.
/// Explicit header and layer settings take precedence.
pub fn set_identity(value: &'static str) -> Result<(), SetIdentityError> {
    let value = HeaderValueString::try_from_static(value)
        .map_err(|_invalid| SetIdentityError::InvalidValue)?;
    IDENTITY
        .set(value)
        .map_err(|_value| SetIdentityError::AlreadySet)
}
