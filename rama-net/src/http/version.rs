//! HTTP protocol version, owned by rama-net as a protocol primitive.
//!
//! Mirrors the shape of the `http` crate's `Version` (opaque, with the
//! standard `HTTP_09..HTTP_3` constants) so it is a drop-in replacement for
//! `rama_http_types::Version`, which re-exports this type.

use std::{error::Error, fmt};

use rama_core::error::{BoxError, BoxErrorExt as _, ErrorExt as _};
use rama_macros::Extension;

use crate::tls::ApplicationProtocol;

/// Represents a version of the HTTP spec.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct Version(Http);

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Extension)]
#[extension(tags(http))]
/// Target http version
///
/// This can be set manually to enforce a specific version,
/// otherwise this will be set automatically by things such
/// tls alpn
pub struct TargetHttpVersion(pub Version);

/// HTTP version to use only when connection negotiation does not select one.
///
/// Unlike [`TargetHttpVersion`], this is not an egress requirement and must not
/// constrain TLS ALPN. It becomes the target only after the transport has been
/// established without negotiating an HTTP version.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Extension)]
#[extension(tags(http))]
pub struct FallbackHttpVersion(pub Version);

/// HTTP version carried by the request that initiated a connection attempt.
///
/// This is descriptive input context, not an egress requirement. Connectors
/// must not use it to constrain protocol negotiation as they would a
/// [`TargetHttpVersion`].
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Extension)]
#[extension(tags(http))]
pub struct HttpRequestVersion(pub Version);

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Debug)]
enum Http {
    Http09,
    Http10,
    Http11,
    H2,
    H3,
}

impl Version {
    /// `HTTP/0.9`
    pub const HTTP_09: Self = Self(Http::Http09);

    /// `HTTP/1.0`
    pub const HTTP_10: Self = Self(Http::Http10);

    /// `HTTP/1.1`
    pub const HTTP_11: Self = Self(Http::Http11);

    /// `HTTP/2.0`
    pub const HTTP_2: Self = Self(Http::H2);

    /// `HTTP/3.0`
    pub const HTTP_3: Self = Self(Http::H3);

    /// The canonical `HTTP/x.y` text for this version.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self.0 {
            Http::Http09 => "HTTP/0.9",
            Http::Http10 => "HTTP/1.0",
            Http::Http11 => "HTTP/1.1",
            Http::H2 => "HTTP/2.0",
            Http::H3 => "HTTP/3.0",
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Version {
    type Err = InvalidVersion;

    /// Parse from the canonical `HTTP/x.y` text or any of its
    /// common aliases (`1.1`, `2`, `HTTP/2`, ...).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "HTTP/0.9" | "0.9" => Self::HTTP_09,
            "HTTP/1.0" | "1.0" => Self::HTTP_10,
            "HTTP/1.1" | "1.1" => Self::HTTP_11,
            "HTTP/2" | "HTTP/2.0" | "2" | "2.0" => Self::HTTP_2,
            "HTTP/3" | "HTTP/3.0" | "3" | "3.0" => Self::HTTP_3,
            _ => return Err(InvalidVersion::new()),
        })
    }
}

impl Default for Version {
    #[inline]
    fn default() -> Self {
        Self::HTTP_11
    }
}

impl core::fmt::Debug for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A possible error value when converting `Version` from bytes
/// or a related type.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct InvalidVersion;

impl InvalidVersion {
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }
}

impl fmt::Display for InvalidVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid HTTP version")
    }
}

impl Error for InvalidVersion {}

use rama_utils::macros::serde_str::impl_serde_str;

impl_serde_str!(as_str Version);

impl TryFrom<Version> for ApplicationProtocol {
    type Error = BoxError;

    fn try_from(value: Version) -> Result<Self, Self::Error> {
        Ok(match value {
            Version::HTTP_09 => Self::HTTP_09,
            Version::HTTP_10 => Self::HTTP_10,
            Version::HTTP_11 => Self::HTTP_11,
            Version::HTTP_2 => Self::HTTP_2,
            Version::HTTP_3 => Self::HTTP_3,
        })
    }
}

impl TryFrom<ApplicationProtocol> for Version {
    type Error = BoxError;

    fn try_from(value: ApplicationProtocol) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&ApplicationProtocol> for Version {
    type Error = BoxError;

    fn try_from(value: &ApplicationProtocol) -> Result<Self, Self::Error> {
        Ok(match value {
            ApplicationProtocol::HTTP_09 => Self::HTTP_09,
            ApplicationProtocol::HTTP_10 => Self::HTTP_10,
            ApplicationProtocol::HTTP_11 => Self::HTTP_11,
            ApplicationProtocol::HTTP_2 => Self::HTTP_2,
            ApplicationProtocol::HTTP_3 => Self::HTTP_3,
            alpn => {
                return Err(
                    BoxError::from_static_str("cannot convert given ALPN to HTTP version")
                        .context_field("alpn", alpn.clone()),
                );
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_versions_and_application_protocols_round_trip() {
        for (version, protocol) in [
            (Version::HTTP_09, ApplicationProtocol::HTTP_09),
            (Version::HTTP_10, ApplicationProtocol::HTTP_10),
            (Version::HTTP_11, ApplicationProtocol::HTTP_11),
            (Version::HTTP_2, ApplicationProtocol::HTTP_2),
            (Version::HTTP_3, ApplicationProtocol::HTTP_3),
        ] {
            assert_eq!(ApplicationProtocol::try_from(version).unwrap(), protocol);
            assert_eq!(Version::try_from(&protocol).unwrap(), version);
            assert_eq!(Version::try_from(protocol).unwrap(), version);
        }
    }

    #[test]
    fn non_http_application_protocol_is_not_an_http_version() {
        Version::try_from(ApplicationProtocol::DNS_OVER_TLS).unwrap_err();
        Version::try_from(ApplicationProtocol::from(b"h3-29")).unwrap_err();
    }
}
