//! HTTP protocol version, owned by rama-net as a protocol primitive.
//!
//! Mirrors the shape of the `http` crate's `Version` (opaque, with the
//! standard `HTTP_09..HTTP_3` constants) so it is a drop-in replacement for
//! `rama_http_types::Version`, which re-exports this type.

use std::{error::Error, fmt};

use rama_macros::Extension;

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

    fn as_str(self) -> &'static str {
        match self.0 {
            Http::Http09 => "HTTP/0.9",
            Http::Http10 => "HTTP/1.0",
            Http::Http11 => "HTTP/1.1",
            Http::H2 => "HTTP/2.0",
            Http::H3 => "HTTP/3.0",
        }
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

// `ApplicationProtocol` (ALPN) <-> `Version` conversions live in `rama-tls`
// (which depends on both this crate and the TLS enum vocabulary).
