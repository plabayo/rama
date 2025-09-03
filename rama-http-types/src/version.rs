//! HTTP version
//!
//! This module contains a definition of the `Version` type. The `Version`
//! type is intended to be accessed through the root of the crate
//! (`http::Version`) rather than this module.
//!
//! The `Version` type contains constants that represent the various versions
//! of the HTTP protocol.
//!
//! # Examples
//!
//! ```
//! use rama_http_types::Version;
//!
//! let http11 = Version::HTTP_11;
//! let http2 = Version::HTTP_2;
//! assert!(http11 != http2);
//!
//! println!("{:?}", http2);
//! ```

use std::fmt;

use crate::dep::http_upstream;

/// Represents a version of the HTTP spec.
#[derive(PartialEq, PartialOrd, Copy, Clone, Eq, Ord, Hash)]
pub struct Version(Http);

impl From<http_upstream::Version> for Version {
    fn from(value: http_upstream::Version) -> Self {
        match value {
            http_upstream::Version::HTTP_09 => Self::HTTP_09,
            http_upstream::Version::HTTP_10 => Self::HTTP_10,
            http_upstream::Version::HTTP_11 => Self::HTTP_11,
            http_upstream::Version::HTTP_2 => Self::HTTP_2,
            http_upstream::Version::HTTP_3 => Self::HTTP_3,
            _ => unreachable!("unreachable"),
        }
    }
}

impl From<Version> for http_upstream::Version {
    fn from(value: Version) -> Self {
        match value {
            Version::HTTP_09 => Self::HTTP_09,
            Version::HTTP_10 => Self::HTTP_10,
            Version::HTTP_11 => Self::HTTP_11,
            Version::HTTP_2 => Self::HTTP_2,
            Version::HTTP_3 => Self::HTTP_3,
            _ => unreachable!("unreachable"),
        }
    }
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
}

#[derive(PartialEq, PartialOrd, Copy, Clone, Eq, Ord, Hash)]
enum Http {
    Http09,
    Http10,
    Http11,
    H2,
    H3,
    __NonExhaustive,
}

impl Default for Version {
    #[inline]
    fn default() -> Self {
        Self::HTTP_11
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Http::{__NonExhaustive, H2, H3, Http09, Http10, Http11};

        f.write_str(match self.0 {
            Http09 => "HTTP/0.9",
            Http10 => "HTTP/1.0",
            Http11 => "HTTP/1.1",
            H2 => "HTTP/2.0",
            H3 => "HTTP/3.0",
            __NonExhaustive => unreachable!(),
        })
    }
}
