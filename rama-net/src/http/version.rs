//! HTTP protocol version, owned by rama-net as a protocol primitive.
//!
//! Mirrors the shape of the `http` crate's `Version` (opaque, with the
//! standard `HTTP_09..HTTP_3` constants) so it is a drop-in replacement for
//! `rama_http_types::Version`, which re-exports this type.

/// Represents a version of the HTTP spec.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct Version(Http);

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

impl std::fmt::Debug for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// `ApplicationProtocol` (ALPN) <-> `Version`, only meaningful when both the
// `tls` (ApplicationProtocol) and `http` (this module) features are enabled.
#[cfg(feature = "tls")]
mod alpn {
    use super::Version;
    use crate::tls::ApplicationProtocol;
    use rama_core::error::{BoxError, BoxErrorExt as _, ErrorExt as _};

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
                    return Err(BoxError::from_static_str(
                        "cannot convert given alpn to http version",
                    )
                    .context_field("alpn", alpn.clone()));
                }
            })
        }
    }
}
