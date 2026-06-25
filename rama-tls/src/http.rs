//! HTTP ⇄ TLS glue.
//!
//! `ApplicationProtocol` (ALPN) ⇄ http `Version` conversions, which need both
//! the TLS enum vocabulary (this crate) and the http `Version` (`rama-net`).

use crate::ApplicationProtocol;
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorExt as _};
use rama_net::http::Version;

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
                    BoxError::from_static_str("cannot convert given alpn to http version")
                        .context_field("alpn", alpn.clone()),
                );
            }
        })
    }
}
