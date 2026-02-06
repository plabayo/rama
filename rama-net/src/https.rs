use rama_core::error::{BoxError, ErrorExt};
use rama_http_types::Version;

use crate::tls::ApplicationProtocol;

impl TryFrom<Version> for ApplicationProtocol {
    type Error = BoxError;

    fn try_from(value: Version) -> Result<Self, Self::Error> {
        let version = match value {
            Version::HTTP_09 => Self::HTTP_09,
            Version::HTTP_10 => Self::HTTP_10,
            Version::HTTP_11 => Self::HTTP_11,
            Version::HTTP_2 => Self::HTTP_2,
            Version::HTTP_3 => Self::HTTP_3,
            _ => Err(BoxError::from("received unexpected http version"))?,
        };
        Ok(version)
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
        let version = match value {
            ApplicationProtocol::HTTP_09 => Self::HTTP_09,
            ApplicationProtocol::HTTP_10 => Self::HTTP_10,
            ApplicationProtocol::HTTP_11 => Self::HTTP_11,
            ApplicationProtocol::HTTP_2 => Self::HTTP_2,
            ApplicationProtocol::HTTP_3 => Self::HTTP_3,
            alpn => Err(
                BoxError::from("cannot convert given alpn {alpn} to http version")
                    .context_field("alpn", alpn.clone()),
            )?,
        };
        Ok(version)
    }
}
