use rama_core::error::OpaqueError;
use rama_http_types::Version;

use crate::tls::ApplicationProtocol;

impl TryFrom<Version> for ApplicationProtocol {
    type Error = OpaqueError;

    fn try_from(value: Version) -> Result<Self, Self::Error> {
        let version = match value {
            Version::HTTP_09 => ApplicationProtocol::HTTP_09,
            Version::HTTP_10 => ApplicationProtocol::HTTP_10,
            Version::HTTP_11 => ApplicationProtocol::HTTP_11,
            Version::HTTP_2 => ApplicationProtocol::HTTP_2,
            Version::HTTP_3 => ApplicationProtocol::HTTP_3,
            _ => Err(OpaqueError::from_display(
                "received unexpected http version",
            ))?,
        };
        Ok(version)
    }
}

impl TryFrom<ApplicationProtocol> for Version {
    type Error = OpaqueError;

    fn try_from(value: ApplicationProtocol) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&ApplicationProtocol> for Version {
    type Error = OpaqueError;

    fn try_from(value: &ApplicationProtocol) -> Result<Self, Self::Error> {
        let version = match value {
            ApplicationProtocol::HTTP_09 => Version::HTTP_09,
            ApplicationProtocol::HTTP_10 => Version::HTTP_10,
            ApplicationProtocol::HTTP_11 => Version::HTTP_11,
            ApplicationProtocol::HTTP_2 => Version::HTTP_2,
            ApplicationProtocol::HTTP_3 => Version::HTTP_3,
            alpn => Err(OpaqueError::from_display(format!(
                "cannot convert given alpn {alpn} to http version"
            )))?,
        };
        Ok(version)
    }
}
