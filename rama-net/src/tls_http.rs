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
            _ => Err(OpaqueError::from_display("not supported"))?,
        };
        Ok(version)
    }
}
