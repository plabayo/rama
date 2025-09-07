#[cfg(feature = "http")]
use rama_http_types::Version;

#[derive(Debug, PartialEq, PartialOrd, Copy, Clone, Eq, Ord, Hash)]
/// Version of the forwarded protocol.
pub struct ForwardedVersion(VersionKind);

#[derive(Debug, PartialEq, PartialOrd, Copy, Clone, Eq, Ord, Hash)]
enum VersionKind {
    Http09,
    Http10,
    Http11,
    H2,
    H3,
}

impl ForwardedVersion {
    /// `HTTP/0.9`
    pub const HTTP_09: Self = Self(VersionKind::Http09);

    /// `HTTP/1.0`
    pub const HTTP_10: Self = Self(VersionKind::Http10);

    /// `HTTP/1.1`
    pub const HTTP_11: Self = Self(VersionKind::Http11);

    /// `HTTP/2.0`
    pub const HTTP_2: Self = Self(VersionKind::H2);

    /// `HTTP/3.0`
    pub const HTTP_3: Self = Self(VersionKind::H3);
}

#[cfg(feature = "http")]
impl ForwardedVersion {
    /// Returns this [`ForwardedVersion`] as a [`Version`] if it is defined as http.
    #[must_use]
    pub fn as_http(&self) -> Option<Version> {
        Some(match self.0 {
            VersionKind::Http09 => Version::HTTP_09,
            VersionKind::Http10 => Version::HTTP_10,
            VersionKind::Http11 => Version::HTTP_11,
            VersionKind::H2 => Version::HTTP_2,
            VersionKind::H3 => Version::HTTP_3,
        })
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "invalid forwarded version"]
    pub struct InvalidForwardedVersion;
}

impl TryFrom<&str> for ForwardedVersion {
    type Error = InvalidForwardedVersion;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.as_bytes().try_into()
    }
}

impl TryFrom<String> for ForwardedVersion {
    type Error = InvalidForwardedVersion;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_bytes().try_into()
    }
}

impl TryFrom<Vec<u8>> for ForwardedVersion {
    type Error = InvalidForwardedVersion;

    #[inline]
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&[u8]> for ForwardedVersion {
    type Error = InvalidForwardedVersion;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(match bytes {
            b"0.9" => VersionKind::Http09,
            b"1" | b"1.0" => VersionKind::Http10,
            b"1.1" => VersionKind::Http11,
            b"2" | b"2.0" => VersionKind::H2,
            b"3" | b"3.0" => VersionKind::H3,
            _ => return Err(InvalidForwardedVersion),
        }))
    }
}

impl std::fmt::Display for ForwardedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            VersionKind::Http09 => f.write_str("0.9"),
            VersionKind::Http10 => f.write_str("1.0"),
            VersionKind::Http11 => f.write_str("1.1"),
            VersionKind::H2 => f.write_str("2"),
            VersionKind::H3 => f.write_str("3"),
        }
    }
}
