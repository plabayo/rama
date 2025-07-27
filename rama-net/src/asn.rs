//! autonomous system number (ASN)
//!
//! See [`Asn`] and its methods for more information.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// autonomous system number (ASN).
///
/// Within Rama this has little use as we do facilitate or drive BGP routing.
/// It is however defined to allow interaction with services that do interact
/// with this layer, such as proxy gateway services, especially one
/// of residential type.
pub struct Asn(AsnData);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AsnData {
    Unspecified,
    Specified(u32),
}

impl Asn {
    /// Create a valid ASN from a static number, validated at compile time.
    #[must_use]
    pub const fn from_static(value: u32) -> Self {
        if value == 0 {
            return Self(AsnData::Unspecified);
        }
        if !is_valid_asn_range(value) {
            panic!("invalid ASN range")
        }
        Self(AsnData::Specified(value))
    }
    /// Internally makes use of a value that's invalid within ASN,
    /// but that be used to identify an AS with an unspecified number,
    /// or a router that can route to the AS of a given ASN.
    #[must_use]
    pub fn unspecified() -> Self {
        Self(AsnData::Unspecified)
    }

    /// Return [`Asn`] as u32
    #[must_use]
    pub fn as_u32(&self) -> u32 {
        match self.0 {
            AsnData::Specified(n) => n,
            AsnData::Unspecified => 0,
        }
    }

    /// Returns `true` if this value is considered to be "any" value.
    #[must_use]
    pub fn is_any(&self) -> bool {
        self.0 == AsnData::Unspecified
    }
}

const fn is_valid_asn_range(value: u32) -> bool {
    (value >= 1 && value <= 23455)
        || (value >= 23457 && value <= 64495)
        || (value >= 131072 && value <= 4294967294)
}

impl TryFrom<u32> for Asn {
    type Error = InvalidAsn;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 0 {
            return Ok(Self(AsnData::Unspecified));
        }
        is_valid_asn_range(value)
            .then_some(Self(AsnData::Specified(value)))
            .ok_or(InvalidAsn)
    }
}

impl TryFrom<&str> for Asn {
    type Error = InvalidAsn;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value: u32 = value.parse().map_err(|_| InvalidAsn)?;
        value.try_into()
    }
}

impl TryFrom<String> for Asn {
    type Error = InvalidAsn;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&String> for Asn {
    type Error = InvalidAsn;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&[u8]> for Asn {
    type Error = InvalidAsn;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(value)
            .map_err(|_| InvalidAsn)?
            .try_into()
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            AsnData::Specified(n) => write!(f, "AS{n}"),
            AsnData::Unspecified => write!(f, "unspecified"),
        }
    }
}

#[cfg(feature = "venndb")]
impl venndb::Any for Asn {
    fn is_any(&self) -> bool {
        Self::is_any(self)
    }
}

impl Serialize for Asn {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.0 {
            AsnData::Unspecified => 0u32.serialize(serializer),
            AsnData::Specified(u) => u.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Asn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        value
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid asn"))
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "invalid ASN (e.g. within reserved space)"]
    pub struct InvalidAsn;
}
