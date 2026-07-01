//! autonomous system number (ASN)
//!
//! See [`Asn`] and its methods for more information.

use core::fmt;

use crate::std::string::String;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// autonomous system number (ASN).
///
/// Within Rama this has little use as we do facilitate or drive BGP routing.
/// It is however defined to allow interaction with services that do interact
/// with this layer, such as proxy gateway services, especially one
/// of residential type.
///
/// Only assignable ASNs are representable; see [`LossyAsn`] when you need to
/// preserve a raw `u32` that may fall outside the assignable ranges (e.g. as
/// found in third-party geolocation data).
pub struct Asn(AsnData);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AsnData {
    Unspecified,
    Specified(u32),
}

impl Asn {
    /// Create a valid ASN from a static number, validated at compile time.
    #[must_use]
    #[expect(
        clippy::panic,
        reason = "static-value invariant: panic at compile time when ASN constant is out of range"
    )]
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

// Assignable ASN ranges only, excluding the reserved/documentation/private-use
// blocks: 23456 (AS_TRANS), the 64496..=131071 gap (16-bit private + docs), the
// 32-bit private-use block 4200000000..=4294967294 (RFC 6996), and 4294967295.
const fn is_valid_asn_range(value: u32) -> bool {
    (value >= 1 && value <= 23455)
        || (value >= 23457 && value <= 64495)
        || (value >= 131072 && value <= 4199999999)
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
        let value: u32 = value.parse().map_err(|_e| InvalidAsn)?;
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
        core::str::from_utf8(value)
            .map_err(|_e| InvalidAsn)?
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
#[cfg_attr(docsrs, doc(cfg(feature = "venndb")))]
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
            .map_err(|_e| serde::de::Error::custom("invalid asn"))
    }
}

/// An autonomous system number that may fall outside the assignable ranges.
///
/// Unlike [`Asn`], this preserves any `u32` verbatim — including reserved,
/// documentation, or special values such as `AS_TRANS` (`23456`) and
/// `4294967295` that legitimately appear in third-party data sets (e.g.
/// geolocation ASN databases). It is a [`Copy`] type, so it can be returned
/// from borrowing views as easily as from owned ones.
///
/// Convert to a strict [`Asn`] with [`Asn::try_from`] (or [`Self::to_asn`])
/// when you need the validated form.
///
/// Ordering is by the underlying ASN number (not the internal variant), so a
/// reserved value like `AS_TRANS` (`23456`) sorts after `15169`, not before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LossyAsn(LossyAsnData);

impl Ord for LossyAsn {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // a LossyAsn is only constructible via From, where as_u32 uniquely
        // determines the value — so this stays consistent with Eq
        self.as_u32().cmp(&other.as_u32())
    }
}

impl PartialOrd for LossyAsn {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LossyAsnData {
    /// A `u32` that is not a valid assignable ASN.
    Invalid(u32),
    /// A value that maps onto a valid [`Asn`].
    Valid(AsnData),
}

impl LossyAsn {
    /// Return the underlying value as a `u32` (`0` for an unspecified ASN).
    #[must_use]
    pub fn as_u32(self) -> u32 {
        match self.0 {
            LossyAsnData::Invalid(n) | LossyAsnData::Valid(AsnData::Specified(n)) => n,
            LossyAsnData::Valid(AsnData::Unspecified) => 0,
        }
    }

    /// Returns `true` if this value maps onto a valid assignable [`Asn`].
    #[must_use]
    pub fn is_valid(self) -> bool {
        matches!(self.0, LossyAsnData::Valid(_))
    }

    /// Returns `true` if this is the unspecified ("any") ASN.
    #[must_use]
    pub fn is_any(self) -> bool {
        matches!(self.0, LossyAsnData::Valid(AsnData::Unspecified))
    }

    /// Convert into a strict [`Asn`], or `None` if the value is not assignable.
    #[must_use]
    pub fn to_asn(self) -> Option<Asn> {
        match self.0 {
            LossyAsnData::Valid(data) => Some(Asn(data)),
            LossyAsnData::Invalid(_) => None,
        }
    }
}

impl From<u32> for LossyAsn {
    fn from(value: u32) -> Self {
        match Asn::try_from(value) {
            Ok(asn) => Self(LossyAsnData::Valid(asn.0)),
            Err(_) => Self(LossyAsnData::Invalid(value)),
        }
    }
}

impl From<Asn> for LossyAsn {
    fn from(asn: Asn) -> Self {
        Self(LossyAsnData::Valid(asn.0))
    }
}

impl TryFrom<LossyAsn> for Asn {
    type Error = InvalidAsn;

    fn try_from(value: LossyAsn) -> Result<Self, Self::Error> {
        value.to_asn().ok_or(InvalidAsn)
    }
}

impl fmt::Display for LossyAsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            LossyAsnData::Valid(data) => Asn(data).fmt(f),
            LossyAsnData::Invalid(n) => write!(f, "AS{n}"),
        }
    }
}

impl Serialize for LossyAsn {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_u32().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LossyAsn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self::from(u32::deserialize(deserializer)?))
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "invalid ASN (e.g. within reserved space)"]
    pub struct InvalidAsn;
}

#[cfg(test)]
mod lossy_asn_tests {
    use super::*;

    #[test]
    fn valid_asn_roundtrips() {
        let a = LossyAsn::from(15169);
        assert!(a.is_valid());
        assert!(!a.is_any());
        assert_eq!(a.as_u32(), 15169);
        assert_eq!(a.to_asn(), Some(Asn::from_static(15169)));
    }

    #[test]
    fn out_of_range_is_preserved_but_invalid() {
        // AS_TRANS and the all-ones value are not assignable but must survive.
        for n in [23456u32, 4_294_967_295] {
            let a = LossyAsn::from(n);
            assert!(!a.is_valid(), "{n} should be invalid");
            assert_eq!(a.as_u32(), n);
            assert_eq!(a.to_asn(), None);
            assert_eq!(Asn::try_from(a), Err(InvalidAsn));
        }
    }

    #[test]
    fn zero_is_unspecified() {
        let a = LossyAsn::from(0);
        assert!(a.is_valid());
        assert!(a.is_any());
        assert_eq!(a.as_u32(), 0);
    }

    #[test]
    fn serde_is_a_bare_u32() {
        let a = LossyAsn::from(23456);
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "23456");
        let back: LossyAsn = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn lossy_asn_orders_by_number_not_variant() {
        // 23456 is reserved (Invalid), 15169 is valid — numeric order must win
        assert!(LossyAsn::from(15169) < LossyAsn::from(23456));
        let mut v = [
            LossyAsn::from(23456),
            LossyAsn::from(15169),
            LossyAsn::from(0),
        ];
        v.sort();
        assert_eq!(v.map(|a| a.as_u32()), [0, 15169, 23456]);
    }

    #[test]
    fn thirty_two_bit_private_use_is_not_assignable() {
        // RFC 6996 32-bit private-use: preserved by LossyAsn, rejected by Asn
        let private = LossyAsn::from(4_200_000_000);
        assert!(!private.is_valid());
        assert_eq!(private.as_u32(), 4_200_000_000);
        assert_eq!(Asn::try_from(4_200_000_000u32), Err(InvalidAsn));
        // the value just below the private block stays assignable
        Asn::try_from(4_199_999_999u32).unwrap();
    }
}
