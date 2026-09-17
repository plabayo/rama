//! QUIC protocol versions and the wire constants that differ between them.
//!
//! RFC 8999 fixes what every version shares; RFC 9000/9001 define version 1 and RFC 9369
//! defines version 2 as version 1 with different long-header type bits, Initial salt, HKDF
//! labels and Retry integrity key. Everything here is a pure function of the version number.

use std::fmt;

use rama_core::bytes::{Buf, BufMut};
use serde::{Deserialize, Serialize};

use crate::proto::coding::{self, Codec};

/// A QUIC version number as it appears in long headers (RFC 8999 §5).
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Version(u32);

impl Version {
    /// QUIC version 1 (RFC 9000).
    pub const V1: Self = Self(0x0000_0001);
    /// QUIC version 2 (RFC 9369).
    pub const V2: Self = Self(0x6b33_43cf);

    /// A version from its 32-bit wire value.
    #[must_use]
    pub const fn from_u32(version: u32) -> Self {
        Self(version)
    }

    /// The 32-bit wire value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// The version in network byte order.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// A version from network byte order.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    /// Zero, which marks a Version Negotiation packet rather than a version (RFC 8999 §6).
    #[must_use]
    pub const fn is_negotiation(self) -> bool {
        self.0 == 0
    }

    /// Whether this is one of the `0x?a?a?a?a` versions reserved to exercise version
    /// negotiation (RFC 9000 §15). Such a version is never selected.
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        self.0 & 0x0f0f_0f0f == 0x0a0a_0a0a
    }

    /// Whether this is a standardized version this crate implements.
    #[must_use]
    pub const fn is_standard(self) -> bool {
        matches!(self, Self::V1 | Self::V2)
    }

    /// Whether a first flight in this version can be converted into one of `other`
    /// (RFC 9368 §2.2). Version 1 and version 2 are compatible in both directions
    /// (RFC 9369 §4); a version is always compatible with itself.
    #[must_use]
    pub const fn is_compatible_with(self, other: Self) -> bool {
        self.0 == other.0 || matches!((self, other), (Self::V1, Self::V2) | (Self::V2, Self::V1))
    }

    /// A reserved version to grease a version list with, distinct from `avoid`.
    pub(crate) const fn grease(avoid: Self) -> Self {
        const FIRST: Version = Version(0x0a1a_2a3a);
        const SECOND: Version = Version(0x0a1a_2a4a);
        if avoid.0 == FIRST.0 { SECOND } else { FIRST }
    }

    /// The version-specific wire constants, when this crate implements the version.
    pub(crate) const fn wire(self) -> Option<&'static Wire> {
        match self.0 {
            0x0000_0001 | 0xff00_0021..=0xff00_0022 => Some(&V1_WIRE),
            0xff00_001d..=0xff00_0020 => Some(&DRAFT29_WIRE),
            0x6b33_43cf => Some(&V2_WIRE),
            _ => None,
        }
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V1 => f.write_str("Version::V1"),
            Self::V2 => f.write_str("Version::V2"),
            Self(other) => write!(f, "Version({other:#010x})"),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V1 => f.write_str("QUICv1"),
            Self::V2 => f.write_str("QUICv2"),
            Self(other) => write!(f, "{other:#010x}"),
        }
    }
}

impl From<Version> for u32 {
    fn from(version: Version) -> Self {
        version.0
    }
}

impl From<u32> for Version {
    fn from(version: u32) -> Self {
        Self(version)
    }
}

impl Codec for Version {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        u32::decode(buf).map(Self)
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.0.encode(buf)
    }
}

/// The HKDF-Expand-Label labels a version uses to derive packet protection material
/// (RFC 9001 §5.1, §5.4, §6.1; RFC 9369 §3.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Labels {
    pub(crate) key: &'static [u8],
    pub(crate) iv: &'static [u8],
    pub(crate) hp: &'static [u8],
    pub(crate) ku: &'static [u8],
}

/// Long header packet kinds, before the version decides how their type bits look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LongKind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

/// Everything about a version's wire image that is not shared by all versions.
#[derive(Debug)]
pub(crate) struct Wire {
    /// Salt for the Initial secret (RFC 9001 §5.2, RFC 9369 §3.3.1).
    #[cfg_attr(
        not(feature = "boring"),
        expect(
            dead_code,
            reason = "rustls derives Initial keys from its own salt table"
        )
    )]
    pub(crate) initial_salt: [u8; 20],
    #[cfg_attr(
        not(feature = "boring"),
        expect(dead_code, reason = "rustls derives packet keys with its own labels")
    )]
    pub(crate) labels: Labels,
    /// Retry Integrity Tag key and nonce (RFC 9001 §5.8, RFC 9369 §3.3.3).
    #[cfg_attr(
        not(any(
            feature = "boring",
            all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
        )),
        expect(dead_code, reason = "only a TLS backend computes Retry tags")
    )]
    pub(crate) retry_key: [u8; 16],
    #[cfg_attr(
        not(any(
            feature = "boring",
            all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
        )),
        expect(dead_code, reason = "only a TLS backend computes Retry tags")
    )]
    pub(crate) retry_nonce: [u8; 12],
    /// Long header type bits for Initial, 0-RTT, Handshake and Retry in that order
    /// (RFC 9000 §17.2, RFC 9369 §3.2).
    long_types: [u8; 4],
}

impl Wire {
    /// The two type bits (already shifted into place) for a long header kind.
    pub(crate) const fn long_type_bits(&self, kind: LongKind) -> u8 {
        self.long_types[kind as usize] << 4
    }

    /// The long header kind the two type bits name.
    pub(crate) fn long_kind(&self, first_byte: u8) -> LongKind {
        let bits = (first_byte & 0x30) >> 4;
        const KINDS: [LongKind; 4] = [
            LongKind::Initial,
            LongKind::ZeroRtt,
            LongKind::Handshake,
            LongKind::Retry,
        ];
        #[expect(
            clippy::unwrap_used,
            reason = "`long_types` is a permutation of 0..4, so exactly one entry matches"
        )]
        KINDS
            .into_iter()
            .find(|kind| self.long_types[*kind as usize] == bits)
            .unwrap()
    }
}

const V1_LABELS: Labels = Labels {
    key: b"quic key",
    iv: b"quic iv",
    hp: b"quic hp",
    ku: b"quic ku",
};

pub(crate) static V1_WIRE: Wire = Wire {
    initial_salt: [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ],
    labels: V1_LABELS,
    retry_key: [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ],
    retry_nonce: [
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
    ],
    long_types: [0b00, 0b01, 0b10, 0b11],
};

static DRAFT29_WIRE: Wire = Wire {
    initial_salt: [
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11,
        0xe0, 0x43, 0x90, 0xa8, 0x99,
    ],
    labels: V1_LABELS,
    retry_key: [
        0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b,
        0xe1,
    ],
    retry_nonce: [
        0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
    ],
    long_types: [0b00, 0b01, 0b10, 0b11],
};

pub(crate) static V2_WIRE: Wire = Wire {
    initial_salt: [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
        0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ],
    labels: Labels {
        key: b"quicv2 key",
        iv: b"quicv2 iv",
        hp: b"quicv2 hp",
        ku: b"quicv2 ku",
    },
    retry_key: [
        0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc,
        0x92,
    ],
    retry_nonce: [
        0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
    ],
    long_types: [0b01, 0b10, 0b11, 0b00],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_versions_follow_the_greasing_pattern() {
        assert!(Version::from_u32(0x0a1a_2a3a).is_reserved());
        assert!(Version::from_u32(0xfafa_fafa).is_reserved());
        assert!(!Version::V1.is_reserved());
        assert!(!Version::V2.is_reserved());
        assert!(!Version::from_u32(0x0a1a_2a3b).is_reserved());
        assert_ne!(
            Version::grease(Version::grease(Version::V1)),
            Version::grease(Version::V1)
        );
    }

    #[test]
    fn only_v1_and_v2_are_compatible() {
        assert!(Version::V1.is_compatible_with(Version::V2));
        assert!(Version::V2.is_compatible_with(Version::V1));
        assert!(Version::V1.is_compatible_with(Version::V1));
        let draft = Version::from_u32(0xff00_001d);
        assert!(!Version::V1.is_compatible_with(draft));
        assert!(!draft.is_compatible_with(Version::V2));
    }

    #[test]
    fn v2_type_bits_are_a_permutation_of_v1() {
        let v1 = Version::V1.wire().unwrap();
        let v2 = Version::V2.wire().unwrap();
        for kind in [
            LongKind::Initial,
            LongKind::ZeroRtt,
            LongKind::Handshake,
            LongKind::Retry,
        ] {
            assert_eq!(v1.long_kind(0x80 | v1.long_type_bits(kind)), kind);
            assert_eq!(v2.long_kind(0x80 | v2.long_type_bits(kind)), kind);
        }
        // RFC 9369 §3.2
        assert_eq!(v2.long_type_bits(LongKind::Initial), 0b01 << 4);
        assert_eq!(v2.long_type_bits(LongKind::ZeroRtt), 0b10 << 4);
        assert_eq!(v2.long_type_bits(LongKind::Handshake), 0b11 << 4);
        assert_eq!(v2.long_type_bits(LongKind::Retry), 0b00 << 4);
    }

    #[test]
    fn unknown_versions_have_no_wire_image() {
        assert!(Version::from_u32(0x0a1a_2a3a).wire().is_none());
        assert!(Version::from_u32(0).wire().is_none());
        assert!(Version::from_u32(0xff00_001c).wire().is_none());
        assert!(Version::from_u32(0xff00_0022).wire().is_some());
    }

    #[test]
    fn display_names_standard_versions() {
        assert_eq!(Version::V1.to_string(), "QUICv1");
        assert_eq!(Version::V2.to_string(), "QUICv2");
        assert_eq!(Version::from_u32(0x0a1a_2a3a).to_string(), "0x0a1a2a3a");
        assert_eq!(format!("{:?}", Version::from_u32(7)), "Version(0x00000007)");
    }
}

/// The `version_information` transport parameter (RFC 9368 §3): the version an endpoint chose
/// and the versions it can work with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInformation {
    chosen: Version,
    available: Vec<Version>,
}

impl VersionInformation {
    pub(crate) fn new(chosen: Version, available: Vec<Version>) -> Self {
        Self { chosen, available }
    }

    /// The version the sender uses for this connection.
    #[must_use]
    pub fn chosen(&self) -> Version {
        self.chosen
    }

    /// From a client, the versions its first flight is compatible with, most preferred first;
    /// from a server, the versions every instance of its deployment speaks.
    #[must_use]
    pub fn available(&self) -> &[Version] {
        &self.available
    }

    /// The wire size of the value: four bytes per version.
    pub(crate) fn wire_size(&self) -> usize {
        4 * (1 + self.available.len())
    }

    pub(crate) fn write<W: BufMut>(&self, w: &mut W) {
        self.chosen.encode(w);
        for version in &self.available {
            version.encode(w);
        }
    }

    /// Parse a value of `len` bytes. RFC 9368 §4 makes a short or misaligned value, a zero
    /// version, or (for a server) a chosen version missing from the list a parsing failure.
    pub(crate) fn read<B: Buf>(
        receiver_is_server: bool,
        len: usize,
        r: &mut B,
    ) -> Result<Self, VersionInformationError> {
        if len < 4 || !len.is_multiple_of(4) || r.remaining() < len {
            return Err(VersionInformationError);
        }
        let chosen = Version::decode(r).map_err(|_error| VersionInformationError)?;
        if chosen.is_negotiation() {
            return Err(VersionInformationError);
        }
        let available = (0..len / 4 - 1)
            .map(|_| {
                let version = Version::decode(r).map_err(|_error| VersionInformationError)?;
                if version.is_negotiation() {
                    return Err(VersionInformationError);
                }
                Ok(version)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if receiver_is_server && !available.contains(&chosen) {
            return Err(VersionInformationError);
        }
        Ok(Self { chosen, available })
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "malformed version_information transport parameter"]
    #[derive(Copy)]
    pub struct VersionInformationError;
}

/// Why a version policy is not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VersionPolicyError {
    /// A list must contain the version the first flight uses.
    MissingOriginal,
    /// A list must not be empty.
    Empty,
    /// This crate does not implement the version.
    Unknown(Version),
    /// Reserved `0x?a?a?a?a` versions are greased into lists, never listed as usable.
    Reserved(Version),
    /// Versions that are not compatible with each other cannot be offered for compatible
    /// negotiation (RFC 9368 §2.2).
    Incompatible(Version, Version),
    /// The TLS provider cannot change version during the handshake, so it can only offer the
    /// version it starts with.
    SwitchUnsupported,
}

impl fmt::Display for VersionPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingOriginal => {
                f.write_str("version list does not contain the first flight's version")
            }
            Self::Empty => f.write_str("version list is empty"),
            Self::Unknown(version) => write!(f, "QUIC version {version} is not implemented"),
            Self::Reserved(version) => write!(f, "reserved QUIC version {version} cannot be used"),
            Self::Incompatible(a, b) => write!(f, "QUIC versions {a} and {b} are not compatible"),
            Self::SwitchUnsupported => {
                f.write_str("the TLS provider cannot switch QUIC version during the handshake")
            }
        }
    }
}

impl std::error::Error for VersionPolicyError {}

fn check_list(versions: &[Version]) -> Result<(), VersionPolicyError> {
    if versions.is_empty() {
        return Err(VersionPolicyError::Empty);
    }
    for &version in versions {
        if version.is_reserved() {
            return Err(VersionPolicyError::Reserved(version));
        }
        if version.wire().is_none() {
            return Err(VersionPolicyError::Unknown(version));
        }
    }
    Ok(())
}

/// How a client picks its first flight's version and what it lets the server negotiate
/// (RFC 9368 §2.5, §3).
///
/// The default starts in [`Version::V1`], lets a server move the connection to
/// [`Version::V2`] without a round trip, and restarts in either version if the server answers
/// with a Version Negotiation packet. A TLS provider that cannot change version during the
/// handshake narrows the compatible set to the original version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientVersionPolicy {
    original: Version,
    compatible: Vec<Version>,
    supported: Vec<Version>,
    grease: ReservedVersionGrease,
    resume_in_ticket_version: bool,
}

/// Where a reserved `0x?a?a?a?a` version goes in an advertised version list (RFC 9368 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ReservedVersionGrease {
    /// No reserved version.
    None,
    /// Before the real versions.
    First,
    /// After them.
    #[default]
    Last,
}

impl Default for ClientVersionPolicy {
    fn default() -> Self {
        Self {
            original: Version::V1,
            compatible: vec![Version::V1, Version::V2],
            supported: vec![Version::V1, Version::V2],
            grease: ReservedVersionGrease::Last,
            resume_in_ticket_version: true,
        }
    }
}

impl ClientVersionPolicy {
    /// Start in `original` and offer nothing else: no compatible switch and no restart.
    pub fn new(original: Version) -> Result<Self, VersionPolicyError> {
        check_list(&[original])?;
        Ok(Self {
            original,
            compatible: vec![original],
            supported: vec![original],
            grease: ReservedVersionGrease::Last,
            // An explicit first flight version is what the application asked for.
            resume_in_ticket_version: false,
        })
    }

    /// The version of the first flight.
    #[must_use]
    pub fn original(&self) -> Version {
        self.original
    }

    /// The versions the first flight is compatible with, most preferred first. A server may
    /// move the connection to any of them during the handshake.
    #[must_use]
    pub fn compatible(&self) -> &[Version] {
        &self.compatible
    }

    /// The versions a new first flight may use after a Version Negotiation packet, most
    /// preferred first.
    #[must_use]
    pub fn supported(&self) -> &[Version] {
        &self.supported
    }

    /// Whether, and where, a reserved version is added to the advertised list (RFC 9368 §3).
    #[must_use]
    pub fn reserved_version_grease(&self) -> ReservedVersionGrease {
        self.grease
    }

    /// Whether this policy may need the TLS session to change version mid-handshake.
    #[must_use]
    pub fn needs_switch(&self) -> bool {
        self.compatible
            .iter()
            .any(|&version| version != self.original)
    }

    /// The versions the first flight is compatible with; must contain the original and only
    /// versions compatible with it.
    pub fn try_with_compatible(
        mut self,
        compatible: Vec<Version>,
    ) -> Result<Self, VersionPolicyError> {
        check_list(&compatible)?;
        if !compatible.contains(&self.original) {
            return Err(VersionPolicyError::MissingOriginal);
        }
        if let Some(&other) = compatible
            .iter()
            .find(|&&version| !self.original.is_compatible_with(version))
        {
            return Err(VersionPolicyError::Incompatible(self.original, other));
        }
        self.compatible = compatible;
        Ok(self)
    }

    /// The versions a restart after Version Negotiation may pick from; must contain the
    /// original.
    pub fn try_with_supported(
        mut self,
        supported: Vec<Version>,
    ) -> Result<Self, VersionPolicyError> {
        check_list(&supported)?;
        if !supported.contains(&self.original) {
            return Err(VersionPolicyError::MissingOriginal);
        }
        self.supported = supported;
        Ok(self)
    }

    rama_utils::macros::generate_set_and_with! {
        /// Whether, and where, to add a reserved version to the advertised compatible list.
        /// Last by default.
        pub fn reserved_version_grease(mut self, grease: ReservedVersionGrease) -> Self {
            self.grease = grease;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Whether a first flight to a server that issued a session ticket in another
        /// supported version starts in that version, so the ticket can resume it
        /// (RFC 9369 §5, §6). On for the default policy; off once a first flight version is
        /// chosen explicitly, until turned on again here.
        pub fn resume_in_ticket_version(mut self, resume: bool) -> Self {
            self.resume_in_ticket_version = resume;
            self
        }
    }

    /// Whether a first flight follows the version of a held session ticket.
    #[must_use]
    pub fn resumes_in_ticket_version(&self) -> bool {
        self.resume_in_ticket_version
    }

    /// The policy for an attempt to a server that issued a ticket in `ticket`: the same policy
    /// starting in that version when it is supported and following tickets is on.
    pub(crate) fn for_ticket(&self, ticket: Option<Version>) -> Self {
        match ticket {
            Some(version)
                if self.resume_in_ticket_version
                    && version != self.original
                    && self.supported.contains(&version) =>
            {
                #[expect(
                    clippy::expect_used,
                    reason = "`supported` only holds versions `check_list` accepted"
                )]
                let mut policy = self
                    .clone()
                    .with_original(version)
                    .expect("a supported version is usable as the original");
                policy.resume_in_ticket_version = true;
                policy
            }
            _ => self.clone(),
        }
    }

    /// Start in `original`, keeping the rest of the policy and adding `original` to its lists.
    pub(crate) fn with_original(mut self, original: Version) -> Result<Self, VersionPolicyError> {
        check_list(&[original])?;
        self.original = original;
        self.resume_in_ticket_version = false;
        // Only versions compatible with the new original can stay in the compatible list.
        self.compatible
            .retain(|&version| original.is_compatible_with(version));
        if !self.compatible.contains(&original) {
            self.compatible.insert(0, original);
        }
        if !self.supported.contains(&original) {
            self.supported.insert(0, original);
        }
        Ok(self)
    }

    /// The same policy with no compatible version other than the original, so no switch is
    /// needed. A backend that cannot change version mid-handshake uses this.
    #[must_use]
    pub fn narrowed_public(self) -> Self {
        self.narrowed()
    }

    /// The same policy without a compatible switch, for a TLS session that cannot change
    /// version.
    #[must_use]
    pub(crate) fn narrowed(mut self) -> Self {
        self.compatible = vec![self.original];
        self
    }

    /// Every version the endpoint must be able to decode for this policy.
    pub(crate) fn all_versions(&self) -> impl Iterator<Item = Version> + '_ {
        std::iter::once(self.original)
            .chain(self.compatible.iter().copied())
            .chain(self.supported.iter().copied())
    }

    /// The version this client would pick from a server's list, by its own preference order,
    /// ignoring reserved versions (RFC 9368 §2.1, §4).
    pub(crate) fn select(&self, offered: &[Version]) -> Option<Version> {
        self.supported
            .iter()
            .copied()
            .find(|version| !version.is_reserved() && offered.contains(version))
    }

    /// What the client advertises: its original version and, in preference order, what the
    /// first flight is compatible with.
    pub(crate) fn information(&self, grease: Version) -> VersionInformation {
        let mut available = self.compatible.clone();
        match self.grease {
            ReservedVersionGrease::None => {}
            ReservedVersionGrease::First => available.insert(0, grease),
            ReservedVersionGrease::Last => available.push(grease),
        }
        VersionInformation::new(self.original, available)
    }
}

/// Which version a server settles on when a client offers several compatible ones.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum VersionPreference {
    /// Use the version the client's first flight came in.
    #[default]
    KeepClientChoice,
    /// Use the first of these the client offered and this endpoint accepts, falling back to the
    /// client's choice.
    Prefer(Vec<Version>),
}

/// How a server negotiates versions (RFC 9368 §2.3, §5).
///
/// The acceptable versions are the endpoint's supported set; this policy adds what a Version
/// Negotiation packet offers, what the server reports as fully deployed, and which compatible
/// version it prefers. By default it offers and reports everything it accepts and keeps the
/// client's choice.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerVersionPolicy {
    offered: Option<Vec<Version>>,
    fully_deployed: Option<Vec<Version>>,
    preference: VersionPreference,
    grease: bool,
}

impl ServerVersionPolicy {
    /// Offer and report everything the endpoint accepts, keep the client's choice, and grease
    /// the advertised list with a reserved version.
    #[must_use]
    pub fn new() -> Self {
        Self {
            offered: None,
            fully_deployed: None,
            preference: VersionPreference::KeepClientChoice,
            grease: true,
        }
    }

    /// The versions a Version Negotiation packet lists, when narrower than the acceptable set
    /// (RFC 9368 §5, "Offered Versions").
    pub fn try_with_offered(mut self, offered: Vec<Version>) -> Result<Self, VersionPolicyError> {
        check_list(&offered)?;
        self.offered = Some(offered);
        Ok(self)
    }

    /// The versions reported in `version_information`, when narrower than the acceptable set
    /// (RFC 9368 §5, "Fully Deployed Versions"). May be empty during a rollout.
    pub fn try_with_fully_deployed(
        mut self,
        fully_deployed: Vec<Version>,
    ) -> Result<Self, VersionPolicyError> {
        for &version in &fully_deployed {
            if version.is_reserved() {
                return Err(VersionPolicyError::Reserved(version));
            }
        }
        self.fully_deployed = Some(fully_deployed);
        Ok(self)
    }

    /// Which compatible version to move a connection to when the client offers a choice.
    pub fn try_with_preference(
        mut self,
        preference: VersionPreference,
    ) -> Result<Self, VersionPolicyError> {
        if let VersionPreference::Prefer(versions) = &preference {
            check_list(versions)?;
        }
        self.preference = preference;
        Ok(self)
    }

    rama_utils::macros::generate_set_and_with! {
        /// Whether to add a reserved version to the reported list. On by default.
        pub fn reserved_version_grease(mut self, grease: bool) -> Self {
            self.grease = grease;
            self
        }
    }

    /// Which compatible version this server moves a connection to.
    #[must_use]
    pub fn preference(&self) -> &VersionPreference {
        &self.preference
    }

    /// Whether this policy can ever pick a version other than the client's.
    pub(crate) fn may_switch(&self) -> bool {
        matches!(self.preference, VersionPreference::Prefer(_))
    }

    /// The versions a Version Negotiation packet lists.
    pub(crate) fn offered<'a>(&'a self, acceptable: &'a [Version]) -> &'a [Version] {
        self.offered.as_deref().unwrap_or(acceptable)
    }

    /// The version to continue in, given the client's first flight version and what it says
    /// that flight is compatible with (RFC 9368 §2.3, RFC 9369 §4.1).
    pub(crate) fn negotiate(
        &self,
        chosen: Version,
        client_available: Option<&[Version]>,
        acceptable: &[Version],
    ) -> Version {
        let VersionPreference::Prefer(preferred) = &self.preference else {
            return chosen;
        };
        let Some(available) = client_available else {
            return chosen;
        };
        preferred
            .iter()
            .copied()
            .find(|version| {
                !version.is_reserved()
                    && acceptable.contains(version)
                    && available.contains(version)
                    && chosen.is_compatible_with(*version)
            })
            .unwrap_or(chosen)
    }

    /// What the server advertises: the negotiated version and its fully deployed set.
    pub(crate) fn information(
        &self,
        negotiated: Version,
        acceptable: &[Version],
        grease: Version,
    ) -> VersionInformation {
        let mut available = self
            .fully_deployed
            .clone()
            .unwrap_or_else(|| acceptable.to_vec());
        if self.grease {
            available.push(grease);
        }
        VersionInformation::new(negotiated, available)
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn the_default_client_policy_starts_in_v1_and_offers_v2() {
        let policy = ClientVersionPolicy::default();
        assert_eq!(policy.original(), Version::V1);
        assert_eq!(policy.compatible(), [Version::V1, Version::V2]);
        assert!(policy.needs_switch());
        assert!(!policy.narrowed().needs_switch());
    }

    #[test]
    fn a_client_policy_refuses_unusable_lists() {
        let policy = ClientVersionPolicy::new(Version::V1).unwrap();
        assert_eq!(
            policy.clone().try_with_compatible(vec![Version::V2]),
            Err(VersionPolicyError::MissingOriginal)
        );
        assert_eq!(
            policy.clone().try_with_compatible(vec![]),
            Err(VersionPolicyError::Empty)
        );
        let reserved = Version::from_u32(0x1a2a_3a4a);
        assert_eq!(
            policy
                .clone()
                .try_with_supported(vec![Version::V1, reserved]),
            Err(VersionPolicyError::Reserved(reserved))
        );
        let unknown = Version::from_u32(0x1234_5678);
        assert_eq!(
            policy
                .clone()
                .try_with_supported(vec![Version::V1, unknown]),
            Err(VersionPolicyError::Unknown(unknown))
        );
        let draft = Version::from_u32(0xff00_001d);
        assert_eq!(
            policy.try_with_compatible(vec![Version::V1, draft]),
            Err(VersionPolicyError::Incompatible(Version::V1, draft))
        );
        ClientVersionPolicy::new(reserved).unwrap_err();
    }

    #[test]
    fn changing_the_original_keeps_only_compatible_versions() {
        let draft = Version::from_u32(0xff00_001d);
        let policy = ClientVersionPolicy::default().with_original(draft).unwrap();
        assert_eq!(policy.compatible(), [draft]);
        assert_eq!(policy.supported(), [draft, Version::V1, Version::V2]);
        let policy = ClientVersionPolicy::default()
            .with_original(Version::V2)
            .unwrap();
        assert_eq!(policy.compatible(), [Version::V1, Version::V2]);
    }

    #[test]
    fn selection_follows_the_clients_preference_and_skips_reserved_versions() {
        let policy = ClientVersionPolicy::new(Version::V1)
            .unwrap()
            .try_with_supported(vec![Version::V2, Version::V1])
            .unwrap();
        let grease = Version::from_u32(0x0a1a_2a3a);
        assert_eq!(
            policy.select(&[grease, Version::V1, Version::V2]),
            Some(Version::V2)
        );
        assert_eq!(policy.select(&[grease, Version::V1]), Some(Version::V1));
        assert_eq!(policy.select(&[grease]), None);
    }

    #[test]
    fn a_server_keeps_the_clients_choice_unless_it_prefers_otherwise() {
        let acceptable = [Version::V1, Version::V2];
        let policy = ServerVersionPolicy::new();
        assert_eq!(
            policy.negotiate(Version::V1, Some(&[Version::V1, Version::V2]), &acceptable),
            Version::V1
        );
        let policy = policy
            .try_with_preference(VersionPreference::Prefer(vec![Version::V2]))
            .unwrap();
        assert_eq!(
            policy.negotiate(Version::V1, Some(&[Version::V1, Version::V2]), &acceptable),
            Version::V2
        );
        // The client did not offer v2, or the server does not accept it, or nothing was said.
        assert_eq!(
            policy.negotiate(Version::V1, Some(&[Version::V1]), &acceptable),
            Version::V1
        );
        assert_eq!(
            policy.negotiate(
                Version::V1,
                Some(&[Version::V1, Version::V2]),
                &[Version::V1]
            ),
            Version::V1
        );
        assert_eq!(
            policy.negotiate(Version::V1, None, &acceptable),
            Version::V1
        );
    }

    #[test]
    fn version_information_round_trips_and_rejects_bad_values() {
        let info = VersionInformation::new(Version::V1, vec![Version::V1, Version::V2]);
        let mut bytes = Vec::new();
        info.write(&mut bytes);
        assert_eq!(bytes.len(), info.wire_size());
        assert_eq!(
            VersionInformation::read(true, bytes.len(), &mut &bytes[..]).unwrap(),
            info
        );
        // Length not a multiple of four, too short, zero versions, chosen missing for a server.
        VersionInformation::read(true, 5, &mut &bytes[..5]).unwrap_err();
        VersionInformation::read(true, 0, &mut &bytes[..0]).unwrap_err();
        let zero = [0u8; 8];
        VersionInformation::read(false, 8, &mut &zero[..]).unwrap_err();
        let chosen_missing = Version::V2
            .to_be_bytes()
            .into_iter()
            .chain(Version::V1.to_be_bytes())
            .collect::<Vec<_>>();
        VersionInformation::read(true, 8, &mut &chosen_missing[..]).unwrap_err();
        VersionInformation::read(false, 8, &mut &chosen_missing[..]).unwrap();
    }
}
