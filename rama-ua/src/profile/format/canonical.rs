//! Versioned profile identities independent of serialization and dependency hashes.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(feature = "tls")]
use crate::profile::capture::tls::{
    TlsCapture, TlsCaptureLimits, structure::validate_tls_structure,
};

use crate::profile::{
    capture::{
        headers::{HeaderCapture, HeaderCapturePolicy, structure::validate_header_structure},
        http2::{H2Capture, H2CaptureLimits},
        http3::{H3ClientSequenceCapture, H3SequenceCaptureLimits},
        joint::{JointCapture, JointCaptureLimits, validate_joint_structure},
        order::{OrderCaptureLimits, OrderedProtocolCapture, validate_structure},
        pseudo_headers::PseudoHeaderCapture,
        quic::{QuicFlightCapture, QuicFlightCaptureLimits},
        runtime::RuntimeProfileCapture,
    },
    format::legacy::{LegacyFieldCapture, LegacyHeaderCapture},
    model::{
        identity::{FlowKey, ProfileKey},
        scope::ProfileObservationScope,
    },
};

/// Stable canonical domains; serialized tags remain independent of Rust enum layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
#[repr(u16)]
pub enum CanonicalDomain {
    Headers = 1,
    Profile = 2,
    Flow = 3,
    Order = 4,
    OrderStructure = 5,
    Joint = 6,
    JointStructure = 7,
    Scope = 8,
    HeaderStructure = 9,
    Tls = 10,
    TlsStructure = 11,
    H2 = 12,
    H2Structure = 13,
    PseudoHeaders = 14,
    PseudoHeaderStructure = 15,
    RuntimeMetadata = 16,
    RuntimeMetadataStructure = 17,
    QuicFlight = 18,
    H3Sequence = 19,
    H3SequenceStructure = 20,
    QuicFlightStructure = 21,
    LegacyHeaders = 22,
    LegacyField = 23,
    LegacyFieldStructure = 24,
}

impl From<CanonicalDomain> for u16 {
    fn from(value: CanonicalDomain) -> Self {
        value as Self
    }
}

impl From<CanonicalDomain> for i32 {
    fn from(value: CanonicalDomain) -> Self {
        Self::from(u16::from(value))
    }
}

impl TryFrom<u16> for CanonicalDomain {
    type Error = ProfileDataError;
    fn try_from(tag: u16) -> Result<Self, Self::Error> {
        match tag {
            1 => Ok(Self::Headers),
            2 => Ok(Self::Profile),
            3 => Ok(Self::Flow),
            4 => Ok(Self::Order),
            5 => Ok(Self::OrderStructure),
            6 => Ok(Self::Joint),
            7 => Ok(Self::JointStructure),
            8 => Ok(Self::Scope),
            9 => Ok(Self::HeaderStructure),
            10 => Ok(Self::Tls),
            11 => Ok(Self::TlsStructure),
            12 => Ok(Self::H2),
            13 => Ok(Self::H2Structure),
            14 => Ok(Self::PseudoHeaders),
            15 => Ok(Self::PseudoHeaderStructure),
            16 => Ok(Self::RuntimeMetadata),
            17 => Ok(Self::RuntimeMetadataStructure),
            18 => Ok(Self::QuicFlight),
            19 => Ok(Self::H3Sequence),
            20 => Ok(Self::H3SequenceStructure),
            21 => Ok(Self::QuicFlightStructure),
            22 => Ok(Self::LegacyHeaders),
            23 => Ok(Self::LegacyField),
            24 => Ok(Self::LegacyFieldStructure),
            _ => Err(ProfileDataError::Unsupported("canonical content domain")),
        }
    }
}

pub(in crate::profile) const HEADER_DOMAIN: CanonicalDomain = CanonicalDomain::Headers;
pub(in crate::profile) const HEADER_STRUCTURE_DOMAIN: CanonicalDomain =
    CanonicalDomain::HeaderStructure;
pub(in crate::profile) const PROFILE_DOMAIN: CanonicalDomain = CanonicalDomain::Profile;
pub(in crate::profile) const FLOW_DOMAIN: CanonicalDomain = CanonicalDomain::Flow;
pub(in crate::profile) const ORDER_DOMAIN: CanonicalDomain = CanonicalDomain::Order;
pub(in crate::profile) const ORDER_STRUCTURE_DOMAIN: CanonicalDomain =
    CanonicalDomain::OrderStructure;
pub(in crate::profile) const JOINT_DOMAIN: CanonicalDomain = CanonicalDomain::Joint;
pub(in crate::profile) const JOINT_STRUCTURE_DOMAIN: CanonicalDomain =
    CanonicalDomain::JointStructure;
pub(in crate::profile) const SCOPE_DOMAIN: CanonicalDomain = CanonicalDomain::Scope;

const PREFIX: &[u8] = b"rama-profile\0";
const VERSION: u16 = 1;

fn canonical_version(domain: CanonicalDomain) -> u16 {
    match domain {
        CanonicalDomain::Headers
        | CanonicalDomain::Order
        | CanonicalDomain::Joint
        | CanonicalDomain::JointStructure
        | CanonicalDomain::Tls
        | CanonicalDomain::TlsStructure
        | CanonicalDomain::OrderStructure => 2,
        _ => VERSION,
    }
}

/// SHA-256 of a versioned canonical value, including its domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ValueId(pub [u8; 32]);

/// Interned values retain their bytes so a digest collision cannot alias two values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalValue {
    pub id: ValueId,
    pub bytes: Box<[u8]>,
}

/// Invalid, incomplete or over-budget profile data never acquires replay capability.
#[derive(Debug, Clone)]
pub enum ProfileDataError {
    LimitExceeded(&'static str),
    Invalid(&'static str),
    Incomplete(&'static str),
    Unsupported(&'static str),
    IdentityMismatch,
    CounterOverflow,
    Expired,
}

impl fmt::Display for ProfileDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded(value) => write!(f, "profile limit exceeded: {value}"),
            Self::Invalid(value) => write!(f, "invalid profile data: {value}"),
            Self::Incomplete(value) => write!(f, "incomplete profile data: {value}"),
            Self::Unsupported(value) => write!(f, "unsupported profile data: {value}"),
            Self::IdentityMismatch => f.write_str("profile digest does not match canonical bytes"),
            Self::CounterOverflow => f.write_str("profile observation count overflow"),
            Self::Expired => f.write_str("profile observation expired"),
        }
    }
}

impl Error for ProfileDataError {}

impl CanonicalValue {
    /// Validate the owned payload and return its persistent domain tag.
    /// Storage adapters use this instead of interpreting the canonical envelope.
    pub fn validated_domain(
        &self,
        maximum_bytes: usize,
    ) -> Result<CanonicalDomain, ProfileDataError> {
        let domain = self.domain_tag(maximum_bytes)?;
        self.validate_content(domain, maximum_bytes)?;
        Ok(domain)
    }

    /// Read a dispatch tag only; the selected decoder must validate the payload.
    pub(in crate::profile) fn domain_tag(
        &self,
        maximum_bytes: usize,
    ) -> Result<CanonicalDomain, ProfileDataError> {
        if self.bytes.len() > maximum_bytes {
            return Err(ProfileDataError::LimitExceeded("canonical bytes"));
        }
        let offset = PREFIX.len() + 2;
        let tag = self
            .bytes
            .get(offset..offset + 2)
            .ok_or(ProfileDataError::Invalid("truncated canonical domain"))?;
        CanonicalDomain::try_from(u16::from_be_bytes([tag[0], tag[1]]))
    }

    /// An envelope and digest do not establish the payload's ownership or semantics.
    pub(in crate::profile) fn validate_content(
        &self,
        domain: CanonicalDomain,
        maximum_bytes: usize,
    ) -> Result<(), ProfileDataError> {
        match domain {
            CanonicalDomain::LegacyHeaders => {
                LegacyHeaderCapture::from_canonical(self, maximum_bytes)?;
            }
            CanonicalDomain::LegacyField => {
                LegacyFieldCapture::from_canonical(self, maximum_bytes)?;
            }
            CanonicalDomain::LegacyFieldStructure => {
                LegacyFieldCapture::validate_structure(self, maximum_bytes)?
            }
            #[cfg(not(feature = "tls"))]
            CanonicalDomain::TlsStructure | CanonicalDomain::Tls => {
                return Err(ProfileDataError::Unsupported("TLS profile component"));
            }

            #[cfg(feature = "tls")]
            CanonicalDomain::TlsStructure => {
                validate_tls_structure(self, maximum_bytes)?;
            }

            #[cfg(feature = "tls")]
            CanonicalDomain::Tls => {
                TlsCapture::from_canonical(
                    self,
                    TlsCaptureLimits {
                        elements: maximum_bytes,
                        bytes: maximum_bytes,
                    },
                )?;
            }
            CanonicalDomain::H3Sequence | CanonicalDomain::H3SequenceStructure => {
                H3ClientSequenceCapture::decode(
                    self,
                    H3SequenceCaptureLimits {
                        bytes: maximum_bytes,
                        ..H3SequenceCaptureLimits::default()
                    },
                    domain == CanonicalDomain::H3SequenceStructure,
                )?;
            }
            CanonicalDomain::QuicFlightStructure => {
                QuicFlightCapture::validate_structure(
                    self,
                    QuicFlightCaptureLimits {
                        bytes: maximum_bytes,
                        ..QuicFlightCaptureLimits::default()
                    },
                )?;
            }
            CanonicalDomain::QuicFlight => {
                QuicFlightCapture::from_canonical(
                    self,
                    QuicFlightCaptureLimits {
                        bytes: maximum_bytes,
                        ..QuicFlightCaptureLimits::default()
                    },
                )?;
            }
            CanonicalDomain::RuntimeMetadata => {
                RuntimeProfileCapture::from_canonical(self, maximum_bytes)?;
            }
            CanonicalDomain::RuntimeMetadataStructure => {
                RuntimeProfileCapture::validate_structure(self, maximum_bytes)?;
            }
            CanonicalDomain::PseudoHeaders | CanonicalDomain::PseudoHeaderStructure => {
                PseudoHeaderCapture::decode(
                    self,
                    maximum_bytes,
                    domain == CanonicalDomain::PseudoHeaderStructure,
                )?;
            }
            CanonicalDomain::H2 | CanonicalDomain::H2Structure => {
                H2Capture::decode(
                    self,
                    H2CaptureLimits {
                        frames: maximum_bytes,
                        settings: maximum_bytes,
                        bytes: maximum_bytes,
                    },
                    domain == CanonicalDomain::H2Structure,
                )?;
            }
            HEADER_DOMAIN => {
                // Every encoded occurrence consumes bytes; decoding remains bounded even
                // for callers whose capture field budget exceeds the default.
                let policy = HeaderCapturePolicy {
                    fields: maximum_bytes,
                    bytes: maximum_bytes,
                    overrides: Box::default(),
                };
                HeaderCapture::from_canonical(self, &policy)?;
            }
            PROFILE_DOMAIN => {
                ProfileKey::from_canonical(self, maximum_bytes)?;
            }
            FLOW_DOMAIN => {
                FlowKey::from_canonical(self, maximum_bytes)?;
            }
            ORDER_DOMAIN => {
                OrderedProtocolCapture::from_canonical(
                    self,
                    OrderCaptureLimits {
                        elements: maximum_bytes,
                        bytes: maximum_bytes,
                    },
                )?;
            }
            ORDER_STRUCTURE_DOMAIN => validate_structure(self, maximum_bytes)?,
            HEADER_STRUCTURE_DOMAIN => validate_header_structure(self, maximum_bytes)?,
            JOINT_DOMAIN => {
                JointCapture::from_canonical(
                    self,
                    JointCaptureLimits {
                        slots: maximum_bytes,
                        value_bytes: maximum_bytes,
                        bytes: maximum_bytes,
                    },
                )?;
            }
            JOINT_STRUCTURE_DOMAIN => validate_joint_structure(self, maximum_bytes)?,
            SCOPE_DOMAIN => {
                ProfileObservationScope::from_canonical(self, maximum_bytes)?;
            }
        }
        Ok(())
    }

    /// Verify persisted identity and envelope before interpreting the domain's payload.
    pub fn verify(
        &self,
        domain: CanonicalDomain,
        maximum_bytes: usize,
    ) -> Result<(), ProfileDataError> {
        if self.bytes.len() > maximum_bytes {
            return Err(ProfileDataError::LimitExceeded("canonical bytes"));
        }
        _ = CanonicalReader::new(&self.bytes, domain)?;
        if self.id.0 != <[u8; 32]>::from(Sha256::digest(&self.bytes)) {
            return Err(ProfileDataError::IdentityMismatch);
        }
        Ok(())
    }
}

pub(in crate::profile) struct CanonicalWriter {
    bytes: Vec<u8>,
    maximum_bytes: usize,
}

impl CanonicalWriter {
    pub(in crate::profile) fn new(
        domain: CanonicalDomain,
        maximum_bytes: usize,
    ) -> Result<Self, ProfileDataError> {
        let mut this = Self {
            bytes: Vec::new(),
            maximum_bytes,
        };
        this.raw(PREFIX)?;
        this.u16(canonical_version(domain))?;
        this.u16(domain.into())?;
        Ok(this)
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), ProfileDataError> {
        if value.len() > self.maximum_bytes.saturating_sub(self.bytes.len()) {
            return Err(ProfileDataError::LimitExceeded("canonical bytes"));
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(in crate::profile) fn u8(&mut self, value: u8) -> Result<(), ProfileDataError> {
        self.raw(&[value])
    }

    pub(in crate::profile) fn u16(&mut self, value: u16) -> Result<(), ProfileDataError> {
        self.raw(&value.to_be_bytes())
    }

    pub(in crate::profile) fn u32(&mut self, value: u32) -> Result<(), ProfileDataError> {
        self.raw(&value.to_be_bytes())
    }

    pub(in crate::profile) fn u64(&mut self, value: u64) -> Result<(), ProfileDataError> {
        self.raw(&value.to_be_bytes())
    }

    pub(in crate::profile) fn bytes(&mut self, value: &[u8]) -> Result<(), ProfileDataError> {
        self.u64(value.len() as u64)?;
        self.raw(value)
    }

    pub(in crate::profile) fn finish(self) -> CanonicalValue {
        CanonicalValue {
            id: ValueId(Sha256::digest(&self.bytes).into()),
            bytes: self.bytes.into_boxed_slice(),
        }
    }
}

pub(in crate::profile) struct CanonicalReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> CanonicalReader<'a> {
    pub(in crate::profile) fn new(
        bytes: &'a [u8],
        domain: CanonicalDomain,
    ) -> Result<Self, ProfileDataError> {
        let mut this = Self { bytes, position: 0 };
        if this.raw(PREFIX.len())? != PREFIX || this.u16()? != canonical_version(domain) {
            return Err(ProfileDataError::Unsupported("canonical format version"));
        }
        if this.u16()? != u16::from(domain) {
            return Err(ProfileDataError::Invalid("canonical domain"));
        }
        Ok(this)
    }

    fn raw(&mut self, length: usize) -> Result<&'a [u8], ProfileDataError> {
        let rest = &self.bytes[self.position..];
        let value = rest
            .get(..length)
            .ok_or(ProfileDataError::Invalid("truncated canonical value"))?;
        self.position += length;
        Ok(value)
    }

    pub(in crate::profile) fn u8(&mut self) -> Result<u8, ProfileDataError> {
        Ok(self.raw(1)?[0])
    }

    pub(in crate::profile) fn u16(&mut self) -> Result<u16, ProfileDataError> {
        let bytes = self.raw(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(in crate::profile) fn u32(&mut self) -> Result<u32, ProfileDataError> {
        let bytes = self.raw(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(in crate::profile) fn u64(&mut self) -> Result<u64, ProfileDataError> {
        let bytes = self.raw(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(in crate::profile) fn count(&mut self, maximum: usize) -> Result<usize, ProfileDataError> {
        let count = usize::try_from(self.u64()?)
            .map_err(|_error| ProfileDataError::LimitExceeded("canonical count"))?;
        if count > maximum {
            return Err(ProfileDataError::LimitExceeded("canonical count"));
        }
        Ok(count)
    }

    pub(in crate::profile) fn bytes(
        &mut self,
        maximum: usize,
    ) -> Result<&'a [u8], ProfileDataError> {
        let length = self.count(maximum)?;
        self.raw(length)
    }

    pub(in crate::profile) fn finish(self) -> Result<(), ProfileDataError> {
        if self.position != self.bytes.len() {
            return Err(ProfileDataError::Invalid("trailing canonical bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tags_round_trip_as_stable_numbers_and_reject_unknown_values() {
        for (tag, domain) in [
            (1, CanonicalDomain::Headers),
            (2, CanonicalDomain::Profile),
            (3, CanonicalDomain::Flow),
            (4, CanonicalDomain::Order),
            (5, CanonicalDomain::OrderStructure),
            (6, CanonicalDomain::Joint),
            (7, CanonicalDomain::JointStructure),
            (8, CanonicalDomain::Scope),
            (9, CanonicalDomain::HeaderStructure),
            (10, CanonicalDomain::Tls),
            (11, CanonicalDomain::TlsStructure),
            (12, CanonicalDomain::H2),
            (13, CanonicalDomain::H2Structure),
            (14, CanonicalDomain::PseudoHeaders),
            (15, CanonicalDomain::PseudoHeaderStructure),
            (16, CanonicalDomain::RuntimeMetadata),
            (17, CanonicalDomain::RuntimeMetadataStructure),
            (18, CanonicalDomain::QuicFlight),
            (19, CanonicalDomain::H3Sequence),
            (20, CanonicalDomain::H3SequenceStructure),
            (21, CanonicalDomain::QuicFlightStructure),
            (22, CanonicalDomain::LegacyHeaders),
            (23, CanonicalDomain::LegacyField),
            (24, CanonicalDomain::LegacyFieldStructure),
        ] {
            assert_eq!(u16::from(domain), tag);
            assert_eq!(CanonicalDomain::try_from(tag).unwrap(), domain);
            let json = serde_json::to_string(&domain).unwrap();
            assert_eq!(json, tag.to_string());
            assert_eq!(
                serde_json::from_str::<CanonicalDomain>(&json).unwrap(),
                domain
            );
        }
        for tag in [0, 25, u16::MAX] {
            CanonicalDomain::try_from(tag).unwrap_err();
            serde_json::from_str::<CanonicalDomain>(&tag.to_string()).unwrap_err();
        }
    }
}

#[cfg(all(test, not(feature = "tls")))]
mod tls_disabled_tests {
    use super::*;
    #[test]
    fn tls_domains_do_not_acquire_capability_without_the_feature() {
        for domain in [CanonicalDomain::Tls, CanonicalDomain::TlsStructure] {
            let value = CanonicalWriter::new(domain, 64).unwrap().finish();
            assert!(matches!(
                value.validated_domain(64),
                Err(ProfileDataError::Unsupported("TLS profile component"))
            ));
        }
    }
}
