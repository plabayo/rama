//! Versioned profile identities independent of serialization and dependency hashes.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    FlowKey, HeaderCapture, HeaderCapturePolicy, JointCapture, JointCaptureLimits,
    OrderCaptureLimits, OrderedProtocolCapture, ProfileKey, ProfileObservationScope,
    joint::validate_joint_structure, order_capture::validate_structure,
};

pub(super) const HEADER_DOMAIN: u16 = 1;
pub(super) const PROFILE_DOMAIN: u16 = 2;
pub(super) const FLOW_DOMAIN: u16 = 3;
pub(super) const ORDER_DOMAIN: u16 = 4;
pub(super) const ORDER_STRUCTURE_DOMAIN: u16 = 5;
pub(super) const JOINT_DOMAIN: u16 = 6;
pub(super) const JOINT_STRUCTURE_DOMAIN: u16 = 7;
pub(super) const SCOPE_DOMAIN: u16 = 8;

const PREFIX: &[u8] = b"rama-profile\0";
const VERSION: u16 = 1;

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
        }
    }
}

impl Error for ProfileDataError {}

impl CanonicalValue {
    /// Validate the owned payload and return its persistent domain tag.
    /// Storage adapters use this instead of interpreting the canonical envelope.
    pub fn validated_domain(&self, maximum_bytes: usize) -> Result<u16, ProfileDataError> {
        if self.bytes.len() > maximum_bytes {
            return Err(ProfileDataError::LimitExceeded("canonical bytes"));
        }
        let offset = PREFIX.len() + 2;
        let tag = self
            .bytes
            .get(offset..offset + 2)
            .ok_or(ProfileDataError::Invalid("truncated canonical domain"))?;
        let domain = u16::from_be_bytes([tag[0], tag[1]]);
        self.validate_content(domain, maximum_bytes)?;
        Ok(domain)
    }

    /// An envelope and digest do not establish the payload's ownership or semantics.
    pub(super) fn validate_content(
        &self,
        domain: u16,
        maximum_bytes: usize,
    ) -> Result<(), ProfileDataError> {
        match domain {
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
            _ => return Err(ProfileDataError::Unsupported("canonical content domain")),
        }
        Ok(())
    }

    /// Verify persisted identity and envelope before interpreting the domain's payload.
    pub fn verify(&self, domain: u16, maximum_bytes: usize) -> Result<(), ProfileDataError> {
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

pub(super) struct CanonicalWriter {
    bytes: Vec<u8>,
    maximum_bytes: usize,
}

impl CanonicalWriter {
    pub(super) fn new(domain: u16, maximum_bytes: usize) -> Result<Self, ProfileDataError> {
        let mut this = Self {
            bytes: Vec::new(),
            maximum_bytes,
        };
        this.raw(PREFIX)?;
        this.u16(VERSION)?;
        this.u16(domain)?;
        Ok(this)
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), ProfileDataError> {
        if value.len() > self.maximum_bytes.saturating_sub(self.bytes.len()) {
            return Err(ProfileDataError::LimitExceeded("canonical bytes"));
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn u8(&mut self, value: u8) -> Result<(), ProfileDataError> {
        self.raw(&[value])
    }

    pub(super) fn u16(&mut self, value: u16) -> Result<(), ProfileDataError> {
        self.raw(&value.to_be_bytes())
    }

    pub(super) fn u32(&mut self, value: u32) -> Result<(), ProfileDataError> {
        self.raw(&value.to_be_bytes())
    }

    pub(super) fn u64(&mut self, value: u64) -> Result<(), ProfileDataError> {
        self.raw(&value.to_be_bytes())
    }

    pub(super) fn bytes(&mut self, value: &[u8]) -> Result<(), ProfileDataError> {
        self.u64(value.len() as u64)?;
        self.raw(value)
    }

    pub(super) fn finish(self) -> CanonicalValue {
        CanonicalValue {
            id: ValueId(Sha256::digest(&self.bytes).into()),
            bytes: self.bytes.into_boxed_slice(),
        }
    }
}

pub(super) struct CanonicalReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> CanonicalReader<'a> {
    pub(super) fn new(bytes: &'a [u8], domain: u16) -> Result<Self, ProfileDataError> {
        let mut this = Self { bytes, position: 0 };
        if this.raw(PREFIX.len())? != PREFIX || this.u16()? != VERSION {
            return Err(ProfileDataError::Unsupported("canonical format version"));
        }
        if this.u16()? != domain {
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

    pub(super) fn u8(&mut self) -> Result<u8, ProfileDataError> {
        Ok(self.raw(1)?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, ProfileDataError> {
        let bytes = self.raw(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(super) fn u32(&mut self) -> Result<u32, ProfileDataError> {
        let bytes = self.raw(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(super) fn u64(&mut self) -> Result<u64, ProfileDataError> {
        let bytes = self.raw(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(super) fn count(&mut self, maximum: usize) -> Result<usize, ProfileDataError> {
        let count = usize::try_from(self.u64()?)
            .map_err(|_error| ProfileDataError::LimitExceeded("canonical count"))?;
        if count > maximum {
            return Err(ProfileDataError::LimitExceeded("canonical count"));
        }
        Ok(count)
    }

    pub(super) fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], ProfileDataError> {
        let length = self.count(maximum)?;
        self.raw(length)
    }

    pub(super) fn finish(self) -> Result<(), ProfileDataError> {
        if self.position != self.bytes.len() {
            return Err(ProfileDataError::Invalid("trailing canonical bytes"));
        }
        Ok(())
    }
}
