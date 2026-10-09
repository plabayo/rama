//! Complete component tuples retain observed cross-component correlations.

use rama_utils::octets::kib;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::{
    CanonicalValue, OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture, ProfileDataError,
    ValueId,
    canonical::{
        CanonicalReader, CanonicalWriter, HEADER_DOMAIN, JOINT_DOMAIN, JOINT_STRUCTURE_DOMAIN,
        ORDER_STRUCTURE_DOMAIN,
    },
    order_capture::validate_structure,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CaptureLevel {
    Connection,
    Request,
}

impl CaptureLevel {
    fn tag(self) -> u8 {
        match self {
            Self::Connection => 0,
            Self::Request => 1,
        }
    }
    fn from_tag(tag: u8) -> Result<Self, ProfileDataError> {
        match tag {
            0 => Ok(Self::Connection),
            1 => Ok(Self::Request),
            _ => Err(ProfileDataError::Invalid("joint capture level")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum CapturedSlotKind {
    Headers,
    QuicParameters,
    Http3Settings,
    QuicVersions,
}

impl CapturedSlotKind {
    fn tag(self) -> u16 {
        match self {
            Self::Headers => 0,
            Self::QuicParameters => 1,
            Self::Http3Settings => 2,
            Self::QuicVersions => 3,
        }
    }
    fn from_tag(tag: u16) -> Result<Self, ProfileDataError> {
        match tag {
            0 => Ok(Self::Headers),
            1 => Ok(Self::QuicParameters),
            2 => Ok(Self::Http3Settings),
            3 => Ok(Self::QuicVersions),
            _ => Err(ProfileDataError::Unsupported("joint slot kind")),
        }
    }
    fn level(self) -> CaptureLevel {
        match self {
            Self::Headers => CaptureLevel::Request,
            _ => CaptureLevel::Connection,
        }
    }
    fn namespace(self) -> Option<OrderNamespace> {
        match self {
            Self::Headers => None,
            Self::QuicParameters => Some(OrderNamespace::QuicParameter),
            Self::Http3Settings => Some(OrderNamespace::Http3Setting),
            Self::QuicVersions => Some(OrderNamespace::QuicVersion),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CapturedSlot {
    pub kind: CapturedSlotKind,
    pub value: CanonicalValue,
}

#[derive(Debug, Clone)]
pub struct JointCapture {
    pub level: CaptureLevel,
    pub slots: Box<[CapturedSlot]>,
}

#[derive(Debug, Clone, Copy)]
pub struct JointCaptureLimits {
    pub slots: usize,
    pub value_bytes: usize,
    pub bytes: usize,
}

impl Default for JointCaptureLimits {
    fn default() -> Self {
        Self {
            slots: 16,
            value_bytes: kib(16),
            bytes: kib(64),
        }
    }
}

fn validate_slot(
    slot: &CapturedSlot,
    structural: bool,
    maximum: usize,
) -> Result<(), ProfileDataError> {
    let Some(namespace) = slot.kind.namespace() else {
        return slot.value.validate_content(HEADER_DOMAIN, maximum);
    };
    if structural {
        validate_structure(&slot.value, maximum)?;
        let mut reader = CanonicalReader::new(&slot.value.bytes, ORDER_STRUCTURE_DOMAIN)?;
        if reader.u8()? != namespace.tag() {
            return Err(ProfileDataError::Invalid("joint structural namespace"));
        }
    } else {
        let captured = OrderedProtocolCapture::from_canonical(
            &slot.value,
            OrderCaptureLimits {
                elements: maximum,
                bytes: maximum,
            },
        )?;
        if captured.namespace.tag() != namespace.tag() {
            return Err(ProfileDataError::Invalid("joint value namespace"));
        }
    }
    Ok(())
}

fn encode_joint(
    capture: &JointCapture,
    structural: bool,
    limits: JointCaptureLimits,
) -> Result<CanonicalValue, ProfileDataError> {
    if capture.slots.len() > limits.slots {
        return Err(ProfileDataError::LimitExceeded("joint slots"));
    }
    // Bound the complete input before collecting references or decoding components.
    let mut remaining = limits.bytes;
    for slot in &capture.slots {
        if slot.value.bytes.len() > limits.value_bytes {
            return Err(ProfileDataError::LimitExceeded("joint component bytes"));
        }
        remaining = remaining
            .checked_sub(slot.value.bytes.len())
            .ok_or(ProfileDataError::LimitExceeded("joint input bytes"))?;
        if slot.kind.level() != capture.level {
            return Err(ProfileDataError::Invalid(
                "connection/request slot ownership",
            ));
        }
    }
    let mut slots: Vec<_> = capture.slots.iter().collect();
    slots.sort_unstable_by_key(|slot| slot.kind);
    let mut writer = CanonicalWriter::new(
        if structural {
            JOINT_STRUCTURE_DOMAIN
        } else {
            JOINT_DOMAIN
        },
        limits.bytes,
    )?;
    writer.u8(capture.level.tag())?;
    writer.u64(slots.len() as u64)?;
    let mut previous = None;
    for slot in slots {
        if previous == Some(slot.kind) {
            return Err(ProfileDataError::Invalid("duplicate joint slot"));
        }
        validate_slot(slot, structural, limits.value_bytes)?;
        writer.u16(slot.kind.tag())?;
        writer.bytes(&slot.value.bytes)?;
        previous = Some(slot.kind);
    }
    Ok(writer.finish())
}

fn decode_joint(
    value: &CanonicalValue,
    structural: bool,
    limits: JointCaptureLimits,
) -> Result<JointCapture, ProfileDataError> {
    let domain = if structural {
        JOINT_STRUCTURE_DOMAIN
    } else {
        JOINT_DOMAIN
    };
    value.verify(domain, limits.bytes)?;
    let mut reader = CanonicalReader::new(&value.bytes, domain)?;
    let level = CaptureLevel::from_tag(reader.u8()?)?;
    let count = reader.count(limits.slots)?;
    let mut slots = Vec::new();
    let mut previous = None;
    for _ in 0..count {
        let kind = CapturedSlotKind::from_tag(reader.u16()?)?;
        if previous.is_some_and(|value| value >= kind) {
            return Err(ProfileDataError::Invalid("joint slot ordering"));
        }
        if kind.level() != level {
            return Err(ProfileDataError::Invalid(
                "connection/request slot ownership",
            ));
        }
        let bytes = reader.bytes(limits.value_bytes)?;
        let nested = CanonicalValue {
            id: ValueId(Sha256::digest(bytes).into()),
            bytes: bytes.into(),
        };
        let slot = CapturedSlot {
            kind,
            value: nested,
        };
        // Slot kinds admit only leaf domains, so nested tuples cannot cause recursive decoding.
        validate_slot(&slot, structural, limits.value_bytes)?;
        slots.push(slot);
        previous = Some(kind);
    }
    reader.finish()?;
    let capture = JointCapture {
        level,
        slots: slots.into(),
    };
    if encode_joint(&capture, structural, limits)?.bytes != value.bytes {
        return Err(ProfileDataError::Invalid("noncanonical joint capture"));
    }
    Ok(capture)
}

impl JointCapture {
    pub fn canonical(
        &self,
        limits: JointCaptureLimits,
    ) -> Result<CanonicalValue, ProfileDataError> {
        encode_joint(self, false, limits)
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        limits: JointCaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        decode_joint(value, false, limits)
    }

    /// Structural normalization changes the index, never the retained complete tuple.
    /// Header slots retain literal keys; numeric protocol orders use their owned normalizer.
    pub fn structural(
        &self,
        limits: JointCaptureLimits,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.canonical(limits)?;
        let slots = self
            .slots
            .iter()
            .map(|slot| {
                let value = if slot.kind.namespace().is_none() {
                    slot.value.clone()
                } else {
                    let order_limits = OrderCaptureLimits {
                        elements: limits.value_bytes,
                        bytes: limits.value_bytes,
                    };
                    OrderedProtocolCapture::from_canonical(&slot.value, order_limits)?
                        .structural(order_limits)?
                };
                Ok(CapturedSlot {
                    kind: slot.kind,
                    value,
                })
            })
            .collect::<Result<Box<[_]>, ProfileDataError>>()?;
        encode_joint(
            &Self {
                level: self.level,
                slots,
            },
            true,
            limits,
        )
    }
}

pub(super) fn validate_joint_structure(
    value: &CanonicalValue,
    maximum: usize,
) -> Result<(), ProfileDataError> {
    decode_joint(
        value,
        true,
        JointCaptureLimits {
            slots: maximum,
            value_bytes: maximum,
            bytes: maximum,
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
