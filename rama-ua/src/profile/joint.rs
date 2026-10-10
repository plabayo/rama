//! Complete component tuples retain observed cross-component correlations.

use rama_utils::octets::kib;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[cfg(feature = "tls")]
use super::{
    TlsCapture, TlsCaptureLimits, TlsCaptureTransport, tls_capture::structure::decode_tls_structure,
};

use super::{
    CanonicalDomain, CanonicalValue, H2Capture, H2CaptureLimits, HeaderCapture,
    HeaderCapturePolicy, OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture,
    ProfileCaptureCompleteness, ProfileDataError, PseudoHeaderCapture, QuicFlightCapture,
    QuicFlightCaptureLimits, RuntimeProfileCapture, ValueId,
    canonical::{
        CanonicalReader, CanonicalWriter, HEADER_DOMAIN, HEADER_STRUCTURE_DOMAIN, JOINT_DOMAIN,
        JOINT_STRUCTURE_DOMAIN, ORDER_STRUCTURE_DOMAIN,
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
    TcpTls,
    QuicTls,
    Http2EarlyFrames,
    PseudoHeaders,
    RuntimeMetadata,
    QuicFirstFlight,
}

impl CapturedSlotKind {
    fn tag(self) -> u16 {
        match self {
            Self::Headers => 0,
            Self::QuicParameters => 1,
            Self::Http3Settings => 2,
            Self::QuicVersions => 3,
            Self::TcpTls => 4,
            Self::QuicTls => 5,
            Self::Http2EarlyFrames => 6,
            Self::PseudoHeaders => 7,
            Self::RuntimeMetadata => 8,
            Self::QuicFirstFlight => 9,
        }
    }
    fn from_tag(tag: u16) -> Result<Self, ProfileDataError> {
        match tag {
            0 => Ok(Self::Headers),
            1 => Ok(Self::QuicParameters),
            2 => Ok(Self::Http3Settings),
            3 => Ok(Self::QuicVersions),
            4 => Ok(Self::TcpTls),
            5 => Ok(Self::QuicTls),
            6 => Ok(Self::Http2EarlyFrames),
            7 => Ok(Self::PseudoHeaders),
            8 => Ok(Self::RuntimeMetadata),
            9 => Ok(Self::QuicFirstFlight),
            _ => Err(ProfileDataError::Unsupported("joint slot kind")),
        }
    }
    fn level(self) -> CaptureLevel {
        match self {
            Self::Headers | Self::PseudoHeaders | Self::RuntimeMetadata => CaptureLevel::Request,
            _ => CaptureLevel::Connection,
        }
    }
    fn namespace(self) -> Option<OrderNamespace> {
        match self {
            Self::Headers
            | Self::QuicFirstFlight
            | Self::RuntimeMetadata
            | Self::PseudoHeaders
            | Self::TcpTls
            | Self::QuicTls
            | Self::Http2EarlyFrames => None,
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

impl CapturedSlot {
    /// The same owned normalization is used by joint and individual buckets.
    pub fn structural(&self, maximum_bytes: usize) -> Result<CanonicalValue, ProfileDataError> {
        validate_slot(self, false, maximum_bytes)?;
        if self.kind == CapturedSlotKind::QuicFirstFlight {
            let limits = QuicFlightCaptureLimits {
                bytes: maximum_bytes,
                ..QuicFlightCaptureLimits::default()
            };
            return QuicFlightCapture::from_canonical(&self.value, limits)?.structural(limits);
        }
        if self.kind == CapturedSlotKind::RuntimeMetadata {
            return RuntimeProfileCapture::from_canonical(&self.value, maximum_bytes)?
                .structural(maximum_bytes);
        }
        if self.kind == CapturedSlotKind::PseudoHeaders {
            return PseudoHeaderCapture::from_canonical(&self.value, maximum_bytes)?
                .structural(maximum_bytes);
        }
        if self.kind == CapturedSlotKind::Http2EarlyFrames {
            let limits = H2CaptureLimits {
                frames: maximum_bytes,
                settings: maximum_bytes,
                bytes: maximum_bytes,
            };
            return H2Capture::from_canonical(&self.value, limits)?.structural(limits);
        }
        if matches!(
            self.kind,
            CapturedSlotKind::TcpTls | CapturedSlotKind::QuicTls
        ) {
            #[cfg(feature = "tls")]
            {
                let limits = TlsCaptureLimits {
                    elements: maximum_bytes,
                    bytes: maximum_bytes,
                };
                return TlsCapture::from_canonical(&self.value, limits)?.structural(limits);
            }
            #[cfg(not(feature = "tls"))]
            return Err(ProfileDataError::Unsupported("TLS profile component"));
        }
        if self.kind == CapturedSlotKind::Headers {
            let policy = HeaderCapturePolicy {
                fields: maximum_bytes,
                bytes: maximum_bytes,
                overrides: Box::default(),
            };
            HeaderCapture::from_canonical(&self.value, &policy)?.structural(&policy)
        } else {
            let limits = OrderCaptureLimits {
                elements: maximum_bytes,
                bytes: maximum_bytes,
            };
            OrderedProtocolCapture::from_canonical(&self.value, limits)?.structural(limits)
        }
    }
}

#[derive(Debug, Clone)]
pub struct JointCapture {
    pub completeness: ProfileCaptureCompleteness,
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
    if matches!(
        slot.kind,
        CapturedSlotKind::TcpTls | CapturedSlotKind::QuicTls
    ) {
        #[cfg(feature = "tls")]
        {
            let capture = if structural {
                decode_tls_structure(&slot.value, maximum)?
            } else {
                TlsCapture::from_canonical(
                    &slot.value,
                    TlsCaptureLimits {
                        elements: maximum,
                        bytes: maximum,
                    },
                )?
            };
            if !matches!(
                (slot.kind, capture.transport),
                (CapturedSlotKind::TcpTls, TlsCaptureTransport::Tcp)
                    | (CapturedSlotKind::QuicTls, TlsCaptureTransport::Quic)
            ) {
                return Err(ProfileDataError::Invalid("joint TLS transport"));
            }
            return Ok(());
        }
        #[cfg(not(feature = "tls"))]
        return Err(ProfileDataError::Unsupported("TLS profile component"));
    }
    if slot.kind == CapturedSlotKind::QuicFirstFlight {
        return slot
            .value
            .validate_content(CanonicalDomain::QuicFlight, maximum);
    }
    if slot.kind == CapturedSlotKind::RuntimeMetadata {
        return slot.value.validate_content(
            if structural {
                CanonicalDomain::RuntimeMetadataStructure
            } else {
                CanonicalDomain::RuntimeMetadata
            },
            maximum,
        );
    }
    if slot.kind == CapturedSlotKind::PseudoHeaders {
        return slot.value.validate_content(
            if structural {
                CanonicalDomain::PseudoHeaderStructure
            } else {
                CanonicalDomain::PseudoHeaders
            },
            maximum,
        );
    }
    if slot.kind == CapturedSlotKind::Http2EarlyFrames {
        return slot.value.validate_content(
            if structural {
                CanonicalDomain::H2Structure
            } else {
                CanonicalDomain::H2
            },
            maximum,
        );
    }
    let Some(namespace) = slot.kind.namespace() else {
        return slot.value.validate_content(
            if structural {
                HEADER_STRUCTURE_DOMAIN
            } else {
                HEADER_DOMAIN
            },
            maximum,
        );
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
    capture.completeness.require_complete("joint observation")?;
    if capture.slots.len() > limits.slots {
        return Err(ProfileDataError::LimitExceeded("joint slots"));
    }
    // Bound the complete input before collecting references or decoding components.
    let mut remaining = limits.bytes;
    let mut transport = None;
    for slot in &capture.slots {
        let current = match slot.kind {
            CapturedSlotKind::Headers
            | CapturedSlotKind::PseudoHeaders
            | CapturedSlotKind::RuntimeMetadata => None,
            CapturedSlotKind::TcpTls | CapturedSlotKind::Http2EarlyFrames => Some(0),
            CapturedSlotKind::QuicFirstFlight
            | CapturedSlotKind::QuicTls
            | CapturedSlotKind::QuicParameters
            | CapturedSlotKind::Http3Settings
            | CapturedSlotKind::QuicVersions => Some(1),
        };
        if let Some(current) = current {
            if transport.is_some_and(|previous| previous != current) {
                return Err(ProfileDataError::Invalid("mixed connection transports"));
            }
            transport = Some(current);
        }
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
    writer.u8(capture.completeness.tag())?;
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
    let completeness = ProfileCaptureCompleteness::from_tag(reader.u8()?)?;
    completeness.require_complete("joint observation")?;
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
        completeness,
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
    /// Each component uses its owned normalizer and a separate structural namespace.
    pub fn structural(
        &self,
        limits: JointCaptureLimits,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.canonical(limits)?;
        let slots = self
            .slots
            .iter()
            .map(|slot| {
                let value = slot.structural(limits.value_bytes)?;
                Ok(CapturedSlot {
                    kind: slot.kind,
                    value,
                })
            })
            .collect::<Result<Box<[_]>, ProfileDataError>>()?;
        encode_joint(
            &Self {
                completeness: self.completeness,
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
