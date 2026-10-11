//! Protocol-owned order normalization precedes statistical classification.

use rama_http::proto::h3::SettingId;
use rama_quic_proto::{Version, profile::ParameterId, version::VersionInformation};
use rama_utils::octets::kib;
use serde::Serialize;

use super::{
    CanonicalValue, ProfileCaptureCompleteness, ProfileDataError,
    canonical::{CanonicalReader, CanonicalWriter, ORDER_DOMAIN, ORDER_STRUCTURE_DOMAIN},
};

#[derive(Debug, Clone, Copy, Serialize)]
pub enum OrderNamespace {
    QuicParameter,
    Http3Setting,
    QuicVersion,
}

impl OrderNamespace {
    pub(super) fn tag(self) -> u8 {
        match self {
            Self::QuicParameter => 0,
            Self::Http3Setting => 1,
            Self::QuicVersion => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ProfileDataError> {
        match tag {
            0 => Ok(Self::QuicParameter),
            1 => Ok(Self::Http3Setting),
            2 => Ok(Self::QuicVersion),
            _ => Err(ProfileDataError::Invalid("order namespace")),
        }
    }

    /// Namespace membership is only a candidate marker, never a generation rule.
    #[must_use]
    pub fn reserved_candidate(self, id: u64) -> bool {
        match self {
            Self::QuicParameter => id < (1 << 62) && ParameterId(id).is_reserved(),
            Self::Http3Setting => id < (1 << 62) && SettingId::new(id).is_reserved(),
            Self::QuicVersion => {
                u32::try_from(id).is_ok_and(|id| Version::from_u32(id).is_reserved())
            }
        }
    }

    fn connection_owned(self, id: u64) -> bool {
        // Transport bindings, opaque handshake messages (0x26ab/0x4751), and debugging
        // SNI (0x219bbcd0) belong to the connection, not a reusable profile.
        matches!(self, Self::QuicParameter)
            && matches!(
                id,
                0 | 2 | 0x0d | 0x0f | 0x10 | 0x26ab | 0x4751 | 0x219bbcd0
            )
    }

    fn connection_value(self, id: u64) -> bool {
        // Cached RTT (0x3127) is a path measurement; discard padding (0x173e)
        // has no transport semantics. Keep their literal samples for analysis,
        // but only their presence in a structure. Capability/configuration
        // values, including Google's connection options (0x3128), stay literal.
        matches!(self, Self::QuicParameter) && matches!(id, 0x3127 | 0x173e)
    }

    fn validate_field(
        self,
        field: &OrderedProtocolField,
        limits: OrderCaptureLimits,
    ) -> Result<(), ProfileDataError> {
        let limit = match self {
            Self::QuicVersion => u64::from(u32::MAX),
            Self::QuicParameter | Self::Http3Setting => (1 << 62) - 1,
        };
        if field.id > limit
            || match &field.value {
                ProtocolValue::Literal(bytes) => bytes.len() > limits.bytes,
                // Redacted transport bindings retain a scalar, not the wire payload.
                ProtocolValue::ConnectionLength(length) => *length > usize::from(u16::MAX),
            }
        {
            return Err(ProfileDataError::LimitExceeded("ordered protocol field"));
        }
        if self.connection_owned(field.id)
            != matches!(field.value, ProtocolValue::ConnectionLength(_))
        {
            return Err(ProfileDataError::Invalid("protocol value ownership"));
        }
        match (self, &field.value) {
            (Self::Http3Setting, ProtocolValue::Literal(bytes)) => {
                let bytes: [u8; 8] = bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_error| ProfileDataError::Invalid("SETTINGS value encoding"))?;
                if u64::from_be_bytes(bytes) >= (1 << 62) {
                    return Err(ProfileDataError::Invalid("SETTINGS value range"));
                }
            }
            (Self::QuicParameter, ProtocolValue::Literal(bytes)) if field.id == 0x11 => {
                version_information(bytes, limits)?;
            }
            (Self::QuicVersion, ProtocolValue::Literal(bytes)) if !bytes.is_empty() => {
                return Err(ProfileDataError::Invalid("QUIC version payload"));
            }
            _ => (),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OrderCaptureLimits {
    pub elements: usize,
    pub bytes: usize,
}

impl Default for OrderCaptureLimits {
    fn default() -> Self {
        Self {
            elements: 256,
            bytes: kib(16),
        }
    }
}

/// Transport bindings and opaque handshake messages retain only their shape.
/// Literal ordering is also used to canonicalize structural multisets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ProtocolValue {
    Literal(Box<[u8]>),
    ConnectionLength(usize),
}

impl ProtocolValue {
    fn encode(&self, writer: &mut CanonicalWriter) -> Result<(), ProfileDataError> {
        match self {
            Self::Literal(bytes) => {
                writer.u8(0)?;
                writer.bytes(bytes)
            }
            Self::ConnectionLength(length) => {
                writer.u8(1)?;
                writer.u64(*length as u64)
            }
        }
    }

    fn decode(
        reader: &mut CanonicalReader<'_>,
        limits: OrderCaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        match reader.u8()? {
            0 => Ok(Self::Literal(reader.bytes(limits.bytes)?.into())),
            1 => Ok(Self::ConnectionLength(reader.count(usize::from(u16::MAX))?)),
            _ => Err(ProfileDataError::Invalid("protocol value tag")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct OrderedProtocolField {
    pub id: u64,
    pub value: ProtocolValue,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrderedProtocolCapture {
    pub completeness: ProfileCaptureCompleteness,
    pub namespace: OrderNamespace,
    pub fields: Box<[OrderedProtocolField]>,
}

impl OrderedProtocolCapture {
    /// Values for SETTINGS use eight-byte big-endian integers; version values are empty.
    /// Source completeness is required before iterating or retaining available fields.
    pub fn capture<B: AsRef<[u8]>>(
        completeness: ProfileCaptureCompleteness,
        namespace: OrderNamespace,
        input: impl IntoIterator<Item = (u64, B)>,
        limits: OrderCaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        completeness.require_complete("protocol order observation")?;
        let mut fields = Vec::new();
        let mut remaining = limits.bytes;
        for (id, bytes) in input {
            if fields.len() >= limits.elements {
                return Err(ProfileDataError::LimitExceeded("ordered elements"));
            }
            let bytes = bytes.as_ref();
            remaining = remaining
                .checked_sub(8)
                .and_then(|n| n.checked_sub(bytes.len()))
                .ok_or(ProfileDataError::LimitExceeded("ordered input bytes"))?;
            let value = if namespace.connection_owned(id) {
                ProtocolValue::ConnectionLength(bytes.len())
            } else {
                ProtocolValue::Literal(bytes.into())
            };
            let field = OrderedProtocolField { id, value };
            namespace.validate_field(&field, limits)?;
            fields.push(field);
        }
        let captured = Self {
            completeness,
            namespace,
            fields: fields.into(),
        };
        captured.canonical(limits)?;
        Ok(captured)
    }

    // Nested formats share semantic validation without allocating an unrelated
    // canonical envelope or charging its overhead to their own encoding budget.
    pub(super) fn validate_fields(
        &self,
        limits: OrderCaptureLimits,
    ) -> Result<(), ProfileDataError> {
        self.completeness
            .require_complete("protocol order observation")?;
        if self.fields.len() > limits.elements {
            return Err(ProfileDataError::LimitExceeded("ordered elements"));
        }
        for field in &self.fields {
            self.namespace.validate_field(field, limits)?;
        }
        Ok(())
    }

    pub fn canonical(
        &self,
        limits: OrderCaptureLimits,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.validate_fields(limits)?;
        let mut writer = CanonicalWriter::new(ORDER_DOMAIN, limits.bytes)?;
        writer.u8(self.namespace.tag())?;
        writer.u8(self.completeness.tag())?;
        writer.u64(self.fields.len() as u64)?;
        for field in &self.fields {
            writer.u64(field.id)?;
            field.value.encode(&mut writer)?;
        }
        Ok(writer.finish())
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        limits: OrderCaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        value.verify(ORDER_DOMAIN, limits.bytes)?;
        let mut reader = CanonicalReader::new(&value.bytes, ORDER_DOMAIN)?;
        let namespace = OrderNamespace::from_tag(reader.u8()?)?;
        let completeness = ProfileCaptureCompleteness::from_tag(reader.u8()?)?;
        completeness.require_complete("protocol order observation")?;
        let count = reader.count(limits.elements)?;
        let mut fields = Vec::new();
        for _ in 0..count {
            let field = OrderedProtocolField {
                id: reader.u64()?,
                value: ProtocolValue::decode(&mut reader, limits)?,
            };
            namespace.validate_field(&field, limits)?;
            fields.push(field);
        }
        reader.finish()?;
        let captured = Self {
            completeness,
            namespace,
            fields: fields.into(),
        };
        if captured.canonical(limits)?.bytes != value.bytes {
            return Err(ProfileDataError::Invalid("noncanonical protocol order"));
        }
        Ok(captured)
    }

    /// Order and reserved-candidate identifiers do not multiply structural rows.
    /// Literal semantic choices and duplicate multiplicity remain in the key.
    /// Complete samples retain path measurements, padding and nested version ordering.
    pub fn structural(
        &self,
        limits: OrderCaptureLimits,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.canonical(limits)?;
        let mut entries: Vec<_> = self
            .fields
            .iter()
            .map(|field| {
                if self.namespace.reserved_candidate(field.id) {
                    Ok(StructureEntry::Reserved)
                } else {
                    Ok(StructureEntry::Literal(normalized_field(
                        self.namespace,
                        field,
                        limits,
                    )?))
                }
            })
            .collect::<Result<Vec<_>, ProfileDataError>>()?;
        entries.sort_unstable();
        encode_structure(self.namespace, &entries, limits)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum StructureEntry {
    Literal(OrderedProtocolField),
    Reserved,
}

fn encode_structure(
    namespace: OrderNamespace,
    entries: &[StructureEntry],
    limits: OrderCaptureLimits,
) -> Result<CanonicalValue, ProfileDataError> {
    let mut writer = CanonicalWriter::new(ORDER_STRUCTURE_DOMAIN, limits.bytes)?;
    writer.u8(namespace.tag())?;
    writer.u64(entries.len() as u64)?;
    for entry in entries {
        match entry {
            StructureEntry::Literal(field) => {
                writer.u8(0)?;
                writer.u64(field.id)?;
                field.value.encode(&mut writer)?;
            }
            StructureEntry::Reserved => writer.u8(1)?,
        }
    }
    Ok(writer.finish())
}

pub(super) fn validate_structure(
    value: &CanonicalValue,
    maximum_bytes: usize,
) -> Result<(), ProfileDataError> {
    value.verify(ORDER_STRUCTURE_DOMAIN, maximum_bytes)?;
    let limits = OrderCaptureLimits {
        elements: maximum_bytes,
        bytes: maximum_bytes,
    };
    let mut reader = CanonicalReader::new(&value.bytes, ORDER_STRUCTURE_DOMAIN)?;
    let namespace = OrderNamespace::from_tag(reader.u8()?)?;
    let count = reader.count(limits.elements)?;
    let mut entries = Vec::new();
    for _ in 0..count {
        let entry = match reader.u8()? {
            0 => {
                let field = OrderedProtocolField {
                    id: reader.u64()?,
                    value: ProtocolValue::decode(&mut reader, limits)?,
                };
                namespace.validate_field(&field, limits)?;
                if namespace.reserved_candidate(field.id) {
                    return Err(ProfileDataError::Invalid("literal reserved structural key"));
                }
                if normalized_field(namespace, &field, limits)? != field {
                    return Err(ProfileDataError::Invalid("unnormalized protocol structure"));
                }
                StructureEntry::Literal(field)
            }
            1 => StructureEntry::Reserved,
            _ => return Err(ProfileDataError::Invalid("structural element tag")),
        };
        if entries.last().is_some_and(|previous| previous > &entry) {
            return Err(ProfileDataError::Invalid("structural ordering"));
        }
        entries.push(entry);
    }
    reader.finish()?;
    if encode_structure(namespace, &entries, limits)?.bytes != value.bytes {
        return Err(ProfileDataError::Invalid("noncanonical structural key"));
    }
    Ok(())
}

fn version_information(
    bytes: &[u8],
    limits: OrderCaptureLimits,
) -> Result<VersionInformation, ProfileDataError> {
    if bytes.len() / 4 > limits.elements {
        return Err(ProfileDataError::LimitExceeded("QUIC version information"));
    }
    VersionInformation::read(true, bytes.len(), &mut &bytes[..])
        .map_err(|_error| ProfileDataError::Invalid("QUIC version information"))
}

fn normalized_field(
    namespace: OrderNamespace,
    field: &OrderedProtocolField,
    limits: OrderCaptureLimits,
) -> Result<OrderedProtocolField, ProfileDataError> {
    let value = match &field.value {
        ProtocolValue::ConnectionLength(_) => ProtocolValue::ConnectionLength(0),
        ProtocolValue::Literal(_) if namespace.connection_value(field.id) => {
            ProtocolValue::Literal(Box::default())
        }
        ProtocolValue::Literal(bytes)
            if matches!(namespace, OrderNamespace::QuicParameter) && field.id == 0x11 =>
        {
            let versions = version_information(bytes, limits)?;
            let chosen = versions.chosen();
            let mut available: Vec<_> = versions
                .available()
                .iter()
                .map(|version| {
                    if version.is_reserved() && *version != chosen {
                        Version::from_u32(0x0a0a0a0a)
                    } else {
                        *version
                    }
                })
                .collect();
            // Keep known-version preference order; only reserved placement is a draw.
            available.sort_by_key(|version| version.is_reserved() && *version != chosen);
            let mut bytes = Vec::new();
            VersionInformation::new(chosen, available).write(&mut bytes);
            ProtocolValue::Literal(bytes.into())
        }
        value @ ProtocolValue::Literal(_) => value.clone(),
    };
    Ok(OrderedProtocolField {
        id: field.id,
        value,
    })
}

#[cfg(test)]
mod tests;
