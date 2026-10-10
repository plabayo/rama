//! Protocol-owned order normalization precedes statistical classification.

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
            Self::QuicParameter => id < (1 << 62) && id % 31 == 27,
            Self::Http3Setting => {
                (0x21..(1 << 62)).contains(&id) && (id - 0x21).is_multiple_of(0x1f)
            }
            Self::QuicVersion => id <= u64::from(u32::MAX) && id & 0x0f0f_0f0f == 0x0a0a_0a0a,
        }
    }

    fn connection_owned(self, id: u64) -> bool {
        matches!(self, Self::QuicParameter) && matches!(id, 0 | 2 | 0x0d | 0x0f | 0x10)
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
        if field.id > limit || field.value.length() > limits.bytes {
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

/// Connection IDs, reset tokens and preferred addresses retain only their shape.
/// Literal ordering is also used to canonicalize structural multisets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ProtocolValue {
    Literal(Box<[u8]>),
    ConnectionLength(usize),
}

impl ProtocolValue {
    fn length(&self) -> usize {
        match self {
            Self::Literal(bytes) => bytes.len(),
            Self::ConnectionLength(length) => *length,
        }
    }

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
            1 => Ok(Self::ConnectionLength(reader.count(limits.bytes)?)),
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

    pub fn canonical(
        &self,
        limits: OrderCaptureLimits,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.completeness
            .require_complete("protocol order observation")?;
        if self.fields.len() > limits.elements {
            return Err(ProfileDataError::LimitExceeded("ordered elements"));
        }
        let mut writer = CanonicalWriter::new(ORDER_DOMAIN, limits.bytes)?;
        writer.u8(self.namespace.tag())?;
        writer.u8(self.completeness.tag())?;
        writer.u64(self.fields.len() as u64)?;
        for field in &self.fields {
            self.namespace.validate_field(field, limits)?;
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
    /// Literal semantic values, duplicate multiplicity and candidate lengths do.
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
                    StructureEntry::Reserved(field.value.length())
                } else {
                    StructureEntry::Literal(field.clone())
                }
            })
            .collect();
        entries.sort_unstable();
        encode_structure(self.namespace, &entries, limits)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum StructureEntry {
    Literal(OrderedProtocolField),
    Reserved(usize),
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
            StructureEntry::Reserved(length) => {
                writer.u8(1)?;
                writer.u64(*length as u64)?;
            }
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
                StructureEntry::Literal(field)
            }
            1 => {
                let length = reader.count(limits.bytes)?;
                match namespace {
                    OrderNamespace::Http3Setting if length != 8 => {
                        return Err(ProfileDataError::Invalid("reserved SETTINGS shape"));
                    }
                    OrderNamespace::QuicVersion if length != 0 => {
                        return Err(ProfileDataError::Invalid("reserved version shape"));
                    }
                    _ => (),
                }
                StructureEntry::Reserved(length)
            }
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

#[cfg(test)]
mod tests;
