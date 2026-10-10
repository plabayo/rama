use super::*;
use crate::profile::{
    CanonicalDomain, CanonicalValue,
    canonical::{CanonicalReader, CanonicalWriter},
};

pub(super) fn connection_owned(id: u16) -> bool {
    matches!(
        id,
        2 | 3
            | 5
            | 6
            | 7
            | 8
            | 12
            | 17
            | 25
            | 29
            | 30
            | 31
            | 32
            | 33
            | 35
            | 36
            | 37
            | 38
            | 44
            | 47
            | 48
            | 54
            | 55
            | 56
            | 57
            | 59
            | 51764
            | 65281
    )
}

impl TlsCapturedExtension {
    fn wire_length(&self) -> Result<usize, ProfileDataError> {
        let size = match &self.value {
            TlsCapturedExtensionValue::Literal(value) => value.len(),
            TlsCapturedExtensionValue::U16List(value) => {
                value.len() * 2
                    + match self.id {
                        28 => 0,
                        27 | 43 => 1,
                        _ => 2,
                    }
            }
            TlsCapturedExtensionValue::U8List(value) => value.len() + 1,
            TlsCapturedExtensionValue::Protocols(values) => {
                2 + values.iter().map(|value| value.len() + 1).sum::<usize>()
            }
            TlsCapturedExtensionValue::ServerNameLength(value) => {
                2 + value.map_or(0, |size| usize::from(size) + 3)
            }
            TlsCapturedExtensionValue::KeyShares(values) => {
                2 + values
                    .iter()
                    .map(|value| usize::from(value.length) + 4)
                    .sum::<usize>()
            }
            TlsCapturedExtensionValue::PreSharedKeys {
                identities,
                binders,
            } => {
                4 + identities
                    .iter()
                    .map(|size| usize::from(*size) + 6)
                    .sum::<usize>()
                    + binders
                        .iter()
                        .map(|size| usize::from(*size) + 1)
                        .sum::<usize>()
            }
            TlsCapturedExtensionValue::EchOuter { enc, payload, .. } => {
                10 + usize::from(*enc) + usize::from(*payload)
            }
            TlsCapturedExtensionValue::EchInner => 1,
            TlsCapturedExtensionValue::ConnectionLength(size) => usize::from(*size),
        };
        length(size)?;
        Ok(size + 4)
    }

    fn validate(&self, budget: &mut InputBudget) -> Result<(), ProfileDataError> {
        let valid = match &self.value {
            TlsCapturedExtensionValue::Literal(bytes) => {
                budget.take(0, bytes.len())?;
                length(bytes.len())?;
                if matches!(self.id, 18 | 22 | 23 | 42 | 49) && !bytes.is_empty() {
                    return Err(ProfileDataError::Invalid("nonempty TLS empty extension"));
                }
                if self.id == 21 && bytes.iter().any(|byte| *byte != 0) {
                    return Err(ProfileDataError::Invalid("TLS padding bytes"));
                }
                !connection_owned(self.id)
                    && !matches!(
                        self.id,
                        0 | 10
                            | 11
                            | 13
                            | 16
                            | 27
                            | 28
                            | 34
                            | 41
                            | 43
                            | 45
                            | 50
                            | 51
                            | 17513
                            | 17613
                            | 65037
                    )
            }
            TlsCapturedExtensionValue::U16List(values) => {
                budget.list(values.len(), 2)?;
                !values.is_empty()
                    && match self.id {
                        10 | 13 | 34 | 50 => values.len() <= usize::from(u16::MAX) / 2,
                        27 | 43 => values.len() <= usize::from(u8::MAX) / 2,
                        28 => values.len() == 1,
                        _ => false,
                    }
            }
            TlsCapturedExtensionValue::U8List(values) => {
                budget.list(values.len(), 1)?;
                !values.is_empty()
                    && values.len() <= usize::from(u8::MAX)
                    && matches!(self.id, 11 | 45)
            }
            TlsCapturedExtensionValue::Protocols(values) => {
                budget.take(values.len(), 0)?;
                let mut bytes = 0usize;
                for value in values {
                    if value.is_empty() || value.len() > usize::from(u8::MAX) {
                        return Err(ProfileDataError::Invalid("TLS application protocol"));
                    }
                    budget.take(0, value.len())?;
                    bytes = bytes
                        .checked_add(value.len() + 1)
                        .ok_or(ProfileDataError::LimitExceeded("TLS protocol vector"))?;
                }
                !values.is_empty()
                    && bytes <= usize::from(u16::MAX)
                    && matches!(self.id, 16 | 17513 | 17613)
            }
            TlsCapturedExtensionValue::ServerNameLength(size) => {
                budget.take(0, usize::from(size.unwrap_or(0)))?;
                self.id == 0 && size.is_none_or(|size| size != 0)
            }
            TlsCapturedExtensionValue::KeyShares(shapes) => {
                budget.take(shapes.len(), 2)?;
                let mut bytes = 0usize;
                for (index, shape) in shapes.iter().enumerate() {
                    budget.take(0, usize::from(shape.length) + 4)?;
                    bytes = bytes
                        .checked_add(usize::from(shape.length) + 4)
                        .ok_or(ProfileDataError::LimitExceeded("TLS key share vector"))?;
                    if shape.length == 0
                        || shapes[..index]
                            .iter()
                            .any(|previous| previous.group == shape.group)
                    {
                        return Err(ProfileDataError::Invalid("TLS key share shape"));
                    }
                }
                self.id == 51 && bytes <= usize::from(u16::MAX)
            }
            TlsCapturedExtensionValue::PreSharedKeys {
                identities,
                binders,
            } => {
                budget.take(identities.len(), 4)?;
                budget.take(binders.len(), 0)?;
                let mut identity_bytes = 0usize;
                let mut binder_bytes = 0usize;
                for size in identities {
                    if *size == 0 {
                        return Err(ProfileDataError::Invalid("TLS PSK identity shape"));
                    }
                    budget.take(0, usize::from(*size) + 6)?;
                    identity_bytes = identity_bytes
                        .checked_add(usize::from(*size) + 6)
                        .ok_or(ProfileDataError::LimitExceeded("TLS PSK identity vector"))?;
                }
                for size in binders {
                    if *size < 32 {
                        return Err(ProfileDataError::Invalid("TLS PSK binder shape"));
                    }
                    budget.take(0, usize::from(*size) + 1)?;
                    binder_bytes = binder_bytes
                        .checked_add(usize::from(*size) + 1)
                        .ok_or(ProfileDataError::LimitExceeded("TLS PSK binder vector"))?;
                }
                self.id == 41
                    && !identities.is_empty()
                    && identities.len() == binders.len()
                    && identity_bytes <= usize::from(u16::MAX)
                    && binder_bytes <= usize::from(u16::MAX)
            }
            TlsCapturedExtensionValue::EchOuter { enc, payload, .. } => {
                budget.take(0, usize::from(*enc))?;
                budget.take(0, usize::from(*payload))?;
                self.id == 65037
            }
            TlsCapturedExtensionValue::EchInner => self.id == 65037,
            TlsCapturedExtensionValue::ConnectionLength(size) => {
                budget.take(0, usize::from(*size))?;
                connection_owned(self.id)
            }
        };
        if !valid {
            return Err(ProfileDataError::Invalid("TLS extension capture ownership"));
        }
        Ok(())
    }
}

impl TlsCapture {
    pub(super) fn validate(&self, limits: TlsCaptureLimits) -> Result<(), ProfileDataError> {
        self.completeness
            .require_complete("TLS ClientHello observation")?;
        let mut budget = InputBudget {
            elements: limits.elements,
            bytes: limits.bytes,
        };
        budget.list(self.ciphers.len(), 2)?;
        budget.list(self.compression.len(), 1)?;
        budget.list(self.extensions.len(), 4)?;
        if self.ciphers.is_empty()
            || self.ciphers.len() > usize::from(u16::MAX) / 2
            || self.compression.is_empty()
            || self.compression.len() > usize::from(u8::MAX)
        {
            return Err(ProfileDataError::Invalid("TLS ClientHello list"));
        }
        let mut extension_bytes = 0usize;
        for (index, extension) in self.extensions.iter().enumerate() {
            if self.extensions[..index]
                .iter()
                .any(|previous| previous.id == extension.id)
            {
                return Err(ProfileDataError::Invalid("duplicate TLS extension"));
            }
            if extension.id == 41 && index + 1 != self.extensions.len() {
                return Err(ProfileDataError::Invalid("TLS PSK extension order"));
            }
            extension.validate(&mut budget)?;
            extension_bytes = extension_bytes
                .checked_add(extension.wire_length()?)
                .ok_or(ProfileDataError::LimitExceeded("TLS extensions vector"))?;
            length(extension_bytes)?;
        }
        Ok(())
    }

    pub fn canonical(&self, limits: TlsCaptureLimits) -> Result<CanonicalValue, ProfileDataError> {
        self.validate(limits)?;
        let mut writer = CanonicalWriter::new(CanonicalDomain::Tls, limits.bytes)?;
        writer.u8(match self.transport {
            TlsCaptureTransport::Tcp => 0,
            TlsCaptureTransport::Quic => 1,
        })?;
        writer.u8(self.completeness.tag())?;
        writer.u16(self.protocol_version)?;
        write_u16s(&mut writer, &self.ciphers)?;
        writer.bytes(&self.compression)?;
        writer.u64(self.extensions.len() as u64)?;
        for extension in &self.extensions {
            writer.u16(extension.id)?;
            write_value(&mut writer, &extension.value)?;
        }
        Ok(writer.finish())
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        limits: TlsCaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        value.verify(CanonicalDomain::Tls, limits.bytes)?;
        let mut reader = CanonicalReader::new(&value.bytes, CanonicalDomain::Tls)?;
        let transport = match reader.u8()? {
            0 => TlsCaptureTransport::Tcp,
            1 => TlsCaptureTransport::Quic,
            _ => return Err(ProfileDataError::Invalid("TLS capture transport")),
        };
        let completeness = ProfileCaptureCompleteness::from_tag(reader.u8()?)?;
        completeness.require_complete("TLS ClientHello observation")?;
        let protocol_version = reader.u16()?;
        let ciphers = read_u16s(&mut reader, limits.elements)?;
        let compression = reader.bytes(limits.elements)?.into();
        let count = reader.count(limits.elements)?;
        let mut extensions = Vec::new();
        for _ in 0..count {
            extensions.push(TlsCapturedExtension {
                id: reader.u16()?,
                value: read_value(&mut reader, limits)?,
            });
        }
        reader.finish()?;
        let capture = Self {
            completeness,
            transport,
            protocol_version,
            ciphers,
            compression,
            extensions: extensions.into(),
        };
        if capture.canonical(limits)?.bytes != value.bytes {
            return Err(ProfileDataError::Invalid("noncanonical TLS capture"));
        }
        Ok(capture)
    }
}

fn write_u16s(writer: &mut CanonicalWriter, values: &[u16]) -> Result<(), ProfileDataError> {
    writer.u64(values.len() as u64)?;
    for value in values {
        writer.u16(*value)?;
    }
    Ok(())
}
fn read_u16s(
    reader: &mut CanonicalReader<'_>,
    maximum: usize,
) -> Result<Box<[u16]>, ProfileDataError> {
    let count = reader.count(maximum)?;
    let mut values = Vec::new();
    for _ in 0..count {
        values.push(reader.u16()?);
    }
    Ok(values.into())
}
fn write_value(
    writer: &mut CanonicalWriter,
    value: &TlsCapturedExtensionValue,
) -> Result<(), ProfileDataError> {
    match value {
        TlsCapturedExtensionValue::Literal(bytes) => {
            writer.u8(0)?;
            writer.bytes(bytes)?;
        }
        TlsCapturedExtensionValue::U16List(values) => {
            writer.u8(1)?;
            write_u16s(writer, values)?;
        }
        TlsCapturedExtensionValue::U8List(values) => {
            writer.u8(2)?;
            writer.bytes(values)?;
        }
        TlsCapturedExtensionValue::Protocols(values) => {
            writer.u8(3)?;
            writer.u64(values.len() as u64)?;
            for value in values {
                writer.bytes(value)?;
            }
        }
        TlsCapturedExtensionValue::ServerNameLength(size) => {
            writer.u8(4)?;
            writer.u8(u8::from(size.is_some()))?;
            if let Some(size) = size {
                writer.u16(*size)?;
            }
        }
        TlsCapturedExtensionValue::KeyShares(values) => {
            writer.u8(5)?;
            writer.u64(values.len() as u64)?;
            for value in values {
                writer.u16(value.group)?;
                writer.u16(value.length)?;
            }
        }
        TlsCapturedExtensionValue::PreSharedKeys {
            identities,
            binders,
        } => {
            writer.u8(6)?;
            write_u16s(writer, identities)?;
            writer.bytes(binders)?;
        }
        TlsCapturedExtensionValue::EchOuter {
            kdf,
            aead,
            enc,
            payload,
        } => {
            writer.u8(7)?;
            writer.u16(*kdf)?;
            writer.u16(*aead)?;
            writer.u16(*enc)?;
            writer.u16(*payload)?;
        }
        TlsCapturedExtensionValue::EchInner => writer.u8(8)?,
        TlsCapturedExtensionValue::ConnectionLength(size) => {
            writer.u8(9)?;
            writer.u16(*size)?;
        }
    }
    Ok(())
}
fn read_value(
    reader: &mut CanonicalReader<'_>,
    limits: TlsCaptureLimits,
) -> Result<TlsCapturedExtensionValue, ProfileDataError> {
    Ok(match reader.u8()? {
        0 => TlsCapturedExtensionValue::Literal(reader.bytes(limits.bytes)?.into()),
        1 => TlsCapturedExtensionValue::U16List(read_u16s(reader, limits.elements)?),
        2 => TlsCapturedExtensionValue::U8List(reader.bytes(limits.elements)?.into()),
        3 => {
            let count = reader.count(limits.elements)?;
            let mut values = Vec::new();
            for _ in 0..count {
                values.push(reader.bytes(usize::from(u8::MAX))?.into());
            }
            TlsCapturedExtensionValue::Protocols(values.into())
        }
        4 => TlsCapturedExtensionValue::ServerNameLength(match reader.u8()? {
            0 => None,
            1 => Some(reader.u16()?),
            _ => return Err(ProfileDataError::Invalid("TLS server name shape")),
        }),
        5 => {
            let count = reader.count(limits.elements)?;
            let mut values = Vec::new();
            for _ in 0..count {
                values.push(TlsKeyShareShape {
                    group: reader.u16()?,
                    length: reader.u16()?,
                });
            }
            TlsCapturedExtensionValue::KeyShares(values.into())
        }
        6 => TlsCapturedExtensionValue::PreSharedKeys {
            identities: read_u16s(reader, limits.elements)?,
            binders: reader.bytes(limits.elements)?.into(),
        },
        7 => TlsCapturedExtensionValue::EchOuter {
            kdf: reader.u16()?,
            aead: reader.u16()?,
            enc: reader.u16()?,
            payload: reader.u16()?,
        },
        8 => TlsCapturedExtensionValue::EchInner,
        9 => TlsCapturedExtensionValue::ConnectionLength(reader.u16()?),
        _ => return Err(ProfileDataError::Invalid("TLS extension capture tag")),
    })
}
