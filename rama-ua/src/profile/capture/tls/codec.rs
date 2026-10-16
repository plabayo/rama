use super::*;
use crate::profile::format::canonical::{
    CanonicalDomain, CanonicalReader, CanonicalValue, CanonicalWriter,
};
use rama_tls::{ExtensionId, client::client_hello_extension_is_connection_bound};

impl TlsCapturedExtension {
    fn wire_length(&self) -> Result<usize, ProfileDataError> {
        let size = match &self.value {
            TlsCapturedExtensionValue::Literal(value) => value.len(),
            TlsCapturedExtensionValue::U16List(value) => {
                value.len() * 2
                    + match ExtensionId::from(self.id) {
                        ExtensionId::RECORD_SIZE_LIMIT => 0,
                        ExtensionId::COMPRESS_CERTIFICATE | ExtensionId::SUPPORTED_VERSIONS => 1,
                        _ => 2,
                    }
            }
            TlsCapturedExtensionValue::U8List(value) => value.len() + 1,
            TlsCapturedExtensionValue::Protocols(values) => {
                2 + values.iter().map(|value| value.len() + 1).sum::<usize>()
            }
            // Only a minimum shape remains for destination-owned SNI.
            TlsCapturedExtensionValue::ServerName { present } => {
                if *present {
                    6
                } else {
                    2
                }
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

    // Canonical budgets charge retained shapes. The borrowed capture path bounds
    // original wire payloads; wire_length independently enforces TLS vector limits.
    fn validate(&self, budget: &mut InputBudget) -> Result<(), ProfileDataError> {
        let valid = match &self.value {
            TlsCapturedExtensionValue::Literal(bytes) => {
                budget.take(0, bytes.len())?;
                length(bytes.len())?;
                let id = ExtensionId::from(self.id);
                if matches!(
                    id,
                    ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP
                        | ExtensionId::ENCRYPT_THEN_MAC
                        | ExtensionId::EXTENDED_MASTER_SECRET
                        | ExtensionId::EARLY_DATA
                        | ExtensionId::POST_HANDSHAKE_AUTH
                ) && !bytes.is_empty()
                {
                    return Err(ProfileDataError::Invalid("nonempty TLS empty extension"));
                }
                !client_hello_extension_is_connection_bound(id)
                    && !matches!(
                        id,
                        ExtensionId::SERVER_NAME
                            | ExtensionId::SUPPORTED_GROUPS
                            | ExtensionId::EC_POINT_FORMATS
                            | ExtensionId::SIGNATURE_ALGORITHMS
                            | ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
                            | ExtensionId::COMPRESS_CERTIFICATE
                            | ExtensionId::RECORD_SIZE_LIMIT
                            | ExtensionId::DELEGATED_CREDENTIAL
                            | ExtensionId::PRE_SHARED_KEY
                            | ExtensionId::SUPPORTED_VERSIONS
                            | ExtensionId::PSK_KEY_EXCHANGE_MODES
                            | ExtensionId::SIGNATURE_ALGORITHMS_CERT
                            | ExtensionId::KEY_SHARE
                            | ExtensionId::OLD_APPLICATION_SETTINGS
                            | ExtensionId::APPLICATION_SETTINGS
                            | ExtensionId::ENCRYPTED_CLIENT_HELLO
                    )
            }
            TlsCapturedExtensionValue::U16List(values) => {
                budget.list(values.len(), 2)?;
                !values.is_empty()
                    && match ExtensionId::from(self.id) {
                        ExtensionId::SUPPORTED_GROUPS
                        | ExtensionId::SIGNATURE_ALGORITHMS
                        | ExtensionId::DELEGATED_CREDENTIAL
                        | ExtensionId::SIGNATURE_ALGORITHMS_CERT => {
                            values.len() <= usize::from(u16::MAX) / 2
                        }
                        ExtensionId::COMPRESS_CERTIFICATE | ExtensionId::SUPPORTED_VERSIONS => {
                            values.len() <= usize::from(u8::MAX) / 2
                        }
                        ExtensionId::RECORD_SIZE_LIMIT => values.len() == 1,
                        _ => false,
                    }
            }
            TlsCapturedExtensionValue::U8List(values) => {
                budget.list(values.len(), 1)?;
                !values.is_empty()
                    && values.len() <= usize::from(u8::MAX)
                    && matches!(
                        ExtensionId::from(self.id),
                        ExtensionId::EC_POINT_FORMATS | ExtensionId::PSK_KEY_EXCHANGE_MODES
                    )
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
                    && matches!(
                        ExtensionId::from(self.id),
                        ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
                            | ExtensionId::OLD_APPLICATION_SETTINGS
                            | ExtensionId::APPLICATION_SETTINGS
                    )
            }
            TlsCapturedExtensionValue::ServerName { .. } => {
                ExtensionId::from(self.id) == ExtensionId::SERVER_NAME
            }
            TlsCapturedExtensionValue::KeyShares(shapes) => {
                budget.take(shapes.len(), 2)?;
                let mut bytes = 0usize;
                for (index, shape) in shapes.iter().enumerate() {
                    budget.take(0, 4)?;
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
                ExtensionId::from(self.id) == ExtensionId::KEY_SHARE
                    && bytes <= usize::from(u16::MAX)
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
                    budget.take(0, 2)?;
                    identity_bytes = identity_bytes
                        .checked_add(usize::from(*size) + 6)
                        .ok_or(ProfileDataError::LimitExceeded("TLS PSK identity vector"))?;
                }
                for size in binders {
                    if *size < 32 {
                        return Err(ProfileDataError::Invalid("TLS PSK binder shape"));
                    }
                    budget.take(0, 1)?;
                    binder_bytes = binder_bytes
                        .checked_add(usize::from(*size) + 1)
                        .ok_or(ProfileDataError::LimitExceeded("TLS PSK binder vector"))?;
                }
                ExtensionId::from(self.id) == ExtensionId::PRE_SHARED_KEY
                    && !identities.is_empty()
                    && identities.len() == binders.len()
                    && identity_bytes <= usize::from(u16::MAX)
                    && binder_bytes <= usize::from(u16::MAX)
            }
            TlsCapturedExtensionValue::EchOuter { .. } => {
                budget.take(0, 8)?;
                ExtensionId::from(self.id) == ExtensionId::ENCRYPTED_CLIENT_HELLO
            }
            TlsCapturedExtensionValue::EchInner => {
                ExtensionId::from(self.id) == ExtensionId::ENCRYPTED_CLIENT_HELLO
            }
            TlsCapturedExtensionValue::ConnectionLength(size) => {
                budget.take(0, 2)?;
                let id = ExtensionId::from(self.id);
                client_hello_extension_is_connection_bound(id)
                    && (id != ExtensionId::PADDING || *size == 0)
            }
        };
        if !valid {
            return Err(ProfileDataError::Invalid("TLS extension capture ownership"));
        }
        Ok(())
    }
}

impl TlsCapture {
    /// Validate completeness, ownership and resource limits without serialization.
    pub fn validate_fields(&self, limits: TlsCaptureLimits) -> Result<(), ProfileDataError> {
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
            if ExtensionId::from(extension.id) == ExtensionId::PRE_SHARED_KEY
                && index + 1 != self.extensions.len()
            {
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
        self.validate_fields(limits)?;
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
        TlsCapturedExtensionValue::ServerName { present } => {
            writer.u8(4)?;
            writer.u8(u8::from(*present))?;
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
        4 => TlsCapturedExtensionValue::ServerName {
            present: match reader.u8()? {
                0 => false,
                1 => true,
                _ => return Err(ProfileDataError::Invalid("TLS server name shape")),
            },
        },
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
