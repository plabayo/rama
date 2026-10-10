use rama_tls::ExtensionId;
use sha2::{Digest as _, Sha256};

use super::{TlsCapture, TlsCaptureLimits, TlsCapturedExtensionValue};
use crate::profile::{
    CanonicalDomain, CanonicalValue, ProfileDataError, ValueId,
    canonical::{CanonicalReader, CanonicalWriter},
};

fn reserved(value: u16) -> bool {
    ExtensionId::from(value).is_grease()
}
fn normalize(value: &mut u16) {
    if reserved(*value) {
        *value = 0x0a0a;
    }
}
fn representative(index: u16) -> u16 {
    0x0a0a + 0x1010 * index
}

impl TlsCapture {
    /// Groups order and reserved-value variation without assigning replay behavior.
    /// Complete captures retain the literal values and correlated original orders.
    pub fn structural(&self, limits: TlsCaptureLimits) -> Result<CanonicalValue, ProfileDataError> {
        self.validate(limits)?;
        let mut normalized = self.clone();
        for value in &mut normalized.ciphers {
            normalize(value);
        }
        normalized.ciphers.sort_unstable();
        normalized.compression.sort_unstable();
        let mut extension_count = 0;
        for extension in &mut normalized.extensions {
            if reserved(extension.id) {
                extension.id = representative(extension_count);
                extension_count += 1;
                extension.value = TlsCapturedExtensionValue::Literal(Box::default());
                continue;
            }
            match &mut extension.value {
                TlsCapturedExtensionValue::ConnectionLength(length) => *length = 0,
                TlsCapturedExtensionValue::PreSharedKeys { identities, .. } => identities.fill(1),
                TlsCapturedExtensionValue::EchOuter { payload, .. } => *payload = 0,
                TlsCapturedExtensionValue::U16List(values) if extension.id != 28 => {
                    if matches!(extension.id, 10 | 13 | 34 | 43 | 50) {
                        for value in &mut *values {
                            normalize(value);
                        }
                    }
                    values.sort_unstable();
                }
                TlsCapturedExtensionValue::U8List(values) => {
                    if extension.id == 45 {
                        for value in &mut *values {
                            if matches!(
                                *value,
                                0x0b | 0x2a | 0x49 | 0x68 | 0x87 | 0xa6 | 0xc5 | 0xe4
                            ) {
                                *value = 0x0b;
                            }
                        }
                    }
                    values.sort_unstable();
                }
                TlsCapturedExtensionValue::Protocols(values) => {
                    for value in &mut *values {
                        if let [a, b] = value.as_ref()
                            && reserved(u16::from_be_bytes([*a, *b]))
                        {
                            *value = Box::new([0x0a, 0x0a]);
                        }
                    }
                    values.sort_unstable();
                }
                TlsCapturedExtensionValue::KeyShares(values) => {
                    let mut count = 0;
                    for value in &mut *values {
                        if reserved(value.group) {
                            value.group = representative(count);
                            count += 1;
                            value.length = 1;
                        }
                    }
                    values.sort_unstable_by_key(|value| (value.group, value.length));
                }
                _ => (),
            }
        }
        normalized
            .extensions
            .sort_unstable_by_key(|extension| (extension.id == 41, extension.id));
        let inner = normalized.canonical(limits)?;
        let mut writer = CanonicalWriter::new(CanonicalDomain::TlsStructure, limits.bytes)?;
        writer.bytes(&inner.bytes)?;
        Ok(writer.finish())
    }
}

pub(in crate::profile) fn decode_tls_structure(
    value: &CanonicalValue,
    maximum_bytes: usize,
) -> Result<TlsCapture, ProfileDataError> {
    value.verify(CanonicalDomain::TlsStructure, maximum_bytes)?;
    let mut reader = CanonicalReader::new(&value.bytes, CanonicalDomain::TlsStructure)?;
    let bytes = reader.bytes(maximum_bytes)?;
    let inner = CanonicalValue {
        id: ValueId(Sha256::digest(bytes).into()),
        bytes: bytes.into(),
    };
    reader.finish()?;
    let limits = TlsCaptureLimits {
        elements: maximum_bytes,
        bytes: maximum_bytes,
    };
    let capture = TlsCapture::from_canonical(&inner, limits)?;
    if capture.structural(limits)?.bytes != value.bytes {
        return Err(ProfileDataError::Invalid("noncanonical TLS structure"));
    }
    Ok(capture)
}

pub(in crate::profile) fn validate_tls_structure(
    value: &CanonicalValue,
    maximum_bytes: usize,
) -> Result<(), ProfileDataError> {
    decode_tls_structure(value, maximum_bytes)?;
    Ok(())
}
