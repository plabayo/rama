use rama_tls::{
    CipherSuite, ExtensionId, GREASE_PSK_KEY_EXCHANGE_MODE_FIRST, GREASE_U16_FIRST,
    ProtocolVersion, SignatureScheme, SupportedGroup, grease_u16, is_grease_psk_key_exchange_mode,
    is_grease_u16,
};
use sha2::{Digest as _, Sha256};

use crate::profile::capture::tls::{TlsCapture, TlsCaptureLimits, TlsCapturedExtensionValue};
use crate::profile::format::canonical::{
    CanonicalDomain, CanonicalReader, CanonicalValue, CanonicalWriter, ProfileDataError, ValueId,
};

fn normalize_grease(value: &mut u16, is_grease: impl Fn(u16) -> bool) {
    if is_grease(*value) {
        *value = GREASE_U16_FIRST;
    }
}

fn grease_representative(index: usize) -> Result<u16, ProfileDataError> {
    grease_u16(index).ok_or(ProfileDataError::LimitExceeded("TLS GREASE values"))
}

fn normalize_extension_list(extension: ExtensionId, values: &mut [u16]) {
    match extension {
        ExtensionId::SUPPORTED_GROUPS => {
            for value in values {
                normalize_grease(value, |value| SupportedGroup::from(value).is_grease());
            }
        }
        ExtensionId::SIGNATURE_ALGORITHMS
        | ExtensionId::DELEGATED_CREDENTIAL
        | ExtensionId::SIGNATURE_ALGORITHMS_CERT => {
            for value in values {
                normalize_grease(value, |value| SignatureScheme::from(value).is_grease());
            }
        }
        ExtensionId::SUPPORTED_VERSIONS => {
            for value in values {
                normalize_grease(value, |value| ProtocolVersion::from(value).is_grease());
            }
        }
        _ => {}
    }
}

impl TlsCapture {
    /// Groups order and reserved-value variation without assigning replay behavior.
    /// Complete captures retain the literal values and correlated original orders.
    pub fn structural(&self, limits: TlsCaptureLimits) -> Result<CanonicalValue, ProfileDataError> {
        self.validate(limits)?;
        let mut normalized = self.clone();

        for value in &mut normalized.ciphers {
            normalize_grease(value, |value| CipherSuite::from(value).is_grease());
        }
        normalized.ciphers.sort_unstable();
        normalized.compression.sort_unstable();

        let mut extension_count = 0;
        for extension in &mut normalized.extensions {
            let extension_id = ExtensionId::from(extension.id);
            if extension_id.is_grease() {
                extension.id = grease_representative(extension_count)?;
                extension_count += 1;
                extension.value = TlsCapturedExtensionValue::Literal(Box::default());
                continue;
            }

            match &mut extension.value {
                TlsCapturedExtensionValue::ConnectionLength(length) => *length = 0,
                TlsCapturedExtensionValue::PreSharedKeys { identities, .. } => identities.fill(1),
                TlsCapturedExtensionValue::EchOuter { payload, .. } => *payload = 0,
                TlsCapturedExtensionValue::U16List(values)
                    if extension_id != ExtensionId::RECORD_SIZE_LIMIT =>
                {
                    normalize_extension_list(extension_id, values);
                    values.sort_unstable();
                }
                TlsCapturedExtensionValue::U8List(values) => {
                    if extension_id == ExtensionId::PSK_KEY_EXCHANGE_MODES {
                        for value in &mut *values {
                            if is_grease_psk_key_exchange_mode(*value) {
                                *value = GREASE_PSK_KEY_EXCHANGE_MODE_FIRST;
                            }
                        }
                    }
                    values.sort_unstable();
                }
                TlsCapturedExtensionValue::Protocols(values) => {
                    for value in &mut *values {
                        if let [a, b] = value.as_ref()
                            && is_grease_u16(u16::from_be_bytes([*a, *b]))
                        {
                            *value = Box::new(GREASE_U16_FIRST.to_be_bytes());
                        }
                    }
                    values.sort_unstable();
                }
                TlsCapturedExtensionValue::KeyShares(values) => {
                    let mut count = 0;
                    for value in &mut *values {
                        if SupportedGroup::from(value.group).is_grease() {
                            value.group = grease_representative(count)?;
                            count += 1;
                            value.length = 1;
                        }
                    }
                    values.sort_unstable_by_key(|value| (value.group, value.length));
                }
                _ => (),
            }
        }

        normalized.extensions.sort_unstable_by_key(|extension| {
            (
                ExtensionId::from(extension.id) == ExtensionId::PRE_SHARED_KEY,
                extension.id,
            )
        });

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
