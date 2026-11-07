use rama_tls::{ExtensionId, grease_u16, is_grease_u16};

use crate::profile::{
    capture::tls::{TlsCapture, TlsCapturedExtensionValue},
    format::canonical::ProfileDataError,
};

/// The `index`th GREASE slot of a list.
fn placeholder(index: usize) -> Result<u16, ProfileDataError> {
    grease_u16(index).ok_or(ProfileDataError::LimitExceeded("TLS GREASE slots"))
}

/// Number each GREASE value of `values` by its slot in the list.
fn number_slots<'a>(values: impl Iterator<Item = &'a mut u16>) -> Result<(), ProfileDataError> {
    for (index, value) in values.filter(|value| is_grease_u16(**value)).enumerate() {
        *value = placeholder(index)?;
    }
    Ok(())
}

impl TlsCapture {
    /// Replace GREASE values by numbered slots, the form profiles read and replay draws for.
    pub fn with_grease_placeholders(mut self) -> Result<Self, ProfileDataError> {
        number_slots(self.ciphers.iter_mut())?;
        number_slots(
            self.extensions
                .iter_mut()
                .map(|extension| &mut extension.id),
        )?;
        for extension in &mut self.extensions {
            match (ExtensionId::from(extension.id), &mut extension.value) {
                (
                    ExtensionId::SUPPORTED_GROUPS
                    | ExtensionId::SIGNATURE_ALGORITHMS
                    | ExtensionId::DELEGATED_CREDENTIAL
                    | ExtensionId::SIGNATURE_ALGORITHMS_CERT
                    | ExtensionId::SUPPORTED_VERSIONS,
                    TlsCapturedExtensionValue::U16List(values),
                ) => number_slots(values.iter_mut())?,
                (ExtensionId::KEY_SHARE, TlsCapturedExtensionValue::KeyShares(shares)) => {
                    number_slots(shares.iter_mut().map(|share| &mut share.group))?;
                }
                _ => {}
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use rama_tls::GREASE_U16_FIRST;

    use super::*;
    use crate::profile::capture::{
        completeness::ProfileCaptureCompleteness,
        tls::{TlsCaptureLimits, TlsCaptureTransport, TlsCapturedExtension, TlsKeyShareShape},
    };

    fn capture(grease: [u16; 4]) -> TlsCapture {
        let [cipher, extension, group, last_extension] = grease;
        TlsCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            transport: TlsCaptureTransport::Tcp,
            protocol_version: 0x0303,
            ciphers: vec![cipher, 0x1301, 0x1302].into(),
            compression: vec![0].into(),
            extensions: vec![
                TlsCapturedExtension {
                    id: extension,
                    value: TlsCapturedExtensionValue::Literal(Box::default()),
                },
                TlsCapturedExtension {
                    id: u16::from(ExtensionId::SUPPORTED_GROUPS),
                    value: TlsCapturedExtensionValue::U16List(vec![group, 0x001d].into()),
                },
                TlsCapturedExtension {
                    id: u16::from(ExtensionId::KEY_SHARE),
                    value: TlsCapturedExtensionValue::KeyShares(
                        vec![
                            TlsKeyShareShape { group, length: 1 },
                            TlsKeyShareShape {
                                group: 0x001d,
                                length: 32,
                            },
                        ]
                        .into(),
                    ),
                },
                TlsCapturedExtension {
                    id: last_extension,
                    value: TlsCapturedExtensionValue::Literal(vec![0].into()),
                },
            ]
            .into(),
        }
    }

    #[test]
    fn connections_that_differ_only_in_grease_values_capture_the_same() {
        let a = capture([0x3a3a, 0x5a5a, 0x7a7a, 0xcaca])
            .with_grease_placeholders()
            .unwrap();
        let b = capture([0xbaba, 0x0a0a, 0x2a2a, 0x8a8a])
            .with_grease_placeholders()
            .unwrap();
        let limits = TlsCaptureLimits::default();
        assert_eq!(
            a.canonical(limits).unwrap().bytes,
            b.canonical(limits).unwrap().bytes
        );

        let slot = |index| grease_u16(index).unwrap();
        assert_eq!(a.ciphers[0], GREASE_U16_FIRST);
        // Each list numbers its own slots, so the two GREASE extensions stay distinct.
        assert_eq!(a.extensions[0].id, slot(0));
        assert_eq!(a.extensions[3].id, slot(1));
        assert!(matches!(
            &a.extensions[2].value,
            TlsCapturedExtensionValue::KeyShares(shares) if shares[0].group == slot(0)
        ));
    }
}
