use rama_net::address::Domain;
use rama_tls::{
    CertificateCompressionAlgorithm, CipherSuite, CompressionAlgorithm, ECPointFormat, ExtensionId,
    ProtocolVersion, SignatureScheme, SupportedGroup,
    client::{ClientHello, ClientHelloExtension, ECHClientHello},
};

use crate::profile::capture::tls::{TlsCapture, TlsCapturedExtensionValue as Value};

// Stands in for the destination, which a capture never retains.
const PLACEHOLDER_SERVER_NAME: Domain = Domain::from_static("example.com");

impl TlsCapture {
    /// A ClientHello with the captured shape, for computing fingerprints such as JA3 or JA4.
    ///
    /// Values a capture keeps only as lengths (SNI, key shares, tickets, ECH) are zero-filled,
    /// so the result is never suitable for sending.
    #[must_use]
    pub fn representative_client_hello(&self) -> ClientHello {
        ClientHello::new(
            ProtocolVersion::from(self.protocol_version),
            self.ciphers
                .iter()
                .copied()
                .map(CipherSuite::from)
                .collect(),
            self.compression
                .iter()
                .copied()
                .map(CompressionAlgorithm::from)
                .collect(),
            self.extensions
                .iter()
                .map(|extension| representative_extension(extension.id, &extension.value))
                .collect(),
        )
    }
}

fn representative_extension(id: u16, value: &Value) -> ClientHelloExtension {
    let extension = ExtensionId::from(id);
    match (extension, value) {
        (ExtensionId::SERVER_NAME, Value::ServerName { present }) => {
            ClientHelloExtension::ServerName(present.then_some(PLACEHOLDER_SERVER_NAME))
        }
        (ExtensionId::SUPPORTED_GROUPS, Value::U16List(values)) => {
            ClientHelloExtension::SupportedGroups(
                values.iter().copied().map(SupportedGroup::from).collect(),
            )
        }
        (ExtensionId::EC_POINT_FORMATS, Value::U8List(values)) => {
            ClientHelloExtension::ECPointFormats(
                values.iter().copied().map(ECPointFormat::from).collect(),
            )
        }
        (ExtensionId::SIGNATURE_ALGORITHMS, Value::U16List(values)) => {
            ClientHelloExtension::SignatureAlgorithms(schemes(values))
        }
        (ExtensionId::DELEGATED_CREDENTIAL, Value::U16List(values)) => {
            ClientHelloExtension::DelegatedCredentials(schemes(values))
        }
        (ExtensionId::SUPPORTED_VERSIONS, Value::U16List(values)) => {
            ClientHelloExtension::SupportedVersions(
                values.iter().copied().map(ProtocolVersion::from).collect(),
            )
        }
        (ExtensionId::COMPRESS_CERTIFICATE, Value::U16List(values)) => {
            ClientHelloExtension::CertificateCompression(
                values
                    .iter()
                    .copied()
                    .map(CertificateCompressionAlgorithm::from)
                    .collect(),
            )
        }
        (ExtensionId::RECORD_SIZE_LIMIT, Value::U16List(values)) if values.len() == 1 => {
            ClientHelloExtension::RecordSizeLimit(values[0])
        }
        (ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, Value::Protocols(values)) => {
            ClientHelloExtension::ApplicationLayerProtocolNegotiation(
                values.iter().map(|value| value.as_ref().into()).collect(),
            )
        }
        (
            ExtensionId::APPLICATION_SETTINGS | ExtensionId::OLD_APPLICATION_SETTINGS,
            Value::Protocols(values),
        ) => ClientHelloExtension::ApplicationSettings {
            protocols: values.iter().map(|value| value.as_ref().into()).collect(),
            new_codepoint: extension == ExtensionId::APPLICATION_SETTINGS,
        },
        (_, Value::EchInner) => ClientHelloExtension::EncryptedClientHello(ECHClientHello::Inner),
        (_, value) => ClientHelloExtension::Opaque {
            id: extension,
            data: opaque(value),
        },
    }
}

fn schemes(values: &[u16]) -> Vec<SignatureScheme> {
    values.iter().copied().map(SignatureScheme::from).collect()
}

fn opaque(value: &Value) -> Vec<u8> {
    match value {
        Value::Literal(bytes) => bytes.to_vec(),
        Value::U16List(values) => {
            let mut data = u16::try_from(values.len() * 2)
                .unwrap_or(u16::MAX)
                .to_be_bytes()
                .to_vec();
            data.extend(values.iter().flat_map(|value| value.to_be_bytes()));
            data
        }
        Value::U8List(values) => {
            let mut data = vec![u8::try_from(values.len()).unwrap_or(u8::MAX)];
            data.extend_from_slice(values);
            data
        }
        Value::Protocols(values) => values.iter().flat_map(|value| value.to_vec()).collect(),
        Value::ServerName { .. } | Value::EchInner => Vec::new(),
        Value::KeyShares(shares) => {
            let mut entries = Vec::new();
            for share in shares {
                entries.extend(share.group.to_be_bytes());
                entries.extend(share.length.to_be_bytes());
                entries.resize(entries.len() + usize::from(share.length), 0);
            }
            let mut data = u16::try_from(entries.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes()
                .to_vec();
            data.extend(entries);
            data
        }
        Value::PreSharedKeys {
            identities,
            binders,
        } => {
            let size = identities
                .iter()
                .map(|length| usize::from(*length) + 6)
                .sum::<usize>()
                + binders
                    .iter()
                    .map(|length| usize::from(*length) + 1)
                    .sum::<usize>()
                + 4;
            vec![0; size]
        }
        Value::EchOuter { enc, payload, .. } => {
            vec![0; 10 + usize::from(*enc) + usize::from(*payload)]
        }
        Value::ConnectionLength(length) => vec![0; usize::from(*length)],
    }
}
