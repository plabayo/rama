//! Capture-safe TLS observations derived from the existing parsed ClientHello.

use rama_net::tls::ApplicationProtocol;
use rama_tls::{
    ExtensionId,
    client::{
        ClientHello, ClientHelloExtension, ECHClientHello,
        client_hello_extension_is_connection_bound,
    },
};
use rama_utils::octets::kib;
use serde::Serialize;

use super::{ProfileCaptureCompleteness, ProfileDataError};

mod codec;
pub(super) mod structure;

#[derive(Debug, Clone, Copy, Serialize)]
pub enum TlsCaptureTransport {
    Tcp,
    Quic,
}

#[derive(Debug, Clone, Copy)]
pub struct TlsCaptureLimits {
    pub elements: usize,
    pub bytes: usize,
}
impl Default for TlsCaptureLimits {
    fn default() -> Self {
        Self {
            elements: 256,
            bytes: kib(64),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsKeyShareShape {
    pub group: u16,
    pub length: u16,
}

/// Request-bound cryptographic values retain lengths, never their original bytes.
#[derive(Debug, Clone, Serialize)]
pub enum TlsCapturedExtensionValue {
    Literal(Box<[u8]>),
    U16List(Box<[u16]>),
    U8List(Box<[u8]>),
    Protocols(Box<[Box<[u8]>]>),
    /// SNI is supplied by the destination. Its length is not a profile property.
    ServerName {
        present: bool,
    },
    KeyShares(Box<[TlsKeyShareShape]>),
    PreSharedKeys {
        identities: Box<[u16]>,
        binders: Box<[u8]>,
    },
    EchOuter {
        kdf: u16,
        aead: u16,
        enc: u16,
        payload: u16,
    },
    EchInner,
    ConnectionLength(u16),
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsCapturedExtension {
    pub id: u16,
    pub value: TlsCapturedExtensionValue,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsCapture {
    pub completeness: ProfileCaptureCompleteness,
    pub transport: TlsCaptureTransport,
    pub protocol_version: u16,
    pub ciphers: Box<[u16]>,
    pub compression: Box<[u8]>,
    pub extensions: Box<[TlsCapturedExtension]>,
}

struct InputBudget {
    elements: usize,
    bytes: usize,
}

impl InputBudget {
    fn take(&mut self, elements: usize, bytes: usize) -> Result<(), ProfileDataError> {
        self.elements = self
            .elements
            .checked_sub(elements)
            .ok_or(ProfileDataError::LimitExceeded("TLS capture elements"))?;
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .ok_or(ProfileDataError::LimitExceeded("TLS capture bytes"))?;
        Ok(())
    }
    fn list(&mut self, count: usize, width: usize) -> Result<(), ProfileDataError> {
        self.take(
            count,
            count
                .checked_mul(width)
                .ok_or(ProfileDataError::LimitExceeded("TLS capture list"))?,
        )
    }
}

fn length(value: usize) -> Result<u16, ProfileDataError> {
    u16::try_from(value).map_err(|_error| ProfileDataError::Invalid("TLS extension length"))
}

fn protocols(
    input: &[ApplicationProtocol],
    budget: &mut InputBudget,
) -> Result<Box<[Box<[u8]>]>, ProfileDataError> {
    budget.take(input.len(), 0)?;
    for protocol in input {
        let bytes = protocol.as_bytes();
        if bytes.is_empty() || bytes.len() > usize::from(u8::MAX) {
            return Err(ProfileDataError::Invalid("TLS application protocol"));
        }
        budget.take(0, bytes.len())?;
    }
    Ok(input
        .iter()
        .map(|protocol| Box::from(protocol.as_bytes()))
        .collect())
}

fn vector16<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], ProfileDataError> {
    let (prefix, rest) = input
        .split_first_chunk::<2>()
        .ok_or(ProfileDataError::Invalid("TLS vector length"))?;
    let (value, rest) = rest
        .split_at_checked(usize::from(u16::from_be_bytes(*prefix)))
        .ok_or(ProfileDataError::Invalid("TLS vector body"))?;
    *input = rest;
    Ok(value)
}

fn key_shares(
    data: &[u8],
    budget: &mut InputBudget,
) -> Result<Box<[TlsKeyShareShape]>, ProfileDataError> {
    let mut remaining = data;
    let mut entries = vector16(&mut remaining)?;
    if !remaining.is_empty() {
        return Err(ProfileDataError::Invalid("TLS key share trailing bytes"));
    }
    let mut shapes = Vec::new();
    while !entries.is_empty() {
        budget.take(1, 0)?;
        let (group, rest) = entries
            .split_first_chunk::<2>()
            .ok_or(ProfileDataError::Invalid("TLS key share group"))?;
        entries = rest;
        let value = vector16(&mut entries)?;
        if value.is_empty() {
            return Err(ProfileDataError::Invalid("empty TLS key share"));
        }
        let group = u16::from_be_bytes(*group);
        if shapes
            .iter()
            .any(|shape: &TlsKeyShareShape| shape.group == group)
        {
            return Err(ProfileDataError::Invalid("duplicate TLS key share group"));
        }
        shapes.push(TlsKeyShareShape {
            group,
            length: length(value.len())?,
        });
    }
    Ok(shapes.into())
}

fn pre_shared_keys(
    data: &[u8],
    budget: &mut InputBudget,
) -> Result<TlsCapturedExtensionValue, ProfileDataError> {
    let mut remaining = data;
    let mut identities = vector16(&mut remaining)?;
    let mut binders = vector16(&mut remaining)?;
    if !remaining.is_empty() {
        return Err(ProfileDataError::Invalid("TLS PSK trailing bytes"));
    }
    let mut identity_lengths = Vec::new();
    let mut binder_lengths = Vec::new();
    while !identities.is_empty() {
        budget.take(1, 0)?;
        let value = vector16(&mut identities)?;
        if value.is_empty() {
            return Err(ProfileDataError::Invalid("empty TLS PSK identity"));
        }
        identities = identities
            .get(4..)
            .ok_or(ProfileDataError::Invalid("TLS PSK ticket age"))?;
        identity_lengths.push(length(value.len())?);
    }
    while !binders.is_empty() {
        budget.take(1, 0)?;
        let (&size, rest) = binders
            .split_first()
            .ok_or(ProfileDataError::Invalid("TLS PSK binder length"))?;
        if size < 32 {
            return Err(ProfileDataError::Invalid("TLS PSK binder length"));
        }
        binders = rest
            .get(usize::from(size)..)
            .ok_or(ProfileDataError::Invalid("TLS PSK binder body"))?;
        binder_lengths.push(size);
    }
    if identity_lengths.is_empty() || identity_lengths.len() != binder_lengths.len() {
        return Err(ProfileDataError::Invalid("TLS PSK binder count"));
    }
    Ok(TlsCapturedExtensionValue::PreSharedKeys {
        identities: identity_lengths.into(),
        binders: binder_lengths.into(),
    })
}

impl TlsCapture {
    pub fn capture(
        completeness: ProfileCaptureCompleteness,
        transport: TlsCaptureTransport,
        hello: &ClientHello,
        limits: TlsCaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        completeness.require_complete("TLS ClientHello observation")?;
        let mut budget = InputBudget {
            elements: limits.elements,
            bytes: limits.bytes,
        };
        budget.list(hello.cipher_suites().len(), 2)?;
        budget.list(hello.compression_algorithms().len(), 1)?;
        budget.list(hello.extensions().len(), 4)?;
        let mut extensions = Vec::with_capacity(hello.extensions().len());
        for (index, extension) in hello.extensions().iter().enumerate() {
            let extension_id = extension.id();
            let id = u16::from(extension_id);
            if extension_id == ExtensionId::PRE_SHARED_KEY && index + 1 != hello.extensions().len()
            {
                return Err(ProfileDataError::Invalid("TLS PSK extension order"));
            }
            if extensions
                .iter()
                .any(|previous: &TlsCapturedExtension| previous.id == id)
            {
                return Err(ProfileDataError::Invalid("duplicate TLS extension"));
            }
            let value = match extension {
                ClientHelloExtension::ServerName(name) => {
                    let size = name
                        .as_ref()
                        .map(|name| length(name.as_str().len()))
                        .transpose()?;
                    budget.take(0, usize::from(size.unwrap_or(0)))?;
                    TlsCapturedExtensionValue::ServerName {
                        present: name.is_some(),
                    }
                }
                ClientHelloExtension::SupportedGroups(values) => {
                    budget.list(values.len(), 2)?;
                    TlsCapturedExtensionValue::U16List(
                        values.iter().copied().map(u16::from).collect(),
                    )
                }
                ClientHelloExtension::ECPointFormats(values) => {
                    budget.list(values.len(), 1)?;
                    TlsCapturedExtensionValue::U8List(
                        values.iter().copied().map(u8::from).collect(),
                    )
                }
                ClientHelloExtension::SignatureAlgorithms(values)
                | ClientHelloExtension::DelegatedCredentials(values) => {
                    budget.list(values.len(), 2)?;
                    TlsCapturedExtensionValue::U16List(
                        values.iter().copied().map(u16::from).collect(),
                    )
                }
                ClientHelloExtension::SupportedVersions(values) => {
                    budget.list(values.len(), 2)?;
                    TlsCapturedExtensionValue::U16List(
                        values.iter().copied().map(u16::from).collect(),
                    )
                }
                ClientHelloExtension::CertificateCompression(values) => {
                    budget.list(values.len(), 2)?;
                    TlsCapturedExtensionValue::U16List(
                        values.iter().copied().map(u16::from).collect(),
                    )
                }
                ClientHelloExtension::RecordSizeLimit(value) => {
                    budget.take(1, 2)?;
                    TlsCapturedExtensionValue::U16List(Box::new([*value]))
                }
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(values)
                | ClientHelloExtension::ApplicationSettings {
                    protocols: values, ..
                } => TlsCapturedExtensionValue::Protocols(protocols(values, &mut budget)?),
                ClientHelloExtension::EncryptedClientHello(ECHClientHello::Inner) => {
                    TlsCapturedExtensionValue::EchInner
                }
                ClientHelloExtension::EncryptedClientHello(ECHClientHello::Outer(value)) => {
                    budget.take(0, value.enc.len())?;
                    budget.take(0, value.payload.len())?;
                    TlsCapturedExtensionValue::EchOuter {
                        kdf: value.cipher_suite.kdf_id.into(),
                        aead: value.cipher_suite.aead_id.into(),
                        enc: length(value.enc.len())?,
                        payload: length(value.payload.len())?,
                    }
                }
                ClientHelloExtension::Opaque { data, .. } => {
                    budget.take(0, data.len())?;
                    let size = length(data.len())?;
                    match extension_id {
                        // Typed extensions cannot bypass their capture policy through Opaque.
                        ExtensionId::SERVER_NAME
                        | ExtensionId::SUPPORTED_GROUPS
                        | ExtensionId::EC_POINT_FORMATS
                        | ExtensionId::SIGNATURE_ALGORITHMS
                        | ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
                        | ExtensionId::COMPRESS_CERTIFICATE
                        | ExtensionId::RECORD_SIZE_LIMIT
                        | ExtensionId::DELEGATED_CREDENTIAL
                        | ExtensionId::SUPPORTED_VERSIONS
                        | ExtensionId::OLD_APPLICATION_SETTINGS
                        | ExtensionId::APPLICATION_SETTINGS
                        | ExtensionId::ENCRYPTED_CLIENT_HELLO => {
                            return Err(ProfileDataError::Invalid("opaque typed TLS extension"));
                        }
                        ExtensionId::KEY_SHARE => {
                            TlsCapturedExtensionValue::KeyShares(key_shares(data, &mut budget)?)
                        }
                        ExtensionId::PRE_SHARED_KEY => pre_shared_keys(data, &mut budget)?,
                        ExtensionId::PSK_KEY_EXCHANGE_MODES => {
                            let (&count, values) = data
                                .split_first()
                                .ok_or(ProfileDataError::Invalid("TLS PSK modes"))?;
                            if count == 0 || usize::from(count) != values.len() {
                                return Err(ProfileDataError::Invalid("TLS PSK modes"));
                            }
                            budget.take(values.len(), 0)?;
                            TlsCapturedExtensionValue::U8List(values.into())
                        }
                        ExtensionId::SIGNATURE_ALGORITHMS_CERT => {
                            let mut rest = data.as_slice();
                            let values = vector16(&mut rest)?;
                            if !rest.is_empty()
                                || values.is_empty()
                                || !values.len().is_multiple_of(2)
                            {
                                return Err(ProfileDataError::Invalid(
                                    "TLS certificate signature schemes",
                                ));
                            }
                            budget.take(values.len() / 2, 0)?;
                            TlsCapturedExtensionValue::U16List(
                                values
                                    .as_chunks::<2>()
                                    .0
                                    .iter()
                                    .copied()
                                    .map(u16::from_be_bytes)
                                    .collect(),
                            )
                        }
                        ExtensionId::PADDING => {
                            if data.iter().any(|byte| *byte != 0) {
                                return Err(ProfileDataError::Invalid("TLS padding bytes"));
                            }
                            // Padding size follows the destination-dependent ClientHello.
                            TlsCapturedExtensionValue::ConnectionLength(0)
                        }
                        // Identities, certificates, cookies, tickets and connection metadata.
                        id if client_hello_extension_is_connection_bound(id) => {
                            TlsCapturedExtensionValue::ConnectionLength(size)
                        }
                        _ => TlsCapturedExtensionValue::Literal(data.as_slice().into()),
                    }
                }
            };
            extensions.push(TlsCapturedExtension { id, value });
        }
        let capture = Self {
            completeness,
            transport,
            protocol_version: hello.protocol_version().into(),
            ciphers: hello
                .cipher_suites()
                .iter()
                .copied()
                .map(u16::from)
                .collect(),
            compression: hello
                .compression_algorithms()
                .iter()
                .copied()
                .map(u8::from)
                .collect(),
            extensions: extensions.into(),
        };
        capture.validate(limits)?;
        Ok(capture)
    }
}

#[cfg(test)]
mod tests;
