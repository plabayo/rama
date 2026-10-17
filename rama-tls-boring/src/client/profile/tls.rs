//! Map bounded TLS observations to native wire settings.
//!
//! Captured secrets are never available here. Connection-owned advertisements
//! need current application bindings; unsupported native shapes fail explicitly.

use rama_boring::ssl::{
    GreaseValues, Padding, SslCipher, SslCurve, SslSignatureAlgorithm, UnknownValues,
};
use rama_core::{bytes::Bytes, conversion::RamaTryInto as _, error::BoxError};
use rama_net::tls::ApplicationProtocol;
use rama_tls::{
    CertificateCompressionAlgorithm, CompressionAlgorithm, ECPointFormat, ExtensionId,
    ProtocolVersion, PskKeyExchangeMode, SignatureScheme, SupportedGroup, client::TlsClientConfig,
    is_grease_u16,
};
use rama_ua::profile::capture::tls::{
    TlsCapture, TlsCaptureLimits, TlsCaptureTransport, TlsCapturedExtensionValue as Value,
};

use super::super::{
    BoringClientConfigExt as _, BoringRequestedTrustAnchors, BoringTlsConnectorConfig,
    ech::EchGrease,
};

fn invalid(message: &'static str) -> BoxError {
    BoxError::from(message)
}

fn protocols(values: &[Box<[u8]>]) -> impl Iterator<Item = ApplicationProtocol> + '_ {
    values.iter().map(|value| value.as_ref().into())
}

// Native empty OCSP request: status type plus two empty u16-length vectors.
const NATIVE_OCSP_REQUEST_LEN: u16 = 1 + 2 + 2;
// Native empty renegotiated_connection: one u8-length prefix.
const NATIVE_RENEGOTIATION_INFO_LEN: u16 = 1;
// Boring's GREASE key-share body is one byte; RFC 8701 does not fix its size.
const NATIVE_GREASE_KEY_SHARE_LEN: u16 = 1;

/// Transport shape required by a compiled TLS offer.
///
/// The native connection owner binds this shape to its actual session before
/// releasing handshake output. QUIC parameter bytes remain in the engine; wire
/// compilation needs only their encoded length and never copies their identities.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum TransportShape {
    /// A TLS connection over TCP.
    Tcp,
    /// A QUIC connection whose encoded parameter block has this length.
    Quic {
        /// Required byte length, checked again against the consuming native session.
        parameters_len: usize,
    },
}

/// Compile native wire settings for the selected TLS capture.
///
/// `transport` describes the required wire shape, not a prepared connection.
/// QUIC callers must check the actual native parameter length before output.
/// `anchors` supplies current trust-anchor identifiers when the capture contains
/// their advertisement. Captured parameter, ticket and secret bytes are never
/// reused. This function does not prepare an SSL session or establish backend
/// support for an entire captured connection: the owning connector must also
/// bind the destination, caller policy, session state and other selected slots.
pub fn compile(
    transport: TransportShape,
    capture: &TlsCapture,
    anchors: Option<&BoringRequestedTrustAnchors>,
) -> Result<TlsClientConfig, BoxError> {
    capture.validate_fields(TlsCaptureLimits::default())?;
    validate_native_lists(capture)?;
    validate_transport(transport, capture)?;
    let mut config = TlsClientConfig::new();
    if capture.protocol_version != u16::from(ProtocolVersion::TLSv1_2)
        || capture.compression.as_ref() != [u8::from(CompressionAlgorithm::Null)]
    {
        return Err(invalid("unsupported TLS transport or legacy fields"));
    }

    // Return wire overrides only. The caller layers these over its current
    // verification, credentials and session policy before native preparation.
    config.set_cipher_suites(capture.ciphers.iter().copied().map(Into::into).collect());
    config.set_supported_groups(Vec::new());
    config.set_key_shares(Vec::new());
    config.set_signature_schemes(Vec::new());
    config.set_alpn(Default::default());
    config.set_alps(Vec::new(), false);
    config.set_cert_compression(Vec::new());
    config.set_delegated_credentials(Vec::new());
    config.set_record_size_limit(0);
    config.set_encrypted_client_hello(false);
    config.set_ech_grease(EchGrease::Native);
    config.set_ocsp_stapling(false);
    config.set_signed_cert_timestamps(false);
    config.set_tls12_session_tickets(false);
    config.set_requested_trust_anchors(BoringRequestedTrustAnchors::omitted());
    config.set_legacy_extensions(false);
    config.set_permute_extensions(false);
    config.set_grease(false);
    config.set_grease_signature_schemes(false);
    config.set_grease_values(GreaseValues::Pinned);
    config.set_client_hello_padding(Padding::Off);
    config.set_unknown_values(UnknownValues::Preserve);
    config.set_extension_order(
        capture
            .extensions
            .iter()
            .map(|field| field.id.into())
            .collect(),
    );

    let mut extended_master_secret = false;
    let mut renegotiation_info = false;
    let mut versions = false;
    let mut bodies = Vec::new();
    for extension in &capture.extensions {
        match (ExtensionId::from(extension.id), &extension.value) {
            (ExtensionId::SERVER_NAME, Value::ServerName { present: true }) => {}
            // The engine supplies these bytes. Compilation checks the required
            // shape; the native session owner validates its actual encoding.
            (ExtensionId::QUIC_TRANSPORT_PARAMETERS, Value::ConnectionLength(_))
                if matches!(transport, TransportShape::Quic { .. }) => {}
            (ExtensionId::STATUS_REQUEST, Value::ConnectionLength(NATIVE_OCSP_REQUEST_LEN)) => {
                config.set_ocsp_stapling(true);
            }
            (ExtensionId::SUPPORTED_GROUPS, Value::U16List(groups)) => {
                config.set_supported_groups(groups.iter().copied().map(Into::into).collect());
            }
            (ExtensionId::EC_POINT_FORMATS, Value::U8List(formats))
                if formats.as_ref() == [u8::from(ECPointFormat::Uncompressed)] => {}
            (ExtensionId::SIGNATURE_ALGORITHMS, Value::U16List(schemes)) => {
                config.set_signature_schemes(schemes.iter().copied().map(Into::into).collect());
            }
            (ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, Value::Protocols(values)) => {
                config.set_alpn(protocols(values).collect());
            }
            (ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP, Value::Literal(value))
                if value.is_empty() =>
            {
                config.set_signed_cert_timestamps(true);
            }
            (ExtensionId::EXTENDED_MASTER_SECRET, Value::Literal(value)) if value.is_empty() => {
                extended_master_secret = true
            }
            (ExtensionId::COMPRESS_CERTIFICATE, Value::U16List(algorithms)) => {
                config.set_cert_compression(algorithms.iter().copied().map(Into::into).collect());
            }
            (ExtensionId::RECORD_SIZE_LIMIT, Value::U16List(limit))
                if limit.len() == 1 && limit[0] != 0 =>
            {
                config.set_record_size_limit(limit[0]);
            }
            (ExtensionId::DELEGATED_CREDENTIAL, Value::U16List(schemes)) => {
                config.set_delegated_credentials(schemes.iter().copied().map(Into::into).collect());
            }
            (ExtensionId::SESSION_TICKET, Value::ConnectionLength(0)) => {
                config.set_tls12_session_tickets(true);
            }
            (ExtensionId::SUPPORTED_VERSIONS, Value::U16List(values))
                if values.contains(&u16::from(ProtocolVersion::TLSv1_3)) =>
            {
                config.set_supported_versions(values.iter().copied().map(Into::into).collect());
                // Restrict native negotiation to this admitted offer. Explicit
                // caller bounds are checked before these overrides are applied.
                let mut offered = values
                    .iter()
                    .copied()
                    .filter(|value| !is_grease_u16(*value));
                let first = offered
                    .next()
                    .ok_or_else(|| invalid("missing negotiable TLS version"))?;
                let (min, max) = offered.fold((first, first), |(min, max), value| {
                    (min.min(value), max.max(value))
                });
                config.set_min_version(min.into());
                config.set_max_version(max.into());
                versions = true;
            }
            (ExtensionId::PSK_KEY_EXCHANGE_MODES, Value::U8List(modes))
                if modes.as_ref() == [u8::from(PskKeyExchangeMode::PskDheKe)] => {}
            (ExtensionId::KEY_SHARE, Value::KeyShares(shares)) => {
                if shares.iter().any(|share| {
                    let group = SupportedGroup::from(share.group);
                    let expected = if group.is_grease() {
                        Some(NATIVE_GREASE_KEY_SHARE_LEN)
                    } else {
                        group.tls13_client_key_share_len()
                    };
                    expected != Some(share.length)
                }) {
                    return Err(invalid("unsupported TLS key-share shape"));
                }
                config.set_key_shares(shares.iter().map(|share| share.group.into()).collect());
            }
            (
                ExtensionId::OLD_APPLICATION_SETTINGS | ExtensionId::APPLICATION_SETTINGS,
                Value::Protocols(values),
            ) => {
                config.set_alps(
                    protocols(values).collect(),
                    ExtensionId::from(extension.id) == ExtensionId::APPLICATION_SETTINGS,
                );
            }
            (ExtensionId::TRUST_ANCHORS, Value::ConnectionLength(length)) => {
                let anchors =
                    anchors.ok_or_else(|| invalid("current trust-anchor binding required"))?;
                anchors.identifier_list()?;
                if anchors.extension_body().map(<[u8]>::len) != Some(usize::from(*length)) {
                    return Err(invalid("current trust-anchor binding length differs"));
                }
                config.set_requested_trust_anchors(anchors.clone());
            }
            (
                ExtensionId::ENCRYPTED_CLIENT_HELLO,
                Value::EchOuter {
                    kdf,
                    aead,
                    enc,
                    payload,
                },
            ) => {
                config.set_encrypted_client_hello(true);
                config.set_ech_grease(EchGrease::Shape {
                    kdf_id: *kdf,
                    aead_id: *aead,
                    encapsulated_key_len: usize::from(*enc),
                    payload_len: usize::from(*payload),
                });
            }
            (
                ExtensionId::RENEGOTIATION_INFO,
                Value::ConnectionLength(NATIVE_RENEGOTIATION_INFO_LEN),
            ) => renegotiation_info = true,
            (ExtensionId::Unknown(_), Value::Literal(body)) => {
                bodies.push((extension.id.into(), Bytes::copy_from_slice(body)));
            }
            _ => {
                return Err(invalid(
                    "unsupported TLS captured extension or native binding",
                ));
            }
        }
    }
    if !versions || extended_master_secret != renegotiation_info {
        return Err(invalid("unsupported TLS version or legacy extension pair"));
    }
    config.set_legacy_extensions(extended_master_secret);
    config.set_extension_bodies(bodies);
    Ok(config)
}

/// Compile wire settings while retaining explicit caller version and cipher limits.
/// Other caller policy, including verification and credentials, stays in the
/// connection owner's effective configuration and is not returned as an override.
pub fn compile_for_policy(
    transport: TransportShape,
    capture: &TlsCapture,
    policy: &BoringTlsConnectorConfig<'_>,
) -> Result<TlsClientConfig, BoxError> {
    validate_version_bounds(
        capture,
        policy.min_version.map(|version| version.0),
        policy.max_version.map(|version| version.0),
    )?;
    if let Some(ciphers) = policy.cipher_suites
        && !ciphers
            .0
            .iter()
            .copied()
            .map(u16::from)
            .eq(capture.ciphers.iter().copied())
    {
        return Err(invalid(
            "caller cipher policy conflicts with captured TLS ciphers",
        ));
    }
    compile(transport, capture, policy.requested_trust_anchors)
}

// QUIC's native handshake filters non-TLS-1.3 offers. Reject such captures
// instead of silently changing their version list during native preparation.
fn validate_transport(transport: TransportShape, capture: &TlsCapture) -> Result<(), BoxError> {
    match (transport, capture.transport) {
        (TransportShape::Tcp, TlsCaptureTransport::Tcp) => Ok(()),
        (TransportShape::Quic { parameters_len }, TlsCaptureTransport::Quic) => {
            let parameter_length = capture.extensions.iter().find_map(|extension| {
                match (ExtensionId::from(extension.id), &extension.value) {
                    (ExtensionId::QUIC_TRANSPORT_PARAMETERS, Value::ConnectionLength(length)) => {
                        Some(*length)
                    }
                    _ => None,
                }
            });
            if parameter_length.map(usize::from) != Some(parameters_len) {
                return Err(invalid(
                    "current QUIC transport-parameter length differs or is absent",
                ));
            }
            let versions = capture
                .extensions
                .iter()
                .find_map(
                    |extension| match (ExtensionId::from(extension.id), &extension.value) {
                        (ExtensionId::SUPPORTED_VERSIONS, Value::U16List(versions)) => {
                            Some(versions.as_ref())
                        }
                        _ => None,
                    },
                )
                .unwrap_or_default();
            if versions.iter().any(|&version| {
                !is_grease_u16(version) && version != u16::from(ProtocolVersion::TLSv1_3)
            }) {
                return Err(invalid("QUIC capture offers a version other than TLS 1.3"));
            }
            Ok(())
        }
        _ => Err(invalid("captured TLS transport and current binding differ")),
    }
}

// Check backend capability separately from protocol encoding sizes. GREASE
// is intentionally non-negotiable and remains literal.
fn validate_native_lists(capture: &TlsCapture) -> Result<(), BoxError> {
    // This compiler supports fresh TLS 1.3 first hellos. Native TLS emits
    // these fields, so omission cannot be advertised as an exact replay.
    for required in [
        ExtensionId::SUPPORTED_GROUPS,
        ExtensionId::SIGNATURE_ALGORITHMS,
        ExtensionId::SUPPORTED_VERSIONS,
        ExtensionId::PSK_KEY_EXCHANGE_MODES,
        ExtensionId::KEY_SHARE,
    ] {
        if !capture
            .extensions
            .iter()
            .any(|extension| extension.id == u16::from(required))
        {
            return Err(invalid(
                "captured TLS shape omits a required native first-hello field",
            ));
        }
    }
    let alpn = capture
        .extensions
        .iter()
        .find_map(|extension| match &extension.value {
            Value::Protocols(protocols)
                if extension.id
                    == u16::from(ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION) =>
            {
                Some(protocols.as_ref())
            }
            _ => None,
        })
        .unwrap_or_default();
    let offers_tls12 = capture.extensions.iter().any(|extension| {
        extension.id == u16::from(ExtensionId::SUPPORTED_VERSIONS)
            && matches!(&extension.value, Value::U16List(values)
                if values.contains(&u16::from(ProtocolVersion::TLSv1_2)))
    });
    let has_point_formats = capture
        .extensions
        .iter()
        .any(|extension| extension.id == u16::from(ExtensionId::EC_POINT_FORMATS));
    if offers_tls12 != has_point_formats {
        return Err(invalid(
            "captured EC point formats differ from native version policy",
        ));
    }
    if !offers_tls12
        && capture
            .extensions
            .iter()
            .any(|extension| extension.id == u16::from(ExtensionId::SESSION_TICKET))
    {
        return Err(invalid(
            "captured session-ticket extension requires a TLS 1.2 offer",
        ));
    }
    let mut alps_seen = false;
    for extension in &capture.extensions {
        if matches!(
            ExtensionId::from(extension.id),
            ExtensionId::OLD_APPLICATION_SETTINGS | ExtensionId::APPLICATION_SETTINGS
        ) && let Value::Protocols(protocols) = &extension.value
        {
            if alps_seen
                || protocols.iter().enumerate().any(|(index, protocol)| {
                    !alpn.contains(protocol) || protocols[..index].contains(protocol)
                })
            {
                return Err(invalid("captured ALPS offer cannot be emitted exactly"));
            }
            alps_seen = true;
        }
    }
    if capture
        .ciphers
        .iter()
        .any(|&value| !is_grease_u16(value) && SslCipher::from_value(value).is_none())
    {
        return Err(invalid(
            "captured cipher is not implemented by this backend",
        ));
    }
    for extension in &capture.extensions {
        match (ExtensionId::from(extension.id), &extension.value) {
            (ExtensionId::SUPPORTED_GROUPS, Value::U16List(values)) => {
                for &value in values.iter().filter(|&&value| !is_grease_u16(value)) {
                    let _: SslCurve =
                        SupportedGroup::from(value)
                            .rama_try_into()
                            .map_err(|_unsupported| {
                                invalid("captured group is not implemented by this backend")
                            })?;
                }
            }
            (
                ExtensionId::SIGNATURE_ALGORITHMS | ExtensionId::DELEGATED_CREDENTIAL,
                Value::U16List(values),
            ) => {
                for &value in values.iter().filter(|&&value| !is_grease_u16(value)) {
                    let _: SslSignatureAlgorithm = SignatureScheme::from(value)
                        .rama_try_into()
                        .map_err(|_unsupported| {
                            invalid("captured signature scheme is not implemented by this backend")
                        })?;
                }
            }
            (ExtensionId::COMPRESS_CERTIFICATE, Value::U16List(values)) => {
                if values.iter().enumerate().any(|(index, &value)| {
                    values[..index].contains(&value)
                        || !crate::certificate_compression::SUPPORTED_CERTIFICATE_COMPRESSION
                            .contains(&CertificateCompressionAlgorithm::from(value))
                }) {
                    return Err(invalid(
                        "captured certificate compression list cannot be emitted exactly",
                    ));
                }
            }
            (ExtensionId::SUPPORTED_VERSIONS, Value::U16List(values)) => {
                // Without GREASE the existing connector derives a descending
                // native version range, rather than installing a raw list.
                if !values.iter().any(|&value| is_grease_u16(value))
                    && values.windows(2).any(|pair| pair[0] <= pair[1])
                {
                    return Err(invalid(
                        "captured TLS version order needs a raw-list compiler",
                    ));
                }
                if values.iter().any(|&value| {
                    !is_grease_u16(value)
                        && !matches!(
                            ProtocolVersion::from(value),
                            ProtocolVersion::TLSv1_2 | ProtocolVersion::TLSv1_3
                        )
                }) {
                    return Err(invalid(
                        "captured TLS version is not supported by this compiler",
                    ));
                }
            }
            _ => {}
        }
    }
    let groups = capture.extensions.iter().find_map(|extension| {
        match (&extension.value, ExtensionId::from(extension.id)) {
            (Value::U16List(groups), ExtensionId::SUPPORTED_GROUPS) => Some(groups.as_ref()),
            _ => None,
        }
    });
    if let Some(groups) = groups {
        let raw_groups = groups
            .iter()
            .enumerate()
            .any(|(index, value)| is_grease_u16(*value) || groups[..index].contains(value));
        for extension in &capture.extensions {
            if let Value::KeyShares(shares) = &extension.value {
                let mut previous = None;
                for share in shares {
                    let position = groups
                        .iter()
                        .position(|group| *group == share.group)
                        .ok_or_else(|| {
                            invalid("captured key share is absent from supported groups")
                        })?;
                    if !raw_groups && previous.is_some_and(|previous| previous >= position) {
                        return Err(invalid(
                            "captured key-share order needs a raw-list compiler",
                        ));
                    }
                    previous = Some(position);
                }
            }
        }
    }
    Ok(())
}

// A captured offer may narrow caller policy, but must never broaden it. Check
// every negotiable version before installing the offer's own native bounds.
pub(super) fn validate_version_bounds(
    capture: &TlsCapture,
    min: Option<ProtocolVersion>,
    max: Option<ProtocolVersion>,
) -> Result<(), BoxError> {
    for extension in &capture.extensions {
        if extension.id != u16::from(ExtensionId::SUPPORTED_VERSIONS) {
            continue;
        }
        let Value::U16List(versions) = &extension.value else {
            return Err(invalid("captured TLS version list is malformed"));
        };
        for &version in versions.iter().filter(|&&version| !is_grease_u16(version)) {
            if min.is_some_and(|min| version < u16::from(min))
                || max.is_some_and(|max| version > u16::from(max))
            {
                return Err(invalid(
                    "caller TLS version bounds conflict with captured offer",
                ));
            }
        }
    }
    Ok(())
}
