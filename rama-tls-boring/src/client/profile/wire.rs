//! Map bounded TLS observations to native wire settings.
//!
//! Captured secrets are never available here. Connection-owned advertisements
//! need current application bindings. A captured value this backend cannot emit
//! falls back to native or caller behaviour and is recorded as a difference;
//! only malformed or protocol-invalid captures fail.

use rama_boring::ssl::{
    GreaseValues, Padding, SslCipher, SslCurve, SslSignatureAlgorithm, UnknownValues,
};
use rama_core::{
    bytes::Bytes,
    conversion::RamaTryInto as _,
    error::{BoxError, BoxErrorExt as _},
};
use rama_net::tls::ApplicationProtocol;
use rama_tls::{
    CertificateCompressionAlgorithm, CompressionAlgorithm, ECPointFormat, ExtensionId,
    ProtocolVersion, PskKeyExchangeMode, SignatureScheme, SupportedGroup, client::TlsClientConfig,
    is_grease_u16,
};
use rama_ua::profile::{
    capture::tls::{
        TlsCapture, TlsCaptureLimits, TlsCaptureTransport, TlsCapturedExtensionValue as Value,
    },
    replay::request::{
        LoweredProfileItem, ProfilePreservationDifference, ProfilePreservationReport,
    },
};

use super::super::{
    BoringClientConfigExt as _, BoringExtensionPresence, BoringRequestedTrustAnchors,
    BoringTlsConnectorConfig, ech::EchGrease,
};

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
/// Captured items this backend cannot emit exactly are left to native or caller
/// configuration and recorded in `report`.
pub fn compile(
    transport: TransportShape,
    capture: &TlsCapture,
    anchors: Option<&BoringRequestedTrustAnchors>,
    report: &mut ProfilePreservationReport,
) -> Result<TlsClientConfig, BoxError> {
    compile_lowered(transport, capture, anchors, Lowered::default(), report)
}

/// Compile wire settings while retaining explicit caller version and cipher limits.
/// Other caller policy, including verification and credentials, stays in the
/// connection owner's effective configuration and is not returned as an override.
pub fn compile_for_policy(
    transport: TransportShape,
    capture: &TlsCapture,
    policy: &BoringTlsConnectorConfig<'_>,
    report: &mut ProfilePreservationReport,
) -> Result<TlsClientConfig, BoxError> {
    let mut lowered = Lowered::default();
    if version_bounds_conflict(
        capture,
        policy.min_version.map(|version| version.0),
        policy.max_version.map(|version| version.0),
    )? {
        lower(report, LoweredProfileItem::CallerTlsVersionBounds);
        lowered.versions = true;
    }
    if let Some(ciphers) = policy.cipher_suites
        && !ciphers
            .0
            .iter()
            .copied()
            .map(u16::from)
            .eq(capture.ciphers.iter().copied())
    {
        lower(report, LoweredProfileItem::CallerTlsCipherSuites);
        lowered.ciphers = true;
    }
    compile_lowered(
        transport,
        capture,
        policy.requested_trust_anchors,
        lowered,
        report,
    )
}

/// Captured items left to the caller's or native configuration.
#[derive(Debug, Default, Clone, Copy)]
struct Lowered {
    ciphers: bool,
    groups: bool,
    signatures: bool,
    versions: bool,
    key_shares: bool,
    alps: bool,
    cert_compression: bool,
    session_ticket: bool,
    ec_point_formats: bool,
}

fn lower(report: &mut ProfilePreservationReport, item: LoweredProfileItem) {
    report.push(ProfilePreservationDifference::LoweredProfileItem { item });
}

fn compile_lowered(
    transport: TransportShape,
    capture: &TlsCapture,
    anchors: Option<&BoringRequestedTrustAnchors>,
    mut lowered: Lowered,
    report: &mut ProfilePreservationReport,
) -> Result<TlsClientConfig, BoxError> {
    capture.validate_fields(TlsCaptureLimits::default())?;
    validate_transport(transport, capture, report)?;
    validate_native_lists(capture, &mut lowered, report)?;
    let mut config = TlsClientConfig::new();
    if capture.protocol_version != u16::from(ProtocolVersion::TLSv1_2)
        || capture.compression.as_ref() != [u8::from(CompressionAlgorithm::Null)]
    {
        // Native TLS always emits these legacy values.
        lower(report, LoweredProfileItem::TlsLegacyFields);
    }

    // Return wire overrides only. The caller layers these over its current
    // verification, credentials and session policy before native preparation.
    if !lowered.ciphers {
        // The raw setter can advertise unsupported IDs without negotiating them.
        // Preserve Safari's legacy suites too; preflight still requires at least
        // one negotiable suite, and explicit caller restrictions take precedence.
        config.set_cipher_suites(capture.ciphers.iter().copied().map(Into::into).collect());
    }
    if !lowered.groups {
        config.set_supported_groups(Vec::new());
    }
    if !lowered.key_shares {
        config.set_key_shares(Vec::new());
    }
    if !lowered.signatures {
        config.set_signature_schemes(Vec::new());
    }
    config.set_alpn(Default::default());
    if !lowered.alps {
        config.set_alps(Vec::new(), false);
    }
    if !lowered.cert_compression {
        config.set_cert_compression(Vec::new());
    }
    config.set_delegated_credentials(Vec::new());
    config.set_record_size_limit(0);
    config.set_server_padding_request(None);
    config.set_encrypted_client_hello(false);
    config.set_ech_grease(EchGrease::Native);
    config.set_ocsp_stapling(false);
    config.set_signed_cert_timestamps(false);
    config.set_tls12_session_tickets(false);
    config.set_requested_trust_anchors(BoringRequestedTrustAnchors::omitted());
    config.set_legacy_extensions(false);
    config.set_extension_presence(BoringExtensionPresence::default());
    config.set_permute_extensions(false);
    config.set_grease(false);
    config.set_grease_signature_schemes(false);
    config.set_grease_values(GreaseValues::Pinned);
    config.set_client_hello_padding(Padding::Off);
    config.set_unknown_values(UnknownValues::Preserve);

    let mut extended_master_secret = false;
    let mut renegotiation_info = false;
    let mut presence = BoringExtensionPresence {
        ec_point_formats: lowered.ec_point_formats,
        omit_psk_key_exchange_modes: false,
    };
    let mut versions = false;
    let mut bodies = Vec::new();
    let mut order = Vec::with_capacity(capture.extensions.len());
    for extension in &capture.extensions {
        match (ExtensionId::from(extension.id), &extension.value) {
            (ExtensionId::SERVER_NAME, Value::ServerName { present: true }) => {}
            // The engine supplies these bytes. Compilation checks the required
            // shape; the native session owner validates its actual encoding.
            (ExtensionId::QUIC_TRANSPORT_PARAMETERS, Value::ConnectionLength(_))
            | (ExtensionId::PRE_SHARED_KEY, Value::PreSharedKeys { .. })
                if matches!(transport, TransportShape::Quic { .. }) => {}
            (ExtensionId::STATUS_REQUEST, Value::ConnectionLength(NATIVE_OCSP_REQUEST_LEN)) => {
                config.set_ocsp_stapling(true);
            }
            (ExtensionId::SUPPORTED_GROUPS, Value::U16List(groups)) => {
                if !lowered.groups {
                    let groups = supported_only(
                        report,
                        LoweredProfileItem::TlsSupportedGroups,
                        groups,
                        group_supported,
                    );
                    config.set_supported_groups(groups.into_iter().map(Into::into).collect());
                }
            }
            (ExtensionId::EC_POINT_FORMATS, Value::U8List(formats))
                if formats.as_ref() == [u8::from(ECPointFormat::Uncompressed)] =>
            {
                presence.ec_point_formats = true;
            }
            (ExtensionId::SIGNATURE_ALGORITHMS, Value::U16List(schemes)) => {
                if !lowered.signatures {
                    let schemes = supported_only(
                        report,
                        LoweredProfileItem::TlsSignatureAlgorithms,
                        schemes,
                        scheme_supported,
                    );
                    config.set_signature_schemes(schemes.into_iter().map(Into::into).collect());
                }
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
                if !lowered.cert_compression {
                    config
                        .set_cert_compression(algorithms.iter().copied().map(Into::into).collect());
                }
            }
            (ExtensionId::RECORD_SIZE_LIMIT, Value::U16List(limit))
                if limit.len() == 1 && limit[0] != 0 =>
            {
                config.set_record_size_limit(limit[0]);
            }
            (ExtensionId::SERVER_PADDING_REQUEST, Value::Literal(body)) => {
                let bytes = body.as_ref().try_into().map_err(|_error| {
                    BoxError::from_static_str("invalid captured server padding request")
                })?;
                config.set_server_padding_request(Some(u16::from_be_bytes(bytes)));
            }
            (ExtensionId::DELEGATED_CREDENTIAL, Value::U16List(schemes)) => {
                let schemes = supported_only(
                    report,
                    LoweredProfileItem::TlsSignatureAlgorithms,
                    schemes,
                    scheme_supported,
                );
                config.set_delegated_credentials(schemes.into_iter().map(Into::into).collect());
            }
            (ExtensionId::SESSION_TICKET, Value::ConnectionLength(0)) => {
                if !lowered.session_ticket {
                    config.set_tls12_session_tickets(true);
                }
            }
            (ExtensionId::SUPPORTED_VERSIONS, Value::U16List(values))
                if values.contains(&u16::from(ProtocolVersion::TLSv1_3)) =>
            {
                versions = true;
                if !lowered.versions {
                    let values = supported_only(
                        report,
                        LoweredProfileItem::TlsSupportedVersions,
                        values,
                        version_supported,
                    );
                    // Restrict native negotiation to this admitted offer. Explicit
                    // caller bounds are checked before these overrides are applied.
                    let mut offered = values
                        .iter()
                        .copied()
                        .filter(|value| !is_grease_u16(*value));
                    let first = offered.next().ok_or_else(|| {
                        BoxError::from_static_str("missing negotiable TLS version")
                    })?;
                    let (min, max) = offered.fold((first, first), |(min, max), value| {
                        (min.min(value), max.max(value))
                    });
                    config.set_supported_versions(values.into_iter().map(Into::into).collect());
                    config.set_min_version(min.into());
                    config.set_max_version(max.into());
                }
            }
            (ExtensionId::PSK_KEY_EXCHANGE_MODES, Value::U8List(modes))
                if modes.as_ref() == [u8::from(PskKeyExchangeMode::PskDheKe)] => {}
            (ExtensionId::KEY_SHARE, Value::KeyShares(shares)) => {
                if !lowered.key_shares {
                    config.set_key_shares(shares.iter().map(|share| share.group.into()).collect());
                }
            }
            (
                ExtensionId::OLD_APPLICATION_SETTINGS | ExtensionId::APPLICATION_SETTINGS,
                Value::Protocols(values),
            ) => {
                if !lowered.alps {
                    config.set_alps(
                        protocols(values).collect(),
                        ExtensionId::from(extension.id) == ExtensionId::APPLICATION_SETTINGS,
                    );
                }
            }
            (ExtensionId::TRUST_ANCHORS, Value::ConnectionLength(length)) => match anchors {
                Some(anchors) => {
                    anchors.identifier_list()?;
                    if anchors.extension_body().map(<[u8]>::len) != Some(usize::from(*length)) {
                        // Current trust anchors are connection-owned; keep the caller's.
                        lower(report, LoweredProfileItem::TlsTrustAnchors);
                    }
                    config.set_requested_trust_anchors(anchors.clone());
                }
                None => lower(report, LoweredProfileItem::TlsTrustAnchors),
            },
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
                // No native equivalent: omit it rather than emit a different shape.
                lower(
                    report,
                    LoweredProfileItem::TlsExtension {
                        extension: extension.id,
                    },
                );
                continue;
            }
        }
        order.push(extension.id.into());
    }
    config.set_extension_order(order);
    // Only a TLS 1.3 offer that omitted the modes omits them; other bodies keep native ones.
    presence.omit_psk_key_exchange_modes = versions
        && !capture
            .extensions
            .iter()
            .any(|extension| extension.id == u16::from(ExtensionId::PSK_KEY_EXCHANGE_MODES));
    if !versions && !lowered.versions {
        // Native TLS 1.3 always sends supported_versions.
        lower(report, LoweredProfileItem::TlsSupportedVersions);
    }
    if extended_master_secret != renegotiation_info {
        // Native TLS sends these two legacy extensions together.
        lower(report, LoweredProfileItem::TlsLegacyExtensionPair);
    }
    config.set_legacy_extensions(extended_master_secret || renegotiation_info);
    config.set_extension_presence(presence);
    config.set_extension_bodies(bodies);
    Ok(config)
}

// Keep the captured list order with unsupported entries removed. GREASE stays literal.
fn supported_only(
    report: &mut ProfilePreservationReport,
    item: LoweredProfileItem,
    values: &[u16],
    supported: impl Fn(u16) -> bool,
) -> Vec<u16> {
    let kept: Vec<_> = values
        .iter()
        .copied()
        .filter(|&value| is_grease_u16(value) || supported(value))
        .collect();
    if kept.len() != values.len() {
        lower(report, item);
    }
    kept
}

fn cipher_supported(value: u16) -> bool {
    SslCipher::from_value(value).is_some()
}

fn group_supported(value: u16) -> bool {
    let curve: Result<SslCurve, _> = SupportedGroup::from(value).rama_try_into();
    curve.is_ok()
}

fn scheme_supported(value: u16) -> bool {
    let algorithm: Result<SslSignatureAlgorithm, _> = SignatureScheme::from(value).rama_try_into();
    algorithm.is_ok()
}

fn version_supported(value: u16) -> bool {
    matches!(
        ProtocolVersion::from(value),
        ProtocolVersion::TLSv1_2 | ProtocolVersion::TLSv1_3
    )
}

// QUIC's native handshake filters non-TLS-1.3 offers, which is reported here.
fn validate_transport(
    transport: TransportShape,
    capture: &TlsCapture,
    report: &mut ProfilePreservationReport,
) -> Result<(), BoxError> {
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
                lower(report, LoweredProfileItem::QuicTransportParametersLength);
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
                lower(report, LoweredProfileItem::TlsSupportedVersions);
            }
            Ok(())
        }
        _ => Err(BoxError::from_static_str(
            "captured TLS transport and current binding differ",
        )),
    }
}

// Check backend capability separately from protocol encoding sizes. GREASE
// is intentionally non-negotiable and remains literal.
fn validate_native_lists(
    capture: &TlsCapture,
    lowered: &mut Lowered,
    report: &mut ProfilePreservationReport,
) -> Result<(), BoxError> {
    let sent = |id: ExtensionId| {
        capture
            .extensions
            .iter()
            .any(|extension| extension.id == u16::from(id))
    };
    // Native TLS 1.3 first hellos always emit these; an omission keeps the native field.
    for (required, native) in [
        (ExtensionId::SUPPORTED_GROUPS, &mut lowered.groups),
        (ExtensionId::SIGNATURE_ALGORITHMS, &mut lowered.signatures),
        (ExtensionId::SUPPORTED_VERSIONS, &mut lowered.versions),
        (ExtensionId::KEY_SHARE, &mut lowered.key_shares),
    ] {
        if !sent(required) {
            lower(
                report,
                LoweredProfileItem::TlsRequiredField {
                    extension: required.into(),
                },
            );
            *native = true;
        }
    }
    // A PSK offer requires the key exchange modes (RFC 8446 §4.2.9).
    if sent(ExtensionId::PRE_SHARED_KEY) && !sent(ExtensionId::PSK_KEY_EXCHANGE_MODES) {
        return Err(BoxError::from_static_str(
            "captured pre_shared_key lacks psk_key_exchange_modes",
        ));
    }
    // An empty native list would fail to build; keep the native list instead.
    let none_supported =
        |values: &[u16], supported: fn(u16) -> bool| !values.iter().any(|&value| supported(value));
    let list = |id: ExtensionId| {
        capture
            .extensions
            .iter()
            .find_map(|extension| match &extension.value {
                Value::U16List(values) if extension.id == u16::from(id) => Some(values.as_ref()),
                _ => None,
            })
    };
    if !lowered.ciphers && none_supported(&capture.ciphers, cipher_supported) {
        lower(report, LoweredProfileItem::TlsCipherSuites);
        lowered.ciphers = true;
    } else if !lowered.ciphers
        && capture
            .ciphers
            .iter()
            .any(|&cipher| !is_grease_u16(cipher) && !cipher_supported(cipher))
    {
        lower(report, LoweredProfileItem::TlsCipherNegotiation);
    }
    if !lowered.groups
        && list(ExtensionId::SUPPORTED_GROUPS)
            .is_some_and(|values| none_supported(values, group_supported))
    {
        lower(report, LoweredProfileItem::TlsSupportedGroups);
        lowered.groups = true;
    }
    if !lowered.signatures
        && list(ExtensionId::SIGNATURE_ALGORITHMS)
            .is_some_and(|values| none_supported(values, scheme_supported))
    {
        lower(report, LoweredProfileItem::TlsSignatureAlgorithms);
        lowered.signatures = true;
    }
    // Native key shares have fixed sizes per group.
    let unsupported_share = capture.extensions.iter().any(|extension| {
        let Value::KeyShares(shares) = &extension.value else {
            return false;
        };
        shares.iter().any(|share| {
            let group = SupportedGroup::from(share.group);
            let expected = if group.is_grease() {
                Some(NATIVE_GREASE_KEY_SHARE_LEN)
            } else {
                group.tls13_client_key_share_len()
            };
            expected != Some(share.length)
        })
    });
    if !lowered.key_shares && unsupported_share {
        lower(report, LoweredProfileItem::TlsKeyShares);
        lowered.key_shares = true;
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
    // A TLS 1.2 offer always sends point formats natively; a TLS 1.3-only one may.
    if offers_tls12 && !sent(ExtensionId::EC_POINT_FORMATS) {
        lower(report, LoweredProfileItem::TlsEcPointFormats);
        lowered.ec_point_formats = true;
    }
    // Native TLS sends session tickets only alongside a TLS 1.2 offer.
    if !offers_tls12 && sent(ExtensionId::SESSION_TICKET) {
        lower(report, LoweredProfileItem::TlsSessionTicket);
        lowered.session_ticket = true;
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
                lowered.alps = true;
            }
            alps_seen = true;
        }
    }
    if lowered.alps {
        lower(report, LoweredProfileItem::TlsAlps);
    }
    for extension in &capture.extensions {
        match (ExtensionId::from(extension.id), &extension.value) {
            (ExtensionId::COMPRESS_CERTIFICATE, Value::U16List(values)) => {
                if values.iter().enumerate().any(|(index, &value)| {
                    values[..index].contains(&value)
                        || !crate::certificate_compression::SUPPORTED_CERTIFICATE_COMPRESSION
                            .contains(&CertificateCompressionAlgorithm::from(value))
                }) {
                    lower(report, LoweredProfileItem::TlsCertificateCompression);
                    lowered.cert_compression = true;
                }
            }
            // Without GREASE the connector derives a descending native range.
            (ExtensionId::SUPPORTED_VERSIONS, Value::U16List(values))
                if !values.iter().any(|&value| is_grease_u16(value))
                    && values.windows(2).any(|pair| pair[0] <= pair[1]) =>
            {
                lower(report, LoweredProfileItem::TlsSupportedVersions);
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
    if let Some(groups) = groups
        && !lowered.key_shares
    {
        let raw_groups = groups
            .iter()
            .enumerate()
            .any(|(index, value)| is_grease_u16(*value) || groups[..index].contains(value));
        let native_order = capture.extensions.iter().all(|extension| {
            let Value::KeyShares(shares) = &extension.value else {
                return true;
            };
            let mut previous = None;
            shares.iter().all(|share| {
                let Some(position) = groups.iter().position(|group| *group == share.group) else {
                    return false;
                };
                let ordered = raw_groups || previous.is_none_or(|previous| previous < position);
                previous = Some(position);
                ordered
            })
        });
        if !native_order {
            // Native key shares follow the supported-groups order.
            lower(report, LoweredProfileItem::TlsKeyShares);
            lowered.key_shares = true;
        }
    }
    Ok(())
}

// A captured offer may narrow caller policy, but must never broaden it.
fn version_bounds_conflict(
    capture: &TlsCapture,
    min: Option<ProtocolVersion>,
    max: Option<ProtocolVersion>,
) -> Result<bool, BoxError> {
    for extension in &capture.extensions {
        if extension.id != u16::from(ExtensionId::SUPPORTED_VERSIONS) {
            continue;
        }
        let Value::U16List(versions) = &extension.value else {
            return Err(BoxError::from_static_str(
                "captured TLS version list is malformed",
            ));
        };
        if versions
            .iter()
            .filter(|&&version| !is_grease_u16(version))
            .any(|&version| {
                min.is_some_and(|min| version < u16::from(min))
                    || max.is_some_and(|max| version > u16::from(max))
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
}
