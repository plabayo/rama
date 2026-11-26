//! Map bounded TLS observations to native wire settings.
//!
//! Captured secrets are never available here. Connection-owned advertisements
//! need current application bindings. A captured value this backend cannot emit
//! falls back to native or caller behaviour and is recorded as a difference;
//! only malformed or protocol-invalid captures fail. Listed values this backend
//! cannot negotiate are filtered out and reported, unless [`NonNegotiableValues`]
//! retains them.

use std::{borrow::Cow, ops::RangeInclusive};

use rama_boring::ssl::{EchGreaseShape, GreaseValues, Padding, UnknownValues};
use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
};
use rama_net::tls::{ApplicationProtocol, TlsAlpn};
use rama_tls::{
    CertificateCompressionAlgorithm, CipherSuite, CompressionAlgorithm, ECPointFormat, ExtensionId,
    ProtocolVersion, PskKeyExchangeMode, SupportedGroup,
    client::{TlsClientConfig, TlsClientSni},
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
use rama_utils::macros::generate_set_and_with;

use crate::client::{
    BoringClientConfigExt as _, BoringRequestedTrustAnchors, BoringTlsConnectorConfig,
    config::{BoringExtensionPresence, set_alpn_list_with_coupled_alps},
    ech::EchGrease,
    negotiable::{
        cipher_negotiable, cipher_supported, group_supported, scheme_supported, version_supported,
    },
};

/// Replace a compiled ALPN offer; a changed offer keeps captured ALPS within it.
#[doc(hidden)]
pub fn set_alpn(settings: &TlsClientConfig, alpn: TlsAlpn) {
    set_alpn_list_with_coupled_alps(settings.as_extensions(), alpn);
}

/// SNI policy implied by the effective captured hello, without retaining its destination.
#[must_use]
pub fn captured_sni_policy(capture: &TlsCapture) -> TlsClientSni {
    capture
        .extensions
        .iter()
        .find_map(
            |extension| match (ExtensionId::from(extension.id), &extension.value) {
                (ExtensionId::SERVER_NAME, Value::IpServerName) => Some(TlsClientSni::IncludeIp),
                (ExtensionId::SERVER_NAME, Value::ServerName { present: true }) => {
                    Some(TlsClientSni::Auto)
                }
                _ => None,
            },
        )
        .unwrap_or(TlsClientSni::Disabled)
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
/// releasing handshake output. QUIC parameter bytes come from the engine; wire
/// compilation never copies them.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum TransportShape {
    /// A TLS connection over TCP.
    Tcp,
    /// A QUIC connection; the engine supplies the transport parameters.
    Quic,
}

/// What a compiled offer sends for captured values this backend cannot negotiate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NonNegotiable {
    /// Leave them out, keeping the order of the other values and the GREASE slots.
    #[default]
    Filter,
    /// Keep IANA-discouraged cipher suites, RFC 8422 deprecated curves, historical
    /// MD5/RSA, SHA-1, SHA-224 and DSA signature pairs, and SSLv3 through TLS 1.1.
    /// An unsupported selection still fails the handshake.
    RetainLegacy,
    /// Send them as captured; a server that selects one fails the handshake.
    Retain,
}

/// Per-list choice for captured values this backend cannot negotiate.
///
/// Every list filters by default, and filtered values are reported. GREASE and the
/// renegotiation SCSV are signals and are always sent as captured. A list without
/// any negotiable value keeps the native list under every policy. Delegated
/// credential schemes are always filtered, and certificate compression and key
/// shares fall back to native lists: the backend sets those natively only.
#[derive(Debug, Clone, Copy, Default)]
pub struct NonNegotiableValues {
    cipher_suites: NonNegotiable,
    supported_groups: NonNegotiable,
    signature_algorithms: NonNegotiable,
    supported_versions: NonNegotiable,
}

impl NonNegotiableValues {
    /// Filter every list.
    #[must_use]
    pub const fn new() -> Self {
        Self::all(NonNegotiable::Filter)
    }

    /// Apply `choice` to every list.
    #[must_use]
    pub const fn all(choice: NonNegotiable) -> Self {
        Self {
            cipher_suites: choice,
            supported_groups: choice,
            signature_algorithms: choice,
            supported_versions: choice,
        }
    }

    generate_set_and_with!(
        /// Set the choice for the cipher suite list.
        pub const fn cipher_suites(mut self, choice: NonNegotiable) -> Self {
            self.cipher_suites = choice;
            self
        }
    );

    generate_set_and_with!(
        /// Set the choice for the supported groups list.
        pub const fn supported_groups(mut self, choice: NonNegotiable) -> Self {
            self.supported_groups = choice;
            self
        }
    );

    generate_set_and_with!(
        /// Set the choice for the signature algorithms list.
        pub const fn signature_algorithms(mut self, choice: NonNegotiable) -> Self {
            self.signature_algorithms = choice;
            self
        }
    );

    generate_set_and_with!(
        /// Set the choice for the supported versions list.
        pub const fn supported_versions(mut self, choice: NonNegotiable) -> Self {
            self.supported_versions = choice;
            self
        }
    );
}

/// Compile native wire settings for the selected TLS capture.
///
/// `transport` describes the required wire shape, not a prepared connection.
/// `anchors` replaces captured trust-anchor identifiers, and supplies them for
/// length-only captures. Captured parameter, ticket and secret bytes are never
/// reused. This function does not prepare an SSL session or establish backend
/// support for an entire captured connection: the owning connector must also
/// bind the destination, caller policy, session state and other selected slots.
/// Captured items this backend cannot emit exactly are left to native or caller
/// configuration and recorded in `report`; `retention` decides per list whether
/// values it cannot negotiate are filtered out or sent as captured.
pub fn compile(
    transport: TransportShape,
    capture: &TlsCapture,
    anchors: Option<&BoringRequestedTrustAnchors>,
    retention: NonNegotiableValues,
    report: &mut ProfilePreservationReport,
) -> Result<TlsClientConfig, BoxError> {
    compile_lowered(
        transport,
        capture,
        anchors,
        retention,
        Lowered::default(),
        (None, None),
        report,
    )
}

/// Compile wire settings while retaining explicit caller version, cipher and ECH policy.
/// Other caller policy, including verification and credentials, stays in the
/// connection owner's effective configuration and is not returned as an override.
pub fn compile_for_policy(
    transport: TransportShape,
    capture: &TlsCapture,
    policy: &BoringTlsConnectorConfig<'_>,
    retention: NonNegotiableValues,
    report: &mut ProfilePreservationReport,
) -> Result<TlsClientConfig, BoxError> {
    // Validate caller contradictions before captured wire settings can replace intent.
    policy
        .ech_requirement
        .copied()
        .unwrap_or_default()
        .intent(policy.encrypted_client_hello)?;
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
    let mut config = compile_lowered(
        transport,
        capture,
        policy.requested_trust_anchors,
        retention,
        lowered,
        (
            policy.min_version.map(|version| version.0),
            policy.max_version.map(|version| version.0),
        ),
        report,
    )?;
    if let Some(intent) = policy.encrypted_client_hello {
        let captured = BoringTlsConnectorConfig::from_extensions(config.as_extensions())
            .encrypted_client_hello
            .is_some_and(|intent| intent.0);
        if intent.0 != captured {
            lower(
                report,
                LoweredProfileItem::TlsExtension {
                    extension: ExtensionId::ENCRYPTED_CLIENT_HELLO.into(),
                },
            );
        }
        config.set_encrypted_client_hello(intent.0);
    }
    Ok(config)
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
    retention: NonNegotiableValues,
    mut lowered: Lowered,
    caller: (Option<ProtocolVersion>, Option<ProtocolVersion>),
    report: &mut ProfilePreservationReport,
) -> Result<TlsClientConfig, BoxError> {
    capture.validate_fields(TlsCaptureLimits::default())?;
    validate_transport(transport, capture, report)?;
    if !lowered.versions
        && captured_versions(capture)
            .is_some_and(|values| !values.iter().any(|&value| version_supported(value)))
    {
        // A list without a negotiable version cannot connect; keep the native list instead.
        lower(report, LoweredProfileItem::TlsSupportedVersions);
        lowered.versions = true;
    }
    let offer = Offer::effective(transport, capture, lowered.versions, caller);
    validate_native_lists(capture, offer, &mut lowered, report)?;
    let mut config = TlsClientConfig::new();
    let legacy_field = legacy_offer(capture).unwrap_or(ProtocolVersion::TLSv1_2);
    if capture.protocol_version != u16::from(legacy_field)
        || capture.compression.as_ref() != [u8::from(CompressionAlgorithm::Null)]
    {
        // Native TLS emits these legacy values for the offered version range.
        lower(report, LoweredProfileItem::TlsLegacyFields);
    }

    // Return wire overrides only. The caller layers these over its current
    // verification, credentials and session policy before native preparation.
    if !lowered.ciphers {
        // Validation kept the native list when no captured suite can negotiate.
        let ciphers = negotiable(
            report,
            retention.cipher_suites,
            LoweredProfileItem::TlsCipherSuites,
            &capture.ciphers,
            |value| cipher_supported(value, offer.range()),
        );
        config.set_cipher_suites(ciphers.iter().copied().map(Into::into).collect());
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
    config.set_cert_compression(Vec::new());
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
    // GREASE slots get values drawn per connection, as browsers do.
    config.set_grease_values(GreaseValues::Fresh);
    config.set_client_hello_padding(Padding::Off);
    config.set_unknown_values(UnknownValues::Preserve);

    let tls13 = offer.tls13();
    let mut extended_master_secret = false;
    let mut renegotiation_info = false;
    let mut presence = BoringExtensionPresence {
        ec_point_formats: lowered.ec_point_formats,
        omit_psk_key_exchange_modes: false,
        omit_renegotiation_info: false,
    };
    let mut versions = false;
    let mut bodies = Vec::new();
    let mut order = Vec::with_capacity(capture.extensions.len());
    for (index, extension) in capture.extensions.iter().enumerate() {
        match (ExtensionId::from(extension.id), &extension.value) {
            (
                ExtensionId::SERVER_NAME,
                Value::ServerName { present: true } | Value::IpServerName,
            ) => {}
            // Browsers pad by the same length rule as BoringSSL, last or before
            // pre_shared_key; the body length follows each connection's ClientHello.
            (ExtensionId::PADDING, Value::ConnectionLength(_))
                if matches!(transport, TransportShape::Tcp)
                    && capture.extensions[index + 1..].iter().all(|later| {
                        ExtensionId::from(later.id) == ExtensionId::PRE_SHARED_KEY
                    }) =>
            {
                config.set_client_hello_padding(Padding::Native);
                continue;
            }
            // The engine supplies these bytes for its actual session.
            (ExtensionId::QUIC_TRANSPORT_PARAMETERS, Value::ConnectionLength(_))
            | (ExtensionId::PRE_SHARED_KEY, Value::PreSharedKeys { .. })
                if matches!(transport, TransportShape::Quic) => {}
            (ExtensionId::STATUS_REQUEST, Value::ConnectionLength(NATIVE_OCSP_REQUEST_LEN)) => {
                config.set_ocsp_stapling(true);
            }
            (ExtensionId::SUPPORTED_GROUPS, Value::U16List(groups)) => {
                if !lowered.groups {
                    let groups = negotiable(
                        report,
                        retention.supported_groups,
                        LoweredProfileItem::TlsSupportedGroups,
                        groups,
                        |value| group_supported(value, tls13),
                    );
                    config.set_supported_groups(groups.iter().copied().map(Into::into).collect());
                }
            }
            (ExtensionId::EC_POINT_FORMATS, Value::U8List(formats))
                if formats.as_ref() == [u8::from(ECPointFormat::Uncompressed)] =>
            {
                presence.ec_point_formats = true;
            }
            (ExtensionId::SIGNATURE_ALGORITHMS, Value::U16List(schemes)) => {
                if !lowered.signatures {
                    let schemes = negotiable(
                        report,
                        retention.signature_algorithms,
                        LoweredProfileItem::TlsSignatureAlgorithms,
                        schemes,
                        scheme_supported,
                    );
                    config.set_signature_schemes(schemes.iter().copied().map(Into::into).collect());
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
                let schemes = negotiable(
                    report,
                    NonNegotiable::Filter,
                    LoweredProfileItem::TlsSignatureAlgorithms,
                    schemes,
                    scheme_supported,
                );
                config.set_delegated_credentials(schemes.iter().copied().map(Into::into).collect());
            }
            (ExtensionId::SESSION_TICKET, Value::ConnectionLength(0)) => {
                if !lowered.session_ticket {
                    config.set_tls12_session_tickets(true);
                }
            }
            (ExtensionId::SUPPORTED_VERSIONS, Value::U16List(values)) => {
                versions = true;
                if !lowered.versions {
                    let values = negotiable(
                        report,
                        retention.supported_versions,
                        LoweredProfileItem::TlsSupportedVersions,
                        values,
                        version_supported,
                    );
                    // Negotiate the whole negotiable range. Explicit caller bounds are
                    // checked before these overrides are applied.
                    let mut offered = values
                        .iter()
                        .copied()
                        .filter(|&value| version_supported(value));
                    let first = offered.next().ok_or_else(|| {
                        BoxError::from_static_str("missing negotiable TLS version")
                    })?;
                    let (min, max) = offered.fold((first, first), |(min, max), value| {
                        (min.min(value), max.max(value))
                    });
                    if max < u16::from(ProtocolVersion::TLSv1_3) {
                        // The engine writes supported_versions only with a TLS 1.3 maximum
                        // (`ext_supported_versions_add_clienthello` in the vendored patch).
                        lower(report, LoweredProfileItem::TlsSupportedVersions);
                    } else if native_version_range_reorders(&values) {
                        // Without GREASE or gaps the connector derives a descending native range.
                        lower(report, LoweredProfileItem::TlsSupportedVersions);
                    }
                    config.set_supported_versions(values.iter().copied().map(Into::into).collect());
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
            (ExtensionId::TRUST_ANCHORS, Value::Literal(body)) => {
                let requested = match anchors {
                    Some(anchors) => {
                        if anchors.extension_body() != Some(body.as_ref()) {
                            lower(report, LoweredProfileItem::TlsTrustAnchors);
                        }
                        anchors.clone()
                    }
                    None => BoringRequestedTrustAnchors::from_raw_extension_body(body.clone()),
                };
                requested.identifier_list()?;
                config.set_requested_trust_anchors(requested);
            }
            (ExtensionId::TRUST_ANCHORS, Value::ConnectionLength(length)) => match anchors {
                Some(anchors) => {
                    anchors.identifier_list()?;
                    if anchors.extension_body().map(<[u8]>::len) != Some(usize::from(*length)) {
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
                let shape = EchGrease::Shape {
                    kdf_id: *kdf,
                    aead_id: *aead,
                    encapsulated_key_len: usize::from(*enc),
                    payload_len: usize::from(*payload),
                };
                let shape = if shape.native_shape().is_ok() {
                    shape
                } else {
                    lower(
                        report,
                        LoweredProfileItem::TlsExtension {
                            extension: extension.id,
                        },
                    );
                    EchGrease::Shape {
                        kdf_id: 1,
                        aead_id: if (1..=3).contains(aead) { *aead } else { 1 },
                        encapsulated_key_len: EchGreaseShape::ENCAPSULATED_KEY_LEN,
                        payload_len: usize::from(*payload).clamp(
                            EchGreaseShape::MIN_PAYLOAD_LEN,
                            EchGreaseShape::MAX_PAYLOAD_LEN,
                        ),
                    }
                };
                config.set_ech_grease(shape);
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
    presence.omit_psk_key_exchange_modes = tls13
        && offers_tls13(capture)
        && !capture
            .extensions
            .iter()
            .any(|extension| extension.id == u16::from(ExtensionId::PSK_KEY_EXCHANGE_MODES));
    if !versions && !lowered.versions {
        if let Some(version) = legacy_offer(capture) {
            // Without supported_versions the legacy field is the only version offered.
            config.set_min_version(version);
            config.set_max_version(version);
        } else {
            // Native TLS 1.3 always sends supported_versions.
            lower(report, LoweredProfileItem::TlsSupportedVersions);
        }
    }
    // Below TLS 1.3 native TLS always sends EMS; RI is omitted only while RFC 5746 stays signalled.
    let below_tls13 = offer.below_tls13();
    let legacy = extended_master_secret || renegotiation_info || below_tls13;
    let scsv_lost = lowered.ciphers
        && capture
            .ciphers
            .contains(&u16::from(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV));
    presence.omit_renegotiation_info = legacy && !renegotiation_info && !scsv_lost;
    let sends_renegotiation_info = legacy && !presence.omit_renegotiation_info;
    if legacy != extended_master_secret || sends_renegotiation_info != renegotiation_info {
        // Native TLS cannot send RI without EMS, nor omit EMS below a TLS 1.3 minimum.
        lower(report, LoweredProfileItem::TlsLegacyExtensionPair);
    }
    config.set_legacy_extensions(extended_master_secret || renegotiation_info);
    config.set_extension_presence(presence);
    config.set_extension_bodies(bodies);
    Ok(config)
}

// The captured list with values the backend cannot negotiate filtered or retained.
// GREASE slots and signalling values stay in place either way.
// Only a list that actually drops a value is copied.
fn negotiable<'a>(
    report: &mut ProfilePreservationReport,
    choice: NonNegotiable,
    dropped: LoweredProfileItem,
    values: &'a [u16],
    supported: impl Fn(u16) -> bool,
) -> Cow<'a, [u16]> {
    let usable = |value| is_grease_u16(value) || supported(value);
    let retained = |value| match choice {
        NonNegotiable::Filter => false,
        NonNegotiable::RetainLegacy => legacy_value(dropped, value),
        NonNegotiable::Retain => true,
    };
    let mut has_dropped = false;
    let mut has_retained = false;
    for &value in values {
        if !usable(value) {
            if retained(value) {
                has_retained = true;
            } else {
                has_dropped = true;
            }
        }
    }
    if has_retained {
        lower(report, cannot_negotiate(dropped));
    }
    if !has_dropped {
        return Cow::Borrowed(values);
    }
    lower(report, dropped);
    Cow::Owned(
        values
            .iter()
            .copied()
            .filter(|&value| usable(value) || retained(value))
            .collect(),
    )
}

// Only assigned values with a documented legacy classification qualify.
fn legacy_value(property: LoweredProfileItem, value: u16) -> bool {
    match property {
        // TLS Cipher Suites marked D in the IANA registry (RFC 9847).
        LoweredProfileItem::TlsCipherSuites => matches!(value,
            0x0001..=0x001b
                | 0x001e
                | 0x0020..=0x0022
                | 0x0024..=0x0046
                | 0x0067..=0x006d
                | 0x0084..=0x008a
                | 0x008e..=0x00a7
                | 0x00aa..=0x00ad
                | 0x00b0..=0x00c5
                | 0xc001..=0xc007
                | 0xc00b..=0xc011
                | 0xc015..=0xc019
                | 0xc025..=0xc026
                | 0xc029..=0xc02a
                | 0xc02d..=0xc02e
                | 0xc031..=0xc033
                | 0xc039..=0xc047
                | 0xc04a..=0xc04b
                | 0xc04e..=0xc05b
                | 0xc05e..=0xc05f
                | 0xc062..=0xc063
                | 0xc066..=0xc069
                | 0xc06c..=0xc06f
                | 0xc074..=0xc075
                | 0xc078..=0xc085
                | 0xc088..=0xc089
                | 0xc08c..=0xc08d
                | 0xc090..=0xc093
                | 0xc096..=0xc099
                | 0xc09c..=0xc0a3
                | 0xc0a6..=0xc0a7
                | 0xc0aa..=0xc0ab
                | 0xc0b4..=0xc0b5
                | 0xccaa
                | 0xccad..=0xccae
        ),
        // RFC 8422 section 5.1.1 retires these named and explicitly defined curves.
        LoweredProfileItem::TlsSupportedGroups => matches!(value, 1..=22 | 0xff01..=0xff02),
        // Historical TLS 1.2 hash/signature pairs for MD5/RSA, SHA-1, SHA-224 and DSA.
        LoweredProfileItem::TlsSignatureAlgorithms => matches!(value,
            0x0101 | 0x0201..=0x0203 | 0x0301..=0x0303 | 0x0402 | 0x0502 | 0x0602
        ),
        // SSLv3 and TLS 1.0/1.1 are retired stream protocol versions (RFC 7568/8996).
        LoweredProfileItem::TlsSupportedVersions => matches!(value, 0x0300..=0x0302),
        _ => false,
    }
}

// The item reporting a retained list whose filtered form reports `dropped`.
fn cannot_negotiate(dropped: LoweredProfileItem) -> LoweredProfileItem {
    match dropped {
        LoweredProfileItem::TlsCipherSuites => LoweredProfileItem::TlsCipherNegotiation,
        LoweredProfileItem::TlsSupportedGroups => LoweredProfileItem::TlsGroupNegotiation,
        LoweredProfileItem::TlsSignatureAlgorithms => {
            LoweredProfileItem::TlsSignatureAlgorithmNegotiation
        }
        LoweredProfileItem::TlsSupportedVersions => LoweredProfileItem::TlsVersionNegotiation,
        other => other,
    }
}

// QUIC's native handshake filters non-TLS-1.3 offers, which is reported here.
fn validate_transport(
    transport: TransportShape,
    capture: &TlsCapture,
    report: &mut ProfilePreservationReport,
) -> Result<(), BoxError> {
    match (transport, capture.transport) {
        (TransportShape::Tcp, TlsCaptureTransport::Tcp) => Ok(()),
        (TransportShape::Quic, TlsCaptureTransport::Quic) => {
            if !offers_tls13(capture) {
                return Err(BoxError::from_static_str(
                    "captured QUIC offer does not list TLS 1.3",
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
    offer: Offer,
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
    // A TLS 1.2-only offer has no TLS 1.3 fields to keep.
    let tls13 = offer.tls13();
    // Native TLS sends signature_algorithms only when it offers TLS 1.2 or later.
    let below_tls12 = offer.max < u16::from(ProtocolVersion::TLSv1_2);
    if below_tls12 && sent(ExtensionId::SIGNATURE_ALGORITHMS) {
        lower(
            report,
            LoweredProfileItem::TlsExtension {
                extension: ExtensionId::SIGNATURE_ALGORITHMS.into(),
            },
        );
    }
    for (required, native) in [
        (ExtensionId::SUPPORTED_GROUPS, &mut lowered.groups),
        (ExtensionId::SIGNATURE_ALGORITHMS, &mut lowered.signatures),
        (ExtensionId::SUPPORTED_VERSIONS, &mut lowered.versions),
        (ExtensionId::KEY_SHARE, &mut lowered.key_shares),
    ] {
        let tls13_only = matches!(
            required,
            ExtensionId::SUPPORTED_VERSIONS | ExtensionId::KEY_SHARE
        );
        if (tls13_only && !tls13) || (below_tls12 && required == ExtensionId::SIGNATURE_ALGORITHMS)
        {
            continue;
        }
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
    // A list without a negotiable value cannot connect; keep the native list instead.
    let none_supported = |values: &[u16], supported: &dyn Fn(u16) -> bool| {
        !values.iter().any(|&value| supported(value))
    };
    let list = |id: ExtensionId| {
        capture
            .extensions
            .iter()
            .find_map(|extension| match &extension.value {
                Value::U16List(values) if extension.id == u16::from(id) => Some(values.as_ref()),
                _ => None,
            })
    };
    if !lowered.ciphers
        && none_supported(&capture.ciphers, &|value| {
            cipher_negotiable(value, offer.range())
        })
    {
        lower(report, LoweredProfileItem::TlsCipherSuites);
        lowered.ciphers = true;
    }
    if !lowered.groups
        && list(ExtensionId::SUPPORTED_GROUPS)
            .is_some_and(|values| none_supported(values, &|value| group_supported(value, tls13)))
    {
        lower(report, LoweredProfileItem::TlsSupportedGroups);
        lowered.groups = true;
    }
    if !lowered.signatures
        && list(ExtensionId::SIGNATURE_ALGORITHMS)
            .is_some_and(|values| none_supported(values, &scheme_supported))
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
    let offers_tls12 = offer.below_tls13();
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
            // Protocols outside the ALPN offer are sent as listed.
            if alps_seen
                || protocols
                    .iter()
                    .enumerate()
                    .any(|(index, protocol)| protocols[..index].contains(protocol))
            {
                lowered.alps = true;
            }
            alps_seen = true;
            // Native TLS offers ALPS only with a TLS 1.3 maximum.
            lowered.alps |= !tls13;
        }
    }
    if lowered.alps {
        lower(report, LoweredProfileItem::TlsAlps);
    }
    for extension in &capture.extensions {
        if let (ExtensionId::COMPRESS_CERTIFICATE, Value::U16List(values)) =
            (ExtensionId::from(extension.id), &extension.value)
            && values.iter().enumerate().any(|(index, &value)| {
                values[..index].contains(&value)
                    || !crate::certificate_compression::SUPPORTED_CERTIFICATE_COMPRESSION
                        .contains(&CertificateCompressionAlgorithm::from(value))
            })
        {
            lower(report, LoweredProfileItem::TlsCertificateCompression);
            lowered.cert_compression = true;
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

/// Whether the connector would emit `values` as its native descending range while
/// they differ from it in order or repeats; a list with GREASE, a gap or a value the
/// backend cannot negotiate is sent as listed instead.
fn native_version_range_reorders(values: &[u16]) -> bool {
    if values
        .iter()
        .any(|&value| is_grease_u16(value) || !version_supported(value))
    {
        return false;
    }
    let (Some(&min), Some(&max)) = (values.iter().min(), values.iter().max()) else {
        return false;
    };
    let range = [
        ProtocolVersion::TLSv1_3,
        ProtocolVersion::TLSv1_2,
        ProtocolVersion::TLSv1_1,
        ProtocolVersion::TLSv1_0,
    ]
    .into_iter()
    .map(u16::from)
    .filter(|version| (min..=max).contains(version));
    range.clone().all(|version| values.contains(&version)) && !range.eq(values.iter().copied())
}

/// The TLS versions a compiled connection offers, after caller bounds and filtering.
#[derive(Debug, Clone, Copy)]
struct Offer {
    min: u16,
    max: u16,
}

impl Offer {
    // Native client defaults when neither the capture nor the caller bounds a side.
    const NATIVE_MIN: u16 = 0x0303;
    const NATIVE_MAX: u16 = 0x0304;

    fn effective(
        transport: TransportShape,
        capture: &TlsCapture,
        lowered_versions: bool,
        (min, max): (Option<ProtocolVersion>, Option<ProtocolVersion>),
    ) -> Self {
        let tls13 = u16::from(ProtocolVersion::TLSv1_3);
        if matches!(transport, TransportShape::Quic) {
            return Self {
                min: tls13,
                max: tls13,
            };
        }
        if !lowered_versions {
            if let Some(version) = legacy_offer(capture) {
                let version = u16::from(version);
                return Self {
                    min: version,
                    max: version,
                };
            }
            let negotiable = || {
                captured_versions(capture)
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|&value| version_supported(value))
            };
            if let (Some(min), Some(max)) = (negotiable().min(), negotiable().max()) {
                return Self { min, max };
            }
        }
        Self {
            min: min.map_or(Self::NATIVE_MIN, u16::from),
            max: max.map_or(Self::NATIVE_MAX, u16::from),
        }
    }

    fn range(self) -> RangeInclusive<u16> {
        self.min..=self.max
    }

    fn tls13(self) -> bool {
        self.max >= u16::from(ProtocolVersion::TLSv1_3)
    }

    fn below_tls13(self) -> bool {
        self.min < u16::from(ProtocolVersion::TLSv1_3)
    }
}

/// Whether the capture lists TLS 1.3.
fn offers_tls13(capture: &TlsCapture) -> bool {
    captured_versions(capture)
        .is_some_and(|values| values.contains(&u16::from(ProtocolVersion::TLSv1_3)))
}

fn captured_versions(capture: &TlsCapture) -> Option<&[u16]> {
    capture.extensions.iter().find_map(|extension| {
        match (ExtensionId::from(extension.id), &extension.value) {
            (ExtensionId::SUPPORTED_VERSIONS, Value::U16List(values)) => Some(values.as_ref()),
            _ => None,
        }
    })
}

/// The version a ClientHello without any TLS 1.3 extension offers: its legacy field,
/// when the backend negotiates it. A hello mixing TLS 1.3 fields keeps native TLS 1.3
/// and reports what differs.
fn legacy_offer(capture: &TlsCapture) -> Option<ProtocolVersion> {
    let version = capture.protocol_version;
    (version_supported(version)
        && version < u16::from(ProtocolVersion::TLSv1_3)
        && !capture.extensions.iter().any(|extension| {
            matches!(
                ExtensionId::from(extension.id),
                ExtensionId::SUPPORTED_VERSIONS
                    | ExtensionId::KEY_SHARE
                    | ExtensionId::PSK_KEY_EXCHANGE_MODES
                    | ExtensionId::PRE_SHARED_KEY
                    | ExtensionId::EARLY_DATA
                    | ExtensionId::COOKIE
                    | ExtensionId::POST_HANDSHAKE_AUTH
                    | ExtensionId::DELEGATED_CREDENTIAL
                    | ExtensionId::APPLICATION_SETTINGS
                    | ExtensionId::OLD_APPLICATION_SETTINGS
                    | ExtensionId::ENCRYPTED_CLIENT_HELLO
            )
        }))
    .then(|| ProtocolVersion::from(version))
}

// A captured offer may narrow caller policy, but must never broaden it.
fn version_bounds_conflict(
    capture: &TlsCapture,
    min: Option<ProtocolVersion>,
    max: Option<ProtocolVersion>,
) -> Result<bool, BoxError> {
    if let Some(version) = legacy_offer(capture) {
        return Ok(min.is_some_and(|min| min > version) || max.is_some_and(|max| max < version));
    }
    for extension in &capture.extensions {
        if extension.id != u16::from(ExtensionId::SUPPORTED_VERSIONS) {
            continue;
        }
        let Value::U16List(versions) = &extension.value else {
            return Err(BoxError::from_static_str(
                "captured TLS version list is malformed",
            ));
        };
        // Values the backend cannot negotiate never widen negotiation, filtered or retained.
        if versions
            .iter()
            .filter(|&&version| version_supported(version))
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
