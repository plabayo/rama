#[cfg(feature = "compression")]
use rama_boring::ssl::SslSignatureAlgorithm;
#[cfg(feature = "compression")]
use std::fmt;

use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
};

use rama_boring::ssl::{HandshakeError, SslCurve, UnknownValues};
use rama_core::conversion::RamaTryInto as _;
use rama_net::{address::Host, tls::ApplicationProtocol};
use rama_tls::{
    CertificateCompressionAlgorithm, CipherSuite, CompressionAlgorithm, ExtensionId,
    ProtocolVersion, SignatureScheme, SupportedGroup,
    client::{
        ClientHello, ClientHelloExtension, ServerVerifyMode, TlsClientConfig,
        parse_client_hello_handshake,
    },
};
use rama_ua::{
    UserAgentKind,
    profile::{model::tls::TlsProfile, selection::database::UserAgentDatabase},
};

use super::{
    BoringClientConfigExt, BoringRequestedTrustAnchors, BoringTlsConnectorConfig,
    TlsConnectorContext, TlsConnectorContextBuilder, TlsConnectorData,
};

#[test]
fn permutation_is_per_handshake_and_takes_precedence_over_explicit_order() {
    let declared = [43u16, 10, 13, 16];
    let mut membership = None;
    for (permute, explicit) in [
        (None, false),
        (None, true),
        (Some(false), false),
        (Some(false), true),
        (Some(true), true),
        (Some(true), false),
    ] {
        let permuted = permute == Some(true);
        let mut config = TlsClientConfig::new()
            .with_server_name(Host::try_from("example.test").unwrap())
            .with_alpn(vec![ApplicationProtocol::HTTP_2].into())
            .with_grease(true)
            .with_extension_order(if explicit {
                declared.into_iter().map(Into::into).collect()
            } else {
                Vec::new()
            });
        if let Some(enabled) = permute {
            config.set_permute_extensions(enabled);
        }
        // Reuse ONE native context: rebuilding it could hide load-time shuffling.
        let context = TlsConnectorContextBuilder::try_from(&config)
            .unwrap()
            .build();
        let mut orders = BTreeSet::new();
        for _ in 0..20 {
            let hello = first_flight(&context, None);
            let ids: Vec<_> = hello.extensions().iter().map(|ext| ext.id()).collect();
            assert!(ids[0].is_grease());
            // An order is a prefix: its second GREASE slot ends it; native GREASE ends the hello.
            let second = if explicit && !permuted {
                declared.len() + 1
            } else {
                ids.len() - 1
            };
            assert!(ids[second].is_grease(), "{ids:?}");
            assert_eq!(ids.iter().filter(|id| id.is_grease()).count(), 2, "{ids:?}");
            // Padding follows the hello's length, not the configuration.
            let mut all_ids: Vec<u16> = hello
                .extensions()
                .iter()
                .map(|ext| ext.id())
                .filter(|id| !id.is_grease() && *id != ExtensionId::PADDING)
                .map(Into::into)
                .collect();
            all_ids.sort_unstable();
            assert_eq!(&all_ids, membership.get_or_insert_with(|| all_ids.clone()));
            let order: Vec<u16> = hello
                .extensions()
                .iter()
                .map(|ext| ext.id().into())
                .filter(|id| declared.contains(id))
                .collect();
            let mut ids = order.clone();
            ids.sort_unstable();
            assert_eq!(ids, [10, 13, 16, 43]);
            if explicit && !permuted {
                assert_eq!(order, declared);
            }
            orders.insert(order);
        }
        if permuted {
            assert!(
                orders.len() > 1,
                "fresh handshakes must not share one permutation"
            );
        } else {
            assert_eq!(orders.len(), 1);
        }
    }
}

/// Set lists are exact, so GREASE turned on puts its slots into a set cipher list and
/// extension order that name none, where the native lists have them: as before such lists
/// were exact.
#[test]
fn set_lists_without_grease_get_the_native_grease_slots() {
    let ciphers = [
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
    ];
    let order = [
        ExtensionId::SUPPORTED_VERSIONS,
        ExtensionId::SUPPORTED_GROUPS,
    ];
    for grease in [true, false] {
        for explicit in [true, false] {
            let config = TlsClientConfig::new()
                .with_grease(grease)
                .with_cipher_suites(ciphers.to_vec())
                .with_extension_order(if explicit { order.to_vec() } else { Vec::new() });
            let context = TlsConnectorContextBuilder::try_from(&config)
                .unwrap()
                .build();
            let hello = first_flight(&context, None);
            let suites = hello.cipher_suites();
            assert_eq!(suites[0].is_grease(), grease, "{grease} {explicit}");
            assert_eq!(&suites[usize::from(grease)..], ciphers.as_slice());
            let ids: Vec<_> = hello.extensions().iter().map(|ext| ext.id()).collect();
            let greased = ids.iter().filter(|id| id.is_grease()).count();
            assert_eq!(greased, if grease { 2 } else { 0 }, "{ids:?}");
            if grease {
                assert!(ids[0].is_grease(), "{ids:?}");
                // A set order ends with its second slot; an empty one keeps native GREASE last.
                let second = if explicit {
                    order.len() + 1
                } else {
                    ids.len() - 1
                };
                assert!(ids[second].is_grease(), "{ids:?}");
            }
        }
    }
}

/// An extension order naming no GREASE codepoint keeps the native GREASE slots, first and last
/// of its prefix, instead of turning GREASE off; an order naming them places them itself.
#[test]
fn an_extension_order_without_grease_keeps_the_native_grease_slots() {
    for order in [
        vec![],
        vec![43, 10, 13, 16],
        vec![0x0a0a, 43, 10, 13, 16, 0x1a1a],
    ] {
        let config = TlsClientConfig::new()
            .with_server_name(Host::try_from("example.test").unwrap())
            .with_alpn(vec![ApplicationProtocol::HTTP_2].into())
            .with_grease(true)
            .with_extension_order(order.iter().copied().map(Into::into).collect());
        let context = TlsConnectorContextBuilder::try_from(&config)
            .unwrap()
            .build();
        let hello = first_flight(&context, None);
        let actual: Vec<ExtensionId> = hello.extensions().iter().map(|ext| ext.id()).collect();
        assert_eq!(
            actual.iter().filter(|id| id.is_grease()).count(),
            2,
            "{order:?}: {actual:?}"
        );
        let names_grease = order.iter().any(|id| ExtensionId::from(*id).is_grease());
        let prefix = if order.is_empty() || names_grease {
            order.clone()
        } else {
            [vec![0x0a0a], order.clone(), vec![0x1a1a]].concat()
        };
        // GREASE values stay fresh; their positions follow the prefix.
        for (actual, expected) in actual.iter().zip(prefix.into_iter().map(ExtensionId::from)) {
            if expected.is_grease() {
                assert!(actual.is_grease(), "{order:?}: {actual:?}");
            } else {
                assert_eq!(*actual, expected, "{order:?}");
            }
        }
    }
}

#[test]
fn mirrored_hello_does_not_inherit_base_shaping() {
    let minimal = ClientHello::new(
        ProtocolVersion::TLSv1_2,
        vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ],
        vec![CompressionAlgorithm::Null],
        vec![
            ClientHelloExtension::SupportedGroups(vec![SupportedGroup::X25519]),
            ClientHelloExtension::SignatureAlgorithms(vec![SignatureScheme::ECDSA_NISTP256_SHA256]),
            ClientHelloExtension::SupportedVersions(vec![
                ProtocolVersion::TLSv1_3,
                ProtocolVersion::TLSv1_2,
            ]),
        ],
    );
    let base = TlsClientConfig::new()
        .with_grease(true)
        .with_permute_extensions(true)
        .with_alps(vec![ApplicationProtocol::HTTP_2], true)
        .with_cert_compression(vec![CertificateCompressionAlgorithm::Brotli])
        .with_delegated_credentials(vec![SignatureScheme::ECDSA_NISTP256_SHA256])
        .with_record_size_limit(16385)
        .with_encrypted_client_hello(true)
        .with_ocsp_stapling(true)
        .with_signed_cert_timestamps(true)
        .with_tls12_session_tickets(true)
        .with_requested_trust_anchors(BoringRequestedTrustAnchors::try_from_ids([[1]]).unwrap());
    let mirror = TlsClientConfig::new_from_client_hello(&minimal);
    let effective = mirror
        .as_extensions()
        .fork()
        .with_base(base.as_extensions());
    let context =
        TlsConnectorContextBuilder::try_from(BoringTlsConnectorConfig::from_extensions(&effective))
            .unwrap()
            .build();
    for _ in 0..32 {
        let hello = first_flight(&context, None);
        // BoringSSL always adds these for a TLS 1.2-capable ECDHE offer, in a
        // random tail position, and pads after an empty final extension.
        let implicit = [
            ExtensionId::SERVER_NAME,
            ExtensionId::EXTENDED_MASTER_SECRET,
            ExtensionId::RENEGOTIATION_INFO,
            ExtensionId::EC_POINT_FORMATS,
            ExtensionId::KEY_SHARE,
            ExtensionId::PSK_KEY_EXCHANGE_MODES,
            ExtensionId::PADDING,
        ];
        let ids: Vec<ExtensionId> = hello
            .extensions()
            .iter()
            .map(ClientHelloExtension::id)
            .filter(|id| !implicit.contains(id))
            .collect();
        assert_eq!(
            ids,
            [
                ExtensionId::SUPPORTED_GROUPS,
                ExtensionId::SIGNATURE_ALGORITHMS,
                ExtensionId::SUPPORTED_VERSIONS,
            ]
        );
        assert!(!hello.cipher_suites().iter().any(|c| c.is_grease()));
    }
}

/// Native BoringSSL limits which no client configuration can lift today. Each
/// rule documents one, so lifting it makes this test fail and then shrink.
#[cfg(feature = "compression")]
struct NativeLimits;

#[cfg(feature = "compression")]
impl NativeLimits {
    /// Without `Preserve`, signature schemes BoringSSL does not implement are left out.
    fn signature_schemes(captured: &[SignatureScheme]) -> Vec<String> {
        captured
            .iter()
            .filter(|scheme| {
                scheme.is_grease()
                    || SslSignatureAlgorithm::from(u16::from(**scheme))
                        .name()
                        .is_some()
            })
            .map(|scheme| grease_or(scheme.is_grease(), scheme))
            .collect()
    }

    /// Without `Preserve`, finite-field groups (no native implementation) are left out.
    fn supported_groups(captured: &[SupportedGroup]) -> Vec<String> {
        captured
            .iter()
            .filter(|group| {
                !matches!(
                    group,
                    SupportedGroup::FFDHE2048
                        | SupportedGroup::FFDHE3072
                        | SupportedGroup::FFDHE4096
                        | SupportedGroup::FFDHE6144
                        | SupportedGroup::FFDHE8192
                )
            })
            .map(|group| grease_or(group.is_grease(), group))
            .collect()
    }
}

// Embedded browser profiles require the certificate compressors.
#[cfg(feature = "compression")]
#[test]
fn embedded_profiles_are_mirrored_on_the_wire() {
    let db = UserAgentDatabase::try_embedded().unwrap();
    assert!(!db.is_empty());
    for (profile, preserve) in db
        .iter()
        .flat_map(|profile| [(profile, false), (profile, true)])
    {
        let tls = profile.tls.as_ref().unwrap();
        let captured = &tls.client_hello;
        let mut config = TlsClientConfig::new_from_client_hello(captured);
        if preserve {
            config.set_unknown_values(UnknownValues::Preserve);
        }
        let context = TlsConnectorContextBuilder::try_from(&config)
            .unwrap()
            .build();
        let server_name = captured.ext_server_name().cloned().map(Host::from);
        let emitted = first_flight(&context, server_name);
        let ua = profile.ua_str().unwrap_or_default();

        assert_eq!(
            normalized_ciphers(captured),
            normalized_ciphers(&emitted),
            "{ua}"
        );
        assert_eq!(
            captured.extensions().len(),
            emitted.extensions().len(),
            "{ua}: {:?} vs {:?}",
            captured
                .extensions()
                .iter()
                .map(|e| e.id())
                .collect::<Vec<_>>(),
            emitted
                .extensions()
                .iter()
                .map(|e| e.id())
                .collect::<Vec<_>>(),
        );
        for (captured, emitted) in captured.extensions().iter().zip(emitted.extensions()) {
            match (captured, emitted) {
                (
                    ClientHelloExtension::Opaque { id, data: captured },
                    ClientHelloExtension::Opaque {
                        id: emitted_id,
                        data: emitted,
                    },
                ) if *id == ExtensionId::KEY_SHARE && *emitted_id == ExtensionId::KEY_SHARE => {
                    assert_eq!(
                        key_share_groups(captured),
                        key_share_groups(emitted),
                        "{ua}: key shares"
                    );
                }
                // With `Preserve` nothing is left out, so no native limit applies.
                _ => assert_eq!(
                    normalized_extension(captured, !preserve),
                    normalized_extension(emitted, false),
                    "{ua} (preserve: {preserve})"
                ),
            }
        }
    }
}

#[test]
fn embedded_chromium_profiles_permute_extensions() {
    let db = UserAgentDatabase::try_embedded().unwrap();
    let mut chromium = 0;
    for profile in db.iter() {
        let tls = profile.tls.as_ref().unwrap();
        let expected = profile.ua_kind.is_some_and(|kind| {
            TlsProfile::user_agent_permutes_extensions(kind, profile.ua_version, profile.platform)
        });
        assert_eq!(tls.permute_extensions, expected, "{:?}", profile.ua_str());
        chromium += usize::from(expected);
    }
    assert!(chromium > 0);
}

#[test]
fn embedded_chromium_profile_emits_per_connection_extension_orders() {
    let db = UserAgentDatabase::try_embedded().unwrap();
    let profile = db
        .iter()
        .find(|profile| {
            profile.ua_kind == Some(UserAgentKind::Chromium)
                && profile.tls.as_ref().unwrap().permute_extensions
        })
        .unwrap();
    let tls = profile.tls.as_ref().unwrap();
    let config = TlsClientConfig::new_from_client_hello(&tls.client_hello)
        .with_permute_extensions(tls.permute_extensions);
    let context = TlsConnectorContextBuilder::try_from(&config)
        .unwrap()
        .build();
    let mut orders = BTreeSet::new();
    let mut membership = None;
    // A fixed batch exercises the native entropy source; no retry on failure.
    for _ in 0..20 {
        let hello = first_flight(
            &context,
            tls.client_hello.ext_server_name().cloned().map(Host::from),
        );
        let order: Vec<u16> = hello
            .extensions()
            .iter()
            .map(|extension| extension.id())
            .filter(|id| !id.is_grease())
            .map(Into::into)
            .collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(&sorted, membership.get_or_insert_with(|| sorted.clone()));
        orders.insert(order);
    }
    assert!(orders.len() > 1);
}

#[cfg(feature = "compression")]
fn normalized_ciphers(hello: &ClientHello) -> Vec<String> {
    hello
        .cipher_suites()
        .iter()
        .map(|cipher| grease_or(cipher.is_grease(), cipher))
        .collect()
}

#[cfg(feature = "compression")]
fn grease_or(is_grease: bool, value: impl fmt::Debug) -> String {
    if is_grease {
        "GREASE".to_owned()
    } else {
        format!("{value:?}")
    }
}

/// Compare-ready form of an extension. GREASE values are random per handshake;
/// `captured` applies [`NativeLimits`] to the side that was recorded.
#[cfg(feature = "compression")]
fn normalized_extension(ext: &ClientHelloExtension, captured: bool) -> String {
    match ext {
        ClientHelloExtension::SupportedGroups(groups) if captured => {
            format!("groups{:?}", NativeLimits::supported_groups(groups))
        }
        ClientHelloExtension::SupportedGroups(groups) => format!(
            "groups{:?}",
            groups
                .iter()
                .map(|group| grease_or(group.is_grease(), group))
                .collect::<Vec<_>>()
        ),
        ClientHelloExtension::SignatureAlgorithms(schemes) if captured => {
            format!("sigalgs{:?}", NativeLimits::signature_schemes(schemes))
        }
        ClientHelloExtension::SignatureAlgorithms(schemes) => format!(
            "sigalgs{:?}",
            schemes
                .iter()
                .map(|scheme| grease_or(scheme.is_grease(), scheme))
                .collect::<Vec<_>>()
        ),
        ClientHelloExtension::SupportedVersions(versions) => format!(
            "versions{:?}",
            versions
                .iter()
                .map(|version| grease_or(version.is_grease(), version))
                .collect::<Vec<_>>()
        ),
        // ECH GREASE picks its own HPKE suite, config id and payload.
        ClientHelloExtension::EncryptedClientHello(_) => "ech".to_owned(),
        ClientHelloExtension::Opaque { id, .. } if id.is_grease() => "GREASE".to_owned(),
        // Padding length follows from the rest of the hello, compared field by field.
        ClientHelloExtension::Opaque { id, .. } if *id == ExtensionId::PADDING => {
            "padding".to_owned()
        }
        other => format!("{other:?}"),
    }
}

fn key_share_groups(data: &[u8]) -> Vec<u16> {
    let mut groups = Vec::new();
    let mut rest = data.get(2..).unwrap_or_default();
    while let [a, b, l1, l2, tail @ ..] = rest {
        let group = u16::from_be_bytes([*a, *b]);
        groups.push(if SupportedGroup::from(group).is_grease() {
            0x0a0a
        } else {
            group
        });
        rest = tail
            .get(usize::from(u16::from_be_bytes([*l1, *l2]))..)
            .unwrap_or_default();
    }
    groups
}

const VARIANT_CIPHERS: [CipherSuite; 2] = [
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_AES_128_GCM_SHA256,
];

/// The security policy both variants share: the cipher list is part of it.
fn plain_variant() -> TlsClientConfig {
    TlsClientConfig::new().with_cipher_suites(VARIANT_CIPHERS.to_vec())
}

/// Every other wire option set, on the same security policy.
pub(super) fn wire_variant() -> TlsClientConfig {
    plain_variant()
        .with_grease(true)
        .with_supported_groups(vec![SupportedGroup::SECP256R1, SupportedGroup::X25519])
        .with_key_shares(vec![SupportedGroup::SECP256R1])
        .with_signature_schemes(vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ])
        .with_supported_versions(vec![ProtocolVersion::TLSv1_3])
        .with_alpn(vec![ApplicationProtocol::HTTP_2].into())
        .with_ocsp_stapling(true)
        .with_signed_cert_timestamps(true)
        .with_cert_compression(vec![CertificateCompressionAlgorithm::Brotli])
        .with_extension_order(
            [ExtensionId::SUPPORTED_VERSIONS, ExtensionId::KEY_SHARE]
                .into_iter()
                .collect(),
        )
}

pub(super) fn hello_from_data(mut data: TlsConnectorData) -> ClientHello {
    data.server_name = Some(Host::try_from("example.test").unwrap());
    let ssl = data.into_ssl().unwrap();
    let Err(HandshakeError::WouldBlock(stream)) = ssl.connect(HelloSink::default()) else {
        panic!("the client must write its first flight before waiting for the server");
    };
    parse_client_hello_handshake(&stream.get_ref().0).unwrap()
}

/// Every ID in a list, with GREASE codepoints as `None`.
fn ids(hello: &ClientHello) -> Vec<Option<u16>> {
    hello
        .extensions()
        .iter()
        .map(|ext| (!ext.id().is_grease()).then(|| u16::from(ext.id())))
        .collect()
}

#[test]
fn wire_variants_of_one_policy_share_a_context_and_keep_their_own_hellos() {
    let plain = plain_variant();
    let variant = wire_variant();
    let first = TlsConnectorData::try_from(&plain).unwrap();
    let second = TlsConnectorData::try_from(&variant).unwrap();
    let third = TlsConnectorData::try_from(&plain).unwrap();
    // One native context per security policy, whatever the wire settings.
    assert!(std::ptr::eq(
        first.config.ssl_context(),
        second.config.ssl_context()
    ));
    assert!(std::ptr::eq(
        first.config.ssl_context(),
        third.config.ssl_context()
    ));
    // A different policy gets its own.
    let insecure = TlsConnectorData::try_from(
        &TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
    )
    .unwrap();
    assert!(!std::ptr::eq(
        first.config.ssl_context(),
        insecure.config.ssl_context()
    ));

    let (first, second, third) = (
        hello_from_data(first),
        hello_from_data(second),
        hello_from_data(third),
    );
    // Nothing of the variant leaks into a plain connection on the same context.
    assert_eq!(ids(&first), ids(&third));
    assert_eq!(first.cipher_suites(), third.cipher_suites());
    for hello in [&first, &third] {
        assert!(
            hello
                .cipher_suites()
                .iter()
                .all(|cipher| !cipher.is_grease())
        );
        for absent in [
            ExtensionId::STATUS_REQUEST,
            ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP,
            ExtensionId::COMPRESS_CERTIFICATE,
            ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        ] {
            assert!(
                hello.extensions().iter().all(|ext| ext.id() != absent),
                "{absent:?}"
            );
        }
    }
    // The variant carries each of its own settings.
    let ciphers = second.cipher_suites();
    assert!(ciphers[0].is_grease());
    assert_eq!(&ciphers[1..], VARIANT_CIPHERS);
    let order = ids(&second);
    assert_eq!(order[0], None, "GREASE first");
    assert_eq!(
        &order[1..3],
        [
            Some(u16::from(ExtensionId::SUPPORTED_VERSIONS)),
            Some(u16::from(ExtensionId::KEY_SHARE))
        ]
    );
    for present in [
        ExtensionId::STATUS_REQUEST,
        ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP,
    ] {
        assert!(
            second.extensions().iter().any(|ext| ext.id() == present),
            "{present:?}"
        );
    }
    assert_eq!(
        second
            .extensions()
            .iter()
            .any(|ext| ext.id() == ExtensionId::COMPRESS_CERTIFICATE),
        cfg!(feature = "compression"),
        "certificate compression follows the enabled codecs",
    );
    for ext in second.extensions() {
        match ext {
            ClientHelloExtension::SupportedGroups(groups) => {
                assert!(groups[0].is_grease());
                assert_eq!(
                    &groups[1..],
                    [SupportedGroup::SECP256R1, SupportedGroup::X25519]
                );
            }
            ClientHelloExtension::SignatureAlgorithms(schemes) => assert_eq!(
                schemes,
                &[
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::RSA_PSS_SHA256
                ]
            ),
            ClientHelloExtension::SupportedVersions(versions) => {
                assert!(versions[0].is_grease());
                assert_eq!(&versions[1..], [ProtocolVersion::TLSv1_3]);
            }
            ClientHelloExtension::ApplicationLayerProtocolNegotiation(protocols) => {
                assert_eq!(protocols, &[ApplicationProtocol::HTTP_2]);
            }
            ClientHelloExtension::CertificateCompression(algorithms) => {
                assert_eq!(algorithms, &[CertificateCompressionAlgorithm::Brotli]);
            }
            _ => {}
        }
    }
}

#[test]
fn naming_only_unusable_groups_fails_instead_of_offering_defaults() {
    let config = TlsClientConfig::new().with_supported_groups(vec![SupportedGroup::FFDHE2048]);
    TlsConnectorData::try_from(&config).unwrap_err();
    // One usable group is enough, and is all that is offered.
    let config = TlsClientConfig::new()
        .with_supported_groups(vec![SupportedGroup::FFDHE2048, SupportedGroup::X25519]);
    let hello = hello_from_data(TlsConnectorData::try_from(&config).unwrap());
    let groups = hello
        .extensions()
        .iter()
        .find_map(|ext| match ext {
            ClientHelloExtension::SupportedGroups(groups) => Some(groups.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(groups, [SupportedGroup::X25519]);
}

/// Drive a fresh connection until it has written its ClientHello.
fn first_flight(context: &TlsConnectorContext, server_name: Option<Host>) -> ClientHello {
    let mut data = context.configure().unwrap();
    data.server_name = Some(server_name.unwrap_or_else(|| Host::try_from("example.test").unwrap()));
    let ssl = data.into_ssl().unwrap();
    let Err(HandshakeError::WouldBlock(stream)) = ssl.connect(HelloSink::default()) else {
        panic!("the client must write its first flight before waiting for the server");
    };
    parse_client_hello_handshake(&stream.get_ref().0).unwrap()
}

#[derive(Debug, Default)]
struct HelloSink(Vec<u8>);

impl Read for HelloSink {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl Write for HelloSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A TLS 1.3 hello with a value of every kind BoringSSL cannot negotiate itself: an unknown
/// group, an unknown signature scheme, `status_request_v2` and a private extension.
fn hello_with_unknown_values() -> ClientHello {
    ClientHello::new(
        ProtocolVersion::TLSv1_2,
        vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ],
        vec![CompressionAlgorithm::Null],
        vec![
            ClientHelloExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
            ClientHelloExtension::SupportedGroups(vec![
                SupportedGroup::X25519,
                SupportedGroup::from(0x0abc),
            ]),
            ClientHelloExtension::SignatureAlgorithms(vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::from(0x0999),
                SignatureScheme::RSA_PSS_SHA256,
            ]),
            ClientHelloExtension::Opaque {
                id: ExtensionId::STATUS_REQUEST_V2,
                data: vec![0, 7, 2, 0, 4, 0, 0, 0, 0],
            },
            ClientHelloExtension::Opaque {
                id: ExtensionId::from(0x1234),
                data: vec![1, 2, 3],
            },
        ],
    )
}

pub(super) fn emitted_with(config: &TlsClientConfig) -> ClientHello {
    hello_from_data(TlsConnectorData::try_from(config).unwrap())
}

#[test]
fn unknown_values_are_dropped_by_default_and_preserved_on_request() {
    let captured = hello_with_unknown_values();
    let unknown_group = SupportedGroup::from(0x0abc);
    let unknown_scheme = SignatureScheme::from(0x0999);
    for preserve in [false, true] {
        let mut config = TlsClientConfig::new_from_client_hello(&captured);
        if preserve {
            config.set_unknown_values(UnknownValues::Preserve);
        }
        let emitted = emitted_with(&config);
        let groups = emitted.ext_supported_groups().unwrap();
        let schemes = emitted.ext_signature_algorithms().unwrap();
        assert_eq!(groups.contains(&unknown_group), preserve);
        assert_eq!(schemes.contains(&unknown_scheme), preserve);
        let opaque = |id: ExtensionId| {
            emitted.extensions().iter().find_map(|ext| match ext {
                ClientHelloExtension::Opaque { id: ext_id, data } if *ext_id == id => {
                    Some(data.clone())
                }
                _ => None,
            })
        };
        let expected = |data: Vec<u8>| preserve.then_some(data);
        assert_eq!(
            opaque(ExtensionId::STATUS_REQUEST_V2),
            expected(vec![0, 7, 2, 0, 4, 0, 0, 0, 0])
        );
        assert_eq!(opaque(ExtensionId::from(0x1234)), expected(vec![1, 2, 3]));
        // status_request_v2 is not OCSP status_request.
        assert!(
            emitted
                .extensions()
                .iter()
                .all(|ext| ext.id() != ExtensionId::STATUS_REQUEST)
        );
        if preserve {
            // As captured, in order.
            assert_eq!(
                emitted
                    .extensions()
                    .iter()
                    .map(|ext| ext.id())
                    .filter(|id| captured.extensions().iter().any(|ext| ext.id() == *id))
                    .collect::<Vec<_>>(),
                captured
                    .extensions()
                    .iter()
                    .map(|ext| ext.id())
                    .collect::<Vec<_>>()
            );
            assert_eq!(schemes, captured.ext_signature_algorithms().unwrap());
        }
    }
}

/// The GREASE codepoints of a hello, in order of appearance.
fn grease_values(hello: &ClientHello) -> Vec<u16> {
    let mut values: Vec<u16> = hello
        .cipher_suites()
        .iter()
        .filter(|c| c.is_grease())
        .map(|c| u16::from(*c))
        .collect();
    for ext in hello.extensions() {
        if ext.id().is_grease() {
            values.push(u16::from(ext.id()));
        }
        match ext {
            ClientHelloExtension::SupportedGroups(groups) => values.extend(
                groups
                    .iter()
                    .filter(|g| g.is_grease())
                    .map(|g| u16::from(*g)),
            ),
            ClientHelloExtension::SupportedVersions(versions) => values.extend(
                versions
                    .iter()
                    .filter(|v| v.is_grease())
                    .map(|v| u16::from(*v)),
            ),
            _ => {}
        }
    }
    values
}

#[test]
fn grease_values_can_be_pinned_or_seeded() {
    let captured = ClientHello::new(
        ProtocolVersion::TLSv1_2,
        vec![
            CipherSuite::from(0x3a3a),
            CipherSuite::TLS13_AES_128_GCM_SHA256,
        ],
        vec![CompressionAlgorithm::Null],
        vec![
            ClientHelloExtension::Opaque {
                id: ExtensionId::from(0x6a6a),
                data: Vec::new(),
            },
            ClientHelloExtension::SupportedVersions(vec![
                ProtocolVersion::from(0xdada),
                ProtocolVersion::TLSv1_3,
            ]),
            ClientHelloExtension::SupportedGroups(vec![
                SupportedGroup::from(0x8a8a),
                SupportedGroup::X25519,
            ]),
            ClientHelloExtension::SignatureAlgorithms(vec![SignatureScheme::ECDSA_NISTP256_SHA256]),
            ClientHelloExtension::Opaque {
                id: ExtensionId::from(0xbaba),
                data: vec![0],
            },
        ],
    );
    let pinned = TlsClientConfig::new_from_client_hello(&captured)
        .with_grease_values(rama_boring::ssl::GreaseValues::Pinned);
    for _ in 0..2 {
        assert_eq!(
            grease_values(&emitted_with(&pinned)),
            [0x3a3a, 0x6a6a, 0xdada, 0x8a8a, 0xbaba]
        );
    }
    let seeded = |seed| {
        grease_values(&emitted_with(
            &TlsClientConfig::new_from_client_hello(&captured)
                .with_grease_values(rama_boring::ssl::GreaseValues::Seeded(seed)),
        ))
    };
    assert_eq!(seeded(7), seeded(7));
    assert_ne!(seeded(7), seeded(8));
}

/// A small deterministic generator, so every case is reproducible from its seed.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self) -> bool {
        self.next() & 1 == 1
    }

    /// A random non-empty selection of `items`, in random order.
    fn pick<T: Copy>(&mut self, items: &[T]) -> Vec<T> {
        let mut pool = items.to_vec();
        let mut picked = Vec::new();
        let count = 1 + self.below(pool.len());
        for _ in 0..count {
            picked.push(pool.remove(self.below(pool.len())));
        }
        picked
    }

    /// `list` with GREASE codepoint `grease` at a random position, half of the time.
    fn with_grease<T>(&mut self, mut list: Vec<T>, grease: T) -> Vec<T> {
        if self.chance() {
            let at = self.below(list.len() + 1);
            list.insert(at, grease);
        }
        list
    }
}

fn random_hello(seed: u64) -> ClientHello {
    let mut rng = XorShift(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let ciphers = rng.pick(&[
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ]);
    let mut ciphers = rng.with_grease(ciphers, CipherSuite::from(0x2a2a));
    // Always one TLS 1.3 cipher.
    if !ciphers.iter().any(|c| c.is_tls13()) {
        ciphers.push(CipherSuite::TLS13_AES_128_GCM_SHA256);
    }
    let mut groups = rng.pick(&[
        SupportedGroup::X25519,
        SupportedGroup::SECP256R1,
        SupportedGroup::SECP384R1,
        SupportedGroup::X25519MLKEM768,
        SupportedGroup::FFDHE2048,
        SupportedGroup::from(0x0abc),
    ]);
    // Key shares need a group BoringSSL implements.
    let native = |g: &SupportedGroup| -> bool {
        let curve: Option<SslCurve> = (*g).rama_try_into().ok();
        curve.is_some()
    };
    if !groups.iter().any(native) {
        groups.push(SupportedGroup::X25519);
    }
    let share = *groups.iter().find(|g| native(g)).unwrap();
    let grease_group = rng.chance();
    if grease_group {
        groups.insert(0, SupportedGroup::from(0x4a4a));
    }
    let mut schemes = rng.pick(&[
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::from(0x0999),
    ]);
    // Always one TLS 1.3 scheme, and sometimes a repeat as some browsers send.
    schemes.push(SignatureScheme::RSA_PSS_SHA384);
    if rng.chance() {
        schemes.push(schemes[0]);
    }
    let schemes = rng.with_grease(schemes, SignatureScheme::from(0x5a5a));
    let versions = rng.with_grease(
        vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2],
        ProtocolVersion::from(0x6a6a),
    );
    let mut key_share = Vec::new();
    for group in grease_group
        .then_some(SupportedGroup::from(0x4a4a))
        .into_iter()
        .chain([share])
    {
        let key: &[u8] = if group.is_grease() { &[0] } else { &[] };
        key_share.extend_from_slice(&u16::from(group).to_be_bytes());
        key_share.extend_from_slice(&u16::try_from(key.len()).unwrap().to_be_bytes());
        key_share.extend_from_slice(key);
    }
    let mut key_share_body = u16::try_from(key_share.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    key_share_body.extend_from_slice(&key_share);

    let mut extensions = vec![
        ClientHelloExtension::ServerName(Some(rama_net::address::Domain::from_static(
            "example.test",
        ))),
        ClientHelloExtension::SupportedGroups(groups),
        ClientHelloExtension::SignatureAlgorithms(schemes),
        ClientHelloExtension::SupportedVersions(versions),
        ClientHelloExtension::Opaque {
            id: ExtensionId::KEY_SHARE,
            data: key_share_body,
        },
        ClientHelloExtension::Opaque {
            id: ExtensionId::PSK_KEY_EXCHANGE_MODES,
            data: vec![1, 1],
        },
        ClientHelloExtension::Opaque {
            id: ExtensionId::EXTENDED_MASTER_SECRET,
            data: Vec::new(),
        },
        ClientHelloExtension::Opaque {
            id: ExtensionId::RENEGOTIATION_INFO,
            data: vec![0],
        },
        ClientHelloExtension::ECPointFormats(vec![rama_tls::ECPointFormat::Uncompressed]),
    ];
    if rng.chance() {
        extensions.push(ClientHelloExtension::Opaque {
            id: ExtensionId::from(0x1234),
            data: vec![1, 2, 3],
        });
    }
    if rng.chance() {
        extensions.push(ClientHelloExtension::Opaque {
            id: ExtensionId::from(0x7a7a),
            data: vec![0],
        });
    }
    // A random order.
    let mut ordered = Vec::new();
    while !extensions.is_empty() {
        ordered.push(extensions.remove(rng.below(extensions.len())));
    }
    ClientHello::new(
        ProtocolVersion::TLSv1_2,
        ciphers,
        vec![CompressionAlgorithm::Null],
        ordered,
    )
}

/// Everything of a hello that is not drawn per connection: every list in order with its
/// GREASE codepoints, the key share groups, and the extension order (padding aside).
fn round_trip_shape(hello: &ClientHello) -> Vec<String> {
    let mut shape = vec![format!("{:?}", hello.cipher_suites())];
    for ext in hello.extensions() {
        match ext {
            ClientHelloExtension::Opaque { id, .. } if *id == ExtensionId::PADDING => {}
            ClientHelloExtension::Opaque { id, data } if *id == ExtensionId::KEY_SHARE => {
                shape.push(format!("key_share {:?}", key_share_groups(data)));
            }
            ClientHelloExtension::ServerName(_) => shape.push("server_name".to_owned()),
            other => shape.push(format!("{other:?}")),
        }
    }
    shape
}

#[test]
fn preserved_and_pinned_hellos_round_trip_exactly() {
    for seed in 0..128 {
        let captured = random_hello(seed);
        let config = TlsClientConfig::new_from_client_hello(&captured)
            .with_unknown_values(UnknownValues::Preserve)
            .with_grease_values(rama_boring::ssl::GreaseValues::Pinned);
        let emitted = emitted_with(&config);
        assert_eq!(
            round_trip_shape(&emitted),
            round_trip_shape(&captured),
            "seed {seed}"
        );
    }
}

mod server_padding;
