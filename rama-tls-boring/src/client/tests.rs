use std::{
    collections::BTreeSet,
    fmt,
    io::{self, Read, Write},
};

use rama_boring::ssl::{HandshakeError, SslSignatureAlgorithm};
use rama_net::{address::Host, tls::ApplicationProtocol};
use rama_tls::{
    CertificateCompressionAlgorithm, CipherSuite, CompressionAlgorithm, ExtensionId,
    ProtocolVersion, SignatureScheme, SupportedGroup,
    client::{ClientHello, ClientHelloExtension, TlsClientConfig, parse_client_hello_handshake},
};
use rama_ua::{
    UserAgentKind,
    profile::{TlsProfile, UserAgentDatabase},
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
struct NativeLimits;

impl NativeLimits {
    /// BoringSSL rejects duplicate and unknown signature schemes.
    fn signature_schemes(captured: &[SignatureScheme]) -> Vec<String> {
        let mut seen = Vec::new();
        captured
            .iter()
            .filter(|scheme| {
                scheme.is_grease()
                    || SslSignatureAlgorithm::from(u16::from(**scheme))
                        .name()
                        .is_some()
            })
            .filter(|scheme| {
                let first = !seen.contains(*scheme);
                seen.push(**scheme);
                first
            })
            .map(|scheme| grease_or(scheme.is_grease(), scheme))
            .collect()
    }

    /// Finite-field groups have no native implementation, so they are not offered.
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

#[test]
fn embedded_profiles_are_mirrored_on_the_wire() {
    let db = UserAgentDatabase::try_embedded().unwrap();
    assert!(!db.is_empty());
    for profile in db.iter() {
        let tls = profile.tls.as_ref().unwrap();
        let captured = &tls.client_hello;
        let context =
            TlsConnectorContextBuilder::try_from(&TlsClientConfig::new_from_client_hello(captured))
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
                _ => assert_eq!(
                    normalized_extension(captured, true),
                    normalized_extension(emitted, false),
                    "{ua}"
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

fn normalized_ciphers(hello: &ClientHello) -> Vec<String> {
    hello
        .cipher_suites()
        .iter()
        .map(|cipher| grease_or(cipher.is_grease(), cipher))
        .collect()
}

fn grease_or(is_grease: bool, value: impl fmt::Debug) -> String {
    if is_grease {
        "GREASE".to_owned()
    } else {
        format!("{value:?}")
    }
}

/// Compare-ready form of an extension. GREASE values are random per handshake;
/// `captured` applies [`NativeLimits`] to the side that was recorded.
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
fn wire_variant() -> TlsClientConfig {
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

fn hello_from_data(mut data: TlsConnectorData) -> ClientHello {
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
        &TlsClientConfig::new().with_server_verify(rama_tls::client::ServerVerifyMode::Disable),
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
        ExtensionId::COMPRESS_CERTIFICATE,
    ] {
        assert!(
            second.extensions().iter().any(|ext| ext.id() == present),
            "{present:?}"
        );
    }
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
