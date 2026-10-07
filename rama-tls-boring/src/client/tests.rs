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
use rama_ua::{PlatformKind, UserAgentKind, profile::UserAgentDatabase};

use super::{
    BoringClientConfigExt, BoringRequestedTrustAnchors, BoringTlsConnectorConfig,
    TlsConnectorContext, TlsConnectorContextBuilder,
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
            assert!(hello.extensions().first().unwrap().id().is_grease());
            assert!(hello.extensions().last().unwrap().id().is_grease());
            let mut all_ids: Vec<u16> = hello
                .extensions()
                .iter()
                .map(|ext| ext.id())
                .filter(|id| !id.is_grease())
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
        .with_session_tickets(true)
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

/// Known differences: BoringSSL limits, or BoringSSL features rama-boring does
/// not expose yet. Lifting one makes this test fail, so its rule can shrink.
struct NativeLimits;

impl NativeLimits {
    /// BoringSSL rejects duplicate and unknown schemes; rama-boring does not
    /// expose GREASE in `signature_algorithms` yet.
    fn signature_schemes(captured: &[SignatureScheme]) -> Vec<String> {
        let mut seen = Vec::new();
        captured
            .iter()
            .filter(|scheme| !scheme.is_grease())
            .filter(|scheme| {
                SslSignatureAlgorithm::from(u16::from(**scheme))
                    .name()
                    .is_some()
            })
            .filter(|scheme| {
                let first = !seen.contains(*scheme);
                seen.push(**scheme);
                first
            })
            .map(|scheme| format!("{scheme:?}"))
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

    /// rama-boring does not expose explicit key shares yet, so the default of
    /// at most two applies and a captured offer only matches as a prefix.
    fn key_share_groups_match(captured: &[u16], emitted: &[u16]) -> bool {
        !emitted.is_empty() && captured.starts_with(emitted)
    }
}

#[test]
fn embedded_profiles_are_mirrored_on_the_wire() {
    let db = UserAgentDatabase::try_embedded().unwrap();
    assert!(!db.is_empty());
    for profile in db.iter() {
        let captured = &profile.tls.client_hello;
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
                    let (captured, emitted) =
                        (key_share_groups(captured), key_share_groups(emitted));
                    assert!(
                        NativeLimits::key_share_groups_match(&captured, &emitted),
                        "{ua}: key shares {captured:x?} vs {emitted:x?}"
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
    for profile in db.iter() {
        let permutes = profile.ua_kind == UserAgentKind::Chromium
            && profile.platform != Some(PlatformKind::IOS);
        assert_eq!(
            profile.tls.permute_extensions,
            permutes,
            "{:?}",
            profile.ua_str()
        );
    }
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
        groups.push(if group & 0x0f0f == 0x0a0a {
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
