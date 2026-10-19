use rama_boring::{ssl::UnknownValues, x509::store::X509Store};
use rama_core::error::BoxError;
use rama_crypto::pki_types::CertificateDer;
use rama_net::address::{Domain, Host, HostWithPort};
use rama_tls::{
    KeyLogIntent,
    client::{
        ClientHello, ServerVerifyMode, TlsClientConfig, TlsServerCertPins, TlsServerTrust,
        TlsServerVerify,
    },
};
use rama_utils::macros::generate_set_and_with;
use std::sync::Arc;

use crate::client::BoringClientConfigExt as _;

/// Server-authentication policy for upstream TLS connections made by a
/// [`TlsMitmRelay`](super::TlsMitmRelay).
///
/// This deliberately exposes only certificate/identity verification controls.
/// TLS fingerprint and protocol-negotiation settings remain owned by the relay
/// and mirrored from the ingress ClientHello.
///
/// Verification is disabled by default. A transparent MITM relay should not
/// reject an upstream certificate that the intercepted client may deliberately
/// accept; doing so would make previously viable traffic fail at the relay.
/// Configure [`ServerVerifyMode::Auto`] explicitly when the proxy operator
/// wants to enforce upstream certificate and hostname verification.
#[derive(Debug, Clone)]
pub struct TlsMitmEgressServerAuth {
    config: TlsClientConfig,
}

impl Default for TlsMitmEgressServerAuth {
    fn default() -> Self {
        Self {
            config: TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
        }
    }
}

impl TlsMitmEgressServerAuth {
    /// Create a policy with upstream certificate verification disabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Set the upstream identity used for certificate verification.
        ///
        /// A DNS identity is also sent as SNI. Without an explicit identity,
        /// the relay uses ingress SNI. When verification or pinning is
        /// configured and ingress SNI is absent, it falls back to the
        /// connector-target host.
        pub fn server_name(mut self, server_name: Host) -> Self {
            self.config.set_server_name(server_name);
            self
        }
    }

    generate_set_and_with! {
        /// Set how the upstream certificate is verified.
        ///
        /// Select [`ServerVerifyMode::Auto`] to opt into normal certificate and
        /// hostname verification.
        pub fn server_verify(mut self, mode: ServerVerifyMode) -> Self {
            self.config.set_server_verify(mode);
            self
        }
    }

    generate_set_and_with! {
        /// Require the upstream leaf certificate to match an applicable pin set.
        pub fn server_cert_pins(mut self, pins: TlsServerCertPins) -> Self {
            self.config.set_server_cert_pins(pins);
            self
        }
    }

    generate_set_and_with! {
        /// Replace the complete upstream trust policy.
        ///
        /// Trust settings are used only with [`ServerVerifyMode::Auto`].
        pub fn server_trust(mut self, trust: TlsServerTrust) -> Self {
            self.config.set_server_trust(trust);
            self
        }
    }

    generate_set_and_with! {
        /// Replace the default roots with the supplied upstream trust anchors.
        ///
        /// Trust settings are used only with [`ServerVerifyMode::Auto`].
        pub fn server_trust_anchors(
            mut self,
            certificates: impl IntoIterator<Item = CertificateDer<'static>>,
        ) -> Result<Self, BoxError> {
            self.config.try_set_server_trust_anchors(certificates)?;
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Add certificates to the configured upstream trust roots.
        ///
        /// Trust settings are used only with [`ServerVerifyMode::Auto`].
        pub fn extra_server_trust_anchors(
            mut self,
            certificates: impl IntoIterator<Item = CertificateDer<'static>>,
        ) -> Result<Self, BoxError> {
            self.config.try_set_extra_server_trust_anchors(certificates)?;
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Use Rama's bundled Mozilla roots for upstream verification.
        ///
        /// Trust settings are used only with [`ServerVerifyMode::Auto`].
        pub fn webpki_roots(mut self) -> Self {
            self.config.set_webpki_roots();
            self
        }
    }

    generate_set_and_with! {
        /// Set a BoringSSL certificate store for upstream verification.
        ///
        /// The store takes precedence over the backend-neutral trust policy and
        /// is ignored when verification is explicitly disabled.
        pub fn server_verify_cert_store(mut self, store: Arc<X509Store>) -> Self {
            self.config.set_server_verify_cert_store(store);
            self
        }
    }

    pub(super) fn write_to(&self, config: &TlsClientConfig) {
        self.config.write_to(config.as_extensions());
    }

    /// Return whether a missing ingress SNI should fall back to the connector
    /// target for an effective server identity.
    ///
    /// Merely attaching the default verification-disabled policy must not make
    /// a previously SNI-less transparent flow start sending SNI upstream. An
    /// identity fallback is needed when normal verification or certificate
    /// pinning is configured; an explicit policy server name is written later
    /// and therefore does not need this fallback.
    pub(super) fn requires_connector_target_identity(&self) -> bool {
        self.config
            .as_extensions()
            .get_ref::<TlsServerVerify>()
            .is_some_and(|verify| verify.0 == ServerVerifyMode::Auto)
            || self
                .config
                .as_extensions()
                .get_ref::<TlsServerCertPins>()
                .is_some()
    }
}

/// Build the relay-owned portion of an upstream TLS client config.
///
/// This is shared by [`TlsMitmRelayService`](super::TlsMitmRelayService) and
/// direct [`TlsMitmRelay::handshake`](super::TlsMitmRelay::handshake) calls so
/// the policy, key logging, and transparent verification default cannot drift
/// between the two entry points.
pub(super) fn tls_client_config(
    client_hello: Option<&ClientHello>,
    server_name: Option<Host>,
    keylog: KeyLogIntent,
    server_auth: Option<&TlsMitmEgressServerAuth>,
) -> TlsClientConfig {
    let mut config = match client_hello {
        // A relay preserves unsupported offers as well as supported ones. The
        // native TLS engine still rejects an unsupported server selection.
        Some(hello) => TlsClientConfig::new_from_client_hello(hello)
            .with_unknown_values(UnknownValues::Preserve),
        None => TlsClientConfig::new(),
    }
    .with_keylog(keylog);

    if let Some(server_name) = server_name {
        config.set_server_name(server_name);
    }

    match server_auth {
        Some(server_auth) => server_auth.write_to(&config),
        None => {
            config.set_server_verify(ServerVerifyMode::Disable);
        }
    }

    config
}

/// Resolve the relay's effective upstream identity without changing transparent
/// no-SNI behavior merely because a disabled policy object was attached.
pub(super) fn server_name(
    ingress_sni: Option<&Domain>,
    connector_target: Option<&HostWithPort>,
    server_auth: Option<&TlsMitmEgressServerAuth>,
) -> Option<Host> {
    ingress_sni.cloned().map(Into::into).or_else(|| {
        if server_auth.is_some_and(TlsMitmEgressServerAuth::requires_connector_target_identity) {
            connector_target.map(|target| target.host.clone())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};

    use rama_boring::ssl::HandshakeError;
    use rama_tls::{
        CipherSuite, CompressionAlgorithm, ExtensionId, ProtocolVersion, SignatureScheme,
        SupportedGroup,
        client::{ClientHelloExtension, parse_client_hello_handshake},
    };

    use super::*;
    use crate::client::{BoringTlsConnectorConfig, TlsConnectorData};

    /// Record what the native TLS engine emits, without completing a handshake.
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

    fn emitted(config: &TlsClientConfig) -> ClientHello {
        let ssl = TlsConnectorData::try_from(config)
            .unwrap()
            .into_ssl()
            .unwrap();
        let Err(HandshakeError::WouldBlock(stream)) = ssl.connect(HelloSink::default()) else {
            panic!("native client must emit its offer before waiting for a server");
        };
        parse_client_hello_handshake(&stream.get_ref().0).unwrap()
    }

    fn offered_hello() -> ClientHello {
        ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            vec![CompressionAlgorithm::Null],
            vec![
                ClientHelloExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
                ClientHelloExtension::SupportedGroups(vec![
                    SupportedGroup::from(0x0abc),
                    SupportedGroup::X25519,
                ]),
                ClientHelloExtension::SignatureAlgorithms(vec![
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::from(0x0999),
                    SignatureScheme::RSA_PSS_SHA256,
                ]),
                ClientHelloExtension::Opaque {
                    id: ExtensionId::from(50),
                    data: vec![0, 4, 4, 3, 8, 4],
                },
                ClientHelloExtension::Opaque {
                    id: ExtensionId::KEY_SHARE,
                    data: [vec![0, 36, 0, 29, 0, 32], vec![7; 32]].concat(),
                },
            ],
        )
    }

    fn opaque_body(hello: &ClientHello, id: ExtensionId) -> Option<&[u8]> {
        hello
            .extensions()
            .iter()
            .find_map(|extension| match extension {
                ClientHelloExtension::Opaque { id: actual, data } if *actual == id => {
                    Some(data.as_slice())
                }
                _ => None,
            })
    }

    #[test]
    fn mirror_preserves_native_offer_lists_and_certificate_signature_extension() {
        let source = offered_hello();
        for auth in [None, Some(TlsMitmEgressServerAuth::new())] {
            let config =
                tls_client_config(Some(&source), None, KeyLogIntent::Disabled, auth.as_ref());
            let first = emitted(&config);
            let second = emitted(&config);
            for hello in [&first, &second] {
                assert_eq!(hello.ext_supported_groups(), source.ext_supported_groups());
                assert_eq!(
                    hello.ext_signature_algorithms(),
                    source.ext_signature_algorithms()
                );
                assert_eq!(
                    opaque_body(hello, ExtensionId::from(50)),
                    Some(&[0, 4, 4, 3, 8, 4][..])
                );
                // Preserving an offer never invents a key for an unknown group.
                assert_eq!(
                    hello.ext_key_share_groups().unwrap(),
                    [SupportedGroup::X25519]
                );
                let source_order: Vec<_> = source
                    .extensions()
                    .iter()
                    .map(ClientHelloExtension::id)
                    .collect();
                let emitted_order: Vec<_> = hello
                    .extensions()
                    .iter()
                    .map(ClientHelloExtension::id)
                    .filter(|id| source_order.contains(id))
                    .collect();
                assert_eq!(emitted_order, source_order);
            }
            assert_ne!(
                opaque_body(&first, ExtensionId::KEY_SHARE),
                opaque_body(&second, ExtensionId::KEY_SHARE)
            );
        }
    }

    #[test]
    fn ordinary_mimic_configuration_keeps_its_default_unknown_value_policy() {
        let source = offered_hello();
        let ordinary = emitted(
            &TlsClientConfig::new_from_client_hello(&source)
                .with_server_verify(ServerVerifyMode::Disable),
        );
        assert_eq!(
            ordinary.ext_supported_groups().unwrap(),
            [SupportedGroup::X25519]
        );
        assert!(
            !ordinary
                .ext_signature_algorithms()
                .unwrap()
                .contains(&SignatureScheme::from(0x0999))
        );
        assert_eq!(opaque_body(&ordinary, ExtensionId::from(50)), None);

        let default = tls_client_config(None, None, KeyLogIntent::Disabled, None);
        assert!(
            BoringTlsConnectorConfig::from_extensions(default.as_extensions())
                .unknown_values
                .is_none()
        );
    }
}
