use rama_boring::{ssl::UnknownValues, x509::store::X509Store};
use rama_core::{
    error::{BoxError, ErrorContext as _},
    telemetry::tracing,
};
use rama_crypto::pki_types::CertificateDer;
use rama_net::{address::HostWithPort, tls::ServerName};
use rama_tls::{
    KeyLogIntent, ProtocolVersion,
    client::{
        ClientHello, DynTlsServerCertChainPolicy, ServerVerifyMode, TlsClientConfig,
        TlsServerCertPins, TlsServerTrust, TlsServerVerify,
    },
};
use rama_utils::macros::generate_set_and_with;
use std::sync::Arc;

use crate::client::{
    BoringClientConfigExt as _,
    negotiable::{ALL_VERSIONS, cipher_negotiable, cipher_supported, version_supported},
};

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
///
/// Intercepted clients only see the relay's re-signed certificate, so their
/// own revocation, distrust and certificate transparency checks never see the
/// upstream chain. [`Self::with_platform_verifier`] restores the platform's
/// judgement for the upstream. A [`DynTlsServerCertChainPolicy`] rejects chains
/// with known bad keys; while verification stays disabled that only covers
/// servers presenting such a chain, not an attacker who can present any.
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
        /// connector-target host. A target that is not a server name fails
        /// only where verification or a name-scoped pin needs one; otherwise
        /// no SNI is sent.
        pub fn server_name(mut self, server_name: impl Into<ServerName>) -> Self {
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

    /// The effective upstream verification mode. Disabled verification still
    /// enforces any configured certificate-chain policy.
    #[must_use]
    pub fn server_verify_mode(&self) -> ServerVerifyMode {
        self.config
            .as_extensions()
            .get_ref::<TlsServerVerify>()
            .map_or(ServerVerifyMode::Disable, |verify| verify.0)
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
        /// Verify upstream certificates with the operating system's verifier.
        ///
        /// Native calls may fetch intermediates or revocation information. They
        /// continue after a handshake timeout. Bound concurrent upstream work
        /// and size the shared Tokio blocking pool for it, especially when
        /// intercepted clients choose upstream hosts or certificates. Handshake
        /// deadlines alone do not prevent pool saturation. On Linux this uses
        /// native roots instead.
        ///
        /// Enables [`ServerVerifyMode::Auto`]. See
        /// [`ServerTrustSource::Platform`](rama_tls::client::ServerTrustSource::Platform).
        pub fn platform_verifier(mut self) -> Self {
            self.config.set_server_verify(ServerVerifyMode::Auto);
            self.config.set_platform_verifier();
            self
        }
    }

    generate_set_and_with! {
        /// Reject upstream certificate chains that `policy` refuses.
        ///
        /// Enforced also while upstream verification is disabled. Replaces any
        /// previously configured chain policy.
        pub fn server_cert_chain_policy(
            mut self,
            policy: impl Into<DynTlsServerCertChainPolicy>,
        ) -> Self {
            self.config.set_server_cert_chain_policy(policy);
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
        let extensions = self.config.as_extensions();
        !extensions.contains::<ServerName>()
            && (self.verifies_server() || extensions.get_ref::<TlsServerCertPins>().is_some())
    }

    /// Return whether the upstream handshake cannot be authenticated without a
    /// server name: the certificate is verified against a name, or no
    /// configured pin set applies to a connection without one.
    pub(super) fn requires_server_name(&self) -> bool {
        self.verifies_server()
            || self
                .config
                .as_extensions()
                .get_ref::<TlsServerCertPins>()
                .is_some_and(|pins| !pins.applies_to(None))
    }

    fn verifies_server(&self) -> bool {
        self.config
            .as_extensions()
            .get_ref::<TlsServerVerify>()
            .is_some_and(|verify| verify.0 == ServerVerifyMode::Auto)
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
    server_name: Option<ServerName>,
    keylog: KeyLogIntent,
    server_auth: Option<&TlsMitmEgressServerAuth>,
) -> TlsClientConfig {
    let mut config = match client_hello {
        // A relay offers only what its native engine implements, so no origin
        // selection can fail the handshake.
        Some(hello) => {
            tracing::debug!(
                "TLS MITM relay mirrors the ClientHello without values the native engine cannot negotiate"
            );
            let mut config = TlsClientConfig::new_from_client_hello(hello)
                .with_unknown_values(UnknownValues::Drop);
            offer_negotiable_only(&mut config, hello);
            config
        }
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

// Unknown-value dropping misses suites and versions, which are set as listed.
fn offer_negotiable_only(config: &mut TlsClientConfig, hello: &ClientHello) {
    let suites = hello.cipher_suites();
    // Without a negotiable suite the ingress offer is mirrored as is: a relay never invents one.
    if suites
        .iter()
        .any(|suite| cipher_negotiable(u16::from(*suite), ALL_VERSIONS))
    {
        config.set_cipher_suites(
            suites
                .iter()
                .copied()
                .filter(|suite| {
                    suite.is_grease() || cipher_supported(u16::from(*suite), ALL_VERSIONS)
                })
                .collect(),
        );
    }
    match hello.supported_versions() {
        Some(versions) => {
            let offered: Vec<_> = versions
                .iter()
                .copied()
                .filter(|version| version.is_grease() || version_supported(u16::from(*version)))
                .collect();
            if offered.iter().any(|version| !version.is_grease()) {
                config.set_supported_versions(offered);
            }
        }
        // Without supported_versions the legacy field is the only version offered.
        None if hello.protocol_version() < ProtocolVersion::TLSv1_2
            && version_supported(u16::from(hello.protocol_version())) =>
        {
            config.set_min_version(hello.protocol_version());
        }
        None => {}
    }
}

/// Resolve the relay's effective upstream identity without changing transparent
/// no-SNI behavior merely because a disabled policy object was attached.
pub(super) fn server_name(
    ingress_sni: Option<&ServerName>,
    connector_target: Option<&HostWithPort>,
    server_auth: Option<&TlsMitmEgressServerAuth>,
) -> Result<Option<ServerName>, BoxError> {
    if let Some(sni) = ingress_sni {
        return Ok(Some(sni.clone()));
    }
    let Some(server_auth) =
        server_auth.filter(|server_auth| server_auth.requires_connector_target_identity())
    else {
        return Ok(None);
    };
    let Some(target) = connector_target else {
        return Ok(None);
    };
    match ServerName::try_from(&target.host) {
        Ok(server_name) => Ok(Some(server_name)),
        Err(error) if server_auth.requires_server_name() => {
            Err(error).context("connector target host is not a TLS server name")
        }
        Err(_) => {
            tracing::debug!(
                server.address = %target.host,
                "connector target is not a TLS server name: no SNI is sent upstream"
            );
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};

    use rama_boring::{
        pkey::PKey,
        ssl::{HandshakeError, Ssl, SslContextBuilder, SslMethod, SslVersion},
        x509::X509,
    };
    use rama_boring_tokio::SslStreamBuilder;
    use rama_net::address::{Domain, Host};
    use rama_tls::{
        CipherSuite, CompressionAlgorithm, ExtensionId, ProtocolVersion, SignatureScheme,
        SupportedGroup,
        client::{ClientHelloExtension, TlsServerCertPinSet, parse_client_hello_handshake},
        server::{GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData},
    };
    use rama_utils::octets::kib;

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
    fn mirror_offers_only_values_the_native_engine_negotiates() {
        let source = offered_hello();
        for auth in [None, Some(TlsMitmEgressServerAuth::new())] {
            let config =
                tls_client_config(Some(&source), None, KeyLogIntent::Disabled, auth.as_ref());
            let first = emitted(&config);
            let second = emitted(&config);
            for hello in [&first, &second] {
                // An origin could otherwise select a value the native engine rejects.
                assert_eq!(
                    hello.ext_supported_groups().unwrap(),
                    [SupportedGroup::X25519]
                );
                assert_eq!(
                    hello.ext_signature_algorithms().unwrap(),
                    [
                        SignatureScheme::ECDSA_NISTP256_SHA256,
                        SignatureScheme::RSA_PSS_SHA256
                    ]
                );
                assert_eq!(opaque_body(hello, ExtensionId::from(50)), None);
                assert_eq!(
                    hello.ext_key_share_groups().unwrap(),
                    [SupportedGroup::X25519]
                );
                let source_order: Vec<_> = source
                    .extensions()
                    .iter()
                    .map(ClientHelloExtension::id)
                    .filter(|id| *id != ExtensionId::from(50))
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
    fn mirror_filters_suites_and_versions_the_native_engine_cannot_negotiate() {
        let suites = |values: &[u16]| values.iter().copied().map(CipherSuite::from).collect();
        let versions = |values: &[u16]| {
            values
                .iter()
                .copied()
                .map(ProtocolVersion::from)
                .collect::<Vec<_>>()
        };
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            suites(&[0x1301, 0xfe00, 0xc013, 0x00ff, 0xffff]),
            vec![CompressionAlgorithm::Null],
            vec![
                ClientHelloExtension::SupportedVersions(versions(&[
                    0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301, 0x0300,
                ])),
                ClientHelloExtension::SupportedGroups(vec![SupportedGroup::X25519]),
                ClientHelloExtension::SignatureAlgorithms(vec![
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                ]),
            ],
        );
        let emitted = emitted(&tls_client_config(
            Some(&hello),
            None,
            KeyLogIntent::Disabled,
            None,
        ));
        // The renegotiation SCSV is a signal and stays.
        assert_eq!(
            emitted.cipher_suites(),
            suites(&[0x1301, 0xc013, 0x00ff]).as_slice()
        );
        let sent: Vec<_> = emitted
            .supported_versions()
            .unwrap()
            .iter()
            .filter(|version| !version.is_grease())
            .copied()
            .collect();
        assert_eq!(sent, versions(&[0x0304, 0x0303, 0x0302, 0x0301]));
    }

    #[test]
    fn mirror_without_a_negotiable_suite_keeps_the_ingress_suites() {
        let offered: Vec<_> = [0x00ff, 0xfe00, 0xffff]
            .into_iter()
            .map(CipherSuite::from)
            .collect();
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            offered.clone(),
            vec![CompressionAlgorithm::Null],
            vec![ClientHelloExtension::SupportedGroups(vec![
                SupportedGroup::X25519,
            ])],
        );
        let config = tls_client_config(Some(&hello), None, KeyLogIntent::Disabled, None);
        assert_eq!(emitted(&config).cipher_suites(), offered.as_slice());
    }

    #[test]
    fn mirror_keeps_renegotiation_info_presence_next_to_extended_master_secret() {
        let opaque = |id: ExtensionId, data: Vec<u8>| ClientHelloExtension::Opaque { id, data };
        for renegotiation_info in [false, true] {
            let mut extensions = vec![
                ClientHelloExtension::SupportedGroups(vec![SupportedGroup::X25519]),
                opaque(ExtensionId::EXTENDED_MASTER_SECRET, Vec::new()),
            ];
            if renegotiation_info {
                extensions.push(opaque(ExtensionId::RENEGOTIATION_INFO, vec![0]));
            }
            let hello = ClientHello::new(
                ProtocolVersion::TLSv1_2,
                vec![CipherSuite::from(0x00ff), CipherSuite::from(0xc013)],
                vec![CompressionAlgorithm::Null],
                extensions,
            );
            let emitted = emitted(&tls_client_config(
                Some(&hello),
                None,
                KeyLogIntent::Disabled,
                None,
            ));
            let sent = |id| emitted.extensions().iter().any(|ext| ext.id() == id);
            assert!(sent(ExtensionId::EXTENDED_MASTER_SECRET));
            assert_eq!(sent(ExtensionId::RENEGOTIATION_INFO), renegotiation_info);
        }
    }

    #[test]
    fn mirror_of_a_legacy_tls11_offer_offers_tls11() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_1,
            vec![CipherSuite::from(0xc013)],
            vec![CompressionAlgorithm::Null],
            vec![ClientHelloExtension::SupportedGroups(vec![
                SupportedGroup::X25519,
            ])],
        );
        let emitted = emitted(&tls_client_config(
            Some(&hello),
            None,
            KeyLogIntent::Disabled,
            None,
        ));
        assert_eq!(emitted.protocol_version(), ProtocolVersion::TLSv1_1);
        assert!(emitted.supported_versions().is_none());
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

    fn target_that_is_not_a_server_name() -> HostWithPort {
        HostWithPort::new("[v1.foo]".parse::<Host>().unwrap(), 443)
    }

    fn pin() -> CertificateDer<'static> {
        CertificateDer::from(vec![1, 2, 3])
    }

    #[test]
    fn global_pins_proceed_without_sni_when_the_target_is_not_a_server_name() {
        let target = target_that_is_not_a_server_name();
        let policy =
            TlsMitmEgressServerAuth::new().with_server_cert_pins(TlsServerCertPins::new(pin()));
        let name = server_name(None, Some(&target), Some(&policy)).unwrap();
        assert_eq!(name, None);

        let config = tls_client_config(None, name, KeyLogIntent::Disabled, Some(&policy));
        assert_eq!(emitted(&config).ext_server_name(), None);
    }

    #[test]
    fn name_scoped_pins_require_a_server_name_from_the_target() {
        let target = target_that_is_not_a_server_name();
        let policy = TlsMitmEgressServerAuth::new().with_server_cert_pins(TlsServerCertPins::new(
            TlsServerCertPinSet::new(pin()).with_server_name(Domain::from_static("target.example")),
        ));
        server_name(None, Some(&target), Some(&policy)).unwrap_err();
    }

    #[test]
    fn verification_requires_a_server_name_from_the_target() {
        let target = target_that_is_not_a_server_name();
        let policy = TlsMitmEgressServerAuth::new()
            .with_server_verify(ServerVerifyMode::Auto)
            .with_server_cert_pins(TlsServerCertPins::new(pin()));
        server_name(None, Some(&target), Some(&policy)).unwrap_err();
    }

    #[test]
    fn a_configured_server_name_does_not_need_the_target() {
        let target = target_that_is_not_a_server_name();
        let policy = TlsMitmEgressServerAuth::new()
            .with_server_verify(ServerVerifyMode::Auto)
            .with_server_name(Domain::from_static("policy.example"));
        let name = server_name(None, Some(&target), Some(&policy)).unwrap();

        let config = tls_client_config(None, name, KeyLogIntent::Disabled, Some(&policy));
        assert_eq!(
            emitted(&config).ext_server_name(),
            Some(&ServerName::from(Domain::from_static("policy.example")))
        );
    }

    /// The version the mirror of `hello` negotiates with an origin accepting only `version`.
    async fn origin_negotiates(hello: &ClientHello, version: SslVersion) -> Option<SslVersion> {
        let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::SelfSignedLeaf(
            LeafCertRequest::default(),
        ))
        .unwrap();
        let mut origin = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
        origin
            .set_certificate(&X509::from_der(auth.cert_chain[0].as_ref()).unwrap())
            .unwrap();
        origin
            .set_private_key(&PKey::private_key_from_der(auth.private_key.secret_der()).unwrap())
            .unwrap();
        origin.set_min_proto_version(Some(version)).unwrap();
        origin.set_max_proto_version(Some(version)).unwrap();
        let origin = Ssl::new(&origin.build()).unwrap();
        let config = tls_client_config(Some(hello), None, KeyLogIntent::Disabled, None);
        let mut data = TlsConnectorData::try_from(&config).unwrap();
        data.server_name = Some(ServerName::from(Domain::from_static("origin.example")));
        let (client_io, origin_io) = tokio::io::duplex(kib(64));
        let (client, _origin) = tokio::join!(
            SslStreamBuilder::new(data.into_ssl().unwrap(), client_io).connect(),
            SslStreamBuilder::new(origin, origin_io).accept(),
        );
        client.ok().and_then(|stream| stream.ssl().version())
    }

    #[tokio::test]
    async fn mirror_of_tls13_without_tls13_suites_or_schemes_is_left_to_the_origin() {
        let hello = |ciphers: Vec<u16>, scheme| {
            ClientHello::new(
                ProtocolVersion::TLSv1_2,
                ciphers.into_iter().map(CipherSuite::from).collect(),
                vec![CompressionAlgorithm::Null],
                vec![
                    ClientHelloExtension::SupportedVersions(vec![
                        ProtocolVersion::TLSv1_3,
                        ProtocolVersion::TLSv1_2,
                    ]),
                    ClientHelloExtension::SupportedGroups(vec![
                        SupportedGroup::X25519,
                        SupportedGroup::SECP256R1,
                    ]),
                    ClientHelloExtension::SignatureAlgorithms(vec![scheme]),
                ],
            )
        };
        for hello in [
            hello(vec![0xc02b, 0xc02f], SignatureScheme::ECDSA_NISTP256_SHA256),
            hello(vec![0x1301, 0xc02b], SignatureScheme::ECDSA_SHA1_Legacy),
        ] {
            let mirrored = emitted(&tls_client_config(
                Some(&hello),
                None,
                KeyLogIntent::Disabled,
                None,
            ));
            assert_eq!(mirrored.cipher_suites(), hello.cipher_suites());
            assert_eq!(mirrored.supported_versions(), hello.supported_versions());
            // The origin refuses TLS 1.3 as it would for the client, and TLS 1.2 completes.
            assert_eq!(origin_negotiates(&hello, SslVersion::TLS1_3).await, None);
            assert_eq!(
                origin_negotiates(&hello, SslVersion::TLS1_2).await,
                Some(SslVersion::TLS1_2)
            );
        }
    }
}
