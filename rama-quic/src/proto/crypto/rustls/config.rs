use super::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig, rustls};
use rama_core::error::BoxError;
use rama_tls::{
    ProtocolVersion, TlsSupportedVersions, client::TlsClientConfig, server::TlsServerConfig,
};
use rama_tls_rustls::{client::RustlsTlsConnectorConfig, server::RustlsTlsAcceptorConfig};
use std::{fmt, sync::Arc};

/// How the application protocol is agreed for a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum AlpnPolicy {
    /// Require a nonempty ALPN offer and a negotiated protocol on both peers.
    #[default]
    Require,
    /// The application has explicitly agreed the protocol through another mechanism.
    OutOfBandAgreement,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TlsOptions {
    pub(crate) alpn: AlpnPolicy,
    /// Enable replayable early application data. Applications must opt in deliberately.
    pub(crate) early_data: bool,
}

#[derive(Debug)]
pub(crate) enum TlsConfigError {
    Tls13Required,
    AlpnRequired,
    InvalidAlpn,
    UnsupportedDynamicConfig,
    EarlyDataNotEnabled,
    NoInitialCipherSuite(NoInitialCipherSuite),
    InvalidConfiguration(BoxError),
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls13Required => f.write_str("QUIC requires TLS 1.3"),
            Self::AlpnRequired => f.write_str("QUIC requires ALPN unless another protocol agreement is explicit"),
            Self::InvalidAlpn => f.write_str("invalid ALPN protocol list"),
            Self::UnsupportedDynamicConfig => f.write_str("asynchronous per-ClientHello TLS configuration is not supported by this QUIC backend"),
            Self::EarlyDataNotEnabled => f.write_str("TLS configuration enables early data without QUIC application opt-in"),
            Self::NoInitialCipherSuite(error) => error.fmt(f),
            Self::InvalidConfiguration(error) => write!(f, "invalid QUIC TLS configuration: {error}"),
        }
    }
}

impl std::error::Error for TlsConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoInitialCipherSuite(error) => Some(error),
            Self::InvalidConfiguration(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<BoxError> for TlsConfigError {
    fn from(error: BoxError) -> Self {
        Self::InvalidConfiguration(error)
    }
}

impl From<rustls::Error> for TlsConfigError {
    fn from(error: rustls::Error) -> Self {
        Self::InvalidConfiguration(Box::new(error))
    }
}

impl From<NoInitialCipherSuite> for TlsConfigError {
    fn from(error: NoInitialCipherSuite) -> Self {
        Self::NoInitialCipherSuite(error)
    }
}

impl QuicClientConfig {
    pub(crate) fn from_rama(
        config: &TlsClientConfig,
        provider: Arc<rustls::crypto::CryptoProvider>,
        options: TlsOptions,
    ) -> Result<Self, TlsConfigError> {
        let mut pieces = RustlsTlsConnectorConfig::from_extensions(config.as_extensions());
        validate_versions(pieces.versions)?;
        let versions = TlsSupportedVersions(vec![ProtocolVersion::TLSv1_3]);
        pieces.versions = Some(&versions);
        let modify = pieces.modify.take();
        let mut native = pieces.try_into_client_config_with_provider(provider)?;
        native.enable_early_data = options.early_data;
        if let Some(modify) = modify {
            native = (modify.0)(native)?;
        }
        validate_alpn(&native.alpn_protocols, options.alpn)?;
        if native.enable_early_data && !options.early_data {
            return Err(TlsConfigError::EarlyDataNotEnabled);
        }
        // Validate the final hook result through Rustls's actual QUIC constructor.
        // Never consume tickets from the application's resumption cache in a probe.
        let mut probe = native.clone();
        probe.resumption = rustls::client::Resumption::disabled();
        probe.key_log = Arc::new(rustls::NoKeyLog);
        rustls::quic::ClientConnection::new(
            Arc::new(probe),
            rustls::quic::Version::V1,
            rustls::pki_types::ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()),
            Vec::new(),
        )?;
        let mut config = Self::try_from(native)?;
        config.alpn_policy = options.alpn;
        Ok(config)
    }
}

impl QuicServerConfig {
    pub(crate) fn from_rama(
        config: &TlsServerConfig,
        provider: Arc<rustls::crypto::CryptoProvider>,
        options: TlsOptions,
    ) -> Result<Self, TlsConfigError> {
        let mut pieces = RustlsTlsAcceptorConfig::from_extensions(config.as_extensions());
        if pieces.dynamic.is_some() {
            return Err(TlsConfigError::UnsupportedDynamicConfig);
        }
        validate_versions(pieces.versions)?;
        let versions = TlsSupportedVersions(vec![ProtocolVersion::TLSv1_3]);
        pieces.versions = Some(&versions);
        let modify = pieces.modify.take();
        let mut native = pieces.try_into_server_config_with_provider(provider)?;
        native.max_early_data_size = if options.early_data { u32::MAX } else { 0 };
        if let Some(modify) = modify {
            native = (modify.0)(native)?;
        }
        validate_alpn(&native.alpn_protocols, options.alpn)?;
        if native.max_early_data_size != 0 && !options.early_data {
            return Err(TlsConfigError::EarlyDataNotEnabled);
        }
        let native = Arc::new(native);
        rustls::quic::ServerConnection::new(native.clone(), rustls::quic::Version::V1, Vec::new())?;
        let mut config = Self::try_from(native)?;
        config.alpn_policy = options.alpn;
        Ok(config)
    }
}

fn validate_versions(versions: Option<&TlsSupportedVersions>) -> Result<(), TlsConfigError> {
    if versions.is_some_and(|v| !v.0.is_empty() && !v.0.contains(&ProtocolVersion::TLSv1_3)) {
        return Err(TlsConfigError::Tls13Required);
    }
    Ok(())
}

fn validate_alpn(protocols: &[Vec<u8>], policy: AlpnPolicy) -> Result<(), TlsConfigError> {
    if protocols.is_empty() && policy == AlpnPolicy::Require {
        return Err(TlsConfigError::AlpnRequired);
    }
    let mut total = 0usize;
    for protocol in protocols {
        if protocol.is_empty() || protocol.len() > 255 {
            return Err(TlsConfigError::InvalidAlpn);
        }
        total = total
            .checked_add(protocol.len() + 1)
            .ok_or(TlsConfigError::InvalidAlpn)?;
    }
    // The extension's two-byte list length is part of its u16-sized body.
    if total > usize::from(u16::MAX) - 2 {
        return Err(TlsConfigError::InvalidAlpn);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::crypto::rustls::configured_provider;
    use rama_tls::server::{GeneratedServerAuthConfig, ServerAuthData};
    use rama_tls_rustls::{client::RustlsClientConfigExt, server::RustlsServerConfigExt};

    fn configs() -> (TlsClientConfig, TlsServerConfig) {
        let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        let alpn = || {
            [rama_net::tls::ApplicationProtocol::from(
                b"rama-quic-test".as_slice(),
            )]
            .into_iter()
            .collect()
        };
        let client = TlsClientConfig::new()
            .with_server_cert_pins(rama_tls::client::TlsServerCertPins::new(
                auth.cert_chain[0].clone(),
            ))
            .with_alpn(alpn())
            .try_with_server_trust_anchors([auth.cert_chain.last().unwrap().clone()])
            .unwrap();
        (
            client,
            TlsServerConfig::new()
                .with_server_auth(auth)
                .with_alpn(alpn()),
        )
    }

    #[test]
    fn common_config_requires_alpn_and_tls13() {
        let (client, server) = configs();
        QuicClientConfig::from_rama(&client, configured_provider(), TlsOptions::default()).unwrap();
        QuicServerConfig::from_rama(&server, configured_provider(), TlsOptions::default()).unwrap();
        client.insert(TlsSupportedVersions(vec![ProtocolVersion::TLSv1_2]));
        server.insert(TlsSupportedVersions(vec![ProtocolVersion::TLSv1_2]));
        assert!(matches!(
            QuicClientConfig::from_rama(&client, configured_provider(), TlsOptions::default()),
            Err(TlsConfigError::Tls13Required)
        ));
        assert!(matches!(
            QuicServerConfig::from_rama(&server, configured_provider(), TlsOptions::default()),
            Err(TlsConfigError::Tls13Required)
        ));
        client.insert(TlsSupportedVersions(vec![]));
        server.insert(TlsSupportedVersions(vec![]));
        client.insert(rama_net::tls::TlsAlpn(Default::default()));
        server.insert(rama_net::tls::TlsAlpn(Default::default()));
        assert!(matches!(
            QuicClientConfig::from_rama(&client, configured_provider(), TlsOptions::default()),
            Err(TlsConfigError::AlpnRequired)
        ));
        assert!(matches!(
            QuicServerConfig::from_rama(&server, configured_provider(), TlsOptions::default()),
            Err(TlsConfigError::AlpnRequired)
        ));
        let options = TlsOptions {
            alpn: AlpnPolicy::OutOfBandAgreement,
            ..Default::default()
        };
        QuicClientConfig::from_rama(&client, configured_provider(), options).unwrap();
        QuicServerConfig::from_rama(&server, configured_provider(), options).unwrap();
    }

    #[test]
    fn modify_hooks_cannot_bypass_quic_requirements() {
        let (client, server) = configs();
        let client = client.with_modify_rustls_config(|mut native| {
            native.alpn_protocols = vec![vec![]];
            Ok(native)
        });
        assert!(matches!(
            QuicClientConfig::from_rama(&client, configured_provider(), TlsOptions::default()),
            Err(TlsConfigError::InvalidAlpn)
        ));
        let client = client.with_modify_rustls_config(|mut native| {
            native.enable_early_data = true;
            Ok(native)
        });
        assert!(matches!(
            QuicClientConfig::from_rama(&client, configured_provider(), TlsOptions::default()),
            Err(TlsConfigError::EarlyDataNotEnabled)
        ));
        let client = client.with_modify_rustls_config(|native| {
            Ok(
                rustls::ClientConfig::builder_with_provider(native.crypto_provider().clone())
                    .with_protocol_versions(&[&rustls::version::TLS12])?
                    .with_root_certificates(rama_tls_rustls::client::client_root_certs())
                    .with_no_client_auth(),
            )
        });
        let options = TlsOptions {
            alpn: AlpnPolicy::OutOfBandAgreement,
            ..Default::default()
        };
        let error = QuicClientConfig::from_rama(&client, configured_provider(), options)
            .err()
            .unwrap();
        assert!(matches!(error, TlsConfigError::InvalidConfiguration(_)));
        assert!(
            std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<rustls::Error>()
                .is_some()
        );

        let server = server.with_modify_rustls_config(|mut native| {
            native.max_early_data_size = 17;
            Ok(native)
        });
        let options = TlsOptions {
            early_data: true,
            ..Default::default()
        };
        assert!(matches!(
            QuicServerConfig::from_rama(&server, configured_provider(), options),
            Err(TlsConfigError::InvalidConfiguration(_))
        ));
        let server = server.with_modify_rustls_config(|native| {
            Ok(
                rustls::ServerConfig::builder_with_provider(native.crypto_provider().clone())
                    .with_protocol_versions(&[&rustls::version::TLS12])?
                    .with_no_client_auth()
                    .with_cert_resolver(native.cert_resolver),
            )
        });
        let options = TlsOptions {
            alpn: AlpnPolicy::OutOfBandAgreement,
            ..Default::default()
        };
        assert!(matches!(
            QuicServerConfig::from_rama(&server, configured_provider(), options),
            Err(TlsConfigError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn initial_cipher_and_alpn_wire_lengths_are_validated() {
        let (client, server) = configs();
        let mut provider = (*configured_provider()).clone();
        provider
            .cipher_suites
            .retain(|suite| suite.suite() != rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
        let provider = Arc::new(provider);
        assert!(matches!(
            QuicClientConfig::from_rama(&client, provider.clone(), TlsOptions::default()),
            Err(TlsConfigError::NoInitialCipherSuite(_))
        ));
        assert!(matches!(
            QuicServerConfig::from_rama(&server, provider, TlsOptions::default()),
            Err(TlsConfigError::NoInitialCipherSuite(_))
        ));
        for protocols in [vec![vec![]], vec![vec![0; 256]], vec![vec![0; 255]; 256]] {
            assert!(matches!(
                validate_alpn(&protocols, AlpnPolicy::OutOfBandAgreement),
                Err(TlsConfigError::InvalidAlpn)
            ));
        }
        validate_alpn(&vec![vec![0; 255]; 255], AlpnPolicy::Require).unwrap();
    }

    struct Dynamic;
    impl rama_tls_rustls::server::DynamicConfigProvider for Dynamic {
        async fn get_config(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Result<Arc<rustls::ServerConfig>, BoxError> {
            panic!("unsupported dynamic config must never be invoked");
        }
    }

    #[test]
    fn dynamic_config_is_rejected_explicitly() {
        let config = TlsServerConfig::new().with_dynamic_config(Arc::new(Dynamic));
        assert!(matches!(
            QuicServerConfig::from_rama(&config, configured_provider(), TlsOptions::default()),
            Err(TlsConfigError::UnsupportedDynamicConfig)
        ));
    }

    #[test]
    fn both_roles_reject_a_completed_handshake_without_required_alpn() {
        use crate::proto::{
            Side,
            crypto::{ClientConfig as _, ServerConfig as _},
            transport_parameters::TransportParameters,
        };
        for strict_side in [Side::Client, Side::Server] {
            let (client, server) = configs();
            client.insert(rama_net::tls::TlsAlpn(Default::default()));
            server.insert(rama_net::tls::TlsAlpn(Default::default()));
            let options = TlsOptions {
                alpn: AlpnPolicy::OutOfBandAgreement,
                ..Default::default()
            };
            let mut client =
                QuicClientConfig::from_rama(&client, configured_provider(), options).unwrap();
            let mut server =
                QuicServerConfig::from_rama(&server, configured_provider(), options).unwrap();
            // Exercise the session guard against a peer completing TLS without ALPN.
            match strict_side {
                Side::Client => client.alpn_policy = AlpnPolicy::Require,
                Side::Server => server.alpn_policy = AlpnPolicy::Require,
            }
            let params = TransportParameters::default();
            let mut client = Arc::new(client)
                .start_session(1, "localhost", &params)
                .unwrap();
            let mut server = Arc::new(server).start_session(1, &params).unwrap();
            let mut rejected = None;
            for _ in 0..16 {
                let mut bytes = Vec::new();
                client.write_handshake(&mut bytes);
                if !bytes.is_empty()
                    && let Err(error) = server.read_handshake(&bytes)
                {
                    rejected = Some((Side::Server, error));
                    break;
                }
                bytes.clear();
                server.write_handshake(&mut bytes);
                if !bytes.is_empty()
                    && let Err(error) = client.read_handshake(&bytes)
                {
                    rejected = Some((Side::Client, error));
                    break;
                }
            }
            let (side, error) = rejected.expect("missing ALPN was accepted");
            assert_eq!(side, strict_side);
            assert_eq!(u64::from(error.code), 0x0178);
        }
    }

    #[derive(Debug, Default)]
    struct SessionStore {
        reads: std::sync::atomic::AtomicUsize,
    }
    impl rustls::client::ClientSessionStore for SessionStore {
        fn set_kx_hint(&self, _: rustls::pki_types::ServerName<'static>, _: rustls::NamedGroup) {}
        fn kx_hint(&self, _: &rustls::pki_types::ServerName<'_>) -> Option<rustls::NamedGroup> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
        fn set_tls12_session(
            &self,
            _: rustls::pki_types::ServerName<'static>,
            _: rustls::client::Tls12ClientSessionValue,
        ) {
        }
        fn tls12_session(
            &self,
            _: &rustls::pki_types::ServerName<'_>,
        ) -> Option<rustls::client::Tls12ClientSessionValue> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
        fn remove_tls12_session(&self, _: &rustls::pki_types::ServerName<'static>) {}
        fn insert_tls13_ticket(
            &self,
            _: rustls::pki_types::ServerName<'static>,
            _: rustls::client::Tls13ClientSessionValue,
        ) {
        }
        fn take_tls13_ticket(
            &self,
            _: &rustls::pki_types::ServerName<'static>,
        ) -> Option<rustls::client::Tls13ClientSessionValue> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
    }

    #[test]
    fn validation_does_not_consume_application_session_tickets() {
        use crate::proto::{crypto::ClientConfig as _, transport_parameters::TransportParameters};
        use std::sync::atomic::Ordering;
        let (client, _) = configs();
        let store = Arc::new(SessionStore::default());
        let captured = store.clone();
        let client = client.with_modify_rustls_config(move |mut native| {
            native.resumption = rustls::client::Resumption::store(captured.clone());
            Ok(native)
        });
        let client =
            QuicClientConfig::from_rama(&client, configured_provider(), TlsOptions::default())
                .unwrap();
        assert_eq!(store.reads.load(Ordering::Relaxed), 0);
        Arc::new(client)
            .start_session(1, "localhost", &TransportParameters::default())
            .unwrap();
        assert!(store.reads.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn invalid_native_sessions_return_errors_instead_of_panicking() {
        use crate::proto::{
            ConnectError,
            crypto::{ClientConfig as _, ServerConfig as _},
            transport_parameters::TransportParameters,
        };
        let (client, server) = configs();
        let mut client =
            QuicClientConfig::from_rama(&client, configured_provider(), TlsOptions::default())
                .unwrap();
        let mut server =
            QuicServerConfig::from_rama(&server, configured_provider(), TlsOptions::default())
                .unwrap();
        client.inner = Arc::new(
            rustls::ClientConfig::builder_with_provider(configured_provider())
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .with_root_certificates(rama_tls_rustls::client::client_root_certs())
                .with_no_client_auth(),
        );
        Arc::make_mut(&mut server.inner).max_early_data_size = 23;
        let params = TransportParameters::default();
        assert!(matches!(
            Arc::new(client).start_session(1, "localhost", &params),
            Err(ConnectError::Crypto(_))
        ));
        let error = Arc::new(server).start_session(1, &params).err().unwrap();
        assert!(
            std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<rustls::Error>()
                .is_some()
        );
    }

    #[tokio::test]
    async fn early_server_handle_reports_failed_client_authentication() {
        use crate::{
            driver::Endpoint,
            proto::{ClientConfig, ServerConfig},
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (client_tls, server_tls) = configs();
            let (chain, _) = rama_tls_rustls::client::self_signed_client_auth().unwrap();
            let server_tls = server_tls
                .with_client_verify(rama_tls::server::ClientVerifyMode::ClientAuth(chain));
            let client_config = ClientConfig::new(Arc::new(
                QuicClientConfig::from_rama(
                    &client_tls,
                    configured_provider(),
                    TlsOptions::default(),
                )
                .unwrap(),
            ));
            let server_config = ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::from_rama(
                    &server_tls,
                    configured_provider(),
                    TlsOptions::default(),
                )
                .unwrap(),
            ));
            let server = Endpoint::server(
                server_config,
                "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
            )
            .await
            .unwrap();
            let client = Endpoint::client("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
                .await
                .unwrap();
            let connecting = client
                .connect_with(client_config, server.local_addr().unwrap(), "localhost")
                .unwrap();
            let (_, (connection, error)) = tokio::join!(connecting, async {
                let incoming = server.accept().await.unwrap().accept().unwrap();
                let (connection, established) = incoming.into_0rtt().unwrap();
                let error = established.await.unwrap_err();
                (connection, error)
            });
            assert!(matches!(error, crate::ConnectionError::TransportError(_)));
            assert!(
                std::error::Error::source(&error)
                    .unwrap()
                    .source()
                    .unwrap()
                    .downcast_ref::<rustls::Error>()
                    .is_some()
            );
            assert!(connection.close_reason().is_some());
            client.wait_idle().await;
            server.wait_idle().await;
        })
        .await
        .unwrap();
    }

    #[derive(Debug, Default)]
    struct KeyLogCount(std::sync::atomic::AtomicUsize);
    impl rama_tls::keylog::KeyLogSink for KeyLogCount {
        fn write_line(&self, line: &str) {
            assert!(line.ends_with('\n'));
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn authenticated_common_tls_over_quic_streams() {
        use crate::{
            driver::Endpoint,
            proto::{ClientConfig, ServerConfig, VarInt},
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for policy in [AlpnPolicy::Require, AlpnPolicy::OutOfBandAgreement] {
                let (client_tls, server_tls) = configs();
                let (chain, key) = rama_tls_rustls::client::self_signed_client_auth().unwrap();
                let client_tls = client_tls.with_client_auth(rama_tls::client::ClientAuth::Single(
                    rama_tls::client::ClientAuthData {
                        cert_chain: chain.clone(),
                        private_key: key,
                    },
                ));
                let server_tls = server_tls
                    .with_client_verify(rama_tls::server::ClientVerifyMode::ClientAuth(chain));
                let client_log = Arc::new(KeyLogCount::default());
                let server_log = Arc::new(KeyLogCount::default());
                let client_tls =
                    client_tls.with_keylog(rama_tls::KeyLogIntent::Custom(client_log.clone()));
                let server_tls =
                    server_tls.with_keylog(rama_tls::KeyLogIntent::Custom(server_log.clone()));

                // Select the trusted certificate by SNI, replacing an unrelated base
                // identity so success proves the resolver was actually used.
                let auth = RustlsTlsAcceptorConfig::from_extensions(server_tls.as_extensions())
                    .server_auth
                    .unwrap()
                    .0
                    .clone();
                let cert = rustls::sign::CertifiedKey::from_der(
                    auth.cert_chain,
                    auth.private_key,
                    &configured_provider(),
                )
                .unwrap();
                let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
                resolver.add("localhost", cert).unwrap();
                let resolver = Arc::new(resolver);
                let server_tls = server_tls
                    .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
                    .unwrap()
                    .with_modify_rustls_config(move |mut native| {
                        native.cert_resolver = resolver.clone();
                        Ok(native)
                    });
                if policy == AlpnPolicy::OutOfBandAgreement {
                    client_tls.insert(rama_net::tls::TlsAlpn(Default::default()));
                    server_tls.insert(rama_net::tls::TlsAlpn(Default::default()));
                }
                let options = TlsOptions {
                    alpn: policy,
                    ..Default::default()
                };
                let client_config = ClientConfig::new(Arc::new(
                    QuicClientConfig::from_rama(&client_tls, configured_provider(), options)
                        .unwrap(),
                ));
                let server_config = ServerConfig::with_crypto(Arc::new(
                    QuicServerConfig::from_rama(&server_tls, configured_provider(), options)
                        .unwrap(),
                ));
                let server = Endpoint::server(
                    server_config,
                    "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
                )
                .await
                .unwrap();
                let client =
                    Endpoint::client("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
                        .await
                        .unwrap();
                let connecting = client
                    .connect_with(client_config, server.local_addr().unwrap(), "localhost")
                    .unwrap();
                let (client_conn, server_conn) =
                    tokio::join!(connecting, async { server.accept().await.unwrap().await });
                let client_conn = client_conn.unwrap();
                let server_conn = server_conn.unwrap();
                assert!(client_log.0.load(std::sync::atomic::Ordering::Relaxed) > 0);
                assert!(server_log.0.load(std::sync::atomic::Ordering::Relaxed) > 0);
                let mut send = client_conn.open_uni().await.unwrap();
                send.write_all(b"common TLS over QUIC").await.unwrap();
                send.finish().unwrap();
                let mut receive = server_conn.accept_uni().await.unwrap();
                assert_eq!(
                    receive.read_to_end(64).await.unwrap(),
                    b"common TLS over QUIC"
                );
                client_conn.close(VarInt::from_u32(0), b"done");
                client.wait_idle().await;
                server.wait_idle().await;
            }
        })
        .await
        .unwrap();
    }
}
