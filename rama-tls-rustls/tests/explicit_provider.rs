#![cfg(any(feature = "aws-lc", feature = "ring"))]

#[cfg(test)]
mod tests {
    use rama_crypto::pki_types::{CertificateDer, ServerName};
    use rama_tls::{
        ProtocolVersion,
        client::{
            ClientAuth, ClientAuthData, ServerVerifyMode, TlsClientConfig, TlsServerCertPins,
        },
        server::{ClientVerifyMode, GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    };
    use rama_tls_rustls::{
        client::{RustlsClientConfigExt, RustlsTlsConnectorConfig, self_signed_client_auth},
        dep::rustls::{self, crypto::CryptoProvider},
        server::{RustlsServerConfigExt, RustlsTlsAcceptorConfig},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug, Default)]
    struct KeyLogCount(AtomicUsize);
    impl rama_tls::keylog::KeyLogSink for KeyLogCount {
        fn write_line(&self, line: &str) {
            assert!(line.ends_with('\n'));
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    // This binary has one test so no other test can initialize the process-wide provider.
    #[test]
    fn explicit_provider_is_independent_of_process_default() {
        assert!(CryptoProvider::get_default().is_none());
        let providers = vec![
            #[cfg(feature = "ring")]
            Arc::new(rustls::crypto::ring::default_provider()),
            #[cfg(feature = "aws-lc")]
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        ];
        for provider in &providers {
            exercise_configuration(provider);
            assert!(CryptoProvider::get_default().is_none());
        }

        let mut global = (*providers[0]).clone();
        global.cipher_suites.reverse();
        global.install_default().unwrap();
        for provider in providers {
            assert!(!Arc::ptr_eq(
                CryptoProvider::get_default().unwrap(),
                &provider
            ));
            exercise_configuration(&provider);
        }
    }

    fn exercise_configuration(provider: &Arc<CryptoProvider>) {
        let client_log = Arc::new(KeyLogCount::default());
        let server_log = Arc::new(KeyLogCount::default());
        let server_auth =
            ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        let (client_chain, client_key) = self_signed_client_auth().unwrap();
        let client_auth = ClientAuth::Single(ClientAuthData {
            cert_chain: client_chain.clone(),
            private_key: client_key,
        });
        let client = TlsClientConfig::new()
            .with_keylog(rama_tls::KeyLogIntent::Custom(client_log.clone()))
            .with_supported_versions(vec![ProtocolVersion::TLSv1_3])
            .with_alpn_http_auto()
            .try_with_server_trust_anchors([server_auth.cert_chain.last().unwrap().clone()])
            .unwrap()
            .with_server_cert_pins(TlsServerCertPins::new(server_auth.cert_chain[0].clone()))
            .with_client_auth(client_auth)
            .with_modify_rustls_config(|mut config| {
                assert_eq!(
                    config.alpn_protocols,
                    [b"h2".to_vec(), b"http/1.1".to_vec()]
                );
                config.alpn_protocols = vec![b"provider-test".to_vec()];
                Ok(config)
            });
        let server = TlsServerConfig::new()
            .with_keylog(rama_tls::KeyLogIntent::Custom(server_log.clone()))
            .with_supported_versions(vec![ProtocolVersion::TLSv1_3])
            .with_alpn_http_auto()
            .with_server_auth(server_auth)
            .with_client_verify(ClientVerifyMode::ClientAuth(client_chain))
            .with_modify_rustls_config(|mut config| {
                assert_eq!(
                    config.alpn_protocols,
                    [b"h2".to_vec(), b"http/1.1".to_vec()]
                );
                config.alpn_protocols = vec![b"provider-test".to_vec()];
                Ok(config)
            });
        let build_client = || {
            RustlsTlsConnectorConfig::from_extensions(client.as_extensions())
                .try_into_client_config_with_provider(provider.clone())
                .unwrap()
        };
        let build_server = || {
            RustlsTlsAcceptorConfig::from_extensions(server.as_extensions())
                .try_into_server_config_with_provider(provider.clone())
                .unwrap()
        };
        let native_client = build_client();
        let native_server = build_server();
        assert!(Arc::ptr_eq(native_client.crypto_provider(), provider));
        assert!(Arc::ptr_eq(native_server.crypto_provider(), provider));
        handshake(native_client, native_server).unwrap();
        assert!(client_log.0.load(Ordering::Relaxed) > 0);
        assert!(server_log.0.load(Ordering::Relaxed) > 0);

        // Exercise the pin-only verifier's signature provider as well as the ordinary
        // trust-and-pin verifier used above, then reject an incorrect pin.
        client.insert(rama_tls::client::TlsServerVerify(ServerVerifyMode::Disable));
        handshake(build_client(), build_server()).unwrap();
        client.insert(TlsServerCertPins::new(CertificateDer::from(vec![1, 2, 3])));
        assert!(handshake(build_client(), build_server()).is_err());

        let mut invalid = (**provider).clone();
        invalid.cipher_suites.clear();
        let invalid = Arc::new(invalid);
        RustlsTlsConnectorConfig::from_extensions(client.as_extensions())
            .try_into_client_config_with_provider(invalid.clone())
            .unwrap_err();
        RustlsTlsAcceptorConfig::from_extensions(server.as_extensions())
            .try_into_server_config_with_provider(invalid)
            .unwrap_err();
    }

    fn handshake(
        client: rustls::ClientConfig,
        server: rustls::ServerConfig,
    ) -> Result<(), rustls::Error> {
        let mut client = rustls::ClientConnection::new(
            Arc::new(client),
            ServerName::try_from("localhost").unwrap(),
        )?;
        let mut server = rustls::ServerConnection::new(Arc::new(server))?;
        for _ in 0..16 {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            server.read_tls(&mut bytes.as_slice()).unwrap();
            server.process_new_packets()?;
            bytes.clear();
            server.write_tls(&mut bytes).unwrap();
            client.read_tls(&mut bytes.as_slice()).unwrap();
            client.process_new_packets()?;
            if !client.is_handshaking() && !server.is_handshaking() {
                assert_eq!(client.alpn_protocol(), Some(b"provider-test".as_slice()));
                assert!(server.peer_certificates().is_some());
                return Ok(());
            }
        }
        panic!("in-memory TLS handshake did not finish");
    }
}
