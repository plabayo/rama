use rama_boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode, SslVersion};
use rama_boring_tokio::SslStream;
use rama_core::{
    Service, ServiceInput, conversion::RamaFrom as _, error::BoxError,
    extensions::ExtensionsRef as _, service::service_fn,
};
use rama_crypto::cert::{CertificateKeyKind, LeafCertConfig};
use rama_tls::{
    CipherSuite, SignatureScheme, SupportedGroup,
    client::{NegotiatedTlsAlgorithms, NegotiatedTlsParameters},
    server::{
        CertificateIssuanceContext, DynamicCertIssuer, GeneratedServerAuthConfig, LeafCertRequest,
        ServerAuthData, TlsServerConfig,
    },
};
use tokio::io::DuplexStream;

use super::{BoringServerConfigExt as _, ServerCertIssuerData, TlsAcceptorService};
use crate::TlsStream;

/// Handshake `client` with a boring acceptor for `server`.
///
/// Returns the client stream and what the server recorded.
async fn handshake(
    server: TlsServerConfig,
    client: SslConnectorBuilder,
) -> (SslStream<DuplexStream>, NegotiatedTlsParameters) {
    let acceptor = TlsAcceptorService::new(
        server,
        service_fn(|stream: TlsStream<ServiceInput<DuplexStream>>| async move {
            Ok::<_, BoxError>(
                stream
                    .extensions()
                    .get_ref::<NegotiatedTlsParameters>()
                    .unwrap()
                    .clone(),
            )
        }),
        false,
    );
    let config = client.build().configure().unwrap();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (client, server) = tokio::join!(
        rama_boring_tokio::connect(config, Some("localhost"), client_io),
        acceptor.serve(ServiceInput::new(server_io)),
    );
    (client.unwrap(), server.unwrap())
}

fn client(max_version: SslVersion) -> SslConnectorBuilder {
    let mut client = SslConnector::builder(SslMethod::tls_client()).unwrap();
    client.set_verify(SslVerifyMode::NONE);
    client.set_max_proto_version(Some(max_version)).unwrap();
    client
}

fn server_auth(key_kind: CertificateKeyKind) -> ServerAuthData {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::SelfSignedLeaf(LeafCertRequest {
        config: LeafCertConfig {
            key_kind,
            ..Default::default()
        },
        ..Default::default()
    }))
    .unwrap()
}

#[tokio::test]
async fn configured_cipher_suites_are_the_server_preference() {
    let auth = server_auth(CertificateKeyKind::EcP256);
    let offered = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384";
    for (configured, negotiated) in [
        (None, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        (
            Some(vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ]),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ),
    ] {
        let mut server = TlsServerConfig::new().with_server_auth(auth.clone());
        if let Some(suites) = configured {
            server.set_cipher_suites(suites);
        }
        let mut client = client(SslVersion::TLS1_2);
        client.set_cipher_list(offered).unwrap();
        let (_, params) = handshake(server, client).await;
        assert_eq!(params.algorithms.cipher_suite, Some(negotiated));
    }
}

#[tokio::test]
async fn configured_groups_are_the_server_preference() {
    let auth = server_auth(CertificateKeyKind::EcP256);
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        for (configured, negotiated) in [
            (None, SupportedGroup::X25519),
            (
                Some(vec![SupportedGroup::SECP256R1, SupportedGroup::X25519]),
                SupportedGroup::SECP256R1,
            ),
        ] {
            let mut server = TlsServerConfig::new().with_server_auth(auth.clone());
            if let Some(groups) = configured {
                server.set_supported_groups(groups);
            }
            let mut client = client(version);
            client.set_curves_list("X25519:P-256").unwrap();
            let (_, params) = handshake(server, client).await;
            assert_eq!(
                params.algorithms.key_exchange_group,
                Some(negotiated),
                "{version:?}"
            );
        }
    }
}

struct FixedIssuer(ServerAuthData);

impl DynamicCertIssuer for FixedIssuer {
    async fn issue_cert(&self, _: CertificateIssuanceContext) -> Result<ServerAuthData, BoxError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn configured_signature_schemes_sign_the_handshake_for_every_identity_source() {
    let auth = server_auth(CertificateKeyKind::Rsa2048);
    for issued in [false, true] {
        for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
            for (configured, signed) in [
                (None, SignatureScheme::RSA_PSS_SHA256),
                (
                    Some(vec![
                        SignatureScheme::ED25519,
                        SignatureScheme::RSA_PSS_SHA512,
                        SignatureScheme::RSA_PSS_SHA256,
                    ]),
                    SignatureScheme::RSA_PSS_SHA512,
                ),
            ] {
                let mut server = if issued {
                    TlsServerConfig::new()
                        .with_cert_issuer(ServerCertIssuerData::new(FixedIssuer(auth.clone())))
                } else {
                    TlsServerConfig::new().with_server_auth(auth.clone())
                };
                if let Some(schemes) = configured {
                    server.set_signature_schemes(schemes);
                }
                let (client, _) = handshake(server, client(version)).await;
                let algorithms = NegotiatedTlsAlgorithms::rama_from(client.ssl());
                assert_eq!(
                    algorithms.peer_signature_scheme,
                    Some(signed),
                    "issued={issued} {version:?}"
                );
            }
        }
    }
}

#[cfg(feature = "compression")]
mod compression {
    use std::{
        io::{Result, Write},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use rama_boring::ssl::{CertificateCompressionAlgorithm, CertificateCompressor};
    use rama_tls::CertificateCompressionAlgorithm as Algorithm;

    use super::*;
    use crate::certificate_compression::codecs::BrotliCertificateCompressor;

    /// A brotli decompressor that counts how often the server compressed.
    struct CountingBrotli(Arc<AtomicUsize>);

    impl CertificateCompressor for CountingBrotli {
        const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
        const CAN_COMPRESS: bool = false;
        const CAN_DECOMPRESS: bool = true;

        fn decompress<W>(&self, input: &[u8], output: &mut W) -> Result<()>
        where
            W: Write,
        {
            self.0.fetch_add(1, Ordering::SeqCst);
            BrotliCertificateCompressor::default().decompress(input, output)
        }
    }

    #[tokio::test]
    async fn configured_cert_compression_compresses_for_a_client_that_offers_it() {
        let auth = server_auth(CertificateKeyKind::EcP256);
        for (configured, compressed) in [
            (None, 0),
            (Some(vec![Algorithm::Zlib]), 0),
            (Some(vec![Algorithm::Zlib, Algorithm::Brotli]), 1),
        ] {
            let mut server = TlsServerConfig::new().with_server_auth(auth.clone());
            if let Some(algorithms) = configured.clone() {
                server.set_cert_compression(algorithms);
            }
            let decompressed = Arc::new(AtomicUsize::new(0));
            let mut client = client(SslVersion::TLS1_3);
            client
                .add_certificate_compression_algorithm(CountingBrotli(decompressed.clone()))
                .unwrap();
            handshake(server, client).await;
            assert_eq!(
                decompressed.load(Ordering::SeqCst),
                compressed,
                "{configured:?}"
            );
        }
    }
}
