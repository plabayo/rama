use crate::RamaTlsRustlsCrateMarker;
use crate::client::config::RustlsTlsConnectorConfig;
use crate::dep::rustls::RootCertStore;
use crate::dep::rustls::{ALL_VERSIONS, ClientConfig, client::WebPkiServerVerifier};
use crate::key_log::RamaKeyLog;
use crate::verify::{NoServerCertVerifier, PinnedServerCertVerifier};
use rama_core::conversion::{RamaTryFrom, RamaTryInto};
use rama_core::error::BoxError;
#[cfg(any(feature = "aws-lc", feature = "ring"))]
use rama_core::error::ErrorContext;
use rama_crypto::pki_types::{CertificateDer, PrivateKeyDer};
use rama_net::address::Host;
use rama_tls::client::{ClientAuth, ServerVerifyMode};
use rama_tls::keylog::open_intent_sink;
use std::sync::{Arc, LazyLock};

#[cfg(any(feature = "aws-lc", feature = "ring"))]
use rama_crypto::pki_types::PrivatePkcs8KeyDer;

#[derive(Debug, Clone)]
/// The resolved native rustls config consumed by [`super::TlsConnector`].
pub(crate) struct TlsConnectorData {
    pub client_config: Arc<ClientConfig>,
    pub server_name: Option<Host>,
    pub store_server_certificate_chain: bool,
}

impl TryFrom<RustlsTlsConnectorConfig<'_>> for TlsConnectorData {
    type Error = BoxError;

    fn try_from(value: RustlsTlsConnectorConfig<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            server_name: value.server_name.map(|sni| sni.0.clone()),
            store_server_certificate_chain: value.store_chain.is_some_and(|flag| flag.0),
            client_config: Arc::new(value.try_into()?),
        })
    }
}

impl RamaTryFrom<rama_tls::client::TlsClientConfig, RamaTlsRustlsCrateMarker> for ClientConfig {
    type Error = BoxError;

    fn rama_try_from(value: rama_tls::client::TlsClientConfig) -> Result<Self, Self::Error> {
        Self::try_from(RustlsTlsConnectorConfig::from_extensions(
            value.as_extensions(),
        ))
    }
}

impl RamaTryFrom<&rama_tls::client::TlsClientConfig, RamaTlsRustlsCrateMarker> for ClientConfig {
    type Error = BoxError;

    fn rama_try_from(value: &rama_tls::client::TlsClientConfig) -> Result<Self, Self::Error> {
        Self::try_from(RustlsTlsConnectorConfig::from_extensions(
            value.as_extensions(),
        ))
    }
}

impl TryFrom<RustlsTlsConnectorConfig<'_>> for ClientConfig {
    type Error = BoxError;

    fn try_from(value: RustlsTlsConnectorConfig<'_>) -> Result<Self, Self::Error> {
        crate::ensure_default_crypto_provider();

        let server_verify_mode = value.verify.map(|verify| verify.0).unwrap_or_default();

        // Map common protocol versions to rustls, rustls only models TLS 1.2/1.3,
        // anything else (incl. GREASE) is dropped. Empty = all supported versions.
        let versions: Vec<&'static rustls::SupportedProtocolVersion> = value
            .versions
            .map(|v| {
                v.0.iter()
                    .filter_map(|pv| (*pv).rama_try_into().ok())
                    .collect()
            })
            .unwrap_or_default();

        let builder = if versions.is_empty() {
            Self::builder_with_protocol_versions(ALL_VERSIONS)
        } else {
            Self::builder_with_protocol_versions(&versions)
        };

        let builder = builder.with_root_certificates(client_root_certs());
        let mut client_config = match value.client_auth.map(|auth| &auth.0) {
            Some(client_auth) => {
                let (cert_chain, private_key) = rustls_client_auth(client_auth)?;
                builder.with_client_auth_cert(cert_chain, private_key)?
            }
            None => builder.with_no_client_auth(),
        };

        match (server_verify_mode, value.server_cert_pins) {
            (ServerVerifyMode::Disable, Some(pins)) => {
                let signature_verifier =
                    WebPkiServerVerifier::builder(client_root_certs()).build()?;
                client_config.dangerous().set_certificate_verifier(Arc::new(
                    PinnedServerCertVerifier::pin_only(pins.clone(), signature_verifier),
                ));
            }
            (ServerVerifyMode::Disable, None) => {
                client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(NoServerCertVerifier::default()));
            }
            (ServerVerifyMode::Auto, Some(pins)) => {
                let child = match value.verifier {
                    Some(verifier) => verifier.0.clone(),
                    None => WebPkiServerVerifier::builder(client_root_certs()).build()?,
                };
                client_config.dangerous().set_certificate_verifier(Arc::new(
                    PinnedServerCertVerifier::new(pins.clone(), child),
                ));
            }
            (ServerVerifyMode::Auto, None) => {
                if let Some(verifier) = value.verifier {
                    client_config
                        .dangerous()
                        .set_certificate_verifier(verifier.0.clone());
                }
            }
        }

        if let Some(alpn) = value.alpn {
            client_config.alpn_protocols = alpn
                .0
                .iter()
                .map(|proto| proto.as_bytes().to_vec())
                .collect();
        }

        if let Some(keylog) = value.keylog
            && let Some(sink) = open_intent_sink(&keylog.0)?
        {
            client_config.key_log = Arc::new(RamaKeyLog::new(sink));
        }

        if let Some(modify) = value.modify {
            client_config = modify.apply(client_config)?;
        }

        Ok(client_config)
    }
}

/// Resolve a common [`ClientAuth`] into the native rustls cert chain + private
/// key consumed by [`rustls::ConfigBuilder::with_client_auth_cert`].
///
/// `SelfSigned` generates a throwaway client identity.
fn rustls_client_auth(
    client_auth: &ClientAuth,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    let data = match client_auth {
        ClientAuth::SelfSigned => return self_signed_client_auth(),
        ClientAuth::Single(data) => data,
    };

    let cert_chain = data.cert_chain.clone();
    let private_key = data.private_key.clone_key();

    Ok((cert_chain, private_key))
}

/// The default client root certificate store used to verify servers.
///
/// By default this is built from the platform's native trust store (the system
/// root certificates), loaded once and shared process-wide via
/// [`rama_crypto::native_certs::shared_native_trust_anchors`]. On systems where
/// no native roots are found, that loader warns and falls back to the bundled
/// webpki (Mozilla CCADB) roots.
pub fn client_root_certs() -> Arc<RootCertStore> {
    static ROOT_CERTS: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
        let mut root_storage = RootCertStore::empty();
        let anchors = rama_crypto::native_certs::shared_native_trust_anchors();
        let (added, ignored) = root_storage.add_parsable_certificates(anchors.iter().cloned());
        rama_core::telemetry::tracing::trace!(
            added,
            ignored,
            "rama-tls-rustls: initialised client root cert store from shared native trust anchors"
        );
        Arc::new(root_storage)
    });
    ROOT_CERTS.clone()
}

#[cfg(not(any(feature = "aws-lc", feature = "ring")))]
#[cfg_attr(docsrs, doc(cfg(not(any(feature = "aws-lc", feature = "ring")))))]
pub fn self_signed_client_auth()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    Err(BoxError::from(
        "enable aws-lc or ring feature to use fn self_signed_client_auth",
    ))
}

#[cfg(any(feature = "aws-lc", feature = "ring"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "aws-lc", feature = "ring"))))]
pub fn self_signed_client_auth()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    // Create a client end entity cert.
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let client_key_pair = rcgen::KeyPair::generate_for(alg)
        .context("self-signed client auth: generate client key pair")?;
    let mut client_ee_params = rcgen::CertificateParams::new(vec![])
        .context("self-signed client auth: create client EE Params")?;
    client_ee_params.is_ca = rcgen::IsCa::NoCa;
    client_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];

    let client_cert = client_ee_params
        .self_signed(&client_key_pair)
        .context("create client self-signed cert")?;
    let client_cert_der = client_cert.into();
    let client_key_der = PrivatePkcs8KeyDer::from(client_key_pair.serialize_der());

    Ok((
        vec![client_cert_der],
        PrivatePkcs8KeyDer::from(client_key_der.secret_pkcs8_der().to_owned()).into(),
    ))
}

// build() needs an installed CryptoProvider so feature gate these tests
#[cfg(all(test, any(feature = "aws-lc", feature = "ring")))]
mod tests {
    use super::*;
    use rama_core::{error::BoxErrorExt, extensions::Extensions};
    use rama_tls::{
        TlsAlpn,
        client::{TlsClientAuth, TlsServerCertPins, TlsServerVerify, TlsStoreServerCertChain},
    };

    #[test]
    fn build_from_pieces_sets_alpn_and_flags() {
        crate::ensure_default_crypto_provider();
        let ext = Extensions::new();
        ext.insert(TlsAlpn::http_auto());
        ext.insert(TlsServerVerify(ServerVerifyMode::Disable));
        ext.insert(TlsStoreServerCertChain(true));

        let config = RustlsTlsConnectorConfig::from_extensions(&ext);
        let data = TlsConnectorData::try_from(config).unwrap();

        assert_eq!(
            data.client_config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        );
        assert!(data.store_server_certificate_chain);
    }

    #[test]
    fn build_empty_uses_defaults() {
        crate::ensure_default_crypto_provider();
        let ext = Extensions::new();
        let config = RustlsTlsConnectorConfig::from_extensions(&ext);
        let data = TlsConnectorData::try_from(config).unwrap();

        assert!(data.client_config.alpn_protocols.is_empty());
        assert!(!data.store_server_certificate_chain);
        assert!(data.server_name.is_none());
        assert!(!data.client_config.client_auth_cert_resolver.has_certs());
    }

    #[test]
    fn build_applies_client_auth_from_der() {
        use rama_tls::client::ClientAuthData;

        crate::ensure_default_crypto_provider();

        let (cert_chain, private_key) = self_signed_client_auth().unwrap();
        let ext = Extensions::new();
        ext.insert(TlsClientAuth(ClientAuth::Single(ClientAuthData {
            cert_chain,
            private_key,
        })));

        let config = RustlsTlsConnectorConfig::from_extensions(&ext);
        let data = TlsConnectorData::try_from(config).unwrap();

        assert!(data.client_config.client_auth_cert_resolver.has_certs());
    }

    #[test]
    fn modify_rustls_config_runs_last_and_overrides_common_pieces() {
        use crate::client::RustlsClientConfigExt;
        use rama_tls::client::TlsClientConfig;

        crate::ensure_default_crypto_provider();

        let cfg = TlsClientConfig::new()
            .with_alpn_http_auto()
            .with_modify_rustls_config(|mut config| {
                config.alpn_protocols = vec![b"my-proto".to_vec()];
                Ok(config)
            });

        let ext = Extensions::new();
        cfg.write_to(&ext);

        let config = RustlsTlsConnectorConfig::from_extensions(&ext);
        let data = TlsConnectorData::try_from(config).unwrap();

        assert_eq!(
            data.client_config.alpn_protocols,
            vec![b"my-proto".to_vec()]
        );
    }

    #[test]
    fn modify_rustls_config_error_propagates() {
        use crate::client::RustlsClientConfigExt;
        use rama_tls::client::TlsClientConfig;

        crate::ensure_default_crypto_provider();

        let cfg = TlsClientConfig::new()
            .with_modify_rustls_config(|_| Err(BoxError::from_static_str("boom")));

        let ext = Extensions::new();
        cfg.write_to(&ext);

        let config = RustlsTlsConnectorConfig::from_extensions(&ext);
        let err = TlsConnectorData::try_from(config).unwrap_err();

        assert!(err.to_string().contains("boom"));
    }

    #[test]
    fn pins_can_be_the_only_certificate_check() {
        crate::ensure_default_crypto_provider();

        let ext = Extensions::new();
        ext.insert(TlsServerVerify(ServerVerifyMode::Disable));
        ext.insert(TlsServerCertPins::try_new([CertificateDer::from(vec![1, 2, 3])]).unwrap());

        let config = RustlsTlsConnectorConfig::from_extensions(&ext);
        TlsConnectorData::try_from(config).unwrap();
    }
}
