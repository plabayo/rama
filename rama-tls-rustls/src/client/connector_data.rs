use crate::dep::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use crate::dep::rcgen::{self, KeyPair};
use crate::dep::rustls::RootCertStore;
use crate::dep::rustls::{ALL_VERSIONS, ClientConfig};
use crate::key_log::KeyLogFile;
use rama_core::error::{ErrorContext, OpaqueError};
use rama_net::address::Host;
use rama_net::tls::{ApplicationProtocol, KeyLogIntent};
use std::sync::{Arc, OnceLock};

#[derive(Debug, Clone)]
/// Internal data used as configuration/input for the [`super::HttpsConnector`].
///
/// Created by converting a [`rustls::ClientConfig`] into it directly,
/// or by trying to turn the _rama_ opiniated [`rama_net::tls::client::ClientConfig`] into it.
pub struct TlsConnectorData {
    pub client_config: Arc<rustls::ClientConfig>,
    pub server_name: Option<Host>,
    pub store_server_certificate_chain: bool,
}

impl From<rustls::ClientConfig> for TlsConnectorData {
    #[inline]
    fn from(value: rustls::ClientConfig) -> Self {
        Arc::new(value).into()
    }
}

impl From<Arc<rustls::ClientConfig>> for TlsConnectorData {
    fn from(value: Arc<rustls::ClientConfig>) -> Self {
        Self {
            client_config: value,
            server_name: None,
            store_server_certificate_chain: false,
        }
    }
}

impl TlsConnectorData {
    /// Create a default [`TlsConnectorData`] that is focussed
    /// on providing auto http connections, meaning supporting
    /// the http connections which `rama` supports out of the box.
    pub fn new_http_auto() -> Result<TlsConnectorData, OpaqueError> {
        let mut config = ClientConfig::builder_with_protocol_versions(ALL_VERSIONS)
            .with_root_certificates(client_root_certs())
            .with_no_client_auth();

        config.alpn_protocols = vec![
            ApplicationProtocol::HTTP_2.as_bytes().to_vec(),
            ApplicationProtocol::HTTP_11.as_bytes().to_vec(),
        ];

        if let Some(path) = KeyLogIntent::Environment.file_path() {
            let key_logger = Arc::new(KeyLogFile::new(path).unwrap());
            config.key_log = key_logger;
        };

        Ok(config.into())
    }
}

pub fn client_root_certs() -> Arc<RootCertStore> {
    static ROOT_CERTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOT_CERTS
        .get_or_init(|| {
            let mut root_storage = RootCertStore::empty();
            root_storage.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(root_storage)
        })
        .clone()
}

pub fn self_signed_client_auth()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), OpaqueError> {
    // Create a client end entity cert.
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let client_key_pair =
        KeyPair::generate_for(alg).context("self-signed client auth: generate client key pair")?;
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
