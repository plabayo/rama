use crate::rustls::dep::pemfile;
use crate::rustls::dep::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use crate::rustls::dep::rcgen::{self, KeyPair};
use crate::rustls::dep::rustls::{self, RootCertStore};
use crate::rustls::key_log::KeyLogFile;
use crate::rustls::verify::NoServerCertVerifier;
use rama_core::error::{ErrorContext, OpaqueError};
use rama_net::address::Host;
use rama_net::tls::client::{ClientAuth, ClientHelloExtension, ServerVerifyMode};
use rama_net::tls::{ApplicationProtocol, DataEncoding, KeyLogIntent};
use std::io::BufReader;
use std::sync::{Arc, OnceLock};
use tracing::trace;

#[derive(Debug, Clone)]
/// Internal data used as configuration/input for the [`super::HttpsConnector`].
///
/// Created by converting a [`rustls::ClientConfig`] into it directly,
/// or by trying to turn the _rama_ opiniated [`rama_net::tls::client::ClientConfig`] into it.
pub struct TlsConnectorData {
    pub(super) client_config: Arc<rustls::ClientConfig>,
    pub(super) client_auth_cert_chain: Option<Vec<CertificateDer<'static>>>,
    pub(super) server_name: Option<Host>,
}

impl TlsConnectorData {
    /// Create a default [`TlsConnectorData`].
    ///
    /// This constructor is best fit for tunnel purposes,
    /// for https purposes and other application protocols
    /// you may want to use another constructor instead.
    pub fn new() -> Result<TlsConnectorData, OpaqueError> {
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(client_root_certs())
            .with_no_client_auth();
        Ok(cfg.into())
    }

    /// Create a default [`TlsConnectorData`] that is focussed
    /// on providing auto http connections, meaning supporting
    /// the http connections which `rama` supports out of the box.
    pub fn new_http_auto() -> Result<TlsConnectorData, OpaqueError> {
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(client_root_certs())
            .with_no_client_auth();
        // needs to remain in sync with rama's default `HttpConnector`
        cfg.alpn_protocols = vec![
            ApplicationProtocol::HTTP_2.as_bytes().to_vec(),
            ApplicationProtocol::HTTP_11.as_bytes().to_vec(),
        ];
        Ok(cfg.into())
    }

    /// Create a default [`TlsConnectorData`] that is focussed
    /// on providing http/1.1 connections.
    pub fn new_http_1() -> Result<TlsConnectorData, OpaqueError> {
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(client_root_certs())
            .with_no_client_auth();
        // needs to remain in sync with rama's default `HttpConnector`
        cfg.alpn_protocols = vec![ApplicationProtocol::HTTP_11.as_bytes().to_vec()];
        Ok(cfg.into())
    }

    /// Create a default [`TlsConnectorData`] that is focussed
    /// on providing h2 connections.
    pub fn new_http_2() -> Result<TlsConnectorData, OpaqueError> {
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(client_root_certs())
            .with_no_client_auth();
        // needs to remain in sync with rama's default `HttpConnector`
        cfg.alpn_protocols = vec![ApplicationProtocol::HTTP_2.as_bytes().to_vec()];
        Ok(cfg.into())
    }
}

impl TlsConnectorData {
    /// Return a shared reference to the underlying [`rustls::ClientConfig`].
    pub fn client_config(&self) -> &rustls::ClientConfig {
        self.client_config.as_ref()
    }

    /// Return a shared copy to the underlying [`rustls::ClientConfig`].
    pub fn shared_client_config(&self) -> Arc<rustls::ClientConfig> {
        self.client_config.clone()
    }

    /// Return a reference to the exposed client cert chain,
    /// should these exist and be exposed.
    pub fn client_auth_cert_chain(&self) -> Option<&[CertificateDer<'static>]> {
        self.client_auth_cert_chain.as_deref()
    }

    /// Take (consume) the exposed client cert chain,
    /// should these exist and be exposed.
    pub fn take_client_auth_cert_chain(&mut self) -> Option<Vec<CertificateDer<'static>>> {
        self.client_auth_cert_chain.take()
    }

    /// Return a reference the desired (SNI) in case it exists
    pub fn server_name(&self) -> Option<&Host> {
        self.server_name.as_ref()
    }
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
            client_auth_cert_chain: None,
            server_name: None,
        }
    }
}

impl TryFrom<rama_net::tls::client::ClientConfig> for TlsConnectorData {
    type Error = OpaqueError;

    fn try_from(value: rama_net::tls::client::ClientConfig) -> Result<Self, Self::Error> {
        let mut client_auth_cert_chain = None;
        let mut server_name = None;
        let builder = value
            .extensions
            .iter()
            .flatten()
            .find_map(|ext| {
                if let ClientHelloExtension::SupportedVersions(versions) = ext {
                    let v: Vec<_> = versions
                        .iter()
                        .filter_map(|v| (*v).try_into().ok())
                        .collect();
                    Some(rustls::ClientConfig::builder_with_protocol_versions(&v[..]))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                rustls::ClientConfig::builder_with_protocol_versions(rustls::ALL_VERSIONS)
            });

        let builder = builder.with_root_certificates(client_root_certs());

        // builder with client auth configured
        let mut client_config = match value.client_auth {
            None => builder.with_no_client_auth(),
            Some(ClientAuth::SelfSigned) => {
                let (cert_chain, key_der) =
                    self_signed_client_auth().context("rustls/TlsConnectorData")?;
                if value.expose_client_cert {
                    client_auth_cert_chain = Some(cert_chain.clone());
                }
                builder.with_client_auth_cert(cert_chain, key_der).context(
                    "rustls/TlsConnectorData: build base self-signed rustls ClientConfig",
                )?
            }
            Some(ClientAuth::Single(data)) => {
                // client TLS Certs
                let cert_chain = match data.cert_chain {
                    DataEncoding::Der(raw_data) => vec![CertificateDer::from(raw_data)],
                    DataEncoding::DerStack(raw_data_list) => raw_data_list
                        .into_iter()
                        .map(CertificateDer::from)
                        .collect(),
                    DataEncoding::Pem(raw_data) => {
                        let mut pem = BufReader::new(raw_data.as_bytes());
                        let mut cert_chain = Vec::new();
                        for cert in pemfile::certs(&mut pem) {
                            cert_chain.push(
                                cert.context("rustls/TlsConnectorData: parse tls client cert")?,
                            );
                        }
                        cert_chain
                    }
                };

                // client TLS key
                let key_der = match data.private_key {
                    DataEncoding::Der(raw_data) => raw_data
                        .try_into()
                        .map_err(|_| OpaqueError::from_display("invalid key data"))
                        .context("rustls/TlsConnectorData: read private (DER) key")?,
                    DataEncoding::DerStack(raw_data_list) => raw_data_list
                        .first()
                        .cloned()
                        .context("DataEncoding::DerStack: get first private (DER) key")?
                        .try_into()
                        .map_err(|_| OpaqueError::from_display("invalid key data"))
                        .context("rustls/TlsConnectorData: read private (DER) key")?,
                    DataEncoding::Pem(raw_data) => {
                        let mut key_reader = BufReader::new(raw_data.as_bytes());
                        pemfile::private_key(&mut key_reader)
                            .context("rustls/TlsConnectorData: read private (PEM) key")?
                            .context("rustls/TlsConnectorData: private found (in PEM)")?
                    }
                };

                if value.expose_client_cert {
                    client_auth_cert_chain = Some(cert_chain.clone());
                }

                builder
                    .with_client_auth_cert(cert_chain, key_der)
                    .context("rustls/TlsConnectorData: build base rustls ClientConfig")?
            }
        };

        match value.server_verify_mode {
            ServerVerifyMode::Auto => (), // = default
            ServerVerifyMode::Disable => {
                trace!("rustls: tls connector data: disable server cert verification");
                client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(NoServerCertVerifier::default()));
            }
        }

        // set key logger if one is requested
        match value.key_logger {
            KeyLogIntent::Disabled => (),
            KeyLogIntent::File(path) => {
                let key_logger = KeyLogFile::new(path).context("rustls/TlsConnectorData")?;
                client_config.key_log = Arc::new(key_logger);
            }
        };

        // set all other extensions that we recognise for rustls purposes
        for extension in value.extensions.iter().flatten() {
            match extension {
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpns) => {
                    let alpns = alpns.iter().map(|p| p.as_bytes().to_vec()).collect();
                    client_config.alpn_protocols = alpns;
                }
                ClientHelloExtension::ServerName(opt_host) => {
                    server_name = opt_host.clone();
                }
                other => {
                    trace!(ext = ?other, "rustls/TlsConnectorData: ignore client hello ext");
                }
            }
        }

        // return the created client config, all good if you reach here
        Ok(TlsConnectorData {
            client_config: Arc::new(client_config),
            client_auth_cert_chain,
            server_name,
        })
    }
}

pub(super) fn client_root_certs() -> Arc<RootCertStore> {
    static ROOT_CERTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOT_CERTS
        .get_or_init(|| {
            let mut root_storage = RootCertStore::empty();
            root_storage.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(root_storage)
        })
        .clone()
}

fn self_signed_client_auth(
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), OpaqueError> {
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
