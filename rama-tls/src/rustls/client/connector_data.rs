use crate::rustls::dep::pemfile;
use crate::rustls::dep::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use crate::rustls::dep::rcgen::{self, KeyPair};
use crate::rustls::dep::rustls::client::danger::ServerCertVerifier;
use crate::rustls::dep::rustls::RootCertStore;
use crate::rustls::dep::rustls::{ClientConfig, SupportedProtocolVersion, ALL_VERSIONS};
use crate::rustls::key_log::KeyLogFile;
use crate::rustls::verify::NoServerCertVerifier;
use rama_core::error::{ErrorContext, OpaqueError};
use rama_net::address::Host;
use rama_net::tls::client::{ClientAuth, ClientHelloExtension, ServerVerifyMode};
use rama_net::tls::{ApplicationProtocol, DataEncoding};
use std::io::BufReader;
use std::sync::{Arc, OnceLock};
use tracing::trace;

#[derive(Debug, Clone)]
/// Internal data used as configuration/input for the [`super::HttpsConnector`].
///
/// Created by converting a [`rustls::ClientConfig`] into it directly,
/// or by trying to turn the _rama_ opiniated [`rama_net::tls::client::ClientConfig`] into it.
pub struct TlsConnectorData {
    client_config_input: Arc<ClientConfigInput>,
    server_name: Option<Host>,
}

#[derive(Debug, Default)]
struct ClientConfigInput {
    protocol_versions: Option<Vec<&'static SupportedProtocolVersion>>,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    key_logger: Option<Arc<KeyLogFile>>,
    alpn_protos: Option<Vec<Vec<u8>>>,
    cert_verifier: Option<Arc<dyn ServerCertVerifier>>,
}

impl TlsConnectorData {
    /// Create a default [`TlsConnectorData`].
    ///
    /// This constructor is best fit for tunnel purposes,
    /// for https purposes and other application protocols
    /// you may want to use another constructor instead.
    pub fn new() -> Result<TlsConnectorData, OpaqueError> {
        Ok(TlsConnectorData {
            client_config_input: Arc::new(ClientConfigInput::default()),
            server_name: None,
        })
    }

    /// Create a default [`TlsConnectorData`] that is focussed
    /// on providing auto http connections, meaning supporting
    /// the http connections which `rama` supports out of the box.
    pub fn new_http_auto() -> Result<TlsConnectorData, OpaqueError> {
        Ok(TlsConnectorData {
            client_config_input: Arc::new(ClientConfigInput {
                alpn_protos: Some(vec![
                    ApplicationProtocol::HTTP_2.as_bytes().to_vec(),
                    ApplicationProtocol::HTTP_11.as_bytes().to_vec(),
                ]),
                ..Default::default()
            }),
            server_name: None,
        })
    }

    /// Create a default [`TlsConnectorData`] that is focussed
    /// on providing http/1.1 connections.
    pub fn new_http_1() -> Result<TlsConnectorData, OpaqueError> {
        Ok(TlsConnectorData {
            client_config_input: Arc::new(ClientConfigInput {
                alpn_protos: Some(vec![ApplicationProtocol::HTTP_11.as_bytes().to_vec()]),
                ..Default::default()
            }),
            server_name: None,
        })
    }

    /// Create a default [`TlsConnectorData`] that is focussed
    /// on providing h2 connections.
    pub fn new_http_2() -> Result<TlsConnectorData, OpaqueError> {
        Ok(TlsConnectorData {
            client_config_input: Arc::new(ClientConfigInput {
                alpn_protos: Some(vec![
                    ApplicationProtocol::HTTP_2.as_bytes().to_vec(),
                    ApplicationProtocol::HTTP_11.as_bytes().to_vec(),
                ]),
                ..Default::default()
            }),
            server_name: None,
        })
    }
}

#[derive(Debug)]
pub(super) struct ClientConfigData {
    pub(super) config: ClientConfig,
    pub(super) server_name: Option<Host>,
}

impl TlsConnectorData {
    pub(super) fn try_to_build_config(&self) -> Result<ClientConfigData, OpaqueError> {
        let builder = ClientConfig::builder_with_protocol_versions(
            self.client_config_input
                .protocol_versions
                .as_deref()
                .unwrap_or(ALL_VERSIONS),
        )
        .with_root_certificates(client_root_certs());

        let mut client_config = match self.client_config_input.client_auth.as_ref() {
            Some((cert_chain, key_der)) => builder
                .with_client_auth_cert(cert_chain.clone(), key_der.clone_key())
                .context("rustls connector: create tls client config with client auth certs")?,
            None => builder.with_no_client_auth(),
        };

        if let Some(key_logger) = self.client_config_input.key_logger.clone() {
            client_config.key_log = key_logger;
        }

        if let Some(alpn_protos) = self.client_config_input.alpn_protos.clone() {
            client_config.alpn_protocols = alpn_protos;
        }

        if let Some(cert_verifier) = self.client_config_input.cert_verifier.clone() {
            client_config
                .dangerous()
                .set_certificate_verifier(cert_verifier);
        }

        Ok(ClientConfigData {
            config: client_config,
            server_name: self.server_name.clone(),
        })
    }

    /// Merge `self` together with the `other`, resulting in
    /// a new [`TlsConnectorData`], where any defined properties of `other`
    /// take priority over conflicting ones in `self`.
    pub fn merge(&self, other: &TlsConnectorData) -> TlsConnectorData {
        TlsConnectorData {
            client_config_input: Arc::new(ClientConfigInput {
                protocol_versions: other
                    .client_config_input
                    .protocol_versions
                    .clone()
                    .or_else(|| self.client_config_input.protocol_versions.clone()),
                client_auth: other
                    .client_config_input
                    .client_auth
                    .as_ref()
                    .map(|(cert_chain, key_der)| (cert_chain.clone(), key_der.clone_key()))
                    .or_else(|| {
                        self.client_config_input
                            .client_auth
                            .as_ref()
                            .map(|(cert_chain, key_der)| (cert_chain.clone(), key_der.clone_key()))
                    }),
                key_logger: other
                    .client_config_input
                    .key_logger
                    .clone()
                    .or_else(|| self.client_config_input.key_logger.clone()),
                alpn_protos: other
                    .client_config_input
                    .alpn_protos
                    .clone()
                    .or_else(|| self.client_config_input.alpn_protos.clone()),
                cert_verifier: other
                    .client_config_input
                    .cert_verifier
                    .clone()
                    .or_else(|| self.client_config_input.cert_verifier.clone()),
            }),
            server_name: other
                .server_name
                .clone()
                .or_else(|| self.server_name.clone()),
        }
    }
}

impl TlsConnectorData {
    /// Return a reference to the exposed client cert chain,
    /// should these exist and be exposed.
    pub fn client_auth_cert_chain(&self) -> Option<&[CertificateDer<'static>]> {
        self.client_config_input
            .client_auth
            .as_ref()
            .map(|t| t.0.as_ref())
    }

    /// Return a reference the desired (SNI) in case it exists
    pub fn server_name(&self) -> Option<&Host> {
        self.server_name.as_ref()
    }
}

impl TryFrom<rama_net::tls::client::ClientConfig> for TlsConnectorData {
    type Error = OpaqueError;

    fn try_from(value: rama_net::tls::client::ClientConfig) -> Result<Self, Self::Error> {
        let protocol_versions = value.extensions.iter().flatten().find_map(|ext| {
            if let ClientHelloExtension::SupportedVersions(versions) = ext {
                Some(
                    versions
                        .iter()
                        .filter_map(|v| (*v).try_into().ok())
                        .collect(),
                )
            } else {
                None
            }
        });

        let client_auth = match value.client_auth {
            None => None,
            Some(ClientAuth::SelfSigned) => {
                let (cert_chain, key_der) =
                    self_signed_client_auth().context("rustls/TlsConnectorData")?;
                Some((cert_chain, key_der))
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

                Some((cert_chain, key_der))
            }
        };

        let cert_verifier: Option<Arc<dyn ServerCertVerifier>> =
            match value.server_verify_mode.unwrap_or_default() {
                ServerVerifyMode::Auto => None, // = default
                ServerVerifyMode::Disable => {
                    trace!("rustls: tls connector data: disable server cert verification");
                    Some(Arc::new(NoServerCertVerifier::default()))
                }
            };

        // set key logger if one is requested
        let key_logger = match value.key_logger.clone().unwrap_or_default().file_path() {
            Some(path) => {
                let key_logger = KeyLogFile::new(path).context("rustls/TlsConnectorData")?;
                Some(Arc::new(key_logger))
            }
            None => None,
        };

        let mut alpn_protos = None;
        let mut server_name = None;

        // set all other extensions that we recognise for rustls purposes
        for extension in value.extensions.iter().flatten() {
            match extension {
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpns) => {
                    alpn_protos = Some(alpns.iter().map(|p| p.as_bytes().to_vec()).collect());
                }
                ClientHelloExtension::ServerName(opt_host) => {
                    server_name = match opt_host {
                        Some(Host::Name(_)) => opt_host.clone(),
                        Some(Host::Address(_)) => None, // ignore ip addresses, servers might bork
                        None => None,
                    };
                }
                other => {
                    trace!(ext = ?other, "rustls/TlsConnectorData: ignore client hello ext");
                }
            }
        }

        // return the created client config, all good if you reach here
        Ok(TlsConnectorData {
            client_config_input: Arc::new(ClientConfigInput {
                protocol_versions,
                client_auth,
                key_logger,
                alpn_protos,
                cert_verifier,
            }),
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
