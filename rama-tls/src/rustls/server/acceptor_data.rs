use crate::rustls::dep::pemfile;
use crate::rustls::dep::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use crate::rustls::dep::rcgen::{self, KeyPair};
use crate::rustls::dep::rustls::{self, server::WebPkiClientVerifier, RootCertStore};
use crate::rustls::key_log::KeyLogFile;
use rama_core::error::{ErrorContext, OpaqueError};
use rama_net::address::{Domain, Host};
use rama_net::tls::server::{ClientVerifyMode, SelfSignedData, ServerAuth};
use rama_net::tls::DataEncoding;
use std::io::BufReader;
use std::sync::Arc;

#[derive(Debug, Clone)]
/// Internal data used as configuration/input for the [`super::TlsAcceptorService`].
///
/// Created by converting a [`rustls::ServerConfig`] into it directly,
/// or by trying to turn the _rama_ opiniated [`rama_net::tls::server::ServerConfig`] into it.
pub struct TlsAcceptorData {
    pub(super) server_config: Arc<rustls::ServerConfig>,
    pub(super) server_cert_chain: Option<Vec<CertificateDer<'static>>>,
}

impl TlsAcceptorData {
    /// Return a shared reference to the underlying [`rustls::ServerConfig`].
    pub fn server_config(&self) -> &rustls::ServerConfig {
        self.server_config.as_ref()
    }

    /// Return a reference to the exposed server cert chain,
    /// should these exist and be exposed.
    pub fn server_cert_chain(&self) -> Option<&[CertificateDer<'static>]> {
        self.server_cert_chain.as_deref()
    }

    /// Take (consume) the exposed server cert chain,
    /// should these exist and be exposed.
    pub fn take_server_cert_chain(&mut self) -> Option<Vec<CertificateDer<'static>>> {
        self.server_cert_chain.take()
    }
}

impl From<rustls::ServerConfig> for TlsAcceptorData {
    #[inline]
    fn from(value: rustls::ServerConfig) -> Self {
        Arc::new(value).into()
    }
}

impl From<Arc<rustls::ServerConfig>> for TlsAcceptorData {
    fn from(value: Arc<rustls::ServerConfig>) -> Self {
        Self {
            server_config: value,
            server_cert_chain: None,
        }
    }
}

impl TryFrom<rama_net::tls::server::ServerConfig> for TlsAcceptorData {
    type Error = OpaqueError;

    fn try_from(value: rama_net::tls::server::ServerConfig) -> Result<Self, Self::Error> {
        let mut server_cert_chain = None;

        let v: Vec<_> = value
            .protocol_versions
            .into_iter()
            .flatten()
            .filter_map(|v| v.try_into().ok())
            .collect();

        // builder with protocol versions defined (be it auto)
        let builder = if v.is_empty() {
            rustls::ServerConfig::builder_with_protocol_versions(rustls::ALL_VERSIONS)
        } else {
            rustls::ServerConfig::builder_with_protocol_versions(&v[..])
        };

        // builder with client auth configured
        let builder = match value.client_verify_mode {
            ClientVerifyMode::Auto | ClientVerifyMode::Disable => builder.with_no_client_auth(),
            ClientVerifyMode::ClientAuth(DataEncoding::Der(bytes)) => {
                let client_cert_der = CertificateDer::from(bytes);
                let mut root_cert_storage = RootCertStore::empty();
                root_cert_storage
                    .add(client_cert_der)
                    .context("rustls/TlsAcceptorData: der: add client cert to root cert storage")?;
                let cert_verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_storage))
                    .build()
                    .context("rustls/TlsAcceptorData: der: create webpki client verifier")?;
                builder.with_client_cert_verifier(cert_verifier)
            }
            ClientVerifyMode::ClientAuth(DataEncoding::DerStack(bytes_list)) => {
                let mut root_cert_storage = RootCertStore::empty();
                for bytes in bytes_list {
                    let client_cert_der = CertificateDer::from(bytes);
                    root_cert_storage.add(client_cert_der).context(
                        "rustls/TlsAcceptorData: der: add client cert to root cert storage",
                    )?
                }
                let cert_verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_storage))
                    .build()
                    .context("rustls/TlsAcceptorData: der: create webpki client verifier")?;
                builder.with_client_cert_verifier(cert_verifier)
            }
            ClientVerifyMode::ClientAuth(DataEncoding::Pem(raw_pem)) => {
                let mut root_cert_storage = RootCertStore::empty();
                let mut pem = BufReader::new(raw_pem.as_bytes());
                for (index, cert) in pemfile::certs(&mut pem).enumerate() {
                    let cert = cert.with_context(|| {
                        format!("rustls/TlsAcceptorData: pem #{index}: parse tls client cert")
                    })?;
                    root_cert_storage
                        .add(cert)
                        .with_context(|| format!("rustls/TlsAcceptorData: pem #{index}: add client cert to root cert storage"))?;
                }
                let cert_verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_storage))
                    .build()
                    .context("rustls/TlsAcceptorData: create webpki client verifier")?;
                builder.with_client_cert_verifier(cert_verifier)
            }
        };

        let mut server_config = match value.server_auth {
            ServerAuth::SelfSigned(data) => {
                let (cert_chain, key_der) =
                    self_signed_server_auth(data).context("rustls/TlsAcceptorData")?;
                if value.expose_server_cert {
                    server_cert_chain = Some(cert_chain.clone());
                }
                builder
                    .with_single_cert(cert_chain, key_der)
                    .context("rustls/TlsAcceptorData: build base self-signed rustls ServerConfig")?
            }
            ServerAuth::Single(data) => {
                // server TLS Certs
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
                                cert.context("rustls/TlsAcceptorData: parse tls server cert")?,
                            );
                        }
                        cert_chain
                    }
                };

                if value.expose_server_cert {
                    server_cert_chain = Some(cert_chain.clone());
                }

                // server TLS key
                let key_der = match data.private_key {
                    DataEncoding::Der(raw_data) => raw_data
                        .try_into()
                        .map_err(|_| OpaqueError::from_display("invalid key data"))
                        .context("rustls/TlsAcceptorData: read private (DER) key")?,
                    DataEncoding::DerStack(raw_data_list) => {
                        let data = raw_data_list
                            .first()
                            .context("rustls/TlsAcceptorData: get first (DER) key")?
                            .clone();
                        data.try_into()
                            .map_err(|_| OpaqueError::from_display("invalid key data"))
                            .context("rustls/TlsAcceptorData: read private (DER) key")?
                    }
                    DataEncoding::Pem(raw_data) => {
                        let mut key_reader = BufReader::new(raw_data.as_bytes());
                        pemfile::private_key(&mut key_reader)
                            .context("rustls/TlsAcceptorData: read private (PEM) key")?
                            .context("rustls/TlsAcceptorData: private found (in PEM)")?
                    }
                };

                // builder with server auth configured
                match data.ocsp {
                    None => builder.with_single_cert(cert_chain, key_der),
                    Some(ocsp) => builder.with_single_cert_with_ocsp(cert_chain, key_der, ocsp),
                }
                .context("rustls/TlsAcceptorData: build base rustls ServerConfig")?
            }

            ServerAuth::CertIssuer { .. } => {
                return Err(OpaqueError::from_display("CertIssuer not supported for Rustls (open an PR with a patch to add support for it if you want this or use boring instead)"));
            }
        };

        // set key logger if one is requested
        if let Some(path) = value.key_logger.file_path() {
            let key_logger = KeyLogFile::new(path).context("rustls/TlsAcceptorData")?;
            server_config.key_log = Arc::new(key_logger);
        };

        // set ALPN for negotiation, resulting in the (default) empty Vec if none was defined
        server_config.alpn_protocols = value
            .application_layer_protocol_negotiation
            .into_iter()
            .flatten()
            .map(|p| p.as_bytes().to_vec())
            .collect();

        // return the created server config, all good if you reach here
        Ok(TlsAcceptorData {
            server_config: Arc::new(server_config),
            server_cert_chain,
        })
    }
}

fn self_signed_server_auth(
    data: SelfSignedData,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), OpaqueError> {
    // Create an issuer CA cert.
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let ca_key_pair = KeyPair::generate_for(alg).context("self-signed: generate ca key pair")?;

    let common_name = data
        .common_name
        .clone()
        .unwrap_or(Host::Name(Domain::from_static("localhost")));

    let mut ca_params =
        rcgen::CertificateParams::new(Vec::new()).context("self-signed: create ca params")?;
    ca_params.distinguished_name.push(
        rcgen::DnType::OrganizationName,
        data.organisation_name
            .unwrap_or_else(|| "Anonymous".to_owned()),
    );
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name.to_string().as_str());
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .context("self-signed: create ca cert")?;

    let server_key_pair =
        KeyPair::generate_for(alg).context("self-signed: create server key pair")?;
    let mut server_ee_params =
        rcgen::CertificateParams::new(data.subject_alternative_names.unwrap_or_default())
            .context("self-signed: create server EE params")?;
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_ee_params
        .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
        .context("self-signed: sign servert cert")?;

    let server_ca_cert_der: CertificateDer = ca_cert.into();
    let server_cert_der: CertificateDer = server_cert.into();
    let server_key_der = PrivatePkcs8KeyDer::from(server_key_pair.serialize_der());

    Ok((
        vec![server_cert_der, server_ca_cert_der],
        PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned()).into(),
    ))
}
