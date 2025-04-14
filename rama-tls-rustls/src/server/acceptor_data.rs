use crate::dep::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use crate::dep::rcgen::{self, KeyPair};
use crate::dep::rustls::ServerConfig;
use crate::key_log::KeyLogFile;
use rama_core::error::{ErrorContext, OpaqueError};
use rama_net::address::{Domain, Host};
use rama_net::tls::server::SelfSignedData;
use rama_net::tls::{ApplicationProtocol, KeyLogIntent};
use rustls::ALL_VERSIONS;
use std::sync::Arc;

#[derive(Debug, Clone)]
/// Internal data used as configuration/input for the [`super::TlsAcceptorService`].
///
/// Created by converting a [`rustls::ServerConfig`] into it directly,
/// or by using [`TlsAcceptorDataBuilder`] to create this in a more ergonomic way.
pub struct TlsAcceptorData {
    pub(super) server_config: Arc<ServerConfig>,
}

impl From<ServerConfig> for TlsAcceptorData {
    #[inline]
    fn from(value: ServerConfig) -> Self {
        Arc::new(value).into()
    }
}

impl From<Arc<ServerConfig>> for TlsAcceptorData {
    fn from(value: Arc<ServerConfig>) -> Self {
        Self {
            server_config: value,
        }
    }
}

/// [`TlsAcceptorDataBuilder`] can be used to construct [`rustls::ServerConfig`] for most common use cases in Rama.
///
/// If this doesn't work for your use case, no problem [`TlsConnectorData`] can be created from a raw [`rustls::ServerConfig`]
pub struct TlsAcceptorDataBuilder {
    server_config: ServerConfig,
}

impl From<ServerConfig> for TlsAcceptorDataBuilder {
    fn from(value: ServerConfig) -> Self {
        Self {
            server_config: value,
        }
    }
}

impl TlsAcceptorDataBuilder {
    /// Create a [`TlsAcceptorDataBuilder`] support all tls versions, using no client auth, and the
    /// provided certificate chain and private key for the server
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Self, OpaqueError> {
        let config = ServerConfig::builder_with_protocol_versions(ALL_VERSIONS)
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .context("new tls acceptor builder with single cert")?;

        Ok(Self {
            server_config: config,
        })
    }

    /// Create a [`TlsAcceptorDataBuilder`] support all tls versions, using no client auth, and a self
    /// generated certificate chain and private key
    pub fn new_self_signed(data: SelfSignedData) -> Result<Self, OpaqueError> {
        let (cert_chain, key_der) = self_signed_server_auth(data)?;
        let config = ServerConfig::builder_with_protocol_versions(ALL_VERSIONS)
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .context("new tls acceptor builder with self signed data")?;

        Ok(Self {
            server_config: config,
        })
    }

    /// If [`KeyLogIntent::Environment`] is set to a path, create a key logger that will write to that path
    /// and set it in the current config
    pub fn set_env_key_logger(&mut self) -> Result<&mut Self, OpaqueError> {
        if let Some(path) = KeyLogIntent::Environment.file_path() {
            let key_logger = Arc::new(KeyLogFile::new(path)?);
            self.server_config.key_log = key_logger;
        };
        Ok(self)
    }

    /// Same as [`Self::set_env_key_logger`] but consuming self
    pub fn with_env_key_logger(mut self) -> Result<Self, OpaqueError> {
        self.set_env_key_logger()?;
        Ok(self)
    }

    /// Set [`ApplicationProtocol`]s supported in alpn extension
    pub fn set_alpn_protocols(&mut self, protos: &[ApplicationProtocol]) -> &mut Self {
        self.server_config.alpn_protocols = protos
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect();

        self
    }

    /// Same as [`Self::set_alpn_protocols`] but consuming self
    pub fn with_alpn_protocols(mut self, protos: &[ApplicationProtocol]) -> Self {
        self.set_alpn_protocols(protos);
        self
    }

    /// Build [`TlsAcceptorData`] from the current config
    pub fn build(self) -> TlsAcceptorData {
        TlsAcceptorData {
            server_config: Arc::new(self.server_config),
        }
    }
}

pub fn self_signed_server_auth(
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
