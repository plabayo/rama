use crate::dep::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use crate::dep::rcgen::{self, Issuer, KeyPair};
use crate::dep::rustls::{self, ALL_VERSIONS};
use crate::key_log::KeyLogFile;
use rama_core::error::{BoxError, ErrorContext};
use rama_net::address::Domain;
use rama_net::tls::server::SelfSignedData;
use rama_net::tls::{ApplicationProtocol, KeyLogIntent};
use std::pin::Pin;
use std::sync::Arc;

#[derive(Clone, Debug)]
/// Internal data used as configuration/input for the [`super::TlsAcceptorService`].
///
/// Created by converting a [`rustls::ServerConfig`] into it directly,
/// or by using [`TlsAcceptorDataBuilder`] to create this in a more ergonomic way.
pub struct TlsAcceptorData {
    pub(super) server_config: ServerConfig,
}

#[derive(Clone)]
/// [`ServerConfig`] used to configure rustls
///
/// This can either be a directly stored [`rustls::ServerConfig`], or a [`rustls::ServerConfig`]
/// returned by a [`DynamicConfigProvider`] based on the received client hello
pub(super) enum ServerConfig {
    Stored(Arc<rustls::ServerConfig>),
    Async(Arc<dyn DynDynamicConfigProvider + Send + Sync>),
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stored(arg0) => f.debug_tuple("Stored").field(arg0).finish(),
            Self::Async(_) => f
                .debug_tuple("Async")
                .field(&"dynamic config provider")
                .finish(),
        }
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
            server_config: ServerConfig::Stored(value),
        }
    }
}

impl<D: DynamicConfigProvider> From<D> for TlsAcceptorData {
    fn from(value: D) -> Self {
        Arc::new(value).into()
    }
}

impl<D: DynamicConfigProvider> From<Arc<D>> for TlsAcceptorData {
    fn from(value: Arc<D>) -> Self {
        Self {
            server_config: ServerConfig::Async(value),
        }
    }
}

pub trait DynamicConfigProvider: Send + Sync + 'static {
    fn get_config(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> impl Future<Output = Result<Arc<rustls::ServerConfig>, BoxError>> + Send;
}

/// Internal trait to support dynamic dispatch of trait with async fn.
/// See trait [`rama_core::service::svc::DynService`] for more info about this pattern.
pub(super) trait DynDynamicConfigProvider {
    fn get_config<'a, 'b: 'a>(
        &'a self,
        client_hello: rustls::server::ClientHello<'b>,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<rustls::ServerConfig>, BoxError>> + Send + 'a>>;
}

impl<T> DynDynamicConfigProvider for T
where
    T: DynamicConfigProvider,
{
    fn get_config<'a, 'b: 'a>(
        &'a self,
        client_hello: rustls::server::ClientHello<'b>,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<rustls::ServerConfig>, BoxError>> + Send + 'a>>
    {
        Box::pin(self.get_config(client_hello))
    }
}

/// [`TlsAcceptorDataBuilder`] can be used to construct [`rustls::ServerConfig`] for most common use cases in Rama.
///
/// If this doesn't work for your use case, no problem,
/// You can also use a [`rustls::ServerConfig`].
pub struct TlsAcceptorDataBuilder {
    server_config: rustls::ServerConfig,
}

impl From<rustls::ServerConfig> for TlsAcceptorDataBuilder {
    fn from(value: rustls::ServerConfig) -> Self {
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
    ) -> Result<Self, BoxError> {
        let config = rustls::ServerConfig::builder_with_protocol_versions(ALL_VERSIONS)
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .context("new tls acceptor builder with single cert")?;

        Ok(Self {
            server_config: config,
        })
    }

    /// Create a [`TlsAcceptorDataBuilder`] support all tls versions, using no client auth, and a self
    /// generated certificate chain and private key
    pub fn try_new_self_signed(data: SelfSignedData) -> Result<Self, BoxError> {
        let (cert_chain, key_der) = self_signed_server_auth(data)?;
        let config = rustls::ServerConfig::builder_with_protocol_versions(ALL_VERSIONS)
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .context("new tls acceptor builder with self signed data")?;

        Ok(Self {
            server_config: config,
        })
    }

    rama_utils::macros::generate_set_and_with! {
        /// If [`KeyLogIntent::Environment`] is set to a path, create a key logger that will write to that path
        /// and set it in the current config
        pub fn env_key_logger(mut self) -> Result<Self, BoxError> {
            if let Some(path) = KeyLogIntent::Environment.file_path().as_deref() {
                let key_logger = Arc::new(KeyLogFile::try_new(path)?);
                self.server_config.key_log = key_logger;
            };
            Ok(self)
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set [`ApplicationProtocol`]s supported in alpn extension
        pub fn alpn_protocols(mut self, protos: &[ApplicationProtocol]) -> Self {
            self.server_config.alpn_protocols = protos
                .iter()
                .map(|proto| proto.as_bytes().to_vec())
                .collect();

            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set alpn protocols to most commonly used http protocols:
        /// [`ApplicationProtocol::HTTP_2`], [`ApplicationProtocol::HTTP_11`]
        pub fn alpn_protocols_http_auto(mut self) -> Self {
            self.set_alpn_protocols(&[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]);
            self
        }
    }

    /// Build [`TlsAcceptorData`] from the current config
    #[must_use]
    pub fn build(self) -> TlsAcceptorData {
        self.server_config.into()
    }

    /// Convert current config into a rustls config.
    ///
    /// Useful if you want to use some utilities this builder provides and
    /// then continue on directly with a native rustls config
    #[must_use]
    pub fn into_rustls_config(self) -> rustls::ServerConfig {
        self.server_config
    }
}

pub fn self_signed_server_auth(
    data: SelfSignedData,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    // Create an issuer CA cert.
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let ca_key_pair = KeyPair::generate_for(alg).context("self-signed: generate ca key pair")?;

    let common_name = data
        .common_name
        .clone()
        .unwrap_or(Domain::from_static("localhost"));

    let mut ca_params =
        rcgen::CertificateParams::new(Vec::new()).context("self-signed: create ca params")?;
    ca_params.distinguished_name.push(
        rcgen::DnType::OrganizationName,
        data.organisation_name
            .unwrap_or_else(|| "Anonymous".to_owned()),
    );
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name.as_str());
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
        .signed_by(&server_key_pair, &Issuer::new(ca_params, ca_key_pair))
        .context("self-signed: sign servert cert")?;

    let server_ca_cert_der: CertificateDer = ca_cert.into();
    let server_cert_der: CertificateDer = server_cert.into();
    let server_key_der = PrivatePkcs8KeyDer::from(server_key_pair.serialize_der());

    Ok((
        vec![server_cert_der, server_ca_cert_der],
        PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned()).into(),
    ))
}
