use crate::{
    address::Domain,
    tls::{ApplicationProtocol, DataEncoding, KeyLogIntent, ProtocolVersion, client::ClientHello},
};
use rama_core::error::OpaqueError;
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU64, pin::Pin, sync::Arc};

#[derive(Debug, Clone)]
/// Common API to configure a TLS Server
pub struct ServerConfig {
    /// required raw (PEM-encoded) server auth certs
    pub server_auth: ServerAuth,

    /// optionally provide the option expose the server cert if one is defined
    ///
    /// this will effectively clone the memory to keep these at hand,
    /// so only enable this option if you need it for something specific
    pub expose_server_cert: bool,

    /// optional supported versions by the server
    pub protocol_versions: Option<Vec<ProtocolVersion>>,

    /// optional ALPNs used for protocol negotiation with the client
    pub application_layer_protocol_negotiation: Option<Vec<ApplicationProtocol>>,

    /// optionally define how client should be verified by server
    pub client_verify_mode: ClientVerifyMode,

    /// key log intent
    pub key_logger: KeyLogIntent,

    /// store client certificate chain
    pub store_client_certificate_chain: bool,
}

impl ServerConfig {
    /// Create a new [`ServerConfig`] using the given [`ServerAuth`].
    #[must_use]
    pub fn new(auth: ServerAuth) -> Self {
        Self {
            server_auth: auth,
            expose_server_cert: false,
            protocol_versions: None,
            application_layer_protocol_negotiation: None,
            client_verify_mode: ClientVerifyMode::default(),
            key_logger: KeyLogIntent::default(),
            store_client_certificate_chain: false,
        }
    }
}

#[derive(Debug, Clone)]
/// The kind of server auth to be used.
pub enum ServerAuth {
    /// Request the tls implementation to generate self-signed single data
    SelfSigned(SelfSignedData),
    /// Single data provided by the configurator
    Single(ServerAuthData),
    /// Issuer which provides certs on the fly
    CertIssuer(ServerCertIssuerData),
}

impl Default for ServerAuth {
    fn default() -> Self {
        Self::SelfSigned(SelfSignedData::default())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServerCertIssuerData {
    /// The kind of server cert issuer
    pub kind: ServerCertIssuerKind,
    /// Cache kind that will be used to cache certificates
    pub cache_kind: CacheKind,
}

#[derive(Debug, Clone)]
/// Cache kind that will be used to cache results of certificate issuers
pub enum CacheKind {
    MemCache {
        max_size: NonZeroU64,
        ttl: Option<std::time::Duration>,
    },
    Disabled,
}

impl Default for CacheKind {
    fn default() -> Self {
        Self::MemCache {
            max_size: NonZeroU64::new(8096).unwrap(),
            ttl: None,
        }
    }
}

#[derive(Debug, Clone)]
/// A type of [`ServerAuth`] which can be used to generate
/// server certs on the fly using the given issuer
pub enum ServerCertIssuerKind {
    /// Request the tls implementation to generate self-signed single data
    SelfSigned(SelfSignedData),
    /// Single data provided by the configurator
    Single(ServerAuthData),
    /// A dynamic data provider which can decide depending on client hello msg
    Dynamic(DynamicIssuer),
}

impl Default for ServerCertIssuerKind {
    fn default() -> Self {
        Self::SelfSigned(SelfSignedData::default())
    }
}

impl<T> From<T> for ServerCertIssuerKind
where
    T: DynamicCertIssuer,
{
    fn from(issuer: T) -> Self {
        Self::Dynamic(DynamicIssuer::new(issuer))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// Data that can be used to configure the self-signed single data
pub struct SelfSignedData {
    /// name of the organisation
    pub organisation_name: Option<String>,
    /// common name (CN): server name protected by the SSL certificate
    pub common_name: Option<Domain>,
    /// Subject Alternative Names (SAN) can be defined
    /// to create a cert which allows multiple hostnames or domains to be secured under one certificate.
    pub subject_alternative_names: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
/// Raw private key and certificate data to facilitate server authentication.
pub struct ServerAuthData {
    /// private key used by server
    pub private_key: DataEncoding,
    /// certificate chain as a companion to the private key
    pub cert_chain: DataEncoding,

    /// `ocsp` is a DER-encoded OCSP response
    pub ocsp: Option<Vec<u8>>,
}

#[derive(Clone)]
/// Dynamic issuer which internally contains the dyn issuer
pub struct DynamicIssuer {
    /// Issuer not public in case we want to migrate away from dyn approach to alternative (eg channels)
    issuer: Arc<dyn DynDynamicCertIssuer + Send + Sync>,
}

impl DynamicIssuer {
    pub fn new<T: DynamicCertIssuer>(issuer: T) -> Self {
        Self {
            issuer: Arc::new(issuer),
        }
    }

    pub async fn issue_cert(
        &self,
        client_hello: ClientHello,
        server_name: Option<Domain>,
    ) -> Result<ServerAuthData, OpaqueError> {
        self.issuer.issue_cert(client_hello, server_name).await
    }
}

impl std::fmt::Debug for DynamicIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicIssuer").finish()
    }
}

/// Trait that needs to be implemented by cert issuers to support dynamically
/// issueing (external) certs based on client_hello input.
pub trait DynamicCertIssuer: Send + Sync + 'static {
    fn issue_cert(
        &self,
        client_hello: ClientHello,
        server_name: Option<Domain>,
    ) -> impl Future<Output = Result<ServerAuthData, OpaqueError>> + Send + Sync + '_;
}

/// Internal trait to support dynamic dispatch of trait with async fn.
/// See trait [`rama_core::service::svc::DynService`] for more info about this pattern.
trait DynDynamicCertIssuer {
    fn issue_cert(
        &self,
        client_hello: ClientHello,
        server_name: Option<Domain>,
    ) -> Pin<Box<dyn Future<Output = Result<ServerAuthData, OpaqueError>> + Send + Sync + '_>>;
}

impl<T> DynDynamicCertIssuer for T
where
    T: DynamicCertIssuer,
{
    fn issue_cert(
        &self,
        client_hello: ClientHello,
        server_name: Option<Domain>,
    ) -> Pin<Box<dyn Future<Output = Result<ServerAuthData, OpaqueError>> + Send + Sync + '_>> {
        Box::pin(self.issue_cert(client_hello, server_name))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Mode of client verification by a (tls) server
pub enum ClientVerifyMode {
    #[default]
    /// Use the default verification approach as defined
    /// by the implementation of the used (tls) server
    Auto,
    /// Explicitly disable client verification (if possible)
    Disable,
    /// PEM-encoded certificate chain containing the acceptable client certificates
    ClientAuth(DataEncoding),
}
