use rama_core::error::BoxError;
use rama_net::address::Domain;
use rama_net::tls::client::ClientHello;
use rama_net::tls::server::{DynamicCertIssuer, SelfSignedData, ServerAuthData};
use std::{num::NonZeroU64, pin::Pin, sync::Arc};

#[derive(Debug, Clone, Default)]
/// Configures on-the-fly server cert issuance + the cache used for issued certs.
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

const CACHE_KIND_DEFAULT_MAX_SIZE: NonZeroU64 =
    NonZeroU64::new(8096).expect("NonZeroU64: 8096 != 0");

impl Default for CacheKind {
    fn default() -> Self {
        Self::MemCache {
            max_size: CACHE_KIND_DEFAULT_MAX_SIZE,
            ttl: Some(std::time::Duration::from_hours(24 * 89)), // 89 days
        }
    }
}

#[derive(Debug, Clone)]
/// The way certs are issued on the fly by a [`ServerCertIssuerData`].
pub enum ServerCertIssuerKind {
    /// Generate a self-signed CA and issue per-domain leaves from it.
    SelfSigned(SelfSignedData),
    /// Use the provided cert+key as a CA and issue per-domain leaves from it.
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
    ) -> Result<ServerAuthData, BoxError> {
        self.issuer.issue_cert(client_hello, server_name).await
    }

    #[must_use]
    pub fn norm_cn(&self, domain: &Domain) -> Option<&Domain> {
        self.issuer.norm_cn(domain)
    }
}

impl std::fmt::Debug for DynamicIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicIssuer").finish()
    }
}

/// Internal trait to support dynamic dispatch of trait with async fn.
/// See trait [`rama_core::service::svc::DynService`] for more info about this pattern.
trait DynDynamicCertIssuer {
    fn issue_cert(
        &self,
        client_hello: ClientHello,
        server_name: Option<Domain>,
    ) -> Pin<Box<dyn Future<Output = Result<ServerAuthData, BoxError>> + Send + '_>>;

    fn norm_cn(&self, _domain: &Domain) -> Option<&Domain> {
        None
    }
}

impl<T> DynDynamicCertIssuer for T
where
    T: DynamicCertIssuer,
{
    fn issue_cert(
        &self,
        client_hello: ClientHello,
        server_name: Option<Domain>,
    ) -> Pin<Box<dyn Future<Output = Result<ServerAuthData, BoxError>> + Send + '_>> {
        Box::pin(self.issue_cert(client_hello, server_name))
    }

    fn norm_cn(&self, domain: &Domain) -> Option<&Domain> {
        self.norm_cn(domain)
    }
}
