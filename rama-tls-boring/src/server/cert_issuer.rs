use rama_core::error::BoxError;
use rama_tls::server::{
    CertificateAuthorityData, CertificateIdentity, CertificateIssuanceContext, DynamicCertIssuer,
    LeafCertConfig, SelfSignedCaConfig,
};
use std::{num::NonZeroU64, pin::Pin, sync::Arc};

#[derive(Debug, Clone, Default)]
/// Configures on-the-fly server cert issuance + the cache used for issued certs.
pub struct ServerCertIssuerData {
    /// The kind of server cert issuer
    pub kind: ServerCertIssuerKind,
    /// Cache kind that will be used to cache certificates
    pub cache_kind: CacheKind,
    /// Identity used when neither ClientHello SNI nor a target authority is available.
    pub fallback_identity: Option<CertificateIdentity>,
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
            ttl: None,
        }
    }
}

#[derive(Debug, Clone)]
/// The way certs are issued on the fly by a [`ServerCertIssuerData`].
pub enum ServerCertIssuerKind {
    /// Generate a self-signed CA and issue per-identity leaves from it.
    GeneratedCa {
        ca: SelfSignedCaConfig,
        leaf: LeafCertConfig,
    },
    /// Use the provided cert+key as a CA and issue per-identity leaves from it.
    ProvidedCa {
        ca: CertificateAuthorityData,
        leaf: LeafCertConfig,
    },
    /// A dynamic data provider which can decide depending on client hello msg
    Dynamic(DynamicIssuer),
}

impl Default for ServerCertIssuerKind {
    fn default() -> Self {
        Self::GeneratedCa {
            ca: SelfSignedCaConfig::default(),
            leaf: LeafCertConfig::default(),
        }
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
        context: CertificateIssuanceContext,
    ) -> Result<rama_tls::server::ServerAuthData, BoxError> {
        self.issuer.issue_cert(context).await
    }

    #[must_use]
    pub fn normalize_identity(
        &self,
        identity: &CertificateIdentity,
    ) -> Option<CertificateIdentity> {
        self.issuer.normalize_identity(identity)
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
        context: CertificateIssuanceContext,
    ) -> Pin<Box<dyn Future<Output = Result<rama_tls::server::ServerAuthData, BoxError>> + Send + '_>>;

    fn normalize_identity(&self, _identity: &CertificateIdentity) -> Option<CertificateIdentity> {
        None
    }
}

impl<T> DynDynamicCertIssuer for T
where
    T: DynamicCertIssuer,
{
    fn issue_cert(
        &self,
        context: CertificateIssuanceContext,
    ) -> Pin<Box<dyn Future<Output = Result<rama_tls::server::ServerAuthData, BoxError>> + Send + '_>>
    {
        Box::pin(DynamicCertIssuer::issue_cert(self, context))
    }

    fn normalize_identity(&self, identity: &CertificateIdentity) -> Option<CertificateIdentity> {
        DynamicCertIssuer::normalize_identity(self, identity)
    }
}
