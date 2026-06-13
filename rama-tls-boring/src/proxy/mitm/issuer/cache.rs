use std::{num::NonZeroU64, sync::Arc, time::Duration};

use moka::sync::Cache;
use rama_boring::x509::X509;
use rama_core::telemetry::tracing;

use super::{BoringMitmCertIssuer, MitmIssuedCert};

#[derive(Debug, Clone)]
/// A [`BoringMitmCertIssuer`] which adds an in-memory
/// caching layer over the internal [`BoringMitmCertIssuer`],
/// allowing to reuse previously issued certs.
pub struct CachedBoringMitmCertIssuer<T> {
    issuer: T,
    cache: Cache<Arc<[u8]>, MitmIssuedCert>,
}

#[derive(Debug, Clone, Copy)]
/// Config used by to create in-mem cache for [`CachedBoringMitmCertIssuer`]
pub struct BoringMitmCertIssuerCacheConfig {
    pub max_size: NonZeroU64,
    /// defaults to a default TTL (some) value if `None` is defined,
    /// same one as used for `Default::default`
    pub ttl: Option<std::time::Duration>,
}

impl Default for BoringMitmCertIssuerCacheConfig {
    fn default() -> Self {
        Self {
            max_size: CACHE_KIND_DEFAULT_MAX_SIZE,
            ttl: Some(CACHE_DEFAULT_TTL),
        }
    }
}

const CACHE_DEFAULT_TTL: Duration = Duration::from_hours(24 * 89); // 89 DAYS

const CACHE_KIND_DEFAULT_MAX_SIZE: NonZeroU64 =
    NonZeroU64::new(32_000).expect("NonZeroU64: 32_000 != 0");

impl<T> CachedBoringMitmCertIssuer<T> {
    #[inline(always)]
    /// Create a new [`CachedBoringMitmCertIssuer`].
    #[must_use]
    pub fn new(issuer: T) -> Self {
        Self::new_with_config(issuer, BoringMitmCertIssuerCacheConfig::default())
    }

    #[inline(always)]
    /// Create a new [`CachedBoringMitmCertIssuer`] with the given config.
    #[must_use]
    pub fn new_with_config(issuer: T, cfg: BoringMitmCertIssuerCacheConfig) -> Self {
        Self {
            issuer,
            cache: Cache::builder()
                .time_to_live(match cfg.ttl {
                    None | Some(Duration::ZERO) => CACHE_DEFAULT_TTL,
                    Some(custom) => custom,
                })
                .max_capacity(cfg.max_size.into())
                .build(),
        }
    }
}

impl<T: BoringMitmCertIssuer> BoringMitmCertIssuer for CachedBoringMitmCertIssuer<T> {
    type Error = T::Error;

    #[inline(always)]
    async fn issue_mitm_x509_cert(&self, original: X509) -> Result<MitmIssuedCert, Self::Error> {
        let signature = original.signature().as_slice();

        if let Some(issued) = self.cache.get(signature) {
            tracing::debug!(
                "reuse cached x509 cert pair for MITM boring crt issuer (signature: 0x{signature:x?}"
            );
            return Ok(issued);
        }

        let signature = Arc::from(signature);
        let issued = self.issuer.issue_mitm_x509_cert(original).await?;

        tracing::debug!(
            "cached newly issued x509 cert pair for MITM boring crt issuer (signature: 0x{signature:x?}; return copy"
        );

        self.cache.insert(signature, issued.clone());

        Ok(issued)
    }
}
