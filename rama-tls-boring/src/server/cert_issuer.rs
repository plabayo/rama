use crate::core::{
    pkey::{PKey, Private},
    ssl::SslCredential,
    x509::X509,
};
use moka::future::Cache;
use parking_lot::Mutex;
use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    telemetry::tracing,
};
use rama_crypto::ocsp::ocsp_response_next_update;
use rama_net::address::Domain;
use rama_tls::server::{
    CertificateAuthorityData, CertificateIdentity, CertificateIssuanceContext, DynamicCertIssuer,
    LeafCertConfig, SelfSignedCaConfig,
};
use rama_utils::time::unix_timestamp_secs;
use std::{fmt, num::NonZeroU64, ops::Range, pin::Pin, sync::Arc, time::UNIX_EPOCH};

/// Configures on-the-fly server certificate issuance and caching.
///
/// Clones share generated CA material and cached certificates. Changing the
/// issuer kind or cache kind starts a new runtime, while changing only the
/// fallback identity retains it. Use [`ServerCertIssuerData::new`] when an
/// independent runtime is required.
#[derive(Debug, Clone)]
pub struct ServerCertIssuerData {
    kind: ServerCertIssuerKind,
    cache_kind: CacheKind,
    fallback_identity: Option<CertificateIdentity>,
    runtime: Arc<ServerCertIssuerRuntime>,
}

impl ServerCertIssuerData {
    /// Create an issuer configuration with the default in-memory cache.
    pub fn new(kind: impl Into<ServerCertIssuerKind>) -> Self {
        let cache_kind = CacheKind::default();
        Self {
            kind: kind.into(),
            runtime: Arc::new(ServerCertIssuerRuntime::new(&cache_kind)),
            cache_kind,
            fallback_identity: Some(CertificateIdentity::Dns(Domain::from_static("localhost"))),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &ServerCertIssuerKind {
        &self.kind
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the kind of server certificate issuer.
        pub fn kind(mut self, kind: impl Into<ServerCertIssuerKind>) -> Self {
            self.kind = kind.into();
            self.reset_runtime();
            self
        }
    }

    #[must_use]
    pub const fn cache_kind(&self) -> &CacheKind {
        &self.cache_kind
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the cache used for issued certificates.
        pub fn cache_kind(mut self, cache_kind: CacheKind) -> Self {
            self.cache_kind = cache_kind;
            self.reset_runtime();
            self
        }
    }

    #[must_use]
    pub const fn fallback_identity(&self) -> Option<&CertificateIdentity> {
        self.fallback_identity.as_ref()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the identity used when no SNI or target identity is available.
        ///
        /// The default is the DNS identity `localhost`, matching the conventional
        /// default-certificate behavior of TLS servers. Use
        /// [`Self::without_fallback_identity`] to reject handshakes that provide
        /// neither SNI nor a target identity.
        pub fn fallback_identity(
            mut self,
            fallback_identity: Option<CertificateIdentity>,
        ) -> Self {
            self.fallback_identity = fallback_identity;
            self
        }
    }

    pub(super) fn cache(&self) -> Option<Cache<CertificateIdentity, IssuedCert>> {
        self.runtime.cert_cache.clone()
    }

    pub(super) fn ca_material(
        &self,
        init: impl FnOnce() -> Result<CaMaterial, BoxError>,
    ) -> Result<CaMaterial, BoxError> {
        let mut material = self.runtime.ca_material.lock();
        if material.is_none() {
            *material = Some(init()?);
        }
        material.as_ref().cloned().ok_or_else(|| {
            BoxError::from_static_str("certificate authority material failed to initialize")
        })
    }

    pub(super) fn ca_material_is_initialized(&self) -> bool {
        self.runtime.ca_material.lock().is_some()
    }

    fn reset_runtime(&mut self) {
        self.runtime = Arc::new(ServerCertIssuerRuntime::new(&self.cache_kind));
    }
}

impl Default for ServerCertIssuerData {
    fn default() -> Self {
        Self::new(ServerCertIssuerKind::default())
    }
}

/// Cache kind that will be used to cache results of certificate issuers
#[derive(Debug, Clone)]
pub enum CacheKind {
    /// An in-memory cache bounded by entry count and optionally by time.
    MemCache {
        /// Maximum number of cached certificate identities.
        max_size: NonZeroU64,
        /// Entry lifetime. `None` has no time limit; zero disables reuse.
        ttl: Option<std::time::Duration>,
    },
    /// Do not cache issued certificates.
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

#[derive(Debug)]
struct ServerCertIssuerRuntime {
    cert_cache: Option<Cache<CertificateIdentity, IssuedCert>>,
    ca_material: Mutex<Option<CaMaterial>>,
}

impl ServerCertIssuerRuntime {
    fn new(cache_kind: &CacheKind) -> Self {
        let cert_cache = match cache_kind {
            CacheKind::Disabled => None,
            CacheKind::MemCache { max_size, ttl } => {
                let builder = Cache::builder().max_capacity(max_size.get());
                let builder = match ttl {
                    Some(ttl) => builder.time_to_live(*ttl),
                    None => builder,
                };
                Some(builder.build())
            }
        };
        Self {
            cert_cache,
            ca_material: Mutex::new(None),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct CaMaterial {
    pub(super) key: PKey<Private>,
    pub(super) chain: Vec<X509>,
}

#[derive(Clone)]
pub(super) struct IssuedCert {
    /// Chain, key and stapled OCSP response, built once and shared by every handshake.
    pub(super) credential: SslCredential,
    validity: Range<i64>,
}

impl fmt::Debug for IssuedCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCert")
            .field("validity", &self.validity)
            .finish_non_exhaustive()
    }
}

impl IssuedCert {
    pub(super) fn try_new(cert_chain: &[X509], key: &PKey<Private>) -> Result<Self, BoxError> {
        Self::try_new_with_ocsp(cert_chain, key, None)
    }

    pub(super) fn try_new_with_ocsp(
        cert_chain: &[X509],
        key: &PKey<Private>,
        ocsp_response: Option<&[u8]>,
    ) -> Result<Self, BoxError> {
        let leaf = cert_chain
            .first()
            .context("issued certificate chain cannot be empty")?;
        let der = leaf.to_der().map_err(|err| {
            err.into_box_error()
                .context("serialize issued leaf validity")
        })?;
        let (_, certificate) = rama_crypto::dep::x509_parser::parse_x509_certificate(&der)
            .context("parse issued leaf validity")?;
        let validity = certificate.validity();

        let mut validity = validity.not_before.timestamp()..validity.not_after.timestamp();

        let mut credential = SslCredential::builder().context("create server credential")?;
        credential
            .set_certificate_chain(cert_chain)
            .context("set server credential certificate chain")?;
        // Fails when the key does not match the leaf configured above.
        credential
            .set_private_key(key)
            .context("set server credential private key")?;
        if let Some(response) = ocsp_response {
            credential
                .set_ocsp_response(response)
                .context("set server credential OCSP response")?;
            // A cached issuance must not outlive its staple, so it gets reissued instead.
            match ocsp_response_next_update(response) {
                Ok(Some(next_update)) => {
                    let next_update = next_update
                        .duration_since(UNIX_EPOCH)
                        .ok()
                        .and_then(|since| i64::try_from(since.as_secs()).ok())
                        .unwrap_or_default();
                    validity.end = validity.end.min(next_update);
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::debug!(%err, "staple OCSP response without a readable nextUpdate");
                }
            }
        }
        Ok(Self {
            credential: credential.build(),
            validity,
        })
    }

    pub(super) fn is_valid(&self) -> bool {
        let now = unix_timestamp_secs();
        self.is_valid_at_unix(now)
    }

    fn is_valid_at_unix(&self, now: i64) -> bool {
        self.validity.start <= now && now < self.validity.end
    }
}

/// The way certs are issued on the fly by a [`ServerCertIssuerData`].
#[derive(Debug, Clone)]
pub enum ServerCertIssuerKind {
    /// Generate a self-signed CA and issue per-identity leaves from it.
    ///
    /// CA key generation runs synchronously on first use. Prefer
    /// [`ServerCertIssuerKind::ProvidedCa`] with pre-generated material when
    /// cold-start latency matters, especially for RSA keys.
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

#[cfg(test)]
mod tests {
    use super::*;
    use rama_crypto::ocsp::{
        OcspCertId, OcspCertStatus, OcspSignatureAlgorithm, build_ocsp_response,
        sha1_hash_algorithm_der,
    };
    use rama_tls::server::{CertificateKeyKind, LeafCertRequest};
    use std::assert_matches;
    use std::time::{Duration, SystemTime};

    struct NormalizingIssuer;

    impl DynamicCertIssuer for NormalizingIssuer {
        async fn issue_cert(
            &self,
            _context: CertificateIssuanceContext,
        ) -> Result<rama_tls::server::ServerAuthData, BoxError> {
            panic!("not used by this test")
        }

        fn normalize_identity(
            &self,
            _identity: &CertificateIdentity,
        ) -> Option<CertificateIdentity> {
            Some(CertificateIdentity::Ip(
                std::net::Ipv4Addr::LOCALHOST.into(),
            ))
        }
    }

    #[test]
    fn clones_share_runtime_until_runtime_configuration_changes() {
        let original = ServerCertIssuerData::default();
        let clone = original.clone();
        assert!(Arc::ptr_eq(&original.runtime, &clone.runtime));
        assert_matches!(original.kind(), ServerCertIssuerKind::GeneratedCa { .. });
        assert_matches!(original.cache_kind(), CacheKind::MemCache { .. });
        assert_eq!(
            original.fallback_identity(),
            Some(&CertificateIdentity::Dns(Domain::from_static("localhost")))
        );

        let identity =
            CertificateIdentity::Dns(rama_net::address::Domain::from_static("fallback.example"));
        let with_fallback = original.clone().with_fallback_identity(identity.clone());
        assert_eq!(with_fallback.fallback_identity(), Some(&identity));
        assert!(Arc::ptr_eq(&original.runtime, &with_fallback.runtime));

        let without_cache = original.clone().with_cache_kind(CacheKind::Disabled);
        assert_matches!(without_cache.cache_kind(), CacheKind::Disabled);
        assert!(without_cache.cache().is_none());
        assert!(!Arc::ptr_eq(&original.runtime, &without_cache.runtime));

        let with_new_kind = original
            .clone()
            .with_kind(ServerCertIssuerKind::GeneratedCa {
                ca: SelfSignedCaConfig {
                    key_kind: CertificateKeyKind::Rsa2048,
                    ..Default::default()
                },
                leaf: LeafCertConfig::default(),
            });
        assert_matches!(
            with_new_kind.kind(),
            ServerCertIssuerKind::GeneratedCa {
                ca: SelfSignedCaConfig {
                    key_kind: CertificateKeyKind::Rsa2048,
                    ..
                },
                ..
            },
        );
        assert!(!Arc::ptr_eq(&original.runtime, &with_new_kind.runtime));
    }

    #[tokio::test]
    async fn cache_ttl_distinguishes_unbounded_immediate_and_expiring_entries() {
        let max_size = NonZeroU64::new(8).expect("non-zero cache size");
        let unbounded = ServerCertIssuerRuntime::new(&CacheKind::MemCache {
            max_size,
            ttl: None,
        })
        .cert_cache
        .expect("unbounded cache");
        assert_eq!(unbounded.policy().time_to_live(), None);

        let (ca_cert, ca_key) = rama_crypto::cert::boring::generate_certificate_authority_x509(
            &SelfSignedCaConfig::default(),
        )
        .expect("generate CA");
        let (cert, key) = rama_crypto::cert::boring::issue_leaf_certificate(
            &LeafCertRequest::default(),
            &ca_cert,
            &ca_key,
        )
        .expect("issue leaf");
        let issued = IssuedCert::try_new(&[cert], &key).expect("issued certificate");
        let identity = CertificateIdentity::Ip(std::net::Ipv4Addr::LOCALHOST.into());

        let immediate = ServerCertIssuerRuntime::new(&CacheKind::MemCache {
            max_size,
            ttl: Some(Duration::ZERO),
        })
        .cert_cache
        .expect("immediate-expiry cache");
        assert_eq!(immediate.policy().time_to_live(), Some(Duration::ZERO));
        immediate.insert(identity.clone(), issued.clone()).await;
        assert!(immediate.get(&identity).await.is_none());

        let ttl = Duration::from_millis(200);
        let expiring = ServerCertIssuerRuntime::new(&CacheKind::MemCache {
            max_size,
            ttl: Some(ttl),
        })
        .cert_cache
        .expect("expiring cache");
        assert_eq!(expiring.policy().time_to_live(), Some(ttl));
        expiring.insert(identity.clone(), issued).await;
        assert!(expiring.get(&identity).await.is_some());
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(expiring.get(&identity).await.is_none());
    }

    #[test]
    fn issued_certificate_validity_includes_start_and_excludes_end() {
        let (ca_cert, ca_key) = rama_crypto::cert::boring::generate_certificate_authority_x509(
            &SelfSignedCaConfig::default(),
        )
        .expect("generate CA");
        let (cert, key) = rama_crypto::cert::boring::issue_leaf_certificate(
            &LeafCertRequest::default(),
            &ca_cert,
            &ca_key,
        )
        .expect("issue leaf");
        let chain = [cert];
        let issued = IssuedCert::try_new(&chain, &key).expect("issued certificate");

        assert!(issued.is_valid());
        assert!(issued.is_valid_at_unix(issued.validity.start));
        assert!(!issued.is_valid_at_unix(issued.validity.end));
        IssuedCert::try_new(&[], &key).unwrap_err();
        // The key must belong to the leaf certificate.
        IssuedCert::try_new(&chain, &ca_key).unwrap_err();
    }

    #[test]
    fn a_stapled_ocsp_response_bounds_the_cached_validity() {
        let (ca_cert, ca_key) = rama_crypto::cert::boring::generate_certificate_authority_x509(
            &SelfSignedCaConfig::default(),
        )
        .expect("generate CA");
        let (cert, key) = rama_crypto::cert::boring::issue_leaf_certificate(
            &LeafCertRequest::default(),
            &ca_cert,
            &ca_key,
        )
        .expect("issue leaf");
        let chain = [cert];
        let produced_at = SystemTime::now();
        let staple = build_ocsp_response(
            &OcspCertId {
                issuer_name_der: &[0x30, 0x00],
                hash_algorithm_der: &sha1_hash_algorithm_der(),
                issuer_name_hash: &[0; 20],
                issuer_key_hash: &[0; 20],
                serial: &[1],
            },
            OcspCertStatus::Good,
            produced_at,
            Duration::from_hours(1),
            None,
            |_| Ok((OcspSignatureAlgorithm::EcdsaSha256, vec![0])),
        )
        .expect("build OCSP response");

        let unstapled = IssuedCert::try_new(&chain, &key).expect("issued certificate");
        let stapled = IssuedCert::try_new_with_ocsp(&chain, &key, Some(&staple))
            .expect("stapled certificate");
        let next_update = i64::try_from(
            (produced_at + Duration::from_hours(1))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        assert_eq!(stapled.validity.end, next_update);
        assert!(stapled.validity.end < unstapled.validity.end);
        assert!(stapled.is_valid());
        // An unreadable staple is still stapled, bounded by the certificate alone.
        let opaque =
            IssuedCert::try_new_with_ocsp(&chain, &key, Some(b"opaque")).expect("opaque staple");
        assert_eq!(opaque.validity, unstapled.validity);
    }

    #[test]
    fn dynamic_issuer_forwards_identity_normalization() {
        let issuer = DynamicIssuer::new(NormalizingIssuer);
        let identity =
            CertificateIdentity::Dns(rama_net::address::Domain::from_static("www.example.com"));
        assert_eq!(
            issuer.normalize_identity(&identity),
            Some(CertificateIdentity::Ip(
                std::net::Ipv4Addr::LOCALHOST.into()
            ))
        );
    }
}
