use rama_core::{
    error::BoxError,
    extensions::{Extension, Extensions},
};
use rama_tls::client::TlsServerTrust;
#[cfg(feature = "boring")]
use rama_tls_boring::client::BoringTlsConnectorConfig;
#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
use rama_tls_rustls::client::RustlsTlsConnectorConfig;
use std::fmt;
#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
use {
    rama_core::combinators::Either, rama_crypto::platform_verifier::PlatformVerifier,
    rama_net::client::pool::ReuseKey, std::sync::Arc,
};

use super::QuicClientConfigProvider;

/// Native trust used both to classify the cached QUIC configuration and to build it.
#[derive(Clone, Extension)]
#[extension(tags(tls))]
pub(crate) enum ServerVerification {
    #[cfg(feature = "boring")]
    Boring(Either<Arc<rama_tls_boring::core::x509::store::X509Store>, Arc<PlatformVerifier>>),
    #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    Rustls(Either<Arc<rama_tls_rustls::dep::rustls::RootCertStore>, Arc<PlatformVerifier>>),
}

impl fmt::Debug for ServerVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerVerification").finish_non_exhaustive()
    }
}

impl PartialEq for ServerVerification {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for ServerVerification {}

enum Backend {
    #[cfg(feature = "boring")]
    Boring,
    #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    Rustls,
}

impl Backend {
    fn select(provider: &dyn QuicClientConfigProvider, extensions: &Extensions) -> Option<Self> {
        if !extensions.contains::<TlsServerTrust>() {
            return None;
        }
        let _classifier = provider.pool_classifier();
        #[cfg(feature = "boring")]
        if _classifier == ReuseKey::of::<BoringTlsConnectorConfig>() {
            return Some(Self::Boring);
        }
        #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
        if _classifier == ReuseKey::of::<RustlsTlsConnectorConfig>() {
            return Some(Self::Rustls);
        }
        None
    }
}

impl ServerVerification {
    // The cache entry owns the Arc, so its address cannot be reused while the
    // corresponding native configuration can still be retrieved.
    fn identity(&self) -> *const () {
        match *self {
            #[cfg(feature = "boring")]
            Self::Boring(Either::A(ref store)) => Arc::as_ptr(store).cast(),
            #[cfg(feature = "boring")]
            Self::Boring(Either::B(ref verifier)) => Arc::as_ptr(verifier).cast(),
            #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
            Self::Rustls(Either::A(ref store)) => Arc::as_ptr(store).cast(),
            #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
            Self::Rustls(Either::B(ref verifier)) => Arc::as_ptr(verifier).cast(),
        }
    }

    pub(super) fn acquire(
        provider: &dyn QuicClientConfigProvider,
        extensions: &Extensions,
    ) -> Result<Option<Self>, BoxError> {
        match Backend::select(provider, extensions) {
            #[cfg(feature = "boring")]
            Some(Backend::Boring) => {
                Ok(BoringTlsConnectorConfig::server_verification(extensions)?.map(Self::Boring))
            }
            #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
            Some(Backend::Rustls) => {
                Ok(RustlsTlsConnectorConfig::server_verification(extensions)?.map(Self::Rustls))
            }
            None => Ok(None),
        }
    }

    pub(super) async fn acquire_async(
        provider: &dyn QuicClientConfigProvider,
        extensions: &Extensions,
    ) -> Result<Option<Self>, BoxError> {
        match Backend::select(provider, extensions) {
            #[cfg(feature = "boring")]
            Some(Backend::Boring) => Ok(BoringTlsConnectorConfig::server_verification_async(
                extensions,
            )
            .await?
            .map(Self::Boring)),
            #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
            Some(Backend::Rustls) => Ok(RustlsTlsConnectorConfig::server_verification_async(
                extensions,
            )
            .await?
            .map(Self::Rustls)),
            None => Ok(None),
        }
    }
}
