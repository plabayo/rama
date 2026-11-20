use std::sync::{Arc, LazyLock};

use moka::sync::Cache;
use rama_core::{
    error::{BoxError, ErrorExt as _},
    extensions::Extensions,
};
use rama_crypto::platform_verifier::PlatformVerifier;
use rama_tls::client::{TlsServerTrust, platform_verifier};

pub(crate) use platform_verifier::PreparedPlatformVerifier;

fn verifiers() -> &'static Cache<TlsServerTrust, PreparedPlatformVerifier> {
    const MAX_CACHED_VERIFIERS: u64 = 64;
    static VERIFIERS: LazyLock<Cache<TlsServerTrust, PreparedPlatformVerifier>> =
        LazyLock::new(|| Cache::builder().max_capacity(MAX_CACHED_VERIFIERS).build());
    &VERIFIERS
}

pub(super) fn cached_platform_verifier(
    trust: &TlsServerTrust,
    prepared: Option<&PreparedPlatformVerifier>,
) -> Result<Arc<PlatformVerifier>, BoxError> {
    platform_verifier::resolve_platform_verifier(trust, prepared, cache_platform_verifier)
}

fn cache_platform_verifier(trust: &TlsServerTrust) -> Result<PreparedPlatformVerifier, BoxError> {
    verifiers()
        .try_get_with(trust.clone(), || {
            platform_verifier::build_platform_verifier(trust)
        })
        .map_err(|error| error.to_string().context("build cached platform verifier"))
}

pub(super) async fn prepare_server_trust(
    extensions: &Extensions,
    trust: &TlsServerTrust,
) -> Result<(), BoxError> {
    platform_verifier::prepare_server_trust(
        extensions,
        trust,
        |trust| verifiers().get(trust),
        cache_platform_verifier,
    )
    .await
}
