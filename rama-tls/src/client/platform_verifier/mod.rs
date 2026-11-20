//! Platform verifier preparation for TLS backend integrations.

use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extension, Extensions},
};
use rama_crypto::{pki_types::CertificateDer, platform_verifier::PlatformVerifier};
use std::sync::Arc;

use super::{PlatformTrustPolicy, ServerTrustSource, TlsServerTrust, TlsServerTrustAnchors};

/// A platform verifier retained by one prepared connection configuration.
#[derive(Clone, Debug, Extension)]
#[extension(tags(tls))]
pub struct PreparedPlatformVerifier(Arc<PreparedVerifier>);

#[derive(Debug)]
struct PreparedVerifier {
    trust: TlsServerTrust,
    verifier: Arc<PlatformVerifier>,
}

impl PreparedPlatformVerifier {
    fn matches(&self, trust: &TlsServerTrust) -> bool {
        &self.0.trust == trust
    }

    fn for_trust(&self, trust: &TlsServerTrust) -> Option<Arc<PlatformVerifier>> {
        self.matches(trust).then(|| self.0.verifier.clone())
    }
}

fn pinned_extra_roots(trust: &TlsServerTrust) -> Option<&[CertificateDer<'static>]> {
    match trust.source() {
        ServerTrustSource::Platform(policy) => policy.pinned_extra_roots(),
        _ => None,
    }
}

fn shared_platform_verifier(trust: &TlsServerTrust) -> Option<Arc<PlatformVerifier>> {
    (PlatformVerifier::IS_AVAILABLE
        && matches!(trust.source(), ServerTrustSource::Platform(policy) if *policy == PlatformTrustPolicy::new())
        && trust.additional_anchors().is_none())
    .then(PlatformVerifier::shared)
}

/// Resolve the platform verifier for the effective trust policy.
///
/// A matching prepared handle takes precedence over the cache. The backend
/// supplies its synchronous cache loader for other policies.
pub fn resolve_platform_verifier(
    trust: &TlsServerTrust,
    prepared: Option<&PreparedPlatformVerifier>,
    load: fn(&TlsServerTrust) -> Result<PreparedPlatformVerifier, BoxError>,
) -> Result<Arc<PlatformVerifier>, BoxError> {
    if let Some(verifier) = prepared
        .and_then(|prepared| prepared.for_trust(trust))
        .or_else(|| shared_platform_verifier(trust))
    {
        return Ok(verifier);
    }
    load(trust)?.for_trust(trust).ok_or_else(|| {
        BoxError::from_static_str("platform verifier cache returned another trust policy")
    })
}

/// Build a platform verifier from the configured extra and additional roots.
/// An already-pinned extra-root set, including an empty set, takes precedence
/// over the process-wide environment snapshot. A reloadable source must first
/// resolve to a pinned generation. This operation may block.
pub fn build_platform_verifier(
    trust: &TlsServerTrust,
) -> Result<PreparedPlatformVerifier, BoxError> {
    let ServerTrustSource::Platform(policy) = trust.source() else {
        return Err(BoxError::from_static_str(
            "platform verifier requires a platform trust policy",
        ));
    };
    if !PlatformVerifier::IS_AVAILABLE {
        return Err(BoxError::from_static_str("platform verifier unavailable"));
    }
    let environment;
    let roots = if let Some(roots) = policy.pinned_extra_roots() {
        roots
    } else if *policy == PlatformTrustPolicy::new() {
        environment = rama_crypto::native_certs::shared_extra_trust_anchors();
        &environment
    } else {
        return Err(BoxError::from_static_str(
            "platform trust source must be pinned",
        ));
    };
    let additional = trust
        .additional_anchors()
        .into_iter()
        .flat_map(TlsServerTrustAnchors::certificates);
    let verifier = PlatformVerifier::try_with_extra_roots(roots.iter().chain(additional).cloned())?;
    Ok(PreparedPlatformVerifier(Arc::new(PreparedVerifier {
        trust: trust.clone(),
        verifier: Arc::new(verifier),
    })))
}

/// Pin the trust source and retain its prepared verifier on this connection's
/// extensions. The backend supplies its cache lookup and synchronous builder.
/// A pinned verifier cache miss runs on a blocking worker.
pub async fn prepare_server_trust(
    extensions: &Extensions,
    trust: &TlsServerTrust,
    lookup: fn(&TlsServerTrust) -> Option<PreparedPlatformVerifier>,
    build: fn(&TlsServerTrust) -> Result<PreparedPlatformVerifier, BoxError>,
) -> Result<(), BoxError> {
    let pinned = trust
        .source()
        .snapshot_async()
        .await?
        .map(|source| trust.clone().with_source(source));
    let trust = pinned.as_ref().unwrap_or(trust);
    if PlatformVerifier::IS_AVAILABLE
        && pinned_extra_roots(trust).is_some()
        && extensions
            .get_ref::<PreparedPlatformVerifier>()
            .is_none_or(|prepared| !prepared.matches(trust))
    {
        let prepared =
            if let Some(prepared) = lookup(trust).filter(|prepared| prepared.matches(trust)) {
                prepared
            } else {
                let trust = trust.clone();
                tokio::task::spawn_blocking(move || build(&trust)).await??
            };
        if !prepared.matches(trust) {
            return Err(BoxError::from_static_str(
                "platform verifier belongs to another trust policy",
            ));
        }
        extensions.insert(prepared);
    }
    if let Some(pinned) = pinned {
        extensions.insert(pinned);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
