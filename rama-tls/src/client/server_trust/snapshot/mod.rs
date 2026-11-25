use std::{
    any::Any,
    sync::{Arc, OnceLock},
};

use rama_core::{combinators::Either, error::BoxError};
use rama_crypto::{native_certs, pki_types::CertificateDer, platform_verifier::PlatformVerifier};
use tokio::runtime::Handle;

use super::{
    ServerTrustSource, TlsServerTrust, TlsServerTrustAnchors,
    native::{
        has_reload_trigger, ready_trust_anchors, server_trust_anchors, server_trust_anchors_async,
        trigger_events,
    },
};
use crate::client::{TlsComponentIdentity, TlsPoolComponent};

type Anchors = Arc<[CertificateDer<'static>]>;

/// Process-wide trust material that a TLS backend builds at most once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SharedServerTrustRoots {
    /// The static snapshot of native roots.
    Native,
    /// Rama's bundled WebPKI roots.
    WebPki,
    /// The operating system verifier with the static environment extra roots.
    Platform,
}

/// The roots a TLS backend derives its server verification from.
#[derive(Debug, Clone)]
pub enum ServerTrustRoots {
    /// Process-wide built-in trust material.
    Shared(SharedServerTrustRoots),
    /// Only the configured anchors.
    Custom(TlsServerTrustAnchors),
    /// Native roots read for this handshake by a reload policy. May be empty.
    Native(Anchors),
    /// Extra roots for the operating system verifier read by a reload policy.
    PlatformExtras(Anchors),
}

/// The server trust that applies to one handshake.
///
/// Reading a snapshot pins the trust generation of a reloadable source.
/// Backends cache what they build from it under [`Self::key`].
#[derive(Debug, Clone)]
pub struct ServerTrustSnapshot {
    roots: ServerTrustRoots,
    additional: Option<TlsServerTrustAnchors>,
    generation: u64,
}

/// Cache key of the verification a backend builds from a [`ServerTrustSnapshot`].
///
/// Reloaded anchors compare by allocation, so the key retains them. An
/// operating system verifier also changes with every trigger event, because
/// such an event can report a change in system trust that no snapshot shows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerTrustKey {
    base: KeyBase,
    additional: Option<TlsServerTrustAnchors>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum KeyBase {
    Shared(SharedServerTrustRoots),
    Custom(TlsServerTrustAnchors),
    Native(TlsComponentIdentity<[CertificateDer<'static>]>),
    PlatformExtras {
        anchors: TlsComponentIdentity<[CertificateDer<'static>]>,
        generation: u64,
    },
}

enum Plan<'a> {
    Ready(ServerTrustRoots),
    Read(&'a ServerTrustSource),
}

impl ServerTrustSnapshot {
    /// Read the trust for one handshake. This can block on trust-store IO.
    pub fn read(trust: &TlsServerTrust) -> Result<Self, BoxError> {
        let roots = match Self::plan(trust) {
            Plan::Ready(roots) => roots,
            Plan::Read(source) => Self::reloaded(source, server_trust_anchors(source)?),
        };
        Ok(Self::new(trust, roots))
    }

    /// Read the trust for one handshake, running trust-store IO on a blocking worker.
    pub async fn read_async(trust: &TlsServerTrust) -> Result<Self, BoxError> {
        let roots = match Self::plan(trust) {
            Plan::Ready(roots) => roots,
            Plan::Read(source) => Self::reloaded(source, server_trust_anchors_async(source).await?),
        };
        Ok(Self::new(trust, roots))
    }

    /// Read the trust for one handshake only if that needs no trust-store IO.
    ///
    /// `None` when a reload trigger event, the age limit or a failed refresh
    /// requires a fresh read, which [`Self::read`] performs.
    #[must_use]
    pub fn read_ready(trust: &TlsServerTrust) -> Option<Self> {
        let roots = match Self::plan(trust) {
            Plan::Ready(roots) => roots,
            Plan::Read(source) => Self::reloaded(source, ready_trust_anchors(source)?),
        };
        Some(Self::new(trust, roots))
    }

    /// The process-wide trust material that applies unchanged to `trust`.
    ///
    /// Unlike [`Self::read`], this never reads a trust store.
    #[must_use]
    pub fn shared_for(trust: &TlsServerTrust) -> Option<SharedServerTrustRoots> {
        match (Self::plan(trust), trust.additional_anchors()) {
            (Plan::Ready(ServerTrustRoots::Shared(shared)), None) => Some(shared),
            _ => None,
        }
    }

    /// The process-wide trust material when it applies unchanged.
    #[must_use]
    pub fn shared(&self) -> Option<SharedServerTrustRoots> {
        match (&self.roots, &self.additional) {
            (ServerTrustRoots::Shared(shared), None) => Some(*shared),
            _ => None,
        }
    }

    /// The roots to derive verification from.
    #[must_use]
    pub fn roots(&self) -> &ServerTrustRoots {
        &self.roots
    }

    /// Anchors added to [`Self::roots`].
    #[must_use]
    pub fn additional_anchors(&self) -> Option<&TlsServerTrustAnchors> {
        self.additional.as_ref()
    }

    /// The cache key of the verification derived from this snapshot.
    #[must_use]
    pub fn key(&self) -> ServerTrustKey {
        let base = match &self.roots {
            ServerTrustRoots::Shared(shared) => KeyBase::Shared(*shared),
            ServerTrustRoots::Custom(anchors) => KeyBase::Custom(anchors.clone()),
            ServerTrustRoots::Native(anchors) => {
                KeyBase::Native(TlsComponentIdentity::shared(anchors))
            }
            ServerTrustRoots::PlatformExtras(anchors) => KeyBase::PlatformExtras {
                anchors: TlsComponentIdentity::shared(anchors),
                generation: self.generation,
            },
        };
        ServerTrustKey {
            base,
            additional: self.additional.clone(),
        }
    }

    /// Build the operating system verifier for [`SharedServerTrustRoots::Platform`]
    /// or [`ServerTrustRoots::PlatformExtras`] roots.
    ///
    /// It trusts the extra roots and additional anchors on top of the operating
    /// system's trust; other roots contribute nothing. This can block while
    /// reading extra roots.
    pub fn platform_verifier(&self) -> Result<Arc<PlatformVerifier>, BoxError> {
        let extras = match &self.roots {
            ServerTrustRoots::Shared(SharedServerTrustRoots::Platform)
                if self.additional.is_none() =>
            {
                return Ok(shared_platform_verifier());
            }
            ServerTrustRoots::Shared(SharedServerTrustRoots::Platform) => {
                native_certs::shared_extra_trust_anchors()
            }
            ServerTrustRoots::PlatformExtras(extras) => extras.clone(),
            ServerTrustRoots::Shared(_)
            | ServerTrustRoots::Custom(_)
            | ServerTrustRoots::Native(_) => Anchors::from([]),
        };
        let roots = extras.iter().chain(
            self.additional
                .iter()
                .flat_map(TlsServerTrustAnchors::certificates),
        );
        PlatformVerifier::try_with_extra_roots(roots.cloned()).map(Arc::new)
    }

    /// Derive a loading plan from the trust policy.
    fn plan(trust: &TlsServerTrust) -> Plan<'_> {
        let source = trust.source();
        if source.is_reloadable() {
            return Plan::Read(source);
        }
        Plan::Ready(match source {
            ServerTrustSource::Platform(_) if PlatformVerifier::IS_AVAILABLE => {
                ServerTrustRoots::Shared(SharedServerTrustRoots::Platform)
            }
            ServerTrustSource::Native(_) | ServerTrustSource::Platform(_) => {
                ServerTrustRoots::Shared(SharedServerTrustRoots::Native)
            }
            ServerTrustSource::WebPki => ServerTrustRoots::Shared(SharedServerTrustRoots::WebPki),
            ServerTrustSource::Custom(anchors) => ServerTrustRoots::Custom(anchors.clone()),
        })
    }

    /// Create a replacement snapshot from reloaded trust state.
    fn reloaded(source: &ServerTrustSource, anchors: Anchors) -> ServerTrustRoots {
        if PlatformVerifier::IS_AVAILABLE && matches!(source, ServerTrustSource::Platform(_)) {
            ServerTrustRoots::PlatformExtras(anchors)
        } else {
            ServerTrustRoots::Native(anchors)
        }
    }

    /// Build a snapshot from the selected trust sources.
    fn new(trust: &TlsServerTrust, roots: ServerTrustRoots) -> Self {
        Self {
            roots,
            additional: trust.additional_anchors().cloned(),
            // Read after the anchors so the events their read consumed are included.
            generation: trigger_events(trust.source()),
        }
    }
}

/// Pool identity of the verification one handshake used under reloadable trust.
///
/// A static trust policy is already part of a pool identity; the store or
/// verifier read for a reloadable policy is not. Each reload, and for an
/// operating system verifier each trigger event, yields a new scope, so
/// sessions and cached configurations never cross a trust change or loss of the reload signal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerVerificationScope {
    verifier: TlsComponentIdentity<dyn Any + Send + Sync>,
    allows_resumption: bool,
}

impl ServerVerificationScope {
    /// The scope of `verification` when `trust` reloads, otherwise `None`.
    pub fn reloadable<S: Any + Send + Sync>(
        trust: Option<&TlsServerTrust>,
        verification: &Either<Arc<S>, Arc<PlatformVerifier>>,
    ) -> Option<Self> {
        if !trust?.source().is_reloadable() {
            return None;
        }
        let shared: Arc<dyn Any + Send + Sync> = match verification {
            Either::A(store) => store.clone(),
            Either::B(verifier) => verifier.clone(),
        };
        Some(Self {
            verifier: TlsComponentIdentity::shared(&shared),
            allows_resumption: Self::allows_resumption(trust, verification),
        })
    }

    /// Whether sessions verified with `verification` may resume on later connections.
    ///
    /// An operating system verifier needs a reload trigger that has not ended, the
    /// only report of a system trust change; resumption would otherwise skip that
    /// verifier until the session expires.
    pub fn allows_resumption<S: Any + Send + Sync>(
        trust: Option<&TlsServerTrust>,
        verification: &Either<Arc<S>, Arc<PlatformVerifier>>,
    ) -> bool {
        match verification {
            Either::A(_) => true,
            Either::B(_) => trust.is_some_and(|trust| has_reload_trigger(trust.source())),
        }
    }
}

impl TlsPoolComponent for ServerVerificationScope {
    type Identity = Self;

    fn pool_component_identity(&self) -> Self::Identity {
        self.clone()
    }
}

static PLATFORM: OnceLock<Arc<PlatformVerifier>> = OnceLock::new();

/// The process-wide operating system verifier. The first call can block.
#[must_use]
pub fn shared_platform_verifier() -> Arc<PlatformVerifier> {
    PLATFORM.get_or_init(PlatformVerifier::shared).clone()
}

/// The process-wide operating system verifier. The first call builds it off the async worker.
pub async fn shared_platform_verifier_async() -> Result<Arc<PlatformVerifier>, BoxError> {
    if let Some(verifier) = PLATFORM.get() {
        return Ok(verifier.clone());
    }
    match Handle::try_current() {
        Ok(runtime) => Ok(runtime.spawn_blocking(shared_platform_verifier).await?),
        Err(_no_runtime) => Ok(shared_platform_verifier()),
    }
}

#[cfg(test)]
mod tests;
