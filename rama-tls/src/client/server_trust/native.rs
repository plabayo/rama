use std::{
    hash::{Hash, Hasher},
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use rama_core::{
    error::BoxError,
    futures::{StreamExt as _, stream::BoxStream},
};
use rama_crypto::{native_certs, pki_types::CertificateDer, platform_verifier::PlatformVerifier};
use rama_utils::macros::generate_set_and_with;

use super::{NativeTrustPolicy, PlatformTrustPolicy, ServerTrustSource};
use crate::client::{
    IntoNativeTrustReloadTrigger,
    native_trust::{NativeTrustReload, NativeTrustScope},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct NativeTrustState {
    reload: Option<Reload>,
    max_age: Option<Duration>,
}

/// A reload controller and the number of trigger events it consumed.
#[derive(Debug, Clone)]
struct Reload {
    controller: NativeTrustReload,
    events: Arc<AtomicU64>,
}

impl Reload {
    fn new(scope: NativeTrustScope, trigger: Option<BoxStream<'static, ()>>) -> Self {
        let events = Arc::new(AtomicU64::new(0));
        let counted = events.clone();
        // Counting at the source sees every event, including those coalesced into one refresh.
        let trigger = trigger.map(|trigger| {
            trigger
                .inspect(move |()| {
                    counted.fetch_add(1, Ordering::Relaxed);
                })
                .boxed()
        });
        Self {
            controller: NativeTrustReload::new(scope, trigger),
            events,
        }
    }
}

// The event counter belongs to its controller, which alone identifies the policy.
impl PartialEq for Reload {
    fn eq(&self, other: &Self) -> bool {
        self.controller == other.controller
    }
}

impl Eq for Reload {}

impl Hash for Reload {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.controller.hash(state);
    }
}

impl NativeTrustState {
    pub(super) const STATIC: Self = Self {
        reload: None,
        max_age: None,
    };

    fn set_trigger<T>(
        &mut self,
        scope: NativeTrustScope,
        trigger: impl IntoNativeTrustReloadTrigger<T>,
    ) {
        self.reload = Some(Reload::new(
            scope,
            Some(Box::pin(trigger.into_reload_stream())),
        ));
    }

    fn set_max_age(&mut self, scope: NativeTrustScope, max_age: Option<Duration>) {
        self.max_age = max_age;
        if max_age.is_some() && self.reload.is_none() {
            self.reload = Some(Reload::new(scope, None));
        } else if max_age.is_none()
            && self
                .reload
                .as_ref()
                .is_some_and(|reload| !reload.controller.has_trigger())
        {
            self.reload = None;
        }
    }
}

impl NativeTrustPolicy {
    generate_set_and_with! {
        /// Refresh native roots when the trigger fires.
        ///
        /// Pass a stream of unit events or a tuple of streams. A handshake
        /// processes pending events and pins one trust generation.
        pub fn reload_trigger<T>(mut self, trigger: impl IntoNativeTrustReloadTrigger<T>) -> Self {
            self.state.set_trigger(NativeTrustScope::Full, trigger);
            self
        }
    }

    generate_set_and_with! {
        /// Limit how long a handshake may rely on its native trust snapshot.
        ///
        /// At the age limit, a fresh read is required even if no trigger has fired.
        /// If the read fails, the handshake fails. A limit of zero requires a
        /// successful read for every handshake.
        pub fn max_age(mut self, max_age: Option<Duration>) -> Self {
            self.state.set_max_age(NativeTrustScope::Full, max_age);
            self
        }
    }
}

impl PlatformTrustPolicy {
    generate_set_and_with! {
        /// Refresh trust roots when the trigger fires.
        ///
        /// On targets with an operating system verifier, refresh only
        /// `SSL_CERT_EXTRA_FILE` and `SSL_CERT_EXTRA_DIR`. Use
        /// [`NativeTrustStoreChanges::extra_roots`](crate::client::NativeTrustStoreChanges::extra_roots)
        /// to watch these settings. On macOS, Keychain lookup remains part of
        /// operating system verification.
        ///
        /// On targets without an operating system verifier, refresh the full
        /// native store. A trigger stream requests a refresh and the platform
        /// decides which roots the policy reloads.
        ///
        /// With an operating system verifier, every event also ends resumption
        /// of earlier TLS sessions, since system trust may have changed.
        pub fn reload_trigger<T>(mut self, trigger: impl IntoNativeTrustReloadTrigger<T>) -> Self {
            self.state.set_trigger(Self::SCOPE, trigger);
            self
        }
    }

    generate_set_and_with! {
        /// Limit how long a handshake may rely on its trust snapshot.
        ///
        /// The limit applies to environment-supplied extra roots when an
        /// operating system verifier is available, or the full native snapshot
        /// on other targets. At the limit, the handshake requires a successful
        /// read. With a limit of zero, this applies to every handshake.
        pub fn max_age(mut self, max_age: Option<Duration>) -> Self {
            self.state.set_max_age(Self::SCOPE, max_age);
            self
        }
    }

    const SCOPE: NativeTrustScope = if PlatformVerifier::IS_AVAILABLE {
        NativeTrustScope::PlatformExtras
    } else {
        NativeTrustScope::Full
    };
}

/// Read the configured source's server trust anchors.
///
/// An active operating system verifier supplies its own system roots. For a
/// Platform source on those targets this returns only the environment extra
/// roots. On other targets Platform returns the full native root collection.
/// Additional application anchors on [`super::TlsServerTrust`] are separate.
/// A successful empty collection represents an empty source. This operation
/// can block while reading the configured trust store.
pub fn server_trust_anchors(
    source: &ServerTrustSource,
) -> Result<Arc<[CertificateDer<'static>]>, BoxError> {
    if let Some(state) = native_state(source)
        && let Some(reload) = &state.reload
    {
        return reload.controller.pin(state.max_age);
    }
    Ok(static_trust_anchors(source))
}

/// Read the configured source's server trust anchors on a Tokio runtime.
///
/// See [`server_trust_anchors`] for which certificates the source supplies.
/// Reads from disk or a system store run on a blocking worker.
pub async fn server_trust_anchors_async(
    source: &ServerTrustSource,
) -> Result<Arc<[CertificateDer<'static>]>, BoxError> {
    if let Some(state) = native_state(source)
        && let Some(reload) = &state.reload
    {
        return reload.controller.pin_async(state.max_age).await;
    }
    match source {
        ServerTrustSource::Platform(_) if PlatformVerifier::IS_AVAILABLE => {
            native_certs::shared_extra_trust_anchors_async().await
        }
        ServerTrustSource::Native(_) | ServerTrustSource::Platform(_) => {
            native_certs::shared_native_trust_anchors_async().await
        }
        ServerTrustSource::WebPki | ServerTrustSource::Custom(_) => {
            Ok(static_trust_anchors(source))
        }
    }
}

/// The reloaded anchors of `source` when they can be pinned without a trust-store read.
pub(super) fn ready_trust_anchors(
    source: &ServerTrustSource,
) -> Option<Arc<[CertificateDer<'static>]>> {
    let state = native_state(source)?;
    state.reload.as_ref()?.controller.pin_ready(state.max_age)
}

/// Whether a reload policy applies to `source`.
pub(super) fn is_reloadable(source: &ServerTrustSource) -> bool {
    native_state(source).is_some_and(|state| state.reload.is_some())
}

/// Whether a reload trigger can still report trust changes for `source`.
pub(super) fn has_reload_trigger(source: &ServerTrustSource) -> bool {
    native_state(source)
        .and_then(|state| state.reload.as_ref())
        .is_some_and(|reload| reload.controller.has_live_trigger())
}

/// Trigger events consumed so far by the reload policy of `source`.
pub(super) fn trigger_events(source: &ServerTrustSource) -> u64 {
    native_state(source)
        .and_then(|state| state.reload.as_ref())
        .map_or(0, |reload| reload.events.load(Ordering::Relaxed))
}

fn native_state(source: &ServerTrustSource) -> Option<&NativeTrustState> {
    match source {
        ServerTrustSource::Native(policy) => Some(&policy.state),
        ServerTrustSource::Platform(policy) => Some(&policy.state),
        _ => None,
    }
}

fn static_trust_anchors(source: &ServerTrustSource) -> Arc<[CertificateDer<'static>]> {
    match source {
        ServerTrustSource::Platform(_) if PlatformVerifier::IS_AVAILABLE => {
            native_certs::shared_extra_trust_anchors()
        }
        ServerTrustSource::Native(_) | ServerTrustSource::Platform(_) => {
            native_certs::shared_native_trust_anchors()
        }
        ServerTrustSource::WebPki => {
            static ROOTS: LazyLock<Arc<[CertificateDer<'static>]>> =
                LazyLock::new(|| Arc::from(native_certs::bundled_root_certs()));
            ROOTS.clone()
        }
        ServerTrustSource::Custom(anchors) => anchors.certificates.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Duration, NativeTrustPolicy, NativeTrustScope, PlatformTrustPolicy, PlatformVerifier,
        ServerTrustSource,
    };
    use crate::client::{ChannelReloadTrigger, TlsServerTrust, TlsServerTrustAnchors};
    use rama_crypto::pki_types::CertificateDer;

    #[test]
    fn replacing_native_source_discards_reload_policy() {
        let custom = TlsServerTrustAnchors::try_new([CertificateDer::from(vec![1])]).unwrap();
        let (_sender, trigger) = ChannelReloadTrigger::new();
        let policy = NativeTrustPolicy::new()
            .with_reload_trigger(trigger)
            .with_max_age(Duration::ZERO);
        let native = TlsServerTrust::new(ServerTrustSource::Native(policy));

        for source in [ServerTrustSource::WebPki, ServerTrustSource::Custom(custom)] {
            let switched = native.clone().with_source(source);
            assert!(super::native_state(switched.source()).is_none());
            assert_eq!(
                switched.with_source(ServerTrustSource::native_roots()),
                TlsServerTrust::native_roots()
            );
        }
    }

    #[test]
    fn platform_reload_uses_the_scope_for_the_current_target() {
        let static_policy = PlatformTrustPolicy::new();
        let age_only = static_policy.clone().with_max_age(Duration::ZERO);
        let (_sender, trigger) = ChannelReloadTrigger::new();
        let triggered = static_policy.clone().with_reload_trigger(trigger);

        assert_ne!(triggered, static_policy);
        assert_eq!(age_only.without_max_age(), static_policy);
        assert_eq!(
            matches!(PlatformTrustPolicy::SCOPE, NativeTrustScope::PlatformExtras),
            PlatformVerifier::IS_AVAILABLE
        );
    }

    #[test]
    fn clearing_an_age_limit_retains_the_native_trigger() {
        let (_sender, trigger) = ChannelReloadTrigger::new();
        let native = NativeTrustPolicy::new().with_reload_trigger(trigger);
        assert_eq!(
            native
                .clone()
                .with_max_age(Duration::ZERO)
                .without_max_age(),
            native
        );
    }
}
