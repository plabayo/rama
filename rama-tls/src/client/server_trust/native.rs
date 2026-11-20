use std::time::Duration;

use rama_core::error::BoxError;
use rama_crypto::{pki_types::CertificateDer, platform_verifier::PlatformVerifier};
use rama_utils::macros::generate_set_and_with;

use super::{NativeTrustPolicy, PlatformTrustPolicy, ServerTrustSource};
use crate::client::{
    IntoNativeTrustReloadTrigger,
    native_trust::{NativeTrustReload, NativeTrustScope, NativeTrustSnapshot},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct NativeTrustState {
    reload: Option<NativeTrustReload>,
    max_age: Option<Duration>,
    snapshot: Option<NativeTrustSnapshot>,
}

impl NativeTrustState {
    pub(super) const STATIC: Self = Self {
        reload: None,
        max_age: None,
        snapshot: None,
    };

    fn set_trigger<T>(
        &mut self,
        scope: NativeTrustScope,
        trigger: impl IntoNativeTrustReloadTrigger<T>,
    ) {
        self.reload = Some(NativeTrustReload::new(
            scope,
            Some(Box::pin(trigger.into_reload_stream())),
        ));
        self.snapshot = None;
    }

    fn set_max_age(&mut self, scope: NativeTrustScope, max_age: Option<Duration>) {
        self.max_age = max_age;
        if max_age.is_some() && self.reload.is_none() {
            self.reload = Some(NativeTrustReload::new(scope, None));
        } else if max_age.is_none()
            && self
                .reload
                .as_ref()
                .is_some_and(|reload| !reload.has_trigger())
        {
            self.reload = None;
        }
        self.snapshot = None;
    }

    fn pin(&self) -> Result<Option<Self>, BoxError> {
        let Some(reload) = &self.reload else {
            return Ok(None);
        };
        let snapshot = reload.pin(self.max_age)?;
        Ok(Some(self.with_native_snapshot(snapshot)))
    }

    async fn pin_async(&self) -> Result<Option<Self>, BoxError> {
        let Some(reload) = &self.reload else {
            return Ok(None);
        };
        let snapshot = reload.pin_async(self.max_age).await?;
        Ok(Some(self.with_native_snapshot(snapshot)))
    }

    fn with_native_snapshot(&self, snapshot: NativeTrustSnapshot) -> Self {
        Self {
            snapshot: Some(snapshot),
            max_age: self.max_age,
            reload: None,
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

    /// Roots pinned for this source by [`ServerTrustSource::snapshot`].
    pub fn pinned_roots(&self) -> Option<&[CertificateDer<'static>]> {
        self.state.snapshot.as_ref()?.native_roots()
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

    /// Full native roots pinned for this source by [`ServerTrustSource::snapshot`]
    /// on targets without an operating system verifier.
    pub fn pinned_native_roots(&self) -> Option<&[CertificateDer<'static>]> {
        self.state.snapshot.as_ref()?.native_roots()
    }

    /// Extra roots pinned for this source by [`ServerTrustSource::snapshot`] on
    /// targets with an operating system verifier.
    ///
    /// An empty slice is a pinned generation with no environment extra roots.
    /// Application anchors are available through [`TlsServerTrust::additional_anchors`](super::TlsServerTrust::additional_anchors).
    pub fn pinned_extra_roots(&self) -> Option<&[CertificateDer<'static>]> {
        self.state.snapshot.as_ref()?.platform_extra_roots()
    }

    const SCOPE: NativeTrustScope = if PlatformVerifier::IS_AVAILABLE {
        NativeTrustScope::PlatformExtras
    } else {
        NativeTrustScope::Full
    };
}

impl ServerTrustSource {
    /// Pin a reloadable source to one immutable generation for a handshake.
    ///
    /// TLS backends may use the returned source as part of a cache key.
    /// Returns `None` for static or already pinned sources. May block on
    /// filesystem or system store access. Async connectors should use
    /// [`Self::snapshot_async`].
    pub fn snapshot(&self) -> Result<Option<Self>, BoxError> {
        let Some(state) = self.native_state() else {
            return Ok(None);
        };
        Ok(state.pin()?.map(|state| self.with_pinned_state(state)))
    }

    /// Pin a reloadable source on a Tokio runtime, reading trust stores on
    /// a blocking worker. Returns `None` under the same conditions as
    /// [`Self::snapshot`].
    pub async fn snapshot_async(&self) -> Result<Option<Self>, BoxError> {
        let Some(state) = self.native_state() else {
            return Ok(None);
        };
        Ok(state
            .pin_async()
            .await?
            .map(|state| self.with_pinned_state(state)))
    }

    fn native_state(&self) -> Option<&NativeTrustState> {
        match self {
            Self::Native(policy) => Some(&policy.state),
            Self::Platform(policy) => Some(&policy.state),
            _ => None,
        }
    }

    fn with_pinned_state(&self, state: NativeTrustState) -> Self {
        match self {
            Self::Platform(_) => Self::Platform(PlatformTrustPolicy { state }),
            _ => Self::Native(NativeTrustPolicy { state }),
        }
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
            assert!(switched.source().snapshot().unwrap().is_none());
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
